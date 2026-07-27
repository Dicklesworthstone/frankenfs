# bd-b9dug — the benchmarked binary is not the shipped binary

**Initial audit: 2026-07-25, with ISA-only pairs on pinned worker `hz2`.
Exact CLI lookup follow-up: 2026-07-27 on pinned worker `ovh-a`.**

Unless its row proves otherwise from the executing process, every historical
frankenfs performance ratio published before this correction was measured on a
binary that is **not** the one `scripts/build-perf.sh` produces. The first
follow-up measured the ISA-only residual for two owned benchmark families. The
second closes exact production-shaped v3+PGO identity for one CLI lookup
workload. It does **not** convert unrelated generic-ELF or kernel-comparator
claims into shipped-binary results.

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

The owned allocator and JBD2 benchmark executables now print both the SHA-256 of the
executing ELF and their compile-time/runtime ISA features. Both whole-binary pairs ran
on `hz2`, pinned to CPU 6:

| benchmark | build | executing ELF SHA-256 | compile-time witness |
|---|---|---|---|
| inode allocator | generic | `444f2807ea2920cb2f90fb09a85c9b31c53091981eb3b76f6d9d4cf1895a1cb3` | SSE2; no SSE4.2/AVX2/FMA |
| inode allocator | v3 | `fc40f87b2647fda9ac36501f673428c090f3d88b2d20136deca81e8c6ea41955` | SSE2+SSE4.2+AVX2+FMA |
| JBD2 writer | generic | `8695daa5adfbbe17e9a823790ebc644b490f9738a41f44e93f7005b51ca2f899` | SSE2; no SSE4.2/AVX2/FMA |
| JBD2 writer | v3 | `f91979ffaf94b61a589716314344f6ec006e31a3beffe01faaf817e8a208f433` | SSE2+SSE4.2+AVX2+FMA |

All four executions reported AVX2+FMA at runtime. The generic binaries therefore
proved the mismatch directly; the v3 binaries proved that the correction reached
`rustc`.

Three apparent v3 routes were rejected before the valid pair. Local `RUSTFLAGS`
without an RCH allowlist (job `j-29946774143631803`), Cargo global
`build.rustflags` (job `j-29946774143631815`), and Cargo target-table rustflags
(job `j-29947955108642846`, ELF
`0b7d8ce475a0afcf2fc302f812533611e312adb73969de122fb9edb4ee8e3ef8`) all produced
different ELFs that still self-reported `compile_avx2=false,compile_fma=false`.
Those measurements are inadmissible as v3 evidence. A different ELF SHA is necessary,
but it is not sufficient.

### Exact production-shaped CLI witness

The 2026-07-27 gate exercised the complete `build-perf.sh` code-generation
shape—fat-LTO `release-perf`, `target-cpu=x86-64-v3`, profile generation over
the CLI create/lookup/rename/delete/walk workload family, profile merge, and
profile use—on one pinned `ovh-a` worker:

| role | executing ELF SHA-256 | compile-time ISA | embedded profile SHA-256 |
|---|---|---|---|
| generic release-perf control | `1d36a367ee3703d99a92b8af52387af2570787db4070065082185db681517764` | SSE2; no SSE4.2/AVX2/FMA | `none` |
| v3 profile-generation CLI | `16b0b3d621dac6742d3af29aeac235bddbc3b3fc191403e64354432b0f64582a` | SSE2+SSE4.2+AVX2+FMA | `none` |
| final v3+PGO CLI | `7136d8bf768a222ec2e6985efbe25249131a274db3b9bc81a4394323265adc62` | SSE2+SSE4.2+AVX2+FMA | `3dbce2b2fca971cacd1963d0aaeb867de10417761624a0c1236d01a6880860db` |
| post-lint replay v3+PGO CLI | `1cf9b1dc5c162760787fb3fe003fbcbcccf132c4a1f753376996ac871c5275af` | SSE2+SSE4.2+AVX2+FMA | `3dbce2b2fca971cacd1963d0aaeb867de10417761624a0c1236d01a6880860db` |

All three processes reported AVX2+FMA available at runtime. The merged
28,739,968-byte profile was generated from 518 run-prefixed raw profiles. The
checked-in 64 MiB fixture constrained the corpus to 6,000 creates, 1,000,000
lookups, 2,000 renames, 2,000 deletes, and one walk; those are the shipping
script's workload families at scaled counts, not a claim of byte identity with
an older opaque training profile.

One parent invocation then ran 31 alternating `AAB`/`BAA` rounds, where A/A was
generic/generic and A/B was the midpoint of those controls versus v3+PGO. Each
observation performed 200,000 lookups on the same 8,003-entry image. The image
SHA-256 was
`7fab3cc32b282ef9a23ef5afb222cd472fc7f3751f630f6848ff46e96c9503a6`;
every arm returned the exact signature
`lookupbench: 200000 lookups in / (8003 entries) -> 200000`.

| statistic | result |
|---|---:|
| generic median wall time | 21,667 us |
| v3+PGO median wall time | 15,110 us |
| generic/generic A/A | 0.994371x, 95% CI [0.974583, 1.005166] |
| symmetric A/A null floor | 1.026080x |
| pre-registered twice-null threshold | 1.052840x |
| generic/v3+PGO | **1.437700x**, 95% CI **[1.414742, 1.494961]** |
| decision | **PGO_FASTER** |

This is a wall-clock result, not an instruction-count inference. The
deterministic 20,000-resample paired bootstrap median CI was the only decision
gate; CV was not computed.

After lint-driven helper extraction, the exact staged harness rebuilt the
profile-use CLI and replayed the full gate rather than relying on compilation
alone. The rebuilt ELF above again consumed the same profile and returned the
same input SHA and output signature. Generic median was 21,410 us, v3+PGO
median was 14,266 us, and generic/v3+PGO was **1.495236x**, 95% CI
**[1.459215, 1.520699]**. Its A/A was 1.032385x, CI
**[1.008930, 1.059704]**, giving a symmetric null floor of 1.059704x and a
twice-null threshold of 1.122973x. The real lower bound cleared that
invocation's own threshold. This confirmation is separately admissible; it
does not replace the first measurement with a pooled estimate.

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
word→SIMD REJECT). The historical instruction magnitude is measured, but it cannot be
converted into the same wall-clock speedup.

The new whole-binary wall-clock pairs show why no universal direction is admissible:

| benchmark | generic ratio, median CI | v3 ratio, median CI | v3 ratio shift |
|---|---:|---:|---:|
| inode allocator scan/cursor | 12.445408× [12.348123, 12.495432] | 13.631067× [13.452977, 13.759302] | **+9.53%** |
| JBD2 scalar/grouped writer | 2.630522× [2.623337, 2.643932] | 2.605531× [2.597625, 2.618523] | **−0.95%** |

Each invocation included an A/A null control whose median CI contained 1.0, exact
semantic parity, and a median-CI gate. The allocator ratio grew; the JBD2 ratio shrank.
ISA effects are workload-dependent.

---

## 2. Re-stating the affected claims

Every published ratio falls into one of three classes, and the correction differs by class.

### Class A — "FrankenFS beats the kernel by N×" (wins)

Examples: allocator range-overlap **3110×**, journal replay **2024×**, extent
coalescing **120×**, incremental crc32c **24.7×**, rmdir dir-emptiness, htree lookup.

The historical ratios remain measurements of their named generic ELF, but the
earlier inference that the shipped advantage is necessarily **at least** N× is
withdrawn. Changing code generation can improve candidate and control paths by
different amounts; the fresh JBD2 internal ratio shrank by 0.95% under v3.
Quote these as *"N× on the recorded baseline-ISA ELF"*. The new lookup result
certifies only generic-versus-v3+PGO FrankenFS lookup wall time; because it has
no mounted-kernel arm, it does not restate any kernel ratio.

### Class B — "FrankenFS is N× slower than the kernel" (losses)

Examples: parallel metadata writes **8.3× slower at 8 threads**, multi-file parallel
read **~2.9× slower**, mounted small-file create storm **4.599×**.

The earlier blanket statement that these losses are **overstated** is also
withdrawn. The historical `create-bench` experiment below is evidence that one
named loss shrank, and the exact lookup gate proves a 1.437700x effect for its
named corpus. Neither licenses the same conclusion for every loss. No loss
should be called structural or irreducible on the strength of a baseline-ISA
measurement, and no correction factor should be applied without a
workload-matched whole-binary rerun.

### Class C — internal A/B (candidate vs control, one binary)

Examples: the 2026-07-25 wait-free publication gate **1.70–2.11× at 8 threads**, and
essentially every KEEP/REJECT row in `docs/progress/perf-negative-results.md`.

Both arms come from the same ELF, so the ratio stands as a measurement of that ELF.
What does not transfer automatically is its magnitude on another binary. The two fresh
pairs demonstrate both directions: allocator grew 9.53%, while JBD2 shrank 0.95%.
Generic-ELF KEEP/REJECT decisions remain historical evidence, not shipped-binary
claims.

`bd-bhh0i` was completed separately. This audit neither re-derives nor changes
that cutover result.

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

The product remains whatever `scripts/build-perf.sh` produces: release-perf,
`target-cpu=x86-64-v3`, and PGO. The fleet change does not silently make ordinary
Cargo builds production-identical. It only makes v3 benchmark reruns schedulable.

**And make the mismatch unpublishable either way:**

1. **Every bench binary self-reports its executing ELF SHA-256 and codegen ISA.**
   One `cfg!(target_feature = ...)` line per binary is the minimum ISA witness.
2. **Admissibility rule (new):** a performance ratio may not be published from a bench
   run whose output lacks a `codegen_isa` line. A ratio whose `compile_avx2` differs
   from the shipped configuration must carry the class-A/B/C qualifier above.
3. **Building the v3/no-PGO half through RCH** requires explicit environment
   forwarding:
   ```
   RUSTFLAGS="-C target-cpu=x86-64-v3" \
   RCH_ENV_ALLOWLIST=RUSTFLAGS \
   RCH_REQUIRE_REMOTE=1 \
   env -u CARGO_TARGET_DIR rch --no-self-healing exec -- \
     cargo bench --profile release-perf …
   ```
   The route must first show `-C target-cpu=x86-64-v3` in remote verbose compiler
   output, and the executing binary must report AVX2+FMA. A distinct SHA alone does not
   prove v3. Exact shipped identity additionally requires the PGO stage from
   `scripts/build-perf.sh`, and the executing binary must print the SHA-256 of
   the merged profile it consumed. The script now embeds that profile SHA and
   executes its hidden `bench-evidence` command after the final build. It also
   refuses to retrain into a non-empty profile directory or reuse a missing
   profile, so stale profile mixing fails closed without recursive deletion.
4. **Do not gate on instruction count for an ISA A/B.** An ISA change retires more work
   per instruction, so fewer instructions is the mechanism, not a neutral proxy. Gate on
   wall/cycles (campaign §2.6).

---

## 4. Measured residual and remaining gap

An earlier revision said the wall-clock size of the gap was wholly unmeasured.
`docs/NEGATIVE_EVIDENCE.md` (bd-b9dug, 2026-07-11) already carried an interleaved A/B
of a production-ISA `create-bench` against the default build:

> v3 is **1.18–1.40× faster** in absolute throughput at every thread count
> (t1 74k→93k, t8 46k→54k), so the benchmark binary **UNDERSTATES production** and the
> "8.3×@8t" gap is inflated.

That experiment remains useful for its named workload, but it compared
`v3 + opt-3 + fat-LTO` with the default `release` profile (`opt-level="z"`), so it
conflated profile, LTO, and ISA.

The fresh pairs isolate generic release-perf versus v3 release-perf:

| benchmark arm | generic normalized median | v3 normalized median | observed change |
|---|---:|---:|---:|
| allocator full scan | 492.435 µs | 490.833 µs | 0.33% faster |
| allocator cursor | 39.614 µs | 36.296 µs | 9.14% faster |
| JBD2 scalar | 4.401601 ms | 4.373304 ms | 0.65% faster |
| JBD2 grouped | 1.670168 ms | 1.680029 ms | 0.59% slower |

These are same-source, same-worker, pinned whole-binary observations. Each
candidate/control decision is supported by its invocation's median CI; the absolute
cross-binary medians are not promoted into a universal correction factor.

Exact production-shaped v3+PGO identity is now closed for the 8,003-entry lookup
workload: generic/v3+PGO was 1.437700x with CI [1.414742, 1.494961], while its
A/A CI contained 1.0. Everything else remains open by workload, including
mounted-kernel lookup and all create/read/rename/delete/kernel ratios.

**Retry predicate for another claim:** train and build the production PGO
binary from the same source, embed and print the consumed profile SHA, record
the executing ELF SHA and AVX2+FMA witness, then compare the same
parity-checked workload on the same pinned worker with a same-invocation A/A
null. Gate on a wall/cycles bootstrap median CI clearing twice its own null
log-margin, never CV or instruction count. For a kernel claim, include the
mounted-kernel arm; the CLI-only lookup result cannot substitute for it.
