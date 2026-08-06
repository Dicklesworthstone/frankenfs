# Mounted-kernel scorecard: FrankenFS FUSE against the incumbent, Linux kernel ext4

**Date:** 2026-07-30 · **Host:** `thinkstation1`, AMD Ryzen Threadripper PRO 5975WX,
32C/64T, 231.7 GB RAM, 1 NUMA node · **Kernel:** 6.17.0-35-generic · **Bead:** `bd-opb6l`

The incumbent is **in-kernel ext4**, not a previous FrankenFS build. Every ratio below
is a direct competitive measurement taken inside **one invocation**, on **one host**,
from **one fixture's bytes**, against **four independent live mounts** (`kernel_a`,
`kernel_b`, `fuse_a`, `fuse_b`) under matched mount options, arranged as a four-round
Latin-square physical-arm crossover. Every row carries **two same-invocation A/A null
controls** — one per filesystem type — and both are printed. A ratio above `1.0` means
FrankenFS is **slower** than the kernel.

All eight ext4 surfaces now score. **0 wins / 7 losses / 1 neutral / 0 unscored.**
(Warm stat added 2026-08-04 — it was the one shape btrfs banked and ext4 did not.
Xattr get/list report and bulk durable write added 2026-08-05,
bd-ext4-xattr-row-unscored-a21dz and bd-bulk-durable-write-unscored-orfck — the harness
could already run both and neither scorecard carried either.)

## The rows

| Workload (the job as timed) | FrankenFS ÷ kernel ext4, bootstrap median 95% CI | Kernel A/A null | FUSE A/A null | Governor / EPP on every involved CPU | Worker threads requested → observed | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| **Large-directory readdir+stat** — enumerate 32,768 zero-byte entries, then 8 workers stat every entry exactly once (ro) | **`4.967448x` `[4.946319, 4.989285]` slower** (clears its twice-null margin of `1.016968x`) | `1.000904x [0.996822, 1.008448]`, spread `1.008448x` | `0.998792x [0.997503, 1.000626]`, spread `1.002503x` | `amd-pstate-epp` / `powersave` / `balance_performance` | **8 → 8** on all four arms, pinning attested | **LOSE** |
| **Small-file create/delete storm** — serially create 2,000 empty files, fsync the parent, delete all 2,000, fsync again | **`2.753659x` `[2.707500, 2.782302]` slower** (twice-null margin `1.029449x`) | `0.996217x [0.985593, 1.007951]`, spread `1.014618x` | `0.995167x [0.988305, 1.004712]`, spread `1.011833x` | `amd-pstate-epp` / `powersave` / `balance_performance` | **1 → 1** on all four arms, pinning attested | **LOSE** |
| **Multi-file parallel read** — enumerate and byte-sort 256 × 256 KiB files, then 8 workers `pread` every file exactly once (ro) | **`1.287862x` `[1.269319, 1.307285]` slower** (twice-null margin `1.036157x`) | `1.003293x [0.982553, 1.016450]`, spread `1.017757x` | `0.994130x [0.982397, 1.002347]`, spread `1.017918x` | `amd-pstate-epp` / `powersave` / `balance_performance` | **8 → 8** on all four arms, pinning attested | **LOSE** |
| **Fsync/journal commit** — 8 × 4 KiB positioned writes to one file, `fsync` after each | `0.997098x [0.990808, 1.009108]` against a twice-null margin of **`1.030661x`**; `directional_claim_clear=false` | `1.001860x [0.991465, 1.004642]`, spread `1.008609x` | `0.997807x [0.991484, 1.015215]`, spread `1.015215x` | `amd-pstate-epp` / `powersave` / `balance_performance` | **1 → 1** on all four arms, pinning attested | **NEUTRAL** |
| **Parallel metadata writes** — 8 workers create exactly 512 empty files into private directories, then fsync every worker directory (**128 crossover blocks**) | **`1.510822x` `[1.493097, 1.539011]` slower** (twice-null margin `1.049223x`); replicated on a **disjoint CPU set** at `1.513052x [1.490837, 1.534711]`, agreeing to **0.15%** | `1.007184x [0.998479, 1.024316]`, spread `1.024316x` · replicate `0.998642x [0.990286, 1.009556]`, spread `1.009809x` | `0.995707x [0.978797, 1.000111]`, spread `1.021662x` · replicate `0.998780x [0.990819, 1.002688]`, spread `1.009266x` | `amd-pstate-epp` / `powersave` / **`performance`** (host EPP differed in this window; uniform across both metadata runs) | **8 → 8** on all four arms, pinning attested | **LOSE** |
| **Warm stat** — issue 2,000 `stat` calls against one mounted file and aggregate the metadata (ro) | **`4.812194x` `[4.779087, 4.819425]` slower** (twice-null margin `1.035698x`) | `1.002547x` | `1.000593x` | `amd-pstate-epp` / **`performance`** / `performance` (uniform, no mixed-governor warning) | **1 → 1** on all four arms, pinning attested | **LOSE** |
| **Xattr get/list report** — repeat 2,000 five-call reports: read one inline value, read one external-block value, check one absent name, list one name, list 24 names (ro) | **`5.749816x` `[5.725990, 5.756846]` slower** (twice-null margin `1.009130x`) | `0.999678x [0.996487, 1.002264]`, spread `1.003525x` | `1.000266x [0.995466, 1.001873]`, spread `1.004555x` | `amd-pstate-epp` / **`performance`** / `performance` (uniform, no mixed-governor warning) | **1 → 1** on all four arms, pinning attested | **LOSE** |
| **Bulk durable write** — overwrite one preallocated 64 MiB file with 64 sequential 1 MiB positioned writes, then one file `fsync` (**2,048 pairs / 512 crossover blocks**) | **`2.898298x` `[2.874382, 2.920502]` slower** (twice-null margin `1.035235x`) | `1.001588x [0.997161, 1.009249]`, spread `1.009249x` | `0.989118x [0.982835, 0.994415]`, spread `1.017465x` | `amd-pstate-epp` / **`performance`** / `performance` (uniform, no mixed-governor warning) | **1 → 1** on all four arms, pinning attested | **LOSE** |

Admission required, per row: both A/A symmetric spreads at most `1.025x` with intervals
containing `1.0`; the effect clearing **twice the widest null log-margin**; exact
four-arm tree and content parity; and a clean offline `e2fsck` after unmount. All five
rows satisfied all four. Wall time was the gate throughout — `cv_used=false`,
`instructions_used=false` — over deterministic 20,000-resample bootstrap median CIs.

**The xattr row was measured later than the rest and does not share their window.** It was
taken 2026-08-05 on kernel `6.17.0-41-generic` (the other rows: `6.17.0-35-generic`) with
candidate ELF `bcf2bc80f02154aa16681b87c64e1beddab996b20cc0bb5ec911b5743133c9d1`, PGO
profile `5c6530a0261f658ed0ace2a9d8bef7c6c63b6f94b4b955e4f7ccba038e011e96`, 32 pairs / 8
crossover blocks, `observation_reducer=min` over 3 repeats. Its own kernel arm is live in
its own invocation, so the ratio stands on its own; it is **not** pooled with the rows
above and must not be diffed against them as if one window produced both.

**Btrfs: UNRUNNABLE for this workload, by the harness's own refusal**, not by omission —
`xattr-get-list-report currently requires --filesystem ext4 because its inline/external
storage-shape proof is ext4-specific`. Recorded the way the btrfs fsync row was.

**The bulk durable write row also stands in its own window** (2026-08-05, kernel
`6.17.0-41-generic`, candidate ELF `bcf2bc80…`), and it needed **2,048 pairs** to be
admitted: this workload's variance is the durability boundary itself, since a mutating
workload is forced to `--observation-repeats 1` and has no min-of-3 to lean on. The
progression is worth recording so nobody re-derives it — 32 pairs blocked on both null
medians, 64 pairs fixed the medians but left spreads at `1.034978`/`1.053581`, 512 pairs
reached `1.021700`/`1.027309` (still over the `1.025` limit by a hair), and 2,048 pairs
cleared at `1.009249`/`1.017465`.

⚠ **This row is `2.898298x` where the 2026-07-31 ledger row measured `2.201986x`** for the
same job shape — about **32% worse**. Different candidate ELF, different kernel, different
window, so it is *not* proof of a regression, but it is the same instrument and contract on
both sides and the gap is far outside either interval. Filed as `bd-2i2ez` to be resolved by
measurement rather than assumed either way. The older figure should not be quoted as current.

**Btrfs bulk durable write: UNRUNNABLE — and unlike the xattr row, by a DEFECT, not a
policy.** The btrfs arm dies before any measurement with `fsync bulk durable workload
…/btrfs/fuse_a/bulk-durable.bin: Invalid argument (os error 22)`, while the ext4 arm of the
identical invocation completes. Filed as `bd-cjqhh`; the row stays unscored on btrfs until
that EINVAL is fixed or proven to be a legitimate unsupported-operation answer.

## One sentence per row

- **Large-directory readdir+stat: we lose.** The kernel finishes the same 32,768-entry
  stat sweep about five times faster, and this is the worst surface we have measured.
- **Small-file create/delete storm: we lose.** Creating and deleting 2,000 files with
  two directory fsyncs takes us about 2.75 times as long as ext4.
- **Multi-file parallel read: we lose.** Even on warm-cache reads of 256 files across 8
  threads, our narrowest gap, we are still about 29% slower.
- **Fsync/journal commit: we neither win nor lose.** The measured `0.997098x` is a tie —
  it sits well inside the twice-null margin, so we are declaring no effect, not a win.
- **Warm stat: we lose, and not because of btrfs.** About 4.81 times slower — the kernel
  takes 4.42 ms for 2,000 warm `stat` calls where we take 21.30 ms. The btrfs bank measures the same shape
  at `4.977803x`, so the two agree to within 3.4%: this loss is the shared per-request
  FUSE floor, not btrfs inode lookup. That matters for where to spend effort — and it
  means the btrfs readdir+stat excess over ext4 (`8.32x` vs `4.97x`) is the part that
  really is btrfs-specific.
- **Parallel metadata writes: we lose.** Eight workers creating 512 files and fsyncing
  their directories run about 1.51 times slower than ext4, reproduced twice on disjoint
  CPU sets.

## Numbers that are withdrawn and must not be restated

- **The `8.3x` parallel-metadata figure is folklore and is retired.** It came from
  *separate* runs, never from a matched same-invocation comparison, and no instrument
  that produced it survives. The honest, admitted figure for that workload is
  **`1.512x` slower**.
- **`1.942477x` for parallel metadata writes is withdrawn.** It was overstated by about
  28% relative to the two admitted 128-block runs, and it came from a run whose kernel
  arm drifted `2.64x` within itself.
- **The fsync `1.005153x` win is withdrawn, not softened.** Re-measured it is
  `0.997098x` with `directional_claim_clear=false`; it was always a sub-null-margin
  effect.

Two of the losses got **worse**, not better, once the instrument was correct: readdir
moved `4.212274x → 4.967448x` and read moved `1.203230x → 1.287862x`. Pinning made the
*kernel* arm faster by preserving locality, so a correct instrument flatters the
incumbent. Storm moved the other way, `2.957531x → 2.753659x`.

## Diagnostic side numbers (recorded, never a gate)

`gate_input=false` for every value in this table. They are here so the ratios can be
sanity-checked against absolute time, not to support any claim.

| Workload | Kernel median batch | FrankenFS median batch |
| --- | --- | --- |
| Large-directory readdir+stat, 32,768 entries | 22.84 ms | 113.44 ms |
| Small-file create/delete storm, 2,000 files | 100.99 ms | 276.60 ms |
| Multi-file parallel read, 256 × 256 KiB | 3.11 ms | 4.01 ms |
| Fsync/journal commit, 8 × 4 KiB | 145.49 ms | 145.08 ms |
| Parallel metadata writes, 512 creates | 29.30 ms | 42.31 ms |

## Replication

- **readdir** replicated at `5.026341x` on a second driver ELF in a second window,
  within **1.2%** of the banked `4.967448x`.
- **storm** replicated **3/3** on a single driver ELF at `2.760102x`, `2.780381x`,
  `2.795147x`, reproducing within **1.3%**.
- **parallel metadata writes** replicated on a **disjoint** CPU set
  (`24,25,26,29,31,56,59,60` versus `0,1,5,6,33,34,35,39`) at `1.513052x`, agreeing with
  the banked `1.510822x` to **0.15%**.
- **read** and **fsync** are each one admitted run at this exact shape.

## Provenance of the warm-stat row (2026-08-04, differs from the other five)

Candidate ELF `9e32e28f766368dd738c7d43e2d4f820a426394b0d1e72b6e565be622835408a`
(x86-64-v3, PGO profile `5c6530a0261f658ed0ace2a9d8bef7c6c63b6f94b4b955e4f7ccba038e011e96`),
driver ELF `8c1c4d35fd0a348e5e612d904f086567a4bd9f03a800127ff1ebedb6a2f2633f`, both
self-hashed in process. `pairs=32`, `observation-repeats=3` reduced by `min`, parity
`pass`, post-unmount `e2fsck` clean, `--placement-scope same-llc`.

**This row's candidate is NOT the frozen `f44b3dc4…` / PGO `6a22cfcf…` the other five use** —
it is a freshly trained profile, so the warm-stat number is not byte-identical-candidate
comparable with them. It is directly comparable with the btrfs warm-stat row, which is the
comparison it was taken for. Unlike the other five it also ran with every CPU on the
`performance` governor, so it carries no mixed-governor warning.

## Scope and limits of these five claims

- **Provenance.** Candidate ELF
  `f44b3dc40b987f36c19a64dfdded3b1890a105cd26a3098cee46eee2b3540349` (x86-64-v3, PGO
  profile `6a22cfcf…`, built on `vmi1167313`); driver ELF `75b400a9…` for the first four
  rows and `8c357460…` for both metadata rows, both built on `hz1`. Every arm
  self-hashed in process. Reports live under
  `/data/tmp/frankenfs-mounted-kernel-nullfix/run_*/mounted-kernel-report.json`
  (schema v5).
- **Placement scope was `same_llc`, not host-wide.** `host_wide_quiescence` reads
  `not_applicable` on all five rows: the sustained five-consecutive-one-second host-wide
  quiet gate exists in the harness but only engages under `--placement-scope host-wide`,
  and it did not gate these runs. What did apply on every row: per-CPU busy fractions
  averaged over a **full one-second** interval, driver and FUSE busy-limit checks, SMT
  sibling guards on both, same-LLC placement, and a 1,000 ms pre-measurement settle.
- **What the one host-wide-scoped window says about that caveat.** The 2026-07-29
  governor-attested runs *did* run `--placement-scope host-wide` with the sustained
  five-consecutive-one-second gate clearing (`samples_observed` 106 and 55). Only
  **storm** was admitted there, at `2.691204x [2.675323, 2.717540]` and
  `2.676393x [2.657974, 2.701633]` — same verdict as the row published above and within
  about 3% of its `2.753659x`. That is corroboration of direction and rough magnitude,
  **not** a controlled scope comparison: those runs used a different candidate
  (`93ed…` / PGO `1410…`) and a different driver, and they predate worker pinning, which
  is why read and readdir were `blocked_null` in the same window. No host-wide-scoped
  admitted row exists for any of the other four workloads.
- **The governor was recorded, not set.** All 64 CPUs ran `amd-pstate-epp` with the
  `powersave` governor; the host is shared with other agents, so it was deliberately
  left alone and `non_performance_or_mixed_governor_warning=true` is carried on every
  row. EPP was uniform across the CPUs each row actually used, but it was
  `balance_performance` for the first four rows and `performance` for the two metadata
  runs, because the host-wide setting changed between the two windows.
- **These are not the frozen-candidate host-wide rerun.** A separate assignment in
  thread `bd-kdmu4` calls for the original shapes re-run with candidate `93ed…` / PGO
  profile `1410…` under `--placement-scope host-wide`. These five rows use candidate
  `f44b…` / PGO `6a22…` — the same profile the 2026-07-27 rows used, which is what makes
  this bank comparable to what it replaces. They are the current pinned bank, and the
  schema-v6 gate correction landed in `2198a47d` leaves their score unchanged.
- **Scope of the claims.** Each row applies only to its recorded operation count, thread
  count, durability shape, mount options, warm-cache regime, host, and ISA. Do not
  generalize any of them to other working sets, thread counts, or hardware.

## Retry predicate

Re-measure only with every timed thread — driver included — bound to one CPU, at least
32 crossover blocks (**128** for parallel metadata writes, which does not resolve at
32), both A/A spreads at most `1.025x`, the effect clearing twice its own null
log-margin, exact four-arm parity, and clean `e2fsck`. Never pool the blocked
`1.509x`–`1.688x` metadata estimates, and never restate `1.942477x`, the withdrawn fsync
`1.005153x` win, or the `8.3x` folklore.
