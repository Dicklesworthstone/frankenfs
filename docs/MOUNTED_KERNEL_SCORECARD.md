# Mounted-kernel scorecard: FrankenFS FUSE against the incumbent, Linux kernel ext4

> ## ⛔ FOUR ROWS DESCRIBE FRANKENFS AT `HEAD`. THE OTHER FOUR DO NOT.
>
> **readdir+stat, parallel read and warm stat were re-measured 2026-08-08** on candidate
> `913c36a4…` (PGO `b30de364…`, x86-64-v3 attested) — each twice, all admitted, the last of
> them under the during-run external-load gate (`bd-bt2dy`). **Every other row here was
> measured on an ELF that predates the current tree** and none has been re-measured. The
> provenance, row by row:
>
> | Rows | Candidate ELF | Measured |
> | --- | --- | --- |
> | **readdir+stat**, **parallel read**, **warm stat** | **`913c36a4…`** | **2026-08-08 (current)** |
| **create/delete storm** | **`edbaeb4e…`** | **2026-08-08 (current, post-`bd-pbyu0` fix)** |
> | fsync/journal, parallel metadata | `f44b3dc4…` | 2026-07-30/31 |
> > | Xattr get/list report, bulk durable write | `bcf2bc80…` | 2026-08-05 |
>
> ⛔ **ALL FOUR WRITE ROWS ALSO PREDATE THE 2026-08-17 EXT4 WRITE-PATH WORK** — create/delete
> storm, bulk durable write, parallel metadata writes and fsync/journal commit. `bd-fv9tc`
> landed that day and is measured, in exact integers with both arms in one invocation, to take
> ext4 from **5.00 to 3.00 blocks written per client fsync** against kernel ext4's 4.00 — i.e.
> write amplification `1.250x` -> `0.750x`, so FrankenFS now writes FEWER bytes than kernel
> ext4 per durability boundary. It coalesced the group-descriptor flush by descriptor block
> (it had been issuing one device write per GROUP, with 64 groups sharing a block) and stopped
> writing the superblock on a boundary that changed no free count.
>
> The same class of work moved the btrfs side hard: two btrfs rows changed SIGN on 2026-08-17
> (fsync/journal commit and parallel metadata writes — see the
> [btrfs scorecard](MOUNTED_BTRFS_SCORECARD.md)). The ext4 lever is much smaller (1.67x fewer
> metadata blocks per boundary, against btrfs's ~16x), so expect smaller movement and no sign
> change on the large losses — but **none of these four figures should be quoted as "FrankenFS
> today" until re-measured**. Tracked as `bd-jgq8e`.
>
> ⚠ The re-measured readdir+stat row is **not** comparable with the other seven as if one
> window produced them: it uses a freshly trained PGO profile (`b30de364…`, not the bank's
> `5c6530a0…` — the banked profile was destroyed, see `bd-v0igv`), a different kernel, and a
> corrected fixture. It supersedes its own predecessor; it does not re-baseline the others.
>
> Since the newest of the **stale** rows, **three btrfs correctness commits have landed** —
> `839eb708` (durable commit could not serialize its own leaves: `fsync` EINVAL and a failed
> unmount flush, so data was never persisted), `241093de` and `9d64f4a1` (a write that failed
> with ENOSPC destroyed the data it could not replace), and `7fac4779` (extent splits
> reference the shared extent instead of copying it, which removes a read and an allocation
> from every overwrite-split). The last of those changes the write path's I/O profile, so it
> can move those numbers in either direction.
>
> **Therefore: no figure below EXCEPT readdir+stat, parallel read, warm stat and create/delete
> storm may be presented as "FrankenFS today" until it is re-measured on a current ELF.** Quote
> the rest as historical, with their ELF, or not at all. This is not a hedge about precision —
> it is that the binary those four describe no longer exists in the tree.
>
> ⚠ **Every MUTATING row banked before 2026-08-08 was measured with the `bd-bhh0i` sharded
> create path active, which leaked one inode per delete from the group-descriptor counters
> (`bd-pbyu0`, now defaulted off).** Storm has been re-measured on the fixed candidate;
> **fsync/journal, parallel metadata and bulk durable write have not**, and were taken on a
> filesystem whose inode accounting was drifting mid-run. The read-only rows never mount
> `--rw` and are unaffected.

> ## ⚠ A CLEAR PREFLIGHT IS NOT EVIDENCE OF COMPARABILITY (`bd-4sull`)
>
> `core_contention_preflight … verdict=clear` certifies that **no competing load sat on the
> placement CPUs at the moment sampling started**. It does not certify that a run is
> comparable to a *previously banked* one, and it must never be cited as if it did.
>
> Measured, not argued: two 2,048-pair runs of the **identical** candidate ELF, PGO, kernel
> and governor both printed `verdict=clear` with five consecutive clear samples and
> `driver_busy_fraction=0.000000` — and the incumbent arm still moved **8.26%** between them
> (77.31 ms → 83.69 ms), carrying the published ratio from `2.898298x` to `2.655365x`, a
> 9.15% swing with non-overlapping intervals and roughly 3x the row's own admission margin.
> FrankenFS's own arm moved −1.30%. The entire difference was the incumbent.
>
> The gate cannot see this by construction: it samples CPU busy fractions on the placement
> CPUs immediately before the run, so it is blind to page-cache state, writeback backlog,
> thermal and boost history, and everything else that carries across invocation boundaries.
>
> ⭐ **2026-08-08: this was demonstrated flipping a verdict, not merely shifting a ratio.**
> Two btrfs parallel-read runs, same ELF and same fixture, minutes apart, both
> `verdict=clear`, returned `1.019622x` NEUTRAL and `0.961107x` WIN — non-overlapping
> intervals, `6.09%` spread. A peer's `pytest` was running on CPUs *outside* the placement
> set; the placement CPUs were genuinely idle (max busy `0.020`), so the gate was **correct**
> and still useless, because bandwidth, LLC and boost budget are socket-wide. Re-run in a
> window whose external load was sampled every 3 s throughout, the row is a stable win 2/2
> (`0.893282x`, `0.927352x`, spread `3.81%`).
>
> ✅ **FIXED (`bd-bt2dy`, 2026-08-08).** The harness now samples external load for the whole
> measured region and **fails closed**, and every report carries an `external_load_during_run`
> block whether clean or not — so a row banked from here on can be disqualified by a later
> reader without re-running it. Verified both ways on live runs: a quiet box passes
> (`samples=37, max_external_busy_cpus=2, verdict=clear`), and four off-placement CPUs pinned
> at 100% are refused (`23/23 samples over limit, verdict=CONTENDED`). In that refused run the
> **pre-run gate saw the placement CPUs at `0.011` busy and would have declared the window
> clear** — the exact failure, reproduced deliberately and caught. ⚠ Rows banked BEFORE this
> carry no such block, and its absence is itself informative.
>
> **The rule, which applies to every banked row in every repo, not just this file:**
> a row's A/A nulls and twice-null margin bound **within-invocation** error only. Cross-window
> reproducibility is a *separate, unmeasured* quantity unless a second same-ELF run exists.
> Where one does, quote the observed spread; where none does, quote the worst spread the
> campaign has measured. Eight same-ELF figures now exist: **4.71%** on one workload,
> **9.15%** on bulk durable write, **2.73%** on ext4 readdir+stat, **1.36%** on btrfs
> readdir+stat, **0.83%** on ext4 parallel read, **6.09%** on btrfs parallel read under
> co-tenant load and **3.81%** on the same row in a quiet window, **1.08%** on ext4 warm stat
> and **0.69%** on btrfs warm stat (all the 2026-08-08 ones banked *with* their spread rather
> than having it discovered later). A later measurement that disagrees with a banked row by less than that
> is **not** a regression, an improvement, or a disagreement — it is unresolved.
>
> **The readdir+stat pair is the cleanest demonstration of why this rule exists.** Two
> back-to-back admitted runs of the identical ELF, both `verdict=clear`, measured `4.052605x`
> and `4.163402x`. That **2.73%** spread is larger than run 1's own CI width (**1.84%**) and
> larger than its twice-null admission margin (**3.24%** — comparable, and the intervals
> barely overlap at all). And the split repeats the campaign's pattern: the incumbent arm
> moved **−3.40%** between the two runs while FrankenFS moved **−1.19%**. Since these ran
> back-to-back they share thermal and cache history, so 2.73% is a **lower bound** on this
> row's true cross-window spread, not a measurement of it.
>
> ⚠ **Two things this file said earlier, both now corrected by more data.**
>
> First, "the variance is the incumbent's" is **not** a law. The btrfs readdir+stat pair, run
> minutes later on the same box, spread **1.36%** with the incumbent essentially flat
> (`+0.09%`) and **our** arm carrying it (`−0.90%`) — the reverse split.
>
> Second, and this corrects a claim published in `4f4410a8`: it is **not** true that the
> cross-run spread always exceeds the within-invocation CI. Three measured pairs:
>
> | Pair | Spread | Run-1 CI width | Spread exceeds CI? |
> | --- | --- | --- | --- |
> | ext4 readdir+stat | 2.73% | 1.84% | yes |
> | btrfs readdir+stat | 1.36% | 0.40% | yes |
> | ext4 parallel read | 0.83% | 0.86% | **no** |
> | ext4 warm stat | 1.08% | 0.88% | yes |
> | btrfs warm stat | 0.69% | 1.37% | **no** |
>
> So the spread is *often* the larger quantity but not reliably, and neither number bounds the
> other. That is not a weakening of the rule — it is the reason the rule is stated as
> **quote `max(CI, measured spread)`**, which is correct in both directions and needs no
> assumption about which dominates.
>
> **The incumbent's own drift is larger than either figure.** Across three gate-clear windows
> on one kernel, the kernel ext4 arm of the bulk-durable-write shape moved 77.31 → 83.69 →
> 91.43 ms, **`+18.3%`**, while FrankenFS held 225.31 / 222.39 / 222.22 ms (`1.4%`). Since a
> ratio row is a quotient, that is the floor on how much a re-run can differ from a banked row
> for reasons that have nothing to do with our code. Recorded absolute arm medians are what
> make this decomposable — see the required-per-row table below.

**Date:** 2026-07-30 · **Host:** `thinkstation1`, AMD Ryzen Threadripper PRO 5975WX,
32C/64T, 231.7 GB RAM, 1 NUMA node · **Kernel:** 6.17.0-35-generic · **Bead:** `bd-opb6l`

The incumbent is **in-kernel ext4**, not a previous FrankenFS build. Every ratio below
is a direct competitive measurement taken inside **one invocation**, on **one host**,
from **one fixture's bytes**, against **four independent live mounts** (`kernel_a`,
`kernel_b`, `fuse_a`, `fuse_b`) under matched mount options, arranged as a four-round
Latin-square physical-arm crossover. Every row carries **two same-invocation A/A null
controls** — one per filesystem type — and both are printed. A ratio above `1.0` means
FrankenFS is **slower** than the kernel.

All eight ext4 surfaces now score. **0 wins / 6 losses / 2 neutral / 0 unscored** — parallel
read moved from LOSE to NEUTRAL on re-measurement (2026-08-08); see the row for why that is
not a FrankenFS improvement story.
(Warm stat added 2026-08-04 — it was the one shape btrfs banked and ext4 did not.
Xattr get/list report and bulk durable write added 2026-08-05,
bd-ext4-xattr-row-unscored-a21dz and bd-bulk-durable-write-unscored-orfck — the harness
could already run both and neither scorecard carried either.)

## The rows

| Workload (the job as timed) | FrankenFS ÷ kernel ext4, bootstrap median 95% CI | Kernel A/A null | FUSE A/A null | Governor / EPP on every involved CPU | Worker threads requested → observed | Verdict |
| --- | --- | --- | --- | --- | --- | --- |
| **Large-directory readdir+stat** — enumerate 32,768 zero-byte entries, then 8 workers stat every entry exactly once (ro) | **≈`4.1x` slower** — two admitted same-ELF runs, `4.052605x [4.034231, 4.108783]` and `4.163402x [4.106308, 4.196759]`, margins `1.032372x`/`1.038028x`. **Quote the `2.73%` spread, not either CI.** ⛔ SUPERSEDES the pre-`bd-plkzd` `4.967448x`, measured on an unindexed fixture | run 1 `1.006371x [0.998838, 1.016057]` · run 2 `1.005559x [0.981512, 1.010438]` | run 1 `1.001235x [0.999309, 1.003556]` · run 2 `0.999527x [0.997275, 1.008144]` | `amd-pstate-epp` / **`performance`** / `performance` (uniform, no mixed-governor warning) | **8 → 8** on all four arms, pinning attested | **LOSE** |
| **Small-file create/delete storm** — serially create 2,000 empty files, fsync the parent, delete all 2,000, fsync again | **`2.862033x` `[2.724405, 2.888338]` slower** (twice-null margin `1.048084x`), re-measured 2026-08-08 on candidate `edbaeb4e…`. ⛔ SUPERSEDES `2.753659x`. ⚠ **ONE admitted run — no pair yet**, so quote it to the campaign's worst measured spread, not this CI. A second run measured `2.869817x` (0.27% away) but was `BLOCKED_NULL` and is corroboration only | `0.999400x` (run 2, blocked) | `1.003846x` (run 2, blocked) | `amd-pstate-epp` / **`performance`** / `performance` | **1 → 1** on all four arms, pinning attested | **LOSE** |
| **Multi-file parallel read** — enumerate and byte-sort 256 × 256 KiB files, then 8 workers `pread` every file exactly once (ro) | **≈`0.98x` — a TIE, not a win.** Two admitted same-ELF runs, `0.986316x [0.981390, 0.989874]` and `0.978203x [0.968511, 0.981821]`; neither clears its margin (`1.016961x`/`1.020212x`), `directional_claim_clear=false` on both. Spread `0.83%`. ⛔ SUPERSEDES `1.287862x`, measured on an unindexed fixture and a since-destroyed ELF | run 1 `0.995873x [0.991626, 1.005511]` · run 2 `1.004181x [0.993028, 1.010056]` | run 1 `1.000388x [0.997640, 1.004583]` · run 2 `1.001259x [0.995212, 1.005430]` | `amd-pstate-epp` / **`performance`** / `performance` (uniform, no mixed-governor warning) | **8 → 8** on all four arms, pinning attested | **NEUTRAL** |
| **Fsync/journal commit** — 8 × 4 KiB positioned writes to one file, `fsync` after each | `0.997098x [0.990808, 1.009108]` against a twice-null margin of **`1.030661x`**; `directional_claim_clear=false` | `1.001860x [0.991465, 1.004642]`, spread `1.008609x` | `0.997807x [0.991484, 1.015215]`, spread `1.015215x` | `amd-pstate-epp` / `powersave` / `balance_performance` | **1 → 1** on all four arms, pinning attested | **NEUTRAL** |
| **Parallel metadata writes** — 8 workers create exactly 512 empty files into private directories, then fsync every worker directory (**128 crossover blocks**) | **`1.510822x` `[1.493097, 1.539011]` slower** (twice-null margin `1.049223x`); replicated on a **disjoint CPU set** at `1.513052x [1.490837, 1.534711]`, agreeing to **0.15%** | `1.007184x [0.998479, 1.024316]`, spread `1.024316x` · replicate `0.998642x [0.990286, 1.009556]`, spread `1.009809x` | `0.995707x [0.978797, 1.000111]`, spread `1.021662x` · replicate `0.998780x [0.990819, 1.002688]`, spread `1.009266x` | `amd-pstate-epp` / `powersave` / **`performance`** (host EPP differed in this window; uniform across both metadata runs) | **8 → 8** on all four arms, pinning attested | **LOSE** |
| **Warm stat** — issue 2,000 `stat` calls against one mounted file and aggregate the metadata (ro) | **≈`4.81–4.86x` slower.** Two admitted same-ELF runs on a current candidate, `4.812789x [4.805600, 4.847893]` and `4.864714x [4.855028, 4.976741]`, margins `1.025305x`/`1.036618x`, spread `1.08%`. **Quote the spread, not either CI.** Reproduces the banked `4.812194x` to within `0.01%` on run 1 | run 1 `1.001140x`, spread `1.012573x` · run 2 `1.009427x` | run 1 `1.003030x`, spread `1.009207x` · run 2 `0.993159x` | `amd-pstate-epp` / **`performance`** / `performance` (uniform, no mixed-governor warning) | **1 → 1** on all four arms, pinning attested | **LOSE** |
| **Xattr get/list report** — repeat 2,000 five-call reports: read one inline value, read one external-block value, check one absent name, list one name, list 24 names (ro) | **`5.749816x` `[5.725990, 5.756846]` slower** (twice-null margin `1.009130x`) | `0.999678x [0.996487, 1.002264]`, spread `1.003525x` | `1.000266x [0.995466, 1.001873]`, spread `1.004555x` | `amd-pstate-epp` / **`performance`** / `performance` (uniform, no mixed-governor warning) | **1 → 1** on all four arms, pinning attested | **LOSE** |
| **Bulk durable write** — overwrite one preallocated 64 MiB file with 64 sequential 1 MiB positioned writes, then one file `fsync` (**2,048 pairs / 512 crossover blocks**) | **`2.898298x` `[2.874382, 2.920502]` slower** (twice-null margin `1.035235x`) — ⚠ **this interval is within-invocation only; a second admitted run of the identical ELF measured `2.655365x`, so quote this row as ≈`2.7–2.9x`, never to its own CI** | `1.001588x [0.997161, 1.009249]`, spread `1.009249x` | `0.989118x [0.982835, 0.994415]`, spread `1.017465x` | `amd-pstate-epp` / **`performance`** / `performance` (uniform, no mixed-governor warning) | **1 → 1** on all four arms, pinning attested | **LOSE** |

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

⚠⚠ **This row's cross-window reproducibility is `9.15%`, about 3x its own admission margin,
and the variance is on the INCUMBENT side** (`bd-2i2ez` step 1, 2026-08-06). A second
2,048-pair run of the **identical** candidate ELF `bcf2bc80…`, PGO `5c6530a0…`, kernel
`6.17.0-41-generic` and `performance`/`performance` governor is also admitted
(`verdict=HONEST_LOSS`) and measures **`2.655365x` `[2.641224, 2.672899]`**. Absolute arm
medians across four runs of that one ELF, inside one ~2-hour span:

| Window | Pairs | Kernel arm | FrankenFS arm | Ratio | Admitted |
| --- | --- | --- | --- | --- | --- |
| 20:53 | 64 | 78.42 ms | 232.11 ms | `2.837345x` | no (`BLOCKED_NULL`) |
| 21:04 | 512 | 77.05 ms | 225.22 ms | `2.910966x` | no (`BLOCKED_NULL`) |
| 21:46 | 2,048 | 77.31 ms | 225.31 ms | **`2.898298x`** | yes — the row above |
| 22:57 | 2,048 | 83.69 ms | 222.39 ms | **`2.655365x`** | yes |

**FrankenFS is the stable arm** — 232.11 / 225.22 / 225.31 / 222.39 ms, the three
larger-pair runs agreeing to `1.3%`. The kernel ext4 arm holds 77.05 / 77.31 / 78.42 ms and
then moves to 83.69 ms, `+8.26%`. Between the two admitted runs our arm moved `−1.30%` and
the incumbent moved `+8.26%`, so **the whole ratio swing is the incumbent, not us.**

⚠⚠⚠ **A fifth run extends the incumbent's range to `+18.3%`** (recovered 2026-08-08 from
the surviving `bd-2i2ez` window-1 log, the only comparator log that outlived the scratch
deletion). Same workload shape (`bulk_durable_write`, 64 ops/observation, 2,048 pairs, 512
crossover blocks), same kernel `6.17.0-41-generic`, same `performance`/`performance`, and it
too printed `verdict=clear` with `driver_busy_fraction=0.000000` /
`fuse_busy_fractions=0.000000` and was admitted `HONEST_LOSS`:

| Window | Kernel arm | FrankenFS arm | Ratio | Candidate ELF |
| --- | --- | --- | --- | --- |
| 21:46 | 77.31 ms | 225.31 ms | `2.898298x` | `bcf2bc80…` |
| 22:57 | 83.69 ms | 222.39 ms | `2.655365x` | `bcf2bc80…` |
| 2026-08-06 w1 | **91.43 ms** | 222.22 ms | `2.430234x` | **`d34b21c0…`** |

**Read this carefully, because half of it counts and half of it does not.** The third run's
candidate ELF is *different*, so its **ratio is not a same-ELF replicate** and must not be
folded into the `9.15%` figure — that number still stands on the two `bcf2bc80…` runs alone.
But the **kernel arm does not execute our binary at all**, so its absolute median is a
legitimate third observation of the incumbent: 77.31 → 83.69 → 91.43 ms, a monotone `+18.3%`
climb across three gate-clear windows on one kernel, while our arm sat at 225.31 / 222.39 /
222.22 ms, agreeing to `1.4%`. The one confound worth naming is that the arms run
interleaved in the crossover, so a different candidate could in principle change the
interference the kernel arm sees — but our arm measured 222.22 ms here, inside the banked
222–232 ms band, so the co-load was comparable.

**The incumbent-side drift is therefore larger than this file previously said, and it is
the recorded absolute medians that made it visible.** Had the xattr row carried its own,
the same question could be asked of it; it cannot.

The consequence is general and not specific to this row: **the admission contract bounds
within-invocation error only.** A/A nulls and the twice-null margin say nothing about
whether the same ELF re-measures to the same ratio next window, and here it does not, by
3x the margin. Any row quoted to its own CI across windows is over-precise. Neither
bulk-durable figure is marked superseded — both are admitted under one contract, so
choosing between them would be selection, not measurement.

**Btrfs bulk durable write: UNMEASURED — no longer unrunnable.** The defect that blocked it
is FIXED (`bd-cjqhh`, closed 2026-08-06 in `839eb708`): the durable commit built leaves it
could not serialize, so `fsync` returned EINVAL and the unmount flush failed the same way,
meaning the data was never persisted at all. A mounted 64 MiB run — the full comparator job
shape — now completes with `fsync` OK and every chunk byte-identical across unmount and
remount.

**What is missing is the measurement, not the capability.** No btrfs bulk-durable-write ratio
has been taken since the fix, so this scorecard carries no such row and none may be quoted.
The prior text here read "UNRUNNABLE … by a DEFECT" and was correct when written; it is
retained only in history. For the record, the failure it described was
`fsync bulk durable workload …/btrfs/fuse_a/bulk-durable.bin: Invalid argument (os error 22)`
while the ext4 arm of the identical invocation completed.

Producing the row needs a quiet window and a v3+PGO build; it is measurement work, tracked
under the perf umbrella, and it is explicitly NOT claimed here.

## One sentence per row

- **Large-directory readdir+stat: we lose.** The kernel finishes the same 32,768-entry
  stat sweep about **four** times faster (28.0–29.0 ms against our 115.6–117.0 ms).
  Re-measured 2026-08-08 on a corrected, genuinely htree-indexed fixture (`bd-plkzd`); the
  old "about five times" figure came from a fixture no real ext4 filesystem has and is
  withdrawn. ⚠ **The correction moved this number in our favour, and the delta is NOT
  attributable to the fixture** — the candidate ELF, the PGO profile, the kernel version and
  the window all changed too. What the recorded absolutes do narrow: our arm moved `+3.1%`
  against the old row while the *kernel* arm moved `+26.9%`, and the kernel arm does not
  execute our binary, so the ELF and profile change cannot explain any of it. A plausible
  mechanism, untested: an htree makes `readdir` return **hash** order, scattering the
  subsequent stat pass across the inode table, where a linear directory returns creation
  order — which is also inode-allocation order — and therefore walks it sequentially. On that
  reading the old fixture flattered the *incumbent*, which is what inflated our published
  loss. **`bd-plkzd`'s predicted direction is confirmed**: it said the defect inflates the
  ext4 ratio and therefore *understates* the btrfs/ext4 ratio-of-ratios, and on the corrected
  fixtures that quantity moves `1.675x → 1.887x`. Only its intermediate phrasing ("inflates
  the ext4 arm") is imprecise — **both** arms were faster on the unindexed fixture; the
  kernel arm was just disproportionately so, which shrank the denominator. Attribution still
  needs a same-window A/B of the two fixture constructions on one ELF: `bd-pb85e`.
- **Small-file create/delete storm: we lose.** Creating and deleting 2,000 files with
  two directory fsyncs takes us about 2.75 times as long as ext4.
- **Multi-file parallel read: we TIE.** Re-measured 2026-08-08 on the corrected fixture and
  a current ELF: `0.986316x` and `0.978203x`, both admitted `HONEST_NEUTRAL`, neither
  clearing its margin. The banked "about 29% slower" is withdrawn.
  **This is not a FrankenFS improvement story, and it must not be told as one.** The arms:
  kernel `3.110 → 3.803` ms (**+22.3%**), ours `4.010 → 3.809` ms (**−5.0%**). Four fifths of
  the movement is the incumbent getting slower, not us getting faster — and `+22.3%` sits
  inside the `±18.3%` incumbent drift this file already documents, with a kernel version
  change (6.17.0-35 → 6.17.0-41) on top.
  The fixture fix is *not* the explanation either, and the direction is what rules it out: an
  htree makes this workload's 256 `File::open` lookups **cheaper** than a linear two-block
  scan, so correcting the fixture should have made the kernel arm *faster*. It got slower.
  The extent layout is separately verified identical under both constructions
  (`scripts/cmp_extent_layout_probe.sh`), so data layout is excluded too.
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

## Absolute arm medians — REQUIRED per row, never a gate (`bd-4sull` item 3)

**Not a gate and not a claim** — `gate_input=false` for every value here. But **required
to be recorded**, which is a different thing from being optional: a row that banks only its
ratio cannot be diagnosed later, because a ratio is a quotient and cannot say which arm
moved. That is not hypothetical. The 2026-07-31 bulk-durable-write row transcribed only its
ratio; when it disagreed with the 2026-08-05 row by 32%, answering "was that us or the
incumbent?" required an entire re-run (`bd-2i2ez`) that a recorded kernel-arm median would
have made arithmetic. The report it would have come from has since been deleted
(`bd-v0igv`), so that number is gone permanently.

The harness already emits both, on the `mounted_kernel_throughput` line as
`kernel_median_wall_ns` and `fuse_median_wall_ns`. The gap was never measurement — it was
transcription. **Every future row must carry both**; `scripts/perf_ledger_preflight.py
--lint` refuses a new mounted-comparator ledger row that omits them.

| Workload | Kernel median batch | FrankenFS median batch |
| --- | --- | --- |
| Large-directory readdir+stat, 32,768 entries | **28.98 / 27.99 ms** (runs 1/2) | **117.00 / 115.62 ms** (runs 1/2) |
| Small-file create/delete storm, 2,000 files | **94.807 ms** (2026-08-08; was 100.99 ms) | **264.732 ms** (2026-08-08; was 276.60 ms) |
| Multi-file parallel read, 256 × 256 KiB | **3.803 / 3.917 ms** (runs 1/2, 2026-08-08; was 3.11 ms) | **3.809 / 3.847 ms** (runs 1/2; was 4.01 ms) |
| Fsync/journal commit, 8 × 4 KiB | 145.49 ms | 145.08 ms |
| Parallel metadata writes, 512 creates | 29.30 ms | 42.31 ms |
| Warm stat, 2,000 calls | **4.532 / 4.502 ms** (runs 1/2, 2026-08-08; was 4.42 ms) | **21.893 / 21.891 ms** (runs 1/2; was 21.30 ms) |
| Xattr get/list report, 2,000 five-call reports | ⛔ **not recorded** | ⛔ **not recorded** |
| Bulk durable write, 64 × 1 MiB + fsync | 77.31 ms | 225.31 ms |

**The xattr row is the one that got away.** It was banked with its ratio only, and its
report was deleted with the rest of the comparator scratch (`bd-v0igv`) before this
requirement existed. Nothing in the tree or in surviving logs carries either arm's absolute
median for it, so the row cannot be diagnosed the way bulk durable write was — its `5.749816x`
is un-decomposable into "our cost" and "the incumbent's cost" until it is re-run. **1 of 8
rows is unrecoverable; the other 7 are complete.**

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
  self-hashed in process.
- ⛔ **Reports NO LONGER retained.** This bullet used to say the reports live under
  `/data/tmp/frankenfs-mounted-kernel-nullfix/run_*/mounted-kernel-report.json`
  (schema v5). That tree is **gone** — verified 2026-08-08: the directory does not
  exist, no `mounted-kernel-report*.json` survives anywhere under `/data/tmp`, and
  the volume moved from ~90% full to 696G free. The disk-pressure reclaimer did not
  distinguish the ~1.4 MiB of reports from the ~133 GiB of regenerable arm images,
  and the `.sbh-protect` marker that now guards report directories
  (`protect_report_dir_from_reclaim`) landed after these runs (bd-v0igv).
  **What this does and does not mean:** the ELF hashes, PGO profile, builder hosts
  and per-arm self-hashing above were transcribed into this document at the time and
  are unaffected. What is unavailable is the raw report JSON behind them, so these
  rows can no longer be re-derived from their artifacts or re-examined for fields
  the scorecard did not transcribe. Do not read the dead path as evidence the rows
  were fabricated, and do not treat them as re-verifiable — they are transcribed
  results whose backing artifact is lost. The btrfs scorecard carries the identical
  loss for all six of its rows.
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
