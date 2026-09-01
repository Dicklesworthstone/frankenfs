# bd-bredw — how many pairs does btrfs readdir+stat need?

The question this answers: `bd-btrfs-readdir-stat-8x-8y7vp` had never banked a number
across five weeks and six-plus attempts, and every failure was the FUSE A/A null or a
ratio that would not reproduce. This measures whether that is a property of the
filesystem or of the pair count.

Everything below is ONE ELF — the v3+PGO candidate
`169ceb6f3a998932c739d1e4d19ea7e277a7412779127874cdde9da68ce0fa5c`
(`pgo_profile_sha256=6a22cfcf…`, built on rch worker hz2) — with one driver
`386b4bf7…`, one byte-identical fixture (`tree_sha256=502d72eb…`, 2005 entries),
`operations=2000`, 8 client threads observed 8, `--fuse-cpus 1`,
`--placement-scope same-llc`, run in one session on 2026-09-01. Only `--pairs` changes.

## The answer

| pairs | runs measured | across-run spread | widest intra-run ci95 | FUSE A/A `symmetric_spread` | admitted |
| --- | --- | --- | --- | --- | --- |
| 96  | 5 | **22.0%** | 6.3% | 1.0265 / 1.0322 / 1.0474 / 1.0509 / 1.0652 — 4 of 5 FAIL | 0 of 5 |
| 192 | 3 | **15.0%** | 6.5% | 1.0185 / 1.0271 / 1.0288 — 2 of 3 fail | 1 of 3 |
| 384 | 4 | **0.8%** | 3.7% | 1.0115 / 1.0211 / 1.0272 / 1.0291 — 2 of 4 clear | **2 of 4** |

The 384-pair ratios are `2.866331 / 2.866274 / 2.882223 / 2.888964` — four independent
runs inside **0.8%**. At 96 pairs the same ELF on the same fixture spans
`2.459305` to `3.000176`.

**So the row was never unmeasurable; it was under-sampled.** The instrument's
resolution, not the filesystem, is what had been refusing it.

## The banked row this produced

`btrfs_readdir_stat_384pairs_admitted.json` is the first ADMITTED, gate-clean row this
bead's parent has ever had:

    fuse_over_kernel_median = 2.866331   ci95 [2.841413, 2.944716]
    twice_null_margin_ratio = 1.023115   directional_claim_clear = true
    admitted = true                      verdict = honest_loss
    kernel A/A symmetric_spread 1.007608   fuse A/A 1.011492   (limit 1.025)
    external_load_during_run: 196 samples, contended_fraction 0.0000,
                              max_consecutive 0, max_external_busy_cpus 4,
                              io_storm_samples 0  => clear
    arms: kernel_median_wall_ns 2736009   fuse_median_wall_ns 7636409
    parity pass, initial tree == final tree

⛔ **IT DOES NOT SUPERSEDE THE SCORECARD'S `8.322812x` / `3.832345x`, AND MUST NOT BE
QUOTED AS DOING SO.** Those rows are the **32,768-entry** fixture
(`--operations 32768 --image-size-mib 512`). Everything here is the **default 2,005-entry**
fixture at `operations=2000` — the shape the never-admitted 2026-08-19 ledger rows used
(`1.086696x` through `1.115776x`, same `tree_sha256=502d72eb…`). So this is the first
ADMITTED number for the SMALL-directory shape, and the two shapes are separate rows that
happen to share a workload name. `bd-btrfs-readdir-stat-8x-8y7vp`'s headline `8.32x` is the
large-directory shape and is untouched by anything here.

## Two things worth carrying forward

**1. `sqrt(pairs)` UNDERSTATES the improvement here.** `bd-ynqwx` argues spread falls as
`sqrt(pairs)`, which predicts `22.0% -> 11%` at 384. Observed `0.8%`. Part of that is a
single 96-pair outlier (`2.459305`, whose kernel arm was itself 12% slow — drop it and 96
reads `5.4%`), so the honest statement is that the improvement is **at least** what
`sqrt(pairs)` predicts and plausibly much better, on `n` of 3-5 per cell. Nobody should
extrapolate a third point from this; they should run the pair count they need.

**2. Buying pairs buys REFUSALS as well as resolution, and the two pull against each
other.** `bd-d5pdz` established that `external_load_during_run`'s difficulty scales with
the length of the timed region, not the wall time of the run. A 384-pair region is 196
one-second samples where a 96-pair region is ~50. The admitted run above cleared 196
samples at `contended_fraction 0.0000` — but that took the box's quiet floor, and one of
the four 384-pair runs was refused CONTENDED anyway, as were two of the shorter runs.
Two further runs in these series never measured at all, refused pre-measurement by the
placement gate (`same_llc domain supplied only 6 quiet client CPUs`,
`driver guard cpu22 became 87.0% busy`) — recorded because that is the gate working
rather than degrading placement to fit.

## Files

- `btrfs_readdir_stat_384pairs_admitted.json` — the admitted run's full report.
- `pairs_96_series.txt`, `pairs_192_series.txt`, `pairs_384_series.txt` — the raw
  driver output for every run in each series, including the refusals.
