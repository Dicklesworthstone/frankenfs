# bd-d5pdz — external-load veto recalibration, raw windows

Every window the `2 -> 4` recalibration of `MAX_EXTERNAL_BUSY_CPUS` rests on, kept
raw so the threshold can be re-derived — or overturned — without re-measuring.

Collected 2026-09-01 on the frankenfs host. Each `cal_*.json` holds `rows`: one
entry per 1-second sample, each the OFF-placement per-CPU busy fractions computed
exactly as `sample_cpu_load` does (`busy = (total - (idle + iowait)) / total`, so
iowait counts as IDLE). Replay any candidate threshold pair over them with:

    scripts/external_load_calibration.py --compare 'docs/evidence/bd-d5pdz/cal_quiet_*.json' \
        -- 'docs/evidence/bd-d5pdz/cal_loaded_moderate.json' 'docs/evidence/bd-d5pdz/cal_loaded_heavy.json'

## The windows

| File | Window | loadavg | busy-CPU count at F=0.25 (p50 / max) |
| --- | --- | --- | --- |
| `cal_quiet_1..4` | genuinely quiet, this box's real floor | ~5 | 2 / 4-5 |
| `cal_loaded_moderate` | synthetic, 8 CPU spinners | ~6-9 | 14 / 19 |
| `cal_loaded_heavy` | synthetic, 32 CPU spinners | ~12-26 | 35 / 47 |
| `cal_loaded_realfleet_1..2` | real fleet contention, I/O-bound | **~731** | **2 / 7-8** |
| `iowait_probe_quiet_1..3` | same quiet window, via `iowait_population_probe.py` | ~5 | peak off-placement mean iowait 0.0022-0.0045 |
| `live_window_1` | **a LIVE window admitted at the shipping constants**, 40 samples | **2.7-2.9** | 3 / 5 |
| `iowait_probe_live_1` | the same live window, iowait side, 20 samples | ~5.5 | peak off-placement mean iowait 0.0021 |

## The two things these windows settle

**1. The old limit of `2` did not discriminate — it refused everything.** All four
quiet windows were REFUSED at `L=2` (contended fraction 0.225-0.375 against a 0.10
ceiling), because `2` sat below the quiet population's own MEDIAN. `L=4` admits all
four (0.000-0.050), still refuses both synthetic loaded windows (1.000), and still
refuses the 2026 contended window that motivated the gate (5 busy CPUs > 4). `L>=5`
buys nothing and loses that last property.

**2. The real-fleet windows are why the relaxation is SCOPED.** At loadavg **731**
the busy-CPU counts are indistinguishable from a quiet window, because the load is
D-state and iowait counts as idle here. `L=2` refused those windows only
incidentally (0.325/0.350, tripped by occasional spikes); `L=4` admits them
(0.050/0.025). So the relaxation is withheld from samples whose off-placement mean
iowait exceeds `IO_STORM_OFF_PLACEMENT_MEAN_IOWAIT` — see
`MAX_EXTERNAL_BUSY_CPUS_UNDER_IO_STORM`. That is not the iowait GATE (bd-xhl2g); it
never refuses a sample the pre-2026-09-01 code admitted.

⚠ The loaded arms are two different things and should not be pooled: the synthetic
windows are CPU contention, the real-fleet ones are I/O contention. They are the two
distinct failure modes, and only the first is visible to the busy metric at all.

## 3. The recalibration is reachable in practice, not only on replay (2026-09-01, cc)

`live_window_1` is the first window measured at the box's actual quiet floor —
loadavg **2.7-2.9**, lower than any of the four `cal_quiet_*` windows — and the
shipping constants admit it: `contended_fraction=0.075` against the `0.10` ceiling,
`max_consecutive=1` against the limit of `3`, `max_busy_cpus=5`. Under the old
`L=2` the same window is REFUSED: its per-sample busy-CPU count has `p50=3`, so at
least half its samples are contended by construction.

That also confirms the bead's claim that the `1-5` floor is IRREDUCIBLE rather than
fleet contention. At loadavg 2.7 — a third of the calibration windows' load, with
nothing else benchmarking — the count still sits at `p50=3`. Waiting for a quieter
box cannot fix `L=2`, because this IS the quieter box.

`iowait_probe_live_1` shows the same window is clear on the OTHER side too:
off-placement mean iowait `0.0021` against the `0.10` storm threshold, devices at
2.4% I/O time, `io_storm_samples=0` — so the relaxation applies here rather than
being withheld, and the CLEAN verdict is the relaxed limit's, not an accident of a
window that would have passed anyway.

⚠ Read narrowly, as the bead's own comment says: this is the PROBE replaying the
verdict, not a mounted run's `external_load_during_run`. It shows the gate CAN pass,
not that any given window will.

### A correction this window forced

`iowait_probe_live_1` is the first record written by `iowait_population_probe.py`
AFTER it was repaired. That script shipped with `MAX_EXTERNAL_BUSY_CPUS = 2` and no
consecutive-run rule, and the `2 -> 4` recalibration (`23264bce7`) did not update it
— so the probe whose own comment warns that "changing one here without changing it
there makes the harvested population incomparable to a real run" had become exactly
that. It reported a STRICTER verdict than the harness it mirrors. The first
`live_window_1` iowait pass, taken before the fix, printed
`over_limit_samples=1, max_external_busy_cpus=3` — over a limit the shipping code no
longer applies.

Only `over_limit_samples` / `external_load_verdict` were wrong; the iowait and busy
populations themselves were never affected, so `iowait_probe_quiet_1..3` remain
valid as harvested. The banked record here is a re-run on the repaired script.

## 4. Two MOUNTED runs, back to back — and the gate's verdict is LENGTH-DEPENDENT (2026-09-01, cc)

Section 3 is a probe replaying the verdict. These two are the real thing: mounted
runs, kernel btrfs beside FrankenFS-over-FUSE in one invocation, on a driver built
from `4b1bd9dd3` that carries the recalibrated constants — the report's own
`max_external_busy_cpus_limit` reads **4**, which is the first time any run has
printed it.

| File | pairs | EL samples | contended_fraction | max_consecutive | max_busy | verdict |
| --- | --- | --- | --- | --- | --- | --- |
| `mounted_run_btrfs_12pair_clear` | 12 | 15 | **0.0667** | 1 | 5 | **clear** |
| `mounted_run_btrfs_192pair_contended` | 192 | 99 | **0.3737** | 7 | 8 | **CONTENDED** |

They started **40 seconds apart**, on the same driver and candidate, at the same
`--placement-scope same-llc`, with the **same 10 placement CPUs excluded**, so
they are directly comparable to each other.

**So the close condition is met on the letter and not on the spirit.** A mounted
run WAS observed to pass `external_load_during_run` at the recalibrated limit —
that is the first one, and it is real. But the very next run, over the same
minutes, refused at `0.3737` with a 7-sample consecutive burst. The 15-sample
region caught a quiet patch; the 99-sample region saw the bursts.

This is bd-d5pdz's own methodological point turned on its own evidence. The bead's
09:42Z comment records that a single `mpstat` spot-check returned 0,0,0,0,2 in a
window whose real 20-sample verdict was CONTENDED three times of three — "the
spot-check catches the quiet samples and misses the bursts, and the bursts are the
whole quantity being counted". A 15-sample timed region is a longer spot-check, not
a different kind of measurement.

**What this means for planning a row, and it is the useful part.** The gate's
difficulty scales with the length of the row's TIMED REGION, not with the wall time
of the run. Cheap rows are easy to admit and prove little about whether an expensive
one can be; the rows that most need admitting — btrfs readdir+stat needs 192 pairs
for its A/A nulls (`bd-ynqwx`) — are exactly the ones most exposed. An observation
that the gate can pass should therefore be quoted WITH its sample count, and only an
observation at measurement length retires the question.

**The relaxation did not make the gate toothless**, which is the other thing these
two runs settle. `L=4` still refused a real 99-sample region on a loadavg-10 box, at
`0.3737` against a `0.10` ceiling — nearly four times over. The concern that raising
`2 -> 4` would admit contended windows is not borne out here.

⚠ One thing these runs canNOT settle, stated because the temptation is obvious: the
report records only aggregates, not the per-sample busy counts, so **neither run can
say what the OLD limit of 2 would have returned for it.** `max_external_busy_cpus`
of 5 and 8 proves at least one sample was over 2 in each, and nothing more. The
evidence that `L=2` refuses quiet windows is the probe population in sections 1-3,
not these reports.

