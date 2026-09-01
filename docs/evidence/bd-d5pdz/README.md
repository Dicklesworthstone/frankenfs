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
