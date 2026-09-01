# bd-xhl2g — should iowait GATE the external-load verdict?

**Decision: NO. `peak_off_placement_mean_iowait` stays EVIDENCE and does not gate.**
Not because gating is premature, but because iowait was measured not to detect the
thing the bead is worried about. The field that does detect it —
`peak_device_io_fraction` — is landed alongside this note, also as evidence.

Measured by BlackThrush, 2026-09-01, on `frankenfs` HEAD.

## What the bead asked, and what answers it

| item | asked for | status |
|---|---|---|
| 1 | `peak_off_placement_mean_iowait` from >= 6 runs spanning quiet and I/O-loaded | **done**, n=19 windows (7 quiet, 4 parallel-build, 9 device-saturated, all via `scripts/iowait_population_probe.py`) |
| 2 | show the two populations separate, or report that they do not | **done, and the answer is BOTH** — see below |
| 3 | only if they separate: pick a threshold; say whether it gates | **done: it does not gate** |
| 4 | settle whether same-device is a precondition | **answered 2026-09-01 (prior turn): degenerate**, this box has one device under `/`, `/home` and `/data` |

## Item 2: the populations separate on ONE axis and overlap on the other

Every row is a 40-sample (or 20-sample) window from the probe, which reproduces
`sample_cpu_load` + `ExternalLoadWitness::observe` exactly. `dm-0 util` is
`/proc/diskstats` field 10 over the same window — the share of wall time the
request queue was non-empty. Note it is the WINDOW AVERAGE, not the per-sample
peak the harness records; see item 4 of the decision.

**Quiet windows** (nothing manufactured; loadavg 5.1–7.1):

| iowait | dm-0 util | busy CPUs | verdict |
|---|---|---|---|
| 0.002057 | 0.024 | 5 | CLEAR |
| 0.002199 | 0.124 | 5 | CONTENDED |
| 0.002369 | 0.109 | 5 | CONTENDED |
| 0.004484 | 0.125 | 6 | CONTENDED |
| 0.006937 | 0.047 | 3 | CLEAR |
| 0.007649 | 0.050 | 19 | CONTENDED |
| 0.020123 | 0.066 | 64 | CONTENDED |

**Parallel-build windows** (real fleet load, loadavg 141–731 — the population the
bead's description had in mind):

    iowait  0.864447   0.870921   0.920051   0.922171

Against these, iowait separates cleanly: worst quiet `0.020123` vs mildest storm
`0.864447` is a **42x** gap with no overlap. A threshold is calibratable, and
`IO_STORM_OFF_PLACEMENT_MEAN_IOWAIT = 0.10` sits inside it.

**Device-saturated windows** (manufactured this turn: N in-process `O_DIRECT`
readers against the same backing store, read-only, no page-cache eviction):

| storm shape | iowait | dm-0 util | off-plc mean busy | loadavg | storm samples |
|---|---|---|---|---|---|
| 96 x 4 KiB dd | 0.018185 | **1.000** | 0.981 | 70.98 | 0/40 |
| 48 x 1 MiB dd | 0.066296 | **1.000** | 0.831 | 57.00 | 0/40 |
| 24 x 8 MiB in-proc | 0.228283 | **1.000** | 0.225 | 30.29 | 40/40 |
| 6 x 8 MiB in-proc | 0.052810 | **1.000** | 0.135 | 18.63 | 0/40 |
| 3 x 8 MiB in-proc | 0.020425 | **0.990** | 0.136 | 9.94 | 0/40 |
| 2 x 8 MiB in-proc | 0.023634 | 0.983 | 0.312 | 9.55 | 0/40 |
| 2 x 8 MiB in-proc | 0.041493 | 0.990 | 0.117 | 6.88 | 0/40 |
| 2 x 8 MiB in-proc | 0.016792 | 0.985 | 0.266 | 9.33 | 0/40 |
| 2 x 8 MiB in-proc | 0.016519 | 0.986 | 0.230 | 9.71 | 0/40 |

**Here iowait fails.** Nine windows with the device pinned at 0.98–1.00, and
iowait clears `0.10` in exactly **one of nine**. Four of them — `0.016519`,
`0.016792`, `0.018185`, `0.020425` — sit *inside* the quiet population's range
(quiet max `0.020123`). A reader given only the iowait number cannot tell the
3-reader window from a quiet box.

## Why, stated as mechanism rather than as a caveat

`iowait` is the share of time a CPU is **idle with at least one task blocked on
I/O**. It therefore scales with **how many tasks are blocked at once**, not with
how hard the device is being pushed. The parallel-build storms ran at loadavg
443–731: hundreds of blocked tasks, so most CPUs are idle-with-a-blocked-task and
iowait goes to 0.9. Three readers can pin the same queue just as hard at loadavg
9.9, and 61 of 64 CPUs are then simply idle, charged to `idle`, not `iowait`.

Both populations are honestly "I/O loaded". Only one of them is loaded in the way
iowait can see.

## Item 3: the decision

1. **iowait does not gate.** It has a measured false-negative rate of 8/9 against
   device saturation, which is the mechanism the bead names as the harm
   ("contention for the DEVICE QUEUE"). A gate whose sensitivity to its own stated
   mechanism is 11% would cost windows without closing the hole.
2. **`IO_STORM_OFF_PLACEMENT_MEAN_IOWAIT = 0.10` stays, with its description
   corrected.** It does a real job — withholding bd-d5pdz's busy relaxation from
   heavy multi-task I/O load — and it never refuses a sample the pre-relaxation
   code admitted. It is not a device-contention detector and the constant's doc
   comment no longer claims to be one. That comment also claimed `0.10` sits "~25x
   above the worst quiet sample"; the four new quiet windows reach `0.020123`, so
   the real margin is **4.9x**. Corrected in place.
3. **Device utilisation is now recorded** as `peak_device_io_fraction` /
   `busiest_device` / `device_samples`, evidence-only, pinned by
   `device_io_is_recorded_and_does_not_gate_bd_xhl2g`. Before this change the
   harness read `/proc/stat` and never `/proc/diskstats`, so no run in the bank
   carries any measurement of the device queue at all.
4. **Device utilisation does not gate either, and that is deliberate.** It
   separates cleanly on this evidence — quiet 0.024–0.125 vs saturated
   0.983–1.000, a 7.8x gap over n=16 with zero overlap — but separation is not
   harm. Nothing here measures whether a saturated queue moves a comparator
   ratio. Filed as **bd-cljvq**.

   ⚠ AND THAT GAP IS FOR A DIFFERENT STATISTIC THAN THE ONE NOW RECORDED, which
   has to be said plainly because it is the same drift this turn fixed in the
   probe. Every device figure in the table above is a WINDOW AVERAGE over the
   whole probe. `peak_device_io_fraction` is the PEAK of the per-sample values,
   which is necessarily >= the average, and on one quiet self-check the two read
   0.042 and 0.020 — a factor of ~2. So the quiet half of a peak-based population
   will sit higher than 0.125 and the 7.8x is an upper bound on the real
   separation, not a measurement of it. The saturated half cannot move much,
   being already at ~1.0. Characterising the quiet PEAK population is folded into
   bd-cljvq, and until it is done no threshold should be read off the numbers
   above.

## What I did NOT establish, plainly

**No admitted window with a MANUFACTURED saturated device.** All nine saturated
windows came back `CONTENDED`, so the synthetic storms never exhibited a run the
shipping policy *admits* while the queue is pinned.

⚠ SUPERSEDED LATER THE SAME DAY, and by an organic window rather than a synthetic
one. While a peer's `frankenpandas` I/O benchmark was running, a 40-sample probe
returned `external_load_verdict=CLEAR` — the run would have been ADMITTED — in a
window containing a second at `dm-0` **1.00 utilisation**, with off-placement mean
iowait at `0.002535`, below the median of this box's quiet population. The gate saw
nothing; a gating iowait would have seen nothing. See `docs/evidence/bd-cljvq/`.
That is the end-to-end demonstration this section was written to say was missing —
though one saturated second in a 40-second window (average 0.0707) is not sustained
contention, and it still says nothing about whether a ratio moves.

The original paragraph, left for the record: The refusals were not the storm's doing: in the 6-reader and
3-reader windows off-placement mean busy was only 0.135, and the busy-CPU count
was driven by this box's own background churn. Two attempts to catch a
background-quiet stretch (`storm_tworeader_2`, 6 busy CPUs, contended fraction
0.275) got close and missed. So the hole is demonstrated **at the signal level** —
iowait cannot see a pinned queue — and not as an end-to-end admitted run. That
distinction is why device utilisation lands as evidence rather than as a gate.

**No ratio impact.** Unmeasured, and it is the question that should decide any
future gate. bd-cljvq.

## Reproducing

    python3 scripts/iowait_population_probe.py --label quiet --samples 40 --json out.json

The storm shapes are in this directory's sibling scratch scripts and are
read-only by construction: `O_DIRECT` reads against existing large files, so they
neither consume space (the volume is at 87%) nor evict a peer's page cache.
Variants A (4 KiB dd) and B (1 MiB dd) are recorded above but are the wrong
instrument — dd respawn and syscall churn drove off-placement busy to 0.83–0.98,
so those windows were refused for CPU reasons and say nothing about iowait's
sensitivity. Variant C (in-process, preallocated aligned buffer, one blocking
`preadv` per iteration) is the one that isolates a pinned device from a busy CPU.
