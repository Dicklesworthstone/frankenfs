# bd-cljvq — the peak device statistic, and the blind spot opening organically

Collected by BlackThrush, 2026-09-01, immediately after bd-xhl2g decided that
iowait does not gate. Two things are recorded here.

## 1. The recorded statistic is the PEAK, and it is not the number bd-xhl2g quoted

bd-xhl2g's evidence table reports device utilisation as a **window average** over a
whole 40-second probe. `peak_device_io_fraction`, which is what
`ExternalLoadWitness` actually records, is the **maximum of the per-sample values**.
Those are different quantities and they differ a lot — see the table below, where a
window averaging 0.0707 contains a sample at 1.00.

So the "quiet 0.024–0.125 vs saturated 0.983–1.000, 7.8x" separation in
`docs/evidence/bd-xhl2g/README.md` is an **upper bound** on the separation of the
recorded field, not a measurement of it. No threshold may be read off it.

## 2. The blind spot opens on its own, without anything manufactured

These six windows were sampled while a PEER's `frankenpandas` I/O benchmark
(`csv_read`, uncached, balanced-square) was running on this box. Nothing here is
synthetic: this is ordinary co-tenancy of the kind the comparator meets in practice.

| window | off-plc mean iowait | **peak device** | busiest | window-avg dm-0 | busy CPUs | contended frac | verdict |
|---|---|---|---|---|---|---|---|
| 1 | 0.002535 | **1.0000** | dm-0 | 0.0707 | 6 | 0.100 | **CLEAR** |
| 2 | 0.006014 | 0.6105 | nvme0n1p3 | 0.0634 | 13 | 0.500 | CONTENDED |
| 3 | 0.000947 | 0.0700 | dm-0 | 0.0234 | 5 | 0.100 | CLEAR |
| 4 | 0.002380 | 0.1669 | nvme0n1p3 | 0.0290 | 6 | 0.075 | CLEAR |
| 5 | 0.000797 | 0.0769 | nvme0n1p3 | 0.0234 | 5 | 0.025 | CLEAR |
| 6 | 0.004393 | 0.4037 | dm-0 | 0.0445 | 5 | 0.100 | CLEAR |

**Window 1 is the case bd-xhl2g could not exhibit.** The external-load gate returned
`CLEAR` — the run would have been ADMITTED — in a window containing a second in
which `dm-0` was at **100% utilisation**, while off-placement mean iowait read
`0.002535`, which is *below the median of this box's quiet population*. The gate
saw nothing, and iowait would have seen nothing had it been gating. Only the field
landed this turn saw it.

That is the blind spot bd-xhl2g describes, observed organically rather than
manufactured, in an admitted window rather than a refused one.

**And it says nothing yet about harm, which is the whole point of this bead.** One
saturated second inside a 40-second window is not sustained contention: the window
average was 0.0707. Peak device utilisation swings 14x across these six windows
(0.07 → 1.00) while iowait barely moves and the verdict stays CLEAR in five of six.
Whether any of that moves a ratio is exactly what this bead has to measure, and
these rows do not answer it.

## 3. The PEAK separates badly — and that changed what got landed

Acceptance item 0 asked for the quiet population of the RECORDED field rather than
of the window average. Six quiet windows (loadavg 4.3–8.2, nothing manufactured):

| window | loadavg | off-plc mean iowait | **peak device** | busiest | verdict |
|---|---|---|---|---|---|
| 1 | 8.22 | 0.001717 | 0.1059 | nvme0n1 | CONTENDED |
| 2 | 7.58 | 0.001965 | 0.1329 | nvme0n1p3 | CONTENDED |
| 3 | 5.86 | 0.002969 | 0.3537 | dm-0 | CLEAR |
| 4 | 4.51 | 0.000641 | 0.0610 | nvme0n1 | CLEAR |
| 5 | 4.29 | 0.003286 | 0.4956 | dm-0 | CLEAR |
| 6 | 4.60 | 0.001623 | 0.5286 | dm-0 | CONTENDED |

**A quiet box peaks past half a pinned device.** Against a saturated ~1.0 that is
under **2x with overlap** — where the window MEAN separated 7.8x with none. The
peak is a burst detector, and on a 64-thread machine with ordinary background churn
a single stalled second is normal. Anyone who had read a threshold off bd-xhl2g's
7.8x and applied it to `peak_device_io_fraction` would have refused quiet windows.

So the harness records **both**: `peak_device_io_fraction` (burst) and
`mean_device_io_fraction` (sustained). One field would have silently picked a
statistic, and the measurement says it would have picked the worse one. Neither
gates. The two also let this bead ask its question properly, because "does a BURST
move a ratio" and "does SUSTAINED pressure move a ratio" are different questions
that may well have different answers.

## Caveat recorded rather than buried

`peak_device_io_fraction` is clamped with `.min(1.0)`, so an exact `1.0` cannot be
distinguished here from a small overshoot. `io_ticks` is milliseconds-with-a-
non-empty-queue over a ~1000 ms window, so large overshoot is not possible and the
reading is sound to within timer granularity — but a raw unclamped check taken
during a controlled storm is still owed, and a re-check run in a later, quiet window
saw only 0.115 raw with no overshoot (device idle at the time, so it did not
exercise the clamp). Anyone placing a threshold should confirm this first.

## 4. Is the storm arm ADMISSIBLE at all? Yes — with a generator costing <= 2 busy CPUs

This bead's stated hard part is not producing a storm, it is getting the storm arm
past `external_load_during_run`: 0 of 9 manufactured storms cleared it, and the
refusals came from this box's background churn rather than from the storm. If the
storm arm can never be admitted, the bead is unanswerable by the mounted comparator
on this host, and saying so is the correct outcome.

`headroom.py` settles it without touching the device, so it can run beside a peer's
benchmark — and beside one is the RIGHT reading, since realistic co-tenancy is what
the storm arm would actually face. It samples the background's per-sample busy-CPU
count and asks, for each `k`, what fraction of 40-sample windows would still be
admitted if a storm added `k` busy CPUs. It mirrors `ExternalLoadWitness::clean`
exactly (both the 0.10 contended-fraction ceiling and the 3-consecutive rule).

Over 280 samples — `p50=2, p90=4, p99=11, max=18`:

| storm adds | windows admitted |
|---|---|
| k=0 | 4/7 |
| k=1 | 4/7 |
| k=2 | **3/7** |
| k=3 | 0/7 |
| k>=3 | 0/7 |

**The arm is admissible if and only if the generator costs at most 2 busy CPUs**,
and then in roughly 43% of windows. Note k=0 is already only 4/7: the background
alone refuses 43% of windows, so most of the loss is not the storm's doing.

⚠ A SHORTER RUN SAID OTHERWISE AND WAS WRONG. A first pass over 120 samples read
`p50=1, p90=3, p99=5, max=6` and put the cliff at k=2 (3/3 admitted at k<=1, 0/3 at
k>=2), which would have made the 2-reader generator inadmissible and the bead
unanswerable. 280 samples moved the cliff to k=3. Three windows cannot characterise
a tail — `p99` went 5 -> 11 and `max` 6 -> 18 between the two runs. Buy windows
before concluding a bead is unanswerable.

**This makes the measurement feasible.** The in-process 2-reader generator holds
`dm-0` at 0.983–0.990 (see the bd-xhl2g table) and costs ~2 busy CPUs, which is
exactly the admissible budget. Both arms must land in admitted windows, so at ~43%
each the paired attempt succeeds ~18% of the time and the run needs retries, not a
new instrument. A cheaper generator — one thread issuing asynchronous readahead
rather than blocking reads — would buy more headroom if the retry cost proves too
high.

## 5. The storm arm is admissible — DEMONSTRATED, not just predicted

The headroom model above predicted ~43% admission for a generator costing 2 busy
CPUs. Tested directly with the in-process 2-reader generator on a quiet box
(loadavg 1.84), five consecutive 40-sample windows:

| window | peak device | **window-avg dm-0** | iowait | busy CPUs | contended frac | verdict |
|---|---|---|---|---|---|---|
| 1 | 0.9953 | 0.9884 | 0.016248 | 7 | 0.125 | CONTENDED |
| 2 | 0.9963 | 0.9845 | 0.018094 | 18 | 0.675 | CONTENDED |
| 3 | 0.9973 | **0.9883** | 0.017341 | 6 | 0.075 | **CLEAR** |
| 4 | 0.9963 | 0.9873 | 0.019559 | 11 | 0.350 | CONTENDED |
| 5 | 0.9983 | 0.9868 | 0.016432 | 14 | 0.275 | CONTENDED |

Observed admission 1/5. Lower than the predicted 43% and on the same order; n=5
cannot separate 20% from 43%, and the generator's cost is not exactly 2 (busy-CPU
counts ran 6–18). **The arm exists, which is what the bead needed to know.**

**Window 3 is the strongest artifact this campaign has for the blind spot.** It is
SUSTAINED, not a burst — `dm-0` averaged **0.9883 over the whole 40-second window**,
not one stalled second — and the shipping gate ADMITTED it, while off-placement mean
iowait read `0.017341`, inside the quiet population's range (quiet max `0.020123`).

So the shipping policy will admit a run whose device queue is ~99% busy for its
entire duration, and iowait reads quiet the whole time. bd-xhl2g's organic window
showed this for a single second; this shows it for a whole window.

It also confirms the choice to record the MEAN: the sustained figure separates
quiet (0.023–0.125) from this window (0.9883) by ~7.9x, exactly as the
window-average population predicted, whereas the PEAK cannot tell window 3 from a
quiet box that happened to peak at 0.529.

**What remains is the actual question.** All of this is still about the SIGNAL. No
ratio has been measured under either condition, and the paired quiet-vs-storm
comparator run is what this bead has to deliver. Both arms must land in admitted
windows; at the observed rate that needs retries.

## 6. You cannot buy admission by weakening the storm

The 2-reader generator is admitted ~20% of the time, so the obvious move is a
cheaper one: fewer readers, bigger reads, maximising device time per CPU-second.
Variant D is one reader issuing 32 MiB `O_DIRECT` reads instead of two issuing
8 MiB (`io_storm_d.sh`). Four windows:

| window | peak device | window-avg dm-0 | busy CPUs | contended frac | verdict |
|---|---|---|---|---|---|
| 1 | 0.3258 | 0.2829 | 6 | 0.150 | CONTENDED |
| 2 | 0.5864 | 0.2865 | 6 | 0.100 | CLEAR |
| 3 | 0.3157 | 0.2754 | 5 | 0.050 | CLEAR |
| 4 | 0.3577 | 0.2786 | 7 | 0.125 | CONTENDED |

Admission rises to 2/4, and the device utilisation collapses to **0.28**. That is
not a saturated queue — it is between the quiet population (0.023–0.125) and the
2-reader storm (0.985), and closer to quiet.

**So the trade is not favourable, it is degenerate.** Admission was bought by
removing the treatment. A generator that does not pin the queue cannot answer
"does a pinned queue move a ratio", however often it is admitted. Variant C with
2 readers stays the instrument: sustained `dm-0` 0.985–0.990, admitted ~20% of the
time, retried.

The remaining way to widen the budget is a generator that keeps many requests in
flight from ONE thread — asynchronous submission (io_uring, or `readahead`-style
hints) rather than blocking `preadv`. That decouples queue depth from CPU cost
instead of trading one for the other. Untried; only worth building if the retry
cost of variant C proves prohibitive in the paired run.

## 7. The A/A null CANNOT substitute for the paired run — do not take this shortcut

The paired design is expensive: both arms must land in admitted windows, and at ~20%
each that is ~4% per attempt. The tempting economy is to run ONE storm arm and read
the comparator's built-in A/A null: if the storm biases the instrument, surely the
null moves, and one admitted window suffices instead of two.

**It does not work, and the reason is already recorded in this repo.** An A/A null
compares an arm against ITSELF, so any bias that hits both halves equally cancels
exactly — the same argument that made `peak_placement_mean_busy` necessary for
bd-arm-contention, where franken_numpy confirmed an arm slowing the incumbent it is
measured against while the A/A null stayed clean. A device-queue storm is precisely
a symmetric perturbation: it slows both halves of an A/A pair.

So an A/A null under storm would come back clean whether or not the storm biases the
ratio, and reading that as "no effect" would be a false null bought for half price.

The paired quiet-vs-storm comparison of the RATIO is therefore not a stylistic
preference; it is the only design that can see a symmetric bias. Budget the retries.

## 8. Which row, and what effect size this can resolve

The storm and quiet arms are two DIFFERENT windows, so the noise floor for their
comparison is the row's **cross-window spread**, not its within-invocation CI.
`docs/MOUNTED_KERNEL_SCORECARD.md` banks both, measured 2026-08-08:

| row | cross-window spread | run-1 CI width |
|---|---|---|
| bulk durable write | 9.15% | — |
| btrfs parallel read (co-tenant) | 6.09% | — |
| btrfs parallel read (quiet) | 3.81% | — |
| ext4 readdir+stat | 2.73% | 1.84% |
| btrfs readdir+stat | 1.36% | 0.40% |
| **ext4 warm stat** | **1.08%** | 0.88% |
| **ext4 parallel read** | **0.83%** | 0.86% |
| **btrfs warm stat** | **0.69%** | 1.37% |

**Use btrfs warm stat (0.69%) or ext4 parallel read (0.83%).** They resolve a storm
effect of roughly 1.5–2% — enough to matter for a gate decision, since a bias
smaller than the spread of the rows it would protect cannot justify refusing
windows. Warm stat is also the cheapest row to iterate on.

**Do NOT use readdir+stat or bulk durable write.** bulk durable write's 9.15% spread
would swamp any plausible effect, and btrfs readdir+stat is the row bd-bredw needed
384 pairs to stabilise. Picking a noisy row here converts a decidable question into
an expensive null.

⚠ The spreads above were measured in QUIET windows. The storm arm's own spread may
be larger, and if it is, that is not an obstacle to report — it is part of the
answer. "The storm inflates the row's variance" is a real finding about whether a
saturated queue harms a measurement, even if the central ratio does not move.

## 9. Admission collapses with RUN LENGTH — and that, not the storm, is the binding constraint

Everything above scored 40-second windows because that is what the probe takes. A
comparator run is far longer, and the gate is evaluated over the whole timed region.
bd-d5pdz recorded a "length-dependence caveat" without quantifying it; this
quantifies it.

`trace.py` records one CONTIGUOUS 900-second trace of per-sample busy-CPU counts —
contiguous rather than resampled because contention here ARRIVES IN BURSTS, and
shuffling would destroy the autocorrelation that decides whether a long run survives
the 3-consecutive rule. Real windows of each length are then scored with
`ExternalLoadWitness::clean`.

Trace of 2026-09-01 14:18–14:33 (`p50=2, p90=13, p99=16, max=21`; 37.6% of samples
over the limit of 4):

| window | admitted, no storm (k=0) | admitted, storm (k=2) |
|---|---|---|
| 40 s | 10/22 (45%) | 7/22 (32%) |
| 80 s | 4/11 (36%) | 2/11 (18%) |
| 150 s | 1/6 (17%) | 0/6 (0%) |
| 300 s | 0/3 (0%) | 0/3 (0%) |
| 600 s | 0/1 (0%) | 0/1 (0%) |
| 900 s | 0/1 (0%) | 0/1 (0%) |

**In this regime nothing longer than ~150 s is admitted, storm or no storm.** A
48-pair run is ~5–6.5 min (300–390 s) and a 24-pair run ~2.5 min (150 s), so the RUN
LENGTH — not the storm — is what refuses the measurement. Note the k=0 column: at
300 s the run is refused even with no storm at all.

⚠ THIS IS REGIME-DEPENDENT AND MUST NOT BE READ AS A CONSTANT. An earlier 280-sample
trace the same afternoon gave `p50=2, p90=4, p99=11, max=18` — the box was far
quieter, and long windows would fare much better. Peers had resumed by 14:18. The
finding is the SHAPE (admission decays sharply with length, and the storm shifts the
curve left by roughly one length step), not the specific percentages.

**Consequences for this bead's run plan:**
1. Use the SHORTEST run that still resolves the effect. The row choice in section 8
   already buys this: btrfs warm stat's 0.69% cross-window spread means few pairs
   are needed, where btrfs readdir+stat would have wanted 384.
2. Take the arms in a quiet regime, and measure the regime first — a 300-second
   trace costs 5 minutes and tells you whether the attempt is worth making.
3. If long runs cannot be admitted at all in any available regime, that is a finding
   about the INSTRUMENT rather than about device contention, and it belongs to
   bd-8c9u0 and the host-quiescence work rather than being silently absorbed here.

## 10. The length constraint forces REPLICATION, not a longer run

Sections 8 and 9 combine into a run plan that is not the obvious one.

The instinct with a noisy comparison is to buy pairs — that is what bd-bredw did,
taking btrfs readdir+stat from 96 to 384 pairs and its spread from 22.0% to 0.8%.
Here that instinct is exactly wrong: more pairs means a longer run, and admission
decays sharply with length, reaching 0% by 300 s. Buying pairs buys refusals.

**So replicate short runs instead of extending one.** A 12-pair warm-stat run
(`--pairs 12`, the floor for a run with no candidate comparison) is roughly 75 s,
which sits in the 36–45% admission band rather than the 0% one. Take N admitted
short runs per condition and compare the two distributions of ratios.

This works because the quantity that matters is the CROSS-WINDOW spread, not the
within-run CI: the storm and quiet arms are different windows regardless, so the
comparison was always going to be against run-to-run variation. Replication
estimates that variation directly instead of assuming a single long run would have
suppressed it — which, per section 9, it would not have been allowed to do anyway.

It also gives something a single pair of runs cannot: the storm condition's OWN
spread. If a saturated queue inflates run-to-run variance without moving the
central ratio, that is a real answer about whether it harms a measurement, and only
replication can see it.

⚠ The 12-pair floor widens each run's own CI, so N must be large enough that the
spread of the N ratios — not any single run's CI — carries the conclusion. Report
the N ratios per condition, not a mean with a CI borrowed from one of them.
