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

## Caveat recorded rather than buried

`peak_device_io_fraction` is clamped with `.min(1.0)`, so an exact `1.0` cannot be
distinguished here from a small overshoot. `io_ticks` is milliseconds-with-a-
non-empty-queue over a ~1000 ms window, so large overshoot is not possible and the
reading is sound to within timer granularity — but a raw unclamped check taken
during a controlled storm is still owed, and a re-check run in a later, quiet window
saw only 0.115 raw with no overshoot (device idle at the time, so it did not
exercise the clamp). Anyone placing a threshold should confirm this first.
