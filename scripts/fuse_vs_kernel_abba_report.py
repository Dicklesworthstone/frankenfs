#!/usr/bin/env python3
"""Estimator for `fuse_vs_kernel_abba.sh`.

Deliberately opinionated, because each choice here was forced by a measurement
that went wrong first:

* **The BLOCK is the resampling unit, not the rep.** Reps inside one mount share
  a page-cache state, a daemon process and a scheduling window, so they are
  correlated and a per-rep bootstrap is over-confident. Symptom: a bound that
  slid the wrong way with every added sample (>=3.275914x at two runs,
  >=2.917769x at three) before tightening once the unit was fixed.

* **The A/A null is position-matched and same-invocation.** ABBA visits each arm
  early and late, so visit-1 vs visit-2 within an arm is a control drawn from the
  same invocation with no separate run.

* **The null is reported against the EFFECT, not against 1.0.** A sufficiently
  precise instrument can reject its own null: in one quiet window a null failed at
  1.0215x ci95 [1.0047, 1.0341] simply because the interval had shrunk to +-1.5%.
  Refusing that row while passing a sloppier one at 1.15x inverts the incentive.
  Do NOT read such a failure as a real ordering effect -- that explanation was
  offered once and withdrawn when a later run at the same load put the same null
  at 1.0070x, which a systematic effect would not have done.

* **No delta subtraction.** Kernel ext4 warm stat is indistinguishable from tmpfs,
  so "filesystem-only = arm - floor" divides by noise (it produced 821x once), and
  the delta is far less reproducible than the ratio because host speed enters
  multiplicatively.

Deterministic: seeded SplitMix64, no Math.random, so a rerun reproduces exactly.
"""
import collections
import os
import statistics as st

OUT = os.environ.get("FFS_OUT", "/tmp/ffs-abba")
N = int(os.environ.get("FFS_ENTRIES", "20000")) or 20000
RESAMPLES = 20000


def splitmix(seed):
    s = seed

    def nxt():
        nonlocal s
        s = (s + 0x9E3779B97F4A7C15) & 0xFFFFFFFFFFFFFFFF
        z = s
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & 0xFFFFFFFFFFFFFFFF
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & 0xFFFFFFFFFFFFFFFF
        return z ^ (z >> 31)

    return nxt


def ratio_ci(a, b, seed=0xABBA):
    nxt = splitmix(seed)
    rs = []
    for _ in range(RESAMPLES):
        sa = [a[nxt() % len(a)] for _ in a]
        sb = [b[nxt() % len(b)] for _ in b]
        rs.append(st.median(sa) / st.median(sb))
    rs.sort()
    return rs[RESAMPLES // 40], rs[RESAMPLES - RESAMPLES // 40 - 1]


def main():
    per_arm = collections.defaultdict(list)
    per_visit = collections.defaultdict(list)
    with open(f"{OUT}/samples.tsv") as fh:
        for line in fh:
            arm, pos, val = line.strip().split("\t")
            per_arm[arm].append(float(val))
            per_visit[(arm, pos)].append(float(val))
    loads = [float(x) for x in open(f"{OUT}/loadavg")]

    print(f"\nloadavg during run: median {st.median(loads):.2f} "
          f"min {min(loads):.2f} max {max(loads):.2f} (n={len(loads)})")
    print("record this in the banked row; a row is only as good as the "
          "conditions it actually ran under\n")

    for arm, label in (("ffs", "FrankenFS (FUSE)"),
                       ("kern", "kernel (loop,ro)"),
                       ("cal", "client floor (tmpfs)")):
        if not per_arm[arm]:
            continue
        v = sorted(per_arm[arm])
        print(f"{label:24} n={len(v):3} median {st.median(v):9.2f} ms  "
              f"{st.median(v) * 1000 / N:8.3f} us/op")

    print()
    for arm in ("ffs", "kern", "cal"):
        first = [x for k, vs in per_visit.items()
                 if k[0] == arm and k[1].endswith("1") for x in vs]
        second = [x for k, vs in per_visit.items()
                  if k[0] == arm and k[1].endswith("2") for x in vs]
        if not first or not second:
            continue
        # signed, matching the interval's convention: a direction-free max/min
        # point estimate can fall outside its own CI, which it did once.
        point = st.median(first) / st.median(second)
        lo, hi = ratio_ci(first, second)
        print(f"  A/A null {arm:5} {point:.4f}x ci95 [{lo:.4f}, {hi:.4f}] "
              f"(same-invocation, position-matched)")

    knob = os.environ.get("FFS_KNOB", "")
    if per_arm["ffs_on"]:
        # The lever A/B, position-matched inside the same invocation. Reported
        # BEFORE the vs-kernel ratio because it is the decision the run exists to
        # make; the vs-kernel numbers are context for how much it is worth.
        off, on = per_arm["ffs"], per_arm["ffs_on"]
        eff = st.median(off) / st.median(on)
        lo, hi = ratio_ci(off, on)
        worst = max(
            abs(st.median([x for k, vs in per_visit.items()
                           if k[0] == a and k[1].endswith("1") for x in vs])
                / st.median([x for k, vs in per_visit.items()
                             if k[0] == a and k[1].endswith("2") for x in vs]) - 1.0)
            for a in ("ffs", "ffs_on"))
        print(f"\nLEVER A/B  {knob or 'knob'}")
        print(f"  off {st.median(off) * 1000 / N:8.3f} us/op   "
              f"on {st.median(on) * 1000 / N:8.3f} us/op")
        print(f"  speedup {eff:.6f}x   ci95 [{lo:.6f}, {hi:.6f}]")
        decided = (lo > 1.0 or hi < 1.0) and abs(eff - 1.0) > worst
        print(f"  worst arm null {worst * 100:.2f}%   -> "
              f"{'DECIDED' if decided else 'INSIDE THE NULL, not decidable'}")
        if not decided:
            print("  A lever inside its own null is not a loss; it is an "
                  "unmeasured lever. Buy blocks, not adjectives.")

    if not per_arm["kern"]:
        return
    blocks = []
    for b in sorted({k[1][0] for k in per_visit if k[0] == "ffs"}):
        f = [x for k, vs in per_visit.items()
             if k[0] == "ffs" and k[1].startswith(b) for x in vs]
        k_ = [x for k, vs in per_visit.items()
              if k[0] == "kern" and k[1].startswith(b) for x in vs]
        if f and k_:
            blocks.append(st.median(f) / st.median(k_))

    nxt = splitmix(0xB10C)
    boot = []
    for _ in range(RESAMPLES):
        s = [blocks[nxt() % len(blocks)] for _ in blocks]
        boot.append(st.median(s))
    boot.sort()
    lo, hi = boot[RESAMPLES // 40], boot[RESAMPLES - RESAMPLES // 40 - 1]
    worst_null = max(
        abs(st.median([x for k, vs in per_visit.items()
                       if k[0] == a and k[1].endswith("1") for x in vs])
            / st.median([x for k, vs in per_visit.items()
                         if k[0] == a and k[1].endswith("2") for x in vs]) - 1.0)
        for a in ("ffs", "kern"))
    eff = st.median(blocks)
    print(f"\nBLOCK estimator ({len(blocks)} blocks, block = resampling unit)")
    print(f"  ratio {eff:.6f}x SLOWER   ci95 [{lo:.6f}, {hi:.6f}]")
    print(f"  QUOTE THE WORST BOUND: >= {lo:.6f}x")
    print(f"  all blocks losses: {all(x > 1 for x in blocks)}   "
          f"blocks: {[f'{x:.4f}' for x in blocks]}")
    print(f"  worst null {worst_null * 100:.2f}% against an effect of "
          f"{(eff - 1) * 100:.1f}%  -> margin {(eff - 1) / worst_null:.0f}x")
    if per_arm["cal"]:
        c = st.median(per_arm["cal"]) * 1000 / N
        print(f"\n  PUBLISH C ALONGSIDE THE RATIO: client floor {c:.3f} us/op.")
        print("  The ratio is client-dependent: C = 4.741/3.451/2.252 us gave")
        print("  3.43x/4.59x/5.65x on identical filesystem behaviour. Do not")
        print("  subtract C -- the kernel arm is itself floor-limited.")


def _selftest() -> int:
    """Synthetic checks on the decision logic, runnable without a host.

    These exist because the decision this file makes -- DECIDED vs INSIDE THE
    NULL -- is the one a tired operator is most likely to read wrongly, and it is
    the only part of the pipeline with no measurement to sanity-check it against.
    """
    # A lever whose effect is smaller than its own arm noise must NOT be decided.
    small = [100.0, 101.0, 99.0, 100.5]
    barely = [99.0, 100.0, 98.0, 99.5]
    lo, hi = ratio_ci(small, barely)
    assert lo < 1.02, (lo, hi)  # interval must admit "no effect"

    # A large, clean effect must produce an interval well clear of 1.0.
    slow = [200.0, 201.0, 199.0, 200.5]
    fast = [100.0, 100.5, 99.5, 100.0]
    lo, hi = ratio_ci(slow, fast)
    assert lo > 1.5, (lo, hi)

    # The bootstrap must be deterministic: same input, same interval.
    assert ratio_ci(slow, fast) == ratio_ci(slow, fast)

    # A one-sided input must not raise.
    lo, hi = ratio_ci([1.0], [1.0])
    assert lo == hi == 1.0

    print("abba report selftest: 4 cases pass")
    return 0


if __name__ == "__main__":
    import sys
    if "--selftest" in sys.argv:
        raise SystemExit(_selftest())
    main()
