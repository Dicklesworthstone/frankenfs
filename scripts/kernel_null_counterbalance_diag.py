#!/usr/bin/env python3
"""Diagnose the kernel-side A/A null failure: is it noise, or systematic?

GreenSpring's five-workload suite blocked three workloads on A/A nulls. The
create/delete storm's KERNEL null was 1.009041x [1.001744, 1.013361] — a
confidence interval that EXCLUDES 1.0. Two byte-identical kernel ext4 mounts
disagreeing systematically is not variance, and no amount of extra rounds will
close it.

Hypothesis: the asymmetry is fixed to the PHYSICAL image/mount, not to the
logical arm — different placement on the backing store, different loop-device
state, or different resident cache. If so, swapping which physical image plays
"arm A" must FLIP THE SIGN of the null offset.

This runs the same workload kernel-vs-kernel in two configurations:
  direct : arm A = image1, arm B = image2
  swapped: arm A = image2, arm B = image1

  offsets same sign  -> asymmetry follows the LOGICAL arm (harness/order effect)
  offsets flip sign  -> asymmetry follows the PHYSICAL image
                        => counterbalancing images across rounds is the fix,
                           and adding rounds is not.
"""
from __future__ import annotations

import math
import os
import random
import statistics as st
import sys
import time
from pathlib import Path

COUNT = 2000
ROUNDS = 15


def storm(target: Path, count: int) -> float:
    names = [target / f"s_{i:07}" for i in range(count)]
    start = time.perf_counter()
    for n in names:
        os.close(os.open(n, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o644))
    for n in names:
        os.unlink(n)
    fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return time.perf_counter() - start


def bootstrap_ci(vals: list[float], iters: int = 20000) -> tuple[float, float]:
    rng = random.Random(20260728)
    n = len(vals)
    meds = sorted(st.median([vals[rng.randrange(n)] for _ in range(n)])
                  for _ in range(iters))
    return meds[int(0.025 * (iters - 1))], meds[int(0.975 * (iters - 1))]


def paired(a: Path, b: Path) -> dict[str, float]:
    ratios = []
    for r in range(ROUNDS):
        if r % 2 == 0:
            ta, tb = storm(a, COUNT), storm(b, COUNT)
        else:
            tb, ta = storm(b, COUNT), storm(a, COUNT)
        ratios.append(ta / tb)
    lo, hi = bootstrap_ci(ratios)
    med = st.median(ratios)
    return {"median": med, "ci_lo": lo, "ci_hi": hi,
            "excludes_one": (lo > 1.0 or hi < 1.0),
            "offset_pct": (med - 1.0) * 100.0}


def counterbalanced(a: Path, b: Path) -> dict[str, float]:
    """Cancel a fixed per-image bias exactly, rather than averaging it down.

    With a physical bias factor p on each image, the direct and swapped ratios are
        r_direct  = (p_a * T_A) / (p_b * T_B)
        r_swapped = (p_b * T_A) / (p_a * T_B)
    so their geometric mean is exactly T_A / T_B, independent of p. This is exact
    cancellation per pair, not convergence — which is why it works where extra
    rounds do not.
    """
    ratios = []
    for r in range(ROUNDS):
        # direct half of the pair
        if r % 2 == 0:
            ta, tb = storm(a, COUNT), storm(b, COUNT)
        else:
            tb, ta = storm(b, COUNT), storm(a, COUNT)
        rd = ta / tb
        # swapped half: physical images exchange logical roles
        if r % 2 == 0:
            tb2, ta2 = storm(b, COUNT), storm(a, COUNT)
        else:
            ta2, tb2 = storm(a, COUNT), storm(b, COUNT)
        rs = tb2 / ta2
        ratios.append(math.sqrt(rd * rs))
    lo, hi = bootstrap_ci(ratios)
    med = st.median(ratios)
    return {"median": med, "ci_lo": lo, "ci_hi": hi,
            "excludes_one": (lo > 1.0 or hi < 1.0),
            "spread": hi / lo}


def main() -> int:
    a, b = Path(sys.argv[1]), Path(sys.argv[2])
    print(f"kernel_null_diag,mode=direct,armA={a},armB={b}")
    direct = paired(a, b)
    print(f"  direct : median={direct['median']:.6f} "
          f"CI=[{direct['ci_lo']:.6f},{direct['ci_hi']:.6f}] "
          f"offset={direct['offset_pct']:+.3f}% excludes_1={direct['excludes_one']}")
    swapped = paired(b, a)
    print(f"  swapped: median={swapped['median']:.6f} "
          f"CI=[{swapped['ci_lo']:.6f},{swapped['ci_hi']:.6f}] "
          f"offset={swapped['offset_pct']:+.3f}% excludes_1={swapped['excludes_one']}")

    d, s = direct["offset_pct"], swapped["offset_pct"]
    print()
    if direct["excludes_one"] or swapped["excludes_one"]:
        if d * s < 0:
            print("VERDICT: offsets FLIP SIGN -> the asymmetry follows the PHYSICAL "
                  "image/mount, not the logical arm.")
            print("         FIX: counterbalance physical images across rounds. "
                  "More rounds will NOT help — the bias is systematic.")
        else:
            print("VERDICT: offsets keep the SAME SIGN -> the asymmetry follows the "
                  "LOGICAL arm (ordering/warm-up), not the image.")
            print("         FIX: settle time / cache equalisation per arm; "
                  "counterbalancing images would not help.")
    else:
        print("VERDICT: neither configuration's null excludes 1.0 here — the "
              "systematic offset did not reproduce on this host/placement.")

    print()
    print("counterbalanced (physical images exchange logical roles per pair):")
    cb = counterbalanced(a, b)
    print(f"  median={cb['median']:.6f} CI=[{cb['ci_lo']:.6f},{cb['ci_hi']:.6f}] "
          f"spread={cb['spread']:.6f}x contains_1={not cb['excludes_one']}")
    gate = (not cb["excludes_one"]) and cb["spread"] <= 1.025
    print(f"  gate (CI contains 1.0 AND spread <= 1.025x): {'PASS' if gate else 'FAIL'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
