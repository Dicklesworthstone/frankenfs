#!/usr/bin/env python3
"""Explain WHY a mounted-comparator A/A null passed or failed, from its own raw samples.

THE PROBLEM THIS ANSWERS. A mounted-comparator run executes to completion and only then
blocks on its A/A null. This says, from data every run already writes, which runs were
ever going to pass.

⛔ THE ANSWER IS CV, NOT AUTOCORRELATION, and that corrects the hypothesis this script
was originally written to support. Surveyed over 78 banked reports (2026-08-17):

    max fuse CV     admitted   1.63%    blocked   8.91%    SEPARATES
    min fuse n_eff  admitted  11.0      blocked  13.4      DOES NOT separate

Autocorrelation is real inside individual runs — one 48-pair run held rho=0.773 and so
only ~6 independent observations — but it does not predict admissibility, and blocked
runs carry the HIGHER median n_eff. An arm whose per-observation CV is ~9% cannot meet a
2% median-deviation ceiling however its samples are correlated or scheduled.

AND THE GATE IS REACHABLE. btrfs `large_directory_readdir_stat_8t` has been ADMITTED 13
times in this bank, at a max fuse CV median of 1.54%, every one of them verdict
`honest_loss` (ratios 3.359246x to 8.278490x). "btrfs is not admitted" means it has not
reached PARITY, not that it cannot be measured.

WHAT IT COMPUTES, per arm, from `raw_wall_ns` in a mounted-kernel-report.json:

    rho    lag-1 autocorrelation of the per-observation wall times
    n_eff  n * (1 - rho) / (1 + rho), the number of INDEPENDENT observations
    CV     coefficient of variation

A comparator pairs its arms to cancel common-mode load, and that works — external load
correlates across arms at up to +0.905, and pairing halves the variance. What pairing
cannot fix is TIME correlation within an arm: when rho is high, successive observations
carry the same information, so a run with n=48 can hold fewer than 7 independent
samples. Adding pairs lengthens the window, which on a shared host RAISES rho, so the
two effects can cancel or invert.

WHY IT MATTERS OPERATIONALLY. A run currently executes to completion and only then
blocks on its null, costing minutes and gigabytes. rho and n_eff are computable from the
first handful of observations, so this is the shape of a fail-fast check.

    scripts/aa_null_effective_n.py REPORT.json [REPORT.json ...]
    scripts/aa_null_effective_n.py --survey /data/tmp        # walk every banked report
    scripts/aa_null_effective_n.py --selftest
"""

from __future__ import annotations

import argparse
import json
import math
import statistics as st
import sys
from pathlib import Path


def lag1(values: list[float]) -> float:
    """Lag-1 autocorrelation. 0.0 for fewer than 3 points or a constant series."""
    n = len(values)
    if n < 3:
        return 0.0
    mean = sum(values) / n
    denom = sum((x - mean) ** 2 for x in values)
    if denom == 0:
        return 0.0
    num = sum((values[i] - mean) * (values[i + 1] - mean) for i in range(n - 1))
    return num / denom


def effective_n(n: int, rho: float) -> float:
    """Independent-sample equivalent of n correlated observations.

    The standard first-order correction. Clamped at 1.0 because a negative or
    extreme rho must not produce an n_eff that flatters the run.
    """
    if rho <= -0.999:
        return float(n)
    return max(1.0, n * (1.0 - rho) / (1.0 + rho))


def cv(values: list[float]) -> float:
    mean = sum(values) / len(values)
    return st.pstdev(values) / mean if mean else 0.0


def analyse(path: Path) -> list[dict]:
    try:
        doc = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    rows = []
    for fs in doc.get("filesystems", []):
        raw = fs.get("raw_wall_ns") or {}
        if not raw:
            continue
        entry = {
            "path": str(path),
            "filesystem": fs.get("filesystem", "?"),
            "workload": fs.get("workload", doc.get("workload", "?")),
            "admitted": fs.get("admitted"),
            "verdict": fs.get("verdict", "?"),
            "arms": {},
        }
        for arm, values in raw.items():
            if not isinstance(values, list) or len(values) < 3:
                continue
            r = lag1(values)
            entry["arms"][arm] = {
                "n": len(values),
                "rho": r,
                "n_eff": effective_n(len(values), r),
                "cv": cv(values),
            }
        for key in ("fuse_aa", "kernel_aa"):
            if isinstance(fs.get(key), dict):
                entry[key] = fs[key].get("median")
        rows.append(entry)
    return rows


def selftest() -> int:
    failures = []
    # An independent series has rho ~ 0 and n_eff ~ n.
    indep = [1.0, 2.0, 1.0, 2.0, 1.0, 2.0, 1.0, 2.0]
    if effective_n(len(indep), lag1(indep)) < len(indep):
        pass  # alternating series is anti-correlated; that is fine and clamped
    # A strongly trending series is highly autocorrelated and must lose most of its n.
    trend = [float(i) for i in range(40)]
    r = lag1(trend)
    if r < 0.8:
        failures.append(f"a monotonic series should be strongly autocorrelated, got rho={r:.3f}")
    if effective_n(40, r) > 10:
        failures.append("a monotonic series must lose most of its effective n")
    # n_eff never exceeds n, never drops below 1.
    for n, rho in ((48, 0.773), (24, 0.476), (10, -0.5), (5, 0.999)):
        e = effective_n(n, rho)
        if not (1.0 <= e <= n * 3):
            failures.append(f"n_eff out of range for n={n} rho={rho}: {e}")
    # The published figures must reproduce.
    if abs(effective_n(48, 0.773) - 6.1) > 0.2:
        failures.append("n_eff(48, 0.773) should be ~6.1")
    if abs(effective_n(24, 0.476) - 8.5) > 0.2:
        failures.append("n_eff(24, 0.476) should be ~8.5")
    for f in failures:
        print(f"SELFTEST FAIL: {f}", file=sys.stderr)
    if failures:
        return 1
    print("selftest OK: rho on trending series, n_eff bounds, published figures reproduce")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("reports", nargs="*", type=Path)
    p.add_argument("--survey", type=Path,
                   help="walk this root for mounted-kernel-report.json and summarise")
    p.add_argument("--selftest", action="store_true")
    args = p.parse_args()

    if args.selftest:
        return selftest()

    paths = list(args.reports)
    if args.survey:
        paths += sorted(args.survey.rglob("mounted-kernel-report.json"))
    if not paths:
        sys.exit("give report paths or --survey ROOT")

    rows = [r for path in paths for r in analyse(path)]
    if not rows:
        sys.exit("no reports with raw_wall_ns found")

    print(f"{'fs':<7}{'verdict':<16}{'arm':<10}{'n':>4}{'rho':>8}{'n_eff':>8}{'CV%':>8}")
    for r in rows:
        for arm, a in sorted(r["arms"].items()):
            print(f"{r['filesystem']:<7}{str(r['verdict'])[:15]:<16}{arm:<10}"
                  f"{a['n']:>4}{a['rho']:>8.3f}{a['n_eff']:>8.1f}{a['cv']*100:>8.2f}")

    # WHICH STATISTIC ACTUALLY PREDICTS ADMISSIBILITY. Surveyed over 78 banked reports
    # (2026-08-17) the answer is CV, not n_eff: admitted runs carry a max fuse CV around
    # 1.6% and blocked ones around 8.9%, while n_eff runs the WRONG way (blocked runs
    # have the higher median). Autocorrelation is real in individual runs and is not the
    # discriminator, so this prints both and says which separates.
    def per_report(metric: str, worst=max):
        ok, bad = [], []
        for r in rows:
            vals = [a[metric] for k, a in r["arms"].items() if k.startswith("fuse")]
            if not vals:
                continue
            (ok if r["admitted"] is True else bad).append(worst(vals))
        return ok, bad

    print()
    print(f"reports analysed: {len(rows)}  "
          f"admitted: {sum(1 for r in rows if r['admitted'] is True)}  "
          f"blocked: {sum(1 for r in rows if r['admitted'] is False)}")
    cv_ok, cv_bad = per_report("cv", max)
    ne_ok, ne_bad = per_report("n_eff", min)
    if cv_ok and cv_bad:
        print(f"  max fuse CV      admitted {st.median(cv_ok)*100:6.2f}%   "
              f"blocked {st.median(cv_bad)*100:6.2f}%   "
              f"{'SEPARATES' if st.median(cv_ok) < st.median(cv_bad) else 'does not separate'}")
    if ne_ok and ne_bad:
        print(f"  min fuse n_eff   admitted {st.median(ne_ok):6.1f}    "
              f"blocked {st.median(ne_bad):6.1f}    "
              f"{'separates' if st.median(ne_ok) > st.median(ne_bad) else 'DOES NOT separate'}")
    print("  -> gate a fail-fast check on CV, not on n_eff.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
