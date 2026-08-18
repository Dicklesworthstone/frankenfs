#!/usr/bin/env python3
"""Re-score BANKED mounted-comparator reports for ABBA drift exposure (bd-fj2dg).

WHY THIS EXISTS. ABBA counterbalancing cancels a linear host drift EXACTLY only when
the two arms occupy equal wall time per visit. The comparator's arms are routinely
unequal, and until `be27cc2f9` no row said so — a row silent about its own
precondition quietly asserts the precondition held.

That commit makes new rows self-report. This scores the rows that already exist,
which is the larger set: the entire bank predates the instrument. It needs no
measurement, no build and no quiet window, because every figure it uses is one the
runs already collected and serialised:

    diagnostic_side_throughput.kernel_median_wall_ns
    diagnostic_side_throughput.fuse_median_wall_ns
    fuse_aa.median

⚠️ THE RULE HERE MUST MATCH `abba_symmetry()` IN
crates/ffs-harness/src/bin/ffs_mounted_kernel_bench.rs EXACTLY. If they drift apart,
this script publishes numbers the harness will not reproduce, which is worse than
publishing nothing. `--selftest` pins the shared cases.

REPORTED, NEVER GATING. The inflation mechanism is inferred from four runs and its
one duration-matched test was inconclusive (point estimate 0.6% from prediction, but
its own null failed in the OPPOSITE direction). Nothing here refuses a row or
corrects a ratio; it says which rows were exposed to a drift ABBA could not cancel.

    scripts/abba_drift_exposure.py --survey /data/tmp
    scripts/abba_drift_exposure.py --selftest
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from pathlib import Path

# Mirrors MAXIMUM_ABBA_DURATION_RATIO in the harness.
MAXIMUM_ABBA_DURATION_RATIO = 1.10


def abba_symmetry(
    kernel_ns: float, fuse_ns: float, kernel_null_median: float, fuse_null_median: float
) -> dict:
    """Port of `abba_symmetry()` in ffs_mounted_kernel_bench.rs. Keep in lockstep."""
    usable = (
        all(isinstance(v, (int, float)) for v in (kernel_ns, fuse_ns))
        and math.isfinite(kernel_ns)
        and math.isfinite(fuse_ns)
        and kernel_ns > 0.0
        and fuse_ns > 0.0
    )
    if not usable:
        return {
            "arm_duration_ratio": float("nan"),
            "slower_arm": "unknown",
            "exact_cancellation": False,
            "inflation_suspected": False,
        }
    ratio = max(kernel_ns, fuse_ns) / min(kernel_ns, fuse_ns)
    exact = ratio <= MAXIMUM_ABBA_DURATION_RATIO
    kernel_is_slower = kernel_ns >= fuse_ns
    # The drift ABBA fails to cancel lands on the LONGER arm, so that arm's own null
    # carries the signal. Looking only at the FUSE null is blind to every win.
    slower_null = kernel_null_median if kernel_is_slower else fuse_null_median
    null_ok = isinstance(slower_null, (int, float)) and math.isfinite(slower_null)
    return {
        "arm_duration_ratio": ratio,
        "slower_arm": "kernel" if kernel_is_slower else "fuse",
        "exact_cancellation": exact,
        "inflation_suspected": (not exact) and null_ok and slower_null > 1.0,
    }


def score(path: Path) -> list[dict]:
    try:
        doc = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    rows = []
    for fs in doc.get("filesystems", []):
        diag = fs.get("diagnostic_side_throughput") or {}
        aa = fs.get("fuse_aa") or {}
        sym = abba_symmetry(
            diag.get("kernel_median_wall_ns", float("nan")),
            diag.get("fuse_median_wall_ns", float("nan")),
            (fs.get("kernel_aa") or {}).get("median", float("nan")),
            aa.get("median", float("nan")),
        )
        rows.append(
            {
                "path": str(path),
                "filesystem": fs.get("filesystem", "?"),
                "workload": fs.get("workload", doc.get("workload", "?")),
                "admitted": fs.get("admitted"),
                "verdict": fs.get("verdict", "?"),
                "ratio": (fs.get("fuse_over_kernel") or {}).get("median"),
                **sym,
            }
        )
    return rows


def selftest() -> int:
    failures = []
    matched = abba_symmetry(1000.0, 1050.0, 1.0, 1.0553)
    if not matched["exact_cancellation"] or matched["inflation_suspected"]:
        failures.append("equal-duration arms cancel drift whatever the null's sign")
    observed = abba_symmetry(3.6, 13.8, 1.0, 1.0553)
    if observed["exact_cancellation"] or not observed["inflation_suspected"]:
        failures.append("unequal arms + a POSITIVE null is the observed conjunction")
    if observed["slower_arm"] != "fuse":
        failures.append("the longer arm must be named")
    deflating = abba_symmetry(3.6, 13.8, 1.0, 0.8762)
    if deflating["inflation_suspected"]:
        failures.append("a NEGATIVE null is drift the other way — not inflation")
    flipped = abba_symmetry(13.8, 3.6, 1.0, 1.05)
    if flipped["slower_arm"] != "kernel" or abs(
        flipped["arm_duration_ratio"] - observed["arm_duration_ratio"]
    ) > 1e-9:
        failures.append("the ratio must be orientation-free")
    for bad in ((0.0, 3.6), (13.8, 0.0), (float("nan"), 3.6), (13.8, float("inf"))):
        got = abba_symmetry(bad[0], bad[1], 1.05, 1.05)
        if got["slower_arm"] != "unknown" or got["exact_cancellation"]:
            failures.append(f"unusable input {bad} must claim nothing")
    win = abba_symmetry(2.2, 1.0, 1.0041, 0.9952)
    if win["slower_arm"] != "kernel" or not win["inflation_suspected"]:
        failures.append("a positive null on the slower KERNEL arm inflates OUR win")
    if abba_symmetry(2.2, 1.0, 0.9961, 1.9)["inflation_suspected"]:
        failures.append("drift on the FASTER arm is what ABBA cancels — must not flag")
    for f in failures:
        print(f"SELFTEST FAIL: {f}", file=sys.stderr)
    if failures:
        return 1
    print("selftest OK: matches the harness cases (matched, observed, deflating, flipped, unusable)")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("reports", nargs="*", type=Path)
    p.add_argument("--survey", type=Path, help="walk this root for mounted-kernel-report.json")
    p.add_argument("--selftest", action="store_true")
    args = p.parse_args()

    if args.selftest:
        return selftest()

    paths = list(args.reports)
    if args.survey:
        paths += sorted(args.survey.rglob("mounted-kernel-report.json"))
    if not paths:
        sys.exit("give report paths or --survey ROOT")

    rows = [r for path in paths for r in score(path)]
    if not rows:
        sys.exit("no scorable reports found")

    print(f"{'fs':<7}{'workload':<34}{'adm':<5}{'ratio':>10}{'armdur':>9}{'slower':>8}  flags")
    for r in sorted(rows, key=lambda r: -(r["arm_duration_ratio"] or 0)):
        flags = []
        if not r["exact_cancellation"]:
            flags.append("UNEQUAL")
        if r["inflation_suspected"]:
            flags.append("INFLATION_SUSPECTED")
        ratio = f"{r['ratio']:.4f}" if isinstance(r["ratio"], (int, float)) else "-"
        print(
            f"{r['filesystem']:<7}{str(r['workload'])[:33]:<34}"
            f"{('yes' if r['admitted'] else 'no'):<5}{ratio:>10}"
            f"{r['arm_duration_ratio']:>9.3f}{r['slower_arm']:>8}  {','.join(flags)}"
        )

    total = len(rows)
    unequal = [r for r in rows if not r["exact_cancellation"]]
    suspected = [r for r in rows if r["inflation_suspected"]]
    admitted = [r for r in rows if r["admitted"] is True]
    adm_unequal = [r for r in admitted if not r["exact_cancellation"]]
    adm_suspected = [r for r in admitted if r["inflation_suspected"]]
    print()
    print(f"rows scored                     : {total}")
    print(f"  arms NOT duration-matched     : {len(unequal)}  ({100*len(unequal)/total:.1f}%)")
    print(f"  inflation suspected           : {len(suspected)}  ({100*len(suspected)/total:.1f}%)")
    print(f"ADMITTED rows                   : {len(admitted)}")
    if admitted:
        print(f"  of those, NOT matched         : {len(adm_unequal)}")
        print(f"  of those, inflation suspected : {len(adm_suspected)}")
    print("  -> reported, never gating: no row is refused and no ratio corrected here.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
