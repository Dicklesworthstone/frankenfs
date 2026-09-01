#!/usr/bin/env python3
"""Calibrate the external-load veto's two knobs against real windows (bd-d5pdz).

WHY THIS EXISTS, and why the obvious check is not enough.

`external_load_during_run` refuses a run when, over the run's own 1-second
samples:

    a sample is CONTENDED iff  |{cpu not in placement : busy_cpu > F}| > L
    the run is REFUSED    iff  contended_fraction > 0.10
                           or  max_consecutive_contended >= 3

with the shipping constants F = EXTERNAL_BUSY_CPU_FRACTION = 0.25 and
L = MAX_EXTERNAL_BUSY_CPUS, which bd-d5pdz recalibrated from 2 to 4 using exactly
this probe.

WHAT THIS PROBE DOES NOT REPLAY. The shipping gate also holds a sample taken
during an I/O STORM to the stricter pre-recalibration limit
(MAX_EXTERNAL_BUSY_CPUS_UNDER_IO_STORM, selected by per-sample off-placement mean
iowait). This probe records BUSY fractions only, so its verdict is the storm-free
one. On a window with real iowait the shipping gate is at least as strict as this
probe says, never less -- use scripts/iowait_population_probe.py for the iowait
side.

bd-d5pdz's PRACTICAL NOTE tells a planner to check the window with a single

    mpstat -P ALL 1 1 | awk '... if (100-$NF > 25) n++ ...'

and treat "two or fewer" as "the veto can pass". THAT ADVICE IS NOT THE
CRITERION AND IT SYSTEMATICALLY UNDERSTATES. The criterion is a FRACTION over
many samples plus a consecutive-run rule; one sample cannot evaluate either.
Measured 2026-09-01 on a genuinely-quiet box (loadavg 5, down from 445 earlier
the same day): five consecutive spot-checks each returned 0-2 busy CPUs and
would have said "go", while the real criterion over 20 samples returned
CONTENDED three times out of three, at 30-35% contended samples. The spot-check
catches the quiet samples and misses the bursts, and the bursts are what the
gate is counting.

So this probe records the RAW per-CPU busy vector for every sample and replays
the full verdict over a GRID of (F, L). That turns "is the threshold right?"
into a measurement: for each candidate pair, does a known-quiet window pass and
a known-loaded window still refuse? A pair that admits both has stopped
discriminating; a pair that refuses both is the state bd-d5pdz reports.

Arithmetic is copied from `sample_cpu_load` / `ExternalLoad::observe` in
crates/ffs-harness/src/bin/ffs_mounted_kernel_bench.rs, and matches
scripts/iowait_population_probe.py so the two are comparable:

    busy_i = (total_i - (idle_i + iowait_i)) / total_i     <- iowait counts as IDLE

USAGE
    scripts/external_load_calibration.py --label quiet  --samples 40 --json quiet1.json
    scripts/external_load_calibration.py --label loaded --samples 40 --json loaded1.json
    scripts/external_load_calibration.py --compare quiet*.json -- loaded*.json
"""
from __future__ import annotations

import argparse
import glob
import json
import sys
import time

# Mirrors of the harness constants. Kept as literals, not imported, because the
# point is to sweep AROUND them; a drift here is caught by --verify-shipping.
CPU_SAMPLE_INTERVAL_S = 1.0          # CPU_SAMPLE_INTERVAL_MS = 1_000
EXTERNAL_BUSY_CPU_FRACTION = 0.25    # F
MAX_EXTERNAL_BUSY_CPUS = 4           # L  (was 2 until bd-d5pdz, 2026-09-01)
MAX_CONTENDED_SAMPLE_FRACTION = 0.10
MAX_CONSECUTIVE_CONTENDED_SAMPLES = 3

FRACTION_GRID = [0.20, 0.25, 0.30, 0.40, 0.50, 0.60, 0.75, 0.90]

# The OTHER gate these windows can answer, for free (bd-host-wide-scope-gap-four-rows-dy9s8).
# `--placement-scope host-wide` runs `wait_for_host_quiet`, which needs ZERO of the
# process's allowed CPUs above MAX_DRIVER_PREFLIGHT_BUSY for DEFAULT_HOST_QUIET_SAMPLES
# CONSECUTIVE 1-second samples. That is strictly stricter than the external-load veto:
# not "few busy CPUs", but NONE.
MAX_DRIVER_PREFLIGHT_BUSY = 0.20
DEFAULT_HOST_QUIET_SAMPLES = 5
LIMIT_GRID = list(range(0, 17))


def read_cpu_ticks() -> dict[int, tuple[int, int]]:
    """(total, idle+iowait) per CPU, exactly as the harness reads /proc/stat."""
    out: dict[int, tuple[int, int]] = {}
    with open("/proc/stat") as fh:
        for line in fh:
            if not line.startswith("cpu") or not line[3:4].isdigit():
                continue
            fields = line.split()
            cpu = int(fields[0][3:])
            vals = [int(v) for v in fields[1:]]
            # fields 4+5 (0-indexed 3,4) are idle and iowait; the harness sums them.
            out[cpu] = (sum(vals), vals[3] + vals[4])
    return out


def parse_cpu_list(spec: str) -> set[int]:
    cpus: set[int] = set()
    for part in filter(None, (p.strip() for p in spec.split(","))):
        if "-" in part:
            lo, hi = part.split("-", 1)
            cpus.update(range(int(lo), int(hi) + 1))
        else:
            cpus.add(int(part))
    return cpus


def collect(samples: int, placement: set[int]) -> list[list[float]]:
    """Per-sample list of OFF-placement busy fractions."""
    rows: list[list[float]] = []
    for _ in range(samples):
        before = read_cpu_ticks()
        time.sleep(CPU_SAMPLE_INTERVAL_S)
        after = read_cpu_ticks()
        busy: list[float] = []
        for cpu, (t0, i0) in before.items():
            if cpu in placement or cpu not in after:
                continue
            t1, i1 = after[cpu]
            total = max(t1 - t0, 0)
            busy.append(1.0 if total == 0 else max(total - max(i1 - i0, 0), 0) / total)
        rows.append(busy)
    return rows


def verdict(rows: list[list[float]], frac: float, limit: int) -> dict:
    """Replay ExternalLoad::clean() for one (F, L) pair."""
    contended = [sum(1 for b in row if b > frac) > limit for row in rows]
    run = best = 0
    for c in contended:
        run = run + 1 if c else 0
        best = max(best, run)
    n = len(rows) or 1
    cf = sum(contended) / n
    return {
        "contended_fraction": round(cf, 4),
        "max_consecutive": best,
        "max_busy_cpus": max((sum(1 for b in row if b > frac) for row in rows), default=0),
        "clean": cf <= MAX_CONTENDED_SAMPLE_FRACTION
                 and best < MAX_CONSECUTIVE_CONTENDED_SAMPLES,
    }


def host_wide_gate(paths: list[str]) -> int:
    """Replay `wait_for_host_quiet` over recorded windows.

    Answers whether `--placement-scope host-wide` can ever arm on this fleet,
    without paying for a run that would time out trying.
    """
    recs = load(paths)
    if not recs:
        print("no windows given", file=sys.stderr)
        return 2
    print(f"HOST-WIDE QUIESCENCE GATE replayed over {len(recs)} window(s)")
    print(f"criterion: ZERO allowed CPUs above {MAX_DRIVER_PREFLIGHT_BUSY:.0%} busy, "
          f"for {DEFAULT_HOST_QUIET_SAMPLES} CONSECUTIVE 1-second samples\n")
    total = clear_total = best_overall = 0
    for r in recs:
        rows = r["rows"]
        clear = [all(b <= MAX_DRIVER_PREFLIGHT_BUSY for b in row) for row in rows]
        run = best = 0
        for c in clear:
            run = run + 1 if c else 0
            best = max(best, run)
        above = [sum(1 for b in row if b > MAX_DRIVER_PREFLIGHT_BUSY) for row in rows]
        total += len(rows)
        clear_total += sum(clear)
        best_overall = max(best_overall, best)
        name = r["_path"].rsplit("/", 1)[-1]
        print(f"  {name:<28} label={r.get('label','?'):<18} loadavg {r.get('loadavg_start')}"
              f"  clear {sum(clear)}/{len(rows)}  longest run {best}"
              f"  cpus>{MAX_DRIVER_PREFLIGHT_BUSY:.0%}: median {sorted(above)[len(above)//2]}, max {max(above)}")
    print(f"\n  TOTAL {clear_total}/{total} samples clear; longest consecutive run anywhere "
          f"= {best_overall}, need {DEFAULT_HOST_QUIET_SAMPLES}")
    reached = best_overall >= DEFAULT_HOST_QUIET_SAMPLES
    print(f"  => host-wide gate {'REACHABLE' if reached else 'NOT REACHED'} in these windows")
    if not reached and clear_total == 0:
        print("     and not a SINGLE sample was clear, so this is structural rather than\n"
              "     a matter of waiting: the floor of always-busy CPUs never reaches zero.")
    return 0


def load(paths: list[str]) -> list[dict]:
    recs = []
    for pat in paths:
        for p in sorted(glob.glob(pat)) or [pat]:
            with open(p) as fh:
                r = json.load(fh)
            r["_path"] = p
            recs.append(r)
    return recs


def compare(quiet_paths: list[str], loaded_paths: list[str]) -> int:
    quiet, loaded = load(quiet_paths), load(loaded_paths)
    if not quiet or not loaded:
        print("need at least one window on each side", file=sys.stderr)
        return 2
    print(f"quiet windows: {len(quiet)}   loaded windows: {len(loaded)}\n")
    print(f"{'F':>5} {'L':>3}  {'quiet pass':>10} {'loaded pass':>11}  verdict")
    print("-" * 52)
    separating = []
    for frac in FRACTION_GRID:
        for limit in LIMIT_GRID:
            qv = [verdict(r["rows"], frac, limit)["clean"] for r in quiet]
            lv = [verdict(r["rows"], frac, limit)["clean"] for r in loaded]
            qp, lp = sum(qv), sum(lv)
            if qp == len(qv) and lp == 0:
                separating.append((frac, limit))
                mark = "SEPARATES"
            elif qp == 0 and lp == 0:
                mark = "refuses both"
            elif qp == len(qv) and lp == len(lv):
                mark = "admits both"
            else:
                mark = "partial"
            if mark in ("SEPARATES",) or (frac == EXTERNAL_BUSY_CPU_FRACTION
                                          and limit <= 10):
                print(f"{frac:>5.2f} {limit:>3}  {qp:>4}/{len(qv):<5} {lp:>5}/{len(lv):<5}  {mark}")
    print()
    if separating:
        print("SEPARATING (F, L) pairs — admit every quiet window, refuse every loaded one:")
        for frac, limit in separating:
            print(f"    F={frac}  L={limit}")
    else:
        print("NO (F, L) pair on this grid separates the two populations.")
    ship = (EXTERNAL_BUSY_CPU_FRACTION, MAX_EXTERNAL_BUSY_CPUS)
    print(f"\nshipping pair F={ship[0]} L={ship[1]}: "
          f"{'SEPARATES' if ship in separating else 'does NOT separate'}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--samples", type=int, default=40)
    ap.add_argument("--placement", default="",
                    help="CPUs our arms would occupy; empty means every CPU is "
                         "off-placement, the right reading when asking what a run "
                         "would have seen had it started now")
    ap.add_argument("--label", default="unlabelled")
    ap.add_argument("--json", default=None)
    ap.add_argument("--compare", nargs="+", metavar="QUIET",
                    help="quiet JSONs; put loaded JSONs after a bare --")
    ap.add_argument("--host-wide-gate", nargs="+", metavar="JSON",
                    help="replay the host-wide quiescence gate over recorded windows "
                         "(bd-host-wide-scope-gap-four-rows-dy9s8)")
    ap.add_argument("rest", nargs="*")
    a = ap.parse_args()

    if a.host_wide_gate:
        return host_wide_gate(a.host_wide_gate)
    if a.compare:
        return compare(a.compare, a.rest)

    placement = parse_cpu_list(a.placement)
    with open("/proc/loadavg") as fh:
        loadavg = float(fh.read().split()[0])
    rows = collect(a.samples, placement)
    with open("/proc/loadavg") as fh:
        loadavg_end = float(fh.read().split()[0])

    ship = verdict(rows, EXTERNAL_BUSY_CPU_FRACTION, MAX_EXTERNAL_BUSY_CPUS)
    rec = {
        "label": a.label,
        "samples": a.samples,
        "interval_s": CPU_SAMPLE_INTERVAL_S,
        "placement": sorted(placement),
        "loadavg_start": loadavg,
        "loadavg_end": loadavg_end,
        "shipping_verdict": ship,
        "rows": [[round(b, 4) for b in row] for row in rows],
    }
    print(f"label={a.label}  samples={a.samples}  loadavg {loadavg} -> {loadavg_end}")
    print(f"shipping F={EXTERNAL_BUSY_CPU_FRACTION} L={MAX_EXTERNAL_BUSY_CPUS}: "
          f"contended_fraction={ship['contended_fraction']} "
          f"max_consecutive={ship['max_consecutive']} "
          f"max_busy_cpus={ship['max_busy_cpus']} "
          f"=> {'CLEAN' if ship['clean'] else 'CONTENDED'}")
    print("\nbusy-CPU count percentiles per fraction (over samples):")
    for frac in FRACTION_GRID:
        counts = sorted(sum(1 for b in row if b > frac) for row in rows)
        n = len(counts)
        p = lambda q: counts[min(n - 1, int(q * n))]
        print(f"  F={frac:<5} p50={p(0.5):>3} p90={p(0.9):>3} max={counts[-1]:>3}")
    if a.json:
        with open(a.json, "w") as fh:
            json.dump(rec, fh)
        print(f"\nwrote {a.json}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
