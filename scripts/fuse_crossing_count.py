#!/usr/bin/env python3
"""Count FUSE boundary crossings per operation, without changing the daemon.

WHY. bd-xfe7z asks what the `1.143 us/op` residue in readdir+stat is, once the
`security.capability` probe is suppressed. Two hypotheses predict different
crossing counts:

  transport   readdirplus batches N entries per crossing, so the residue is
              (1/N) x ~7.29us (bd-q0xnl). At 1.143us that implies ~0.157
              crossings per entry -- one per 6.4 entries.
  daemon      the residue is per-entry work inside the daemon, in which case
              crossings per entry are far BELOW 0.157 and the lever is in the
              format layer, not the transport.

One count separates them. It needs no quiet window, which is the point: this
host has spent most of two days above the certification ceiling, and a count is
load-independent in a way a ratio is not.

HOW, and why not the obvious way. The daemon's own `requests_total` counts
REQUEST SCOPES, not crossings -- bdd0fd1b fixed a case where 6001 stats counted
22 requests because the xattr memo returned before `with_request_scope`. A
counter that can miss the thing it counts cannot settle this question.

Every FUSE request instead arrives as one `read()` on /dev/fuse, so counting
those reads counts crossings, whatever the daemon does with them afterwards.
`strace -c -e trace=read -p <daemon>` gives that count from OUTSIDE the process,
so it cannot be fooled by the daemon's own bookkeeping and needs no rebuild.

    scripts/fuse_crossing_count.py --selftest
    scripts/fuse_crossing_count.py --pid <daemon> --seconds 20 --entries 20001

⚠️ strace stops the world it traces: the timing under it is meaningless and must
never be quoted as a ratio. Only the COUNT is a result.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys

# `strace -c` summary rows look like:
#   % time     seconds  usecs/call     calls    errors syscall
#   ------ ----------- ----------- --------- --------- ----------------
#    99.62    0.036067          17      2048           read
SUMMARY_ROW = re.compile(
    r"^\s*[\d.]+\s+[\d.]+\s+\d+\s+(\d+)(?:\s+(\d+))?\s+(\w+)\s*$"
)


def parse_syscall_counts(text: str) -> dict[str, int]:
    """Syscall -> call count, from a `strace -c` summary.

    Returns calls, not errors: a `read` that returned EINTR still crossed the
    boundary to find out. The errors column is parsed only so a row carrying one
    is not mistaken for a different shape and skipped.
    """
    counts: dict[str, int] = {}
    for line in text.splitlines():
        if "syscall" in line or line.strip().startswith("-"):
            continue
        match = SUMMARY_ROW.match(line)
        if match:
            calls, _errors, name = match.groups()
            counts[name] = counts.get(name, 0) + int(calls)
    return counts


def crossings_per_entry(reads: int, entries: int) -> float:
    """Crossings per directory entry, the figure bd-xfe7z turns on."""
    return reads / entries if entries else 0.0


def verdict(per_entry: float, predicted_transport: float = 0.157) -> str:
    """Which hypothesis the count supports.

    The transport prediction is quoted from the residue arithmetic, so a count
    NEAR it supports transport and a count far BELOW it supports daemon work.
    Deliberately not a hypothesis test: one count with a clear separation does
    not need one, and dressing it up as a test would overstate it.
    """
    # Bounded ABOVE as well as below. The first version tested only
    # `>= 0.5 * predicted`, an acceptance region open to infinity, so a count
    # 12.7x the prediction came back as "within 2x ... consistent with
    # BATCHING". A measurement that refutes the hypothesis must not be reported
    # as confirming it, and an unbounded-above region guarantees exactly that.
    if per_entry > predicted_transport * 2.0:
        return (
            f"{per_entry:.4f} crossings/entry is FAR ABOVE the transport "
            f"prediction ({predicted_transport}) and refutes BOTH hypotheses: "
            f"the residue arithmetic implies ~{predicted_transport} crossings "
            f"per entry, and at ~7.29us each this many crossings would exceed "
            f"the entire measured per-op cost. Suspect the COUNT, not the "
            f"filesystem: reads not on /dev/fuse are the first thing to rule out"
        )
    if per_entry >= predicted_transport * 0.5:
        return (
            f"{per_entry:.4f} crossings/entry is within 2x of the transport "
            f"prediction ({predicted_transport}); the residue is consistent with "
            f"BATCHING and the lever is reply sizing"
        )
    return (
        f"{per_entry:.4f} crossings/entry is far below the transport prediction "
        f"({predicted_transport}); the residue is NOT crossings, so it is daemon "
        f"per-entry work and the lever is in the format layer"
    )


def crossover_verdict(a1: float, b1: float, b2: float, a2: float) -> str:
    """Decide an A/B/B/A crossover on the readdirplus remainder.

    WHY A CROSSOVER AND NOT TWO RUNS (bd-xfe7z). Two release-perf splits taken
    in different windows put the remainder at 18387723 ns and 24099500 ns -- a
    31.1% disagreement -- while the format-layer term in the same pair agreed to
    2.4%. The remainder is pure-CPU handler work with no I/O, so it tracks host
    contention directly, and this host has spent a day between loadavg 9 and 525.
    A remainder measured in one window and compared against another is a load
    ratio wearing a lever's costume.

    A/B/B/A because it is the shortest schedule that cancels a LINEAR drift: the
    two A visits straddle the two B visits, so a host getting steadily busier
    inflates both arms equally rather than whichever ran second.

    THE DRIFT CHECK IS THE POINT, not decoration. `a1` versus `a2` is an A/A null
    taken inside the same invocation: two measurements of the identical
    configuration. If the arm disagrees with ITSELF by as much as the arms
    disagree with each other, the window moved more than the lever did and the
    comparison is void -- which is the same rule the mounted comparator applies
    to ratios and which shares were quietly exempted from.
    """
    a_mean = (a1 + a2) / 2.0
    b_mean = (b1 + b2) / 2.0
    if a_mean <= 0 or b_mean <= 0:
        return "VOID: a non-positive arm mean; the timers did not run"

    effect = b_mean / a_mean
    drift = abs(a2 - a1) / a_mean
    margin = abs(effect - 1.0)

    if drift >= margin:
        return (
            f"VOID: the A arm disagrees with ITSELF by {100*drift:.1f}% while the "
            f"arms differ by {100*margin:.1f}%. The window moved more than the "
            f"lever; re-run, do not report {effect:.4f}x"
        )
    if effect < 1.0:
        return (
            f"B IS FASTER: {effect:.4f}x of A ({1/effect:.3f}x speedup), "
            f"A/A drift {100*drift:.1f}% against a {100*margin:.1f}% effect"
        )
    return (
        f"B IS SLOWER: {effect:.4f}x of A, A/A drift {100*drift:.1f}% against a "
        f"{100*margin:.1f}% effect"
    )


def selftest() -> int:
    cases = 0
    sample = """% time     seconds  usecs/call     calls    errors syscall
------ ----------- ----------- --------- --------- ----------------
 99.62    0.036067          17      2048           read
  0.38    0.000138           0       512        12 writev
------ ----------- ----------- --------- --------- ----------------
100.00    0.036205                  2560        12 total
"""
    counts = parse_syscall_counts(sample)
    assert counts["read"] == 2048, counts
    cases += 1
    # A row WITH an errors column must parse, not be skipped -- an EINTR'd read
    # still crossed the boundary.
    assert counts["writev"] == 512, counts
    cases += 1
    # The header, the rules and the total row must not become syscalls.
    assert "syscall" not in counts and "total" in counts
    cases += 1
    assert parse_syscall_counts("") == {}
    cases += 1
    assert parse_syscall_counts("garbage\nmore garbage\n") == {}
    cases += 1

    assert abs(crossings_per_entry(2048, 20001) - 0.10239) < 1e-4
    cases += 1
    # Must not divide by zero when a workload recorded no entries.
    assert crossings_per_entry(10, 0) == 0.0
    cases += 1
    assert crossings_per_entry(0, 100) == 0.0
    cases += 1

    # A count far ABOVE the prediction refutes both hypotheses and must say so
    # rather than reading as confirmation (the 1.9926 observed on 2026-08-17).
    assert "refutes BOTH" in verdict(1.9926)
    assert "refutes BOTH" in verdict(0.157 * 2.0 + 1e-9)
    assert "BATCHING" in verdict(0.157 * 2.0)
    assert "BATCHING" in verdict(0.157)
    cases += 1
    assert "BATCHING" in verdict(0.10)
    cases += 1
    assert "format layer" in verdict(0.01)
    cases += 1
    # The boundary is stated so a future reader does not have to infer it.
    assert "format layer" in verdict(0.157 * 0.5 - 1e-9)
    cases += 1
    assert "BATCHING" in verdict(0.157 * 0.5)
    cases += 1


    # bd-xfe7z: the crossover verdict on the remainder.
    # A clean win: B consistently ~half of A, A stable across its two visits.
    cases += 1
    assert "B IS FASTER" in crossover_verdict(1000.0, 500.0, 510.0, 1010.0)
    # A clean loss.
    cases += 1
    assert "B IS SLOWER" in crossover_verdict(1000.0, 1500.0, 1520.0, 1010.0)
    # THE CASE THAT MATTERS: the A arm disagrees with itself by more than the
    # arms differ. This is the 31% cross-window disagreement in miniature, and
    # it must VOID rather than report a ratio.
    cases += 1
    v = crossover_verdict(1000.0, 1100.0, 1100.0, 1400.0)
    assert "VOID" in v, v
    assert "moved more than the lever" in v, v
    # Exactly-equal drift and effect is still void: ties go to refusing.
    cases += 1
    assert "VOID" in crossover_verdict(1000.0, 1100.0, 1100.0, 1200.0)
    # A dead timer must not be divided by.
    cases += 1
    assert "VOID" in crossover_verdict(0.0, 0.0, 0.0, 0.0)
    cases += 1
    assert "VOID" in crossover_verdict(1000.0, 0.0, 0.0, 1000.0)

    print(f"selftest: {cases} cases OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--pid", type=int, help="the mounted daemon's pid")
    parser.add_argument("--seconds", type=int, default=20)
    parser.add_argument("--entries", type=int, required=False,
                        help="directory entries the workload touches")
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    if not args.pid or not args.entries:
        parser.error("--pid and --entries are required unless --selftest is given")

    proc = subprocess.run(
        ["strace", "-c", "-f", "-e", "trace=read", "-p", str(args.pid)],
        capture_output=True, text=True, timeout=args.seconds + 30,
    )
    counts = parse_syscall_counts(proc.stderr)
    reads = counts.get("read", 0)
    per_entry = crossings_per_entry(reads, args.entries)
    print(f"reads on the fuse device: {reads}")
    print(f"entries touched:          {args.entries}")
    print(f"crossings per entry:      {per_entry:.4f}")
    print(verdict(per_entry))
    print("NOTE: timing under strace is meaningless; only the count is a result.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
