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
