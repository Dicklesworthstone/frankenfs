#!/usr/bin/env python3
"""Decide whether a barrier REORDER can expose a crash state the original could not.

A crash exposes some prefix of the device write stream, and the only states a
filesystem must survive are the ones a barrier makes durable. So the reachable
crash states of a commit are exactly its BARRIER PREFIXES: the set of blocks
written before each flush.

If the reordered sequence's barrier-prefix set is a SUBSET of the original's,
the reorder cannot expose a state the original could not, and no crash needs to
be injected to know it. A superset — or any prefix not present in the original —
is a new crash state and must be argued or tested separately.

usage: barrier_prefix_check.py OLD_TRACE NEW_TRACE
where each trace is `strace -e trace=pwrite64,fdatasync` output from the daemon.
"""

import re
import sys

WRITE = re.compile(r"pwrite64\(\d+, .*?, (\d+), (\d+)\)\s*=\s*\d+")


def barrier_prefixes(path, sb_offset=65536):
    """Barrier-prefix sets, one list per commit (a commit ends at its last
    barrier after the superblock write)."""
    commits, cur, pending, saw_sb = [], [], set(), False
    for line in open(path, errors="replace"):
        m = WRITE.search(line)
        if m:
            pending.add(int(m.group(2)))
            if int(m.group(2)) == sb_offset:
                saw_sb = True
        elif "fdatasync(" in line:
            cur.append(frozenset(pending))
            if saw_sb:
                commits.append(cur)
                cur, pending, saw_sb = [], set(), False
    if cur:
        commits.append(cur)
    return commits


def main():
    old, new = barrier_prefixes(sys.argv[1]), barrier_prefixes(sys.argv[2])
    if not old or not new:
        print("FAIL: no complete commit found in one of the traces")
        return 1
    old_set = set().union(*old)
    new_set = set().union(*new)
    print(f"old: {len(old)} commits, {len(old[0])} barriers each, "
          f"{len(old_set)} distinct barrier prefixes")
    print(f"new: {len(new)} commits, {len(new[0])} barriers each, "
          f"{len(new_set)} distinct barrier prefixes")
    extra = new_set - old_set
    for pfx in sorted(new_set, key=len):
        mark = "NEW STATE" if pfx in extra else "also reachable before"
        print(f"  prefix of {len(pfx)} block(s): {mark}")
    if extra:
        print(f"FAIL: {len(extra)} barrier prefix(es) reachable only AFTER the "
              f"reorder — these are new crash states")
        return 1
    dropped = old_set - new_set
    print(f"PASS: every post-reorder barrier prefix was already reachable before; "
          f"the reorder removes {len(dropped)} intermediate state(s) and adds none")
    return 0


if __name__ == "__main__":
    sys.exit(main())
