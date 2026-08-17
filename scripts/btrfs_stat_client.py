#!/usr/bin/env python3
"""Stat every entry in a directory one of three ways, for bd-2s8zy / bd-yu6jz.

Companion client for `scripts/btrfs_readdir_node_reads.py --client`. The point is
to separate three things that `ls -l` fuses into one number:

  path    os.stat(path)          -- a PATH-BASED metadata op. Linux issues an
                                    uncached getxattr(security.capability) per
                                    path-based op, and on our side that probe
                                    resolves through read_live_inode (bd-t0xoq),
                                    i.e. it can descend the tree per entry.
  fstat   os.open + os.fstat     -- NO path walk on the metadata op itself, so
                                    the kernel does not issue the capability
                                    probe for it (bd-ha71t measured fstat at
                                    1.34 us with zero dispatch). The open still
                                    does a lookup, so this is not zero-cost --
                                    it is the same work MINUS the probe.
  lstat   os.lstat(path)         -- path-based like `path`, no symlink follow;
                                    a control for "is it the follow, not the
                                    probe".

Subtracting `fstat` from `path` attributes what the capability probe costs in
TREE NODE READS, which is the open question left by the readdir+stat re-read
storm: the FUSE path re-descends where the in-process path does not.

Entries are visited in READDIR ORDER, not sorted, so every arm walks the
directory the same way and no arm accidentally gets a friendlier locality.

    scripts/btrfs_stat_client.py --mode path /mnt/point
"""

from __future__ import annotations

import argparse
import os
import sys


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("mountpoint")
    p.add_argument("--mode", choices=("readdir", "path", "fstat", "lstat"),
                   default="path",
                   help="readdir = enumerate only, NO per-entry metadata op at all "
                        "(the control arm); the others stat every entry the way named")
    p.add_argument("--limit", type=int, default=0,
                   help="stat at most N entries (0 = all), so a huge directory "
                        "can be sampled without changing the traversal order")
    p.add_argument("--passes", type=int, default=1,
                   help="repeat the whole sweep N times in ONE mount. This is the "
                        "cache test: a working read-only node cache makes pass 2 "
                        "nearly free, so N passes costing N times one pass proves "
                        "the cache is not serving (bd-2s8zy).")
    args = p.parse_args()

    root = args.mountpoint
    names = os.listdir(root)          # readdir order, deliberately unsorted
    if args.limit:
        names = names[:args.limit]

    done = 0
    for _ in range(max(args.passes, 1)):
        # The readdir control does the enumeration and NOTHING else. It exists so
        # the per-entry metadata cost can be separated from the enumeration cost
        # without trusting an external `ls` to refrain from stat'ing -- which is
        # not a hypothetical: on this host the interactive shell's `ls` is an
        # alias for `lsd --inode --long --all` while a bare execvp("ls") lands on
        # /usr/bin/ls (uutils coreutils). Those are three different workloads
        # behind one name, so the harness defines its own.
        if args.mode == "readdir":
            names = os.listdir(root)
            if args.limit:
                names = names[:args.limit]
            done += len(names)
            continue
        for name in names:
            full = os.path.join(root, name)
            try:
                if args.mode == "path":
                    os.stat(full)
                elif args.mode == "lstat":
                    os.lstat(full)
                else:
                    fd = os.open(full, os.O_RDONLY)
                    try:
                        os.fstat(fd)
                    finally:
                        os.close(fd)
            except OSError as e:
                print(f"{full}: {e}", file=sys.stderr)
                continue
            done += 1

    print(f"{args.mode}: {done} stats over {args.passes} pass(es)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
