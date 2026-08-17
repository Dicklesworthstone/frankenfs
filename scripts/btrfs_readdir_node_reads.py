#!/usr/bin/env python3
"""COUNT tree-node re-reads on the btrfs readdir/stat path, for bd-2s8zy / bd-3zx2x.

THE QUESTION. btrfs readdir+stat is the worst row in the bank while the ext4 twin
is ADMITTED at `1.0266x`. Timing it has never settled anything: its A/A null has
never cleared in 7 attempts, and this host spends most of its life above the
certification ceiling. So count instead.

WHAT IS COUNTED, AND WHY IT IS THE RIGHT QUANTITY. Every parsed btrfs tree node
the daemon needs is either served from `btrfs_parsed_node_cache` or read from the
image with a `pread64` of `nodesize` bytes. So:

    total preads on the image fd   = how many node reads the listing cost
    DISTINCT offsets among them    = how many nodes it actually needed
    total / distinct               = the re-read factor

A re-read factor of 1.0 means every node was needed once and the cache was never
even asked to work. A factor of 35 means the same nodes are being fetched from
disk over and over, which is a cache miss, not work. That ratio is an exact
integer pair at every size, it is load-independent, and it needs no quiet window
-- which on this host is the difference between an answer and a defer.

ONE FRESH MOUNT PER ARM. This is not a detail. The parsed-node cache lives for
the life of the mount, so a second arm run against a warm daemon measures the
first arm's cache and reports a number that cannot be reproduced from a cold
start. Every arm here gets its own mount and its own daemon.

READDIR AND STAT ARE SEPARATED, because they behave completely differently:
`ls` (readdir only) is flat in directory size, `ls -l` (readdir+stat) is not, and
conflating them is how a lever gets aimed at the flat half.

    scripts/btrfs_readdir_node_reads.py --selftest
    scripts/btrfs_readdir_node_reads.py --images ~/btrfs-fixture-2k.img ~/btrfs-fixture-20k.img
    scripts/btrfs_readdir_node_reads.py --images ~/btrfs-bisect-*.img --stat-only

Needs passwordless sudo for `strace` (yama blocks a same-user PTRACE_SEIZE here).
`/data` is mounted `nosuid`, so `fusermount3` is refused there: `--mountpoint`
must live under `$HOME`.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

# strace renders a read as:
#   pread64(3, "<buffer>"..., 16384, 42680320) = 16384
# The buffer is arbitrary bytes and may contain anything including `)`, so anchor
# on the fixed tail (count, offset) = ret rather than trying to parse the string.
PREAD = re.compile(r"pread64\((\d+), .*, (\d+), (\d+)\)\s+=\s+(-?\d+)$")

# The daemon opens the image as fd 3; fd 4 is /dev/fuse. Counting fd 4 would
# measure the FUSE transport, which is a different question (bd-q0xnl).
IMAGE_FD = "3"


def _run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, **kw)


def parse_trace(path: Path) -> tuple[Counter, Counter]:
    """Return (offset -> read count, size -> read count) for the image fd."""
    offsets: Counter = Counter()
    sizes: Counter = Counter()
    with open(path, errors="replace") as fh:
        for line in fh:
            m = PREAD.search(line.strip())
            if not m or m.group(1) != IMAGE_FD:
                continue
            sizes[int(m.group(2))] += 1
            offsets[int(m.group(3))] += 1
    return offsets, sizes


def unmount(mountpoint: Path) -> None:
    _run(["fusermount3", "-u", str(mountpoint)])
    # A daemon started under sudo owns a root mount that fusermount3 will refuse.
    _run(["sudo", "umount", str(mountpoint)])
    time.sleep(1)


def probe(cli: Path, image: Path, mountpoint: Path, workdir: Path,
          label: str, listing: list[str], settle: float,
          daemon_env: dict[str, str] | None = None) -> dict | None:
    """Mount `image` fresh, strace the daemon across one listing, count reads.

    `daemon_env` is applied to the DAEMON only, so an A/B of a knob runs both
    arms from ONE ELF and the ISA/PGO differences that sink cross-binary
    comparisons cancel exactly (bd-b9dug class C).
    """
    scratch = workdir / f"{label}.img"
    shutil.copyfile(image, scratch)
    unmount(mountpoint)
    mountpoint.mkdir(parents=True, exist_ok=True)

    env = dict(os.environ)
    if daemon_env:
        env.update(daemon_env)
    log = open(workdir / "mount.log", "ab")
    daemon = subprocess.Popen([str(cli), "mount", str(scratch), str(mountpoint)],
                              stdout=log, stderr=log, env=env)
    time.sleep(settle)

    # The launcher forks, so the pid that serves requests is not `daemon.pid`.
    pids = _run(["pgrep", "-f", f"ffs-cli mount {scratch}"]).stdout.split()
    if not pids:
        print(f"{label}: FATAL: daemon never appeared", file=sys.stderr)
        scratch.unlink(missing_ok=True)
        return None
    pid = pids[0]

    entries = len(os.listdir(mountpoint))
    trace = workdir / f"{label}.strace"
    tracer = subprocess.Popen(
        ["sudo", "timeout", "300", "strace", "-f", "-p", pid,
         "-e", "trace=pread64", "-o", str(trace)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(settle)

    subprocess.run(listing + [str(mountpoint)],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)

    _run(["sudo", "pkill", "-f", f"strace -f -p {pid}"])
    try:
        tracer.wait(timeout=60)
    except subprocess.TimeoutExpired:
        tracer.kill()
    time.sleep(1)

    offsets, sizes = parse_trace(trace)
    total = sum(offsets.values())
    distinct = len(offsets)
    worst = offsets.most_common(1)[0][1] if offsets else 0

    unmount(mountpoint)
    try:
        daemon.wait(timeout=60)
    except subprocess.TimeoutExpired:
        daemon.kill()
    scratch.unlink(missing_ok=True)
    trace.unlink(missing_ok=True)

    return dict(label=label, entries=entries, total=total, distinct=distinct,
                reread=(total / distinct if distinct else 0.0), worst=worst,
                sizes=dict(sizes.most_common(3)))


def selftest() -> int:
    """Parse-only checks. No mount, no sudo, no image."""
    sample = [
        '1789981 pread64(3, "abc"..., 16384, 42680320) = 16384',
        '1789981 pread64(3, "d)e"..., 16384, 42680320) = 16384',   # `)` in buffer
        '1789981 pread64(3, "xyz"..., 16384, 99999) = 16384',
        '1789981 pread64(4, "fuse"..., 4096, 0) = 4096',           # not the image
        '1789981 fdatasync(3) = 0',                                # not a read
    ]
    with tempfile.NamedTemporaryFile("w", suffix=".strace", delete=False) as fh:
        fh.write("\n".join(sample) + "\n")
        path = Path(fh.name)
    offsets, sizes = parse_trace(path)
    path.unlink()

    failures = []
    if sum(offsets.values()) != 3:
        failures.append(f"expected 3 image reads, got {sum(offsets.values())}")
    if len(offsets) != 2:
        failures.append(f"expected 2 distinct offsets, got {len(offsets)}")
    if offsets.get(42680320) != 2:
        failures.append("a buffer containing ')' broke the tail anchor")
    if sizes.get(16384) != 3:
        failures.append(f"expected 3 nodesize reads, got {sizes.get(16384)}")
    for f in failures:
        print(f"SELFTEST FAIL: {f}", file=sys.stderr)
    if failures:
        return 1
    print("selftest OK: fd filter, tail anchor, offset and size histograms")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--selftest", action="store_true",
                   help="run parse checks and exit; needs no image, mount or sudo")
    p.add_argument("--cli", type=Path,
                   default=Path("target/release-perf/ffs-cli"),
                   help="ffs-cli to mount with. Its SHA-256 is reported, because a "
                        "count from an unnamed binary is not a row")
    p.add_argument("--images", type=Path, nargs="+", default=[],
                   help="btrfs images to probe, smallest first")
    p.add_argument("--mountpoint", type=Path,
                   default=Path.home() / "ffs-readdir-probe",
                   help="must NOT be under a nosuid filesystem (i.e. not /data)")
    p.add_argument("--work-dir", type=Path,
                   default=Path(tempfile.gettempdir()) / "ffs-readdir-probe",
                   help="scratch for per-arm image copies and traces")
    p.add_argument("--stat-only", action="store_true",
                   help="skip the readdir-only arm (it is flat in directory size, "
                        "so it is worth running once and not every time)")
    p.add_argument("--settle", type=float, default=4.0,
                   help="seconds to wait for the daemon and the tracer to attach")
    p.add_argument("--client", action="append", default=[], metavar="ARGV",
                   help="run this client instead of ls/ls -l, repeatable, one arm "
                        "each. The mountpoint is appended as the last argument. "
                        "Split words with commas: "
                        "--client scripts/btrfs_stat_client.py,--mode,fstat")
    p.add_argument("--daemon-env", action="append", default=[], metavar="K=V",
                   help="set an env var on the DAEMON, repeatable. Every arm then "
                        "runs from ONE ELF, so a knob A/B has no ISA/PGO confound "
                        "(bd-b9dug class C). Example: --daemon-env FFS_BTRFS_FLOOR_MEMO=0")
    args = p.parse_args()

    if args.selftest:
        return selftest()
    if not args.images:
        sys.exit("FATAL: --images is required (or use --selftest)")
    if not args.cli.is_file():
        sys.exit(f"FATAL: no ffs-cli at {args.cli}")

    # Provenance first: a count whose binary is not named cannot be compared to
    # another count (bd-b9dug, bd-4w2mf).
    elf = _run(["sha256sum", str(args.cli)]).stdout.split()[0]
    load = Path("/proc/loadavg").read_text().split()[:3]
    mhz = [float(l.split(":")[1]) for l in Path("/proc/cpuinfo").read_text().splitlines()
           if "cpu MHz" in l]
    daemon_env = {}
    for kv in args.daemon_env:
        if "=" not in kv:
            sys.exit(f"FATAL: --daemon-env wants K=V, got {kv!r}")
        k, v = kv.split("=", 1)
        daemon_env[k] = v

    print(f"# host={os.uname().nodename} kernel={os.uname().release}")
    print(f"# elf={elf[:24]}... loadavg={'/'.join(load)} "
          f"mean_cpu_mhz={sum(mhz)/len(mhz):.1f} over {len(mhz)} cpus")
    print(f"# daemon_env={daemon_env or 'default (knobs unset)'}")
    print("# a COUNT is load-independent; the loadavg is recorded, not relied on")
    print()

    args.work_dir.mkdir(parents=True, exist_ok=True)
    if args.client:
        arms = []
        for spec in args.client:
            argv = [w for w in spec.split(",") if w]
            if not argv:
                sys.exit(f"FATAL: empty --client spec {spec!r}")
            if argv[0].endswith(".py"):
                argv = [sys.executable] + argv
            # Name the arm after the last flag value, so `--mode,fstat` reads
            # as `fstat` in the table rather than as the interpreter path.
            arms.append((argv[-1], argv))
    else:
        arms = [("stat", ["ls", "-l"])]
        if not args.stat_only:
            arms.insert(0, ("readdir", ["ls"]))

    print(f"{'arm':>28} {'entries':>8} {'distinct':>9} {'preads':>9} "
          f"{'reread':>9} {'per_entry':>10} {'worst':>8}")
    rows = []
    try:
        for image in args.images:
            if not image.is_file():
                print(f"{image}: MISSING, skipped", file=sys.stderr)
                continue
            for arm, listing in arms:
                label = f"{image.stem}_{arm}"
                r = probe(args.cli, image, args.mountpoint, args.work_dir,
                          label, listing, args.settle, daemon_env)
                if not r:
                    continue
                rows.append(r)
                per = r["total"] / max(r["entries"], 1)
                print(f"{r['label']:>28} {r['entries']:>8} {r['distinct']:>9} "
                      f"{r['total']:>9} {r['reread']:>8.1f}x {per:>10.2f} "
                      f"{r['worst']:>8}")
                sys.stdout.flush()
    finally:
        unmount(args.mountpoint)

    if any(r["reread"] > 2.0 for r in rows):
        print("\n# A re-read factor above 1.0 means nodes are being fetched from disk")
        print("# repeatedly. That is a cache miss, not work -- see bd-2s8zy.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
