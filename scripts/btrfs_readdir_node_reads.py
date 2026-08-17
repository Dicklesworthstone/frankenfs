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

⛔ DEFECT FIXED 2026-08-17, AND ROWS TAKEN BEFORE IT ARE WARM-START ROWS. This script
used to count the directory's entries with `os.listdir(mountpoint)` BEFORE attaching
the tracer, purely to label the output. That listdir is a full readdir the tracer never
sees: it warms the daemon's readdir snapshot and populates the parsed-node cache, so
the arm that followed measured a SECOND, warm traversal. The entry count is now taken
AFTER the traced listing, when the tracer is already stopped and a readdir is harmless.

Consequences, stated because banked rows depend on which way this cuts:
  * CROSS-ARM A/Bs ARE UNAFFECTED. Every arm carried the identical pre-warm, so knob
    comparisons (memo on/off, probe on/off, 1-pass vs 3-pass) are fair and their ratios
    stand.
  * ABSOLUTE READ COUNTS WERE UNDERSTATED, so any "the sweep costs N reads" figure is a
    LOWER BOUND on a genuinely cold sweep. Findings of the form "this is worse than it
    should be" therefore survive and are conservative.
  * DISTINCT-NODE COUNTS ARE ALSO LOWER BOUNDS: a node read during the untraced listdir
    and served from cache thereafter never appears in the trace at all.
  * ANY CLAIM ABOUT A COLD FIRST TRAVERSAL taken before this fix is really a claim about
    a WARM one and must be re-measured before it is relied on.

WHAT THIS COUNTS IS SYSCALLS, NOT PHYSICAL I/O. Each arm's image is a fresh
`copyfile`, so it is warm in the page cache and the daemon's `pread64`s are
served from memory. That is deliberate — the question is how many times the
filesystem ASKS for a node, which is a property of its caching, not of the
storage. It does mean no row here may be read as a disk-seek or latency claim.

REMAINING UNTRACED CONTACT, enumerated so it can be checked rather than assumed:
the daemon's own MOUNT happens before the tracer attaches, and it reads 7-8
distinct nodes (measured separately by stracing from process launch). Everything
else the harness does — the image copy, `pgrep`, the entry count, the unmount —
either precedes the mount or follows the traced window.

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

# strace renders a completed read as:
#   pread64(3, "<buffer>"..., 16384, 42680320) = 16384
# The buffer is arbitrary bytes and may contain anything including `)`, so anchor
# on the fixed tail (count, offset) = ret rather than parsing the string.
PREAD = re.compile(r"pread64\((\d+), .*, (\d+), (\d+)\)\s+=\s+(-?\d+)$")

# ⛔ BUT ON A MULTI-THREADED TRACEE strace SPLITS INTERLEAVED SYSCALLS, and the
# above matches NEITHER half (bd-mdtqc trail, 2026-08-17):
#   1428894 pread64(3 <unfinished ...>
#   1428894 <... pread64 resumed>, "..."..., 16384, 56639488) = 16384
# Matching only completed lines undercounted a `ffs-cli walk` by 64x — 17 parsed
# against 1091 actual — and the FUSE daemon runs 80+ threads, so the effect there
# is larger still. The fd appears only on the UNFINISHED half, so fd filtering
# needs the pid map below.
UNFINISHED = re.compile(r"^(\d+)\s+pread64\((\d+) <unfinished")
RESUMED = re.compile(r"^(\d+)\s+<\.\.\. pread64 resumed>.*, (\d+), (\d+)\)\s+=\s+(-?\d+)$")

# The daemon opens the image as fd 3; fd 4 is /dev/fuse. Counting fd 4 would
# measure the FUSE transport, which is a different question (bd-q0xnl).
IMAGE_FD = "3"


def _run(argv, **kw):
    return subprocess.run(argv, capture_output=True, text=True, **kw)


def parse_trace(path: Path) -> tuple[Counter, Counter, int]:
    """Return (offset -> count, size -> count, total pread64 lines seen).

    Handles BOTH completed lines and unfinished/resumed pairs. The third value
    is every `pread64` occurrence in the file regardless of shape, so the caller
    can assert that parsing accounted for all of them instead of trusting it.
    """
    offsets: Counter = Counter()
    sizes: Counter = Counter()
    pending_fd: dict[str, str] = {}
    unparsed: list[str] = []
    seen = 0
    with open(path, errors="replace") as fh:
        for raw in fh:
            line = raw.strip()
            if "pread64" not in line:
                continue
            # Count the syscall once: an unfinished/resumed PAIR is one call, so
            # tally on the unfinished half and on standalone completed lines.
            u = UNFINISHED.match(line)
            if u:
                seen += 1
                pending_fd[u.group(1)] = u.group(2)
                continue
            r = RESUMED.match(line)
            if r:
                if pending_fd.pop(r.group(1), None) == IMAGE_FD:
                    sizes[int(r.group(2))] += 1
                    offsets[int(r.group(3))] += 1
                continue
            m = PREAD.search(line)
            if m:
                seen += 1
                if m.group(1) == IMAGE_FD:
                    sizes[int(m.group(2))] += 1
                    offsets[int(m.group(3))] += 1
                continue
            # A pread64 line matching NONE of the three shapes is a silent
            # undercount waiting to happen — which is exactly how this harness
            # reported 17 reads for a workload that made 1091. Surface it.
            unparsed.append(line[:120])
    if unparsed:
        print(f"\n⛔ {len(unparsed)} pread64 line(s) matched no known shape — the "
              f"count below is an UNDERCOUNT. First:\n   {unparsed[0]}",
              file=sys.stderr)
    return offsets, sizes, seen


# btrfs tree-block header, 101 bytes, little-endian:
#   csum[32] fsid[16] bytenr:u64 flags:u64 chunk_tree_uuid[16]
#   generation:u64 owner:u64 nritems:u32 level:u8
# `owner` names the tree, `level` says root/internal (>=1) vs leaf (0), and
# `bytenr` is the node's own LOGICAL address. Reading it straight out of the
# image turns a physical offset from the trace into a named node with no mount,
# no daemon and no build -- which is what makes a hot offset actionable instead
# of merely large.
BTRFS_TREES = {
    1: "ROOT_TREE", 2: "EXTENT_TREE", 3: "CHUNK_TREE", 4: "DEV_TREE",
    5: "FS_TREE", 6: "ROOT_TREE_DIR", 7: "CSUM_TREE", 8: "QUOTA_TREE",
    9: "UUID_TREE", 10: "FREE_SPACE_TREE",
}


def name_node(image: Path, physical: int) -> dict | None:
    """Identify the btrfs node at a physical offset from its own header."""
    import struct
    try:
        with open(image, "rb") as fh:
            fh.seek(physical)
            head = fh.read(101)
    except OSError:
        return None
    if len(head) < 101:
        return None
    bytenr, _flags = struct.unpack_from("<QQ", head, 48)
    generation, owner = struct.unpack_from("<QQ", head, 80)
    (nritems,) = struct.unpack_from("<I", head, 96)
    level = head[100]
    # A node whose self-reported bytenr is 0 is almost certainly not a node --
    # say so rather than printing a confident wrong answer.
    if bytenr == 0:
        return None
    return dict(logical=bytenr, owner=owner, tree=BTRFS_TREES.get(owner, f"?{owner}"),
                level=level, nritems=nritems, generation=generation)


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

    # The entry count is taken AFTER the traced listing, never before it.
    # Counting entries up front means calling `os.listdir` on the mount, which
    # is a full readdir the tracer never sees: it warms the daemon's readdir
    # snapshot AND populates the parsed-node cache, so the arm that follows
    # measures a SECOND, warm traversal. Every "cold" claim taken with the count
    # up front is really a warm-readdir claim. Ordering it after costs nothing
    # -- the tracer is already stopped by then.
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

    offsets, sizes, seen = parse_trace(trace)
    total = sum(offsets.values())
    distinct = len(offsets)
    worst = offsets.most_common(1)[0][1] if offsets else 0
    # Safe now: the tracer is stopped, so this readdir cannot pollute the arm.
    entries = len(os.listdir(mountpoint))

    unmount(mountpoint)
    try:
        daemon.wait(timeout=60)
    except subprocess.TimeoutExpired:
        daemon.kill()
    scratch.unlink(missing_ok=True)
    trace.unlink(missing_ok=True)

    return dict(label=label, entries=entries, total=total, distinct=distinct,
                reread=(total / distinct if distinct else 0.0), worst=worst,
                sizes=dict(sizes.most_common(3)), offsets=offsets)


def selftest() -> int:
    """Parse-only checks. No mount, no sudo, no image."""
    sample = [
        '1789981 pread64(3, "abc"..., 16384, 42680320) = 16384',
        '1789981 pread64(3, "d)e"..., 16384, 42680320) = 16384',   # `)` in buffer
        '1789981 pread64(3, "xyz"..., 16384, 99999) = 16384',
        '1789981 pread64(4, "fuse"..., 4096, 0) = 4096',           # not the image
        '1789981 fdatasync(3) = 0',                                # not a read
        # The split-pair shape strace emits for a MULTI-THREADED tracee. Dropping
        # it silently undercounted a real run 64x (17 parsed against 1091 actual),
        # so it is pinned here rather than trusted.
        '1428894 pread64(3 <unfinished ...>',
        '1428894 <... pread64 resumed], "z"..., 16384, 777216) = 16384'.replace("]", ">"),
    ]
    with tempfile.NamedTemporaryFile("w", suffix=".strace", delete=False) as fh:
        fh.write("\n".join(sample) + "\n")
        path = Path(fh.name)
    offsets, sizes, seen = parse_trace(path)
    path.unlink()

    failures = []
    if sum(offsets.values()) != 4:
        failures.append(f"expected 4 image reads, got {sum(offsets.values())}")
    if len(offsets) != 3:
        failures.append(f"expected 3 distinct offsets, got {len(offsets)}")
    if offsets.get(42680320) != 2:
        failures.append("a buffer containing ')' broke the tail anchor")
    if offsets.get(777216) != 1:
        failures.append("an unfinished/resumed PAIR was dropped — the 64x defect")
    # `seen` counts every pread64 call regardless of fd: 4 completed (one on
    # fd 4, deliberately excluded from the histograms) plus 1 split pair.
    if seen != 5:
        failures.append(f"expected 5 pread64 calls seen, got {seen}")
    if sizes.get(16384) != 4:
        failures.append(f"expected 4 nodesize reads, got {sizes.get(16384)}")
    for f in failures:
        print(f"SELFTEST FAIL: {f}", file=sys.stderr)
    if failures:
        return 1
    print("selftest OK: fd filter, tail anchor, histograms, unfinished/resumed pairs")
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
    p.add_argument("--name-hot", type=int, default=0, metavar="N",
                   help="after each arm, identify the N most re-read nodes by reading "
                        "their btrfs header out of the image (tree, level, nritems, "
                        "logical). Needs no mount and no build -- it turns a hot "
                        "physical offset into a named node.")
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
        # Default arms run THIS repo's client, not `ls`. `ls` is not one program
        # on this host: the interactive shell aliases it to `lsd --inode --long
        # --all`, while a bare execvp("ls") from a subprocess lands on
        # /usr/bin/ls (uutils coreutils 0.2.2). A reader reproducing a banked row
        # by typing `ls` would run a different workload than the row measured.
        # Rows banked 2026-08-17 and earlier used `ls`/`ls -l` = uutils 0.2.2.
        client = str(Path(__file__).with_name("btrfs_stat_client.py"))
        arms = [("stat", [sys.executable, client, "--mode", "path"])]
        if not args.stat_only:
            arms.insert(0, ("readdir", [sys.executable, client, "--mode", "readdir"]))

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
                if args.name_hot:
                    for phys, n in r["offsets"].most_common(args.name_hot):
                        info = name_node(image, phys)
                        if info is None:
                            print(f"      phys {phys:>10}  {n:>7} reads  "
                                  f"(no btrfs header -- not a tree node?)")
                        else:
                            print(f"      phys {phys:>10}  {n:>7} reads  -> "
                                  f"logical {info['logical']:<10} {info['tree']:<12} "
                                  f"level={info['level']} nritems={info['nritems']}")
                sys.stdout.flush()
    finally:
        unmount(args.mountpoint)

    if any(r["reread"] > 2.0 for r in rows):
        print("\n# A re-read factor above 1.0 means nodes are being fetched from disk")
        print("# repeatedly. That is a cache miss, not work -- see bd-2s8zy.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
