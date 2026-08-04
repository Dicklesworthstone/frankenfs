#!/usr/bin/env python3
"""Mounted head-to-head: kernel ext4 vs frankenfs-over-FUSE, ONE invocation.

This is the instrument frankenfs did not have. Every KEEP this campaign produced is
a SELF-speedup (frankenfs-before vs frankenfs-after) and reads `N/A` in the
direct-kernel column, so none of them can be shown to matter competitively. This
harness runs the REAL incumbent — a kernel-mounted ext4 filesystem — beside the
frankenfs FUSE mount, in a single process, with an A/A null for BOTH arms.

A MISS IS A SUCCESS. The goal is an instrument that produces an honest number, not
a flattering one. If frankenfs loses, the harness worked.

It is built against six traps, each of which has already cost this fleet a result:

  T1 DISPATCH        Assert each arm's filesystem type AT RUNTIME, from this
                     process's own /proc/self/mountinfo. franken_networkx once
                     published 2.6x while genuine NetworkX was 1.88x SLOWER,
                     because its "incumbent" arm was already dispatched to its own
                     code. A path that merely looks like a mountpoint is not
                     evidence: earlier in this session `touch` "succeeded" on an
                     unmounted directory that was supposed to be the FUSE arm.
  T2 UNMATCHED       Both arms receive byte-identical POSIX call sequences from one
                     driver, and the same durability boundary (one fsync of the
                     directory). frankensqlite compared C at synchronous=FULL
                     against F at NORMAL; franken_whisper compared its greedy
                     against beam-5/best-of-5, ~5x the work. Mount options for both
                     arms are captured and printed, so a mismatch is visible.
  T3 NON-INTERLEAVED Arms alternate INSIDE one measured routine, order flipping per
                     round. Host load degrades arms unequally — frankenfs has
                     measured a comparator arm degrading ~3x harder, biasing the
                     ratio in our own favour.
  T4 CORE CONTENTION Explicit CPU affinity, recorded. frankenredis invalidated a
                     whole window after a peer pinned load onto one arm's core; its
                     A/A null between two IDENTICAL binaries read 0.556.
  T5 CLIENT-BOUND    A tmpfs control arm measures the DRIVER's own ceiling. If a
                     filesystem arm is close to it, the harness is measuring itself
                     and the run is refused. frankenredis's unpipelined rows
                     measured the client, not the server.
  T6 SHARED BASELINE The two arms must be distinct mounts on distinct backing
                     devices. franken_numpy's bool "win" had the same NumPy tail in
                     both arms, so it measured itself.

Usage:
  mounted_kernel_ab.py --kernel DIR --frankenfs DIR [--tmpfs DIR]
                       [--count N] [--rounds R] [--cpus 2,3]
"""

from __future__ import annotations

import argparse
import json
import math
import os
import statistics as st
import sys
import time
from pathlib import Path

EXPECT_KERNEL_FSTYPE = "ext4"
EXPECT_FFS_FSTYPE_PREFIX = "fuse"
# A filesystem arm must be at least this many times slower than the tmpfs driver
# ceiling, or the number is dominated by the driver rather than the filesystem.
CLIENT_BOUND_MIN_RATIO = 2.0


class ArmIdentity:
    """What a path ACTUALLY is, resolved from this process's mount table."""

    def __init__(self, label: str, path: Path) -> None:
        self.label = label
        self.path = path.resolve()
        self.mount_point: str | None = None
        self.fstype: str | None = None
        self.source: str | None = None
        self.options: str | None = None
        self._resolve()

    def _resolve(self) -> None:
        best = -1
        with open("/proc/self/mountinfo", encoding="utf-8") as fh:
            for line in fh:
                fields = line.split()
                try:
                    sep = fields.index("-")
                except ValueError:
                    continue
                mount_point = fields[4]
                # Longest matching mount point wins (a path can sit under several).
                if (
                    str(self.path) == mount_point
                    or str(self.path).startswith(mount_point.rstrip("/") + "/")
                ) and len(mount_point) > best:
                    best = len(mount_point)
                    self.mount_point = mount_point
                    self.fstype = fields[sep + 1]
                    self.source = fields[sep + 2]
                    self.options = f"{fields[5]};{fields[sep + 3]}"

    def as_dict(self) -> dict[str, str | None]:
        return {
            "arm": self.label,
            "path": str(self.path),
            "mount_point": self.mount_point,
            "fstype": self.fstype,
            "source": self.source,
            "options": self.options,
        }


def bootstrap_median_ci(ratios: list[float], iters: int = 20000,
                        alpha: float = 0.05) -> tuple[float, float]:
    """Percentile bootstrap CI for the median ratio.

    A point estimate plus a dispersion number is not a confidence statement; the
    ledger contract requires an interval, and CV is explicitly not a gate.
    """
    import random
    rng = random.Random(20260727)
    n = len(ratios)
    meds = []
    for _ in range(iters):
        sample = [ratios[rng.randrange(n)] for _ in range(n)]
        meds.append(st.median(sample))
    meds.sort()
    lo = meds[int((alpha / 2) * (iters - 1))]
    hi = meds[int((1 - alpha / 2) * (iters - 1))]
    return lo, hi


def serving_daemon_elf_sha256(mount_point: str) -> dict[str, str | None]:
    """SHA-256 of the binary ACTUALLY serving `mount_point`, hashed in-process.

    For a mounted head-to-head the measuring process is the driver, not the code
    under test — hashing the driver would prove nothing. What matters is which
    binary is answering FUSE requests, so this locates that process and hashes its
    /proc/<pid>/exe. A sha256sum of a path on disk cannot establish that.
    """
    import hashlib
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes().split(b"\0")
            argv = [a.decode("utf-8", "replace") for a in cmdline if a]
            if not argv or "mount" not in argv:
                continue
            if mount_point not in argv:
                continue
            exe = entry / "exe"
            digest = hashlib.sha256()
            with open(exe, "rb") as fh:
                for chunk in iter(lambda: fh.read(65536), b""):
                    digest.update(chunk)
            return {"pid": entry.name, "exe": os.readlink(exe),
                    "sha256": digest.hexdigest()}
        except (OSError, PermissionError, UnicodeDecodeError):
            continue
    return {"pid": None, "exe": None, "sha256": None}


def assert_identities(kernel: ArmIdentity, ffs: ArmIdentity) -> None:
    """T1 + T6. Refuse to measure anything we cannot prove the identity of."""
    problems: list[str] = []
    if kernel.fstype != EXPECT_KERNEL_FSTYPE:
        problems.append(
            f"kernel arm is fstype={kernel.fstype!r}, expected {EXPECT_KERNEL_FSTYPE!r} "
            f"— refusing to call this the incumbent (T1 dispatch trap)"
        )
    if not (ffs.fstype or "").startswith(EXPECT_FFS_FSTYPE_PREFIX):
        problems.append(
            f"frankenfs arm is fstype={ffs.fstype!r}, expected a {EXPECT_FFS_FSTYPE_PREFIX}* "
            f"type — an unmounted directory accepts writes and looks fine (T1)"
        )
    if kernel.mount_point is not None and kernel.mount_point == ffs.mount_point:
        problems.append(
            f"both arms resolve to the SAME mount {kernel.mount_point!r} — that measures "
            f"one filesystem against itself (T6 shared-component trap)"
        )
    if kernel.source is not None and kernel.source == ffs.source:
        problems.append(
            f"both arms share backing source {kernel.source!r} (T6)"
        )
    if problems:
        for p in problems:
            print(f"IDENTITY REFUSED: {p}", file=sys.stderr)
        raise SystemExit(2)


# --- workloads ------------------------------------------------------------
# Every workload issues an IDENTICAL POSIX sequence to whichever arm it is handed
# (T2). None of them branch on which filesystem they are talking to.

def _threaded(fn, nthreads: int):
    """Run `fn(tid)` on `nthreads` OS threads. Python releases the GIL inside the
    blocking file syscalls these workloads make, so this really does exercise the
    filesystem concurrently even though CPU-bound Python would not."""
    import threading
    errs: list[BaseException] = []

    def wrap(tid: int) -> None:
        try:
            fn(tid)
        except BaseException as exc:  # surfaced, never swallowed
            errs.append(exc)

    ts = [threading.Thread(target=wrap, args=(i,)) for i in range(nthreads)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    if errs:
        raise errs[0]


def wl_create(target: Path, count: int, threads: int) -> float:
    """Metadata writes. `threads`>1 is the named 8-thread parallel-create gap."""
    per = count // max(threads, 1)
    for tid in range(threads):
        (target / f"t{tid}").mkdir(exist_ok=True)
    start = time.perf_counter()

    def body(tid: int) -> None:
        d = target / f"t{tid}"
        for i in range(per):
            fd = os.open(d / f"h_{i:07}", os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o644)
            os.close(fd)

    _threaded(body, threads)
    dfd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return time.perf_counter() - start


def wl_parallel_read(target: Path, count: int, threads: int) -> float:
    """Multi-file parallel read — the ~2.9x gap with the pread copy tax."""
    files = sorted(p for p in target.iterdir() if p.name.startswith("r_"))
    if not files:
        raise RuntimeError("parallel-read needs a prepared corpus (use --prepare)")
    start = time.perf_counter()

    def body(tid: int) -> None:
        for f in files[tid::threads]:
            fd = os.open(f, os.O_RDONLY)
            try:
                while os.read(fd, 1 << 20):
                    pass
            finally:
                os.close(fd)

    _threaded(body, threads)
    return time.perf_counter() - start


def wl_create_delete(target: Path, count: int, threads: int) -> float:
    """Small-file create/delete storm (bd-opb6l)."""
    start = time.perf_counter()
    names = [target / f"s_{i:07}" for i in range(count)]
    for n in names:
        os.close(os.open(n, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o644))
    for n in names:
        os.unlink(n)
    dfd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)
    return time.perf_counter() - start


def wl_readdir_stat(target: Path, count: int, threads: int) -> float:
    """Large-directory readdir + stat of every entry (bd-57lae)."""
    if not any(p.name.startswith("d_") for p in target.iterdir()):
        raise RuntimeError("readdir-stat needs a prepared corpus (use --prepare)")
    start = time.perf_counter()
    total = 0
    for entry in os.scandir(target):
        st_ = entry.stat(follow_symlinks=False)
        total += st_.st_size + 1
    return time.perf_counter() - start


def wl_fsync_latency(target: Path, count: int, threads: int) -> float:
    """fsync/journal commit latency: write one block, fsync, repeated."""
    path = target / "fsync_probe"
    fd = os.open(path, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o644)
    block = b"x" * 4096
    try:
        start = time.perf_counter()
        for _ in range(count):
            os.write(fd, block)
            os.fsync(fd)
        elapsed = time.perf_counter() - start
    finally:
        os.close(fd)
        os.unlink(path)
    return elapsed


WORKLOADS = {
    "create": wl_create,
    "parallel-read": wl_parallel_read,
    "create-delete": wl_create_delete,
    "readdir-stat": wl_readdir_stat,
    "fsync-latency": wl_fsync_latency,
}

PREPARE_PREFIX = {"parallel-read": "r_", "readdir-stat": "d_"}


def prepare(target: Path, workload: str, count: int, size_kib: int = 64) -> None:
    """Build the read/readdir corpus once, OUTSIDE any timed region."""
    prefix = PREPARE_PREFIX.get(workload)
    if prefix is None:
        return
    blob = b"z" * (size_kib * 1024) if prefix == "r_" else b""
    for i in range(count):
        p = target / f"{prefix}{i:07}"
        if not p.exists():
            with open(p, "wb") as fh:
                if blob:
                    fh.write(blob)
    dfd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def workload(target: Path, count: int) -> float:
    """Identical POSIX sequence for every arm (T2). Returns seconds.

    create `count` empty files, then ONE directory fsync as the durability
    boundary. Both arms get the same boundary; neither is allowed to skip it.
    """
    names = [target / f"h_{i:07}" for i in range(count)]
    start = time.perf_counter()
    for name in names:
        fd = os.open(name, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o644)
        os.close(fd)
    dir_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(dir_fd)
    finally:
        os.close(dir_fd)
    return time.perf_counter() - start


def clear(target: Path) -> None:
    """Reset between rounds. OUTSIDE the timed region, identical for both arms."""
    for entry in target.iterdir():
        if entry.name.startswith("h_"):
            entry.unlink()


SELECTED = {"name": "create", "threads": 1}


def clear_all(target: Path) -> None:
    for entry in list(target.iterdir()):
        if entry.name.startswith(("h_", "s_", "fsync_probe")):
            entry.unlink()
        elif entry.is_dir() and entry.name.startswith("t"):
            for sub in list(entry.iterdir()):
                sub.unlink()
            entry.rmdir()


def measure(target: Path, count: int) -> float:
    fn = WORKLOADS[SELECTED["name"]]
    try:
        return fn(target, count, SELECTED["threads"])
    finally:
        # read/readdir corpora are persistent fixtures and must NOT be cleared,
        # or every round after the first would measure a different filesystem.
        if SELECTED["name"] not in PREPARE_PREFIX:
            clear_all(target)


def paired(a: Path, b: Path, count: int, rounds: int) -> list[float]:
    """T3. Both arms inside one routine, order alternating per round."""
    ratios: list[float] = []
    for r in range(rounds):
        if r % 2 == 0:
            ta = measure(a, count)
            tb = measure(b, count)
        else:
            tb = measure(b, count)
            ta = measure(a, count)
        # ratio > 1 means `a` took longer than `b`, i.e. `b` is faster
        ratios.append(ta / tb)
    return ratios


def summarize(ratios: list[float]) -> dict[str, float]:
    logs = [math.log(r) for r in ratios]
    center = st.median(logs)
    devs = sorted(abs(x - center) for x in logs)
    k = 0.9 * (len(devs) - 1)
    lo = int(k)
    hi = min(lo + 1, len(devs) - 1)
    spread = devs[lo] + (k - lo) * (devs[hi] - devs[lo])
    ci_lo, ci_hi = bootstrap_median_ci(ratios)
    return {
        "median_ratio": math.exp(center),
        "median_ci_lo": ci_lo,
        "median_ci_hi": ci_hi,
        "null_floor": math.exp(abs(center) + spread),
        "min": min(ratios),
        "max": max(ratios),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--kernel", required=True, type=Path)
    ap.add_argument("--frankenfs", required=True, type=Path)
    ap.add_argument("--tmpfs", type=Path, default=None,
                    help="driver-ceiling control (T5); strongly recommended")
    ap.add_argument("--count", type=int, default=2000)
    ap.add_argument("--rounds", type=int, default=11)
    ap.add_argument("--cpus", default=None, help="comma-separated CPU list (T4)")
    ap.add_argument("--workload", default="create", choices=sorted(WORKLOADS))
    ap.add_argument("--threads", type=int, default=1)
    args = ap.parse_args()

    # T4: explicit, recorded affinity.
    if args.cpus:
        cpus = {int(c) for c in args.cpus.split(",")}
        os.sched_setaffinity(0, cpus)
    affinity = sorted(os.sched_getaffinity(0))
    load1 = os.getloadavg()[0]

    SELECTED["name"] = args.workload
    SELECTED["threads"] = max(1, args.threads)
    kernel = ArmIdentity("kernel-ext4", args.kernel)
    ffs = ArmIdentity("frankenfs-fuse", args.frankenfs)
    serving = serving_daemon_elf_sha256(ffs.mount_point or str(args.frankenfs))
    print("mounted_ab_identity," + json.dumps(
        {"kernel": kernel.as_dict(), "frankenfs": ffs.as_dict(),
         "frankenfs_serving_binary": serving,
         "affinity": affinity, "loadavg1": round(load1, 2)}, sort_keys=True))
    if not serving.get("sha256"):
        print("PROVENANCE REFUSED: could not identify the binary serving the FUSE "
              "mount; a result whose code under test is unidentified is not evidence",
              file=sys.stderr)
        raise SystemExit(4)
    assert_identities(kernel, ffs)

    for arm_dir in (args.kernel, args.frankenfs):
        prepare(arm_dir, args.workload, args.count)

    # T5: what can the driver itself do? If an arm approaches this, the number is
    # about Python and the page cache, not about a filesystem.
    ceiling = None
    if args.tmpfs is not None:
        args.tmpfs.mkdir(parents=True, exist_ok=True)
        ceiling = st.median([measure(args.tmpfs, args.count) for _ in range(3)])
        print(f"mounted_ab_driver_ceiling,tmpfs_seconds={ceiling:.6f}")

    # A/A nulls for BOTH arms, same invocation.
    k_null = summarize(paired(args.kernel, args.kernel, args.count, args.rounds))
    f_null = summarize(paired(args.frankenfs, args.frankenfs, args.count, args.rounds))
    # A/B: kernel first, so ratio > 1 means frankenfs is FASTER.
    ab = summarize(paired(args.kernel, args.frankenfs, args.count, args.rounds))

    # Absolute medians. Needed to interpret the ratio at all, and to make the
    # T5 client-bound comparison auditable rather than internal.
    k_abs = st.median([measure(args.kernel, args.count) for _ in range(3)])
    f_abs = st.median([measure(args.frankenfs, args.count) for _ in range(3)])
    print("mounted_ab_absolute," + json.dumps({
        "kernel_seconds": k_abs, "frankenfs_seconds": f_abs,
        "tmpfs_ceiling_seconds": ceiling,
        "kernel_over_ceiling_x": (k_abs / ceiling) if ceiling else None,
        "frankenfs_over_ceiling_x": (f_abs / ceiling) if ceiling else None,
    }, sort_keys=True))

    if ceiling is not None:
        for label, t in (("kernel", k_abs), ("frankenfs", f_abs)):
            if t < ceiling * CLIENT_BOUND_MIN_RATIO:
                print(f"CLIENT-BOUND REFUSED: {label} arm {t:.6f}s is within "
                      f"{CLIENT_BOUND_MIN_RATIO}x of the tmpfs driver ceiling "
                      f"{ceiling:.6f}s — this measures the harness (T5)",
                      file=sys.stderr)
                return 3

    floor = max(k_null["null_floor"], f_null["null_floor"])
    margin = abs(math.log(ab["median_ratio"])) / math.log(floor) if floor > 1 else 0.0
    print("mounted_ab_result," + json.dumps({
        "kernel_AA": k_null, "frankenfs_AA": f_null, "AB_kernel_over_frankenfs": ab,
        "governing_null_floor": floor, "margin_x": margin,
        "workload": args.workload, "threads": SELECTED["threads"],
        "decidable": margin >= 2.0,
        "faster": ("frankenfs" if ab["median_ratio"] > 1 else "kernel-ext4"),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
