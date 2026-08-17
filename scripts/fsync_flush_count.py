#!/usr/bin/env python3
"""COUNT device barriers per client fsync, for bd-7nr8p.

THE QUESTION. `fsync-journal-commit` measures 200.5 ms against kernel ext4's
101.5 ms for 8 x 4 KiB write+fsync -- `1.976308x`, which is close enough to 2.0
on a workload that is nothing but write-and-flush to suggest we issue TWO device
barriers per client fsync where ext4 issues one. Nobody had counted.

WHY A COUNT AND NOT A TIMING. Two attempts to size this by arithmetic already
went wrong in opposite directions, both by borrowing a constant from the wrong
regime (the ~400 us in `ffs-block/src/lib.rs` is a CLEAN flush and does not
describe a data-carrying barrier). A count is regime-independent, deterministic,
and needs no quiet window -- which on this host, which spends most of its time
above the certification ceiling, is the difference between an answer and a defer.

WHAT IS COUNTED, AND WHY IT IS THE SAME QUANTITY IN BOTH ARMS. The comparable
number is *how many durability barriers the filesystem asks its BACKING FILE for,
per client fsync*. Both arms back onto a regular file, so both have one:

  kernel ext4   mounted over a loop device; the loop driver turns each
                `REQ_OP_FLUSH` into a `vfs_fsync` of the backing file, so the
                device's "flush requests completed" (`/proc/diskstats` field 19)
                IS the count of barriers ext4 asked for.
  FrankenFS     the daemon calls `fdatasync` on the image file directly, counted
                with `strace -c` from outside the process.

THE OBVIOUS DESIGN DOES NOT WORK, and the reason is worth writing down: the two
arms cannot be put on the SAME loop device, because `ffs-cli` refuses a block
device outright ("image is not a recognized ext4 or btrfs filesystem" on a
`/dev/loopN` the kernel mounts happily) -- it sizes the image from
`metadata().len()`, which is 0 for a block special. So the arms are counted by
two different tools, and the defence against that being an artifact is that both
tools count the same event at the same boundary, and that both answers are exact
integers at every N rather than noisy averages.

The client is byte-for-byte the harness's `fsync_journal_batch`
(`crates/ffs-harness/src/bin/ffs_mounted_kernel_bench.rs`): one pre-existing
file, a 4096-byte payload rewritten at offset 0, `fsync` after every write.

THE NULL THIS NEEDS. A flush counter on a shared device counts everyone. Every
run therefore takes an idle control of the same wall duration with no client
running, and REFUSES the count if the control is not zero -- otherwise a busy
device would inflate both arms and the ratio would silently be noise/noise.

    scripts/fsync_flush_count.py --selftest
    scripts/fsync_flush_count.py --image ~/ext4.img --cli target/debug/ffs-cli

Needs passwordless sudo for `losetup`/`mount`. `/data` is mounted `nosuid` on
this host, so `fusermount3` is refused there: the mountpoints default to `$HOME`
and `--work-dir` must not point inside a `nosuid` filesystem.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

# /proc/diskstats: major minor name, then 17 stat fields. Flush requests
# completed is the 16th stat, i.e. the 19th whitespace-separated field. Kernels
# before 5.5 emit only 14 stats and have no flush counter at all, which is a
# refusal rather than a zero -- a missing counter reads exactly like a device
# that never flushes.
DISKSTATS = Path("/proc/diskstats")
FLUSH_FIELD = 19
MIN_FIELDS = 20

# `strace -c` summary rows:
#   % time     seconds  usecs/call     calls    errors syscall
SUMMARY_ROW = re.compile(r"^\s*[\d.]+\s+[\d.]+\s+\d+\s+(\d+)(?:\s+(\d+))?\s+(\w+)\s*$")

# 8d0248d3 changed `FileByteDevice::sync` from `sync_all` to `sync_data`, so the
# daemon-side call is `fdatasync`. Filtering on `fsync` alone would count zero
# and read as "no flushes at all", which is the most dangerous possible wrong
# answer here: it looks like a win.
FLUSH_SYSCALLS = ("fsync", "fdatasync", "sync_file_range", "sync", "syncfs")


def parse_flush_count(text: str, device: str) -> int | None:
    """Flush requests completed for `device`, or None if unavailable.

    None means "this kernel does not report it", which callers must treat as a
    refusal. Returning 0 there would be indistinguishable from a device that
    genuinely issued no barriers.
    """
    for line in text.splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[2] == device:
            if len(fields) < MIN_FIELDS:
                return None
            return int(fields[FLUSH_FIELD - 1])
    return None


def parse_syscall_counts(text: str) -> dict[str, int]:
    """Syscall -> call count from a `strace -c` summary.

    Counts calls, not errors: a flush that returned an error still crossed into
    the kernel, and for "how many barriers did we ask for" that is the number
    that matters.
    """
    counts: dict[str, int] = {}
    for line in text.splitlines():
        match = SUMMARY_ROW.match(line)
        if match:
            counts[match.group(3)] = int(match.group(1))
    return counts


def per_fsync(flushes: int, operations: int) -> float:
    """Flushes per client fsync. `operations` of 0 is a caller bug, not a ratio."""
    if operations <= 0:
        raise ValueError("operations must be positive")
    return flushes / operations


def selftest() -> int:
    cases = 0

    sample = "   7      13 loop13 61 0 1520 10 0 0 0 0 0 10 10 0 0 0 0 803 12\n"
    assert parse_flush_count(sample, "loop13") == 803
    cases += 1
    assert parse_flush_count(sample, "loop9") is None, "absent device is not zero"
    cases += 1

    # A pre-5.5 diskstats line has 14 stats and no flush counter. It must refuse,
    # not report 0 -- that is the failure this check exists for.
    short = "   7      13 loop13 61 0 1520 10 0 0 0 0 0 10 10\n"
    assert parse_flush_count(short, "loop13") is None, "missing counter must refuse"
    cases += 1

    strace = (
        "% time     seconds  usecs/call     calls    errors syscall\n"
        "------ ----------- ----------- --------- --------- ----------------\n"
        " 99.62    0.036067          17      2048           fdatasync\n"
        "  0.38    0.000138           4        32         2 fsync\n"
    )
    counts = parse_syscall_counts(strace)
    assert counts["fdatasync"] == 2048, counts
    cases += 1
    assert counts["fsync"] == 32, "errored calls still crossed"
    cases += 1

    assert per_fsync(16, 8) == 2.0
    cases += 1
    try:
        per_fsync(16, 0)
    except ValueError:
        cases += 1
    else:  # pragma: no cover
        raise AssertionError("a zero-operation ratio must not be reported")

    print(f"selftest: {cases} cases OK")
    return 0


# --- everything below here touches real mounts -------------------------------


def run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False, **kwargs)


def flush_count(device: str) -> int:
    value = parse_flush_count(DISKSTATS.read_text(), device)
    if value is None:
        sys.exit(
            f"FATAL: /proc/diskstats reports no flush counter for {device}. "
            "This needs a kernel that exports flush requests (>= 5.5); without it "
            "the count would read as zero for the wrong reason."
        )
    return value


def idle_control(device: str, seconds: float) -> int:
    """Flushes on `device` over `seconds` with no client running.

    The null for the whole measurement: this device is shared, so a non-zero
    control means both arms were counting someone else's barriers too.
    """
    before = flush_count(device)
    time.sleep(seconds)
    return flush_count(device) - before


CLIENT_SOURCE = '''#!/usr/bin/env python3
"""N x (pwrite 4 KiB at offset 0, then fsync) -- the harness's fsync_journal_batch."""
import os, sys
path, n = sys.argv[1], int(sys.argv[2])
fd = os.open(path, os.O_RDWR)
try:
    for index in range(n):
        os.pwrite(fd, bytes([(index * 17) % 251]) * 4096, 0)
        os.fsync(fd)
finally:
    os.close(fd)
'''


def sudo(*cmd: str) -> subprocess.CompletedProcess:
    return run(["sudo", "-n", *cmd])


def make_workload_file(path: Path, as_root: bool) -> None:
    """Create the 4 KiB file the client rewrites. Never part of a measured window."""
    body = (
        "import os,sys;p=sys.argv[1];"
        "fd=os.open(p,os.O_CREAT|os.O_RDWR,0o644);"
        "os.pwrite(fd,b'\\0'*4096,0);os.fsync(fd);os.close(fd);"
        f"os.chown(p,{os.getuid()},{os.getgid()})"
    )
    proc = sudo(sys.executable, "-c", body, str(path)) if as_root else \
        run([sys.executable, "-c", body, str(path)])
    if proc.returncode != 0:
        sys.exit(f"FATAL: could not create {path}: {proc.stderr[-400:]}")


def measure_kernel_arm(device: str, workload: Path, client: Path, operations: int) -> dict:
    """Barriers ext4 asked its backing file for, via the loop device's flush counter."""
    control = idle_control(device, 2.0)
    subprocess.run(["sync"], check=False)
    time.sleep(0.3)
    before = flush_count(device)
    result = run([sys.executable, str(client), str(workload), str(operations)])
    after = flush_count(device)
    if result.returncode != 0:
        sys.exit(f"FATAL: kernel client failed: {result.stderr[-600:]}")
    flushes = after - before
    if control != 0:
        sys.exit(
            f"FATAL: the idle control on {device} counted {control} flushes. This "
            "device is shared, so the arm counts would include someone else's "
            "barriers and the comparison would be noise over noise. Refusing."
        )
    return {
        "arm": "kernel-ext4",
        "counted_by": f"/proc/diskstats flush requests on {device}",
        "operations": operations,
        "control": control,
        "flushes": flushes,
        "per_client_fsync": per_fsync(flushes, operations),
    }


def measure_fuse_arm(daemon_pid: int, workload: Path, client: Path,
                     operations: int, out_dir: Path) -> dict:
    """Barriers FrankenFS asked its image file for, via the daemon's own syscalls."""
    if not shutil.which("strace"):
        sys.exit("FATAL: strace is required to count the daemon's flush syscalls")

    def traced(ops: int, tag: str) -> int:
        out = out_dir / f"strace-{tag}.txt"
        proc = subprocess.Popen(
            ["sudo", "-n", "strace", "-f", "-c", "-e",
             f"trace={','.join(FLUSH_SYSCALLS)}", "-p", str(daemon_pid), "-o", str(out)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(2.5)  # attach must complete before the client starts
        if ops > 0:
            result = run([sys.executable, str(client), str(workload), str(ops)])
            if result.returncode != 0:
                sys.exit(f"FATAL: FUSE client failed: {result.stderr[-600:]}")
        else:
            time.sleep(3.0)
        time.sleep(0.5)
        sudo("pkill", "-INT", "-f", "strace -f -c -e trace=fsync")
        proc.wait(timeout=30)
        time.sleep(1.0)
        if not out.exists():
            return 0
        counts = parse_syscall_counts(out.read_text())
        return sum(value for key, value in counts.items() if key in FLUSH_SYSCALLS)

    control = traced(0, "control")
    if control != 0:
        sys.exit(
            f"FATAL: the idle daemon issued {control} flush syscalls with no client "
            "running. Refusing: the measured arm would include them."
        )
    flushes = traced(operations, f"n{operations}")
    return {
        "arm": "frankenfs-fuse",
        "counted_by": f"strace -c on daemon pid {daemon_pid} ({'/'.join(FLUSH_SYSCALLS)})",
        "operations": operations,
        "control": control,
        "flushes": flushes,
        "per_client_fsync": per_fsync(flushes, operations),
    }


def report(rows: list[dict]) -> None:
    print()
    print("bd-7nr8p — barriers per client fsync (a COUNT; load-independent)")
    print(f"{'arm':<16} {'N':>6} {'control':>8} {'flushes':>8} {'per fsync':>10}")
    for row in rows:
        print(f"{row['arm']:<16} {row['operations']:>6} {row['control']:>8} "
              f"{row['flushes']:>8} {row['per_client_fsync']:>10.4f}")
    for row in rows:
        print(f"  {row['arm']}: {row['counted_by']}")


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--image", type=Path,
                        help="an ext4 image; it is COPIED, never mounted in place")
    parser.add_argument("--cli", type=Path, default=Path("target/debug/ffs-cli"))
    parser.add_argument("--work-dir", type=Path, default=Path.home() / "bd7nr8p-flush-count",
                        help="must NOT be on a nosuid filesystem; /data is one")
    parser.add_argument("--operations", type=int, default=64,
                        help="client fsyncs per arm. The harness row uses 8; more "
                             "only sharpens a count that is already deterministic")
    parser.add_argument("--subdir", default="nested",
                        help="a directory on the image owned by this user; the image "
                             "root is often root-owned and the client must not need sudo")
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    if not args.image:
        parser.error("--image is required")
    if not args.cli.is_file():
        sys.exit(f"FATAL: no ffs-cli at {args.cli}")
    if not args.image.is_file():
        sys.exit(f"FATAL: no image at {args.image}")

    work = args.work_dir
    (work / "kmnt").mkdir(parents=True, exist_ok=True)
    (work / "fmnt").mkdir(parents=True, exist_ok=True)
    client = work / "fsync_client.py"
    client.write_text(CLIENT_SOURCE)

    print("bd-7nr8p: this is a COUNT. It is load-independent and needs no quiet window.")
    rows: list[dict] = []

    # ── kernel ext4 arm ────────────────────────────────────────────────────────
    kimage = work / "kernel.img"
    shutil.copyfile(args.image, kimage)
    losetup = sudo("losetup", "--find", "--show", str(kimage))
    if losetup.returncode != 0:
        sys.exit(f"FATAL: losetup failed: {losetup.stderr[-400:]}")
    loop = losetup.stdout.strip()
    device = os.path.basename(loop)
    try:
        mounted = sudo("mount", "-t", "ext4", loop, str(work / "kmnt"))
        if mounted.returncode != 0:
            sys.exit(f"FATAL: kernel mount failed: {mounted.stderr[-400:]}")
        try:
            workload = work / "kmnt" / args.subdir / "fsync.bin"
            make_workload_file(workload, as_root=True)
            rows.append(measure_kernel_arm(device, workload, client, args.operations))
        finally:
            sudo("umount", str(work / "kmnt"))
    finally:
        sudo("losetup", "-d", loop)

    # ── FrankenFS arm ──────────────────────────────────────────────────────────
    fimage = work / "fuse.img"
    shutil.copyfile(args.image, fimage)
    fmnt = work / "fmnt"
    daemon = subprocess.Popen(
        [str(args.cli.resolve()), "mount", "--rw", str(fimage), str(fmnt)],
        stdout=(work / "mount.log").open("w"), stderr=subprocess.STDOUT,
    )
    try:
        for _ in range(40):
            time.sleep(0.5)
            if os.path.ismount(fmnt):
                break
        else:
            sys.exit(f"FATAL: FUSE mount never appeared\n{(work / 'mount.log').read_text()[-800:]}")
        workload = fmnt / args.subdir / "fsync.bin"
        make_workload_file(workload, as_root=False)
        rows.append(measure_fuse_arm(daemon.pid, workload, client, args.operations, work))
    finally:
        run(["fusermount3", "-u", str(fmnt)])
        try:
            daemon.wait(timeout=20)
        except subprocess.TimeoutExpired:  # pragma: no cover
            daemon.kill()

    report(rows)
    return 0


if __name__ == "__main__":
    sys.exit(main())
