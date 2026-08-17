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
import hashlib
import os
import platform
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
SECTORS_WRITTEN_FIELD = 10  # stat 7 of 17, in 512-byte sectors (bd-2w2me)
MIN_FIELDS = 20

# `strace -c` summary rows:
#   % time     seconds  usecs/call     calls    errors syscall
SUMMARY_ROW = re.compile(r"^\s*[\d.]+\s+[\d.]+\s+\d+\s+(\d+)(?:\s+(\d+))?\s+(\w+)\s*$")

# 8d0248d3 changed `FileByteDevice::sync` from `sync_all` to `sync_data`, so the
# daemon-side call is `fdatasync`. Filtering on `fsync` alone would count zero
# and read as "no flushes at all", which is the most dangerous possible wrong
# answer here: it looks like a win.
FLUSH_SYSCALLS = ("fsync", "fdatasync", "sync_file_range", "sync", "syncfs")

# bd-2w2me. With barrier counts EQUAL, the remaining question is what each
# barrier has to flush, so the write syscalls are traced in the same window.
WRITE_SYSCALLS = ("write", "pwrite64", "writev", "pwritev", "pwritev2")

# The shapes `strace -f -o FILE` produces on a 65-thread daemon. With `-o` the
# pid prefix is BARE (`422667 writev(...)`), not the `[pid N]` form strace uses on
# stderr — a regex written for the bracketed form silently matches nothing and
# reports a daemon that never wrote anything.
TRACE_COMPLETE = re.compile(
    r"^(?:\[pid\s+(\d+)\]|(\d+))?\s*(\w+)\((-?\d+)?.*?=\s+(-?\d+)"
)
TRACE_UNFINISHED = re.compile(
    r"^(?:\[pid\s+(\d+)\]|(\d+))?\s*(\w+)\((-?\d+)?.*<unfinished\s*\.\.\.>"
)
TRACE_RESUMED = re.compile(
    r"^(?:\[pid\s+(\d+)\]|(\d+))?\s*<\.\.\.\s+(\w+)\s+resumed>.*?=\s+(-?\d+)"
)


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


def parse_trace(text: str, image_fd: int | None = None) -> tuple[dict[str, int], int]:
    """(syscall -> completed calls, bytes written TO `image_fd`) from `strace -f`.

    THE FD FILTER IS THE WHOLE POINT, and leaving it out is the trap. A FUSE
    daemon's write traffic is dominated by `writev` to /dev/fuse — the reply
    channel — which is protocol, not storage. Summing every write would have
    reported the FUSE protocol as backing-file write amplification and produced a
    large, entirely fictional number. Only writes to the image fd count.
    `image_fd=None` means count them all, which is for the selftest only.

    Bytes come from RETURN VALUES, never from the count argument and never from
    the number of calls: a daemon writing 4 KiB in one call and one writing 512
    bytes in four are not the same I/O, and ranking by call count inverts them
    (bd-2w2me's stated negative case). A short write returns less than it was
    asked for, and the shorter number is the truth.

    A failed call (`= -1`) still counts as a call — it crossed — but contributes
    no bytes.

    `strace -f` splits calls across an `<unfinished ...>` line and a `<... resumed>`
    line, and only the first carries the fd while only the second carries the
    return. They are matched up per-pid so a split write is neither dropped nor
    counted against the wrong fd.
    """
    calls: dict[str, int] = {}
    written = 0
    pending: dict[str, tuple[str, int | None]] = {}

    def record(name: str, fd: int | None, ret: int) -> None:
        nonlocal written
        calls[name] = calls.get(name, 0) + 1
        if name in WRITE_SYSCALLS and ret > 0 and (image_fd is None or fd == image_fd):
            written += ret

    for line in text.splitlines():
        resumed = TRACE_RESUMED.match(line)
        if resumed:
            pid = resumed.group(1) or resumed.group(2) or ""
            name = resumed.group(3)
            _, fd = pending.pop(pid, (name, None))
            record(name, fd, int(resumed.group(4)))
            continue
        unfinished = TRACE_UNFINISHED.match(line)
        if unfinished:
            pid = unfinished.group(1) or unfinished.group(2) or ""
            fd = int(unfinished.group(4)) if unfinished.group(4) else None
            pending[pid] = (unfinished.group(3), fd)
            continue
        complete = TRACE_COMPLETE.match(line)
        if complete:
            fd = int(complete.group(4)) if complete.group(4) else None
            record(complete.group(3), fd, int(complete.group(5)))
    return calls, written


def image_fd_of(pid: int, image: Path) -> int:
    """The daemon's fd for the image file, from /proc/<pid>/fd.

    Needed because the interesting writes and the uninteresting ones are the same
    syscall on different descriptors; see `parse_trace`.
    """
    target = str(image.resolve())
    proc = sudo("ls", "-l", f"/proc/{pid}/fd")
    if proc.returncode != 0:
        sys.exit(f"FATAL: cannot read /proc/{pid}/fd: {proc.stderr[-300:]}")
    for line in proc.stdout.splitlines():
        if " -> " not in line:
            continue
        name, _, dest = line.rpartition(" -> ")
        if dest.strip() == target:
            return int(name.split()[-1])
    sys.exit(
        f"FATAL: the daemon has no open fd for {target}. Without it every write "
        "would be counted, including the FUSE reply channel, and the byte count "
        "would be fiction."
    )


def elf_sha256(path: Path) -> str:
    """SHA-256 of the binary under test.

    bd-9jat1. The banked `release-perf/ffs-cli` was found to be four hours older
    than the levers it would have been credited with — it still carried the OLD
    per-group GDT path — while the harness binary beside it was current. Anything
    that measures a daemon and does not record WHICH daemon can be attributed to
    the wrong tree, and a timestamp is not enough because the client and the
    daemon are separate binaries with separate mtimes.
    """
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cpu_mhz() -> tuple[float, float, float]:
    """(min, max, mean) core clock across every CPU, right now.

    This host runs the POWERSAVE governor and cores clock INDEPENDENTLY — a 2.94x
    spread between the slowest and fastest core at one instant has been observed
    directly. A count does not care, but a row without its clocks cannot be
    compared against one taken in another window, so every arm records them.
    """
    speeds = [
        float(line.split(":", 1)[1])
        for line in Path("/proc/cpuinfo").read_text().splitlines()
        if line.startswith("cpu MHz")
    ]
    if not speeds:
        return (0.0, 0.0, 0.0)
    return (min(speeds), max(speeds), sum(speeds) / len(speeds))


def loadavg() -> tuple[float, float, float]:
    """The 1/5/15-minute load averages, read fresh.

    Read here rather than accepted from a caller: a load figure quoted from
    outside the run is stale by the time the arm executes.
    """
    parts = Path("/proc/loadavg").read_text().split()
    return (float(parts[0]), float(parts[1]), float(parts[2]))


def arm_provenance() -> dict:
    """Per-ARM load and clocks, sampled at the moment the arm runs."""
    one, five, fifteen = loadavg()
    mhz_min, mhz_max, mhz_mean = cpu_mhz()
    return {
        "loadavg": [one, five, fifteen],
        "cpu_mhz_min": round(mhz_min, 1),
        "cpu_mhz_max": round(mhz_max, 1),
        "cpu_mhz_mean": round(mhz_mean, 1),
        "cpu_mhz_spread": round(mhz_max / mhz_min, 3) if mhz_min > 0 else 0.0,
    }


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

    # bd-2w2me. The daemon runs 65 threads, so `strace -f` interleaves and splits
    # calls across an `<unfinished ...>` line and a `<... resumed>` line. A parser
    # that only matched `name(` would drop every split call — on this daemon that
    # is most of them — and report a write path several times cheaper than it is.
    # `strace -o FILE` writes a BARE pid prefix, not `[pid N]`. Both are accepted;
    # a parser that only knew the bracketed form matched nothing at all and
    # reported a daemon that never wrote.
    trace = (
        '307762 pwrite64(3, "\\0\\0"..., 4096, 8192) = 4096\n'
        "307762 fdatasync(3)                = 0\n"
        '307763 pwrite64(3, "\\1"..., 1024, 0 <unfinished ...>\n'
        "307764 fdatasync(3)                = 0\n"
        "307763 <... pwrite64 resumed>)     = 1024\n"
        '307765 write(3, "x"..., 512)       = -1 EIO (Input/output error)\n'
        '307766 writev(4, [{iov_base="\\20"..., iov_len=16}], 1) = 16\n'
    )
    calls, written = parse_trace(trace, image_fd=3)
    assert calls["pwrite64"] == 2, calls
    cases += 1
    assert calls["fdatasync"] == 2, calls
    cases += 1
    # The split call must be counted once, with the fd from its unfinished half.
    assert written == 4096 + 1024, f"resumed write miscounted: {written}"
    cases += 1
    assert calls["write"] == 1, "a failed write still crossed"
    cases += 1
    # THE LOAD-BEARING CASE: fd 4 is /dev/fuse, the reply channel. Counting it
    # would report the FUSE protocol as backing-file write amplification.
    assert calls["writev"] == 1, "the reply write is still a call"
    cases += 1
    _, unfiltered = parse_trace(trace, image_fd=None)
    assert unfiltered == 4096 + 1024 + 16, unfiltered
    cases += 1
    assert written < unfiltered, "the fd filter must actually exclude /dev/fuse traffic"
    cases += 1

    # Provenance helpers must read THIS host, not a fixture — a per-arm clock that
    # silently returns a constant is worse than none, because a row would carry a
    # figure nobody could falsify.
    mhz_min, mhz_max, mhz_mean = cpu_mhz()
    assert mhz_max >= mhz_min > 0, (mhz_min, mhz_max)
    cases += 1
    assert mhz_min <= mhz_mean <= mhz_max, (mhz_min, mhz_mean, mhz_max)
    cases += 1
    one, five, fifteen = loadavg()
    assert one >= 0 and five >= 0 and fifteen >= 0, (one, five, fifteen)
    cases += 1
    arm = arm_provenance()
    assert set(arm) >= {"loadavg", "cpu_mhz_min", "cpu_mhz_max", "cpu_mhz_spread"}, arm
    cases += 1
    # The ELF hash must actually distinguish two different files, or it cannot
    # detect the stale-daemon case it exists for.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        a, b = Path(tmp) / "a", Path(tmp) / "b"
        a.write_bytes(b"old per-group path")
        b.write_bytes(b"new batched path")
        assert elf_sha256(a) != elf_sha256(b), "the ELF hash must separate two binaries"
        assert elf_sha256(a) == elf_sha256(a), "and be stable for one"
    cases += 2

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
        "import os,sys;p=sys.argv[1];d=os.path.dirname(p);"
        "os.makedirs(d,exist_ok=True);"
        f"os.chown(d,{os.getuid()},{os.getgid()});"
        "fd=os.open(p,os.O_CREAT|os.O_RDWR,0o644);"
        "os.pwrite(fd,b'\\0'*4096,0);os.fsync(fd);os.close(fd);"
        f"os.chown(p,{os.getuid()},{os.getgid()})"
    )
    proc = sudo(sys.executable, "-c", body, str(path)) if as_root else \
        run([sys.executable, "-c", body, str(path)])
    if proc.returncode != 0:
        sys.exit(f"FATAL: could not create {path}: {proc.stderr[-400:]}")


def device_stats(device: str) -> tuple[int, int]:
    """(flush requests completed, sectors written) for `device`."""
    for line in DISKSTATS.read_text().splitlines():
        fields = line.split()
        if len(fields) >= 3 and fields[2] == device:
            if len(fields) < MIN_FIELDS:
                sys.exit(
                    f"FATAL: /proc/diskstats reports no flush counter for {device}. "
                    "This needs a kernel that exports flush requests (>= 5.5); without "
                    "it the count would read as zero for the wrong reason."
                )
            return int(fields[FLUSH_FIELD - 1]), int(fields[SECTORS_WRITTEN_FIELD - 1])
    sys.exit(f"FATAL: {device} not present in /proc/diskstats")


def measure_kernel_arm(device: str, workload: Path, client: Path, operations: int,
                       fstype: str = "ext4") -> dict:
    """Barriers AND bytes ext4 asked its backing file for, via the loop device."""
    control_flushes, control_sectors = device_stats(device)
    time.sleep(2.0)
    idle_flushes, idle_sectors = device_stats(device)
    control = idle_flushes - control_flushes
    control_written = idle_sectors - control_sectors

    subprocess.run(["sync"], check=False)
    time.sleep(0.3)
    before_flushes, before_sectors = device_stats(device)
    provenance = arm_provenance()
    result = run([sys.executable, str(client), str(workload), str(operations)])
    # No `sync` inside the measured window: it is itself a barrier and inflated
    # the count by exactly one (129 flushes for 64 fsyncs, 2.0156). The client's
    # own fsync has already forced everything down to the loop device.
    after_flushes, after_sectors = device_stats(device)
    if result.returncode != 0:
        sys.exit(f"FATAL: kernel client failed: {result.stderr[-600:]}")
    flushes = after_flushes - before_flushes
    written = (after_sectors - before_sectors) * 512
    if control != 0 or control_written != 0:
        sys.exit(
            f"FATAL: the idle control on {device} counted {control} flushes and "
            f"{control_written * 512} bytes. This device is shared, so the arm counts "
            "would include someone else's I/O and the comparison would be noise over "
            "noise. Refusing."
        )
    return {
        "arm": f"kernel-{fstype}",
        "counted_by": f"/proc/diskstats flush requests + sectors written on {device}",
        "operations": operations,
        "control": control,
        "flushes": flushes,
        "per_client_fsync": per_fsync(flushes, operations),
        "bytes": written,
        "bytes_per_client_fsync": written / operations,
        "provenance": provenance,
    }


def measure_fuse_arm(daemon_pid: int, workload: Path, client: Path,
                     operations: int, out_dir: Path, image: Path) -> dict:
    """Barriers and bytes FrankenFS asked its image file for, from the daemon."""
    if not shutil.which("strace"):
        sys.exit("FATAL: strace is required to count the daemon's flush syscalls")

    image_fd = image_fd_of(daemon_pid, image)
    traced_syscalls = FLUSH_SYSCALLS + WRITE_SYSCALLS

    def traced(ops: int, tag: str) -> tuple[int, int]:
        """(flush syscalls, bytes written) over one window."""
        out = out_dir / f"strace-{tag}.txt"
        proc = subprocess.Popen(
            ["sudo", "-n", "strace", "-f", "-e",
             f"trace={','.join(traced_syscalls)}", "-p", str(daemon_pid), "-o", str(out)],
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
        sudo("pkill", "-INT", "-f", "strace -f -e trace=")
        proc.wait(timeout=30)
        time.sleep(1.0)
        if not out.exists():
            return 0, 0
        calls, written = parse_trace(out.read_text(), image_fd=image_fd)
        return sum(v for k, v in calls.items() if k in FLUSH_SYSCALLS), written

    control_flushes, control_bytes = traced(0, "control")
    if control_flushes != 0 or control_bytes != 0:
        sys.exit(
            f"FATAL: the idle daemon issued {control_flushes} flush syscalls and wrote "
            f"{control_bytes} bytes with no client running. Refusing: the measured arm "
            "would include them."
        )
    provenance = arm_provenance()
    flushes, written = traced(operations, f"n{operations}")
    return {
        "arm": "frankenfs-fuse",
        "counted_by": (f"strace -f on daemon pid {daemon_pid}, return values summed, "
                       f"writes filtered to the image fd {image_fd}"),
        "operations": operations,
        "control": control_flushes,
        "flushes": flushes,
        "per_client_fsync": per_fsync(flushes, operations),
        "bytes": written,
        "bytes_per_client_fsync": written / operations,
        "provenance": provenance,
    }


def fsck_or_die(image: Path, fstype: str) -> str:
    """Refuse the run if the FUSE arm left the image inconsistent.

    THIS EXISTS BECAUSE ITS ABSENCE COST A REAL REGRESSION. bd-42gtq made the
    btrfs commit reuse unchanged tree blocks, and every commit opens by purging
    the FS tree's extent items — so a reused block's backref stayed purged and
    `btrfs check` reported "tree extent[...] root 5 has no backref item" for every
    reused node. It appeared only from the SECOND commit onward, so the
    single-commit fixture the lever was verified against could not see it, while
    THIS script — which drives N commits through a real mount — reproduced it
    immediately and said nothing, because it only counted.

    A measurement tool that drives the write path and does not check what it left
    behind is one line short of being a correctness gate. `btrfs check` and
    `e2fsck -fn` are read-only and take seconds.
    """
    if fstype == "btrfs":
        proc = run(["btrfs", "check", "--readonly", str(image)])
        dirty = proc.returncode != 0
    else:
        proc = run(["e2fsck", "-fn", str(image)])
        # e2fsck: 0 clean, 4 uncorrected errors; 1/2 mean it would have fixed it.
        dirty = proc.returncode not in (0,)
    tail = (proc.stdout + proc.stderr).strip().splitlines()
    summary = tail[-1] if tail else "(no output)"
    if dirty:
        interesting = [
            line for line in tail
            if any(k in line.lower() for k in ("error", "backref", "not found", "mismatch"))
        ]
        sys.exit(
            "FATAL: the FUSE arm left the image INCONSISTENT — refusing to report a "
            f"count for a write path that corrupts.\n  fsck rc={proc.returncode}\n  "
            + "\n  ".join(interesting[:8] or [summary])
        )
    return summary


def report(rows: list[dict]) -> None:
    print()
    print("bd-7nr8p / bd-2w2me — barriers and bytes per client fsync, to the BACKING FILE")
    print("(a COUNT; load-independent, needs no quiet window)")
    print(f"{'arm':<16} {'N':>5} {'ctl':>5} {'flushes':>8} {'per fsync':>10} "
          f"{'bytes':>12} {'B/fsync':>10} {'x4KiB':>7}")
    for row in rows:
        amplification = row["bytes_per_client_fsync"] / 4096
        print(f"{row['arm']:<16} {row['operations']:>5} {row['control']:>5} "
              f"{row['flushes']:>8} {row['per_client_fsync']:>10.4f} "
              f"{row['bytes']:>12} {row['bytes_per_client_fsync']:>10.1f} "
              f"{amplification:>7.2f}")
    for row in rows:
        print(f"  {row['arm']}: {row['counted_by']}")
    # bd-9jat1 / provenance. A count is load-independent, but a row without its
    # window cannot be compared against one taken in another, and a row without
    # the daemon's ELF cannot be attributed to a tree at all — the banked
    # release-perf ffs-cli was four hours stale and still carried the OLD GDT path
    # while the harness binary beside it was current.
    print()
    print("  provenance (sampled per ARM, at the moment that arm ran):")
    for row in rows:
        p = row.get("provenance", {})
        load = p.get("loadavg", [0, 0, 0])
        print(f"    {row['arm']:<15} loadavg {load[0]:.2f}/{load[1]:.2f}/{load[2]:.2f}  "
              f"cpu MHz min {p.get('cpu_mhz_min', 0):.0f} max {p.get('cpu_mhz_max', 0):.0f} "
              f"mean {p.get('cpu_mhz_mean', 0):.0f} spread {p.get('cpu_mhz_spread', 0):.2f}x")
    if len(rows) == 2:
        ours = next(r for r in rows if r["arm"] == "frankenfs-fuse")
        theirs = next(r for r in rows if r["arm"].startswith("kernel-"))
        if theirs["bytes_per_client_fsync"] > 0:
            ratio = ours["bytes_per_client_fsync"] / theirs["bytes_per_client_fsync"]
            print(f"\n  write amplification, ours / {theirs['arm']}: {ratio:.3f}x")


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
    parser.add_argument("--fstype", default="ext4", choices=["ext4", "btrfs"],
                        help="filesystem the image holds. The KERNEL arm mounts with this "
                             "type; the FrankenFS arm detects it from the image either way")
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

    # The ext4 fixture has a user-owned `nested/`; the btrfs fixture does not, so
    # its workload file goes in a directory this run creates itself.
    subdir = args.subdir
    if args.fstype == "btrfs" and subdir == "nested":
        subdir = "fsyncdir"

    work = args.work_dir
    work.mkdir(parents=True, exist_ok=True)
    # A run that aborts mid-measurement leaves its mountpoint as a dead transport
    # endpoint, and every LATER run then dies on `stat` before it measures
    # anything -- one abort poisons the instrument indefinitely. That is exactly
    # the defect 1f0257e9 fixed for the comparator's seed mountpoint; do not
    # reintroduce it here. Clear both mountpoints unconditionally at startup.
    for name in ("kmnt", "fmnt"):
        point = work / name
        run(["fusermount3", "-u", str(point)])
        sudo("umount", str(point))
        point.mkdir(parents=True, exist_ok=True)
    client = work / "fsync_client.py"
    client.write_text(CLIENT_SOURCE)

    print("bd-7nr8p: this is a COUNT. It is load-independent and needs no quiet window.")
    # bd-9jat1: name the daemon being measured, before measuring it. The banked
    # release-perf ffs-cli was four hours older than the levers it would have been
    # credited with, while the harness binary beside it was current — so neither
    # an mtime nor "the tree is up to date" is evidence about the DAEMON.
    print(f"  host {platform.node()}  kernel {platform.release()}")
    print(f"  daemon {args.cli}")
    print(f"  daemon ELF sha256 {elf_sha256(args.cli)}")
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
        mounted = sudo("mount", "-t", args.fstype, loop, str(work / "kmnt"))
        if mounted.returncode != 0:
            sys.exit(f"FATAL: kernel mount failed: {mounted.stderr[-400:]}")
        try:
            workload = work / "kmnt" / subdir / "fsync.bin"
            make_workload_file(workload, as_root=True)
            rows.append(measure_kernel_arm(device, workload, client, args.operations,
                                           args.fstype))
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
        workload = fmnt / subdir / "fsync.bin"
        make_workload_file(workload, as_root=False)
        rows.append(measure_fuse_arm(daemon.pid, workload, client, args.operations,
                                     work, fimage))
    finally:
        run(["fusermount3", "-u", str(fmnt)])
        try:
            daemon.wait(timeout=20)
        except subprocess.TimeoutExpired:  # pragma: no cover
            daemon.kill()

    # The image the FUSE arm just wrote, checked before any number is reported.
    fsck_summary = fsck_or_die(fimage, args.fstype)

    report(rows)
    print(f"  fsck after the FUSE arm ({args.fstype}): {fsck_summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
