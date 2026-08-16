#!/usr/bin/env python3
"""Reproduce every bd-ha71t claim about the per-path-op capability probe.

The ledger rows banked on 2026-08-16 -- the counted mechanism (`400 getxattr
crossings for 200 warm stats -> 0`) and the A/B that followed (`>= 4.661799x`,
FrankenFS landing at the tmpfs client floor) -- were produced by four throwaway
shell scripts in a scratchpad. That is the same defect
`scripts/fuse_vs_kernel_abba.sh` was landed to fix for the ratio harness: a row
citing an instrument nobody else can run. This is that instrument.

Four modes, each answering one question:

  count    How many `getxattr` requests cross the FUSE boundary per warm stat,
           with the suppression switch off and on? (The COUNT behind the row.)
           ⚠️ The per-stat figure is CLIENT-DEPENDENT: `--client process`
           (a `stat(1)` per file) crosses 2.000 times per warm stat and
           `--client inproc` (one process, `lstat` in a loop) crosses 1.000.
           Both were measured on this host with the same ELF and image. The
           suppressed arm is 0 either way, which is the part that decides the
           lever.
  parity   Does the suppressed mount return the SAME metadata, or is it merely
           fast? (The validity gate. See WHY IT EXISTS below.)
  auto     Does `FFS_FUSE_XATTR_NO_SUPPORT=auto` prove absence and activate on
           an image that has no xattrs?
  planted  Does it REFUSE on an image that has one? (The negative case.)

WHY THE PARITY MODE EXISTS, because it is the part that is easy to skip. The
ABBA client counts only stats that SUCCEEDED (`if (stat(...) == 0)`), so an arm
whose every stat failed would time as fast as one that answered instantly and
would pass every A/A null. A suppression switch producing a 5x is exactly the
shape of that failure. `parity` compares the full stat tuple -- inode, size,
mode, link count, uid, gid, mtime -- across both settings and fails on the first
difference.

WHY THE COUNTING IS BY TRACE TARGET AND NOT BY MESSAGE. The first version of
this counted the two arms with different filters, because the suppression path
had its own trace target: the ON arm would have read as zero for the wrong
reason. An A/B whose arms are counted by different filters is not a count. Both
paths now emit on `ffs::fuse::xattr_probe` and this counts that target.

  scripts/xattr_probe_evidence.py --selftest
  scripts/xattr_probe_evidence.py count   --cli target/debug/ffs-cli --image X.img
  scripts/xattr_probe_evidence.py parity  --cli ... --image ...
  scripts/xattr_probe_evidence.py auto    --cli ... --image ...
  scripts/xattr_probe_evidence.py planted --cli ... --image ...   # needs sudo

⚠️ MOUNTPOINT LOCATION. `/data` is mounted `nosuid` on this host, so the setuid
`fusermount3` is refused there and every mount under `/data/tmp` fails with
`Permission denied`. Mountpoints default to `$HOME`; `--work-dir` may move them
but must not point inside a `nosuid` filesystem.

None of these modes needs a quiet window. A count and a metadata comparison are
load-independent, which is the reason to prefer them to a timing argument when
the host is busy -- the count was taken at loadavg 17 deliberately.
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

# The one trace target both the probe path and the suppression path emit on.
# Counting by target rather than by message is what keeps the two arms
# comparable; see the module docstring.
PROBE_TARGET = "ffs::fuse::xattr_probe"
PROBE_RUST_LOG = f"{PROBE_TARGET}=trace"

# `tracing`'s human formatter writes the target in the line; ANSI escapes may be
# interleaved, so strip them before matching rather than matching around them.
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def count_crossings(log_text: str) -> int:
    """Count `getxattr` requests that crossed the kernel boundary.

    Counts by TRACE TARGET, so the suppressed arm (which answers `ENOSYS` from a
    different code path) and the normal arm are counted by the same rule. A
    message-text match would silently count only one of them.
    """
    return sum(1 for line in ANSI.sub("", log_text).splitlines() if PROBE_TARGET in line)


def stat_via_process(path: Path) -> None:
    """Stat by spawning `stat(1)`, i.e. ONE PROCESS PER STAT.

    Not a stylistic choice -- it measures a different thing. A fresh process per
    stat crosses the FUSE boundary TWICE per warm stat; a single long-lived
    process doing the same stats in-process crosses ONCE. Both were measured on
    this host with the same ELF and the same image (see `--client`). The per-op
    probe count is therefore a property of the CLIENT as well as the filesystem,
    the same way the client floor `C` is in `scripts/fuse_vs_kernel_abba.sh`, and
    a row quoting "N probes per stat" without saying which client is
    under-specified.
    """
    subprocess.run(["stat", "-c", "%s", str(path)], capture_output=True, check=False)


def stat_tuple(path: Path) -> str | None:
    """Every field of a stat that the format layer is responsible for.

    Returns None if the stat failed, which the caller must count rather than
    skip: a mount whose stats all fail is the failure mode this exists to catch.
    """
    try:
        st = path.lstat()
    except OSError:
        return None
    return (
        f"{st.st_ino} {st.st_size} {st.st_mode} {st.st_nlink} "
        f"{st.st_uid} {st.st_gid} {int(st.st_mtime)}"
    )


def first_difference(off: list[str], on: list[str]) -> str | None:
    """Describe the first metadata difference between two arms, or None.

    A length mismatch is itself a difference and is reported as one: an arm that
    saw fewer files did not agree with the other, it just had less to disagree
    about.
    """
    if len(off) != len(on):
        return f"file count differs: off={len(off)} on={len(on)}"
    for index, (a, b) in enumerate(zip(off, on)):
        if a != b:
            return f"entry {index} differs: off={a!r} on={b!r}"
    return None


def verdict(off_crossings: int, on_crossings: int, stats: int) -> str:
    """Render the count the way the ledger rows quote it."""
    per_stat = off_crossings / stats if stats else 0.0
    return (
        f"switch OFF: {off_crossings} crossings for {stats} warm stats "
        f"({per_stat:.3f} per stat)\n"
        f"switch ON:  {on_crossings} crossings for the same {stats} stats\n"
        f"=> {off_crossings} requests -> {on_crossings}"
    )


# --- everything below here touches a real mount -----------------------------


def _mount(cli: Path, image: Path, mnt: Path, log: Path, env_extra: dict[str, str],
           rw: bool = False) -> subprocess.Popen:
    mnt.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, RUST_LOG=PROBE_RUST_LOG, **env_extra)
    args = [str(cli), "mount"] + (["--rw"] if rw else []) + [str(image), str(mnt)]
    handle = log.open("w")
    proc = subprocess.Popen(args, stdout=handle, stderr=subprocess.STDOUT, env=env)
    # Bounded wait, never an unbounded loop: a mount that has not appeared in
    # 18 seconds has failed, and saying so beats hanging.
    for _ in range(90):
        if os.path.ismount(mnt):
            return proc
        time.sleep(0.2)
    proc.kill()
    sys.exit(f"FATAL: mount did not appear at {mnt}\n{log.read_text()[-600:]}")


def _umount(mnt: Path, proc: subprocess.Popen) -> None:
    subprocess.run(["fusermount3", "-u", str(mnt)], capture_output=True, check=False)
    try:
        proc.wait(timeout=30)
    except subprocess.TimeoutExpired:
        proc.kill()


def _files(mnt: Path, limit: int) -> list[Path]:
    found: list[Path] = []
    for root, _dirs, names in os.walk(mnt):
        for name in sorted(names):
            found.append(Path(root) / name)
            if len(found) >= limit:
                return found
    return found


def _arm(cli: Path, image: Path, work: Path, name: str, knob: str, limit: int,
         rw: bool = False) -> tuple[Path, subprocess.Popen, list[Path]]:
    img = work / f"{name}.img"
    shutil.copy(image, img)
    mnt, log = work / f"mnt-{name}", work / f"{name}.log"
    proc = _mount(cli, img, mnt, log, {"FFS_FUSE_XATTR_NO_SUPPORT": knob}, rw=rw)
    return log, proc, _files(mnt, limit)


def mode_count(args: argparse.Namespace) -> int:
    results = {}
    for name, knob in (("off", "0"), ("on", "1")):
        log, proc, files = _arm(args.cli, args.image, args.work_dir, name, knob, args.stats)
        stat_once = stat_via_process if args.client == "process" else stat_tuple
        # Warm first: the pass being counted must not include the cold walk that
        # populated the kernel's caches.
        for path in files:
            stat_once(path)
        before = count_crossings(log.read_text())
        for path in files:
            stat_once(path)
        after = count_crossings(log.read_text())
        results[name] = (after - before, len(files))
        _umount(args.work_dir / f"mnt-{name}", proc)
    (off, stats), (on, _) = results["off"], results["on"]
    print(f"client={args.client}")
    print(verdict(off, on, stats))
    return 0 if off > on else 1


def mode_parity(args: argparse.Namespace) -> int:
    tuples, failures = {}, {}
    for name, knob in (("off", "0"), ("on", "1")):
        log, proc, files = _arm(args.cli, args.image, args.work_dir, name, knob, args.stats)
        del log
        seen = [stat_tuple(p) for p in files]
        failures[name] = sum(1 for t in seen if t is None)
        tuples[name] = [t for t in seen if t is not None]
        _umount(args.work_dir / f"mnt-{name}", proc)
    for name in ("off", "on"):
        print(f"{name}: stats_ok={len(tuples[name])} stats_failed={failures[name]}")
    if failures["on"] or failures["off"]:
        print("FAIL: a stat failed; a fast arm that answers nothing is not a result")
        return 1
    difference = first_difference(tuples["off"], tuples["on"])
    if difference:
        print(f"FAIL: {difference}")
        return 1
    print(f"IDENTICAL: {len(tuples['off'])} files, every stat field byte-for-byte equal")
    return 0


def _resolution(args: argparse.Namespace, name: str, image: Path, rw: bool) -> str:
    mnt, log = args.work_dir / f"mnt-{name}", args.work_dir / f"{name}.log"
    proc = _mount(args.cli, image, mnt, log, {"FFS_FUSE_XATTR_NO_SUPPORT": "auto"}, rw=rw)
    files = _files(mnt, args.stats)
    for path in files:
        stat_tuple(path)
    crossings = count_crossings(log.read_text())
    text = ANSI.sub("", log.read_text())
    state = "ACTIVE" if "suppression ACTIVE" in text else "REFUSED"
    presence = re.search(r"presence=(\w+)", text)
    _umount(mnt, proc)
    print(f"{name}: suppression {state}  presence={presence.group(1) if presence else '?'}  "
          f"crossings={crossings}  stats_ok={sum(1 for p in files if stat_tuple(p))}")
    return state


def mode_auto(args: argparse.Namespace) -> int:
    image = args.work_dir / "auto.img"
    shutil.copy(args.image, image)
    return 0 if _resolution(args, "auto", image, rw=args.rw) == "ACTIVE" else 1


def mode_planted(args: argparse.Namespace) -> int:
    """Plant one xattr through the KERNEL's own filesystem, then expect a refusal.

    Planted through the kernel deliberately: a fixture built with our own write
    path would make this test depend on the thing it is meant to check.
    """
    image = args.work_dir / "planted.img"
    shutil.copy(args.image, image)
    kmnt = args.work_dir / "kmnt"
    kmnt.mkdir(parents=True, exist_ok=True)
    if subprocess.run(["sudo", "-n", "mount", "-o", "loop", str(image), str(kmnt)],
                      capture_output=True, check=False).returncode != 0:
        sys.exit("FATAL: kernel mount failed; planted mode needs passwordless sudo")
    listing = subprocess.run(["sudo", "-n", "find", str(kmnt), "-maxdepth", "2", "-type", "f"],
                             capture_output=True, text=True, check=False).stdout.split()
    if not listing:
        subprocess.run(["sudo", "-n", "umount", str(kmnt)], check=False)
        sys.exit("FATAL: no file in the image to plant an xattr on")
    subprocess.run(["sudo", "-n", "python3", "-c",
                    "import os,sys; os.setxattr(sys.argv[1], 'user.planted', b'1')", listing[0]],
                   check=True)
    subprocess.run(["sudo", "-n", "umount", str(kmnt)], check=False)
    print(f"planted user.planted on {Path(listing[0]).name}")
    return 0 if _resolution(args, "planted", image, rw=False) == "REFUSED" else 1


def selftest() -> int:
    """Cases for the pure halves -- the parts that had real bugs."""
    cases = 0

    # The trap this instrument was built around: the suppression path emits a
    # DIFFERENT message on the SAME target, and both must count.
    probe = "2026-08-16T22:00:00Z TRACE ffs::fuse::xattr_probe: fuse getxattr from kernel ino=2"
    enosys = ("2026-08-16T22:00:01Z TRACE ffs::fuse::xattr_probe: getxattr answered ENOSYS: "
              "kernel will stop probing (bd-ha71t)")
    assert count_crossings(f"{probe}\n{enosys}\n") == 2, "both paths must count"
    cases += 1
    assert count_crossings(probe) == 1 and count_crossings(enosys) == 1
    cases += 1

    # Unrelated traffic must not inflate a count.
    noise = "2026-08-16T22:00:02Z INFO ffs_core: ext4 journal replay completed\n"
    assert count_crossings(noise * 50) == 0, "only the probe target counts"
    cases += 1
    assert count_crossings(f"{noise}{probe}\n{noise}") == 1
    cases += 1

    # ANSI escapes from the human formatter must not hide a line.
    coloured = f"\x1b[2m2026-08-16\x1b[0m TRACE \x1b[2m{PROBE_TARGET}\x1b[0m: fuse getxattr"
    assert count_crossings(coloured) == 1, "ANSI must be stripped before matching"
    cases += 1
    assert count_crossings("") == 0
    cases += 1

    # Metadata comparison.
    assert first_difference(["a", "b"], ["a", "b"]) is None
    cases += 1
    assert "entry 1" in (first_difference(["a", "b"], ["a", "c"]) or "")
    cases += 1
    # A shorter arm is a DIFFERENCE, not a subset: an arm that saw fewer files
    # did not agree, it had less to disagree about.
    assert "file count" in (first_difference(["a", "b"], ["a"]) or "")
    cases += 1
    assert "file count" in (first_difference([], ["a"]) or "")
    cases += 1

    # The rendered count must quote the per-stat figure the ledger quotes, and
    # must survive a zero-stat run rather than dividing by it.
    assert "2.000 per stat" in verdict(400, 0, 200)
    cases += 1
    assert "400 requests -> 0" in verdict(400, 0, 200)
    cases += 1
    assert "0.000 per stat" in verdict(0, 0, 0)
    cases += 1

    print(f"selftest: {cases} cases OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("mode", nargs="?",
                        choices=["count", "parity", "auto", "planted"])
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--cli", type=Path, default=Path("target/debug/ffs-cli"))
    parser.add_argument("--image", type=Path, default=Path("/data/tmp/ffs-pgo-train.img"))
    parser.add_argument("--work-dir", type=Path,
                        default=Path.home() / "ffs-xattr-evidence",
                        help="must NOT be on a nosuid filesystem; /data is one")
    parser.add_argument("--stats", type=int, default=200)
    parser.add_argument("--client", choices=["inproc", "process"], default="inproc",
                        help="inproc: one process, lstat in a loop (1 crossing per warm "
                             "stat). process: `stat(1)` per file (2 crossings). The "
                             "count depends on the client; say which one a row used.")
    parser.add_argument("--rw", action="store_true",
                        help="mount read-write (auto mode; `auto` requires read-only "
                             "to suppress, so this shows the refusal)")
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    if not args.mode:
        parser.error("a mode is required unless --selftest is given")
    args.work_dir.mkdir(parents=True, exist_ok=True)
    if not args.cli.is_file():
        sys.exit(f"FATAL: no ffs-cli at {args.cli}")
    if not args.image.is_file():
        sys.exit(f"FATAL: no image at {args.image}")
    return {"count": mode_count, "parity": mode_parity,
            "auto": mode_auto, "planted": mode_planted}[args.mode](args)


if __name__ == "__main__":
    sys.exit(main())
