#!/usr/bin/env python3
"""Does a KERNEL mount survive a tree log THIS build left behind? (bd-jhuob)

THE QUESTION, and why no existing test asks it. bd-jhuob already plans a
falsification: write via the ephemeral path, force a full commit, remount, check
the items survived. That exercises OUR replay and would pass whatever the on-disk
format is, because a full commit CLEARS `log_root` (bd-mogn1) — the log is gone
before anyone else looks at it. The interoperability question is the opposite one
and needs the opposite test: leave the log ON DISK and hand the image to the
kernel.

WHY IT MATTERS. `log_root` is only ever set between an ephemeral fsync and the
next full commit. A clean unmount commits, so a cleanly unmounted image carries no
log and this can never fire. The exposure is exactly the window the log exists FOR:
a crash. If the kernel cannot parse what we left, an fsync that RETURNED SUCCESS is
unreadable by the incumbent — our reader opens the image, the kernel refuses it,
which is the silent-interoperability shape of bd-73bi2.

WHAT IT DOES.
  1. copies a btrfs image (never mounts the original)
  2. mounts it read-write through our FUSE daemon with --btrfs-rw-ephemeral-ok
  3. writes and fsyncs, so a tree log is published
  4. SIGKILLs the daemon, so no commit can clear `log_root`
  5. asserts `log_root` is actually non-zero on disk — otherwise the test proved
     nothing and says so rather than passing vacuously
  6. asks the KERNEL to mount the image and read the file back

⚠️ STEP 5 IS THE ONE THAT KEEPS THIS HONEST. If the daemon committed before dying,
or the ephemeral path was not taken, `log_root` is zero, the kernel mounts a
perfectly ordinary image, and a naive script reports PASS having tested nothing.
That is the failure mode this whole bead is about — a check that cannot fail is
worse than no check, because it reads as evidence.

A FIXTURE NEGATIVE CONTROL RUNS FIRST: `btrfs check --readonly` on the pristine
image. If the fixture is already damaged (bd-f3fsg) the run is INCONCLUSIVE rather
than a FINDING — log replay walks refs that an ordinary read-only mount never
touches, so a pre-existing missing backref surfaces only once our log is present
and reads exactly like our defect.

EXIT CODES: 0 pass, 1 the kernel refused the image (the finding), 2 the test could
not be set up (inconclusive, NOT a pass).

Needs passwordless sudo for losetup/mount. `/data` is mounted nosuid here, so
fusermount3 is refused there: mountpoints default to $HOME.
"""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import struct
import subprocess
import sys
import time
from pathlib import Path

BTRFS_SUPER_INFO_OFFSET = 0x10000
BTRFS_MAGIC = b"_BHRfS_M"
LOG_ROOT_OFFSET = 0x60  # __le64, superblock-relative
LOG_ROOT_LEVEL_OFFSET = 0xC8  # u8


def read_log_root(image: Path) -> tuple[int, int]:
    """Return (log_root, log_root_level) straight from the on-disk superblock."""
    with image.open("rb") as handle:
        handle.seek(BTRFS_SUPER_INFO_OFFSET)
        sb = handle.read(4096)
    if sb[0x40:0x48] != BTRFS_MAGIC:
        sys.exit(f"FATAL: {image} is not a btrfs image (bad magic)")
    (log_root,) = struct.unpack_from("<Q", sb, LOG_ROOT_OFFSET)
    return log_root, sb[LOG_ROOT_LEVEL_OFFSET]


# Every wait here is bounded. `btrfs check` on a 20000-file image is the slowest
# thing this script shells out to and it is still seconds, not minutes; an
# unbounded wait on a hung losetup/mount would strand the loop device it just
# claimed. A timeout surfaces as a non-zero verdict, which the callers already
# treat as "could not establish this", not as a pass.
DEFAULT_SUBPROCESS_TIMEOUT_S = 600


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    kw.setdefault("timeout", DEFAULT_SUBPROCESS_TIMEOUT_S)
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=False, **kw)
    except subprocess.TimeoutExpired as expired:
        return subprocess.CompletedProcess(
            cmd,
            returncode=124,
            stdout=expired.stdout.decode() if isinstance(expired.stdout, bytes) else (expired.stdout or ""),
            stderr=f"timed out after {kw['timeout']}s: {' '.join(cmd)}",
        )


def fixture_is_sound(image: Path) -> tuple[bool, str]:
    """Does `btrfs check` accept this image AS STORED? Returns (ok, diagnostic).

    A read-only mount is NOT this question and cannot stand in for it: measured
    2026-08-20, the kernel mounts `btrfs-acct-2000.img` ro without a murmur while
    `btrfs check` reports a tree block with no extent-tree backref in it.
    """
    checked = run(["sudo", "btrfs", "check", "--readonly", str(image)])
    if checked.returncode == 0:
        return True, ""
    lines = [
        line
        for line in (checked.stdout + checked.stderr).splitlines()
        if "error" in line.lower() or "mismatch" in line.lower() or "backref" in line.lower()
    ]
    return False, "\n  ".join(lines[:6]) or f"btrfs check rc={checked.returncode}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="a btrfs image; it is COPIED")
    parser.add_argument("--cli", default="target/debug/ffs-cli")
    parser.add_argument("--work-dir", default=str(Path.home()))
    parser.add_argument("--fsyncs", type=int, default=4)
    parser.add_argument(
        "--files",
        type=int,
        default=1,
        help=(
            "how many files to create and fsync. ⚠️ MORE THAN ONE IS A DIFFERENT "
            "TEST. The log accumulates every inode fsynced since the last full "
            "commit (bd-dm01m), and each inode contributes its PARENT's dir items "
            "as well as its own — so two inodes interleave two ascending key runs "
            "in one leaf. A leaf whose items are out of key order is refused by "
            "the kernel's tree-checker, and one file can never show it."
        ),
    )
    parser.add_argument(
        "--bytes",
        type=int,
        default=256,
        help=(
            "payload size. ⚠️ THE DEFAULT IS AN INLINE EXTENT. btrfs stores a small "
            "file's data inside the EXTENT_DATA item, so a 256-byte probe never "
            "exercises a real extent — the log names no disk_bytenr and the kernel's "
            "replay takes no reference on anything. Pass a size above the inline "
            "threshold (>4096 here) to test the case where it does."
        ),
    )
    args = parser.parse_args()

    cli = Path(args.cli).resolve()
    if not cli.is_file():
        sys.exit(f"FATAL: no CLI at {cli}")
    work = Path(args.work_dir)
    image = work / "tree-log-interop.img"
    mnt = work / "tree-log-interop-mnt"
    kmnt = work / "tree-log-interop-kmnt"
    # A previous run that ended between its SIGKILL and its unmount leaves a
    # stale FUSE endpoint here, and every path call on it then raises ENOTCONN --
    # including the mkdir below, which crashes before the run starts. Clearing it
    # first is cheap and makes back-to-back invocations safe.
    run(["fusermount3", "-u", str(mnt)])
    run(["fusermount3", "-u", str(kmnt)])
    shutil.copyfile(args.image, image)
    mnt.mkdir(exist_ok=True)
    kmnt.mkdir(exist_ok=True)

    print(f"image      {image}")
    print(f"daemon     {cli}")
    print(f"payload    {args.bytes} bytes ({'inline' if args.bytes <= 4096 else 'real extent'})")
    print(f"files      {args.files}")

    # ── 1b. THE FIXTURE NEGATIVE CONTROL (observed 2026-08-20) ──────────────
    # Step 6 below reads a kernel mount failure as "the kernel refused OUR tree
    # log". That inference is only valid if the fixture was sound to begin with.
    #
    # WHAT WAS MEASURED. Three runs against btrfs-acct-2000.img reported FINDING,
    # every one of them failing on tree block 32423936 at slot 121 — the same
    # block whatever we wrote, and the block `btrfs check` already names as having
    # no extent-tree backref in that fixture AS STORED (bd-f3fsg). The same runs
    # against a fixture that passes `btrfs check` PASS.
    #
    # AND THE CONTROL HAS TO BE THE CHECK, NOT A MOUNT. A plain read-only kernel
    # mount of that same damaged fixture SUCCEEDS — it never walks the refs. Only
    # log replay does, and its delayed-ref drop is what hits the missing backref
    # and takes open_ctree down with -ENOENT. So a mount-based control passes and
    # tells you nothing; that mistake was made here first and is recorded so it is
    # not made again.
    #
    # A fixture that fails `btrfs check` makes the run INCONCLUSIVE (2), never a
    # FINDING (1). An instrument that reports somebody else's bug as yours is
    # worse than no instrument, because a FINDING gets acted on.
    sound, why = fixture_is_sound(Path(args.image))
    if not sound:
        print(
            "INCONCLUSIVE: `btrfs check` already rejects this fixture BEFORE we "
            "touch it, so a kernel refusal after our tree log cannot be attributed "
            "to the log.\n"
            f"  fixture {args.image}\n  {why}\n"
            "  Note a read-only kernel mount of such a fixture still succeeds — "
            "replay is what surfaces the damage. Pick a fixture that passes "
            "`btrfs check --readonly` as stored (bd-f3fsg)."
        )
        return 2
    print("control    `btrfs check` accepts the pristine fixture (so a later refusal is ours)")

    # ── 2. mount read-write, ephemeral (tree-log) fsync strategy ────────────
    daemon = subprocess.Popen(
        [str(cli), "mount", "--rw", "--btrfs-rw-ephemeral-ok", str(image), str(mnt)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 30
    while time.time() < deadline:
        if os.path.ismount(mnt):
            break
        if daemon.poll() is not None:
            sys.exit("FATAL: daemon exited before the mount appeared")
        time.sleep(0.1)
    else:
        daemon.kill()
        sys.exit("FATAL: mount did not appear within 30s")

    # ── 3. write + fsync, so a tree log is published ────────────────────────
    unit = b"tree-log-interop"
    payload = (unit * (args.bytes // len(unit) + 1))[: args.bytes]
    names = [
        "interop-probe" if index == 0 else f"interop-probe-{index}"
        for index in range(args.files)
    ]
    try:
        for name in names:
            fd = os.open(mnt / name, os.O_CREAT | os.O_RDWR, 0o644)
            for _ in range(args.fsyncs):
                os.pwrite(fd, payload, 0)
                os.fsync(fd)
            os.close(fd)
    except OSError as err:
        daemon.kill()
        sys.exit(f"FATAL: write+fsync failed: {err}")

    # ── 4. SIGKILL: no commit may run, so log_root stays on disk ────────────
    daemon.send_signal(signal.SIGKILL)
    daemon.wait(timeout=30)
    run(["fusermount3", "-u", str(mnt)])

    # ── 5. the honesty gate ─────────────────────────────────────────────────
    log_root, log_root_level = read_log_root(image)
    print(f"log_root   {log_root} (level {log_root_level})")
    if log_root == 0:
        print(
            "INCONCLUSIVE: log_root is zero, so this image carries no tree log and "
            "the kernel is not being asked the question. Either the daemon committed "
            "before it died, or the ephemeral path was not taken. NOT a pass."
        )
        return 2

    # ── 6. the incumbent's verdict ──────────────────────────────────────────
    loop = run(["sudo", "losetup", "--find", "--show", str(image)])
    if loop.returncode != 0:
        print(f"INCONCLUSIVE: losetup failed: {loop.stderr.strip()}")
        return 2
    device = loop.stdout.strip()
    try:
        mount = run(["sudo", "mount", "-t", "btrfs", "-o", "ro", device, str(kmnt)])
        if mount.returncode != 0:
            print(
                "FINDING: the KERNEL REFUSED an image carrying a tree log this build "
                f"wrote.\n  {mount.stderr.strip()}"
            )
            return 1
        for name in names:
            try:
                data = (kmnt / name).read_bytes()
            except OSError as err:
                print(
                    f"FINDING: kernel mounted the image but {name} is unreadable: {err}"
                )
                return 1
            if data[: len(payload)] != payload:
                print(f"FINDING: kernel mounted and read, but {name}'s bytes differ")
                return 1
        print(
            "PASS: the kernel mounted an image carrying our tree log and read the "
            "fsynced data back."
        )
        return 0
    finally:
        run(["sudo", "umount", str(kmnt)])
        run(["sudo", "losetup", "-d", device])


if __name__ == "__main__":
    sys.exit(main())
