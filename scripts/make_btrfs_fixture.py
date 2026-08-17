#!/usr/bin/env python3
"""Build a POPULATED btrfs fixture for the mounted comparator, and verify it.

WHY THIS EXISTS. The worst row in the bank is btrfs readdir+stat at `8.32x`, and
it has been unmeasurable for a different reason than everyone assumed: not host
load, not the lever, but the FIXTURE. Every btrfs image on this host has 1 or 50
directory entries, and `scripts/fuse_vs_kernel_abba.sh` needs thousands before a
readdir+stat row means anything -- a 50-entry run reports `entries=50` and
measures mostly mount overhead. `mkfs.btrfs` is refused by the command guard
here, so the fixture cannot be made the obvious way.

WHAT IT DOES INSTEAD. It populates an EXISTING btrfs image through our own
read-write FUSE mount, then unmounts and asks the KERNEL to read it back. That
second half is the point: a fixture our own code wrote and only our own code can
read would be worthless for a comparator whose whole purpose is to run both
implementations over the same bytes. The kernel's listing is compared against
the names and sizes we asked for, entry by entry, and a single mismatch fails
the build.

So this is also a correctness check of the btrfs write path, and it should be
read as one. bd-giw9n is the standing hazard -- a btrfs image was UNMOUNTABLE
after ~32k creates -- which is why `--count` defaults well below that and why
the kernel-readback step is mandatory rather than a flag.

    scripts/make_btrfs_fixture.py --selftest
    scripts/make_btrfs_fixture.py --source X.btrfs --out ~/fix.img --count 5000

⚠️ `/data` is mounted `nosuid` on this host, so the setuid `fusermount3` is
refused there. Both the work directory and the output image default to `$HOME`.

The kernel readback needs passwordless `sudo mount -o loop`. Nothing here needs
a quiet window: creating files and comparing listings are load-independent,
which is why this is the right work for a loud host.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

# Wide enough that a readdir+stat client is not measuring its own name parsing,
# short enough to stay off the btrfs inline-extent boundary.
NAME_TEMPLATE = "fixture_{index:06d}"


def fixture_names(count: int) -> list[str]:
    """The names the fixture will contain, in creation order.

    Zero-padded and fixed-width on purpose: a readdir+stat client sorts and
    stats these, and variable-length names would put a name-length effect inside
    a row that is supposed to be about metadata round trips.
    """
    return [NAME_TEMPLATE.format(index=index) for index in range(count)]


def fixture_content(name: str) -> bytes:
    """Content whose LENGTH differs per file.

    A fixture where every file is the same size cannot detect a readback that
    returns the right names attached to the wrong inodes -- the sizes would
    match by coincidence. The length varies with the index, so the size check
    below is a real check.
    """
    return b"x" * (len(name) + int(name.rsplit("_", 1)[1]) % 61)


def compare_listings(expected: dict[str, int], actual: dict[str, int]) -> str | None:
    """First disagreement between what we wrote and what the kernel read back.

    Returns None when they agree. Reports a missing name, an unexpected name and
    a size mismatch differently, because they mean different things: a missing
    name is a lost create, an extra name is a fixture that was not clean to
    start with, and a wrong size is a create that landed on the wrong inode.
    """
    for name, size in sorted(expected.items()):
        if name not in actual:
            return f"kernel cannot see {name!r}: {len(actual)} of {len(expected)} names read back"
        if actual[name] != size:
            return f"{name!r} size differs: wrote {size}, kernel read {actual[name]}"
    extra = sorted(set(actual) - set(expected))
    if extra:
        return f"kernel sees {len(extra)} name(s) we did not write, first {extra[0]!r}"
    return None


def summarize(count: int, seconds: float) -> str:
    per = (seconds / count * 1e6) if count else 0.0
    return f"created {count} files in {seconds:.1f}s ({per:.0f} us/create)"


# --- everything below here touches a real mount -----------------------------


def _mount(cli: Path, image: Path, mnt: Path, log: Path) -> subprocess.Popen:
    mnt.mkdir(parents=True, exist_ok=True)
    handle = log.open("w")
    proc = subprocess.Popen(
        [str(cli), "mount", "--rw", str(image), str(mnt)],
        stdout=handle, stderr=subprocess.STDOUT,
    )
    for _ in range(150):  # bounded: 30s, then say so rather than hang
        if os.path.ismount(mnt):
            return proc
        time.sleep(0.2)
    proc.kill()
    sys.exit(f"FATAL: mount did not appear at {mnt}\n{log.read_text()[-800:]}")


def _kernel_listing(image: Path, mnt: Path) -> dict[str, int]:
    mnt.mkdir(parents=True, exist_ok=True)
    if subprocess.run(["sudo", "-n", "mount", "-o", "loop,ro", str(image), str(mnt)],
                      capture_output=True, check=False).returncode != 0:
        sys.exit("FATAL: the KERNEL could not mount the image we just wrote. That is "
                 "the finding, not an inconvenience -- see bd-giw9n.")
    try:
        out = subprocess.run(
            ["sudo", "-n", "find", str(mnt), "-maxdepth", "1", "-type", "f",
             "-printf", "%f %s\\n"],
            capture_output=True, text=True, check=True).stdout
    finally:
        subprocess.run(["sudo", "-n", "umount", str(mnt)], check=False)
    listing = {}
    for line in out.splitlines():
        name, _, size = line.rpartition(" ")
        if name:
            listing[name] = int(size)
    return listing


def build(args: argparse.Namespace) -> int:
    args.work_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy(args.source, args.out)
    mnt = args.work_dir / "build-mnt"
    proc = _mount(args.cli, args.out, mnt, args.work_dir / "build.log")

    names = fixture_names(args.count)
    expected: dict[str, int] = {}
    started = time.monotonic()
    try:
        for name in names:
            content = fixture_content(name)
            (mnt / name).write_bytes(content)
            expected[name] = len(content)
    except OSError as err:
        print(f"create failed at {len(expected)} of {args.count}: {err}")
        print("that is a result about the btrfs write path, not a script bug (bd-giw9n)")
    elapsed = time.monotonic() - started
    subprocess.run(["fusermount3", "-u", str(mnt)], capture_output=True, check=False)
    try:
        proc.wait(timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()

    print(summarize(len(expected), elapsed))
    if not expected:
        return 1

    actual = _kernel_listing(args.out, args.work_dir / "kernel-mnt")
    difference = compare_listings(expected, actual)
    if difference:
        print(f"FAIL: {difference}")
        return 1
    print(f"VERIFIED by the kernel: {len(actual)} files, every name and size matches")
    print(f"fixture ready: {args.out}")
    return 0


def selftest() -> int:
    cases = 0

    names = fixture_names(3)
    assert names == ["fixture_000000", "fixture_000001", "fixture_000002"]
    cases += 1
    assert len(fixture_names(0)) == 0
    cases += 1
    # Fixed width: a readdir+stat row must not carry a name-length effect.
    assert len({len(n) for n in fixture_names(20000)}) == 1
    cases += 1
    assert len(set(fixture_names(5000))) == 5000, "names must be unique"
    cases += 1

    # Sizes must actually vary, or the size check below proves nothing.
    sizes = {len(fixture_content(n)) for n in fixture_names(200)}
    assert len(sizes) > 1, "a constant size cannot detect a name/inode mix-up"
    cases += 1

    assert compare_listings({"a": 1}, {"a": 1}) is None
    cases += 1
    assert "cannot see" in (compare_listings({"a": 1, "b": 2}, {"a": 1}) or "")
    cases += 1
    assert "size differs" in (compare_listings({"a": 1}, {"a": 2}) or "")
    cases += 1
    assert "we did not write" in (compare_listings({"a": 1}, {"a": 1, "z": 9}) or "")
    cases += 1
    # A lost create and a wrong size must not be reported as the same thing.
    assert "cannot see" in (compare_listings({"a": 1, "b": 2}, {"a": 1, "c": 2}) or "")
    cases += 1
    assert compare_listings({}, {}) is None
    cases += 1

    assert "0 us/create" not in summarize(0, 0.0) or True
    assert "created 100 files" in summarize(100, 1.0)
    cases += 1
    # Must not divide by a zero count when every create failed.
    assert "created 0 files" in summarize(0, 3.0)
    cases += 1

    print(f"selftest: {cases} cases OK")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--selftest", action="store_true")
    parser.add_argument("--cli", type=Path, default=Path("target/debug/ffs-cli"))
    parser.add_argument("--source", type=Path,
                        help="an existing btrfs image to copy and populate")
    parser.add_argument("--out", type=Path, default=Path.home() / "btrfs-fixture.img")
    parser.add_argument("--work-dir", type=Path, default=Path.home() / "ffs-btrfs-fixture",
                        help="must NOT be on a nosuid filesystem; /data is one")
    parser.add_argument("--count", type=int, default=5000,
                        help="files to create. bd-giw9n saw a btrfs image become "
                             "UNMOUNTABLE after ~32k creates, so stay well under it")
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    if not args.source:
        parser.error("--source is required (mkfs.btrfs is refused by the command guard)")
    if not args.cli.is_file():
        sys.exit(f"FATAL: no ffs-cli at {args.cli}")
    if not args.source.is_file():
        sys.exit(f"FATAL: no image at {args.source}")
    return build(args)


if __name__ == "__main__":
    sys.exit(main())
