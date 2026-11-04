#!/usr/bin/env python3
"""Read block-group space records from a mounted FrankenFS filesystem.

The Linux/FUSE extension encodes the full buffer size in BTRFS_IOC_SPACE_INFO.
Use --kernel-btrfs only for a native kernel btrfs mount, whose canonical ioctl
can copy its flexible array directly. Requires Python3's standard library.
FrankenFS currently exposes this accounting on writable btrfs mounts on Linux
x86_64. Native kernel mode additionally reports its transient global reserve.
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import json
import os
import platform
import struct
import sys

HEADER = struct.Struct("<QQ")
RECORD = struct.Struct("<QQQ")
LEGACY_COMMAND = 0xC0109414
SIZE_MASK = 0x3FFF0000
MAX_SLOTS = (0x3FFF - HEADER.size) // RECORD.size
MAX_ATTEMPTS = 3
UNWRITTEN = (1 << 64) - 1


def query(fd: int, slots: int, *, kernel_btrfs: bool = False) -> tuple[int, list[dict]]:
    """One bounded ioctl; return the total count and the records that fit."""
    if not 0 <= slots <= MAX_SLOTS:
        raise ValueError(f"space count must be between 0 and {MAX_SLOTS}")
    size = HEADER.size + slots * RECORD.size
    command = LEGACY_COMMAND if kernel_btrfs else (LEGACY_COMMAND & ~SIZE_MASK) | (size << 16)
    data = bytearray(b"\xff" * size)
    HEADER.pack_into(data, 0, slots, UNWRITTEN)
    if fcntl.ioctl(fd, command, data, True) != 0:
        raise OSError(errno.EIO, "space-info ioctl returned an unexpected nonzero result")
    _, total = HEADER.unpack_from(data)
    if total > MAX_SLOTS:
        raise ValueError("space count is missing or exceeds the bounded ioctl capacity")
    records = []
    for index in range(min(total, slots)):
        flags, total_bytes, used_bytes = RECORD.unpack_from(data, HEADER.size + index * RECORD.size)
        if UNWRITTEN in (flags, total_bytes, used_bytes):
            raise ValueError("space record was not completely returned")
        if used_bytes > total_bytes:
            raise ValueError("space record reports more used bytes than allocated bytes")
        records.append({"flags": flags, "total_bytes": total_bytes, "used_bytes": used_bytes})
    return total, records


def space_info(path: str, *, kernel_btrfs: bool = False) -> dict:
    """Query one open directory; never publish an incomplete array as success."""
    if sys.platform != "linux" or platform.machine().lower() not in ("x86_64", "amd64"):
        raise OSError(errno.EOPNOTSUPP, "this consumer requires Linux x86_64 ioctl encoding")
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        identity = os.fstat(fd)
        total, _ = query(fd, 0, kernel_btrfs=kernel_btrfs)
        for _ in range(MAX_ATTEMPTS):
            total, records = query(fd, total, kernel_btrfs=kernel_btrfs)
            if kernel_btrfs:
                # Native nonzero queries return the count copied, which may
                # hide concurrent growth. Only a fresh count query can detect it.
                total, _ = query(fd, 0, kernel_btrfs=True)
            if len(records) == total:
                return {
                    "path": os.path.realpath(path),
                    "device": identity.st_dev,
                    "inode": identity.st_ino,
                    "transport": "kernel-btrfs" if kernel_btrfs else "linux-fuse-sized",
                    "total_spaces": total,
                    "spaces": records,
                }
        raise OSError(errno.EAGAIN, "space count kept growing during the bounded query")
    finally:
        os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mountpoint", help="directory in the mounted btrfs filesystem")
    parser.add_argument("--kernel-btrfs", action="store_true", help="use the native kernel ABI")
    args = parser.parse_args()
    try:
        result = space_info(args.mountpoint, kernel_btrfs=args.kernel_btrfs)
    except (OSError, ValueError) as error:
        print(f"space-info: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
