#!/usr/bin/env python3
"""Copy an image so every copy gets the SAME on-host extent layout.

A plain `cp` onto a delayed-allocation host filesystem gives each copy whatever
extents happen to be free, and with `losetup --direct-io=on` that layout is on the
critical path: two identical kernel arms measured 6.6% apart (a FAILING A/A null)
purely because their backing files were laid out differently. Preallocating the whole
file with fallocate before writing a byte makes the copies comparable.
"""
import os
import sys

src, dst = sys.argv[1], sys.argv[2]
size = os.path.getsize(src)
if os.path.exists(dst):
    os.remove(dst)
fd = os.open(dst, os.O_CREAT | os.O_WRONLY, 0o644)
try:
    os.posix_fallocate(fd, 0, size)
    with open(src, "rb") as s:
        while True:
            buf = s.read(8 << 20)
            if not buf:
                break
            os.write(fd, buf)
    os.fsync(fd)
finally:
    os.close(fd)
