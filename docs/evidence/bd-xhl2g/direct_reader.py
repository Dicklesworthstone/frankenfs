"""Low-CPU O_DIRECT reader: saturate the device queue while leaving CPUs IDLE.

Variants A (4 KiB dd) and B (1 MiB dd) both drove off-placement mean BUSY to
0.83-0.98 because dd respawn + syscall churn burns CPU, so the busy gate caught
them for the wrong reason. This loops IN PROCESS on a preallocated aligned
buffer: one large blocking read per iteration, no fork, no formatting, so a
blocked reader leaves its CPU idle -- which is the only state /proc/stat can
charge to iowait.
"""
import ctypes, os, random, sys, time

path, dur, chunk_mb = sys.argv[1], float(sys.argv[2]), int(sys.argv[3])
chunk = chunk_mb << 20
fd = os.open(path, os.O_RDONLY | os.O_DIRECT)
size = os.fstat(fd).st_size
# O_DIRECT needs a 512-byte-aligned user buffer.
raw = ctypes.create_string_buffer(chunk + 4096)
off = (-ctypes.addressof(raw)) % 4096
buf = (ctypes.c_char * chunk).from_buffer(raw, off)
end, n = time.time() + dur, 0
while time.time() < end:
    pos = random.randrange(0, max(1, size - chunk)) & ~4095
    try:
        n += os.preadv(fd, [buf], pos)
    except OSError:
        pass
os.close(fd)
print(f"{n/(1<<30):.1f} GiB")
