"""Record a long contiguous trace of per-sample busy-CPU counts (bd-cljvq).

Window-length dependence cannot be answered by resampling: contention on this box
ARRIVES IN BURSTS, so shuffling the samples would destroy the autocorrelation that
decides whether a long run survives the 3-consecutive rule. This records one
contiguous trace so real windows of any length can be scored from it.
"""
import json, sys, time, pathlib

def ticks():
    out = {}
    for line in pathlib.Path('/proc/stat').read_text().splitlines():
        if not line.startswith('cpu') or line.startswith('cpu '):
            continue
        f = line.split()
        try:
            cpu = int(f[0][3:])
        except ValueError:
            continue
        v = [int(x) for x in f[1:]]
        if len(v) >= 5:
            out[cpu] = (sum(v), v[3] + v[4])
    return out

n = int(sys.argv[1]); dest = sys.argv[2]
counts = []
a = ticks()
for i in range(n):
    time.sleep(1.0)
    b = ticks()
    c = 0
    for cpu, (ta, ia) in a.items():
        tb, ib = b[cpu]
        dt = tb - ta
        if dt > 0 and (dt - (ib - ia)) / dt > 0.25:
            c += 1
    counts.append(c)
    a = b
pathlib.Path(dest).write_text(json.dumps({"samples": n, "busy_cpu_counts": counts}))
print(f"wrote {n} samples to {dest}")
