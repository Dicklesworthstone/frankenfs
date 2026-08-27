#!/usr/bin/env python3
"""Bootstrap-median CI on the per-round paired ratios of an interleaved storm run."""
import csv, sys, random, statistics as st

PHASES = ("total_ns", "ns_per_op", "sectors_written", "write_ios", "flush_ios")

path = sys.argv[1]
rows = list(csv.DictReader(open(path)))
arms = {}
for r in rows:
    arms.setdefault(r["arm"], {})[int(r["round"])] = r
names = list(arms)
print(f"file={path} arms={names} rounds={len(arms[names[0]])}")
for a in names:
    v = arms[a].values()
    tot = st.median(int(x["total_ns"]) for x in v) / 1e6
    per = st.median(int(x["ns_per_op"]) for x in v) / 1e3
    sec = st.median(int(x["sectors_written"]) for x in v)
    ios = st.median(int(x["write_ios"]) for x in v)
    fl = st.median(int(x["flush_ios"]) for x in v)
    tk = st.median(int(x["daemon_ticks"]) for x in v)
    print(f"  {a:12s} n={len(arms[a]):3d} total={tot:9.3f}ms  {per:9.2f} us/op  "
          f"sectors={sec:7.0f}  write_ios={ios:5.0f}  flush_ios={fl:5.0f}  ticks={tk:.0f}")


def boot(num, den, field, iters=20000, seed=7):
    rounds = sorted(set(arms[num]) & set(arms[den]))
    pairs = [int(arms[num][r][field]) / int(arms[den][r][field]) for r in rounds]
    rng = random.Random(seed)
    meds = sorted(st.median(rng.choices(pairs, k=len(pairs))) for _ in range(iters))
    return st.median(pairs), meds[int(0.025 * iters)], meds[int(0.975 * iters)], len(pairs)


print()
for field in PHASES:
    print(f"-- paired per-round ratios on {field}")
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            m, lo, hi, n = boot(a, b, field)
            print(f"  {a}/{b}: {m:.6f}  [{lo:.6f}, {hi:.6f}]  n={n}")
