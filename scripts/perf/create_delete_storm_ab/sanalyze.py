#!/usr/bin/env python3
"""Bootstrap-median CI on the per-round paired ratios of an interleaved storm run."""
import csv, sys, random, statistics as st

PHASES = ("total_ns", "create_ns", "fsync1_ns", "delete_ns", "fsync2_ns")

path = sys.argv[1]
rows = list(csv.DictReader(open(path)))
arms = {}
for r in rows:
    arms.setdefault(r["arm"], {})[int(r["round"])] = r
names = list(arms)
print(f"file={path} arms={names} rounds={len(arms[names[0]])}")
for a in names:
    v = arms[a].values()
    med = {p: st.median(int(x[p]) for x in v) / 1e6 for p in PHASES}
    tk = st.median(int(x["daemon_ticks"]) for x in v)
    print(f"  {a:12s} n={len(arms[a]):3d} total={med['total_ns']:9.3f}ms "
          f"create={med['create_ns']:8.3f} fsync1={med['fsync1_ns']:7.3f} "
          f"delete={med['delete_ns']:8.3f} fsync2={med['fsync2_ns']:7.3f}  ticks={tk:.0f}")


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
