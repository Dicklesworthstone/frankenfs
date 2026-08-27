#!/usr/bin/env python3
"""Bootstrap-median CI on the per-round paired ratios of an interleaved bulk run."""
import csv, sys, random, statistics as st

path = sys.argv[1]
rows = list(csv.DictReader(open(path)))
arms = {}
for r in rows:
    arms.setdefault(r["arm"], {})[int(r["round"])] = r
names = list(arms)
print(f"file={path} arms={names} rounds={len(arms[names[0]])}")
for a in names:
    t = [int(x["total_ns"]) for x in arms[a].values()]
    w = [int(x["write_ns"]) for x in arms[a].values()]
    f = [int(x["fsync_ns"]) for x in arms[a].values()]
    tk = [int(x["daemon_ticks"]) for x in arms[a].values()]
    print(f"  {a:12s} n={len(t):3d} total_med={st.median(t)/1e6:9.3f}ms "
          f"write_med={st.median(w)/1e6:9.3f}ms fsync_med={st.median(f)/1e6:9.3f}ms "
          f"apid_ticks_med={st.median(tk):.0f}")


def boot(num, den, field, iters=20000, seed=7):
    rounds = sorted(set(arms[num]) & set(arms[den]))
    pairs = [int(arms[num][r][field]) / int(arms[den][r][field]) for r in rounds]
    rng = random.Random(seed)
    meds = sorted(st.median(rng.choices(pairs, k=len(pairs))) for _ in range(iters))
    return st.median(pairs), meds[int(0.025 * iters)], meds[int(0.975 * iters)], len(pairs)


print()
for field in ("total_ns", "write_ns", "fsync_ns"):
    print(f"-- paired per-round ratios on {field}")
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            m, lo, hi, n = boot(a, b, field)
            print(f"  {a}/{b}: {m:.6f}  [{lo:.6f}, {hi:.6f}]  n={n}")
