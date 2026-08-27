#!/usr/bin/env python3
"""Bootstrap-median CI on the per-round paired ratios of an interleaved rdstat run."""
import csv, sys, random, statistics as st

path = sys.argv[1]
rows = list(csv.DictReader(open(path)))
arms = {}
for r in rows:
    arms.setdefault(r["arm"], {})[int(r["round"])] = r

names = list(arms)
print(f"file={path} arms={names} rounds={len(arms[names[0]])}")
for a in names:
    tot = [int(x["total_ns"]) for x in arms[a].values()]
    stt = [int(x["fsync_ns"]) for x in arms[a].values()]
    rdd = [int(x["create_ns"]) for x in arms[a].values()]
    tk = [int(x["daemon_ticks"]) for x in arms[a].values()]
    print(f"  {a:12s} n={len(tot):3d} total_med={st.median(tot)/1e6:9.3f}ms "
          f"create_med={st.median(rdd)/1e6:8.3f}ms fsync_med={st.median(stt)/1e6:9.3f}ms "
          f"iqr_total={(st.quantiles(tot,n=4)[2]-st.quantiles(tot,n=4)[0])/1e6:7.3f}ms "
          f"apid_ticks_med={st.median(tk):.0f}")


def boot_ratio(num, den, field, iters=20000, seed=12345):
    """Paired per-round ratio, bootstrap median CI."""
    rounds = sorted(set(arms[num]) & set(arms[den]))
    pairs = [int(arms[num][r][field]) / int(arms[den][r][field]) for r in rounds]
    rng = random.Random(seed)
    meds = []
    n = len(pairs)
    for _ in range(iters):
        meds.append(st.median(rng.choices(pairs, k=n)))
    meds.sort()
    return st.median(pairs), meds[int(0.025 * iters)], meds[int(0.975 * iters)], n


print()
for field in ("total_ns", "fsync_ns"):
    print(f"-- paired per-round ratios on {field}")
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            m, lo, hi, n = boot_ratio(a, b, field)
            print(f"  {a}/{b}: {m:.6f}  [{lo:.6f}, {hi:.6f}]  n={n}")
