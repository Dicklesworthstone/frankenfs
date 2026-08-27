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
    stt = [int(x["read_ns"]) for x in arms[a].values()]
    rdd = [int(x["list_ns"]) for x in arms[a].values()]
    tk = [int(x["daemon_ticks"]) for x in arms[a].values()]
    print(f"  {a:12s} n={len(tot):3d} total_med={st.median(tot)/1e6:9.3f}ms "
          f"list_med={st.median(rdd)/1e6:8.3f}ms read_med={st.median(stt)/1e6:9.3f}ms "
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
for field in ("total_ns", "read_ns"):
    print(f"-- paired per-round ratios on {field}")
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            m, lo, hi, n = boot_ratio(a, b, field)
            print(f"  {a}/{b}: {m:.6f}  [{lo:.6f}, {hi:.6f}]  n={n}")


def floor_ratio(num, den, field, iters=20000, seed=12345, k=4):
    """Floor estimator: ratio of each arm's fast mode, with a bootstrap CI.

    bd-4iqg6: the FUSE arms on this row are BIMODAL — a fast mode that reproduces
    across runs to ~1.06x and a tail whose weight does not.  The paired-median ratio
    mixes the two and reproduces only to 1.2-1.4x across runs, which is why the
    banked figures never came back.  Comparing the fast modes instead reproduces to
    1.0440x, matching this instrument's own A/A null spread (1.0415x).

    Reported two ways because `min` is an extreme order statistic: the bootstrap is
    not consistent for it and it is only comparable at EQUAL round counts.  The
    mean-of-k-lowest form bootstraps validly and agreed with `min` to 0.04% over the
    five runs that established this.

    This estimator FLATTERS the FUSE arms (it read 1.3038x where the median read
    1.5065x), so it is never the whole story.  The block below therefore also prints each
    arm's tail burden (median/floor), which on that row was 1.2404 for FrankenFS against 1.0735 for the
    kernel — a real second loss that this estimator deliberately excludes.
    """
    a = [int(x[field]) for x in arms[num].values()]
    b = [int(x[field]) for x in arms[den].values()]
    lo_k = lambda v: sum(sorted(v)[:k]) / float(k)
    rng = random.Random(seed)
    boots = []
    for _ in range(iters):
        boots.append(lo_k(rng.choices(a, k=len(a))) / lo_k(rng.choices(b, k=len(b))))
    boots.sort()
    return (min(a) / min(b), lo_k(a) / lo_k(b),
            boots[int(0.025 * iters)], boots[int(0.975 * iters)])


print()
print("-- floor estimator on total_ns (bd-4iqg6; valid only at equal round counts)")
for a in names:
    tot = [int(x["total_ns"]) for x in arms[a].values()]
    print(f"  {a:12s} floor={min(tot)/1e6:8.3f}ms  tail_burden={st.median(tot)/min(tot):.4f}")
for i, a in enumerate(names):
    for b in names[i + 1:]:
        mn, lo4, clo, chi = floor_ratio(a, b, "total_ns")
        print(f"  {a}/{b}: min={mn:.6f}  lo4={lo4:.6f}  [{clo:.6f}, {chi:.6f}]")
