#!/usr/bin/env python3
"""Bootstrap-median CI on the per-round paired ratios of an interleaved xattr run.

Ratios are formed PER ROUND and only then aggregated, so a drifting window moves
both arms of a pair together and cancels. The CI is over 20000 resamples of those
paired ratios, never over the raw times.
"""
import csv
import random
import statistics as st
import sys

RESAMPLES = 20000


def boot_ci(values, resamples=RESAMPLES, lo=2.5, hi=97.5):
    rng = random.Random(20260827)
    n = len(values)
    meds = []
    for _ in range(resamples):
        meds.append(st.median(values[rng.randrange(n)] for _ in range(n)))
    meds.sort()
    return meds[int(len(meds) * lo / 100)], meds[int(len(meds) * hi / 100)]


def main():
    path = sys.argv[1]
    rows = list(csv.DictReader(open(path)))
    arms = {}
    for r in rows:
        arms.setdefault(r["arm"], {})[int(r["round"])] = r

    names = list(arms)
    print(f"file={path} arms={names} rounds={len(arms[names[0]])}")
    for a in names:
        tot = [int(x["total_ns"]) for x in arms[a].values()]
        tk = [int(x["daemon_ticks"]) for x in arms[a].values()]
        digests = {x["digest"] for x in arms[a].values()}
        print(
            f"  {a:12s} n={len(tot):3d} total_med={st.median(tot) / 1e6:9.3f}ms "
            f"iqr={(st.quantiles(tot, n=4)[2] - st.quantiles(tot, n=4)[0]) / 1e6:7.3f}ms "
            f"ticks_med={st.median(tk):.0f} digest={'|'.join(sorted(digests))}"
        )

    all_digests = {x["digest"] for arm in arms.values() for x in arm.values()}
    print(
        f"-- cross-arm digest parity: "
        f"{'PASS (all arms identical)' if len(all_digests) == 1 else f'FAIL ({len(all_digests)} distinct)'}"
    )

    print("-- paired per-round ratios on total_ns")
    for i, a in enumerate(names):
        for b in names[i + 1 :]:
            common = sorted(set(arms[a]) & set(arms[b]))
            ratios = [
                int(arms[a][r]["total_ns"]) / int(arms[b][r]["total_ns"]) for r in common
            ]
            lo, hi = boot_ci(ratios)
            print(f"  {a}/{b}: {st.median(ratios):.6f}  [{lo:.6f}, {hi:.6f}]  n={len(ratios)}")


if __name__ == "__main__":
    main()
