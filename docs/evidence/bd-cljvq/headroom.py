"""How much CPU headroom does this box leave for a STORM ARM? (bd-cljvq)

bd-cljvq's hard part is not producing a storm, it is getting the storm arm
ADMITTED: 0 of 9 manufactured storms cleared `external_load_during_run`, and the
refusals came from this box's background churn, not from the storm.

This measures the background's per-sample busy-CPU distribution and then asks,
for each k, what fraction of windows would still be admitted if a storm added k
busy CPUs. It touches no device and perturbs nothing, so it can run beside a
peer's benchmark -- and running it beside one is the RIGHT reading, because
realistic co-tenancy is the condition the storm arm would actually face.

Mirrors ExternalLoadWitness::clean exactly: a sample is contended iff its
busy-CPU count exceeds the limit; a window is refused iff the contended fraction
exceeds 0.10 OR 3 consecutive samples are contended.
"""
import sys, time, pathlib

EXTERNAL_BUSY_CPU_FRACTION = 0.25
MAX_EXTERNAL_BUSY_CPUS = 4
MAX_CONTENDED_SAMPLE_FRACTION = 0.10
MAX_CONSECUTIVE = 3
WINDOW = 40

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
        if len(v) < 5:
            continue
        out[cpu] = (sum(v), v[3] + v[4])
    return out

samples = int(sys.argv[1]) if len(sys.argv) > 1 else 120
counts = []
for _ in range(samples):
    a = ticks(); time.sleep(1.0); b = ticks()
    n = 0
    for cpu, (ta, ia) in a.items():
        tb, ib = b[cpu]
        dt = tb - ta
        if dt <= 0:
            continue
        if (dt - (ib - ia)) / dt > EXTERNAL_BUSY_CPU_FRACTION:
            n += 1
    counts.append(n)

def admitted(cs):
    over = [c > MAX_EXTERNAL_BUSY_CPUS for c in cs]
    if sum(over) / len(over) > MAX_CONTENDED_SAMPLE_FRACTION:
        return False
    run = best = 0
    for o in over:
        run = run + 1 if o else 0
        best = max(best, run)
    return best < MAX_CONSECUTIVE

wins = [counts[i:i+WINDOW] for i in range(0, len(counts) - WINDOW + 1, WINDOW)]
counts_sorted = sorted(counts)
p = lambda q: counts_sorted[min(len(counts_sorted)-1, int(q*len(counts_sorted)))]
print(f"samples={len(counts)}  busy-CPU count: p50={p(.5)} p90={p(.9)} p99={p(.99)} max={max(counts)}")
print(f"non-overlapping {WINDOW}-sample windows: {len(wins)}")
print()
print(" storm adds k busy CPUs -> windows ADMITTED")
for k in range(0, 7):
    ok = sum(1 for w in wins if admitted([c + k for c in w]))
    print(f"   k={k}: {ok}/{len(wins)}")
