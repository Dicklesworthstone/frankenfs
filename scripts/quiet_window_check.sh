#!/usr/bin/env bash
# Is this a certification window? Answers the question the comparator's veto asks,
# which is NOT what loadavg answers.
#
# The mounted comparator refuses a row post-hoc when more than 2 off-placement CPUs
# are above 25% busy for more than 10% of samples. Loadavg is a run-queue average
# over 1/5/15 minutes and can read 8-10 while 15 cores are pegged -- that happened
# seven times in one session, every time in the direction of "looks fine, is not".
#
#   scripts/quiet_window_check.sh          # 3 x 10s samples
#   scripts/quiet_window_check.sh 5 6      # 5 samples of 6s
set -euo pipefail
N="${1:-3}"; SECS="${2:-10}"
python3 - "$N" "$SECS" <<'PY'
import sys, time
n, secs = int(sys.argv[1]), int(sys.argv[2])
def snap():
    d = {}
    for l in open('/proc/stat'):
        if l.startswith('cpu') and l[3].isdigit():
            f = l.split(); d[f[0]] = [int(x) for x in f[1:]]
    return d
verdicts = []
for i in range(n):
    a = snap(); time.sleep(secs); b = snap()
    busy = []
    for c in a:
        da = [y - x for x, y in zip(a[c], b[c])]
        tot = sum(da); idle = da[3] + da[4]
        busy.append(100.0 * (tot - idle) / tot if tot else 0.0)
    busy.sort(reverse=True)
    over = sum(1 for x in busy if x > 25)
    verdicts.append(over)
    la = open('/proc/loadavg').read().split()[0]
    print(f"  sample {i+1}: {over:3d} CPUs >25% busy (limit 2)   "
          f"{sum(1 for x in busy if x > 50):2d} >50%   loadavg1={la}   "
          "top: " + " ".join(f"{x:.0f}" for x in busy[:5]))
worst = max(verdicts)
print()
if worst <= 2:
    print(f"QUIET — worst sample had {worst} CPUs over 25%. A timed row can be taken.")
    sys.exit(0)
print(f"NOT QUIET — worst sample had {worst} CPUs over 25% against a limit of 2.")
print("A timed row taken now is likely to be vetoed post-hoc, after paying for the run.")
sys.exit(1)
PY
