#!/usr/bin/env bash
# Sample EXTERNAL (non-bench) CPU load during a comparator run.
#
# bd-4sull's finding is that the harness's preflight samples only BEFORE the run,
# so co-tenant load arriving mid-run is invisible. Total CPU% is useless for this
# because the bench itself is the dominant consumer; what matters is everything
# that is NOT the bench.
out="$1"
: > "$out"
for _ in $(seq 1 500); do
  ext=$(ps -eo pcpu,comm --no-headers \
        | grep -vE 'ffs-mounted-ker|ffs-cli|^ *[0-9.]+ (ps|awk|grep|sleep|bash)$' \
        | awk '{s+=$1} END {printf "%.1f", s}')
  printf '%s load=%s external_cpu=%s\n' "$(date +%H:%M:%S)" "$(cut -d' ' -f1 /proc/loadavg)" "$ext" >> "$out"
  sleep 3
done
