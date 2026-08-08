#!/usr/bin/env bash
# bd-bt2dy negative test: put synthetic load on OFF-PLACEMENT CPUs only, so the
# pre-run placement gate still clears and only the new during-run gate can see it.
# This reproduces the shape of the peer `pytest` that flipped a verdict in bd-ws9dg.
set -u
DURATION="${1:-150}"
# CPUs 16,19,48,51 — outside the same-LLC placement domain (0-7, 32-39), exactly
# where the real contention sat.
for cpu in 16 19 48 51; do
  taskset -c "$cpu" bash -c 'end=$((SECONDS+'"$DURATION"')); while [ $SECONDS -lt $end ]; do :; done' &
done
wait
