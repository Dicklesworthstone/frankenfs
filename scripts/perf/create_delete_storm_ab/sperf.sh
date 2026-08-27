#!/bin/bash
# Profile the FrankenFS daemon while the create/delete storm is in flight, and
# report per-daemon-thread CPU over the same load.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
FM=/home/ubuntu/storm-fa
FCPUS=${FCPUS:-16}
FENV=${FENV:-}
TAG=${TAG:-sperf}
ROUNDS=${ROUNDS:-60}
OPS=${OPS:-2000}

fusermount3 -u "$FM" 2>/dev/null || true
mkdir -p "$FM"
cp "$W/simg-base.ext4" "$W/simg-fa.ext4"
# shellcheck disable=SC2086
env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn $FENV \
  taskset -c "$FCPUS" "$ELF" mount --rw "$W/simg-fa.ext4" "$FM" >> "$W/sfuse-$TAG.log" 2>&1 &
FPID=$!
for _ in $(seq 1 200); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "no mount"; exit 1; }
echo "daemon pid $FPID"
"$W/storm_ab" 1 "$OPS" 8 0 f="$FM" >/dev/null 2>&1

sudo -n perf record -F 4999 -g --call-graph dwarf -p "$FPID" -o "$W/$TAG.data" -- sleep 14 &
PERFPID=$!
"$W/storm_ab" "$ROUNDS" "$OPS" 8 "$FPID" f="$FM" > "$W/storm-$TAG.csv" 2>/dev/null || true
wait $PERFPID 2>/dev/null || true
fusermount3 -u "$FM"
wait "$FPID" 2>/dev/null || true
sudo -n chown "$(id -u):$(id -g)" "$W/$TAG.data"
echo "== dso"
perf report -i "$W/$TAG.data" --stdio --no-children -g none --sort dso 2>/dev/null | sed -n '8,16p'
echo "== self symbols"
perf report -i "$W/$TAG.data" --stdio --no-children -g none --percent-limit 0.9 2>/dev/null | grep "%" | head -28
