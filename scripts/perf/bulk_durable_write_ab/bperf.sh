#!/bin/bash
# Profile the FrankenFS daemon while the bulk-durable-write batch is in flight.
set -euo pipefail
W=${WORK:?set WORK}
ELF=${ELF:?set ELF}
FM=/home/ubuntu/bulk-fa
FCPUS=${FCPUS:-16}
FENV=${FENV:-}
TAG=${TAG:-bperf}
ROUNDS=${ROUNDS:-40}

fusermount3 -u "$FM" 2>/dev/null || true
mkdir -p "$FM"
python3 "$W/mkcopy.py" "$W/bimg-base.ext4" "$W/bimg-fa.ext4"
DEV=$(sudo -n losetup --find --show --direct-io=on "$W/bimg-fa.ext4")
sudo -n chown "$(id -u)" "$DEV"
echo "loop=$DEV dio=$(cat /sys/block/$(basename "$DEV")/loop/dio)"
# shellcheck disable=SC2086
env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn $FENV \
  taskset -c "$FCPUS" "$ELF" mount --rw "$DEV" "$FM" >> "$W/bfuse-$TAG.log" 2>&1 &
FPID=$!
for _ in $(seq 1 200); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "no mount"; exit 1; }
echo "daemon pid $FPID"
"$W/bulkwrite_ab" 1 64 8 0 f="$FM" >/dev/null 2>&1

sudo -n perf record -F 4999 -g --call-graph dwarf -p "$FPID" -o "$W/$TAG.data" -- sleep 14 &
PERFPID=$!
"$W/bulkwrite_ab" "$ROUNDS" 64 8 "$FPID" f="$FM" > "$W/bulk-$TAG.csv" 2>/dev/null || true
wait $PERFPID 2>/dev/null || true
fusermount3 -u "$FM"
wait "$FPID" 2>/dev/null || true
sudo -n losetup -d "$DEV" 2>/dev/null || true
sudo -n chown "$(id -u):$(id -g)" "$W/$TAG.data"
echo "== dso"
perf report -i "$W/$TAG.data" --stdio --no-children -g none --sort dso 2>/dev/null | sed -n '8,16p'
echo "== symbols"
perf report -i "$W/$TAG.data" --stdio --no-children -g none --percent-limit 0.7 2>/dev/null | grep "%" | head -35
