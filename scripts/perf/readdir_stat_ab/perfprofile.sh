#!/bin/bash
# Profile the FrankenFS daemon while the readdir+stat batch is in flight.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
FM=/home/ubuntu/rdstat-fa
FCPUS=${FCPUS:-16}
FENV=${FENV:-}
TAG=${TAG:-perf}

fusermount3 -u "$FM" 2>/dev/null || true
mkdir -p "$FM"
cp "$W/img-base.ext4" "$W/img-fa.ext4"

# shellcheck disable=SC2086
env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn $FENV \
  taskset -c "$FCPUS" "$ELF" mount "$W/img-fa.ext4" "$FM" >> "$W/fuse-$TAG.log" 2>&1 &
FPID=$!
for _ in $(seq 1 150); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "no mount"; exit 1; }
echo "daemon pid $FPID"

# warm
"$W/rdstat_ab" 1 8 8 0 f="$FM" >/dev/null 2>&1

sudo -n perf record -F 4999 -g --call-graph dwarf -p "$FPID" -o "$W/$TAG.data" -- sleep 12 &
PERFPID=$!
"$W/rdstat_ab" 40 8 8 "$FPID" f="$FM" > "$W/rdstat-$TAG.csv" 2>/dev/null || true
wait $PERFPID 2>/dev/null || true

fusermount3 -u "$FM"
wait "$FPID" 2>/dev/null || true
sudo -n chown "$(id -u):$(id -g)" "$W/$TAG.data"
echo "== report"
perf report -i "$W/$TAG.data" --stdio --no-children -g none --percent-limit 0.5 2>/dev/null | head -45
