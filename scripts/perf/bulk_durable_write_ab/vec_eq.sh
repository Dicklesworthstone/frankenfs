set -euo pipefail
W=$PWD; ELF=/data/projects/frankenfs/target/zmvec/release-perf/ffs-cli
FM=/home/ubuntu/ws-fa; TAG=$1; FENV=${2:-}
LOOPS=""
cleanup(){ fusermount3 -u "$FM" 2>/dev/null || true; for d in $LOOPS; do sudo -n losetup -d "$d" 2>/dev/null || true; done; }
trap cleanup EXIT
cleanup; mkdir -p "$FM"
python3 "$W/mkcopy.py" "$W/bimg-base.ext4" "$W/veq-$TAG.img"
DEV=$(sudo -n losetup --find --show --direct-io=on "$W/veq-$TAG.img"); LOOPS="$DEV"
sudo -n chown "$(id -u)" "$DEV"
# shellcheck disable=SC2086
env FFS_MOUNT_BENCH_EVIDENCE=1 RUST_LOG=warn $FENV taskset -c 18 "$ELF" mount --rw "$DEV" "$FM" >>"$W/veq-$TAG.log" 2>&1 &
FPID=$!
for _ in $(seq 1 300); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "FAIL no mount"; exit 1; }
b_tk=$(awk '{print $14+$15}' /proc/$FPID/stat)
out=$("$W/bulkwrite_ab" 6 64 19 "$FPID" "f=$FM" 2>/dev/null | awk -F, 'NR>1{w+=$4;t+=$6;n++} END{printf "%.3f %.3f %d", w/n/1e6, t/n/1e6, n}')
a_tk=$(awk '{print $14+$15}' /proc/$FPID/stat)
fusermount3 -u "$FM"; wait "$FPID" 2>/dev/null || true
read -r wms tms n <<<"$out"
if e2fsck -fn "$W/veq-$TAG.img" >/dev/null 2>&1; then fsck=clean; else fsck=DIRTY; fi
knob=$(grep -h mount_candidate_knobs "$W/veq-$TAG.log" | tail -1 | grep -o 'mvcc_flush_vectored=[a-z]*')
printf "%-10s %-28s rounds=%s write_ms=%-8s total_ms=%-8s ticks=%-5s e2fsck=%-6s sha=%s\n" \
  "$TAG" "$knob" "$n" "$wms" "$tms" "$((a_tk-b_tk))" "$fsck" "$(sha256sum "$W/veq-$TAG.img" | cut -c1-16)"
