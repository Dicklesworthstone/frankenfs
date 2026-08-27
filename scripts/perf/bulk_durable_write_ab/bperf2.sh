set -euo pipefail
W=$PWD; ELF=/data/projects/frankenfs/target/zmpi/release-perf/ffs-cli
FM=/home/ubuntu/ws-fa; TAG=$1; FENV=${2:-}
LOOPS=""
cleanup(){ fusermount3 -u "$FM" 2>/dev/null || true; for d in $LOOPS; do sudo -n losetup -d "$d" 2>/dev/null || true; done; }
trap cleanup EXIT
cleanup; mkdir -p "$FM"
python3 "$W/mkcopy.py" "$W/bimg-base.ext4" "$W/bimg-p2.ext4"
DEV=$(sudo -n losetup --find --show --direct-io=on "$W/bimg-p2.ext4"); LOOPS="$DEV"
sudo -n chown "$(id -u)" "$DEV"
# shellcheck disable=SC2086
env FFS_MOUNT_BENCH_EVIDENCE=1 RUST_LOG=warn $FENV taskset -c 18 "$ELF" mount --rw "$DEV" "$FM" >>"$W/b2-$TAG.log" 2>&1 &
FPID=$!
for _ in $(seq 1 300); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "no mount"; exit 1; }
"$W/bulkwrite_ab" 2 64 19 "$FPID" "f=$FM" >/dev/null 2>&1 || true
sudo -n perf record -F 4999 -p "$FPID" -o "$W/b2-$TAG.data" -- sleep 16 & PP=$!
sleep 1
"$W/bulkwrite_ab" 10 64 19 "$FPID" "f=$FM" >/dev/null 2>&1 || true
wait "$PP" 2>/dev/null || true
sudo -n chown "$(id -u)" "$W/b2-$TAG.data"
fusermount3 -u "$FM"; wait "$FPID" 2>/dev/null || true
printf "%-14s " "$TAG"; grep -h mount_candidate_knobs "$W/b2-$TAG.log" | tail -1 | grep -o 'mvcc_flush_borrow=[a-z]*' | tr '\n' ' '
perf report -i "$W/b2-$TAG.data" --no-children -g none --percent-limit 0.5 2>/dev/null \
  | grep -E '^\s+[0-9]' | grep -E 'memmove|memcpy|_rjem' | head -5 | tr '\n' '|'
echo
