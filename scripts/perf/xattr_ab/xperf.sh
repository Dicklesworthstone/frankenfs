set -euo pipefail
W=$PWD; ELF=/data/projects/frankenfs/target/zmjem/release-perf/ffs-cli
FM=/home/ubuntu/xattr-fa; TAG=$1; FENV=${2:-}
fusermount3 -u "$FM" 2>/dev/null || true; mkdir -p "$FM"
cp "$W/ximg-base.ext4" "$W/ximg-xp.ext4"
# shellcheck disable=SC2086
env FFS_MOUNT_BENCH_EVIDENCE=1 FFS_OP_COUNTS=1 RUST_LOG=warn $FENV taskset -c 18 \
  "$ELF" mount "$W/ximg-xp.ext4" "$FM" >>"$W/xp-$TAG.log" 2>&1 &
FPID=$!
for _ in $(seq 1 300); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "no mount"; exit 1; }
sudo -n perf record -F 4999 -g -p "$FPID" -o "$W/xp-$TAG.data" -- sleep 14 & PP=$!
sleep 1
"$W/xattr_ab" 12 2000 8 "$FPID" "f=$FM" >/dev/null 2>&1 || true
wait "$PP" 2>/dev/null || true
sudo -n chown "$(id -u)" "$W/xp-$TAG.data"
fusermount3 -u "$FM"; wait "$FPID" 2>/dev/null || true
echo "--- $TAG flat self-time"
perf report -i "$W/xp-$TAG.data" --no-children -g none --percent-limit 0.6 2>/dev/null | grep -E '^\s+[0-9]' | head -22
