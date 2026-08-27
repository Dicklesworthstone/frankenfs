set -euo pipefail
W=$PWD; ELF=/data/projects/frankenfs/target/zmopen2/release-perf/ffs-cli
V=$1; BASE=$2; WL=$3; TAG=$4
FM=/home/ubuntu/ws-fa
fusermount3 -u "$FM" 2>/dev/null || true; mkdir -p "$FM"
python3 "$W/mkcopy.py" "$W/$BASE" "$W/imgeq-$TAG.img"
env RUST_LOG=warn FFS_MVCC_FLUSH_BORROW=$V taskset -c 18 "$ELF" mount --rw "$W/imgeq-$TAG.img" "$FM" >>"$W/ie-$TAG.log" 2>&1 &
FPID=$!
for _ in $(seq 1 300); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "no mount"; exit 1; }
case "$WL" in
  storm) "$W/storm_ab" 1 200 8 0 "f=$FM" >/dev/null 2>&1 ;;
  bulk)  "$W/bulkwrite_ab" 3 64 19 "$FPID" "f=$FM" >/dev/null 2>&1 ;;
esac
fusermount3 -u "$FM"; wait "$FPID" 2>/dev/null || true
if e2fsck -fn "$W/imgeq-$TAG.img" >/dev/null 2>&1; then fsck=clean; else fsck=DIRTY; fi
echo "$WL borrow=$V e2fsck=$fsck sha256=$(sha256sum "$W/imgeq-$TAG.img" | cut -c1-64)"
