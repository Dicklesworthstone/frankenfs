set -euo pipefail
W=$PWD; ELF=/data/projects/frankenfs/target/zmci/release-perf/ffs-cli
FM=/home/ubuntu/neg-fa; TAG=$1; FENV=${2:-}; ITERS=${ITERS:-3000}
fusermount3 -u "$FM" 2>/dev/null || true; mkdir -p "$FM"
python3 "$W/mkcopy.py" "$W/pimg-base.ext4" "$W/pimg-neg.ext4"
# shellcheck disable=SC2086
env FFS_MOUNT_BENCH_EVIDENCE=1 RUST_LOG=warn $FENV taskset -c 18 \
  "$ELF" mount --rw "$W/pimg-neg.ext4" "$FM" >>"$W/neg-$TAG.log" 2>&1 &
FPID=$!
for _ in $(seq 1 300); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "FAIL: no mount"; exit 1; }
rc=0; out=$("$W/negdentry_probe" "$FM" "$ITERS") || rc=$?
fusermount3 -u "$FM"; wait "$FPID" 2>/dev/null || true
knob=$(grep -h mount_candidate_knobs "$W/neg-$TAG.log" | tail -1 | grep -o 'fuse_create_inval=[a-z]*')
if e2fsck -fn "$W/pimg-neg.ext4" >/dev/null 2>&1; then fsck=clean; else fsck=DIRTY; fi
if [ "$rc" = 0 ] && [ "$fsck" = clean ]; then echo "PASS $knob e2fsck=$fsck $out";
else echo "FAIL rc=$rc $knob e2fsck=$fsck $out"; exit 1; fi
