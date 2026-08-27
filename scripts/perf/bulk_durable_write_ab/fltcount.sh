set -euo pipefail
W=$PWD; ELF=/data/projects/frankenfs/target/zmbuf/release-perf/ffs-cli
FM=/home/ubuntu/ws-fa; TAG=$1; shift; MC="$*"
fusermount3 -u "$FM" 2>/dev/null || true; mkdir -p "$FM"
python3 "$W/mkcopy.py" "$W/bimg-base.ext4" "$W/bimg-fc.ext4"
# shellcheck disable=SC2086
env RUST_LOG=warn $MC taskset -c 18 "$ELF" mount --rw "$W/bimg-fc.ext4" "$FM" >>"$W/fc-$TAG.log" 2>&1 &
FPID=$!
for _ in $(seq 1 300); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "no mount"; exit 1; }
"$W/bulkwrite_ab" 2 64 19 "$FPID" "f=$FM" >/dev/null 2>&1 || true   # warm
b_min=$(awk '{print $10}' /proc/$FPID/stat); b_maj=$(awk '{print $12}' /proc/$FPID/stat)
b_ut=$(awk '{print $14+$15}' /proc/$FPID/stat)
out=$("$W/bulkwrite_ab" ${R:-6} ${C:-64} 19 "$FPID" "f=$FM" 2>/dev/null | awk -F, 'NR>1{w+=$4; t+=$6; n++} END{printf "%.3f %.3f %d", w/n/1e6, t/n/1e6, n}')
a_min=$(awk '{print $10}' /proc/$FPID/stat); a_maj=$(awk '{print $12}' /proc/$FPID/stat)
a_ut=$(awk '{print $14+$15}' /proc/$FPID/stat)
fusermount3 -u "$FM"; wait "$FPID" 2>/dev/null || true
read -r wms tms n <<<"$out"
printf "%-22s minflt=%-9s majflt=%-4s ticks=%-5s write_ms=%-8s total_ms=%-8s rounds=%s\n" \
  "$TAG" "$((a_min-b_min))" "$((a_maj-b_maj))" "$((a_ut-b_ut))" "$wms" "$tms" "$n"
