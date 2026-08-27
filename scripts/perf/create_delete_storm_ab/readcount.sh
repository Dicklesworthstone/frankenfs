set -euo pipefail
W=$PWD; ELF=/data/projects/frankenfs/target/zmpi/release-perf/ffs-cli
FM=/home/ubuntu/storm-fa; TAG=$1; FENV=${2:-}
LOOPS=""
cleanup(){ fusermount3 -u "$FM" 2>/dev/null || true; for d in $LOOPS; do sudo -n losetup -d "$d" 2>/dev/null || true; done; }
trap cleanup EXIT
cleanup; mkdir -p "$FM"
python3 "$W/mkcopy.py" "$W/simg-base.ext4" "$W/simg-rc.ext4"
DEV=$(sudo -n losetup --find --show --direct-io=on "$W/simg-rc.ext4"); LOOPS="$DEV"
sudo -n chown "$(id -u)" "$DEV"
S=/sys/block/$(basename "$DEV")/stat
# shellcheck disable=SC2086
env FFS_MOUNT_BENCH_EVIDENCE=1 RUST_LOG=warn $FENV taskset -c 18 "$ELF" mount --rw "$DEV" "$FM" >>"$W/rc-$TAG.log" 2>&1 &
FPID=$!
for _ in $(seq 1 300); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "no mount"; exit 1; }
"$W/storm_ab" 1 2000 8 0 "f=$FM" >/dev/null 2>&1 || true   # warm
snap(){ read -r -a A < "$S"; echo "${A[0]} ${A[2]} ${A[4]} ${A[6]}"; }   # rIO rSec wIO wSec
read -r b_rio b_rsec b_wio b_wsec <<<"$(snap)"
b_tk=$(awk '{print $14+$15}' /proc/$FPID/stat)
"$W/storm_ab" 4 2000 8 0 "f=$FM" >/dev/null 2>&1 || true
read -r a_rio a_rsec a_wio a_wsec <<<"$(snap)"
a_tk=$(awk '{print $14+$15}' /proc/$FPID/stat)
fusermount3 -u "$FM"; wait "$FPID" 2>/dev/null || true
ops=$((4*2000*2))
printf "%-24s read_ios=%-8s read_sectors=%-9s write_ios=%-7s write_sectors=%-8s ticks=%-4s reads/op=%.4f\n" \
  "$TAG" "$((a_rio-b_rio))" "$((a_rsec-b_rsec))" "$((a_wio-b_wio))" "$((a_wsec-b_wsec))" "$((a_tk-b_tk))" \
  "$(python3 -c "print(($a_rio-$b_rio)/$ops)")"
