set -euo pipefail
W=$PWD; ELF=/data/projects/frankenfs/target/zmopen2/release-perf/ffs-cli
V=$1; TAG=$2; MODE=${3:-seq}
FM=/home/ubuntu/ws-fa
LOOPS=""
cleanup(){ fusermount3 -u "$FM" 2>/dev/null || true; for d in $LOOPS; do sudo -n losetup -d "$d" 2>/dev/null || true; done; }
trap cleanup EXIT
cleanup; mkdir -p "$FM"
python3 "$W/mkcopy.py" "$W/bimg-base.ext4" "$W/bimg-sq.ext4"
DEV=$(sudo -n losetup --find --show --direct-io=on "$W/bimg-sq.ext4"); LOOPS="$DEV"
sudo -n chown "$(id -u)" "$DEV"
env RUST_LOG=warn FFS_MOUNT_BENCH_EVIDENCE=1 FFS_MVCC_FLUSH_BORROW=$V taskset -c 18 "$ELF" mount --rw "$DEV" "$FM" >>"$W/bs-$TAG.log" 2>&1 &
FPID=$!
for _ in $(seq 1 300); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "no mount"; exit 1; }
if [ "$MODE" = perf ]; then
  sudo -n perf record -F 4999 -g -p "$FPID" -o "$W/bs-$TAG.data" -- sleep 14 & PP=$!
  sleep 1
  "$W/bulkwrite_ab" 8 64 19 "$FPID" "f=$FM" >/dev/null 2>&1 || true
  wait "$PP" 2>/dev/null || true
  sudo -n chown "$(id -u)" "$W/bs-$TAG.data"
else
  sudo -n strace -f -p "$FPID" -e trace=pwrite64,pwritev,fdatasync,fsync -o "$W/bsraw-$TAG.txt" & SPID=$!
  sleep 1
  "$W/bulkwrite_ab" 3 64 19 "$FPID" "f=$FM" >/dev/null 2>&1 || true
  sleep 1
  sudo -n kill -INT "$SPID" 2>/dev/null || true; wait "$SPID" 2>/dev/null || true
  sudo -n chown "$(id -u)" "$W/bsraw-$TAG.txt" 2>/dev/null || true
fi
fusermount3 -u "$FM"; wait "$FPID" 2>/dev/null || true
grep -h 'mount_candidate_knobs' "$W/bs-$TAG.log" | tail -1 | grep -o 'mvcc_flush_borrow=[a-z]*'
if [ "$MODE" = perf ]; then
  echo "--- borrow=$V flush self-time"
  perf report -i "$W/bs-$TAG.data" --no-children --percent-limit 0.05 2>/dev/null | grep -i 'flush_to_device\|write_contiguous\|run_buf' | head -6
else
python3 - "$W/bsraw-$TAG.txt" "$W/bseq-$TAG.txt" <<'PY'
import re, sys
wr = re.compile(r'pwrite(?:64)?\(\d+, .*?, (\d+), (\d+)\)\s*=\s*\d+')
out=[]
for line in open(sys.argv[1], errors="replace"):
    m = wr.search(line)
    if m: out.append(f"W {m.group(1)} {m.group(2)}")
    elif "fdatasync(" in line or re.search(r'\bfsync\(', line): out.append("BARRIER")
open(sys.argv[2],"w").write("\n".join(out)+"\n")
print(f"{sys.argv[2]}: {len(out)} events ({sum(1 for x in out if x=='BARRIER')} barriers)")
PY
fi
