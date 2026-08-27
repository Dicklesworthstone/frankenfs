set -euo pipefail
W=$PWD; ELF=/data/projects/frankenfs/target/zmbuf/release-perf/ffs-cli
FM=/home/ubuntu/ws-fa
fusermount3 -u "$FM" 2>/dev/null || true; mkdir -p "$FM"
python3 "$W/mkcopy.py" "$W/bimg-base.ext4" "$W/bimg-cf.ext4"
env RUST_LOG=warn taskset -c 18 "$ELF" mount --rw "$W/bimg-cf.ext4" "$FM" >>"$W/cf.log" 2>&1 &
FPID=$!
for _ in $(seq 1 300); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "no mount"; exit 1; }
python3 - "$FM" "$FPID" <<'PY'
import os, sys
mnt, pid = sys.argv[1], int(sys.argv[2])
path = os.path.join(mnt, "bulk-durable.bin")
TOTAL = 64 * 1024 * 1024
def minflt():
    return int(open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[7])
def run(chunk, label):
    fd = os.open(path, os.O_RDWR)
    buf = b"\x5a" * chunk
    os.pwrite(fd, buf, 0); os.fsync(fd)              # warm
    b = minflt()
    off = 0
    while off < TOTAL:
        os.pwrite(fd, buf, off); off += chunk
    os.fsync(fd)
    a = minflt()
    os.close(fd)
    n_req = TOTAL // chunk
    print(f"  {label:<22} chunk={chunk:<9} fuse_writes={n_req:<7} minflt={a-b:<8} "
          f"faults_per_4k_block={(a-b)/(TOTAL/4096):.3f} faults_per_write={(a-b)/n_req:.2f}")
for chunk, label in ((1024*1024, "1 MiB writes"), (4096, "4 KiB writes"), (1024*1024, "1 MiB writes (rpt)")):
    run(chunk, label)
PY
fusermount3 -u "$FM"; wait "$FPID" 2>/dev/null || true
