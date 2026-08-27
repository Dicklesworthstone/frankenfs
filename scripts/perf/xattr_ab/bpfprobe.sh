set -euo pipefail
W=$PWD; ELF=/data/projects/frankenfs/target/zmjem/release-perf/ffs-cli
FM=/home/ubuntu/xattr-fa
fusermount3 -u "$FM" 2>/dev/null || true; mkdir -p "$FM"
cp "$W/ximg-base.ext4" "$W/ximg-bp.ext4"
env RUST_LOG=warn taskset -c 18 "$ELF" mount "$W/ximg-bp.ext4" "$FM" >>"$W/bp.log" 2>&1 &
FPID=$!
for _ in $(seq 1 300); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "no mount"; exit 1; }
sudo -n bpftrace -e '
kprobe:fuse_getxattr { @[kstack(12), str(arg1)] = count(); }
interval:s:9 { exit(); }' > "$W/bpout.txt" 2>&1 &
BP=$!
sleep 3
taskset -c 8 "$W/xattr_ab" 2 1500 8 0 "f=$FM" >/dev/null 2>&1 || true
wait "$BP" 2>/dev/null || true
fusermount3 -u "$FM"; wait "$FPID" 2>/dev/null || true
echo "=== distinct getxattr names and their kernel stacks"
tail -60 "$W/bpout.txt"
