#!/usr/bin/env bash
# Bring up the two arms for scripts/mounted_kernel_ab.py.
#
#   arm K : REAL kernel ext4, loop-mounted        -> /mnt/ffsk
#   arm F : frankenfs over FUSE, read-write       -> /tmp/ffsf
#
# Both images are created by the SAME mke2fs invocation shape so the on-disk
# geometry is identical, and both are mounted `noatime` so the durability and
# atime behaviour match (T2). The measurement driver re-asserts all of this from
# /proc/self/mountinfo at runtime and refuses to measure if it does not hold —
# this script being correct is not taken on trust.
#
# Requires: passwordless sudo (loop mount), fuse, mke2fs.
set -uo pipefail

SP="${SP:-/data/tmp/claude-1000/-data-projects-frankenfs/6d73f571-cf28-4b9e-91df-15a86c5e35a5/scratchpad}"
BIN="${BIN:-/data/tmp/cargo-target/release-perf/ffs-cli}"
KMNT="${KMNT:-/mnt/ffsk}"
FMNT="${FMNT:-/tmp/ffsf}"
BLOCKS="${BLOCKS:-524288}"     # 2 GiB at 4 KiB
INODES="${INODES:-262144}"

seed="$SP/seed"
mkdir -p "$seed/d" "$SP"

echo ">> tearing down any previous arms"
fusermount -u "$FMNT" 2>/dev/null
sudo umount "$KMNT" 2>/dev/null
sleep 1

echo ">> building images (identical geometry)"
/usr/sbin/mke2fs -t ext4 -F -q -b 4096 -N "$INODES" -d "$seed" "$SP/k.img" "$BLOCKS" || exit 1
/usr/sbin/mke2fs -t ext4 -F -q -b 4096 -N "$INODES" -d "$seed" "$SP/f.img" "$BLOCKS" || exit 1

echo ">> mounting kernel ext4 at $KMNT (noatime)"
sudo mkdir -p "$KMNT"
sudo mount -o loop,noatime "$SP/k.img" "$KMNT" || exit 1
sudo chown -R "$(id -u):$(id -g)" "$KMNT" || exit 1

echo ">> mounting frankenfs at $FMNT (rw)"
mkdir -p "$FMNT"
( setsid "$BIN" mount "$SP/f.img" "$FMNT" --runtime-mode managed --rw \
    > "$SP/fuse.log" 2>&1 < /dev/null & )
for _ in $(seq 1 30); do
  grep -q " $FMNT " /proc/self/mountinfo && break
  sleep 1
done

echo ">> arm identities as the kernel sees them:"
for m in "$KMNT" "$FMNT"; do
  grep " $m " /proc/self/mountinfo \
    | awk -v m="$m" '{for(i=1;i<=NF;i++) if($i=="-"){printf "   %s fstype=%s src=%s opts=%s\n", m, $(i+1), $(i+2), $6; break}}'
done
echo ">> ready. measure with:"
echo "   python3 scripts/mounted_kernel_ab.py --kernel $KMNT --frankenfs $FMNT/d \\"
echo "        --tmpfs /dev/shm/ffs_ceiling --count 2000 --rounds 11 --cpus 2,3"
