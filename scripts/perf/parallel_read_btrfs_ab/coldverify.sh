set -euo pipefail
W=$PWD; ELF=/data/projects/frankenfs/target/zmcsum/release-perf/ffs-cli
FM=/home/ubuntu/preadb-fa
CYCLES=${CYCLES:-8}
# COLD here means "a freshly mounted daemon with an empty FrankenFS cache", produced
# by remounting between batches. It does NOT drop the host page cache: that is a
# host-wide action on a shared box, and the flag under test gates FrankenFS's own
# verification of bytes it has already fetched, so a fresh daemon is the regime that
# actually distinguishes the two arms.
echo "cycle,arm,list_ns,read_ns,total_ns,digest"
for c in $(seq 1 "$CYCLES"); do
  for arm in ON OFF; do
    [ "$arm" = ON ] && FLAG=true || FLAG=false
    fusermount3 -u "$FM" 2>/dev/null || true
    mkdir -p "$FM"
    python3 "$W/mkcopy.py" "$W/rimgb-base.btrfs" "$W/rimgb-cold.btrfs" 2>/dev/null || cp "$W/rimgb-base.btrfs" "$W/rimgb-cold.btrfs"
    DEV=$(sudo -n losetup --find --show --direct-io=on "$W/rimgb-cold.btrfs")
    sudo -n chown "$(id -u)" "$DEV"
    env FFS_MOUNT_BENCH_EVIDENCE=1 RUST_LOG=warn taskset -c 18 \
      "$ELF" mount --btrfs-verify-data-on-read "$FLAG" "$DEV" "$FM" >>"$W/cold-$arm.log" 2>&1 &
    P=$!
    for _ in $(seq 1 300); do mountpoint -q "$FM" && break; sleep 0.1; done
    mountpoint -q "$FM" || { echo "no mount" >&2; exit 1; }
    row=$("$W/pread_ab" 1 8 8 0 "x=$FM" 2>/dev/null | awk -F, 'NR>1{print $4","$5","$6","$7}')
    echo "$c,$arm,$row"
    fusermount3 -u "$FM"; wait "$P" 2>/dev/null || true
    sudo -n losetup -d "$DEV" 2>/dev/null || true
  done
done
