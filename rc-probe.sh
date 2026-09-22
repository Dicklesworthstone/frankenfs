#!/usr/bin/env bash
# Reality-check functional probes (bd-kiw6c). Non-destructive: all artifacts
# under /tmp on the worker; the image is created fresh by ffs-cli itself.
set -u
cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
mkdir -p probe-out
cargo build -p ffs-cli -p ffs-harness -p ffs-repair --bins > probe-out/build.log 2>&1
echo "build_exit=$?"
tail -2 probe-out/build.log
B=.rch-target/debug
[ -x "$B/ffs-cli" ] || B=target/debug
echo "using B=$B"
ls -la "$B/ffs-cli" "$B/ffs-harness" "$B/ffs-demo" || true
IMG=/tmp/rc_probe.img
rm -f "$IMG"

echo "== probe 1: ffs mkfs (project subcommand, fresh temp file) =="
$B/ffs-cli mkfs "$IMG" --size-mb 64 --block-size 4096 --label rcheck --json > probe-out/mkfs.json 2> probe-out/mkfs.err
echo "mkfs_exit=$?"

echo "== probe 2: inspect =="
$B/ffs-cli inspect "$IMG" --json > probe-out/inspect.json 2>&1
echo "inspect_exit=$?"

echo "== probe 3: info --groups --journal =="
$B/ffs-cli info "$IMG" --groups --journal --json > probe-out/info.json 2>&1
echo "info_exit=$?"

echo "== probe 4: dump dir 2 =="
$B/ffs-cli dump dir 2 "$IMG" --json > probe-out/dumpdir.json 2>&1
echo "dumpdir_exit=$?"

echo "== probe 5: scrub =="
$B/ffs-cli scrub "$IMG" --json > probe-out/scrub.json 2>&1
echo "scrub_exit=$?"

echo "== probe 6: harness parity =="
$B/ffs-harness parity > probe-out/parity.txt 2>&1
echo "parity_exit=$?"

echo "== probe 7: harness check-fixtures =="
$B/ffs-harness check-fixtures > probe-out/fixtures.txt 2>&1
echo "fixtures_exit=$?"

echo "== probe 8: self-healing demo =="
$B/ffs-demo self-healing > probe-out/demo.txt 2>&1
echo "demo_exit=$?"

echo "== probe 9: read-only FUSE mount =="
mkdir -p /tmp/rc_mnt
timeout 90 "$B/ffs-cli" mount "$IMG" /tmp/rc_mnt > probe-out/mount.log 2>&1 &
MPID=$!
sleep 10
ls /tmp/rc_mnt > probe-out/mnt_ls.txt 2>&1
echo "mnt_ls_exit=$?"
stat -f -c '%T' /tmp/rc_mnt > probe-out/mnt_type.txt 2>&1
fusermount3 -u /tmp/rc_mnt >> probe-out/mount.log 2>&1
wait $MPID
echo "mount_probe_exit=$?"

echo "ALL_PROBES_DONE"
