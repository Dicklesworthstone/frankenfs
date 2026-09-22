#!/usr/bin/env bash
# bd-z5bav evidence component: run the runnable non-permissioned contract
# scripts on this FUSE-capable host at one build identity. Records exit codes
# per script; failures are evidence, not obstacles.
# Tracked so the file survives working-tree cleanups.
set -u
cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
mkdir -p rc-e2e-logs
dpkg -l btrfs-progs 2>/dev/null | tail -1 > rc-e2e-logs/host_tools.txt
command -v e2fsck >> rc-e2e-logs/host_tools.txt 2>&1
SCRIPTS="
ffs_self_healing_demo.sh
ffs_wal_replay_e2e.sh
ffs_repair_recovery_smoke.sh
ffs_crash_matrix_e2e.sh
ffs_ext4_rw_smoke.sh
ffs_btrfs_rw_smoke.sh
ffs_btrfs_rw_durable_remount_e2e.sh
ffs_soak_canary_campaign_e2e.sh
"
for s in $SCRIPTS; do
  echo "=== $s start $(date -u +%H:%M:%S) ==="
  timeout 1800 "scripts/e2e/$s" > "rc-e2e-logs/$s.log" 2>&1
  code=$?
  echo "$s exit=$code"
  tail -3 "rc-e2e-logs/$s.log"
done
echo "ALL_E2E_DONE"
