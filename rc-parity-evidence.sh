#!/usr/bin/env bash
# bd-z5bav evidence component: execute all registered parity suites plus the
# canonical §22 gates on ONE build identity, banking ExecutedEvidence reports.
# Tracked so rch --job overlay transfers always include it.
set -u
cd "$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
mkdir -p parity-ev
cargo build -p ffs-harness --bin ffs-harness > parity-ev/build.log 2>&1
echo "build_exit=$?"
B=$(find .rch-target target -type f -name ffs-harness 2>/dev/null | head -1)
echo "binary=$B"
[ -z "$B" ] && { echo "no ffs-harness binary"; exit 1; }
"$B" parity --json > parity-ev/declared_before.json 2>&1
SUITES="ext4-journal ext4-reference ext4-kernel-differential btrfs-reference parity-honesty mvcc-lib journal-lib repair-lib fuse-lib btrfs-lib ondisk-lib core-lib conformance profile-artifacts cli-e2e cli-bins"
for s in $SUITES; do
  "$B" parity --verify "$s" --local > "parity-ev/$s.json" 2> "parity-ev/$s.stderr"
  echo "$s exit=$?"
done
"$B" gates --all --local --out parity-ev/gates.json > parity-ev/gates.stdout 2> parity-ev/gates.stderr
echo "gates exit=$?"
"$B" parity --json > parity-ev/declared_after.json 2>&1
echo "ALL_SUITES_DONE"
