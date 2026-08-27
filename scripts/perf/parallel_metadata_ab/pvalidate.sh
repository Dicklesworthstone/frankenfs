#!/bin/bash
# Correctness gate for the widened dispatch gate: create N files concurrently
# through a FrankenFS --rw mount, unmount, e2fsck the image, then verify through a
# KERNEL mount that exactly the expected names exist, all size 0.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
FENV=${FENV:-}
OPS=${OPS:-4096}
THREADS=${THREADS:-8}
FM=/home/ubuntu/pmeta-fa
V=/home/ubuntu/pmeta-verify
TAG=${TAG:-val}

fusermount3 -u "$FM" 2>/dev/null || true
sudo -n umount "$V" 2>/dev/null || true
mkdir -p "$FM" "$V"
cp "$W/pimg-base.ext4" "$W/pimg-val.ext4"

# shellcheck disable=SC2086
env RUST_LOG=warn $FENV taskset -c 8-15 "$ELF" mount --rw "$W/pimg-val.ext4" "$FM" \
  >> "$W/pfuse-$TAG.log" 2>&1 &
FPID=$!
for _ in $(seq 1 200); do mountpoint -q "$FM" && break; sleep 0.1; done
mountpoint -q "$FM" || { echo "no mount"; exit 1; }

# ONE batch, no reset: creates + directory fsyncs, left on disk.
"$W/pmeta_create_only" "$OPS" "$THREADS" 8 "$FM"

fusermount3 -u "$FM"
wait "$FPID" 2>/dev/null || true

if e2fsck -fn "$W/pimg-val.ext4" >/dev/null 2>&1; then echo "e2fsck=clean"; else echo "e2fsck=DIRTY"; e2fsck -fn "$W/pimg-val.ext4" 2>&1 | head -20; fi

sudo -n mount -o loop,ro "$W/pimg-val.ext4" "$V"
python3 - "$V" "$OPS" "$THREADS" <<'PY'
import os, sys
root, ops, threads = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
missing = extra = nonzero = 0
total = 0
for w in range(threads):
    d = os.path.join(root, "parallel-metadata", f"worker-{w}")
    want = {f"r000000-{i:06d}" for i in range(ops // threads + (1 if w < ops % threads else 0))}
    have = set(os.listdir(d))
    missing += len(want - have)
    extra += len(have - want)
    total += len(have)
    for n in have:
        if os.lstat(os.path.join(d, n)).st_size != 0:
            nonzero += 1
print(f"files_on_disk={total} expected={ops} missing={missing} extra={extra} nonzero_size={nonzero}")
print("PARITY:", "pass" if (missing == 0 and extra == 0 and nonzero == 0 and total == ops) else "FAIL")
PY
sudo -n umount "$V"
rmdir "$V"
