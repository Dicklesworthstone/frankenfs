#!/bin/bash
# Post-run correctness gate for the mutating row: every image the rig wrote must
# pass e2fsck, and `bulk-durable.bin` must read back as ONE uniform byte across all
# 64 MiB (the last batch's sequence byte) through a KERNEL mount of that image.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
V=/home/ubuntu/bulk-verify
mkdir -p "$V"
for n in "$@"; do
  img="$W/bimg-$n.ext4"
  printf '%-6s ' "$n"
  if e2fsck -fn "$img" >/dev/null 2>&1; then printf 'e2fsck=clean '; else printf 'e2fsck=DIRTY '; fi
  sudo -n umount "$V" 2>/dev/null || true
  sudo -n mount -o loop,ro "$img" "$V"
  python3 - "$V/bulk-durable.bin" <<'PY'
import sys
p = sys.argv[1]
first = None
uniform = True
n = 0
with open(p, "rb") as f:
    while True:
        b = f.read(1 << 20)
        if not b:
            break
        n += len(b)
        if first is None:
            first = b[0]
        if b.count(first) != len(b):
            uniform = False
print(f"bytes={n} first_byte={first} uniform={uniform}")
PY
  sudo -n umount "$V"
done
rmdir "$V"
