#!/bin/bash
# Metadata parity: every large-directory entry must present identical name/size/mode/
# nlink/uid/gid through the FrankenFS mount and through the kernel ext4 mount.
set -euo pipefail
W=${WORK:?set WORK to a scratch directory outside the repo}
ELF=${ELF:?set ELF to the ffs-cli under test}
K1=/home/ubuntu/rdstat-k1
FM=/home/ubuntu/rdstat-fa
fusermount3 -u "$FM" 2>/dev/null || true
sudo -n umount "$K1" 2>/dev/null || true
mkdir -p "$K1" "$FM"
cp "$W/img-base.ext4" "$W/img-fa.ext4"
sudo -n mount -o loop,ro "$W/img-k1.ext4" "$K1"
env FFS_FUSE_WORKERS=4 RUST_LOG=warn taskset -c 8-15 "$ELF" mount "$W/img-fa.ext4" "$FM" >>"$W/fuse-parity.log" 2>&1 &
FPID=$!
for _ in $(seq 1 150); do mountpoint -q "$FM" && break; sleep 0.1; done
python3 - <<'PY'
import os, hashlib
def snap(root):
    d = os.path.join(root, "large-directory")
    out = []
    for n in sorted(os.listdir(d)):
        st = os.lstat(os.path.join(d, n))
        out.append(f"{n},{st.st_size},{oct(st.st_mode)},{st.st_nlink},{st.st_uid},{st.st_gid}")
    return out
a = snap("/home/ubuntu/rdstat-k1")
b = snap("/home/ubuntu/rdstat-fa")
print("kernel entries:", len(a), "ffs entries:", len(b))
print("kernel sha256:", hashlib.sha256("\n".join(a).encode()).hexdigest())
print("ffs    sha256:", hashlib.sha256("\n".join(b).encode()).hexdigest())
print("PARITY:", "pass" if a == b else "FAIL")
if a != b:
    for x, y in zip(a, b):
        if x != y:
            print("first diff:", x, "|", y); break
PY
fusermount3 -u "$FM"; wait "$FPID" 2>/dev/null || true
sudo -n umount "$K1"
