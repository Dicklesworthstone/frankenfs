# Explicit sidecar-protected mounts

`ffs-protected-mount` connects the existing RaptorQ `SidecarImageDevice` to
`OpenFs` and the managed FUSE runtime. It is a separate binary in `ffs-cli`;
the ordinary mount command and its defaults are unchanged.

## Authority and admission

Use an unmounted, clean, single-device image and an existing matching archive.
Create protection with the offline tool while the image is quiescent:

```sh
cargo run -p ffs-repair --bin ffs-image-repair -- \
  protect image.ext4 image.ffsrq --offline
cargo run -p ffs-cli --bin ffs-protected-mount -- \
  image.ext4 image.ffsrq --check --exclusive-image --allow-repair
cargo run -p ffs-cli --bin ffs-protected-mount -- \
  image.ext4 image.ffsrq /path/to/empty/mountpoint \
  --exclusive-image --allow-repair
```

Both authority flags are mandatory. `--exclusive-image` is an operator assertion
that no kernel mount or other program accesses the backing image. Advisory inode
locks protect cooperating users of this device; they cannot enforce exclusion
against non-cooperating kernel or userspace writers. Keep both files outside the
mountpoint. The mountpoint must already exist and be empty.

The filesystem mount is read-only, but **read repair can write the backing
image**. That is why `--allow-repair` remains mandatory for read-only mounts and
admission checks. The filesystem's ByteDevice adapter rejects caller writes;
only the explicitly admitted device's own verified repair path can change bytes.

Opening first verifies the complete image against the admitted protection point.
A startup mismatch is not presumed to be media damage and is never silently
rolled back. An unfinished write epoch is also rejected. Resolve these offline
using the documented sidecar recovery authority; this command does not invent a
new protection point from uncertain data.

Ext4 recovery-required, orphan and non-clean states are rejected. Btrfs requires
one device and no pending tree log. This entry point does not perform journal or
tree-log reconciliation. All superblock and filesystem reads, including format
detection, use the protected device rather than a second unverified image opener.

## Runtime and shutdown

Reads that reach the device use its admitted hashes and bounded RaptorQ recovery.
Existing generation checks still refuse old parity when a target or peer differs
from the admitted generation. I/O and cancellation errors retain their original
meaning. This is read-triggered recovery, not a background whole-image scrub.

Ctrl-C cancels startup or requests managed unmount. Shutdown retains device
ownership until the managed filesystem relinquishes its operations, then performs
a final device sync with a separate cleanup context. If managed unmount times out
and a dispatch thread still owns the filesystem, the command reports incomplete
shutdown instead of claiming a clean protection boundary.

`--check` performs admission and opens the filesystem root but never creates a
FUSE mount. Its JSON event is `checked_not_mounted`, distinct from `mounted`.
The JSON fields make read-only filesystem access and repair-write authority
explicit. `--allow-other` is optional; normal permission checks remain enabled.
Kernel writeback cache is not enabled.

## Regression coverage and limits

The binary's Rust tests generate a real ext4 image with `mkfs.ext4`, seed it with
`debugfs`, protect it using the RaptorQ implementation, and inject data/directory
corruption after admission. They assert exact filesystem results, repaired image
bytes, archive health and a clean `e2fsck -fn`. Other cases cover authority,
mountpoint validation, startup mismatch refusal, unfinished epochs, read-only
write rejection and retained dispatch ownership.

```sh
cargo test -p ffs-cli --bin ffs-protected-mount
```

These tests do not require `/dev/fuse`, and therefore do not establish successful
kernel mounting. They require e2fsprogs and fail rather than silently passing when
an oracle is absent. At introduction, Rust/Cargo/rustfmt/RCH and e2fsprogs were
unavailable in the implementation environment: compilation, these regressions,
Clippy, formatting and mounted acceptance have **not** been executed there.
This integration is experimental. It does not close `bd-11a8t` / `bd-j7a4e`,
change default repair policy, reserve native on-image repair space, enable
multi-device recovery, or certify crash recovery across an unfinished epoch.
