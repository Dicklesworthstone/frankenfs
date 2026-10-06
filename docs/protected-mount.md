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

The filesystem mount is read-only by default, but **read repair can write the
backing image**. That is why `--allow-repair` remains mandatory for read-only
mounts and admission checks. Without `--rw`, the filesystem's ByteDevice adapter
rejects caller writes; only the admitted device's verified repair path can change
bytes. To authorize ordinary filesystem writes as well:

```sh
cargo run -p ffs-cli --bin ffs-protected-mount -- \
  image.ext4 image.ffsrq /path/to/empty/mountpoint \
  --exclusive-image --allow-repair --rw
```

`--rw` enables the normal `OpenFs` mutation path through the same protected device,
including the existing ext4 and single-device btrfs write-admission checks. It does
not enable ephemeral btrfs commits or kernel writeback cache. `--check` and `--rw`
are mutually exclusive: an admission-only invocation cannot enable caller writes.

Opening first verifies the complete image against the admitted protection point.
A startup mismatch is not presumed to be media damage and is never silently
rolled back. An unfinished write epoch is also rejected, including with `--rw`.
Resolve these offline using the documented sidecar recovery authority; this
command does not invent a new protection point from uncertain data.

Ext4 recovery-required, orphan and non-clean states are rejected. Btrfs requires
one device and no pending tree log. This entry point does not perform journal or
tree-log reconciliation. All superblock and filesystem I/O, including format
detection, uses the protected device rather than a second unverified image opener.

## Writes and protection boundaries

Caller writes pass through the ordinary filesystem/MVCC machinery. When bytes
reach the image, `SidecarImageDevice` durably invalidates the old archive header
before the first mutation and records the intended new block digests. A successful
write is not itself an acknowledgement of durable data or refreshed protection.

Filesystem fsync/fdatasync barriers reach the protected device's `sync`, which
verifies the intended source bytes, stages and verifies updated repair symbols,
locks the replacement archive, atomically publishes it and synchronizes its parent
directory. Publication errors propagate through the filesystem barrier. No second
writable image descriptor bypasses this protocol.

Each dirty device sync scans the image and archive, although normally only changed
groups are re-encoded. A filesystem commit can issue multiple such barriers. This
mode makes no low-latency fsync or production-performance claim.

During an outstanding write epoch, old parity is usable only for a group whose
intended source digests still equal its admitted protection point. A changed peer
forbids old parity even for an unchanged target in that group. Interrupted epochs
remain rejected at the next open; `--rw` does not reconcile them automatically.
See `protected-sidecar-device.md` for the device-level recovery contract.

## Runtime and shutdown

Reads that reach the device use its admitted hashes and bounded RaptorQ recovery.
I/O and cancellation errors retain their original meaning. This is read-triggered
recovery, not a background whole-image scrub.

Ctrl-C cancels startup or requests managed unmount. Shutdown retains device
ownership until the managed filesystem relinquishes its operations. For a writable
filesystem it then invokes the full filesystem durability path before dropping
`OpenFs`, so committed MVCC writes, allocation accounting and btrfs CoW roots are
not lost by merely syncing the underlying device. A final device sync completes
the protection boundary. Cleanup uses a separate, uncancelled context.

Every exit after successful preparation attempts this cleanup, including mount
failure, status-output failure and startup cancellation. A failed checkpoint or
archive publication is an error, not successful shutdown. When both the operation
and cleanup fail, both errors are reported. If managed unmount times out and a
dispatch thread still owns the filesystem, the command reports incomplete shutdown
instead of flushing concurrently or claiming a clean protection boundary.

`--check` performs admission and opens the filesystem root but never creates a
FUSE mount. Its JSON event is `checked_not_mounted`, distinct from `mounted`.
The `read_only` JSON field reflects actual filesystem writability; repair-write
authority is reported independently. `--allow-other` is optional; normal
permission checks remain enabled. Kernel writeback cache is not enabled.

## Regression coverage and limits

The binary's original Rust tests generate a real ext4 image with `mkfs.ext4`, seed
it with `debugfs`, protect it using RaptorQ, and inject data/directory corruption
after admission. They assert exact filesystem results, repaired image bytes,
archive health and a clean `e2fsck -fn`. Authority, mountpoint validation, startup
mismatch, unfinished epochs, read-only rejection and dispatch ownership tests
remain in place.

The read-write extension adds regressions for non-inline data and namespace
persistence on shutdown without caller fsync, protection publication at both
fsync and fdatasync, and repair of newly written bytes after reopen. Independent
image/archive copies captured immediately after fsync are reopened so the test
cannot accidentally pass using the original process's MVCC cache or a later
shutdown refresh. Other cases cover write-mode admission, cancelled startup versus
cleanup authority, and obstructed archive publication. A `mkfs.btrfs` fixture
checks non-inline data, root publication, matching repair coverage, reopen and
`btrfs check --readonly` through the same writable preparation/shutdown path.

```sh
cargo test -p ffs-cli --bin ffs-protected-mount
```

These tests do not require `/dev/fuse`, and therefore do not establish successful
kernel mounting. They require e2fsprogs and btrfs-progs and fail rather than
silently passing when an oracle is absent. Rust/Cargo/rustfmt/RCH and those oracle
tools were unavailable while implementing the read-write extension: its added
regressions, compilation, Clippy, formatting and mounted acceptance have **not**
been executed in that environment.

This integration is experimental. It does not close `bd-11a8t` / `bd-j7a4e`,
change default repair policy, reserve native on-image repair space, enable
multi-device recovery, or certify crash recovery across an unfinished epoch.
