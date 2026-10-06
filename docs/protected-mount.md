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
I/O and cancellation errors retain their original meaning. Without the explicit
scrub option below, recovery remains read-triggered.

### Background source scrub

`--scrub-interval-secs N` enables a mount-owned source scanner, in either read-only
or `--rw` mode. It starts after mounting and announcing the mount, scans immediately,
then waits N seconds after each complete pass. N must be 1 through 86400. The option
is disabled by default and conflicts with `--check`.

```sh
cargo run -p ffs-cli --bin ffs-protected-mount -- \
  image.ext4 image.ffsrq /path/to/empty/mountpoint \
  --exclusive-image --allow-repair --rw --scrub-interval-secs 300
```

The scanner reads at most 64 KiB per request through the **same admitted device**,
including source blocks no application reads and the short final block. It releases
the device lock between requests and pauses between batches. Corrupt bytes use the
device's ordinary verified repair path; a changed peer still forbids stale parity.
The scanner never calls device sync, publishes a write epoch, or writes caller data.
An explicit filesystem barrier remains responsible for publishing outstanding writes.

Each complete pass emits a `protected_source_scrub_pass` JSON line on stderr with
the verified source-byte count and `consistency: "per_read_not_snapshot"`. Foreground
writes may advance the intended generation between batches. This is **not** a
point-in-time filesystem integrity proof or parity-health attestation: intact source
bytes do not force a scan or regeneration of every repair symbol. No repair count is
inferred from the byte count. Add the separate parity option below to maintain repair
symbols as well as scanning source bytes.

### Background parity maintenance

`--scrub-parity` adds clean-boundary source/parity maintenance to the same joined
worker. It requires `--scrub-interval-secs` and conflicts with `--check`; source-only
scrubbing and ordinary mount defaults do not change.

```sh
cargo run -p ffs-cli --bin ffs-protected-mount -- \
  image.ext4 image.ffsrq /path/to/empty/mountpoint \
  --exclusive-image --allow-repair --rw \
  --scrub-interval-secs 300 --scrub-parity
```

After each completed source pass, maintenance attempts at most 64 device steps.
Ordinary steps check one source group, its admitted digest table and every repair
symbol, releasing the serializer between groups. A busy device or pending caller
writes defer maintenance without touching bytes or reporting a completed parity
pass. Progress resumes after the next source pass; large images can therefore need
multiple source passes for one parity pass. Every successful archive publication
restarts that progress at group zero, even when its bytes are identical. Sustained
writes may postpone parity completion; the worker never forces a write epoch clean
to make maintenance progress, and repeated restarts cannot consume unbounded steps
within one source pass.

After all groups verify, damaged parity or header bytes trigger the existing
verified atomic archive replacement. **This exceptional final step rescans the
whole image under the serializer and may block foreground I/O.** It is not a
low-latency operation. Clean admission and finalization use the actual source-write
lock, so a write cannot race a separate cleanliness check. Unrecoverable source
data, transplanted metadata, I/O and publication failures remain errors, not
permission to regenerate protection from unknown bytes.

A completed maintenance pass emits `protected_parity_scrub_pass` on stderr with
`consistency: "per_group_not_snapshot"`, group and real-byte counts,
`invalid_repair_symbols_observed`, and `archive_rebuilt`. The
`source_blocks_recovered_during_steps` count covers only successful group steps in
that pass, excluding interrupted/restarted passes and final-refresh repairs. Neither
event claims point-in-time consistency or durable publication of pending filesystem
writes. A parity repair or reporting failure requests managed unmount just like a
source-scan failure; the same guard joins the worker before filesystem cleanup.

An unrecoverable read, evidence-output failure, or unwinding worker panic requests
managed unmount and is returned as an error. Panic-abort builds terminate the process
on panic instead. Shutdown cancels and joins the worker before
filesystem cleanup; dropping the guard also joins rather than leaving an orphan
thread holding image locks. I/O errors racing cancellation are not hidden as success.
Cancellation is checked between reads and while waiting; blocking system calls and
the device's existing group-recovery work do not carry a hard latency guarantee.

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

The source-scrub regressions additionally exercise exact batch coverage, cancellation,
failure-triggered unmount, joined ownership, and real RaptorQ repair of unread source
bytes. They check that dirty-epoch scans preserve the pending archive, refuse changed
peers, and observe an explicitly refreshed generation between batches. They do not
need filesystem oracle binaries when selected separately:

```sh
cargo test -p ffs-cli --bin ffs-protected-mount scrub::
```

The implementation environment lacked Rust/Cargo/rustfmt/RCH for this extension too.
These are added regression cases, not claimed executed tests or mounted acceptance.

Parity-maintenance regressions cover pending/busy deferral, bounded restart work,
epoch and reopen identity, late header damage, cancellation and publication errors.
The CLI worker cases damage all repair symbols for a tail group, replenish them,
reopen the image/archive, and recover newly injected source damage using the new
symbols. They also preserve the source-only mode and reject completion claims on
deferral or reporting failure. The new cases require Rust execution; they were not
run in the implementation environment, which still lacks the Rust/RCH toolchain.

```sh
cargo test -p ffs-repair incremental_scrub
cargo test -p ffs-cli --bin ffs-protected-mount scrub::tests::parity_
```
