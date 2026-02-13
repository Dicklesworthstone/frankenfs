# FrankenFS E2E Tests

End-to-end smoke tests for FrankenFS that exercise user-facing workflows.

## Quick Start

```bash
# Run the main smoke test
./scripts/e2e/ffs_smoke.sh

# Run ext4 read-write smoke + crash checks
./scripts/e2e/ffs_ext4_rw_smoke.sh

# Run write-back durability scenarios
./scripts/e2e/ffs_writeback_e2e.sh
```

## What It Tests

The smoke test exercises:

1. **Build** - `cargo build --workspace`
2. **CLI Commands**
   - `ffs inspect` - Parse and display filesystem metadata
   - `ffs scrub` - Validate filesystem integrity
   - `ffs parity` - Show feature parity report
3. **FUSE Mount** (if `/dev/fuse` available)
   - Mount an ext4 image read-only
   - List directory contents
   - Read file contents
   - Unmount cleanly

The write-back E2E suite exercises:

1. Basic flush correctness (1000 committed blocks)
2. Clean shutdown flush-all behavior
3. Simulated SIGKILL durability boundary (fsync vs non-fsync)
4. Abort lifecycle discard behavior
5. Backpressure under sustained write load
6. Concurrent commit/abort transactions with daemon flush

The ext4 read-write smoke suite exercises:

1. Rootless fixture lifecycle: create `base.ext4`, copy to `work.ext4`, mount only the work image
2. RW operations: create/write/overwrite, mkdir/rmdir, rename, unlink
3. Metadata checks (phase-gated): chmod verification and mtime monotonicity
4. Clean shutdown persistence: remount read-only and re-verify post-unmount state
5. Best-effort crash phase: SIGKILL mount process, inspect image, and verify remount or explicit recovery diagnostic

## Output

Test artifacts are stored in `artifacts/e2e/<timestamp>/`:

```
artifacts/e2e/20260212_161500_ffs_smoke/
└── run.log    # Complete test log with timestamps
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `RUST_LOG` | `info` | Rust log level (trace, debug, info, warn, error) |
| `RUST_BACKTRACE` | `1` | Enable backtraces on panic |
| `SKIP_MOUNT` | `0` | Set to `1` to skip FUSE mount tests |

## Requirements

- Rust toolchain (nightly)
- `mkfs.ext4` and `debugfs` (e2fsprogs)
- `/dev/fuse` accessible (for mount tests)
- `fusermount` or `fusermount3` (for unmounting)
- `mountpoint` utility (used for readiness checks)

## Skipping Mount Tests

Mount tests are automatically skipped if:
- `/dev/fuse` doesn't exist
- `/dev/fuse` isn't readable/writable
- `SKIP_MOUNT=1` is set

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All tests passed (or skipped with message) |
| 1 | Test failure |

## Troubleshooting

### "Permission denied" on /dev/fuse

Add your user to the `fuse` group:
```bash
sudo usermod -aG fuse $USER
# Log out and back in
```

Or run with sudo (not recommended).

### Mount times out

Check if another FUSE process is hanging:
```bash
ps aux | grep ffs
fusermount -u /path/to/mount
```

### Build fails

Ensure dependencies are available:
```bash
# Check for asupersync and ftui in parent directory
ls -la /dp/asupersync /dp/frankentui
```

## CI Integration

The E2E tests can be run in CI by:

1. Installing dependencies:
   ```bash
   sudo apt-get install -y e2fsprogs fuse3
   ```

2. Running with mount tests skipped (if FUSE not available):
   ```bash
   SKIP_MOUNT=1 ./scripts/e2e/ffs_smoke.sh
   ```

## Adding New Tests

1. Source `lib.sh` for helpers
2. Use `e2e_step`, `e2e_run`, `e2e_assert` for structure
3. Use `e2e_skip` for optional features
4. Use `e2e_fail` for failures
5. Call `e2e_pass` at the end

Example:
```bash
#!/usr/bin/env bash
cd "$(dirname "$0")/../.."
source scripts/e2e/lib.sh

e2e_init "my_test"
e2e_print_env

e2e_step "My Test"
e2e_assert cargo test -p my-crate

e2e_pass
```
