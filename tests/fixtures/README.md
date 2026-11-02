# FrankenFS Test Fixtures

This directory contains generated filesystem images plus legacy inspect-output
goldens used by targeted tests and local fixture regeneration workflows.
`./scripts/verify_golden.sh` verifies both the canonical artifacts under
`conformance/{fixtures,golden}` and the committed JSON fixtures in
`tests/fixtures/golden`.

## Directory Structure

```
tests/fixtures/
├── images/                  # Filesystem images (gitignored, regenerated)
│   ├── ext4_small.img       # 16 MiB
│   ├── ext4_medium.img      # 64 MiB
│   ├── ext4_large.img       # 128 MiB
│   ├── btrfs_small.img      # 256 MiB
│   ├── btrfs_medium.img     # 512 MiB
│   └── btrfs_large.img      # 1024 MiB
├── golden/                  # Expected outputs (committed)
│   ├── ext4_*.json          # ffs inspect output
│   ├── ext4_fast_commit_*.json # Fast-commit corpus oracles for replay tests
│   ├── btrfs_*.json         # ffs inspect output
│   ├── checksums.txt        # SHA-256 verification
│   └── *.log                # Generation logs
└── README.md                # This file
```

## Regenerating Fixtures

### ext4

For a clean checkout's native unit-test inputs, CI uses:

```bash
./scripts/fixtures/make_ext4_fixtures.sh --images-only
```

This creates all three native ext4 images with exclusive creation, retains
producer scratch and leaves the committed golden JSON and checksums unchanged.
An existing image path makes provisioning fail.

```bash
./scripts/fixtures/make_ext4_fixtures.sh
```

This script:
1. Creates zero-filled images of specified sizes
2. Formats with `mkfs.ext4` using specific feature flags
3. Populates with known content via `debugfs` (no sudo required)
4. Generates golden JSON outputs using `ffs inspect`
5. Creates SHA-256 checksums for verification

Fast-commit replay corpus fixtures are committed as text JSON under
`tests/fixtures/golden/ext4_fast_commit_*.json`. They are small, deterministic
tag-stream oracles used by `ffs-journal` integration tests and do not rely on
large `.img` artifacts. Mount-path coverage for the same feature also uses
synthetic ext4 images built inline in `crates/ffs-core/src/lib.rs`, which lets
the test suite exercise journal-superblock `s_num_fc_blocks` handling and
truncated fast-commit crash envelopes without committing large binary images.

### btrfs

```bash
./scripts/fixtures/make_btrfs_fixtures.sh [--with-content]
```

This script:
1. Creates zero-filled images (btrfs requires minimum ~256 MiB)
2. Formats with `mkfs.btrfs` using default features
3. Optionally populates with content (requires sudo for mounting)
4. Generates golden JSON outputs using `ffs inspect`
5. Updates SHA-256 checksums

## Image Contents

The legacy inspect-output JSON files in `tests/fixtures/golden` intentionally
freeze the older `ffs inspect` summary surface. They are not the canonical
product conformance proof; canonical semantic goldens live under
`conformance/golden`. The harness test
`validate_legacy_fixture_goldens` keeps these legacy files tied to the fixture
constructors below so shallow-but-valid JSON cannot drift to a different
declared variant unnoticed.

### ext4 Images

Legacy ext4 inspect JSON files are summary goldens. The machine-checked
semantic contract for their regenerated images is:

- `/README.txt file`
- `/dir1 directory`
- `/dir1/file1.bin file size 256`
- `/dir1/dir2 directory`
- `/dir1/dir2/file2.txt file`
- `/symlink symlink target dir1/file1.bin`

Each ext4 image contains a known directory structure:

```
/
├── README.txt           # Description text
├── dir1/
│   ├── file1.bin        # 256 bytes binary (0xFF pattern)
│   └── dir2/
│       └── file2.txt    # Multi-line text file
└── symlink -> dir1/file1.bin
```

### btrfs Images

Legacy btrfs inspect JSON files are structural-only goldens. By default, the
fixture generator formats valid btrfs images with default features and does not
populate file content; canonical btrfs semantic coverage is owned by
`conformance/golden/btrfs_*.json`.

By default, btrfs images contain only the filesystem structure (no files).
Use `--with-content` (requires sudo) to populate with the same structure as ext4.

## Feature Combinations

### ext4

| Image | Size | Features |
|-------|------|----------|
| ext4_small | 16 MiB | `extent,filetype` (V1 minimum) |
| ext4_medium | 64 MiB | `extent,filetype,dir_index` |
| ext4_large | 128 MiB | `extent,filetype,dir_index,sparse_super` |

### btrfs

| Image | Size | Features |
|-------|------|----------|
| btrfs_small | 256 MiB | Default (extref, skinny-metadata, no-holes, free-space-tree) |
| btrfs_medium | 512 MiB | Default |
| btrfs_large | 1024 MiB | Default |

## Verification

For the repository-wide golden/conformance gate, run:

```bash
./scripts/verify_golden.sh
```

To verify only the legacy committed JSON fixtures in `tests/fixtures/golden`:

```bash
cd tests/fixtures/golden
sha256sum -c checksums.txt
```

For a fast repository-wide checksum and clean-checkout manifest guard without
running the cargo-backed conformance tests:

```bash
./scripts/verify_golden.sh --checksums-only
```

## Updating Goldens

After intentional changes to the legacy `tests/fixtures/golden` inspect outputs:

```bash
# Regenerate everything
./scripts/fixtures/make_ext4_fixtures.sh
./scripts/fixtures/make_btrfs_fixtures.sh

# Review changes
git diff tests/fixtures/golden/

# Commit if correct
git add tests/fixtures/golden/
git commit -m "chore: update golden outputs"
```

If the change affects the canonical conformance artifacts under
`conformance/{fixtures,golden}`, re-run `./scripts/verify_golden.sh` and update
those tracked checksums/artifacts in the same change set.

## Requirements

- `mkfs.ext4`, `debugfs` (e2fsprogs)
- `mkfs.btrfs`, `btrfs` (btrfs-progs)
- `dd`, `sha256sum` (coreutils)
- Rust toolchain (for building ffs-cli)
- `sudo` (only for btrfs content population)

## Notes

- Images are NOT committed to git (too large). Use `.gitignore`.
- Goldens and checksums ARE committed for CI verification.
- Generation is deterministic given the same tool versions.
- Generation logs capture tool versions for reproducibility.
