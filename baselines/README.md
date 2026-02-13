# Baselines

This directory stores reproducible benchmark snapshots for CLI and harness workflows.

## Record a Baseline

```bash
scripts/benchmark_record.sh --compare
```

What this does:

1. Runs `scripts/verify_golden.sh` as a preflight conformance gate (unless `--skip-verify-golden` is set).
2. Builds release binaries once.
3. Runs `hyperfine` with JSON export for:
   - `ffs-cli inspect <ext4 reference> --json` (if image exists)
   - `ffs-cli scrub <ext4 reference> --json` (if image exists)
   - `ffs-cli parity --json`
   - `ffs-harness parity`
   - `ffs-harness check-fixtures`
4. Writes artifacts to:
   - `baselines/baseline-YYYYMMDD.md`
   - `baselines/hyperfine/YYYYMMDD/*.json`

## Regression Policy (p95)

- Warn if regression is greater than 10%.
- Fail if regression is greater than 25%.

`--compare` checks current p95 values against the latest prior baseline directory under `baselines/hyperfine/`.
