# FrankenFS 128 MiB RaptorQ Encode & GF(256) Delta Refresh Baseline - 20261111

## Scope

Records reproducible Criterion benchmark measurements for the `PLAN_TO_PORT_FRANKENFS_TO_RUST.md` §9.5
128 MiB (`32,768 × 4 KiB`) RaptorQ block-group parity encoding target (`< 100 ms`) and sparse linear
`GF(256)` delta parity refresh (`ΔP = G · (B_old ⊕ B_new)`).

Benchmark target: `crates/ffs-repair/benches/raptorq_128mib_group.rs`
Codec implementation: `crates/ffs-repair/src/codec.rs` (`encode_group_striped`, `update_striped_group_delta`,
`emit_projected_repair_symbols_refs`, `GroupSourceStorage::Contiguous`, `asupersync` `simd-intrinsics`).

## Command

```bash
CARGO_TARGET_DIR=/tmp/ffs-wave3-target rch exec --worker vmi1149989 -- \
  cargo bench -p ffs-repair --bench raptorq_128mib_group -- --quick
```

## Environment

| Field | Value |
|---|---|
| RCH worker | `vmi1149989` |
| Profile | `bench` (`release` / `opt-level` with `asupersync/simd-intrinsics` runtime AVX2/NEON `GF(256)` kernel) |
| Group geometry | `32,768` × `4,096`-byte blocks (`128 MiB` source data), `stride = 64` blocks (`512` stripes × `4` repair symbols = `2,048` repair symbols / `6.25%` overhead) |

## Criterion Results

| Operation | Mean | Throughput | Target (`PLAN_TO_PORT` §9.5) | Status |
|---|---:|---:|---:|---|
| `encode_full_128mib_striped/32768x4k_r4_per_64` | `39.482 ms` | `3.166 GiB/s` (`3.400 GB/s`) | `< 100 ms` (`>= 1.28 GB/s`) | PASS (`2.53x` faster than budget) |
| `delta_update_single_4k_block_in_128mib` | `2.143 us` | `1.780 GiB/s` (`466,635 updates/s`) | `< 1 ms` incremental refresh | PASS (`466x` faster than 1 ms) |

## Architectural Notes

1. **Runtime-Detected SIMD `GF(256)` Kernel (`asupersync/simd-intrinsics`)**: Enables split-nibble
   `vpshufb` (AVX2) / `vtbl` (NEON) table-lookup multiplication+XOR over 32-byte / 16-byte lanes
   with portable scalar fallback and `#![forbid(unsafe_code)]` preserved across every FrankenFS crate.
2. **Zero-Per-Block-Allocation Contiguous Source Reads (`GroupSourceStorage::Contiguous`)**: Reads an
   entire group or stripe via `BlockDevice::read_contiguous_into` into one contiguous buffer instead
   of allocating `32,768` separate 4 KiB `Vec<u8>` heap buffers.
3. **L1D-Cache-Tiled Systematic Projection (`emit_projected_repair_symbols_refs`)**: Tiles row
   accumulations in `32 KiB` L1-resident slices across emitted repair symbols.
4. **Linear `GF(256)` Delta Parity Refresh (`update_encoded_group_delta` / `update_striped_group_delta`)**:
   Exploits linearity of the systematic RaptorQ generator matrix over `GF(2)`/`GF(256)` so mutating
   `m << K` blocks updates repair symbols in `O(m · R · block_size)` rather than re-reading and
   re-encoding all `K = 32,768` blocks; bit-identity against full re-encode is verified via `proptest`
   in `crates/ffs-repair/src/codec.rs`.
