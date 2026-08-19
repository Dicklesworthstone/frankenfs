# PROFILING-SUMMARY.md

> Performance profiling pass for FrankenFS V1.
> Generated: 2026-05-25

## Summary

FrankenFS has comprehensive benchmark coverage (11 criterion targets) with established baselines. The performance infrastructure is mature:

- **Baseline tracking**: `benchmarks/baselines/latest.json` with 29 measured operations
- **Threshold policy**: `benchmarks/thresholds.toml` with family-specific warn/fail bounds
- **Regression detection**: 10-20% warn, 20-50% fail depending on operation family
- **CI integration**: `performance_baseline_manifest.json` with proof-bundle validation

## Benchmark Coverage (7 Scenarios)

| Scenario | Crate | Benchmark | What it measures |
|----------|-------|-----------|------------------|
| Block cache | ffs-block | arc_cache | ARC vs S3-FIFO hit-rate, workload patterns |
| Allocation | ffs-alloc | batch_alloc, bitmap_ops | Buddy-system, find-free, count-free |
| B-tree ops | ffs-btree | bwtree_vs_locked | COW B-tree vs RwLock |
| Extent resolution | ffs-extent | extent_resolve | Logical→physical mapping at depth 1-3 |
| WAL throughput | ffs-mvcc | wal_throughput | Commit rates, SSI overhead, EBR, contention |
| On-disk parsing | ffs-harness | ondisk_parse, metadata_parse | Superblock + group-desc parse |
| Scrub/repair | ffs-repair | scrub_codec | RaptorQ encode/decode |

## Baseline Numbers (April 6, 2026)

### Mount Operations
| Operation | p50 | Throughput |
|-----------|-----|------------|
| Mount cold | 36.8ms | 27 ops/sec |
| Mount warm | 61.1ms | 16 ops/sec |
| Mount recovery | 36.1ms | 28 ops/sec |

### Block Cache (ARC)
| Workload | p50 |
|----------|-----|
| Sequential scan | 10.5s (4096 blocks) |
| Zipf distribution | 9.7s (24000 accesses) |
| Mixed seq70/hot30 | 11.1s |
| Compile-like | 10.2s |
| Database-like | 11.1s |

### WAL + MVCC
| Operation | p50 |
|-----------|-----|
| WAL 1-block commit | 12.0ms |
| WAL 16-block commit | 16.4ms |
| MVCC 2-writer contention | 16.2ms |
| MVCC 4-writer contention | 15.3ms |
| MVCC 8-writer contention | 16.0ms |

### Scrub/Repair
| Operation | p50 |
|-----------|-----|
| Scrub clean 256 blocks | 9.5s |
| Scrub corrupted 256 blocks | 9.6s |
| RaptorQ encode 16 blocks | 10.7ms |
| RaptorQ decode 16 blocks | 12.1ms |

### EBR Memory Report (from artifacts)
| Scenario | Writers | Commits | Elapsed | Reclaim Rate |
|----------|---------|---------|---------|--------------|
| Single writer no GC | 1 | 50K | 30ms | 1.66M/sec |
| Single writer steady | 1 | 100K | 60ms | 1.65M/sec |
| Multi-writer 16 | 16 | 160K | 656ms | 238K/sec |
| Hot key contention | 16 | 128K | 480ms | 266K/sec |

## FUSE Overhead Context

As documented in README:
- FUSE round-trip overhead: ~10µs
- Bounds-check overhead: ~1ns (negligible)
- Expected total overhead vs kernel: ~10-20% on metadata ops

The project explicitly disclaims kernel-parity performance and positions as "not a drop-in replacement" - FUSE latency is acknowledged.

## Assessment

**Gaps Found: 0**

The performance baseline infrastructure is well-developed:
1. All 11 benchmark files have criterion coverage
2. Baselines exist with dated snapshots
3. Thresholds are calibrated per operation family
4. EBR memory behavior is tracked with structured JSON

**No performance-related beads to file** - the infrastructure is mature and claims are appropriately scoped.

## Reproduction Commands

```bash
# Run all benchmarks
cargo bench --workspace --profile release-perf -- --noplot

# Single subsystem
cargo bench -p ffs-mvcc --bench wal_throughput

# Compare to baseline
./scripts/benchmark.sh --compare benchmarks/baselines/latest.json
```

---

*Profiling pass by ProudOtter (2026-05-25)*
