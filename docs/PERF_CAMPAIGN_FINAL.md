# FrankenFS solo perf campaign — FINAL consolidation (2026-07-10)

**Status: COMPLETE. HOLD — no more solo lever-hunting.** All five subsystem axes
(read/IO, compression, checksum, write-path, metadata) are profiled/audited and
are each a landed win or a measured floor. This document is the completed-repo
capstone: the shipped wins by axis, and every reject with its ID, null-control
result, and retry-condition. Detailed per-row prose lives in
`docs/NEGATIVE_EVIDENCE.md` and `docs/progress/perf-negative-results.md`; the
live frontier statement is at the top of `docs/PERF_CAMPAIGN_STATUS.md`.

## 2026-07-25 build-identity correction (`bd-b9dug`)

The historical campaign used ordinary `cargo bench --profile release-perf`
binaries. Those compile FrankenFS code for Rust's generic x86-64 baseline, while
the performance distribution produced by `scripts/build-perf.sh` uses fat LTO,
`target-cpu=x86-64-v3`, and PGO trained on CLI create/lookup/rename/delete/walk
workloads. Unless an individual row proves otherwise with its executing-ELF
hash, every ratio in this document is therefore a **generic benchmark-ELF**
measurement, not a measurement of the binary shipped by that script.

The final same-worker checks ran on pinned `hz2` and required both a distinct
executing-ELF hash and an in-binary AVX2+FMA witness. Allocator moved from
generic **12.445408×** CI `[12.348123, 12.495432]` (ELF
`444f2807ea2920cb2f90fb09a85c9b31c53091981eb3b76f6d9d4cf1895a1cb3`)
to v3 **13.631067×** CI `[13.452977, 13.759302]` (ELF
`fc40f87b2647fda9ac36501f673428c090f3d88b2d20136deca81e8c6ea41955`).
Production JBD2 moved from generic **2.630522×** CI
`[2.623337, 2.643932]` (ELF
`8695daa5adfbbe17e9a823790ebc644b490f9738a41f44e93f7005b51ca2f899`)
to v3 **2.605531×** CI `[2.597625, 2.618523]` (ELF
`f91979ffaf94b61a589716314344f6ec006e31a3beffe01faaf817e8a208f433`).
All four runs had exact behavior parity and approximately 1.000× A/A nulls.
The source ratios therefore moved by +9.53% and -0.95% respectively while both
verdicts remained decisive.

The previously reported “v3” allocator ELF and its 12.122× / 11.6% claims are
withdrawn. That binary had a distinct hash but self-reported
`compile_avx2=false,compile_fma=false`: the local flag did not cross RCH.
Two other Cargo-config routes failed the same witness. The admitted route used
`RCH_ENV_ALLOWLIST=RUSTFLAGS`, and a verbose remote compiler probe plus the
executing binaries both reported AVX2+FMA. These v3 ELFs did **not** carry the
CLI PGO profile, so they are not exact production-binary certifications.

The 2026-07-27 strict-remote closeout now supplies exact production-shaped
v3+PGO evidence for one CLI lookup corpus. On pinned worker `ovh-a`, the
generic release-perf CLI self-reported ELF
`1d36a367ee3703d99a92b8af52387af2570787db4070065082185db681517764`;
the final v3+PGO CLI self-reported ELF
`7136d8bf768a222ec2e6985efbe25249131a274db3b9bc81a4394323265adc62`
and embedded consumed-profile SHA
`3dbce2b2fca971cacd1963d0aaeb867de10417761624a0c1236d01a6880860db`.
Across 31 alternating `AAB`/`BAA` rounds of 200,000 lookups on the same
8,003-entry image, generic median was **21,667 us** and v3+PGO median was
**15,110 us**. Generic/v3+PGO was **1.437700x**, bootstrap median 95% CI
**[1.414742, 1.494961]**, versus generic/generic A/A **0.994371x**, CI
**[0.974583, 1.005166]**. The real lower bound cleared the twice-null
threshold **1.052840x**; exact output signature and input SHA held, and CV was
never computed. The training corpus used the shipping script's
create/lookup/rename/delete/walk workload families at fixture-scaled counts,
so this is not a claim of byte identity with an older opaque profile.

The exact staged-source replay after lint cleanup rebuilt v3+PGO ELF
`1cf9b1dc5c162760787fb3fe003fbcbcccf132c4a1f753376996ac871c5275af`,
which consumed the same profile and preserved the same image SHA and output
signature. It independently measured **1.495236x**, CI
**[1.459215, 1.520699]**, versus its own **1.122973x** twice-null threshold;
A/A was **1.032385x**, CI **[1.008930, 1.059704]**. The two admissible
decisions remain separate rather than being pooled.

| Historical claim class | Corrected status |
| --- | --- |
| Wins vs kernel | Retained as generic-ELF history; neither direction nor magnitude transfers to the shipped binary without a workload-matched v3+PGO rerun. |
| Losses vs kernel | Retained as generic-ELF routing evidence, not an upper bound; the gap cannot justify “structural” or “irreducible” closure without a shipped-binary rerun. |
| Internal source-lever A/B ratios | Retained as historical same-build, generic-ELF measurements because both arms used one ELF. Fresh v3 reruns replace the owned allocator and JBD2 publication numbers above and demonstrate that magnitudes can move in either direction. |
| Absolute throughput and latency | Production-shaped only for the named 8,003-entry lookup corpus above. Every other workload still requires its own exact v3+PGO rerun. |
| Proposed blanket adjustment | Forbidden. ISA and PGO sensitivity is workload-specific: the two ISA-only source ratios moved by -0.95% and +9.53%, while the named whole-CLI lookup moved by 1.437700x under v3+PGO. |

Concrete retry predicate: for a v3 run through RCH, forward `RUSTFLAGS` through
the explicit environment allowlist and require remote rustc plus the executing
binary to report AVX2+FMA; a distinct ELF alone is insufficient. For exact
production attribution, build the benchmark with the complete shipped v3+PGO
configuration, self-report the executing ELF and consumed profile SHA, prove
exact output/fsck parity, then run same-invocation paired A/A and A/B and gate
only on the median-ratio 95% CI outside twice the null margin. Do not infer PGO
identity from v3 alone or transfer the lookup result to a kernel comparator.
See `docs/BD_B9DUG_ISA_CORRECTION.md` for the full claim inventory and
admissibility rule.

- **Comparator:** the mounted kernel filesystem (ext4/btrfs).
- **Methodology:** negative-evidence-ledger-first; profile-first (mechanism from
  the profile / code, not a guess); ONE lever per commit; behaviour parity proven
  byte-identical before keeping; honest same-worker A/B interleaved in ONE binary;
  gate on the **median-ratio 95% CI** vs a paired null control (identical arm
  twice); CV is provenance and never a decision gate.
- **Historical build:** STRICTLY remote-only, but generic x86-64 rather than the
  shipped v3+PGO configuration —
  `RCH_REQUIRE_REMOTE=1 env -u CARGO_TARGET_DIR rch exec -- cargo bench`. rch
  degraded / no slot = SURFACE, never local cargo.
- **Reusable lever models** (how each class of win was found/judged) are
  distilled in the agent memory files `blackthrush_lever_models.md` and
  `blackthrush_campaign_state.md`.

---

## Shipped wins by axis

### Checksum / CRC (the deepest vein)
| Commit | Lever | Ratio | Mechanism |
| --- | --- | --- | --- |
| ff222d17 | incremental crc32c primitive | 11.6x | roll a delta into an existing crc instead of re-CRC-ing the whole block |
| ed0b409d | HW-crc32c the delta CRC | 3.86x @128B | replace the software delta CRC inner step with the crc32c instruction |
| ac18ce8b | constant-time GF(2) suffix shift | 2.01x | base-256 branchless shift in the incremental primitive |
| 17380f69 | branchless `gf2_matrix_times` | — | table-driven, OnceLock-cached matrices |
| 56cb5f94 / 4976d6d7 / c9e12ff4 / 43b967e6 | incremental dir-block csum + wirings | 10.3x / 14.4x/stamp | stamp the dir-block csum incrementally on edit sites |
| 253f2862 | zero-run-aware full dir-block CRC | 3.92x | skip the zero tail algebraically (32-wide) |
| 8221c6f4 | zero-run-aware bitmap CRC | 2.54x @25%-full | " |
| e4d192e4 | zero-run-aware extent-node CRC | 3.52x | " |
| 041f04f4 | zero-run-aware superblock CRC | 1.12x | completes the vein |
| a5a97e12 | **AXIS CLOSE** (this session) | — | verify segmented, write-side stamp no-copy (single-pass zero-in-place); crc32c HW; csum_seed cached at open |

### Compression (codec context reuse)
| Commit | Lever | Ratio | Mechanism |
| --- | --- | --- | --- |
| 32a86235 | btrfs zlib inflate context reuse | 1.43x | thread-local `flate2::Decompress`, reset+`decompress_vec` (byte-identical) — avoids the 32 KiB inflate-window alloc per call |
| 85f0ccea | e2compr gzip inflate reuse | 2.21x @4KiB | shares the same reusable inflate context |
| a1e666c0 | e2compr gzip **deflate** (write) reuse | 1.44x | level-keyed thread-local `flate2::Compress`, byte-identical output |

### Read / extent / IO
| Commit | Lever | Ratio | Mechanism |
| --- | --- | --- | --- |
| 23986087 | extent-cache depth-1 borrow-in-place | — | borrow the cached leaf instead of `Vec` take/store per block |
| 751251da / 8334e658 | sequential resolve hint (read + readdir plan) | 2.0–2.5x | carry last-hit extent index; O(1) common case, binary-search fallback |
| 31c57895 | arc_swap Guard-hold + borrow, ext4 hot-inode/hot-parent | ~1.24x lookup | drop the per-hit `Arc::clone` |
| 0218b2d8 | same, btrfs hot-inode-extents slot | — | " |
| 9bf25f7f / 6da40713 | ext4 depth>0 child-extent-block cache / extent-parse hoist | — | cache the child block across per-block accesses |
| f2ca5cf4 / ee8d5208 | skip redundant readdir prefetch / bound readdirplus getattr fan-out | ~2.8x | avoid redundant work + cap the fan-out |
| 7a6091a2 | bound ext4 data-read fan-out to a dedicated 16-wide pool (bd-ddryj) | — | see cold-read note below |

### Metadata / dir / parse
| Commit | Lever | Ratio | Mechanism |
| --- | --- | --- | --- |
| 8314ca8c | skeletal `AttrOnly` inode parse for getattr | 1.11x | skip the 60 B extent copy for non-device inodes |
| bc47b311 | `MetadataOnly` parse for name-index validation stamp | 1.24x | skip the ibody xattr copy where the caller never re-serializes |
| a4ba9241 | `sort_unstable` for all 3 htree hash sorts | 1.47x | in-place sort on an order-irrelevant hash key |
| 2ad5ec95 / a092e533 / 317b8fbe | SWAR word-at-a-time name compare (lookup / dup-scan / overlapping-tail) | 1.80x / 1.43x | word compare + overlapping-final-word tail |
| 3dcf558f | SWAR ASCII case-fold compare (casefold dirs) | 1.64x | branchless `swar_ascii_to_lower` + word compare, len-gated vs stdlib AVX |
| 2a380996 / e7b665bf / d3b20f15 / 6909f9a0 | has-zero SWAR family (path validate / name validate / first-NUL symlink) | 3.1–4.0x | `haszero` bool-search + position-search |
| 96c27663 | word-at-a-time hash for `extent_root_namespace` | 7.14x | mix 8 bytes/iter (in-memory cache key only) |
| d0d04046 | skip extent-tree parse for depth-0 inline files in meta-block count | ~20x | read `eh_depth` before the parse |
| b83531ef / 61254de6 / ab0d6cae / fa6ba46a | read_fixed / array-REF bounds-hoist (extent parse / serialize / write_entry / dir-header read) | 1.066–1.13x (~1.07x read) | one reslice-to-`&[u8;N]`, no copy — wins across an opaque length guard |

---

## Consolidated rejects — ID · null-control result · retry-condition

Every reject carries non-zero self-time proving the fn ran (ledger-integrity
rule). "Retry-condition" = the specific fact that would have to change for the
lever to become worth revisiting; until then, **do not re-attempt.**

### Metadata / read design turns
| ID | Rejected lever | Measured result (median, null-controlled) | Retry-condition |
| --- | --- | --- | --- |
| 22387e32 / 66402846 / d4e8a94c | `Arc<InodeAttr>` (whole-workspace trait change) | ~10% REGRESSION both fs (130 B POD memcpy < 2 atomic RMW + miss alloc) | InodeAttr grows large enough that memcpy cost > Arc refcount, OR the attr becomes genuinely shared across many readers per lookup |
| 19a20908 | InodeAttr SystemTime→raw time-compaction | ~1.02x NEUTRAL (Duration::new fast-paths nsec<1e9; construction is free) | a non-fast-path timestamp representation makes SystemTime construction actually cost cycles |
| 2e1fce5f | bloom-filter `dir_name_index` negative-lookup pre-filter | NEUTRAL ~1.03–1.06x (HashSet neg-probe already 1 cache line) | the baseline gains MANY cache-missing accesses per op (it does not — all paths are O(1)/O(log N)/seq-cached) |
| 606babe5 / bab1deea | inline present-index keys / MVCC version-chain inline SmallVec | cache-miss-bound / 3x SLOWER on reads (density collapse) | version-chain density stops collapsing under inlining (peer-owned) |
| a1bab91e | `locate_inode` div→shift strength-reduction | 1.00x NEUTRAL (DIV throughput hidden by loop ILP) | locate_inode becomes a hot standalone loop where the DIV latency is exposed |
| bd-cc-interp-search | interpolation search on extent mapping resolution (algorithmic, O(log log E)) | 3.46–6.6x FASTER on synthetic-uniform E≥4096 but **2.4–2.9x SLOWER** on realistic non-uniform (skewed) extents; production leaf ≤340 = L1-resident (per-probe DIVIDE loses to comparisons) | a non-peer hot path searches a genuinely LARGE (E≥~2000, cache-miss-bound) NEAR-UNIFORM sorted array — ext4's ≤340-per-leaf extent structure cannot produce it |
| f31ae693 | `parse_dir_block` `Vec::with_capacity` | below-noise (malloc-bound, the outer realloc is not the cost) | the per-entry `name` alloc is eliminated first, exposing the outer realloc (= the SmallVec task) |

### Write-path / alloc
| ID | Rejected lever | Measured result | Retry-condition |
| --- | --- | --- | --- |
| 33c51394 / 44ad26b2 | `write_block_owned` move-not-copy (both block adapters) | e2e-NEUTRAL (~10% bench noise; 4 KiB copy ≈130 cyc vs the per-write commit ≈thousands) | the write path stops being commit-dominated (peer MVCC commit gets much cheaper) |
| 189493e9 | alloc-refresh @40k blocks | REFUTED (surface) | — (alloc is the peer lane) |
| 174adddb / 5829c6f5 / 80706777 | btrfs staged-internal in-place / leaf-Vec pooling / merge_adjacent targeted-copy | NEUTRAL (count ≠ cost; merges rare) | peer-owned; revisit only under peer coordination |
| 7e401d18 | staged-writes BTreeMap → SmallVec | REFUTED (BTreeMap is the right structure) | never (structural) |

### Checksum
| ID | Rejected lever | Measured result | Retry-condition |
| --- | --- | --- | --- |
| bd-cc-inode-csum-stamp (a5a97e12) | inode-csum stamp copy→segment | NO LEVER — stamp already no-copy (single-pass zero-in-place) | never (already optimal) |
| 5998f96c / 183f7c38 | `csum_seed` recompute caching | parity-tail (~0.1% e2e; once/op, not per-block; usually gated off) | csum_seed moves into a per-block hot loop |
| b80079c9 | incremental dir_csum (alternative form) | proven correct but 10x SLOWER than HW re-crc | never (HW crc32c wins) |

### Compression
| ID | Rejected lever | Measured result | Retry-condition |
| --- | --- | --- | --- |
| bd-cc-lzo (a18705f5) | btrfs LZO per-segment scratch reuse | 1.003x, 7 ns/seg — within the 1.0705x null floor (decode-dominated) | the LZO1X decode itself gets much cheaper, raising the alloc fraction |

### Bounds-hoist / SWAR that self-elided (measure-don't-reason kills)
| ID | Rejected lever | Measured result | Retry-condition |
| --- | --- | --- | --- |
| 07427aeb | `walk_dir_block_entries` array-ref | NEUTRAL (guard is directly on `block.len()` → per-field checks self-elide) | never (guard shape self-elides) |
| 8d143aac | `half_md4_transform` array-ref | NEUTRAL (inlines where len==8 is provable) | never |
| 3c331d62 | `str2hashbuf` bulk-pack | NEUTRAL (dx_hash is half-MD4 transform-bound) | never |
| 593a93c5 / 4fcf675f | inode-parse base array-ref + read_inode→metadata sweep | NEUTRAL / exhausted (const offsets under direct `len>=128` self-elide) | never |
| 12e7d220 / 2a3f8e2a / 8a8abd16 | scrub word→SIMD 64-B fold / xor_into byte→word | NEUTRAL (word-at-a-time already at floor; opt-level artifacts) | never |
| b682b389 | post-SWAR create-scan bounds-elision + alloc-elision | 2× measured-negative (at floor) | never |

### Cold-read (honest re-derivation, not a lever)
`bd-q6k00 / bd-5koeh / bd-ddryj / bd-zvn7r / bd-kdmu4`: the cold-read "gap" was
re-established honestly — loop-device serialization is a buffered-mode artifact,
~41% of the best-config gap is benchmark-harness overhead, and the residual is
kernel page-cache `xa_lock` contention from a shared `Arc<File>` (a shared-fd
readahead artifact), not readahead/extents/copy. O_DIRECT buys 0% wall
(**bd-kdmu4**, owner-gated). See `frankenfs-cold-read-honest-numbers`.

### Peer-lane rejects (recorded, not solo-actionable)
`3f02807f` nested Bw-tree message Arc · `de10e53c` fast-commit extent hint (dead
on the writable path; E1 regresses) · `9d0bf701` s3 fast TLS slab · `90d1d8df`
fuse backpressure table · `329185dc` btrfs inode-item append encoder · `276655a1`
btrfs writeback dense-visited · `8298d563` alloc_extent max-fusion (1.14x SLOWER,
opt-3 vectorization) · `2d831a9f` btrfs_canonical_inode inline · `37b4e263 /
df5cd51a / d77d35b2` btrfs arc_swap dir-entry hot-slot / staged update / outer
alloc read-lock. Retry only under coordination with the owning peer
(btrfs=bd-xmh5g, mvcc/alloc=cod/SilverPine).

---

## Remaining headroom (NOT a solo single-turn micro-lever)
1. **Peer-owned** — MVCC commit is THE write bottleneck; ffs-alloc is the
   most-recently-active peer lane; btrfs.rs (bd-xmh5g). Coordinate, don't collide.
2. **bd-bhh0i** parallel-create alloc_mutex shard — a loom+e2fsck-gated multi-turn
   concurrency refactor (owner decision; see `docs/bd-bhh0i-parallel-create-plan.md`).
3. **Returnable-binary structural unblock** — fixing rch artifact retrieval (it
   uses its own remote target dir → metadata-only retrieval) reopens the
   block-copy read path and enables the v3+PGO production numbers (bd-b9dug).
4. **Scoped design task** — `Ext4DirEntry::name` → SmallVec kills the readdir
   per-entry alloc (`read_dir_with_scope`, `crates/ffs-core/src/lib.rs:12985`);
   broad public-type surface, marginal given jemalloc small-alloc (refuted 5×).

**HOLD.** No honest single-turn measured solo win remains. Await an owner
decision on (1)–(4).
