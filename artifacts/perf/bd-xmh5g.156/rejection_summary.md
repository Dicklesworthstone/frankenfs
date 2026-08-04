# bd-xmh5g.156 Rejection Summary

Target: `ffs-repair` `lrc_encode_global_64blocks_8parity`

Lever: widen the existing adjacent pair GF(256) projection in `encode_global`
to a four-source fused projection while preserving the parity-major Rayon row
layout.

Decision: rejected, no runtime code kept.

## Benchmarks

- Initial focused baseline: RCH remote `ovh-a`
  `[702.23 us, 786.07 us, 862.41 us]`.
- Comparable clean old-code baseline: RCH remote `vmi1227854`
  `[253.42 us, 275.59 us, 305.81 us]`.
- Candidate rebench: RCH remote `vmi1227854`
  `[264.17 us, 280.52 us, 295.66 us]`.

Midpoint speedup was `0.982x`; conservative lower/upper was `0.857x`.
Score: `0.0`, because measured impact was negative/noisy.

## Isomorphism

- Ordering preserved: yes for the candidate; parity rows remained `j=0..p-1`
  and source blocks contributed in increasing source order.
- Tie-breaking unchanged: N/A for encode-only parity generation.
- Floating-point identical: N/A.
- RNG seeds unchanged: N/A.
- Goldens verified: RCH remote `vmi1227854` LRC lib-filter test passed 50
  tests; marker-bounded LRC golden stdout SHA256
  `84e1fd0632220fbbba4154b19448e06ade4c648c724171b5e41c131242a2df8b`.

Shipped-state isomorphism is exact: `crates/ffs-repair/src/lrc.rs` was restored
to the pre-lever source before closeout.
