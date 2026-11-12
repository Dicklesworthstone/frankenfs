#![no_main]
//! Fuzz target for Ext4Extent::actual_len + is_unwritten split-bit
//! encoding (bd-p0jgk).
//!
//! Companion to bd-j0zo3 proptest layer (32 cases per relation).
//! This target lifts the split-bit algebra to libfuzzer scale (>1M
//! iterations/session) with corpus learning across the
//! EXT_INIT_MAX_LEN boundary, the all-ones case, and the smooth-vs-
//! overflow edge. For arbitrary u16 raw_len, asserts:
//!
//!   MR-1 — Determinism: actual_len(ext) called twice gives same.
//!   MR-2 — Bound: actual_len <= EXT_INIT_MAX_LEN for all u16.
//!   MR-3 — Boundary at EXT_INIT_MAX_LEN: written, actual_len == 0x8000.
//!   MR-4 — Written range (raw_len <= MAX): actual_len == raw_len,
//!          is_unwritten == false.
//!   MR-5 — Unwritten range (raw_len > MAX): actual_len ==
//!          raw_len - EXT_INIT_MAX_LEN, is_unwritten == true.
//!   MR-6 — Never panics: implicit — any panic crashes the fuzzer.
//!
//! The split-bit encoding is on the hot path for every extent walk
//! on every ext4 filesystem. A regression in any branch — e.g.,
//! swapping the if/else arms or off-by-oning the boundary check —
//! would silently mis-classify every unwritten extent (treating
//! reserved-but-not-yet-written blocks as if they contained data),
//! catastrophic for fsync and crash recovery. This target catches
//! such regressions as fuzzer failures rather than silent data
//! corruption.

use ffs_ondisk::{Ext4Extent, EXT_INIT_MAX_LEN};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    let raw_len = u16::from_le_bytes(data[0..2].try_into().unwrap());
    let ext = Ext4Extent {
        logical_block: 0,
        raw_len,
        physical_start: 0,
    };

    // MR-1 Determinism + MR-6 implicit no-panic.
    let len_a = ext.actual_len();
    let len_b = ext.actual_len();
    let unwritten_a = ext.is_unwritten();
    let unwritten_b = ext.is_unwritten();
    assert_eq!(len_a, len_b, "actual_len must be deterministic");
    assert_eq!(
        unwritten_a, unwritten_b,
        "is_unwritten must be deterministic"
    );

    // MR-2 Bound: actual_len <= EXT_INIT_MAX_LEN.
    assert!(
        len_a <= EXT_INIT_MAX_LEN,
        "actual_len {len_a:#x} for raw_len {raw_len:#x} must be <= EXT_INIT_MAX_LEN ({EXT_INIT_MAX_LEN:#x})"
    );

    // MR-3, MR-4, MR-5: branch on the boundary.
    if raw_len <= EXT_INIT_MAX_LEN {
        assert!(
            !unwritten_a,
            "raw_len {raw_len:#x} <= EXT_INIT_MAX_LEN must be written"
        );
        assert_eq!(
            len_a, raw_len,
            "written extent: actual_len must equal raw_len"
        );
        if raw_len == EXT_INIT_MAX_LEN {
            // MR-3 boundary pin.
            assert_eq!(
                len_a, EXT_INIT_MAX_LEN,
                "boundary at EXT_INIT_MAX_LEN must yield actual_len == 0x8000"
            );
        }
    } else {
        assert!(
            unwritten_a,
            "raw_len {raw_len:#x} > EXT_INIT_MAX_LEN must be unwritten"
        );
        assert_eq!(
            len_a,
            raw_len - EXT_INIT_MAX_LEN,
            "unwritten extent: actual_len must equal raw_len - EXT_INIT_MAX_LEN"
        );
    }
});
