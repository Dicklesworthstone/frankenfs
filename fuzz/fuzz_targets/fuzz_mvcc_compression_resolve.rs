//! Fuzz `ffs_mvcc::compression::resolve_data_with` against arbitrary
//! version chains.
//!
//! `resolve_data_with` walks backward through a chain of `VersionData`
//! entries (Full / Identical / Zstd / Brotli) and returns the resolved
//! bytes for the entry at `index`. Three concerns motivate fuzzing:
//!
//!   1. Malformed Zstd / Brotli streams must not panic — `decode_all`
//!      and the brotli decompressor should surface I/O errors as `None`.
//!   2. A run of `Identical` markers must always terminate at index 0,
//!      never loop forever, and never panic on an out-of-bounds index.
//!   3. Resolution must be deterministic: identical inputs always
//!      produce identical outputs (caches/race conditions could otherwise
//!      leak across calls).
//!
//! The target also opportunistically generates *valid* Zstd / Brotli
//! payloads via the round-trip path (`encode → decode`), so libFuzzer
//! steers coverage through the success branches as well as the error
//! ones.

#![no_main]

use ffs_mvcc::compression::{resolve_data_with, VersionData};
use libfuzzer_sys::fuzz_target;

const MAX_INPUT_BYTES: usize = 2_048;
const MAX_CHAIN: usize = 16;
const MAX_VARIANT_PAYLOAD: usize = 256;

struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        let b = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        b
    }

    fn next_bytes(&mut self, n: usize) -> Vec<u8> {
        let n = n.min(MAX_VARIANT_PAYLOAD);
        let end = self.pos.saturating_add(n).min(self.data.len());
        let v = self
            .data
            .get(self.pos..end)
            .map_or_else(Vec::new, <[u8]>::to_vec);
        self.pos = end;
        v
    }
}

fn build_chain(cursor: &mut ByteCursor<'_>) -> Vec<VersionData> {
    let raw_count = cursor.next_u8();
    // Always at least one entry so resolve(0) is well-defined.
    let count = 1 + (usize::from(raw_count) % MAX_CHAIN);
    let mut chain = Vec::with_capacity(count);

    for _ in 0..count {
        let kind = cursor.next_u8() % 6;
        let payload_len = usize::from(cursor.next_u8()) % (MAX_VARIANT_PAYLOAD + 1);
        let payload = cursor.next_bytes(payload_len);

        let variant = match kind {
            0 => VersionData::full(payload),
            // Identical at slot 0 is intentionally malformed and should
            // resolve to None. Later Identical entries must resolve exactly
            // like their predecessor, including when the predecessor is a
            // compressed version or another malformed marker.
            1 => VersionData::Identical,
            2 => VersionData::Zstd(payload), // arbitrary: likely malformed
            3 => VersionData::Brotli(payload), // arbitrary: likely malformed
            4 => {
                // Round-trip through real zstd encoder so we exercise the
                // happy path and stress decode_all on a valid stream.
                match zstd::encode_all(payload.as_slice(), 0) {
                    Ok(encoded) => VersionData::Zstd(encoded),
                    Err(_) => VersionData::full(payload),
                }
            }
            _ => {
                // Round-trip via brotli with a small window so the encoder
                // doesn't allocate the default 16 MiB ring per entry.
                let mut encoded = Vec::with_capacity(payload.len() + 16);
                let params = brotli::enc::BrotliEncoderParams {
                    quality: 0,
                    lgwin: 10, // 1 KiB window — bounded encoder memory.
                    ..brotli::enc::BrotliEncoderParams::default()
                };
                let mut input = payload.as_slice();
                let mut out = std::io::Cursor::new(&mut encoded);
                let _ = brotli::BrotliCompress(&mut input, &mut out, &params);
                VersionData::Brotli(encoded)
            }
        };
        chain.push(variant);
    }
    chain
}

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > MAX_INPUT_BYTES {
        return;
    }

    let mut cursor = ByteCursor::new(data);
    let chain = build_chain(&mut cursor);

    // Resolve every index. Capture results into Vecs (not refs) so the
    // borrow on `chain` is released before the second pass.
    let first: Vec<Option<Vec<u8>>> = (0..chain.len())
        .map(|i| resolve_data_with(&chain, i, |d| d).map(|cow| cow.into_owned()))
        .collect();

    // Determinism: a second pass against the same chain must agree
    // byte-for-byte with the first.
    let second: Vec<Option<Vec<u8>>> = (0..chain.len())
        .map(|i| resolve_data_with(&chain, i, |d| d).map(|cow| cow.into_owned()))
        .collect();
    assert_eq!(
        first, second,
        "resolve_data_with must be deterministic across calls on the same chain"
    );

    // Out-of-bounds index must always return None — never panic.
    let oob = chain.len();
    assert!(
        resolve_data_with(&chain, oob, |d| d).is_none(),
        "resolve_data_with(chain, len, _) must return None"
    );
    let very_oob = chain.len().saturating_add(1024);
    assert!(
        resolve_data_with(&chain, very_oob, |d| d).is_none(),
        "resolve_data_with must return None for indices past the end"
    );

    // Structural invariants for successful resolves.
    for (i, result) in first.iter().enumerate() {
        let kind = &chain[i];
        match (kind, result) {
            (VersionData::Full(bytes), Some(resolved)) => {
                assert_eq!(
                    resolved.as_slice(),
                    bytes.as_slice(),
                    "Full at index {i}: resolve must return the inline bytes"
                );
            }
            (VersionData::Identical, result) => {
                if i == 0 {
                    assert!(
                        result.is_none(),
                        "leading Identical at index 0 is malformed and must resolve to None"
                    );
                } else {
                    assert_eq!(
                        result,
                        &first[i - 1],
                        "Identical at index {i} must resolve exactly like its predecessor"
                    );
                }
            }
            (VersionData::Zstd(_) | VersionData::Brotli(_), _) => {
                // Decompression either succeeds (Some) or fails with None;
                // both are acceptable. The contract is "no panic".
            }
            _ => {}
        }
    }
});
