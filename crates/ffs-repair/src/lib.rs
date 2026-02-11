#![forbid(unsafe_code)]
//! RaptorQ self-healing and scrub.
//!
//! Generates fountain-coded repair symbols (RFC 6330) per block group,
//! detects corruption via checksum mismatch (crc32c or BLAKE3), recovers
//! corrupted blocks from repair symbols, and runs background scrub passes.

pub mod scrub;
pub mod symbol;
