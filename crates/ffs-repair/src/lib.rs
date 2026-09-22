#![forbid(unsafe_code)]
//! RaptorQ self-healing and scrub.
//!
//! Generates fountain-coded repair symbols (RFC 6330) per block group,
//! detects corruption via checksum mismatch (crc32c or BLAKE3), recovers
//! corrupted blocks from repair symbols, and runs background scrub passes.

pub mod autopilot;
pub mod codec;
pub mod decision;
pub mod demo;
pub mod evidence;
pub mod exchange;
pub mod lrc;
pub mod ownership;
pub mod pipeline;
pub mod por;
pub mod recovery;
pub mod scrub;
pub mod sidecar;
pub mod sidecar_restore;
pub mod storage;
pub mod symbol;
