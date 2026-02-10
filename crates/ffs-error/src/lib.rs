#![forbid(unsafe_code)]
//! Error types for FrankenFS.
//!
//! # Error Taxonomy
//!
//! FrankenFS uses a two-layer error model:
//!
//! | Layer | Type | Crate | Purpose |
//! |-------|------|-------|---------|
//! | Parsing | `ParseError` | `ffs-types` | On-disk format violations detected during byte parsing |
//! | Runtime | `FfsError` | `ffs-error` (this crate) | User-facing errors for FUSE, CLI, and API consumers |
//!
//! ## Mapping Policy: ParseError → FfsError
//!
//! `ffs-error` is intentionally independent of `ffs-types` and `ffs-ondisk` to
//! avoid cyclic dependencies. The conversion from `ParseError` to `FfsError` is
//! implemented in `ffs-core`, which depends on both crates.
//!
//! The mapping rules are:
//!
//! | ParseError Variant | FfsError Variant | Rationale |
//! |--------------------|------------------|-----------|
//! | `InsufficientData` | `Corruption { block, detail }` | Truncated metadata indicates corruption or a truncated image |
//! | `InvalidMagic` | `Format(detail)` | Wrong magic means wrong filesystem type, not corruption |
//! | `InvalidField` | `Format(detail)` | Structurally invalid field values are format violations |
//! | `IntegerConversion` | `Corruption { block, detail }` | Arithmetic overflow in parsed values suggests corruption |
//!
//! When a `ParseError` occurs during mount-time validation (before the
//! filesystem is live), prefer `FfsError::Format` with a descriptive message.
//! When it occurs while reading live metadata (e.g., reading an inode from a
//! mounted image), prefer `FfsError::Corruption` with the block number for
//! repair triage.
//!
//! ## Mount-Validation Errors
//!
//! Mount-time validation (`validate_v1()` in ffs-ondisk) can fail for three
//! distinct reasons, each with its own FfsError variant:
//!
//! | Failure | FfsError Variant | errno | Example |
//! |---------|------------------|-------|---------|
//! | Feature not supported by this build | `UnsupportedFeature` | `EOPNOTSUPP` | ENCRYPT, INLINE_DATA |
//! | Block size or geometry out of range | `InvalidGeometry` | `EINVAL` | 64K blocks, zero blocks_per_group |
//! | Structurally invalid format | `Format` | `EINVAL` | Bad magic, unknown revision |
//!
//! The `ffs-core` mount path converts `ParseError::InvalidField` from
//! `validate_v1()` into the appropriate variant by inspecting the field
//! name and reason. The parsing layer (`ffs-ondisk`) does not need to know
//! about `FfsError` — it returns `ParseError` and the boundary conversion
//! adds the mount-validation context.
//!
//! ## FUSE errno Mapping
//!
//! Every `FfsError` variant maps to exactly one POSIX errno via [`FfsError::to_errno`].
//! The mapping is exhaustive (no wildcard arms) so adding a new variant is a
//! compile error until its errno is assigned.
//!
//! | Variant | errno | Constant |
//! |---------|-------|----------|
//! | `Io` | `EIO` | 5 |
//! | `Corruption` | `EIO` | 5 |
//! | `Format` | `EINVAL` | 22 |
//! | `Parse` | `EINVAL` | 22 |
//! | `UnsupportedFeature` | `EOPNOTSUPP` | 95 |
//! | `InvalidGeometry` | `EINVAL` | 22 |
//! | `MvccConflict` | `EAGAIN` | 11 |
//! | `Cancelled` | `EINTR` | 4 |
//! | `NoSpace` | `ENOSPC` | 28 |
//! | `NotFound` | `ENOENT` | 2 |
//! | `PermissionDenied` | `EACCES` | 13 |
//! | `ReadOnly` | `EROFS` | 30 |
//! | `NotDirectory` | `ENOTDIR` | 20 |
//! | `IsDirectory` | `EISDIR` | 21 |
//! | `NotEmpty` | `ENOTEMPTY` | 39 |
//! | `NameTooLong` | `ENAMETOOLONG` | 36 |
//! | `Exists` | `EEXIST` | 17 |
//! | `RepairFailed` | `EIO` | 5 |
//!
//! ## Design Constraints
//!
//! - `ffs-error` MUST NOT depend on `ffs-types` or `ffs-ondisk` (no cyclic deps).
//! - `FfsError` is the single user-facing error type; crate-internal errors
//!   (like `ParseError`, `CommitError`) convert into `FfsError` at their
//!   respective crate boundaries.
//! - All string payloads in `FfsError` are owned (`String`) to avoid lifetime
//!   entanglement across async boundaries.

use thiserror::Error;

/// Unified error type for all FrankenFS operations.
///
/// This is the canonical error type returned by FUSE handlers, CLI commands,
/// and public API surfaces. Internal crate-specific errors (e.g., `ParseError`
/// from `ffs-types`) are converted into `FfsError` at crate boundaries.
#[derive(Debug, Error)]
pub enum FfsError {
    /// Operating system I/O error (wraps `std::io::Error`).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// On-disk metadata corruption detected at a known block.
    ///
    /// Used when live metadata reads produce invalid data (checksum mismatch,
    /// truncated structures, out-of-range field values). The `block` field
    /// enables repair triage.
    #[error("corrupt metadata at block {block}: {detail}")]
    Corruption { block: u64, detail: String },

    /// Invalid on-disk format (wrong filesystem type, unsupported features).
    ///
    /// Used during mount-time validation when the image structure is
    /// fundamentally wrong (bad magic, unsupported format version).
    #[error("invalid on-disk format: {0}")]
    Format(String),

    /// Parse-layer error surfaced to the user.
    ///
    /// This variant carries the string representation of a `ParseError` from
    /// `ffs-types`. It exists so that higher-level code can convert parse
    /// failures without losing diagnostic detail. Prefer `Corruption` or
    /// `Format` when the block number or mount-validation context is known.
    #[error("parse error: {0}")]
    Parse(String),

    /// The filesystem image uses a feature that this build does not support.
    ///
    /// Used during mount-time validation when incompatible feature flags are
    /// set (e.g., ENCRYPT, INLINE_DATA). Maps to `EOPNOTSUPP` to distinguish
    /// "we don't support this yet" from "this image is broken."
    #[error("unsupported feature: {0}")]
    UnsupportedFeature(String),

    /// On-disk geometry is invalid or out of the supported range.
    ///
    /// Used during mount-time validation for block sizes, blocks_per_group,
    /// inodes_per_group, or other structural parameters that are numerically
    /// invalid or outside what FrankenFS supports.
    #[error("invalid geometry: {0}")]
    InvalidGeometry(String),

    /// MVCC serialization conflict.
    #[error("MVCC conflict: transaction {tx} conflicts on block {block}")]
    MvccConflict { tx: u64, block: u64 },

    /// Operation cancelled via `Cx` budget exhaustion or explicit cancel.
    #[error("operation cancelled")]
    Cancelled,

    /// No free blocks or inodes available.
    #[error("no space left on device")]
    NoSpace,

    /// File, directory, or other named object not found.
    #[error("not found: {0}")]
    NotFound(String),

    /// Insufficient permissions for the requested operation.
    #[error("permission denied")]
    PermissionDenied,

    /// Filesystem is mounted read-only and a write was attempted.
    #[error("read-only filesystem")]
    ReadOnly,

    /// A path component is not a directory.
    #[error("not a directory")]
    NotDirectory,

    /// Attempted a file operation on a directory.
    #[error("is a directory")]
    IsDirectory,

    /// rmdir on a non-empty directory.
    #[error("directory not empty")]
    NotEmpty,

    /// Filename exceeds the filesystem's name length limit.
    #[error("name too long")]
    NameTooLong,

    /// Target already exists (create, mkdir, exclusive open).
    #[error("file exists")]
    Exists,

    /// RaptorQ repair or self-healing workflow could not recover data.
    #[error("repair failed: {0}")]
    RepairFailed(String),
}

impl FfsError {
    /// Convert this error into a POSIX errno suitable for FUSE replies.
    ///
    /// The mapping is exhaustive — every variant has an explicit arm. Adding a
    /// new variant without updating this function is a compile error.
    ///
    /// Policy notes:
    /// - `Cancelled` → `EINTR`: aligns with POSIX "interrupted system call"
    ///   semantics. FUSE callers may retry at a higher layer.
    /// - `Parse` → `EINVAL`: parse failures during mount are format errors;
    ///   during live operation they should be wrapped as `Corruption` instead.
    /// - `UnsupportedFeature` → `EOPNOTSUPP`: distinguishes "not implemented"
    ///   from "structurally invalid."
    /// - `InvalidGeometry` → `EINVAL`: bad on-disk parameters.
    /// - `ReadOnly` → `EROFS`: standard read-only filesystem errno.
    #[must_use]
    pub fn to_errno(&self) -> libc::c_int {
        match self {
            Self::Io(err) => err.raw_os_error().unwrap_or(libc::EIO),
            Self::Corruption { .. } | Self::RepairFailed(_) => libc::EIO,
            Self::Format(_) | Self::Parse(_) | Self::InvalidGeometry(_) => libc::EINVAL,
            Self::UnsupportedFeature(_) => libc::EOPNOTSUPP,
            Self::MvccConflict { .. } => libc::EAGAIN,
            Self::Cancelled => libc::EINTR,
            Self::NoSpace => libc::ENOSPC,
            Self::NotFound(_) => libc::ENOENT,
            Self::PermissionDenied => libc::EACCES,
            Self::ReadOnly => libc::EROFS,
            Self::NotDirectory => libc::ENOTDIR,
            Self::IsDirectory => libc::EISDIR,
            Self::NotEmpty => libc::ENOTEMPTY,
            Self::NameTooLong => libc::ENAMETOOLONG,
            Self::Exists => libc::EEXIST,
        }
    }
}

/// Result alias using `FfsError`.
pub type Result<T> = std::result::Result<T, FfsError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errno_mapping_covers_all_variants() {
        // Verify each variant produces the expected errno.
        let cases: Vec<(FfsError, libc::c_int)> = vec![
            (FfsError::Io(std::io::Error::other("test")), libc::EIO),
            (
                FfsError::Corruption {
                    block: 0,
                    detail: "test".into(),
                },
                libc::EIO,
            ),
            (FfsError::Format("test".into()), libc::EINVAL),
            (FfsError::Parse("test".into()), libc::EINVAL),
            (
                FfsError::UnsupportedFeature("ENCRYPT".into()),
                libc::EOPNOTSUPP,
            ),
            (
                FfsError::InvalidGeometry("block_size=0".into()),
                libc::EINVAL,
            ),
            (FfsError::MvccConflict { tx: 1, block: 2 }, libc::EAGAIN),
            (FfsError::Cancelled, libc::EINTR),
            (FfsError::NoSpace, libc::ENOSPC),
            (FfsError::NotFound("test".into()), libc::ENOENT),
            (FfsError::PermissionDenied, libc::EACCES),
            (FfsError::ReadOnly, libc::EROFS),
            (FfsError::NotDirectory, libc::ENOTDIR),
            (FfsError::IsDirectory, libc::EISDIR),
            (FfsError::NotEmpty, libc::ENOTEMPTY),
            (FfsError::NameTooLong, libc::ENAMETOOLONG),
            (FfsError::Exists, libc::EEXIST),
            (FfsError::RepairFailed("test".into()), libc::EIO),
        ];

        for (error, expected_errno) in &cases {
            assert_eq!(
                error.to_errno(),
                *expected_errno,
                "wrong errno for {error:?}",
            );
        }
    }

    #[test]
    fn io_error_preserves_raw_os_error() {
        let raw = std::io::Error::from_raw_os_error(libc::EPERM);
        let ffs = FfsError::Io(raw);
        assert_eq!(ffs.to_errno(), libc::EPERM);
    }

    #[test]
    fn display_formatting() {
        let err = FfsError::Corruption {
            block: 42,
            detail: "bad checksum".into(),
        };
        assert_eq!(
            err.to_string(),
            "corrupt metadata at block 42: bad checksum"
        );

        let parse = FfsError::Parse("insufficient data: need 4 bytes at offset 0, got 2".into());
        assert!(parse.to_string().contains("parse error:"));

        let ro = FfsError::ReadOnly;
        assert_eq!(ro.to_string(), "read-only filesystem");

        let unsup = FfsError::UnsupportedFeature("ENCRYPT".into());
        assert_eq!(unsup.to_string(), "unsupported feature: ENCRYPT");

        let geom = FfsError::InvalidGeometry("blocks_per_group=0".into());
        assert_eq!(geom.to_string(), "invalid geometry: blocks_per_group=0");
    }

    #[test]
    fn mount_validation_errnos_are_distinct() {
        // UnsupportedFeature should be EOPNOTSUPP, not EINVAL
        let unsup = FfsError::UnsupportedFeature("ENCRYPT".into());
        let geom = FfsError::InvalidGeometry("bad block size".into());
        let fmt = FfsError::Format("bad magic".into());

        assert_eq!(unsup.to_errno(), libc::EOPNOTSUPP);
        assert_eq!(geom.to_errno(), libc::EINVAL);
        assert_eq!(fmt.to_errno(), libc::EINVAL);

        // EOPNOTSUPP != EINVAL (verifying the distinction matters)
        assert_ne!(unsup.to_errno(), geom.to_errno());
    }
}
