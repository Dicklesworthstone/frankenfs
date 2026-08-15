#![forbid(unsafe_code)]

//! Cross-crate `FfsError::to_errno` dispatch benchmark.
//!
//! The frozen mapper is the pre-split production implementation. The timed
//! catalog contains the direct filesystem variants used at FUSE reply sites;
//! the untimed parity catalog additionally covers raw OS errors and every
//! explicitly mapped stable `ErrorKind`.

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use ffs_error::FfsError;
use std::hint::black_box;
use std::io::ErrorKind;

// `match_same_arms` wants `InvalidFilename` folded into the
// `InvalidInput | InvalidData` arm. Deliberately not done (bd-3ao0l): this
// function is a FROZEN COPY of the pre-split production mapper and exists solely
// to be the A arm this benchmark diffs production against. Tidying its shape
// edits the reference, so the comparison would no longer be measuring what it
// claims to. The equivalent arm in the live mapper is fair game; this one is not.
#[allow(clippy::match_same_arms)]
#[inline(never)]
fn frozen_to_errno(error: &FfsError) -> libc::c_int {
    match error {
        FfsError::Io(error) => match error.raw_os_error() {
            Some(errno) if errno > 0 => errno,
            Some(_) => libc::EIO,
            None => match error.kind() {
                ErrorKind::NotFound => libc::ENOENT,
                ErrorKind::PermissionDenied => libc::EACCES,
                ErrorKind::AlreadyExists => libc::EEXIST,
                ErrorKind::WouldBlock => libc::EAGAIN,
                ErrorKind::NotADirectory => libc::ENOTDIR,
                ErrorKind::IsADirectory => libc::EISDIR,
                ErrorKind::DirectoryNotEmpty => libc::ENOTEMPTY,
                ErrorKind::ReadOnlyFilesystem => libc::EROFS,
                ErrorKind::StorageFull => libc::ENOSPC,
                ErrorKind::QuotaExceeded => libc::EDQUOT,
                ErrorKind::FileTooLarge => libc::EFBIG,
                ErrorKind::ResourceBusy => libc::EBUSY,
                ErrorKind::ExecutableFileBusy => libc::ETXTBSY,
                ErrorKind::Deadlock => libc::EDEADLK,
                ErrorKind::CrossesDevices => libc::EXDEV,
                ErrorKind::TooManyLinks => libc::EMLINK,
                ErrorKind::InvalidFilename => libc::EINVAL,
                ErrorKind::ArgumentListTooLong => libc::E2BIG,
                ErrorKind::NotSeekable => libc::ESPIPE,
                ErrorKind::HostUnreachable => libc::EHOSTUNREACH,
                ErrorKind::NetworkUnreachable => libc::ENETUNREACH,
                ErrorKind::NetworkDown => libc::ENETDOWN,
                ErrorKind::StaleNetworkFileHandle => libc::ESTALE,
                ErrorKind::OutOfMemory => libc::ENOMEM,
                ErrorKind::InvalidInput | ErrorKind::InvalidData => libc::EINVAL,
                ErrorKind::TimedOut => libc::ETIMEDOUT,
                ErrorKind::Interrupted => libc::EINTR,
                ErrorKind::WriteZero
                | ErrorKind::UnexpectedEof
                | ErrorKind::BrokenPipe
                | ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted
                | ErrorKind::NotConnected
                | ErrorKind::AddrInUse
                | ErrorKind::AddrNotAvailable
                | ErrorKind::ConnectionRefused
                | ErrorKind::Unsupported
                | _ => libc::EIO,
            },
        },
        FfsError::Corruption { .. } | FfsError::RepairFailed(_) => libc::EIO,
        FfsError::Format(_) | FfsError::Parse(_) | FfsError::InvalidGeometry(_) => libc::EINVAL,
        FfsError::UnsupportedFeature(_)
        | FfsError::IncompatibleFeature(_)
        | FfsError::UnsupportedBlockSize(_) => libc::EOPNOTSUPP,
        FfsError::MvccConflict { .. } => libc::EAGAIN,
        FfsError::Cancelled => libc::EINTR,
        FfsError::NoSpace => libc::ENOSPC,
        FfsError::NotFound(_) => libc::ENOENT,
        FfsError::PermissionDenied => libc::EACCES,
        FfsError::ReadOnly => libc::EROFS,
        FfsError::NotDirectory => libc::ENOTDIR,
        FfsError::IsDirectory => libc::EISDIR,
        FfsError::NotEmpty => libc::ENOTEMPTY,
        FfsError::NameTooLong => libc::ENAMETOOLONG,
        FfsError::Exists => libc::EEXIST,
        FfsError::ModeViolation(_) => libc::EPERM,
    }
}

fn direct_error_catalog() -> Vec<FfsError> {
    vec![
        FfsError::Corruption {
            block: 42,
            detail: "checksum".into(),
        },
        FfsError::Format("magic".into()),
        FfsError::Parse("short read".into()),
        FfsError::UnsupportedFeature("encrypt".into()),
        FfsError::IncompatibleFeature("missing extents".into()),
        FfsError::UnsupportedBlockSize("8192".into()),
        FfsError::InvalidGeometry("zero groups".into()),
        FfsError::MvccConflict { tx: 7, block: 9 },
        FfsError::Cancelled,
        FfsError::NoSpace,
        FfsError::NotFound("entry".into()),
        FfsError::PermissionDenied,
        FfsError::ReadOnly,
        FfsError::NotDirectory,
        FfsError::IsDirectory,
        FfsError::NotEmpty,
        FfsError::NameTooLong,
        FfsError::Exists,
        FfsError::RepairFailed("decode".into()),
        FfsError::ModeViolation("compat".into()),
    ]
}

fn io_error_catalog() -> Vec<FfsError> {
    let kinds = [
        ErrorKind::NotFound,
        ErrorKind::PermissionDenied,
        ErrorKind::AlreadyExists,
        ErrorKind::WouldBlock,
        ErrorKind::NotADirectory,
        ErrorKind::IsADirectory,
        ErrorKind::DirectoryNotEmpty,
        ErrorKind::ReadOnlyFilesystem,
        ErrorKind::StorageFull,
        ErrorKind::QuotaExceeded,
        ErrorKind::FileTooLarge,
        ErrorKind::ResourceBusy,
        ErrorKind::ExecutableFileBusy,
        ErrorKind::Deadlock,
        ErrorKind::CrossesDevices,
        ErrorKind::TooManyLinks,
        ErrorKind::InvalidFilename,
        ErrorKind::ArgumentListTooLong,
        ErrorKind::NotSeekable,
        ErrorKind::HostUnreachable,
        ErrorKind::NetworkUnreachable,
        ErrorKind::NetworkDown,
        ErrorKind::StaleNetworkFileHandle,
        ErrorKind::OutOfMemory,
        ErrorKind::InvalidInput,
        ErrorKind::InvalidData,
        ErrorKind::TimedOut,
        ErrorKind::Interrupted,
        ErrorKind::WriteZero,
        ErrorKind::UnexpectedEof,
        ErrorKind::BrokenPipe,
        ErrorKind::ConnectionReset,
        ErrorKind::ConnectionAborted,
        ErrorKind::NotConnected,
        ErrorKind::AddrInUse,
        ErrorKind::AddrNotAvailable,
        ErrorKind::ConnectionRefused,
        ErrorKind::Unsupported,
        ErrorKind::Other,
    ];
    let mut errors = vec![
        FfsError::Io(std::io::Error::from_raw_os_error(libc::EPERM)),
        FfsError::Io(std::io::Error::from_raw_os_error(0)),
        FfsError::Io(std::io::Error::from_raw_os_error(-1)),
    ];
    errors.extend(
        kinds
            .into_iter()
            .map(|kind| FfsError::Io(std::io::Error::new(kind, "benchmark"))),
    );
    errors
}

fn raw_errno_catalog() -> Vec<FfsError> {
    const ERRNOS: [libc::c_int; 16] = [
        libc::EPERM,
        libc::ENOENT,
        libc::EIO,
        libc::EAGAIN,
        libc::EACCES,
        libc::EEXIST,
        libc::ENOSPC,
        libc::EROFS,
        libc::ENOTDIR,
        libc::EISDIR,
        libc::ENOTEMPTY,
        libc::ENAMETOOLONG,
        libc::EOPNOTSUPP,
        libc::EINVAL,
        libc::ETIMEDOUT,
        libc::EINTR,
    ];

    (0..64)
        .map(|index| {
            FfsError::Io(std::io::Error::from_raw_os_error(
                ERRNOS[index % ERRNOS.len()],
            ))
        })
        .collect()
}

#[inline(never)]
fn frozen_catalog_digest(errors: &[FfsError]) -> i64 {
    errors.iter().fold(0_i64, |digest, error| {
        digest
            .wrapping_mul(131)
            .wrapping_add(i64::from(frozen_to_errno(error)))
    })
}

#[inline(never)]
fn production_catalog_digest(errors: &[FfsError]) -> i64 {
    errors.iter().fold(0_i64, |digest, error| {
        digest
            .wrapping_mul(131)
            .wrapping_add(i64::from(error.to_errno()))
    })
}

fn bench_errno_map(c: &mut Criterion) {
    let direct_errors = direct_error_catalog();
    let raw_errors = raw_errno_catalog();
    let mut parity_errors = direct_error_catalog();
    parity_errors.extend(io_error_catalog());
    for error in &parity_errors {
        assert_eq!(
            frozen_to_errno(error),
            error.to_errno(),
            "errno mapping changed for {error:?}"
        );
    }
    assert_eq!(
        frozen_catalog_digest(&direct_errors),
        production_catalog_digest(&direct_errors),
        "direct-variant digest changed"
    );
    assert_eq!(
        frozen_catalog_digest(&raw_errors),
        production_catalog_digest(&raw_errors),
        "raw-errno digest changed"
    );

    // Scoped so the group's significant `Drop` runs at `finish()` (bd-3ao0l).
    {
        let mut group = c.benchmark_group("errno_map_common_direct_variants");
        group.sample_size(10);
        group.throughput(Throughput::Elements(
            u64::try_from(direct_errors.len()).expect("catalog length fits u64"),
        ));
        group.bench_function("frozen_full_mapper_a", |b| {
            b.iter(|| black_box(frozen_catalog_digest(black_box(&direct_errors))));
        });
        group.bench_function("production", |b| {
            b.iter(|| black_box(production_catalog_digest(black_box(&direct_errors))));
        });
        group.bench_function("frozen_full_mapper_b", |b| {
            b.iter(|| black_box(frozen_catalog_digest(black_box(&direct_errors))));
        });
        group.finish();
    }

    let mut group = c.benchmark_group("errno_map_raw_os_errors_64");
    group.sample_size(10);
    group.throughput(Throughput::Elements(raw_errors.len() as u64));
    group.bench_function("frozen_full_mapper_a", |b| {
        b.iter(|| black_box(frozen_catalog_digest(black_box(&raw_errors))));
    });
    group.bench_function("production", |b| {
        b.iter(|| black_box(production_catalog_digest(black_box(&raw_errors))));
    });
    group.bench_function("frozen_full_mapper_b", |b| {
        b.iter(|| black_box(frozen_catalog_digest(black_box(&raw_errors))));
    });
    group.finish();
}

criterion_group!(benches, bench_errno_map);
criterion_main!(benches);
