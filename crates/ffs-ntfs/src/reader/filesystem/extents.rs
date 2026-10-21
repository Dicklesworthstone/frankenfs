//! Logical extent queries over already admitted, immutable NTFS streams.
//!
//! These operations inspect mappings, never payload bytes. In particular, a
//! sparse mapping inside a compression unit is not necessarily a logical hole.

use super::super::Storage;
use super::{Cx, FfsError, Result, SeekWhence, Stream, checkpoint, corrupt};
use ffs_core::FiemapExtent;
use ffs_ondisk::ntfs::NtfsRun;

// Linux UAPI flags. UNKNOWN is intentional for resident values: their native
// location is inside a fixup-protected MFT record, not a raw DATA mapping.
const LAST: u32 = 0x0001;
const UNKNOWN: u32 = 0x0002;
const NOT_ALIGNED: u32 = 0x0100;
const DATA_INLINE: u32 = 0x0200;
const UNWRITTEN: u32 = 0x0800;

fn errno(code: i32) -> FfsError {
    FfsError::Io(std::io::Error::from_raw_os_error(code))
}

fn validate_stream(stream: &Stream, cluster_bytes: u32) -> Result<()> {
    if !cluster_bytes.is_power_of_two() {
        return Err(corrupt(0, "invalid NTFS extent-query cluster size"));
    }
    if stream.initialized > stream.size {
        return Err(corrupt(0, "NTFS initialized length exceeds stream size"));
    }
    Ok(())
}

fn run_span(run: &NtfsRun, cluster_bytes: u32) -> Result<(u64, u64)> {
    if run.clusters == 0 {
        return Err(corrupt(0, "empty NTFS extent-query mapping"));
    }
    let cluster_bytes = u64::from(cluster_bytes);
    let start = run
        .vcn
        .checked_mul(cluster_bytes)
        .ok_or_else(|| corrupt(0, "NTFS logical extent start overflow"))?;
    let end = run
        .vcn
        .checked_add(run.clusters)
        .and_then(|vcn| vcn.checked_mul(cluster_bytes))
        .ok_or_else(|| corrupt(0, "NTFS logical extent end overflow"))?;
    Ok((start, end))
}

/// Find data or a hole without probing the corresponding physical allocation.
/// Bytes after ValidDataLength are known zeroes, even when allocated on disk.
/// Compressed/WOF streams retain a conservative dense initialized prefix;
/// interpreting their physical padding as holes would lose actual file data.
pub(super) fn seek(
    cx: &Cx,
    stream: &Stream,
    cluster_bytes: u32,
    offset: u64,
    whence: SeekWhence,
) -> Result<u64> {
    checkpoint(cx)?;
    let want_data = match whence {
        SeekWhence::Data => true,
        SeekWhence::Hole => false,
        _ => return Err(errno(libc::EINVAL)),
    };
    validate_stream(stream, cluster_bytes)?;
    if offset >= stream.size {
        return Err(errno(libc::ENXIO));
    }
    let result = if offset >= stream.initialized {
        if want_data {
            Err(errno(libc::ENXIO))
        } else {
            Ok(offset)
        }
    } else if let Storage::Mapped(runs) = &stream.storage {
        seek_mapped(
            cx,
            runs,
            cluster_bytes,
            stream.initialized,
            offset,
            want_data,
        )
    } else if want_data {
        Ok(offset)
    } else {
        Ok(stream.initialized)
    };
    checkpoint(cx)?;
    result
}

fn seek_mapped(
    cx: &Cx,
    runs: &[NtfsRun],
    cluster_bytes: u32,
    initialized: u64,
    offset: u64,
    want_data: bool,
) -> Result<u64> {
    let vcn = offset / u64::from(cluster_bytes);
    let first = runs
        .partition_point(|run| run.vcn <= vcn)
        .checked_sub(1)
        .ok_or_else(|| corrupt(offset, "missing NTFS mapping before seek"))?;
    let mut position = offset;
    for (index, run) in runs[first..].iter().enumerate() {
        checkpoint(cx)?;
        let (start, end) = run_span(run, cluster_bytes)?;
        if start > position || end <= position || (index != 0 && start != position) {
            return Err(corrupt(position, "gap or overlap in NTFS seek mapping"));
        }
        if run.lcn.is_some() == want_data {
            return Ok(position);
        }
        position = end.min(initialized);
        if position == initialized {
            return if want_data {
                Err(errno(libc::ENXIO))
            } else {
                Ok(initialized)
            };
        }
    }
    Err(corrupt(
        position,
        "NTFS seek mapping ends before initialized data",
    ))
}

/// Report native allocation, not the contents of physical zero-filled blocks.
/// Physical offsets are relative to the selected NTFS volume, not its container.
/// Like native FIEMAP, a returned extent may extend outside the requested range;
/// allocation past EOF is visible as UNWRITTEN, never as initialized file data.
pub(super) fn fiemap(
    cx: &Cx,
    stream: &Stream,
    cluster_bytes: u32,
    start: u64,
    length: u64,
) -> Result<Vec<FiemapExtent>> {
    checkpoint(cx)?;
    validate_stream(stream, cluster_bytes)?;
    let end = start.saturating_add(length);
    if start == end {
        return Ok(Vec::new());
    }
    let query = (start, end);
    let mut result = Vec::new();
    match &stream.storage {
        Storage::Resident(_) => {
            emit_extent(
                &mut result,
                query,
                cluster_bytes,
                FiemapExtent {
                    logical: 0,
                    physical: 0,
                    length: stream.size,
                    flags: LAST | UNKNOWN | DATA_INLINE | NOT_ALIGNED,
                },
            )?;
        }
        Storage::Mapped(runs) => {
            let mut coverage = 0;
            let mut last_allocated_end = None;
            for run in runs {
                checkpoint(cx)?;
                let (logical, limit) = run_span(run, cluster_bytes)?;
                if logical != coverage {
                    return Err(corrupt(logical, "gap or overlap in NTFS FIEMAP mapping"));
                }
                coverage = limit;
                let Some(lcn) = run.lcn else {
                    continue;
                };
                let cluster_size = u64::from(cluster_bytes);
                let physical = lcn
                    .checked_mul(cluster_size)
                    .ok_or_else(|| corrupt(logical, "NTFS physical extent start overflow"))?;
                // Validate the whole physical run even for a narrow query.
                lcn.checked_add(run.clusters)
                    .and_then(|end| end.checked_mul(cluster_size))
                    .ok_or_else(|| corrupt(logical, "NTFS physical extent end overflow"))?;
                last_allocated_end = Some(limit);
                let initialized_end = stream.initialized.clamp(logical, limit);
                emit_extent(
                    &mut result,
                    query,
                    cluster_bytes,
                    FiemapExtent {
                        logical,
                        physical,
                        length: initialized_end - logical,
                        flags: 0,
                    },
                )?;
                emit_extent(
                    &mut result,
                    query,
                    cluster_bytes,
                    FiemapExtent {
                        logical: initialized_end,
                        physical: physical + (initialized_end - logical),
                        length: limit - initialized_end,
                        flags: UNWRITTEN,
                    },
                )?;
            }
            if coverage < stream.size {
                return Err(corrupt(coverage, "NTFS FIEMAP mapping ends before EOF"));
            }
            if let Some(last) = result.last_mut()
                && Some(last.logical + last.length) == last_allocated_end
            {
                last.flags |= LAST;
            }
        }
        Storage::Compressed(_) | Storage::Wof(_) => {
            return Err(super::unsupported(
                "FIEMAP for NTFS compressed/WOF streams requires an encoded extent mapping",
            ));
        }
    }
    checkpoint(cx)?;
    Ok(result)
}

fn emit_extent(
    result: &mut Vec<FiemapExtent>,
    query: (u64, u64),
    cluster_bytes: u32,
    mut extent: FiemapExtent,
) -> Result<()> {
    let end = extent
        .logical
        .checked_add(extent.length)
        .ok_or_else(|| corrupt(extent.logical, "NTFS FIEMAP extent end overflow"))?;
    if extent.length == 0 || extent.logical >= query.1 || end <= query.0 {
        return Ok(());
    }
    let cluster_bytes = u64::from(cluster_bytes);
    if !extent.logical.is_multiple_of(cluster_bytes)
        || !extent.physical.is_multiple_of(cluster_bytes)
        || !extent.length.is_multiple_of(cluster_bytes)
    {
        extent.flags |= NOT_ALIGNED;
    }
    result
        .try_reserve(1)
        .map_err(|error| FfsError::Io(std::io::Error::other(error)))?;
    result.push(extent);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapped(runs: Vec<NtfsRun>, size: u64, initialized: u64) -> Stream {
        Stream {
            storage: Storage::Mapped(runs),
            size,
            initialized,
            allocated: 0,
        }
    }

    fn run(vcn: u64, clusters: u64, lcn: Option<u64>) -> NtfsRun {
        NtfsRun { vcn, clusters, lcn }
    }

    fn assert_errno<T: std::fmt::Debug>(result: Result<T>, expected: i32) {
        let error = result.expect_err("operation must fail");
        match error {
            FfsError::Io(error) => assert_eq!(error.raw_os_error(), Some(expected)),
            error => panic!("expected errno {expected}, got {error:?}"),
        }
    }

    #[test]
    fn sparse_seek_skips_holes_and_preserves_uninitialized_tail() {
        let cx = Cx::for_testing();
        let stream = mapped(
            vec![
                run(0, 2, None),
                run(2, 2, Some(80)),
                run(4, 1, None),
                run(5, 3, Some(32)),
            ],
            4096,
            3089,
        );
        for (offset, whence, expected) in [
            (0, SeekWhence::Data, 1024),
            (513, SeekWhence::Hole, 513),
            (1025, SeekWhence::Data, 1025),
            (1025, SeekWhence::Hole, 2048),
            (2048, SeekWhence::Data, 2560),
            (2560, SeekWhence::Hole, 3089),
            (3089, SeekWhence::Hole, 3089),
            (4095, SeekWhence::Hole, 4095),
        ] {
            assert_eq!(seek(&cx, &stream, 512, offset, whence).unwrap(), expected);
        }
        assert_errno(seek(&cx, &stream, 512, 3089, SeekWhence::Data), libc::ENXIO);
        for whence in [SeekWhence::Data, SeekWhence::Hole] {
            assert_errno(seek(&cx, &stream, 512, 4096, whence), libc::ENXIO);
            assert_errno(seek(&cx, &stream, 512, u64::MAX, whence), libc::ENXIO);
        }
    }

    #[test]
    fn resident_seek_and_invalid_whence_obey_errno_contract() {
        let cx = Cx::for_testing();
        let stream = Stream {
            storage: Storage::Resident(b"hello".to_vec()),
            size: 5,
            initialized: 5,
            allocated: 0,
        };
        assert_eq!(seek(&cx, &stream, 512, 2, SeekWhence::Data).unwrap(), 2);
        assert_eq!(seek(&cx, &stream, 512, 2, SeekWhence::Hole).unwrap(), 5);
        for whence in [SeekWhence::Set, SeekWhence::Cur, SeekWhence::End] {
            for offset in [0, 5, u64::MAX] {
                assert_errno(seek(&cx, &stream, 512, offset, whence), libc::EINVAL);
            }
        }
        let empty = mapped(Vec::new(), 0, 0);
        for whence in [SeekWhence::Data, SeekWhence::Hole] {
            assert_errno(seek(&cx, &empty, 512, 0, whence), libc::ENXIO);
        }
    }

    #[test]
    fn sparse_seek_rejects_broken_mapping_instead_of_inventing_holes() {
        let cx = Cx::for_testing();
        for runs in [
            vec![run(1, 1, Some(80))],
            vec![run(0, 1, Some(80)), run(2, 1, None)],
            vec![run(0, 2, Some(80)), run(1, 2, None)],
            vec![run(0, 0, Some(80))],
            vec![run(0, 1, Some(80))],
        ] {
            let stream = mapped(runs, 2048, 2048);
            assert!(matches!(
                seek(&cx, &stream, 512, 0, SeekWhence::Hole),
                Err(FfsError::Corruption { .. })
            ));
        }
        let invalid = mapped(vec![run(0, 1, Some(80))], 1, 2);
        assert!(matches!(
            seek(&cx, &invalid, 512, 0, SeekWhence::Data),
            Err(FfsError::Corruption { .. })
        ));
        let valid = mapped(vec![run(0, 1, Some(80))], 1, 1);
        for cluster_bytes in [0, 3] {
            assert!(matches!(
                seek(&cx, &valid, cluster_bytes, 0, SeekWhence::Data),
                Err(FfsError::Corruption { .. })
            ));
        }
        assert!(run_span(&run(u64::MAX, 1, Some(1)), 512).is_err());
        assert!(run_span(&run(0, u64::MAX, Some(1)), 512).is_err());
    }

    #[test]
    fn sparse_seek_matches_exhaustive_byte_occupancy_oracle() {
        let cx = Cx::for_testing();
        // Small synthetic clusters permit exhaustive coverage of every byte,
        // mapping mask and initialized boundary, including adjacent split runs.
        for mask in 0_u32..16 {
            for initialized in 0..=16 {
                let runs = (0_u64..4)
                    .map(|vcn| run(vcn, 1, (mask & (1 << vcn) != 0).then_some(80 - vcn)))
                    .collect();
                let stream = mapped(runs, 16, initialized);
                for offset in 0..16 {
                    let expected_data =
                        (offset..initialized).find(|byte| mask & (1 << (byte / 4)) != 0);
                    let expected_hole = (offset..16)
                        .find(|byte| *byte >= initialized || mask & (1 << (byte / 4)) == 0)
                        .unwrap_or(16);
                    match expected_data {
                        Some(expected) => assert_eq!(
                            seek(&cx, &stream, 4, offset, SeekWhence::Data).unwrap(),
                            expected,
                            "mask={mask}, initialized={initialized}, offset={offset}"
                        ),
                        None => assert_errno(
                            seek(&cx, &stream, 4, offset, SeekWhence::Data),
                            libc::ENXIO,
                        ),
                    }
                    assert_eq!(
                        seek(&cx, &stream, 4, offset, SeekWhence::Hole).unwrap(),
                        expected_hole,
                        "mask={mask}, initialized={initialized}, offset={offset}"
                    );
                }
            }
        }
    }

    fn extent(logical: u64, physical: u64, length: u64, flags: u32) -> FiemapExtent {
        FiemapExtent {
            logical,
            physical,
            length,
            flags,
        }
    }

    #[test]
    fn fiemap_preserves_fragmentation_sparse_gaps_and_native_physical_offsets() {
        let cx = Cx::for_testing();
        let stream = mapped(
            vec![
                run(0, 1, None),
                run(1, 2, Some(600)),
                run(3, 1, None),
                run(4, 1, Some(590)),
            ],
            2560,
            2560,
        );
        assert_eq!(
            fiemap(&cx, &stream, 512, 0, u64::MAX).unwrap(),
            vec![extent(512, 307_200, 1024, 0), extent(2048, 302_080, 512, 1),]
        );
        // Adjacent physical runs remain distinct without FIEMAP_FLAG_MERGED.
        let adjacent = mapped(vec![run(0, 1, Some(40)), run(1, 1, Some(41))], 1024, 1024);
        assert_eq!(
            fiemap(&cx, &adjacent, 512, 0, u64::MAX).unwrap(),
            vec![extent(0, 20_480, 512, 0), extent(512, 20_992, 512, 1)]
        );
    }

    #[test]
    fn fiemap_splits_at_valid_data_length_and_marks_unwritten_allocation() {
        let cx = Cx::for_testing();
        let stream = mapped(vec![run(0, 4, Some(20))], 1700, 777);
        assert_eq!(
            fiemap(&cx, &stream, 512, 0, u64::MAX).unwrap(),
            vec![
                extent(0, 10_240, 777, 0x100),
                extent(777, 11_017, 1271, 0x901),
            ]
        );
        // Extents intersecting the query are not truncated to the query itself.
        assert_eq!(
            fiemap(&cx, &stream, 512, 1000, 1).unwrap(),
            vec![extent(777, 11_017, 1271, 0x901)]
        );
        assert_eq!(
            fiemap(&cx, &stream, 512, 0, 777).unwrap(),
            vec![extent(0, 10_240, 777, 0x100)]
        );
        // Explicit queries past EOF can describe still allocated storage.
        assert_eq!(
            fiemap(&cx, &stream, 512, 1800, 1).unwrap(),
            vec![extent(777, 11_017, 1271, 0x901)]
        );
    }

    #[test]
    fn fiemap_last_is_last_allocation_not_last_returned_query_entry() {
        let cx = Cx::for_testing();
        let stream = mapped(
            vec![
                run(0, 1, Some(20)),
                run(1, 1, None),
                run(2, 1, Some(10)),
                run(3, 1, None),
            ],
            2048,
            2048,
        );
        assert_eq!(
            fiemap(&cx, &stream, 512, 0, 1).unwrap(),
            vec![extent(0, 10_240, 512, 0)]
        );
        assert_eq!(
            fiemap(&cx, &stream, 512, 1024, 1).unwrap(),
            vec![extent(1024, 5120, 512, 1)]
        );
        assert_eq!(
            fiemap(&cx, &stream, 512, 512, 512).unwrap(),
            [] as [FiemapExtent; 0]
        );
        assert_eq!(
            fiemap(&cx, &stream, 512, 1536, u64::MAX).unwrap(),
            [] as [FiemapExtent; 0]
        );
    }

    #[test]
    fn fiemap_resident_values_are_inline_unknown_not_fake_physical_data() {
        let cx = Cx::for_testing();
        let stream = Stream {
            storage: Storage::Resident(b"hello".to_vec()),
            size: 5,
            initialized: 5,
            allocated: 5,
        };
        assert_eq!(
            fiemap(&cx, &stream, 512, 1, 1).unwrap(),
            vec![extent(0, 0, 5, 0x303)]
        );
        for (start, length) in [(0, 0), (5, u64::MAX), (u64::MAX, 1)] {
            assert_eq!(
                fiemap(&cx, &stream, 512, start, length).unwrap(),
                [] as [FiemapExtent; 0]
            );
        }
        let empty = mapped(Vec::new(), 0, 0);
        let hole = mapped(vec![run(0, 1, None)], 512, 0);
        assert_eq!(
            fiemap(&cx, &empty, 512, 0, u64::MAX).unwrap(),
            [] as [FiemapExtent; 0]
        );
        assert_eq!(
            fiemap(&cx, &hole, 512, 0, u64::MAX).unwrap(),
            [] as [FiemapExtent; 0]
        );
    }

    #[test]
    fn fiemap_rejects_broken_or_overflowing_maps_without_partial_results() {
        let cx = Cx::for_testing();
        for runs in [
            vec![run(1, 1, Some(20))],
            vec![run(0, 1, Some(20)), run(2, 1, Some(30))],
            vec![run(0, 2, Some(20)), run(1, 1, None)],
            vec![run(0, 0, Some(20))],
            vec![run(0, 1, Some(u64::MAX))],
            vec![run(0, 1, Some(u64::MAX / 512))],
            vec![run(0, 1, Some(20))],
        ] {
            let stream = mapped(runs, 1024, 1024);
            assert!(matches!(
                fiemap(&cx, &stream, 512, 0, u64::MAX),
                Err(FfsError::Corruption { .. })
            ));
        }
        // A narrow query must not return an apparently complete prefix if a
        // later mapping is corrupt and therefore invalidates LAST accounting.
        let later = mapped(vec![run(0, 1, Some(20)), run(2, 1, Some(30))], 1536, 1536);
        assert!(matches!(
            fiemap(&cx, &later, 512, 0, 1),
            Err(FfsError::Corruption { .. })
        ));
    }
}
