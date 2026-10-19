//! Stage only the committed bytes that survive every admitted log edit.
//!
//! A fully replaced or truncated native block is not an input to recovery.
//! Required old bytes still use the normal checked reader; log coverage never
//! grants permission to publish unchecked bytes from a damaged partial block.

use super::{
    Cx, Edit, MAX_READ_BYTES, MAX_RECOVERY_WORK_BYTES, Result, apply, charge_recovery, checkpoint,
    corrupt, overlap, unsupported,
};

const MAX_BASE_READS: usize = 4096;

pub(in super::super) fn read(
    cx: &Cx,
    original_size: u64,
    start: u64,
    length: usize,
    edits: &[Edit<'_>],
    mut base: impl FnMut(u64, usize) -> Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    checkpoint(cx)?;
    if length > MAX_READ_BYTES {
        return Err(unsupported("ZIL recovered range exceeds 16 MiB"));
    }
    start
        .checked_add(length as u64)
        .ok_or_else(|| corrupt("ZIL recovered range overflows its address space"))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|error| super::FfsError::Io(std::io::Error::other(error)))?;
    bytes.resize(length, 0);
    apply(cx, &mut bytes, start, original_size, edits)?;

    // One byte per result byte keeps marking linear and the allocation bounded
    // at 16 MiB. Once changed by any edit, an old byte can never reappear, even
    // after shrink/regrowth. The staged overlay already supplies its new value.
    let mut needed = Vec::new();
    needed
        .try_reserve_exact(length)
        .map_err(|error| super::FfsError::Io(std::io::Error::other(error)))?;
    needed.resize(length, false);
    let old_length = original_size.saturating_sub(start).min(length as u64) as usize;
    needed[..old_length].fill(true);
    let mut size = original_size;
    let mut remaining = MAX_RECOVERY_WORK_BYTES;
    for edit in edits {
        checkpoint(cx)?;
        let changed = match edit {
            Edit::Write { offset, data, .. } | Edit::Indirect { offset, data, .. } => {
                overlap(start, length, *offset, *offset + data.len() as u64)
            }
            Edit::Truncate { size: next, .. } if *next < size => {
                overlap(start, length, *next, u64::MAX)
            }
            Edit::Truncate { size: next, .. } => overlap(start, length, size, *next),
            Edit::Free { offset, end, .. } => overlap(start, length, size.min(*offset), *end),
        };
        charge_recovery(&mut remaining, changed.len())?;
        needed[changed].fill(false);
        size = edit.size_after(size);
    }

    // Admit the complete read plan before the first old-data I/O. A fragmented
    // edit stream cannot turn one bounded request into unbounded device calls.
    let mut spans = Vec::new();
    let mut at = 0;
    while at < needed.len() {
        checkpoint(cx)?;
        at += needed[at..].iter().take_while(|needed| !**needed).count();
        if at == needed.len() {
            break;
        }
        let end = at + needed[at..].iter().take_while(|needed| **needed).count();
        if spans.len() == MAX_BASE_READS {
            return Err(unsupported(
                "ZIL recovery exceeds 4096 surviving base ranges",
            ));
        }
        spans.push(at..end);
        at = end;
    }
    for span in spans {
        checkpoint(cx)?;
        let old = base(start + span.start as u64, span.len())?;
        if old.len() != span.len() {
            return Err(corrupt("ZIL surviving base range returned a short read"));
        }
        checkpoint(cx)?;
        bytes[span].copy_from_slice(&old);
    }
    checkpoint(cx)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::super::FfsError;
    use super::*;

    #[test]
    fn complete_log_coverage_and_shrink_regrowth_never_read_old_data() {
        let cx = Cx::for_testing();
        for edits in [
            vec![Edit::Write {
                object: 7,
                offset: 0,
                data: b"replacement!",
            }],
            vec![
                Edit::Truncate { object: 7, size: 0 },
                Edit::Write {
                    object: 7,
                    offset: 11,
                    data: b"!",
                },
            ],
        ] {
            let recovered = read(&cx, 16, 0, 12, &edits, |_, _| {
                panic!("fully superseded corrupt block must not be read")
            })
            .unwrap();
            assert_eq!(recovered[11], b'!');
            assert_eq!(recovered.len(), 12);
        }
        let edits = [
            Edit::Truncate { object: 7, size: 4 },
            Edit::Truncate {
                object: 7,
                size: 16,
            },
        ];
        assert_eq!(
            read(&cx, 16, 4, 12, &edits, |_, _| panic!("retired tail")).unwrap(),
            [0; 12]
        );
    }

    #[test]
    fn surviving_byte_ranges_are_exact_and_required_damage_is_not_hidden() {
        let cx = Cx::for_testing();
        let edits = [
            Edit::Write {
                object: 7,
                offset: 2,
                data: b"NEW",
            },
            Edit::Truncate { object: 7, size: 8 },
            Edit::Write {
                object: 7,
                offset: 12,
                data: b"!",
            },
        ];
        let mut requests = Vec::new();
        let bytes = read(&cx, 16, 0, 13, &edits, |at, len| {
            requests.push((at, len));
            Ok(b"abcdefghijklmnop"[at as usize..at as usize + len].to_vec())
        })
        .unwrap();
        assert_eq!(bytes, b"abNEWfgh\0\0\0\0!");
        assert_eq!(requests, [(0, 2), (5, 3)]);
        for cancelled in [false, true] {
            let mut calls = 0;
            let result = read(&cx, 16, 0, 13, &edits, |_, len| {
                calls += 1;
                if calls == 1 {
                    return Ok(vec![b'a'; len]);
                }
                Err(if cancelled {
                    FfsError::Cancelled
                } else {
                    corrupt("required damaged bytes")
                })
            });
            assert!(result.is_err());
            assert_eq!(calls, 2);
            if cancelled {
                assert!(matches!(result, Err(FfsError::Cancelled)));
            }
        }
        assert!(read(&cx, 16, 0, 13, &edits, |_, len| Ok(vec![0; len - 1])).is_err());
    }

    #[test]
    fn all_bounded_edit_sequences_match_a_materialized_file_oracle() {
        let cx = Cx::for_testing();
        let original = b"abcdefghijklmnop";
        for pattern in 0..256 {
            let mut edits = Vec::new();
            let mut oracle = original.to_vec();
            for shift in [0, 2, 4, 6] {
                let edit = match (pattern >> shift) & 3 {
                    0 => Edit::Truncate { object: 7, size: 3 },
                    1 => Edit::Truncate {
                        object: 7,
                        size: 24,
                    },
                    2 => Edit::Write {
                        object: 7,
                        offset: 7,
                        data: b"XY\0Z",
                    },
                    _ => Edit::Write {
                        object: 7,
                        offset: 1,
                        data: b"changed",
                    },
                };
                match &edit {
                    Edit::Truncate { size, .. } => oracle.resize(*size as usize, 0),
                    Edit::Free { offset, end, .. } => {
                        oracle.resize(oracle.len().max(*end as usize), 0);
                        oracle[*offset as usize..*end as usize].fill(0);
                    }
                    Edit::Write { offset, data, .. } => {
                        oracle.resize(oracle.len().max(*offset as usize + data.len()), 0);
                        oracle[*offset as usize..*offset as usize + data.len()]
                            .copy_from_slice(data);
                    }
                    Edit::Indirect {
                        offset, data, end, ..
                    } => {
                        let visible = oracle.len().max(*end as usize);
                        oracle.resize(oracle.len().max(*offset as usize + data.len()), 0);
                        oracle[*offset as usize..*offset as usize + data.len()]
                            .copy_from_slice(data);
                        oracle.truncate(visible);
                    }
                }
                edits.push(edit);
            }
            for start in 0..=28 {
                for count in [0, 1, 3, 9, 32] {
                    let length = oracle.len().saturating_sub(start).min(count);
                    let actual = read(&cx, 16, start as u64, length, &edits, |at, len| {
                        Ok(original[at as usize..at as usize + len].to_vec())
                    })
                    .unwrap();
                    let expected =
                        &oracle[start.min(oracle.len())..start.min(oracle.len()) + length];
                    assert_eq!(
                        actual, expected,
                        "pattern={pattern}, start={start}, count={count}"
                    );
                }
            }
        }
    }

    #[test]
    fn range_and_fragmentation_budgets_fail_before_base_io() {
        let cx = Cx::for_testing();
        let edits: Vec<_> = (0..=MAX_BASE_READS)
            .map(|i| Edit::Write {
                object: 7,
                offset: (i * 2 + 1) as u64,
                data: b"x",
            })
            .collect();
        let size = (MAX_BASE_READS * 2 + 3) as u64;
        let error = read(&cx, size, 0, size as usize, &edits, |_, _| {
            panic!("not admitted")
        })
        .unwrap_err();
        assert!(matches!(error, FfsError::UnsupportedFeature(_)));
        assert!(read(&cx, u64::MAX, u64::MAX, 1, &[], |_, _| panic!("overflow")).is_err());
        assert!(
            read(&cx, u64::MAX, 0, MAX_READ_BYTES + 1, &[], |_, _| panic!(
                "budget"
            ))
            .is_err()
        );
        assert_eq!(
            read(&cx, 16, 16, 0, &[], |_, _| panic!("EOF")).unwrap(),
            [] as [u8; 0]
        );
    }
}
