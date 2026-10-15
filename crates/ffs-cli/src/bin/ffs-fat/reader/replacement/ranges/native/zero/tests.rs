use super::*;
use std::sync::Mutex;

struct Source {
    bytes: Vec<u8>,
    forbidden: Range<u64>,
    reads: Mutex<Vec<Range<u64>>>,
}

impl ByteDevice for Source {
    fn len_bytes(&self) -> u64 { self.bytes.len() as u64 }

    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let end = at.0 + bytes.len() as u64;
        assert!(end <= self.len_bytes());
        assert!(end <= self.forbidden.start || at.0 >= self.forbidden.end);
        self.reads.lock().unwrap().push(at.0..end);
        bytes.copy_from_slice(&self.bytes[at.0 as usize..end as usize]);
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, _at: ByteOffset, _bytes: &[u8]) -> ffs_error::Result<()> {
        panic!("zero-range source is read-only")
    }

    fn sync(&self, _cx: &Cx) -> ffs_error::Result<()> { panic!("source is never synchronized") }
}

#[test]
fn zero_source_matches_independent_byte_model_at_every_small_boundary() {
    let cx = Cx::for_testing();
    for old_size in 0..=9_u64 {
        for offset in 0..=12_u64 {
            for length in 1..=9_u64 {
                for keep_size in [false, true] {
                    let end = offset + length;
                    let size = if keep_size { old_size } else { old_size.max(end) };
                    let old = Source {
                        bytes: (0..old_size).map(|at| at as u8 + 1).collect(),
                        forbidden: offset.min(size)..end.min(size),
                        reads: Mutex::new(Vec::new()),
                    };
                    let source = ZeroSource { original: &old, size, zeroed: old.forbidden.clone() };
                    let mut expected = old.bytes.clone();
                    expected.resize(size as usize, 0);
                    expected[offset.min(size) as usize..end.min(size) as usize].fill(0);
                    for start in 0..=size {
                        for count in 0..=size - start {
                            let mut actual = vec![0xCC; count as usize];
                            source.read_exact_at(&cx, ByteOffset(start), &mut actual).unwrap();
                            assert_eq!(actual, expected[start as usize..(start + count) as usize]);
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn large_zero_source_needs_no_payload_sized_storage_or_old_data_reads() {
    let cx = Cx::for_testing();
    let old = Source { bytes: vec![9; 8], forbidden: 0..8, reads: Mutex::new(Vec::new()) };
    let size = u64::from(u32::MAX);
    let source = ZeroSource { original: &old, size, zeroed: 0..size };
    for at in [0, 1, 65_535, 16 * 1024 * 1024, size - 31] {
        let mut bytes = [0xCC; 31];
        source.read_exact_at(&cx, ByteOffset(at), &mut bytes).unwrap();
        assert_eq!(bytes, [0; 31]);
    }
    assert!(old.reads.lock().unwrap().is_empty());
}

#[test]
fn source_bounds_cancellation_and_writes_fail_without_touching_output() {
    let old = Source { bytes: vec![7; 4], forbidden: 1..3, reads: Mutex::new(Vec::new()) };
    let source = ZeroSource { original: &old, size: 4, zeroed: 1..3 };
    let cx = Cx::for_testing();
    for at in [4, 5, u64::MAX] {
        let mut output = [0xA5; 2];
        assert!(source.read_exact_at(&cx, ByteOffset(at), &mut output).is_err());
        assert_eq!(output, [0xA5; 2]);
    }
    source.read_exact_at(&cx, ByteOffset(4), &mut []).unwrap();
    assert!(matches!(source.write_all_at(&cx, ByteOffset(0), b"X"), Err(FfsError::ReadOnly)));
    let cancelled = Cx::for_testing();
    cancelled.cancel_with(asupersync::types::CancelKind::User, Some("zero source cancellation"));
    let mut output = [0xA5; 2];
    assert!(matches!(source.read_exact_at(&cancelled, ByteOffset(1), &mut output), Err(FfsError::Cancelled)));
    assert_eq!(output, [0xA5; 2]);
    assert!(old.reads.lock().unwrap().is_empty());
}
