use super::*;
use asupersync::types::CancelKind;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Read(&'static str, u64, Vec<usize>),
    Write(u64, Vec<usize>),
    Sync,
    Discard(u64, u64),
}

#[derive(Clone, Copy, Default)]
struct Faults {
    read: bool,
    partial_read: bool,
    write: bool,
    sync: bool,
    discard: bool,
    cancel_after_read: bool,
}

struct State {
    bytes: Vec<u8>,
    calls: Vec<Call>,
    faults: Faults,
    scalar_preserved: bool,
    vector_preserved: bool,
    vectored: bool,
    discard: bool,
}

struct Spy {
    length: AtomicU64,
    state: Mutex<State>,
}

fn io_error() -> FfsError {
    std::io::Error::from_raw_os_error(5).into()
}

impl Spy {
    fn new(length: usize) -> Arc<Self> {
        Arc::new(Self {
            length: AtomicU64::new(u64::try_from(length).unwrap()),
            state: Mutex::new(State {
                bytes: (0..length).map(|at| u8::try_from(at % 251).unwrap()).collect(),
                calls: Vec::new(),
                faults: Faults::default(),
                scalar_preserved: true,
                vector_preserved: true,
                vectored: true,
                discard: true,
            }),
        })
    }

    fn view(self: &Arc<Self>, base: u64, length: u64, access: VolumeAccess) -> VolumeDevice {
        VolumeDevice::new(self.clone(), ByteOffset(base), length, access).unwrap()
    }

    fn bytes(&self) -> Vec<u8> {
        self.state.lock().unwrap().bytes.clone()
    }

    fn calls(&self) -> Vec<Call> {
        self.state.lock().unwrap().calls.clone()
    }

    fn fault(&self, faults: Faults) {
        self.state.lock().unwrap().faults = faults;
    }

    fn read(
        &self,
        cx: &Cx,
        kind: &'static str,
        offset: ByteOffset,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.calls.push(Call::Read(
            kind,
            offset.0,
            bufs.iter().map(|buf| buf.len()).collect(),
        ));
        if state.faults.read {
            if state.faults.partial_read
                && let Some(buf) = bufs.iter_mut().find(|buf| !buf.is_empty())
            {
                buf[0] = 0xFA;
            }
            return Err(io_error());
        }
        let mut at = usize::try_from(offset.0).unwrap();
        for buf in bufs {
            let end = at.checked_add(buf.len()).unwrap();
            buf.copy_from_slice(&state.bytes[at..end]);
            at = end;
        }
        if state.faults.cancel_after_read {
            cx.cancel_with(CancelKind::User, Some("cancel after successful backing read"));
        }
        Ok(())
    }
}

impl ByteDevice for Spy {
    fn len_bytes(&self) -> u64 {
        self.length.load(Ordering::SeqCst)
    }

    fn supports_vectored_reads(&self) -> bool {
        self.state.lock().unwrap().vectored
    }

    fn preserves_read_exact_at_destination_on_error(&self) -> bool {
        self.state.lock().unwrap().scalar_preserved
    }

    fn preserves_read_vectored_destinations_on_error(&self) -> bool {
        self.state.lock().unwrap().vector_preserved
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        self.read(cx, "scalar", offset, &mut [IoSliceMut::new(buf)])
    }

    fn read_exact_at_volatile(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        self.read(cx, "volatile", offset, &mut [IoSliceMut::new(buf)])
    }

    fn read_vectored_exact_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Result<()> {
        self.read(cx, "vectored", offset, bufs)
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        self.write_vectored_all_at(cx, offset, &[buf])
    }

    fn write_vectored_all_at(&self, _cx: &Cx, offset: ByteOffset, bufs: &[&[u8]]) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.calls.push(Call::Write(offset.0, bufs.iter().map(|buf| buf.len()).collect()));
        if state.faults.write {
            return Err(io_error());
        }
        let mut at = usize::try_from(offset.0).unwrap();
        for buf in bufs {
            let end = at.checked_add(buf.len()).unwrap();
            state.bytes[at..end].copy_from_slice(buf);
            at = end;
        }
        Ok(())
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.calls.push(Call::Sync);
        if state.faults.sync {
            return Err(io_error());
        }
        Ok(())
    }

    fn supports_discard(&self) -> bool {
        self.state.lock().unwrap().discard
    }

    fn discard(&self, _cx: &Cx, offset: ByteOffset, length: u64) -> Result<()> {
        let mut state = self.state.lock().unwrap();
        state.calls.push(Call::Discard(offset.0, length));
        if !state.discard {
            return Err(FfsError::UnsupportedFeature("test device has no discard".to_owned()));
        }
        if state.faults.discard {
            return Err(io_error());
        }
        let at = usize::try_from(offset.0).unwrap();
        let end = at.checked_add(usize::try_from(length).unwrap()).unwrap();
        state.bytes[at..end].fill(0);
        Ok(())
    }
}

#[test]
fn constructor_rejects_invalid_selections_without_io() {
    let spy = Spy::new(64);
    for (base, length) in [(65, 0), (63, 2), (u64::MAX, 1), (1, u64::MAX)] {
        assert!(matches!(
            VolumeDevice::new(spy.clone(), ByteOffset(base), length, VolumeAccess::ReadOnly),
            Err(FfsError::InvalidGeometry(_))
        ));
    }
    for (base, length) in [(0, 64), (64, 0), (17, 11), (0, 0)] {
        let volume = spy.view(base, length, VolumeAccess::ReadOnly);
        assert_eq!(volume.len_bytes(), length);
        assert_eq!(volume.base_offset().0, base);
        assert_eq!(volume.access(), VolumeAccess::ReadOnly);
    }
    assert!(spy.calls().is_empty());
}

#[test]
fn scalar_read_write_and_discard_translate_once_and_preserve_adjacent_bytes() {
    let cx = Cx::for_testing();
    let spy = Spy::new(64);
    let before = spy.bytes();
    let volume = spy.view(13, 29, VolumeAccess::ReadWrite);
    let mut output = [0; 7];
    volume.read_exact_at(&cx, ByteOffset(3), &mut output).unwrap();
    assert_eq!(output, before[16..23]);
    volume.write_all_at(&cx, ByteOffset(0), b"first").unwrap();
    volume.write_all_at(&cx, ByteOffset(25), b"last").unwrap();
    volume.discard(&cx, ByteOffset(7), 11).unwrap();
    volume.sync(&cx).unwrap();
    let after = spy.bytes();
    assert_eq!(&after[..13], &before[..13]);
    assert_eq!(&after[42..], &before[42..]);
    assert_eq!(&after[13..18], b"first");
    assert_eq!(&after[20..31], &[0; 11]);
    assert_eq!(&after[38..42], b"last");
    assert_eq!(spy.calls(), [
        Call::Read("scalar", 16, vec![7]),
        Call::Write(13, vec![5]),
        Call::Write(38, vec![4]),
        Call::Discard(20, 11),
        Call::Sync,
    ]);
}

#[test]
fn scalar_and_discard_bounds_fail_before_backing_calls() {
    let cx = Cx::for_testing();
    let spy = Spy::new(64);
    let before = spy.bytes();
    let volume = spy.view(13, 29, VolumeAccess::ReadWrite);
    for (offset, length) in [(29, 1_usize), (28, 2), (30, 0), (u64::MAX, 1), (0, 30)] {
        let mut output = vec![0xC3; length];
        assert!(volume.read_exact_at(&cx, ByteOffset(offset), &mut output).is_err());
        assert_eq!(output, vec![0xC3; length]);
        assert!(volume.read_exact_at_volatile(&cx, ByteOffset(offset), &mut output).is_err());
        assert_eq!(output, vec![0xC3; length]);
        assert!(volume.write_all_at(&cx, ByteOffset(offset), &output).is_err());
        assert!(volume.discard(&cx, ByteOffset(offset), u64::try_from(length).unwrap()).is_err());
    }
    assert!(volume.discard(&cx, ByteOffset(1), u64::MAX).is_err());
    assert!(spy.calls().is_empty());
    assert_eq!(spy.bytes(), before);
}

#[test]
fn scatter_and_gather_preserve_native_vectored_calls_and_empty_segments() {
    let cx = Cx::for_testing();
    let spy = Spy::new(64);
    let volume = spy.view(8, 16, VolumeAccess::ReadWrite);
    let mut first = [0; 3];
    let mut empty = [];
    let mut last = [0; 5];
    volume.read_vectored_exact_at(&cx, ByteOffset(2), &mut [
        IoSliceMut::new(&mut first),
        IoSliceMut::new(&mut empty),
        IoSliceMut::new(&mut last),
    ]).unwrap();
    assert_eq!(first, [10, 11, 12]);
    assert_eq!(last, [13, 14, 15, 16, 17]);
    volume.write_vectored_all_at(&cx, ByteOffset(2), &[b"abc", b"", b"defgh"]).unwrap();
    assert_eq!(&spy.bytes()[10..18], b"abcdefgh");
    assert_eq!(spy.calls(), [
        Call::Read("vectored", 10, vec![3, 0, 5]),
        Call::Write(10, vec![3, 0, 5]),
    ]);
}

#[test]
fn later_vector_overrun_does_not_read_or_write_an_earlier_valid_segment() {
    let cx = Cx::for_testing();
    let spy = Spy::new(64);
    let volume = spy.view(8, 8, VolumeAccess::ReadWrite);
    let before = spy.bytes();
    for offset in [0, 1, 8, 9, u64::MAX] {
        let mut first = [0xA3; 4];
        let mut second = [0xC9; 5];
        assert!(volume.read_vectored_exact_at(&cx, ByteOffset(offset), &mut [
            IoSliceMut::new(&mut first), IoSliceMut::new(&mut second),
        ]).is_err());
        assert_eq!(first, [0xA3; 4]);
        assert_eq!(second, [0xC9; 5]);
        assert!(volume.write_vectored_all_at(&cx, ByteOffset(offset), &[b"1234", b"56789"]).is_err());
    }
    assert!(spy.calls().is_empty());
    assert_eq!(spy.bytes(), before);
}

#[test]
fn empty_requests_obey_eof_and_never_reach_backing_io() {
    let cx = Cx::for_testing();
    let spy = Spy::new(64);
    for (base, length) in [(8, 16), (64, 0), (0, 0)] {
        let volume = spy.view(base, length, VolumeAccess::ReadWrite);
        for offset in [0, length] {
            volume.read_exact_at(&cx, ByteOffset(offset), &mut []).unwrap();
            volume.read_exact_at_volatile(&cx, ByteOffset(offset), &mut []).unwrap();
            volume.read_vectored_exact_at(&cx, ByteOffset(offset), &mut []).unwrap();
            volume.read_vectored_exact_at(&cx, ByteOffset(offset), &mut [IoSliceMut::new(&mut [])]).unwrap();
            volume.write_all_at(&cx, ByteOffset(offset), b"").unwrap();
            volume.write_vectored_all_at(&cx, ByteOffset(offset), &[]).unwrap();
            volume.write_vectored_all_at(&cx, ByteOffset(offset), &[b"", b""]).unwrap();
            volume.discard(&cx, ByteOffset(offset), 0).unwrap();
        }
        let beyond = ByteOffset(length + 1);
        assert!(volume.read_vectored_exact_at(&cx, beyond, &mut []).is_err());
        assert!(volume.write_vectored_all_at(&cx, beyond, &[]).is_err());
        assert!(volume.discard(&cx, beyond, 0).is_err());
    }
    assert!(spy.calls().is_empty());
}

#[test]
fn read_only_never_forwards_mutations_or_backing_sync_even_when_empty() {
    let cx = Cx::for_testing();
    let spy = Spy::new(64);
    let volume = spy.view(8, 16, VolumeAccess::ReadOnly);
    let before = spy.bytes();
    assert!(!volume.supports_discard());
    for offset in [0, 16, 17, u64::MAX] {
        for bytes in [b"".as_slice(), b"new".as_slice()] {
            assert!(matches!(volume.write_all_at(&cx, ByteOffset(offset), bytes), Err(FfsError::ReadOnly)));
            assert!(matches!(volume.write_vectored_all_at(&cx, ByteOffset(offset), &[bytes]), Err(FfsError::ReadOnly)));
        }
        assert!(matches!(volume.write_vectored_all_at(&cx, ByteOffset(offset), &[]), Err(FfsError::ReadOnly)));
        for length in [0, 1, u64::MAX] {
            assert!(matches!(volume.discard(&cx, ByteOffset(offset), length), Err(FfsError::ReadOnly)));
        }
    }
    // A faulting backing flush would make this fail if it were ever forwarded.
    spy.fault(Faults { sync: true, ..Faults::default() });
    volume.sync(&cx).unwrap();
    assert!(spy.calls().is_empty());
    assert_eq!(spy.bytes(), before);
}

#[test]
fn nested_views_keep_relative_bounds_and_cannot_escalate_parent_rights() {
    let cx = Cx::for_testing();
    let spy = Spy::new(64);
    let parent = spy.view(11, 24, VolumeAccess::ReadWrite);
    let child = parent.subvolume(ByteOffset(7), 8, VolumeAccess::ReadWrite).unwrap();
    let clone = child.clone();
    assert_eq!(child.base_offset().0, 7);
    clone.write_all_at(&cx, ByteOffset(3), b"ok").unwrap();
    assert_eq!(&spy.bytes()[21..23], b"ok");
    assert!(child.write_all_at(&cx, ByteOffset(7), b"xx").is_err());
    assert!(parent.subvolume(ByteOffset(23), 2, VolumeAccess::ReadOnly).is_err());
    let readonly = child.subvolume(ByteOffset(0), 8, VolumeAccess::ReadOnly).unwrap();
    assert!(matches!(readonly.subvolume(ByteOffset(8), 0, VolumeAccess::ReadWrite), Err(FfsError::ReadOnly)));
    assert!(matches!(readonly.write_all_at(&cx, ByteOffset(0), b"x"), Err(FfsError::ReadOnly)));
    readonly.sync(&cx).unwrap();
    // Even wrapping a read-only device through the generic constructor cannot
    // bypass the underlying gate. ReadWrite is not an assertion of inner rights.
    let wrapped = VolumeDevice::new(Arc::new(readonly), ByteOffset(0), 8, VolumeAccess::ReadWrite).unwrap();
    assert!(!wrapped.supports_discard());
    assert!(matches!(wrapped.write_all_at(&cx, ByteOffset(0), b"x"), Err(FfsError::ReadOnly)));
    wrapped.sync(&cx).unwrap();
    assert_eq!(spy.calls(), [Call::Write(21, vec![2])]);
}

#[test]
fn backing_growth_never_widens_a_view_and_reported_shrink_fails_before_io() {
    let cx = Cx::for_testing();
    let spy = Spy::new(64);
    let volume = spy.view(10, 20, VolumeAccess::ReadWrite);
    spy.length.store(100, Ordering::SeqCst);
    assert_eq!(volume.len_bytes(), 20);
    assert!(volume.write_all_at(&cx, ByteOffset(20), b"x").is_err());
    spy.length.store(29, Ordering::SeqCst);
    let mut bytes = [0xA3; 2];
    assert!(volume.read_exact_at(&cx, ByteOffset(0), &mut bytes).is_err());
    assert_eq!(bytes, [0xA3; 2]);
    assert!(volume.read_exact_at_volatile(&cx, ByteOffset(0), &mut bytes).is_err());
    assert!(volume.read_vectored_exact_at(&cx, ByteOffset(0), &mut [IoSliceMut::new(&mut bytes)]).is_err());
    assert!(volume.write_all_at(&cx, ByteOffset(0), b"x").is_err());
    assert!(volume.write_vectored_all_at(&cx, ByteOffset(0), &[b"x"]).is_err());
    assert!(volume.discard(&cx, ByteOffset(0), 1).is_err());
    assert!(volume.sync(&cx).is_err());
    assert!(spy.calls().is_empty());
    spy.length.store(30, Ordering::SeqCst);
    volume.read_exact_at(&cx, ByteOffset(0), &mut bytes).unwrap();
    assert_eq!(bytes, [10, 11]);
}

#[test]
fn every_io_path_checks_cancellation_before_reaching_the_backing() {
    let spy = Spy::new(64);
    for access in [VolumeAccess::ReadOnly, VolumeAccess::ReadWrite] {
        let volume = spy.view(10, 20, access);
        let cx = Cx::for_testing();
        cx.cancel_with(CancelKind::User, Some("pre-cancelled volume request"));
        let mut output = [0xC3; 2];
        assert!(matches!(volume.read_exact_at(&cx, ByteOffset(0), &mut output), Err(FfsError::Cancelled)));
        assert!(matches!(volume.read_exact_at_volatile(&cx, ByteOffset(0), &mut output), Err(FfsError::Cancelled)));
        assert!(matches!(volume.read_vectored_exact_at(&cx, ByteOffset(0), &mut [IoSliceMut::new(&mut output)]), Err(FfsError::Cancelled)));
        assert_eq!(output, [0xC3; 2]);
        assert!(matches!(volume.write_all_at(&cx, ByteOffset(0), b"x"), Err(FfsError::Cancelled)));
        assert!(matches!(volume.write_vectored_all_at(&cx, ByteOffset(0), &[b"x"]), Err(FfsError::Cancelled)));
        assert!(matches!(volume.discard(&cx, ByteOffset(0), 1), Err(FfsError::Cancelled)));
        assert!(matches!(volume.sync(&cx), Err(FfsError::Cancelled)));
        assert!(matches!(volume.read_exact_at(&cx, ByteOffset(20), &mut []), Err(FfsError::Cancelled)));
        assert!(matches!(volume.read_vectored_exact_at(&cx, ByteOffset(20), &mut []), Err(FfsError::Cancelled)));
    }
    assert!(spy.calls().is_empty());
}

#[test]
fn capability_flags_are_forwarded_independently_without_strengthening_guarantees() {
    let spy = Spy::new(64);
    let volume = spy.view(8, 16, VolumeAccess::ReadWrite);
    for scalar in [false, true] {
        for vector in [false, true] {
            for optimized in [false, true] {
                let mut state = spy.state.lock().unwrap();
                state.scalar_preserved = scalar;
                state.vector_preserved = vector;
                state.vectored = optimized;
                state.discard = optimized;
                drop(state);
                assert_eq!(volume.preserves_read_exact_at_destination_on_error(), scalar);
                assert_eq!(volume.preserves_read_vectored_destinations_on_error(), vector);
                assert_eq!(volume.supports_vectored_reads(), optimized);
                assert_eq!(volume.supports_discard(), optimized);
            }
        }
    }
}

#[test]
fn backing_failures_preserve_their_error_and_declared_destination_contract() {
    let cx = Cx::for_testing();
    let spy = Spy::new(64);
    let volume = spy.view(8, 16, VolumeAccess::ReadWrite);
    spy.fault(Faults { read: true, write: true, sync: true, discard: true, ..Faults::default() });
    let mut output = [0xC3; 2];
    let mut tail = [0xA1; 3];
    let errors = [
        volume.read_exact_at(&cx, ByteOffset(0), &mut output),
        volume.read_exact_at_volatile(&cx, ByteOffset(0), &mut output),
        volume.read_vectored_exact_at(&cx, ByteOffset(0), &mut [IoSliceMut::new(&mut output), IoSliceMut::new(&mut tail)]),
        volume.write_all_at(&cx, ByteOffset(0), b"x"),
        volume.write_vectored_all_at(&cx, ByteOffset(0), &[b"x", b"y"]),
        volume.sync(&cx),
        volume.discard(&cx, ByteOffset(0), 2),
    ];
    for result in errors {
        assert!(matches!(result, Err(FfsError::Io(error)) if error.raw_os_error() == Some(5)));
    }
    assert_eq!(output, [0xC3; 2]);
    assert_eq!(tail, [0xA1; 3]);
    {
        let mut state = spy.state.lock().unwrap();
        state.scalar_preserved = false;
        state.vector_preserved = false;
        state.faults.partial_read = true;
    }
    assert!(!volume.preserves_read_exact_at_destination_on_error());
    assert!(!volume.preserves_read_vectored_destinations_on_error());
    assert!(volume.read_exact_at(&cx, ByteOffset(0), &mut output).is_err());
    assert_eq!(output, [0xFA, 0xC3]);
    assert!(volume.read_vectored_exact_at(&cx, ByteOffset(0), &mut [IoSliceMut::new(&mut tail)]).is_err());
    assert_eq!(tail, [0xFA, 0xA1, 0xA1]);
}

#[test]
fn late_cancellation_does_not_turn_a_committed_read_into_a_destination_error() {
    let spy = Spy::new(64);
    let volume = spy.view(8, 16, VolumeAccess::ReadOnly);
    spy.fault(Faults { cancel_after_read: true, ..Faults::default() });
    for kind in ["scalar", "volatile", "vectored"] {
        let cx = Cx::for_testing();
        let mut output = [0xC3; 3];
        let result = match kind {
            "scalar" => volume.read_exact_at(&cx, ByteOffset(2), &mut output),
            "volatile" => volume.read_exact_at_volatile(&cx, ByteOffset(2), &mut output),
            _ => volume.read_vectored_exact_at(&cx, ByteOffset(2), &mut [IoSliceMut::new(&mut output)]),
        };
        result.unwrap();
        assert_eq!(output, [10, 11, 12]);
        assert!(cx.checkpoint().is_err());
        let before = spy.calls().len();
        assert!(matches!(volume.read_exact_at(&cx, ByteOffset(2), &mut output), Err(FfsError::Cancelled)));
        assert_eq!(spy.calls().len(), before);
        assert_eq!(output, [10, 11, 12]);
    }
    assert_eq!(spy.calls(), [
        Call::Read("scalar", 10, vec![3]),
        Call::Read("volatile", 10, vec![3]),
        Call::Read("vectored", 10, vec![3]),
    ]);
}

#[test]
fn unsupported_discard_is_not_synthesized_as_a_successful_write() {
    let cx = Cx::for_testing();
    let spy = Spy::new(64);
    spy.state.lock().unwrap().discard = false;
    let volume = spy.view(8, 16, VolumeAccess::ReadWrite);
    assert!(!volume.supports_discard());
    assert!(matches!(volume.discard(&cx, ByteOffset(3), 2), Err(FfsError::UnsupportedFeature(_))));
    assert_eq!(spy.calls(), [Call::Discard(11, 2)]);
}

#[test]
fn vector_length_summation_does_not_wrap_or_allocate_payload_storage() {
    let cx = Cx::for_testing();
    assert_eq!(total_bytes(&cx, [0, 3, 0, 5].into_iter()).unwrap(), 8);
    assert_eq!(total_bytes(&cx, std::iter::empty()).unwrap(), 0);
    assert_eq!(total_bytes(&cx, [usize::MAX].into_iter()).unwrap(), u64::try_from(usize::MAX).unwrap());
    #[cfg(target_pointer_width = "64")]
    assert!(total_bytes(&cx, [usize::MAX, 1].into_iter()).is_err());
}

#[test]
fn high_volume_offsets_preserve_u64_endpoints_without_allocating_a_huge_image() {
    let cx = Cx::for_testing();
    let spy = Spy::new(0);
    spy.length.store(u64::MAX, Ordering::SeqCst);
    let volume = spy.view(u64::MAX - 16, 16, VolumeAccess::ReadWrite);
    assert_eq!(volume.physical_range(&cx, ByteOffset(15), 1).unwrap().0, u64::MAX - 1);
    assert_eq!(volume.physical_range(&cx, ByteOffset(16), 0).unwrap().0, u64::MAX);
    assert!(volume.physical_range(&cx, ByteOffset(16), 1).is_err());
    assert!(volume.physical_range(&cx, ByteOffset(u64::MAX), 1).is_err());
    volume.read_exact_at(&cx, ByteOffset(16), &mut []).unwrap();
    assert!(spy.calls().is_empty());
}

#[test]
fn exhaustive_small_ranges_match_an_independent_subtraction_oracle() {
    let cx = Cx::for_testing();
    let spy = Spy::new(20);
    for base in 0_u64..=20 {
        for length in 0..=20 - base {
            let volume = spy.view(base, length, VolumeAccess::ReadWrite);
            for offset in 0..=22 {
                for count in 0..=22 {
                    let expected = offset <= length && count <= length.saturating_sub(offset);
                    let result = volume.physical_range(&cx, ByteOffset(offset), count);
                    assert_eq!(result.is_ok(), expected, "base={base} length={length} offset={offset} count={count}");
                    if let Ok(physical) = result {
                        assert_eq!(physical.0, base + offset);
                    }
                }
            }
        }
    }
    assert!(spy.calls().is_empty());
}

#[test]
fn read_only_file_open_uses_the_selected_bytes_without_changing_the_image() {
    use std::io::Write;

    let cx = Cx::for_testing();
    let mut image = tempfile::NamedTempFile::new().unwrap();
    let original = b"before|native volume|after";
    image.write_all(original).unwrap();
    image.flush().unwrap();
    let selected = VolumeDevice::open_read_only(&cx, image.path(), ByteOffset(7), Some(13)).unwrap();
    let mut output = [0; 13];
    selected.read_exact_at(&cx, ByteOffset(0), &mut output).unwrap();
    assert_eq!(&output, b"native volume");
    assert!(matches!(selected.write_all_at(&cx, ByteOffset(0), b"wrong"), Err(FfsError::ReadOnly)));
    selected.sync(&cx).unwrap();
    assert_eq!(std::fs::read(image.path()).unwrap(), original);
    let rest = VolumeDevice::open_read_only(&cx, image.path(), ByteOffset(20), None).unwrap();
    assert_eq!(rest.len_bytes(), 6);
    assert_eq!(rest.access(), VolumeAccess::ReadOnly);
    assert!(matches!(VolumeDevice::open_read_only(&cx, image.path(), ByteOffset(27), None), Err(FfsError::InvalidGeometry(_))));
    assert!(matches!(VolumeDevice::open_read_only(&cx, image.path(), ByteOffset(20), Some(7)), Err(FfsError::InvalidGeometry(_))));
    let cancelled = Cx::for_testing();
    cancelled.cancel_with(CancelKind::User, Some("cancel before opening any path"));
    assert!(matches!(VolumeDevice::open_read_only(&cancelled, image.path().join("missing"), ByteOffset(0), None), Err(FfsError::Cancelled)));
}

#[test]
fn vector_metadata_scan_observes_cancellation_without_backing_io() {
    use std::sync::atomic::AtomicUsize;

    let cx = Cx::for_testing();
    let seen = AtomicUsize::new(0);
    let lengths = (0..1024).map(|index| {
        seen.fetch_add(1, Ordering::SeqCst);
        if index == 255 {
            cx.cancel_with(CancelKind::User, Some("cancel during vector metadata scan"));
        }
        0_usize
    });
    assert!(matches!(total_bytes(&cx, lengths), Err(FfsError::Cancelled)));
    assert_eq!(seen.load(Ordering::SeqCst), 257);
}
