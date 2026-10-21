use super::super::{DATA, NtfsVolume, VOLUME_INFORMATION};
use super::*;
use asupersync::types::CancelKind;
use std::sync::Mutex;

#[derive(Default)]
struct Trace {
    reads: Vec<(u64, usize)>,
    fail_at: Option<u64>,
    cancel_at: Option<u64>,
    mutations: usize,
}

struct Memory {
    bytes: Vec<u8>,
    trace: Arc<Mutex<Trace>>,
}

impl ByteDevice for Memory {
    fn len_bytes(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        let mut trace = self.trace.lock().unwrap();
        trace.reads.push((offset.0, out.len()));
        if trace.cancel_at == Some(offset.0) {
            cx.cancel_with(
                CancelKind::User,
                Some("injected native source cancellation"),
            );
            return Err(FfsError::Cancelled);
        }
        if trace.fail_at == Some(offset.0) {
            return Err(std::io::Error::from_raw_os_error(5).into());
        }
        let at = usize::try_from(offset.0).unwrap();
        let end = at.checked_add(out.len()).unwrap();
        let bytes = self
            .bytes
            .get(at..end)
            .ok_or_else(|| FfsError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof)))?;
        out.copy_from_slice(bytes);
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _bytes: &[u8]) -> Result<()> {
        self.trace.lock().unwrap().mutations += 1;
        panic!("native source attempted a backing write")
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        self.trace.lock().unwrap().mutations += 1;
        panic!("native source attempted backing synchronization")
    }
}

fn memory(bytes: Vec<u8>, trace: &Arc<Mutex<Trace>>) -> Box<dyn ByteDevice> {
    Box::new(Memory {
        bytes,
        trace: trace.clone(),
    })
}

fn fixture(base: usize, length: usize) -> (Source, Arc<Mutex<Trace>>, Vec<u8>) {
    let bytes: Vec<_> = (0..base + length + 32).map(|at| (at % 251) as u8).collect();
    let trace = Arc::new(Mutex::new(Trace::default()));
    let source = Source::bounded(
        &Cx::for_testing(),
        memory(bytes.clone(), &trace),
        base as u64,
        length as u64,
    )
    .unwrap();
    (source, trace, bytes)
}

#[test]
fn native_source_translates_the_partition_base_only_once_and_rejects_neighboring_bytes() {
    let cx = Cx::for_testing();
    let (source, trace, original) = fixture(37, 2048);
    let mut out = [0; 19];
    source.read(&cx, 2000, &mut out).unwrap();
    assert_eq!(out, original[2037..2056]);
    assert_eq!(trace.lock().unwrap().reads, [(2037, 19)]);
    let before = out;
    for offset in [2040, 2049, u64::MAX] {
        assert!(source.read(&cx, offset, &mut out).is_err());
        assert_eq!(out, before);
    }
    assert_eq!(trace.lock().unwrap().reads, [(2037, 19)]);
    assert_eq!(source.base, 0);
    assert_eq!(source.device.len_bytes(), 2048);
    assert!(matches!(
        source.device.write_all_at(&cx, ByteOffset(0), b"x"),
        Err(FfsError::ReadOnly)
    ));
    source.device.sync(&cx).unwrap();
    assert_eq!(trace.lock().unwrap().mutations, 0);
}

#[test]
fn fully_replaced_sectors_do_not_read_the_old_backing_even_if_it_is_unreadable() {
    let cx = Cx::for_testing();
    let (mut source, trace, _) = fixture(37, 2048);
    trace.lock().unwrap().fail_at = Some(37 + 512);
    source.write_overlay(&cx, 512, &[0xA7; 1024]).unwrap();
    assert_eq!(trace.lock().unwrap().reads, []);
    let mut out = [0; 1000];
    source.read(&cx, 519, &mut out).unwrap();
    assert_eq!(out, [0xA7; 1000]);
    assert_eq!(trace.lock().unwrap().reads, []);
    let cancelled = Cx::for_testing();
    cancelled.cancel_with(CancelKind::User, Some("cached overlay read cancellation"));
    assert!(matches!(
        source.read(&cancelled, 519, &mut out),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(trace.lock().unwrap().mutations, 0);
}

#[test]
fn mixed_reads_copy_exact_overlay_ranges_and_coalesce_the_uncovered_gaps() {
    let cx = Cx::for_testing();
    let (mut source, trace, original) = fixture(37, 4096);
    source.write_overlay(&cx, 512, &[0xA7; 512]).unwrap();
    source.write_overlay(&cx, 2560, &[0xB9; 512]).unwrap();
    assert_eq!(trace.lock().unwrap().reads, []);
    let mut out = vec![0; 3500];
    source.read(&cx, 100, &mut out).unwrap();
    let mut expected = original[137..3637].to_vec();
    expected[412..924].fill(0xA7);
    expected[2460..2972].fill(0xB9);
    assert_eq!(out, expected);
    assert_eq!(
        trace.lock().unwrap().reads,
        [(137, 412), (1061, 1536), (3109, 528)]
    );
}

#[test]
fn partial_patch_preserves_original_and_previous_overlay_bytes() {
    let cx = Cx::for_testing();
    let (mut source, trace, original) = fixture(37, 2048);
    source.write_overlay(&cx, 510, b"abcdef").unwrap();
    assert_eq!(trace.lock().unwrap().reads, [(37, 512), (549, 512)]);
    source.write_overlay(&cx, 511, b"XY").unwrap();
    let mut out = [0; 16];
    source.read(&cx, 505, &mut out).unwrap();
    let mut expected = original[542..558].to_vec();
    expected[5..11].copy_from_slice(b"aXYdef");
    assert_eq!(out.as_slice(), expected.as_slice());
    assert_eq!(trace.lock().unwrap().reads, [(37, 512), (549, 512)]);
}

#[test]
fn later_read_failure_or_cancellation_does_not_publish_an_earlier_overlay_sector() {
    for cancel in [false, true] {
        let cx = Cx::for_testing();
        let (mut source, trace, _) = fixture(37, 2048);
        source.write_overlay(&cx, 1024, &[0xA7; 512]).unwrap();
        let before = source.overlay.clone();
        if cancel {
            trace.lock().unwrap().cancel_at = Some(549);
        } else {
            trace.lock().unwrap().fail_at = Some(549);
        }
        let result = source.write_overlay(&cx, 510, b"abcdef");
        if cancel {
            assert!(matches!(result, Err(FfsError::Cancelled)));
        } else {
            assert!(matches!(result, Err(FfsError::Io(error)) if error.raw_os_error() == Some(5)));
        }
        assert_eq!(source.overlay, before);
        assert_eq!(trace.lock().unwrap().reads, [(37, 512), (549, 512)]);
        assert_eq!(trace.lock().unwrap().mutations, 0);
    }
}

#[test]
fn final_partial_sector_does_not_borrow_bytes_from_the_next_partition() {
    let cx = Cx::for_testing();
    let (mut source, trace, original) = fixture(37, 530);
    source.write_overlay(&cx, 520, b"0123456789").unwrap();
    assert_eq!(trace.lock().unwrap().reads, [(549, 18)]);
    let mut out = [0; 18];
    source.read(&cx, 512, &mut out).unwrap();
    assert_eq!(&out[..8], &original[549..557]);
    assert_eq!(&out[8..], b"0123456789");
    assert!(source.write_overlay(&cx, 530, b"x").is_err());
    assert!(source.read(&cx, 530, &mut [0; 1]).is_err());
    assert_eq!(trace.lock().unwrap().reads, [(549, 18)]);
}

#[test]
fn failed_patch_cannot_change_already_cached_sectors() {
    let cx = Cx::for_testing();
    let (mut source, trace, _) = fixture(37, 2048);
    source.write_overlay(&cx, 0, &[0xA7; 512]).unwrap();
    trace.lock().unwrap().fail_at = Some(549);
    let before = source.overlay.clone();
    assert!(source.write_overlay(&cx, 510, b"abcdef").is_err());
    assert_eq!(source.overlay, before);
    let mut out = [0; 3];
    source.read(&cx, 509, &mut out).unwrap();
    assert_eq!(out, [0xA7; 3]);
}

#[test]
fn empty_and_invalid_patches_are_bounded_before_any_state_change() {
    let cx = Cx::for_testing();
    let (mut source, trace, _) = fixture(37, 2048);
    source.write_overlay(&cx, 2048, &[]).unwrap();
    source.read(&cx, 2048, &mut []).unwrap();
    assert!(source.write_overlay(&cx, 2049, &[]).is_err());
    assert!(source.read(&cx, 2049, &mut []).is_err());
    assert!(source.write_overlay(&cx, u64::MAX, b"xx").is_err());
    assert!(source.request_end(0, MAX_READ + 1).is_err());
    cx.cancel_with(CancelKind::User, Some("cancel before overlay staging"));
    assert!(matches!(
        source.write_overlay(&cx, 0, &[0; 512]),
        Err(FfsError::Cancelled)
    ));
    assert!(source.overlay.is_empty());
    assert_eq!(trace.lock().unwrap().reads, []);
}

#[test]
fn retained_overlay_capacity_counts_new_sectors_not_replacements_and_cannot_wrap() {
    overlay_capacity(MAX_OVERLAY_SECTORS, 3, 3).unwrap();
    overlay_capacity(MAX_OVERLAY_SECTORS - 1, 3, 2).unwrap();
    assert!(overlay_capacity(MAX_OVERLAY_SECTORS, 3, 2).is_err());
    assert!(overlay_capacity(usize::MAX, 1, 0).is_err());
    assert!(overlay_capacity(0, 1, 2).is_err());
}

#[test]
fn uncovered_failures_are_not_hidden_by_an_earlier_overlay_hit() {
    let cx = Cx::for_testing();
    let (mut source, trace, _) = fixture(37, 2048);
    source.write_overlay(&cx, 0, &[0xA7; 512]).unwrap();
    trace.lock().unwrap().fail_at = Some(549);
    let before = source.overlay.clone();
    assert!(
        matches!(source.read(&cx, 0, &mut [0; 513]), Err(FfsError::Io(error)) if error.raw_os_error() == Some(5))
    );
    assert_eq!(source.overlay, before);
    assert_eq!(trace.lock().unwrap().reads, [(549, 1)]);
}

// Native bootstrap fixtures below exercise the actual constructor, not a
// hand-built NtfsVolume with a fictional MFT map. All bytes are constructed.
const BASE: usize = 1024;
const LENGTH: usize = 256 * 512;
const LOG_PAGE: usize = 512;
const LOG_LENGTH: usize = 32 * 1024;

fn resident(kind: u32, value: &[u8]) -> Vec<u8> {
    let length = (24 + value.len()).next_multiple_of(8);
    let mut attr = vec![0; length];
    attr[..4].copy_from_slice(&kind.to_le_bytes());
    attr[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    attr[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
    attr[20..22].copy_from_slice(&24_u16.to_le_bytes());
    attr[24..24 + value.len()].copy_from_slice(value);
    attr
}

fn mapped(lcn: u8, clusters: u8) -> Vec<u8> {
    let mut attr = vec![0; 72];
    attr[..4].copy_from_slice(&DATA.to_le_bytes());
    attr[4..8].copy_from_slice(&72_u32.to_le_bytes());
    attr[8] = 1;
    attr[24..32].copy_from_slice(&(u64::from(clusters) - 1).to_le_bytes());
    attr[32..34].copy_from_slice(&64_u16.to_le_bytes());
    for at in [40, 48, 56] {
        attr[at..at + 8].copy_from_slice(&(u64::from(clusters) * 512).to_le_bytes());
    }
    // Two offset bytes keep positive LCNs >=128 from becoming negative deltas.
    attr[64..69].copy_from_slice(&[0x21, clusters, lcn, 0, 0]);
    attr
}

fn record(number: u32, attributes: &[Vec<u8>]) -> Vec<u8> {
    let mut raw = vec![0; 1024];
    raw[..4].copy_from_slice(b"FILE");
    raw[4..6].copy_from_slice(&48_u16.to_le_bytes());
    raw[6..8].copy_from_slice(&3_u16.to_le_bytes());
    raw[16..18].copy_from_slice(&7_u16.to_le_bytes());
    raw[18..20].copy_from_slice(&1_u16.to_le_bytes());
    raw[20..22].copy_from_slice(&56_u16.to_le_bytes());
    raw[22..24].copy_from_slice(&1_u16.to_le_bytes());
    raw[28..32].copy_from_slice(&1024_u32.to_le_bytes());
    raw[44..48].copy_from_slice(&number.to_le_bytes());
    raw[48..50].copy_from_slice(&0x1357_u16.to_le_bytes());
    let mut at = 56;
    for attr in attributes {
        raw[at..at + attr.len()].copy_from_slice(attr);
        at += attr.len();
    }
    raw[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    raw[24..28].copy_from_slice(&((at + 8) as u32).to_le_bytes());
    ffs_ondisk::ntfs::protect_record(&raw).unwrap()
}

fn clean_log() -> Vec<u8> {
    // The old 16 KiB/four-page fixture was below native minimum geometry.
    // Use a complete 64-page v1.1 journal with a real inactive client list.
    let mut page = vec![0; LOG_PAGE];
    page[..4].copy_from_slice(b"RSTR");
    page[4..6].copy_from_slice(&32_u16.to_le_bytes());
    page[6..8].copy_from_slice(&2_u16.to_le_bytes());
    page[16..20].copy_from_slice(&(LOG_PAGE as u32).to_le_bytes());
    page[20..24].copy_from_slice(&(LOG_PAGE as u32).to_le_bytes());
    page[24..26].copy_from_slice(&64_u16.to_le_bytes());
    page[26..28].copy_from_slice(&1_i16.to_le_bytes());
    page[28..30].copy_from_slice(&1_i16.to_le_bytes());
    page[32..34].copy_from_slice(&0x1357_u16.to_le_bytes());
    let area = &mut page[64..];
    area[8..10].copy_from_slice(&1_u16.to_le_bytes());
    area[12..14].copy_from_slice(&u16::MAX.to_le_bytes());
    area[14..16].copy_from_slice(&2_u16.to_le_bytes());
    area[16..20].copy_from_slice(&51_u32.to_le_bytes());
    area[20..22].copy_from_slice(&224_u16.to_le_bytes());
    area[22..24].copy_from_slice(&64_u16.to_le_bytes());
    area[24..32].copy_from_slice(&(LOG_LENGTH as u64).to_le_bytes());
    area[36..38].copy_from_slice(&48_u16.to_le_bytes());
    area[38..40].copy_from_slice(&64_u16.to_le_bytes());
    area[80..82].copy_from_slice(&u16::MAX.to_le_bytes());
    area[82..84].copy_from_slice(&u16::MAX.to_le_bytes());
    area[84..86].copy_from_slice(&9_u16.to_le_bytes());
    area[92..96].copy_from_slice(&8_u32.to_le_bytes());
    area[96..104].copy_from_slice(b"N\0T\0F\0S\0");
    let page = ffs_ondisk::ntfs::protect_record(&page).unwrap();
    let mut log = vec![0xFF; LOG_LENGTH];
    log[..LOG_PAGE].copy_from_slice(&page);
    log[LOG_PAGE..2 * LOG_PAGE].copy_from_slice(&page);
    log
}

fn image(flags: u16, log: Option<Vec<u8>>) -> Vec<u8> {
    let mut bytes = vec![0; BASE + LENGTH + 512];
    bytes[..BASE].fill(0xD1);
    bytes[BASE + LENGTH..].fill(0xD2);
    let boot = &mut bytes[BASE..BASE + 512];
    boot[3..11].copy_from_slice(b"NTFS    ");
    boot[11..13].copy_from_slice(&512_u16.to_le_bytes());
    boot[13] = 1;
    boot[21] = 0xF8;
    boot[36] = 0x80;
    boot[38] = 0x80;
    boot[40..48].copy_from_slice(&255_u64.to_le_bytes());
    boot[48..56].copy_from_slice(&4_u64.to_le_bytes());
    boot[56..64].copy_from_slice(&128_u64.to_le_bytes());
    boot[64] = 0xF6;
    boot[68] = 0xF4;
    boot[510..512].copy_from_slice(&[0x55, 0xAA]);
    let mft = record(0, &[mapped(4, 64)]);
    bytes[BASE + 4 * 512..BASE + 6 * 512].copy_from_slice(&mft);
    bytes[BASE + 128 * 512..BASE + 130 * 512].copy_from_slice(&mft);
    let mut info = [0; 12];
    info[8..10].copy_from_slice(&[3, 1]);
    info[10..12].copy_from_slice(&flags.to_le_bytes());
    bytes[BASE + 4 * 512 + 3 * 1024..BASE + 4 * 512 + 4 * 1024]
        .copy_from_slice(&record(3, &[resident(VOLUME_INFORMATION, &info)]));
    if let Some(log) = log {
        assert_eq!(log.len(), LOG_LENGTH);
        // Backward fragmentation retains the original read-error injection
        // point and keeps the unowned target at LCN 220 outside the journal.
        let mut attr = mapped(180, 64);
        attr[64..72].copy_from_slice(&[0x21, 32, 180, 0, 0x11, 32, 0xD8, 0]);
        bytes[BASE + 4 * 512 + 2 * 1024..BASE + 4 * 512 + 3 * 1024]
            .copy_from_slice(&record(2, &[attr]));
        bytes[BASE + 180 * 512..BASE + 212 * 512].copy_from_slice(&log[..16_384]);
        bytes[BASE + 140 * 512..BASE + 172 * 512].copy_from_slice(&log[16_384..]);
    }
    bytes
}

fn open(bytes: Vec<u8>, trace: &Arc<Mutex<Trace>>, recover: bool) -> Result<NtfsVolume> {
    NtfsVolume::from_device_with_options(
        &Cx::for_testing(),
        memory(bytes, trace),
        BASE as u64,
        LENGTH as u64,
        recover,
    )
}

#[test]
fn native_bootstrap_and_explicit_clean_log_inspection_still_succeed_with_partition_bounds() {
    for recover in [false, true] {
        let trace = Arc::new(Mutex::new(Trace::default()));
        let volume = open(image(0, Some(clean_log())), &trace, recover).unwrap();
        assert_eq!(volume.record_count(), 32);
        assert_eq!(volume.source.base, 0);
        if recover {
            let plan = volume.logfile_recovery.as_ref().unwrap();
            assert!(plan.restart.is_clean());
            assert_eq!(plan.restart.file_size, LOG_LENGTH as u64);
            assert!(plan.redo_actions.is_empty() && plan.undo_actions.is_empty());
        } else {
            assert!(volume.logfile_recovery.is_none());
        }
        let trace = trace.lock().unwrap();
        assert_eq!(trace.mutations, 0);
        assert!(
            trace.reads.iter().all(
                |&(at, count)| at >= BASE as u64 && at + count as u64 <= (BASE + LENGTH) as u64
            )
        );
    }
}

#[test]
fn requested_recovery_propagates_missing_log_corruption_io_and_cancellation() {
    for flags in [0, 1] {
        for fault in 0..4 {
            let trace = Arc::new(Mutex::new(Trace::default()));
            let log = match fault {
                0 => None,
                1 => Some(vec![0; LOG_LENGTH]),
                _ => Some(clean_log()),
            };
            if fault == 2 {
                trace.lock().unwrap().fail_at = Some((BASE + 180 * 512) as u64);
            }
            if fault == 3 {
                trace.lock().unwrap().cancel_at = Some((BASE + 180 * 512) as u64);
            }
            let result = open(image(flags, log), &trace, true);
            assert!(result.is_err(), "flags={flags} fault={fault}");
            if fault == 2 {
                assert!(
                    matches!(result, Err(FfsError::Io(error)) if error.raw_os_error() == Some(5))
                );
            } else if fault == 3 {
                assert!(matches!(result, Err(FfsError::Cancelled)));
            }
            assert_eq!(trace.lock().unwrap().mutations, 0);
        }
    }
}

#[test]
fn recovery_does_not_override_unrelated_native_volume_flags() {
    for flags in [2_u16, 4, 8, 16, 0x8000, 3] {
        let trace = Arc::new(Mutex::new(Trace::default()));
        assert!(matches!(
            open(image(flags, Some(clean_log())), &trace, true),
            Err(FfsError::UnsupportedFeature(_))
        ));
        let trace = trace.lock().unwrap();
        assert!(
            !trace
                .reads
                .iter()
                .any(|&(at, _)| at == (BASE + 180 * 512) as u64)
        );
        assert_eq!(trace.mutations, 0);
    }
}

#[test]
fn recovery_rejects_log_extent_disagreement_and_a_valid_prefix_of_a_larger_log() {
    let trace = Arc::new(Mutex::new(Trace::default()));
    let mut bytes = image(0, Some(clean_log()));
    // A fully valid restart area must not describe bytes omitted from the
    // admitted stream. Update both pages without manufacturing bad USA checks.
    for page in [0, LOG_PAGE] {
        let at = BASE + 180 * 512 + page;
        bytes[at + 64 + 16..at + 64 + 20].copy_from_slice(&50_u32.to_le_bytes());
        bytes[at + 64 + 24..at + 64 + 32].copy_from_slice(&65_536_u64.to_le_bytes());
    }
    assert!(open(bytes, &trace, true).is_err());
    let mut bytes = image(0, Some(clean_log()));
    // A complete, physically mapped log larger than the work budget must not
    // be truncated to a parseable prefix. First admit its real DATA mapping
    // through the ordinary reader so malformed attributes cannot earn credit.
    let at = BASE + 4 * 512 + 2 * 1024;
    let mut attr = mapped(180, 32);
    let excessive = (MAX_READ as u64) + 512;
    let clusters = excessive / 512;
    let volume_length = (180 + clusters + 4) * 512;
    bytes.resize(BASE + volume_length as usize + 512, 0);
    bytes[BASE + 40..BASE + 48].copy_from_slice(&(volume_length / 512 - 1).to_le_bytes());
    attr[24..32].copy_from_slice(&(clusters - 1).to_le_bytes());
    attr[40..48].copy_from_slice(&excessive.to_le_bytes());
    attr[48..56].copy_from_slice(&excessive.to_le_bytes());
    attr[56..64].copy_from_slice(&excessive.to_le_bytes());
    let count = u16::try_from(clusters).unwrap().to_le_bytes();
    attr[64..70].copy_from_slice(&[0x22, count[0], count[1], 180, 0, 0]);
    bytes[at..at + 1024].copy_from_slice(&record(2, &[attr]));
    let cx = Cx::for_testing();
    let volume = NtfsVolume::from_device_with_options(
        &cx,
        memory(bytes.clone(), &trace),
        BASE as u64,
        volume_length,
        false,
    )
    .unwrap();
    let log_record = volume.record(&cx, 2, None).unwrap();
    let stream = volume.data_stream(&cx, &log_record, &[]).unwrap();
    assert_eq!(stream.size, excessive);
    trace.lock().unwrap().reads.clear();
    assert!(
        NtfsVolume::from_device_with_options(
            &cx,
            memory(bytes, &trace),
            BASE as u64,
            volume_length,
            true,
        )
        .is_err()
    );
    assert!(
        !trace
            .lock()
            .unwrap()
            .reads
            .iter()
            .any(|&(at, _)| at == (BASE + 180 * 512) as u64)
    );
    assert_eq!(trace.lock().unwrap().mutations, 0);
}

fn action_log(lcn: u64, offset: u16, data: &[u8]) -> Vec<u8> {
    let mut log = clean_log();
    let second_at = 64 + (48 + 40 + data.len()).next_multiple_of(8);
    let first_lsn = (1_u64 << 13) | ((4 * LOG_PAGE + 64) as u64 / 8);
    let last_lsn = (1_u64 << 13) | ((4 * LOG_PAGE + second_at) as u64 / 8);
    for start in [0, LOG_PAGE] {
        log[start + 64..start + 72].copy_from_slice(&last_lsn.to_le_bytes());
        log[start + 74..start + 76].copy_from_slice(&u16::MAX.to_le_bytes());
        log[start + 76..start + 80].fill(0); // Active client, dirty restart.
        log[start + 96..start + 100].copy_from_slice(&40_u32.to_le_bytes());
        log[start + 128..start + 136].copy_from_slice(&first_lsn.to_le_bytes());
    }
    let mut page = vec![0; LOG_PAGE];
    page[..4].copy_from_slice(b"RCRD");
    page[4..6].copy_from_slice(&40_u16.to_le_bytes());
    page[6..8].copy_from_slice(&2_u16.to_le_bytes());
    page[8..16].copy_from_slice(&last_lsn.to_le_bytes());
    page[16..20].copy_from_slice(&1_u32.to_le_bytes());
    page[20..22].copy_from_slice(&1_u16.to_le_bytes());
    page[22..24].copy_from_slice(&1_u16.to_le_bytes());
    page[32..40].copy_from_slice(&last_lsn.to_le_bytes());
    page[40..42].copy_from_slice(&0x1357_u16.to_le_bytes());
    let mut at = 64;
    for (lsn, previous, operation, patch) in [
        (first_lsn, 0_u64, 0x08_u16, data),
        (last_lsn, first_lsn, 0x1A, b"".as_slice()),
    ] {
        let payload_length = 40 + patch.len();
        page[at..at + 8].copy_from_slice(&lsn.to_le_bytes());
        page[at + 8..at + 16].copy_from_slice(&previous.to_le_bytes());
        page[at + 24..at + 28].copy_from_slice(&(payload_length as u32).to_le_bytes());
        page[at + 28..at + 30].copy_from_slice(&9_u16.to_le_bytes());
        page[at + 32..at + 36].copy_from_slice(&1_u32.to_le_bytes());
        page[at + 36..at + 40].copy_from_slice(&42_u32.to_le_bytes());
        let payload = &mut page[at + 48..at + 48 + payload_length];
        payload[..2].copy_from_slice(&operation.to_le_bytes());
        if !patch.is_empty() {
            payload[4..6].copy_from_slice(&40_u16.to_le_bytes());
            payload[6..8].copy_from_slice(&(patch.len() as u16).to_le_bytes());
            payload[12..14].copy_from_slice(&24_u16.to_le_bytes());
            payload[14..16].copy_from_slice(&1_u16.to_le_bytes());
            payload[18..20].copy_from_slice(&offset.to_le_bytes());
            payload[32..40].copy_from_slice(&lcn.to_le_bytes());
            payload[40..].copy_from_slice(patch);
        }
        at += (48 + payload_length).next_multiple_of(8);
    }
    page[24..26].copy_from_slice(&(at as u16).to_le_bytes());
    let page = ffs_ondisk::ntfs::protect_record(&page).unwrap();
    log[4 * LOG_PAGE..5 * LOG_PAGE].copy_from_slice(&page);
    let plan = ffs_ondisk::ntfs::parse_ntfs_logfile(&log).unwrap();
    assert_eq!(plan.records_parsed, 2);
    assert_eq!(plan.committed_transactions, [42]);
    assert_eq!(plan.redo_actions.len(), 1);
    assert_eq!(plan.undo_actions, []);
    assert_eq!(plan.redo_actions[0].target_lcns, [lcn]);
    assert_eq!(plan.redo_actions[0].data, data);
    log
}

#[test]
fn arbitrary_nonresident_physical_patches_are_not_native_recovery_operations() {
    let trace = Arc::new(Mutex::new(Trace::default()));
    let log = action_log(220, 3, b"overlay!");
    // The old fixture named no stream or allocated target and relied on a raw
    // memcpy fallback. Preserve it as a regression against that unsafe path.
    assert!(matches!(
        open(image(1, Some(log)), &trace, true),
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert!(
        !trace
            .lock()
            .unwrap()
            .reads
            .iter()
            .any(|&(at, _)| { at == (BASE + 220 * 512) as u64 })
    );
    assert_eq!(trace.lock().unwrap().mutations, 0);
}

#[test]
fn out_of_volume_and_overflowing_recovery_actions_are_errors_not_silently_skipped() {
    for lcn in [256, u64::MAX] {
        let trace = Arc::new(Mutex::new(Trace::default()));
        let log = action_log(lcn, 0, b"invalid");
        assert!(open(image(1, Some(log)), &trace, true).is_err());
        assert_eq!(trace.lock().unwrap().mutations, 0);
    }
}

#[test]
fn broken_file_fixups_and_failed_mft_rebuilds_do_not_publish_a_recovery_result() {
    for bad_mft in [false, true] {
        let trace = Arc::new(Mutex::new(Trace::default()));
        let (target, offset, patch) = if bad_mft {
            (4, 20, vec![0, 0]) // Invalidate the recovered record-zero attribute offset.
        } else {
            (220, 60, b"payload".to_vec())
        };
        let mut bytes = image(1, Some(action_log(target, offset, &patch)));
        if !bad_mft {
            let at = BASE + 220 * 512;
            bytes[at..at + 1024].copy_from_slice(&record(24, &[]));
            bytes[at + 510] ^= 1; // Break the native USA token, not the FILE magic.
        }
        assert!(open(bytes, &trace, true).is_err());
        assert_eq!(trace.lock().unwrap().mutations, 0);
    }
}

#[test]
fn missing_data_and_uninitialized_log_tails_cannot_be_reported_as_successful_recovery() {
    for missing in [false, true] {
        let trace = Arc::new(Mutex::new(Trace::default()));
        let mut bytes = image(0, Some(clean_log()));
        let attributes = if missing {
            Vec::new()
        } else {
            let mut data = mapped(180, 32);
            data[56..64].copy_from_slice(&8192_u64.to_le_bytes());
            vec![data]
        };
        let at = BASE + 4 * 512 + 2 * 1024;
        bytes[at..at + 1024].copy_from_slice(&record(2, &attributes));
        assert!(open(bytes, &trace, true).is_err());
        let trace = trace.lock().unwrap();
        assert!(
            !trace
                .reads
                .iter()
                .any(|&(at, _)| at == (BASE + 180 * 512) as u64)
        );
        assert_eq!(trace.mutations, 0);
    }
}
