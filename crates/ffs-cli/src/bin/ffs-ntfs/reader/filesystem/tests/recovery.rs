use super::*;

const LOG_START: usize = BASE + 192 * 512;
const LOG_SIZE: usize = 32_768;
const RECORD_PAGE: usize = 4 * 512;
const RECORD_OFFSET: usize = 64;
// One sequence bit above the 32 KiB log's eight-byte offset field.
const CURRENT_LSN: u64 = (1 << 13) | ((RECORD_PAGE + RECORD_OFFSET) / 8) as u64;

fn restart_page(clean: bool, token: u16) -> [u8; 512] {
    // Independent 512-byte native restart fixture: USA at 30, restart at 40,
    // 48-byte restart prefix, 160-byte client record. The volume flags stay 0.
    let mut page = [0; 512];
    page[..4].copy_from_slice(b"RSTR");
    page[4..6].copy_from_slice(&30_u16.to_le_bytes());
    page[6..8].copy_from_slice(&2_u16.to_le_bytes());
    page[16..20].copy_from_slice(&512_u32.to_le_bytes());
    page[20..24].copy_from_slice(&512_u32.to_le_bytes());
    page[24..26].copy_from_slice(&40_u16.to_le_bytes());
    page[26..28].copy_from_slice(&1_u16.to_le_bytes());
    page[28..30].copy_from_slice(&1_u16.to_le_bytes());
    page[40..48].copy_from_slice(&CURRENT_LSN.to_le_bytes());
    page[48..50].copy_from_slice(&1_u16.to_le_bytes());
    page[50..52].copy_from_slice(&u16::MAX.to_le_bytes());
    page[54..56].copy_from_slice(&(if clean { 2_u16 } else { 0 }).to_le_bytes());
    page[56..60].copy_from_slice(&51_u32.to_le_bytes());
    page[60..62].copy_from_slice(&208_u16.to_le_bytes());
    page[62..64].copy_from_slice(&48_u16.to_le_bytes());
    page[64..72].copy_from_slice(&(LOG_SIZE as u64).to_le_bytes());
    page[72..76].copy_from_slice(&48_u32.to_le_bytes());
    page[76..78].copy_from_slice(&48_u16.to_le_bytes());
    page[78..80].copy_from_slice(&64_u16.to_le_bytes());
    page[88..96].copy_from_slice(&CURRENT_LSN.to_le_bytes());
    // The current record is an ordinary update, not a client checkpoint.
    // Leave the restart reference absent rather than mislabel that record.
    page[104..106].copy_from_slice(&u16::MAX.to_le_bytes());
    page[106..108].copy_from_slice(&u16::MAX.to_le_bytes());
    page[108..110].copy_from_slice(&9_u16.to_le_bytes());
    page[116..120].copy_from_slice(&8_u32.to_le_bytes());
    page[120..128].copy_from_slice(b"N\0T\0F\0S\0");
    page[30..32].copy_from_slice(&token.to_le_bytes());
    page[510..512].copy_from_slice(&token.to_le_bytes());
    page
}

fn record_page() -> [u8; 512] {
    // Independent native v1 RCRD page: a 48-byte LFS header followed by a
    // 48-byte NTFS client update, ending at byte 160 before the USA trailer.
    let mut page = [0; 512];
    page[..4].copy_from_slice(b"RCRD");
    page[4..6].copy_from_slice(&40_u16.to_le_bytes());
    page[6..8].copy_from_slice(&2_u16.to_le_bytes());
    page[8..16].copy_from_slice(&CURRENT_LSN.to_le_bytes());
    page[16..20].copy_from_slice(&1_u32.to_le_bytes());
    page[20..22].copy_from_slice(&1_u16.to_le_bytes());
    page[22..24].copy_from_slice(&1_u16.to_le_bytes());
    page[24..26].copy_from_slice(&160_u16.to_le_bytes());
    page[32..40].copy_from_slice(&CURRENT_LSN.to_le_bytes());
    let header = &mut page[RECORD_OFFSET..RECORD_OFFSET + 48];
    header[..8].copy_from_slice(&CURRENT_LSN.to_le_bytes());
    header[24..28].copy_from_slice(&48_u32.to_le_bytes());
    header[28..30].copy_from_slice(&9_u16.to_le_bytes());
    header[32..36].copy_from_slice(&1_u32.to_le_bytes());
    header[36..40].copy_from_slice(&17_u32.to_le_bytes());
    let client = &mut page[RECORD_OFFSET + 48..RECORD_OFFSET + 96];
    client[..2].copy_from_slice(&7_u16.to_le_bytes());
    client[2..4].copy_from_slice(&7_u16.to_le_bytes());
    client[4..6].copy_from_slice(&40_u16.to_le_bytes());
    client[6..8].copy_from_slice(&8_u16.to_le_bytes());
    client[8..10].copy_from_slice(&40_u16.to_le_bytes());
    client[10..12].copy_from_slice(&8_u16.to_le_bytes());
    client[12..14].copy_from_slice(&24_u16.to_le_bytes());
    client[40..48].fill(1);
    page[40..42].copy_from_slice(&0x1234_u16.to_le_bytes());
    page[510..512].copy_from_slice(&0x1234_u16.to_le_bytes());
    page
}

fn with_restarts(first_clean: bool, second_clean: bool) -> Vec<u8> {
    let mut bytes = image();
    bytes[LOG_START..LOG_START + 512].copy_from_slice(&restart_page(first_clean, 0xCAFE));
    bytes[LOG_START + 512..LOG_START + 1024].copy_from_slice(&restart_page(second_clean, 0xBEEF));
    bytes[LOG_START + RECORD_PAGE..LOG_START + RECORD_PAGE + 512].copy_from_slice(&record_page());
    bytes
}

#[test]
fn native_mount_admission_reads_journal_and_preserves_regular_file_contents() {
    let cx = Cx::for_testing();
    for bytes in [image(), with_restarts(true, true)] {
        let reads: Reads = Arc::default();
        let fs = open(bytes, Arc::clone(&reads), None).unwrap();
        let mut scope = RequestScope::empty();
        let file = fs
            .lookup(&cx, &mut scope, ROOT, OsStr::new("hello.txt"))
            .unwrap();
        assert_eq!(fs.read(&cx, &mut scope, file.ino, 0, 64).unwrap(), b"hello");
        assert!(
            reads
                .lock()
                .unwrap()
                .iter()
                .any(|(at, _)| *at == LOG_START as u64)
        );
    }
}

#[test]
fn zero_volume_flags_cannot_hide_dirty_torn_or_incomplete_native_journal() {
    for (first, second, expected) in [
        (
            false,
            false,
            "redo/undo recovery before mounting; current transaction 17 has redo opcode 0x07 and undo opcode 0x07",
        ),
        (
            false,
            true,
            "equal-LSN restart copies disagree on checkpoint state",
        ),
        (
            true,
            false,
            "equal-LSN restart copies disagree on checkpoint state",
        ),
    ] {
        let reads: Reads = Arc::default();
        assert!(matches!(
            open(with_restarts(first, second), Arc::clone(&reads), None),
            Err(FfsError::UnsupportedFeature(reason)) if reason.contains(expected)
        ));
        assert_eq!(
            reads
                .lock()
                .unwrap()
                .iter()
                .any(|(at, _)| *at == (LOG_START + RECORD_PAGE) as u64),
            !first && !second,
            "only agreeing dirty copies may advance into the native record decoder"
        );
        assert!(
            reads
                .lock()
                .unwrap()
                .iter()
                .all(|(at, _)| *at != (BASE + 300 * 512) as u64)
        );
    }
    for copy in 0..2 {
        let mut bytes = with_restarts(true, true);
        bytes[LOG_START + copy * 512 + 511] ^= 1;
        assert!(matches!(
            open(bytes, Arc::default(), None),
            Err(FfsError::Corruption { .. })
        ));
    }
    let mut bytes = image();
    bytes[LOG_START + LOG_SIZE - 1] = 0;
    assert!(matches!(
        open(bytes, Arc::default(), None),
        Err(FfsError::Corruption { .. })
    ));
}

#[test]
fn matching_dirty_restarts_require_an_intact_current_native_record() {
    for mutation in 0..3 {
        let mut bytes = with_restarts(false, false);
        let expected = match mutation {
            0 => {
                // Agreeing but impossible LSNs must still be corruption, not
                // a valid dirty tail merely awaiting replay support.
                for copy in 0..2 {
                    let at = LOG_START + copy * 512 + 40;
                    bytes[at..at + 8].copy_from_slice(&42_u64.to_le_bytes());
                    // Isolate the invalid requested LSN from client-window
                    // metadata, which has its own stricter validation.
                    bytes[at + 48..at + 56].fill(0);
                }
                "selected-checkpoint LSN does not address a retained record location"
            }
            1 => {
                bytes[LOG_START + RECORD_PAGE + 511] ^= 1;
                "torn $LogFile record page"
            }
            _ => {
                bytes[LOG_START + RECORD_PAGE..LOG_START + RECORD_PAGE + 4].fill(0xFF);
                "current LSN points into an erased record page"
            }
        };
        let reads: Reads = Arc::default();
        assert!(matches!(
            open(bytes, Arc::clone(&reads), None),
            Err(FfsError::Corruption { detail, .. }) if detail.contains(expected)
        ));
        assert_eq!(
            reads
                .lock()
                .unwrap()
                .iter()
                .any(|(at, _)| *at == (LOG_START + RECORD_PAGE) as u64),
            mutation != 0,
            "invalid LSNs must fail before reading a record page"
        );
        assert!(
            reads
                .lock()
                .unwrap()
                .iter()
                .all(|(at, _)| *at != (BASE + 300 * 512) as u64)
        );
    }
}

#[test]
fn native_log_mapping_supports_backward_fragments_and_propagates_cancellation() {
    let mut bytes = image();
    // Logical second half follows a negative LCN delta from 192 to 160.
    bytes[BASE + 160 * 512..BASE + 192 * 512].fill(0xFF);
    put(
        &mut bytes,
        2,
        &record(
            2,
            false,
            1,
            &[
                standard(),
                mapped(&[0x21, 32, 0xC0, 0, 0x11, 32, 0xE0, 0], 64, 32_768, false),
            ],
        ),
    );
    let reads: Reads = Arc::default();
    open(bytes.clone(), Arc::clone(&reads), None).unwrap();
    assert!(
        reads
            .lock()
            .unwrap()
            .iter()
            .any(|(at, _)| *at == (BASE + 160 * 512) as u64)
    );
    for fail in [LOG_START, BASE + 160 * 512] {
        assert!(matches!(
            open(bytes.clone(), Arc::default(), Some(fail as u64)),
            Err(FfsError::Cancelled)
        ));
    }
}

#[test]
fn initialized_journal_bytes_cannot_be_synthesized_from_valid_data_length() {
    let mut bytes = image();
    let mut data = mapped(&[0x21, 64, 0xC0, 0, 0], 64, 32_768, false);
    data[56..64].copy_from_slice(&512_u64.to_le_bytes());
    put(&mut bytes, 2, &record(2, false, 1, &[standard(), data]));
    let reads: Reads = Arc::default();
    assert!(matches!(
        open(bytes, Arc::clone(&reads), None),
        Err(FfsError::Corruption { .. })
    ));
    assert!(
        reads
            .lock()
            .unwrap()
            .iter()
            .all(|(at, _)| *at != LOG_START as u64)
    );
}
