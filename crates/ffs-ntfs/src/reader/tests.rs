use super::*;
use std::sync::{Arc, Mutex};

type Reads = Arc<Mutex<Vec<(u64, usize)>>>;
const BASE: usize = 1024;
const LENGTH: usize = 256 * 512;

#[test]
fn direct_record_data_admission_refuses_reparse_providers_and_efs_before_data_io() {
    let cx = Cx::for_testing();
    for flags in [0x400_u32, 0x4000] {
        let mut image = Image::new();
        let mut standard = [0; 72];
        standard[32..36].copy_from_slice(&flags.to_le_bytes());
        let mut attributes = vec![
            resident(0x10, 2, "", &standard),
            mapped(&[0x21, 1, 180, 0, 0], 1, 512, 512, 0),
            resident(DATA, 4, "alternate", b"not provider plaintext"),
        ];
        if flags == 0x400 {
            attributes.push(resident(0xC0, 3, "", &[0x17, 0, 0, 0x80, 0, 0, 0, 0]));
        }
        image.put_record(24, &file_record(24, &attributes));
        let reads: Reads = Arc::default();
        let volume = image.open(Arc::clone(&reads), None).unwrap();
        let record = volume.record(&cx, 24, Some(7)).unwrap();
        reads.lock().unwrap().clear();
        for name in [Vec::new(), "alternate".encode_utf16().collect()] {
            assert!(matches!(
                volume.data_stream(&cx, &record, &name),
                Err(FfsError::UnsupportedFeature(_))
            ));
        }
        assert!(reads.lock().unwrap().is_empty());
    }
}

fn resident(kind: u32, id: u16, name: &str, value: &[u8]) -> Vec<u8> {
    let name: Vec<u16> = name.encode_utf16().collect();
    let start = (24 + name.len() * 2).next_multiple_of(8);
    let length = (start + value.len()).next_multiple_of(8);
    let mut a = vec![0; length];
    a[..4].copy_from_slice(&kind.to_le_bytes());
    a[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    a[9] = name.len() as u8;
    a[10..12].copy_from_slice(&24_u16.to_le_bytes());
    a[14..16].copy_from_slice(&id.to_le_bytes());
    a[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
    a[20..22].copy_from_slice(&(start as u16).to_le_bytes());
    for (i, unit) in name.iter().enumerate() {
        a[24 + i * 2..26 + i * 2].copy_from_slice(&unit.to_le_bytes());
    }
    a[start..start + value.len()].copy_from_slice(value);
    a
}

fn mapped(pairs: &[u8], clusters: u64, size: u64, initialized: u64, flags: u16) -> Vec<u8> {
    let start: usize = if flags & SPARSE != 0 { 72 } else { 64 };
    let length = (start + pairs.len()).next_multiple_of(8);
    let mut a = vec![0; length];
    a[..4].copy_from_slice(&DATA.to_le_bytes());
    a[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    a[8] = 1;
    a[12..14].copy_from_slice(&flags.to_le_bytes());
    a[24..32].copy_from_slice(&(clusters - 1).to_le_bytes());
    a[32..34].copy_from_slice(&(start as u16).to_le_bytes());
    a[40..48].copy_from_slice(&(clusters * 512).to_le_bytes());
    a[48..56].copy_from_slice(&size.to_le_bytes());
    a[56..64].copy_from_slice(&initialized.to_le_bytes());
    if flags & SPARSE != 0 {
        a[34..36].copy_from_slice(&4_u16.to_le_bytes());
        a[64..72].copy_from_slice(&1024_u64.to_le_bytes());
    }
    a[start..start + pairs.len()].copy_from_slice(pairs);
    a
}

fn file_record(number: u32, attributes: &[Vec<u8>]) -> Vec<u8> {
    let mut r = vec![0; 1024];
    r[..4].copy_from_slice(b"FILE");
    r[4..6].copy_from_slice(&48_u16.to_le_bytes());
    r[6..8].copy_from_slice(&3_u16.to_le_bytes());
    r[16..18].copy_from_slice(&7_u16.to_le_bytes());
    r[18..20].copy_from_slice(&1_u16.to_le_bytes());
    r[20..22].copy_from_slice(&56_u16.to_le_bytes());
    r[22..24].copy_from_slice(&1_u16.to_le_bytes());
    r[28..32].copy_from_slice(&1024_u32.to_le_bytes());
    r[44..48].copy_from_slice(&number.to_le_bytes());
    let mut at = 56;
    for attr in attributes {
        r[at..at + attr.len()].copy_from_slice(attr);
        at += attr.len();
    }
    r[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    r[24..28].copy_from_slice(&((at + 8) as u32).to_le_bytes());
    for part in 1..=2 {
        let saved = [r[part * 512 - 2], r[part * 512 - 1]];
        r[48 + part * 2..50 + part * 2].copy_from_slice(&saved);
        r[part * 512 - 2..part * 512].copy_from_slice(&0x1357_u16.to_le_bytes());
    }
    r[48..50].copy_from_slice(&0x1357_u16.to_le_bytes());
    r
}

struct Image {
    bytes: Vec<u8>,
}
impl Image {
    fn new() -> Self {
        let mut image = Self {
            bytes: vec![0; BASE + LENGTH + 512],
        };
        image.bytes[..BASE].fill(0xD1);
        image.bytes[BASE + LENGTH..].fill(0xD2);
        let b = &mut image.bytes[BASE..BASE + 512];
        b[3..11].copy_from_slice(b"NTFS    ");
        b[11..13].copy_from_slice(&512_u16.to_le_bytes());
        b[13] = 1;
        b[21] = 0xF8;
        b[36] = 0x80;
        b[38] = 0x80;
        b[40..48].copy_from_slice(&255_u64.to_le_bytes());
        b[48..56].copy_from_slice(&4_u64.to_le_bytes());
        b[56..64].copy_from_slice(&128_u64.to_le_bytes());
        b[64] = 0xF6;
        b[68] = 0xF4;
        b[510..512].copy_from_slice(&[0x55, 0xAA]);
        let mft = file_record(
            0,
            &[mapped(
                &[0x11, 16, 4, 0x11, 48, 36, 0],
                64,
                32 * 1024,
                32 * 1024,
                0,
            )],
        );
        image.put_record(0, &mft);
        image.bytes[BASE + 128 * 512..BASE + 130 * 512].copy_from_slice(&mft);
        let mut info = [0; 12];
        info[8..10].copy_from_slice(&[3, 1]);
        image.put_record(
            3,
            &file_record(3, &[resident(VOLUME_INFORMATION, 0, "", &info)]),
        );
        image.put_record(
            24,
            &file_record(
                24,
                &[
                    resident(DATA, 0, "", b"resident!"),
                    resident(DATA, 1, "note", b"named stream"),
                ],
            ),
        );
        image.put_record(
            25,
            &file_record(
                25,
                &[mapped(&[0x21, 1, 180, 0, 0x11, 1, 0xF6, 0], 2, 600, 600, 0)],
            ),
        );
        image.put_record(
            26,
            &file_record(
                26,
                &[mapped(
                    &[0x21, 1, 200, 0, 0x01, 2, 0x11, 1, 0xF6, 0],
                    4,
                    2035,
                    1543,
                    SPARSE,
                )],
            ),
        );
        for (lcn, value) in [(180, b'A'), (170, b'B'), (200, b'C'), (190, b'D')] {
            image.bytes[BASE + lcn * 512..BASE + (lcn + 1) * 512].fill(value);
        }
        image
    }
    fn record_offset(number: usize) -> usize {
        // Deliberately fragmented MFT: record 8 onward lives in a second extent.
        BASE + if number < 8 {
            4 * 512 + number * 1024
        } else {
            40 * 512 + (number - 8) * 1024
        }
    }
    fn put_record(&mut self, number: usize, record: &[u8]) {
        let at = Self::record_offset(number);
        self.bytes[at..at + 1024].copy_from_slice(record);
    }
    fn open(self, reads: Reads, fail_at: Option<u64>) -> Result<NtfsVolume> {
        NtfsVolume::from_device(
            &Cx::for_testing(),
            Box::new(Memory {
                bytes: self.bytes,
                reads,
                fail_at,
            }),
            BASE as u64,
            LENGTH as u64,
        )
    }
    fn volume(self) -> NtfsVolume {
        self.open(Arc::default(), None).unwrap()
    }
}

struct Memory {
    bytes: Vec<u8>,
    reads: Reads,
    fail_at: Option<u64>,
}
impl ByteDevice for Memory {
    fn len_bytes(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, data: &mut [u8]) -> Result<()> {
        self.reads.lock().unwrap().push((offset.0, data.len()));
        if self.fail_at == Some(offset.0) {
            return Err(FfsError::Cancelled);
        }
        let at = usize::try_from(offset.0)
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
        let end = at
            .checked_add(data.len())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
        let bytes = self
            .bytes
            .get(at..end)
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
        data.copy_from_slice(bytes);
        Ok(())
    }
    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _data: &[u8]) -> Result<()> {
        panic!("native NTFS read attempted a write");
    }
    fn sync(&self, _cx: &Cx) -> Result<()> {
        panic!("native NTFS read attempted a flush");
    }
}

#[test]
fn fragmented_mft_resident_and_named_streams_preserve_identity_and_eof() {
    let cx = Cx::for_testing();
    let volume = Image::new().volume();
    assert_eq!(volume.record_count(), 32);
    let record = volume.record(&cx, 24, Some(7)).unwrap();
    let unnamed = volume.data_stream(&cx, &record, &[]).unwrap();
    assert!(unnamed.resident());
    assert_eq!(volume.read(&cx, &unnamed, 0, 1024).unwrap(), b"resident!");
    assert_eq!(volume.read(&cx, &unnamed, 3, 2).unwrap(), b"id");
    assert_eq!(
        volume.read(&cx, &unnamed, u64::MAX, 1).unwrap(),
        [] as [u8; 0]
    );
    let named = volume
        .data_stream(&cx, &record, &[110, 111, 116, 101])
        .unwrap();
    assert_eq!(volume.read(&cx, &named, 0, 1024).unwrap(), b"named stream");
    assert!(matches!(
        volume.data_stream(&cx, &record, &[88]),
        Err(FfsError::NotFound(_))
    ));
    assert!(matches!(
        volume.record(&cx, 24, Some(8)),
        Err(FfsError::Corruption { .. })
    ));
    assert!(matches!(
        volume.record(&cx, u64::MAX, None),
        Err(FfsError::NotFound(_))
    ));
}

#[test]
fn fragmented_data_reads_cross_runs_without_exposing_cluster_slack() {
    let cx = Cx::for_testing();
    let volume = Image::new().volume();
    let record = volume.record(&cx, 25, None).unwrap();
    let stream = volume.data_stream(&cx, &record, &[]).unwrap();
    let mut expected = vec![b'A'; 512];
    expected.extend_from_slice(&[b'B'; 88]);
    assert_eq!(stream.allocated, 1024);
    assert_eq!(volume.read(&cx, &stream, 0, 4096).unwrap(), expected);
    assert_eq!(
        volume.read(&cx, &stream, 510, 100).unwrap(),
        expected[510..]
    );
    assert_eq!(volume.read(&cx, &stream, 600, 100).unwrap(), [] as [u8; 0]);
    assert!(volume.read(&cx, &stream, 0, MAX_READ + 1).is_err());
}

#[test]
fn sparse_holes_and_valid_data_tail_are_zero_without_physical_reads() {
    let cx = Cx::for_testing();
    let reads: Reads = Arc::default();
    let volume = Image::new().open(Arc::clone(&reads), None).unwrap();
    let record = volume.record(&cx, 26, None).unwrap();
    let stream = volume.data_stream(&cx, &record, &[]).unwrap();
    assert_eq!(stream.allocated, 1024);
    reads.lock().unwrap().clear();
    let mut expected = vec![0; 2035];
    expected[..512].fill(b'C');
    expected[1536..1543].fill(b'D');
    assert_eq!(volume.read(&cx, &stream, 0, 4096).unwrap(), expected);
    assert_eq!(
        *reads.lock().unwrap(),
        [(BASE as u64 + 200 * 512, 512), (BASE as u64 + 190 * 512, 7)]
    );
    reads.lock().unwrap().clear();
    assert_eq!(volume.read(&cx, &stream, 512, 1024).unwrap(), vec![0; 1024]);
    assert_eq!(volume.read(&cx, &stream, 1543, 100).unwrap(), vec![0; 100]);
    assert_eq!(*reads.lock().unwrap(), [] as [(u64, usize); 0]);
}

#[test]
fn malformed_and_disagreeing_mft_bootstrap_never_fall_back_silently() {
    for torn in [false, true] {
        let mut image = Image::new();
        let at = BASE + 128 * 512;
        image.bytes[at + if torn { 1023 } else { 16 }] ^= 1;
        assert!(image.open(Arc::default(), None).is_err());
    }
    let mut image = Image::new();
    let r = file_record(
        0,
        &[mapped(&[0x11, 16, 5, 0x11, 48, 35, 0], 64, 32768, 32768, 0)],
    );
    image.put_record(0, &r);
    image.bytes[BASE + 128 * 512..BASE + 130 * 512].copy_from_slice(&r);
    assert!(image.open(Arc::default(), None).is_err());
}

#[test]
fn volume_flags_versions_and_out_of_bounds_ranges_refuse_admission() {
    for (major, minor, flags) in [(3, 1, 1_u16), (3, 0, 0), (4, 0, 0)] {
        let mut image = Image::new();
        let mut info = [0; 12];
        info[8] = major;
        info[9] = minor;
        info[10..12].copy_from_slice(&flags.to_le_bytes());
        image.put_record(
            3,
            &file_record(3, &[resident(VOLUME_INFORMATION, 0, "", &info)]),
        );
        assert!(matches!(
            image.open(Arc::default(), None),
            Err(FfsError::UnsupportedFeature(_))
        ));
    }
    let reads: Reads = Arc::default();
    for (base, length) in [(u64::MAX, 512), (1, 1024), (0, 511)] {
        let device = Box::new(Memory {
            bytes: vec![0; 1024],
            reads: Arc::clone(&reads),
            fail_at: None,
        });
        assert!(NtfsVolume::from_device(&Cx::for_testing(), device, base, length).is_err());
    }
    assert_eq!(*reads.lock().unwrap(), [] as [(u64, usize); 0]);
}

#[test]
fn attribute_lists_efs_compression_and_ambiguous_streams_never_return_partial_data() {
    let cx = Cx::for_testing();
    for case in 0..4 {
        let mut image = Image::new();
        let mut attr = resident(DATA, 0, "", b"not a complete supported stream");
        let mut attrs = Vec::new();
        match case {
            0 => attrs.push(resident(ATTRIBUTE_LIST, 1, "", &[])),
            1 => attr[12..14].copy_from_slice(&0x4000_u16.to_le_bytes()),
            2 => attr[12..14].copy_from_slice(&1_u16.to_le_bytes()),
            _ => attrs.push(resident(DATA, 1, "", b"duplicate")),
        }
        attrs.push(attr);
        image.put_record(24, &file_record(24, &attrs));
        let volume = image.volume();
        let record = volume.record(&cx, 24, None).unwrap();
        assert!(volume.data_stream(&cx, &record, &[]).is_err());
    }
}

#[test]
fn invalid_mapping_and_uninitialized_file_records_are_not_successful_short_reads() {
    let cx = Cx::for_testing();
    let mut image = Image::new();
    image.put_record(
        25,
        &file_record(25, &[mapped(&[0x11, 1, 100, 0], 2, 600, 600, 0)]),
    );
    let volume = image.volume();
    let record = volume.record(&cx, 25, None).unwrap();
    assert!(volume.data_stream(&cx, &record, &[]).is_err());
    let mut image = Image::new();
    let mut r = file_record(24, &[resident(DATA, 0, "", b"deleted")]);
    r[22] = 0;
    image.put_record(24, &r);
    assert!(matches!(
        image.volume().record(&cx, 24, None),
        Err(FfsError::NotFound(_))
    ));
}

#[test]
fn data_read_cancellation_discards_the_current_buffer_without_retry() {
    let cx = Cx::for_testing();
    let reads: Reads = Arc::default();
    let volume = Image::new()
        .open(Arc::clone(&reads), Some(BASE as u64 + 170 * 512))
        .unwrap();
    let record = volume.record(&cx, 25, None).unwrap();
    let stream = volume.data_stream(&cx, &record, &[]).unwrap();
    reads.lock().unwrap().clear();
    assert!(matches!(
        volume.read(&cx, &stream, 0, 600),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(reads.lock().unwrap().len(), 2);
}

#[test]
fn actual_file_backing_and_adjacent_partition_bytes_remain_unchanged() {
    let image = Image::new();
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("disk.img");
    std::fs::write(&path, &image.bytes).unwrap();
    let cx = Cx::for_testing();
    let volume = NtfsVolume::open(&cx, &path, BASE as u64, Some(LENGTH as u64)).unwrap();
    let record = volume.record(&cx, 25, Some(7)).unwrap();
    let stream = volume.data_stream(&cx, &record, &[]).unwrap();
    assert_eq!(volume.read(&cx, &stream, 0, 1024).unwrap().len(), 600);
    assert_eq!(std::fs::read(&path).unwrap(), image.bytes);
}

fn build_lfs_rcrd_entry(
    (this_lsn, prev_lsn, undo_next_lsn): (u64, u64, u64),
    (tx_id, record_type): (u32, u32),
    (redo_op, undo_op): (u16, u16),
    (virtual_cluster, physical_cluster): (u64, u64),
    attribute_offset: u16,
    redo_data: &[u8],
    undo_data: &[u8],
) -> Vec<u8> {
    // A 1024-byte FILE spans two 512-byte clusters in this fixture.
    let redo_off = 48_usize;
    let undo_off = (redo_off + redo_data.len()).next_multiple_of(8);
    let client_len = (undo_off + undo_data.len()).next_multiple_of(8);
    let mut rec = vec![0_u8; 48 + client_len];
    rec[0..8].copy_from_slice(&this_lsn.to_le_bytes());
    rec[8..16].copy_from_slice(&prev_lsn.to_le_bytes());
    rec[16..24].copy_from_slice(&undo_next_lsn.to_le_bytes());
    rec[24..28].copy_from_slice(&(client_len as u32).to_le_bytes());
    rec[28..30].copy_from_slice(&9_u16.to_le_bytes());
    rec[32..36].copy_from_slice(&record_type.to_le_bytes());
    rec[36..40].copy_from_slice(&tx_id.to_le_bytes());
    let body = &mut rec[48..];
    body[0..2].copy_from_slice(&redo_op.to_le_bytes());
    body[2..4].copy_from_slice(&undo_op.to_le_bytes());
    body[4..6].copy_from_slice(&(redo_off as u16).to_le_bytes());
    body[6..8].copy_from_slice(&(redo_data.len() as u16).to_le_bytes());
    body[8..10].copy_from_slice(&(undo_off as u16).to_le_bytes());
    body[10..12].copy_from_slice(&(undo_data.len() as u16).to_le_bytes());
    body[12..14].copy_from_slice(&0x18_u16.to_le_bytes());
    if physical_cluster != 0 {
        body[14..16].copy_from_slice(&2_u16.to_le_bytes());
        body[16..18].copy_from_slice(&56_u16.to_le_bytes());
        body[32..40].copy_from_slice(&physical_cluster.to_le_bytes());
        body[40..48].copy_from_slice(&(physical_cluster + 1).to_le_bytes());
    }
    body[18..20].copy_from_slice(&attribute_offset.to_le_bytes());
    body[24..32].copy_from_slice(&virtual_cluster.to_le_bytes());
    body[redo_off..redo_off + redo_data.len()].copy_from_slice(redo_data);
    body[undo_off..undo_off + undo_data.len()].copy_from_slice(undo_data);
    rec
}

#[test]
fn logfile_aries_recovery_redoes_committed_and_undoes_loser_transactions_in_overlay() {
    let cx = Cx::for_testing();
    let mut image = Image::new();
    // A native log needs at least fifty pages. Extend only this fixture's
    // selected partition and place the log beyond every existing data extent.
    let recovery_length = 512 * 1024;
    image.bytes.resize(BASE + recovery_length + 512, 0);
    image.bytes[BASE + recovery_length..].fill(0xD2);
    image.bytes[BASE + 40..BASE + 48]
        .copy_from_slice(&((recovery_length / 512 - 1) as u64).to_le_bytes());
    // Supply real native allocation metadata to the semantic target adapter.
    // Both bootstrap copies retain the same fragmented MFT DATA mapping.
    let mft = file_record(
        0,
        &[
            mapped(&[0x11, 16, 4, 0x11, 48, 36, 0], 64, 32 * 1024, 32 * 1024, 0),
            resident(0xB0, 1, "", &[0xFF; 4]),
        ],
    );
    image.put_record(0, &mft);
    image.bytes[BASE + 128 * 512..BASE + 130 * 512].copy_from_slice(&mft);
    image.put_record(6, &file_record(6, &[resident(DATA, 0, "", &[0xFF; 128])]));
    // Record 25 has uncommitted dirty resident data ("loser-bad") that Undo should revert to "CLEAN-25!".
    image.put_record(25, &file_record(25, &[resident(DATA, 0, "", b"loser-bad")]));
    // Native v1.1 RSTR, open-attribute checkpoint and a later commit/loser.
    // Addresses include the native LSN sequence, not synthetic counters.
    let lsns = [64_u64, 216, 328, 456, 552].map(|offset| (1_u64 << 15) | ((4 * 4096 + offset) / 8));
    let mut rstr_page = vec![0_u8; 4096];
    rstr_page[0..4].copy_from_slice(b"RSTR");
    rstr_page[4..6].copy_from_slice(&32_u16.to_le_bytes());
    rstr_page[6..8].copy_from_slice(&9_u16.to_le_bytes());
    rstr_page[16..20].copy_from_slice(&4096_u32.to_le_bytes());
    rstr_page[20..24].copy_from_slice(&4096_u32.to_le_bytes());
    rstr_page[24..26].copy_from_slice(&64_u16.to_le_bytes());
    rstr_page[26..28].copy_from_slice(&1_i16.to_le_bytes());
    rstr_page[28..30].copy_from_slice(&1_i16.to_le_bytes());
    rstr_page[32..34].copy_from_slice(&0x1111_u16.to_le_bytes());
    // Restart area at offset 64:
    rstr_page[64..72].copy_from_slice(&lsns[1].to_le_bytes());
    rstr_page[72..74].copy_from_slice(&1_u16.to_le_bytes());
    rstr_page[74..76].copy_from_slice(&u16::MAX.to_le_bytes());
    rstr_page[80..84].copy_from_slice(&49_u32.to_le_bytes());
    rstr_page[84..86].copy_from_slice(&224_u16.to_le_bytes());
    rstr_page[86..88].copy_from_slice(&64_u16.to_le_bytes());
    rstr_page[88..96].copy_from_slice(&204_800_u64.to_le_bytes());
    rstr_page[96..100].copy_from_slice(&64_u32.to_le_bytes());
    rstr_page[100..102].copy_from_slice(&48_u16.to_le_bytes());
    rstr_page[102..104].copy_from_slice(&64_u16.to_le_bytes());
    // Client record at area + 64 = offset 128:
    rstr_page[128..136].copy_from_slice(&lsns[0].to_le_bytes());
    rstr_page[136..144].copy_from_slice(&lsns[1].to_le_bytes());
    rstr_page[144..146].copy_from_slice(&u16::MAX.to_le_bytes());
    rstr_page[146..148].copy_from_slice(&u16::MAX.to_le_bytes());
    rstr_page[148..150].copy_from_slice(&9_u16.to_le_bytes());
    rstr_page[156..160].copy_from_slice(&8_u32.to_le_bytes());
    rstr_page[160..168].copy_from_slice(b"N\0T\0F\0S\0");
    let rstr_protected = ffs_ondisk::ntfs::protect_record(&rstr_page).unwrap();

    let mut dump = vec![0; 152];
    dump[..8].copy_from_slice(&lsns[0].to_le_bytes());
    dump[24..28].copy_from_slice(&104_u32.to_le_bytes());
    dump[28..30].copy_from_slice(&9_u16.to_le_bytes());
    dump[32..36].copy_from_slice(&1_u32.to_le_bytes());
    dump[36..40].copy_from_slice(&24_u32.to_le_bytes());
    let body = &mut dump[48..];
    body[..2].copy_from_slice(&0x1D_u16.to_le_bytes());
    body[4..6].copy_from_slice(&40_u16.to_le_bytes());
    body[6..8].copy_from_slice(&64_u16.to_le_bytes());
    body[40..42].copy_from_slice(&40_u16.to_le_bytes());
    body[42..44].copy_from_slice(&1_u16.to_le_bytes());
    body[44..46].copy_from_slice(&1_u16.to_le_bytes());
    body[64..68].copy_from_slice(&u32::MAX.to_le_bytes());
    body[72..76].copy_from_slice(&DATA.to_le_bytes());
    body[80..88].copy_from_slice(&(7_u64 << 48).to_le_bytes());
    let mut checkpoint = vec![0; 112];
    checkpoint[..8].copy_from_slice(&lsns[1].to_le_bytes());
    checkpoint[24..28].copy_from_slice(&64_u32.to_le_bytes());
    checkpoint[28..30].copy_from_slice(&9_u16.to_le_bytes());
    checkpoint[32..36].copy_from_slice(&2_u32.to_le_bytes());
    let body = &mut checkpoint[48..];
    body[..4].copy_from_slice(&1_u32.to_le_bytes());
    body[8..16].copy_from_slice(&lsns[1].to_le_bytes());
    body[16..24].copy_from_slice(&lsns[0].to_le_bytes());
    body[48..52].copy_from_slice(&64_u32.to_le_bytes());

    // v1.1 reserves two restart pages and two tail slots before its ring.
    let mut rcrd_page = vec![0_u8; 4096];
    rcrd_page[0..4].copy_from_slice(b"RCRD");
    rcrd_page[4..6].copy_from_slice(&40_u16.to_le_bytes());
    rcrd_page[6..8].copy_from_slice(&9_u16.to_le_bytes());
    rcrd_page[8..16].copy_from_slice(&lsns[4].to_le_bytes());
    rcrd_page[16..20].copy_from_slice(&1_u32.to_le_bytes());
    rcrd_page[20..22].copy_from_slice(&1_u16.to_le_bytes());
    rcrd_page[22..24].copy_from_slice(&1_u16.to_le_bytes());
    rcrd_page[32..40].copy_from_slice(&lsns[4].to_le_bytes());
    rcrd_page[40..42].copy_from_slice(&0x2222_u16.to_le_bytes());

    let rec24_lcn = ((Image::record_offset(24) - BASE) / 512) as u64;
    let rec25_lcn = ((Image::record_offset(25) - BASE) / 512) as u64;
    // Keep the native MFT VCN and attribute-relative offset distinct from LCN.
    let e1 = build_lfs_rcrd_entry(
        (lsns[2], 0, 0),
        (1, 1),
        (0x07, 0x07),
        (48, rec24_lcn),
        24,
        b"COMMITTED",
        b"resident!",
    );
    let e2 = build_lfs_rcrd_entry(
        (lsns[3], lsns[2], 0),
        (1, 1),
        (0x1A, 0x00),
        (0, 0),
        0,
        &[],
        &[],
    );
    let e3 = build_lfs_rcrd_entry(
        (lsns[4], 0, 0),
        (2, 1),
        (0x07, 0x07),
        (50, rec25_lcn),
        24,
        b"loser-bad",
        b"CLEAN-25!",
    );
    let mut pos = 64_usize;
    for entry in [&dump, &checkpoint, &e1, &e2, &e3] {
        rcrd_page[pos..pos + entry.len()].copy_from_slice(entry);
        pos += entry.len();
    }
    rcrd_page[24..26].copy_from_slice(&(pos as u16).to_le_bytes());
    let rcrd_protected = ffs_ondisk::ntfs::protect_record(&rcrd_page).unwrap();

    let log_base = BASE + 256 * 512;
    image.bytes[log_base..log_base + 204_800].fill(0xFF);
    image.bytes[log_base..log_base + 4096].copy_from_slice(&rstr_protected);
    image.bytes[log_base + 4096..log_base + 8192].copy_from_slice(&rstr_protected);
    image.bytes[log_base + 16_384..log_base + 20_480].copy_from_slice(&rcrd_protected);
    // 400 clusters at LCN 256, independently encoded with two-byte fields.
    image.put_record(
        2,
        &file_record(
            2,
            &[mapped(&[0x22, 0x90, 1, 0, 1, 0], 400, 204_800, 204_800, 0)],
        ),
    );

    // 1. Open without recovery: sees unrecovered on-disk bytes.
    let unrecovered = NtfsVolume::from_device_with_options(
        &cx,
        Box::new(Memory {
            bytes: image.bytes.clone(),
            reads: Arc::default(),
            fail_at: None,
        }),
        BASE as u64,
        recovery_length as u64,
        false,
    )
    .unwrap();
    assert!(unrecovered.logfile_recovery.is_none());
    let rec24_raw = unrecovered.record(&cx, 24, Some(7)).unwrap();
    let s24_raw = unrecovered.data_stream(&cx, &rec24_raw, &[]).unwrap();
    assert_eq!(
        unrecovered.read(&cx, &s24_raw, 0, 64).unwrap(),
        b"resident!"
    );
    let rec25_raw = unrecovered.record(&cx, 25, Some(7)).unwrap();
    let s25_raw = unrecovered.data_stream(&cx, &rec25_raw, &[]).unwrap();
    assert_eq!(
        unrecovered.read(&cx, &s25_raw, 0, 64).unwrap(),
        b"loser-bad"
    );

    // 2. Open with ARIES recovery: Redo commits record 24, Undo reverts loser record 25.
    let recovered = NtfsVolume::from_device_with_options(
        &cx,
        Box::new(Memory {
            bytes: image.bytes,
            reads: Arc::default(),
            fail_at: None,
        }),
        BASE as u64,
        recovery_length as u64,
        true,
    )
    .unwrap();
    let plan = recovered
        .logfile_recovery
        .as_ref()
        .expect("recovery plan present");
    assert_eq!(plan.committed_transactions, vec![1]);
    assert_eq!(plan.aborted_transactions, vec![2]);
    assert_eq!(plan.redo_actions.len(), 2);
    assert_eq!(plan.undo_actions.len(), 1);

    let rec24 = recovered.record(&cx, 24, Some(7)).unwrap();
    let s24 = recovered.data_stream(&cx, &rec24, &[]).unwrap();
    assert_eq!(recovered.read(&cx, &s24, 0, 64).unwrap(), b"COMMITTED");

    let rec25 = recovered.record(&cx, 25, Some(7)).unwrap();
    let s25 = recovered.data_stream(&cx, &rec25, &[]).unwrap();
    assert_eq!(recovered.read(&cx, &s25, 0, 64).unwrap(), b"CLEAN-25!");
}

mod attributes;
mod ea;
mod namespace;
mod security;
pub(super) mod wof;
