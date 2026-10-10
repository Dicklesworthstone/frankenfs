use super::*;
use std::sync::{Arc, Mutex};

type Reads = Arc<Mutex<Vec<(u64, usize)>>>;
const BASE: usize = 1024;
const LENGTH: usize = 256 * 512;

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
    for (i, unit) in name.iter().enumerate() { a[24 + i * 2..26 + i * 2].copy_from_slice(&unit.to_le_bytes()); }
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

struct Image { bytes: Vec<u8> }
impl Image {
    fn new() -> Self {
        let mut image = Self { bytes: vec![0; BASE + LENGTH + 512] };
        image.bytes[..BASE].fill(0xD1);
        image.bytes[BASE + LENGTH..].fill(0xD2);
        let b = &mut image.bytes[BASE..BASE + 512];
        b[3..11].copy_from_slice(b"NTFS    ");
        b[11..13].copy_from_slice(&512_u16.to_le_bytes());
        b[13] = 1;
        b[21] = 0xF8;
        b[40..48].copy_from_slice(&255_u64.to_le_bytes());
        b[48..56].copy_from_slice(&4_u64.to_le_bytes());
        b[56..64].copy_from_slice(&128_u64.to_le_bytes());
        b[64] = 0xF6;
        b[68] = 0xF4;
        b[510..512].copy_from_slice(&[0x55, 0xAA]);
        let mft = file_record(0, &[mapped(&[0x11, 16, 4, 0x11, 48, 36, 0], 64, 32 * 1024, 32 * 1024, 0)]);
        image.put_record(0, &mft);
        image.bytes[BASE + 128 * 512..BASE + 130 * 512].copy_from_slice(&mft);
        let mut info = [0; 12];
        info[8..10].copy_from_slice(&[3, 1]);
        image.put_record(3, &file_record(3, &[resident(VOLUME_INFORMATION, 0, "", &info)]));
        image.put_record(24, &file_record(24, &[
            resident(DATA, 0, "", b"resident!"), resident(DATA, 1, "note", b"named stream")
        ]));
        image.put_record(25, &file_record(25, &[
            mapped(&[0x21, 1, 180, 0, 0x11, 1, 0xF6, 0], 2, 600, 600, 0)
        ]));
        image.put_record(26, &file_record(26, &[
            mapped(&[0x21, 1, 200, 0, 0x01, 2, 0x11, 1, 0xF6, 0], 4, 2035, 1543, SPARSE)
        ]));
        for (lcn, value) in [(180, b'A'), (170, b'B'), (200, b'C'), (190, b'D')] {
            image.bytes[BASE + lcn * 512..BASE + (lcn + 1) * 512].fill(value);
        }
        image
    }
    fn record_offset(number: usize) -> usize {
        // Deliberately fragmented MFT: record 8 onward lives in a second extent.
        BASE + if number < 8 { 4 * 512 + number * 1024 } else { 40 * 512 + (number - 8) * 1024 }
    }
    fn put_record(&mut self, number: usize, record: &[u8]) {
        let at = Self::record_offset(number);
        self.bytes[at..at + 1024].copy_from_slice(record);
    }
    fn open(self, reads: Reads, fail_at: Option<u64>) -> Result<NtfsVolume> {
        NtfsVolume::from_device(&Cx::for_testing(), Box::new(Memory {
            bytes: self.bytes, reads, fail_at,
        }), BASE as u64, LENGTH as u64)
    }
    fn volume(self) -> NtfsVolume { self.open(Arc::default(), None).unwrap() }
}

struct Memory { bytes: Vec<u8>, reads: Reads, fail_at: Option<u64> }
impl ByteDevice for Memory {
    fn len_bytes(&self) -> u64 { self.bytes.len() as u64 }
    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, data: &mut [u8]) -> Result<()> {
        self.reads.lock().unwrap().push((offset.0, data.len()));
        if self.fail_at == Some(offset.0) { return Err(FfsError::Cancelled); }
        let at = usize::try_from(offset.0).map_err(|_| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
        let end = at.checked_add(data.len()).ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
        let bytes = self.bytes.get(at..end).ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
        data.copy_from_slice(bytes);
        Ok(())
    }
    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _data: &[u8]) -> Result<()> {
        panic!("native NTFS read attempted a write");
    }
    fn sync(&self, _cx: &Cx) -> Result<()> { panic!("native NTFS read attempted a flush"); }
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
    assert!(volume.read(&cx, &unnamed, u64::MAX, 1).unwrap().is_empty());
    let named = volume.data_stream(&cx, &record, &[110, 111, 116, 101]).unwrap();
    assert_eq!(volume.read(&cx, &named, 0, 1024).unwrap(), b"named stream");
    assert!(matches!(volume.data_stream(&cx, &record, &[88]), Err(FfsError::NotFound)));
    assert!(matches!(volume.record(&cx, 24, Some(8)), Err(FfsError::Corruption { .. })));
    assert!(matches!(volume.record(&cx, u64::MAX, None), Err(FfsError::NotFound)));
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
    assert_eq!(volume.read(&cx, &stream, 510, 100).unwrap(), expected[510..]);
    assert!(volume.read(&cx, &stream, 600, 100).unwrap().is_empty());
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
    assert_eq!(*reads.lock().unwrap(), [(BASE as u64 + 200 * 512, 512), (BASE as u64 + 190 * 512, 7)]);
    reads.lock().unwrap().clear();
    assert_eq!(volume.read(&cx, &stream, 512, 1024).unwrap(), vec![0; 1024]);
    assert_eq!(volume.read(&cx, &stream, 1543, 100).unwrap(), vec![0; 100]);
    assert!(reads.lock().unwrap().is_empty());
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
    let r = file_record(0, &[mapped(&[0x11, 16, 5, 0x11, 48, 35, 0], 64, 32768, 32768, 0)]);
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
        image.put_record(3, &file_record(3, &[resident(VOLUME_INFORMATION, 0, "", &info)]));
        assert!(matches!(image.open(Arc::default(), None), Err(FfsError::UnsupportedFeature(_))));
    }
    let reads: Reads = Arc::default();
    for (base, length) in [(u64::MAX, 512), (1, 1024), (0, 511)] {
        let device = Box::new(Memory { bytes: vec![0; 1024], reads: Arc::clone(&reads), fail_at: None });
        assert!(NtfsVolume::from_device(&Cx::for_testing(), device, base, length).is_err());
    }
    assert!(reads.lock().unwrap().is_empty());
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
    image.put_record(25, &file_record(25, &[mapped(&[0x11, 1, 100, 0], 2, 600, 600, 0)]));
    let volume = image.volume();
    let record = volume.record(&cx, 25, None).unwrap();
    assert!(volume.data_stream(&cx, &record, &[]).is_err());
    let mut image = Image::new();
    let mut r = file_record(24, &[resident(DATA, 0, "", b"deleted")]);
    r[22] = 0;
    image.put_record(24, &r);
    assert!(matches!(image.volume().record(&cx, 24, None), Err(FfsError::NotFound)));
}

#[test]
fn data_read_cancellation_discards_the_current_buffer_without_retry() {
    let cx = Cx::for_testing();
    let reads: Reads = Arc::default();
    let volume = Image::new().open(Arc::clone(&reads), Some(BASE as u64 + 170 * 512)).unwrap();
    let record = volume.record(&cx, 25, None).unwrap();
    let stream = volume.data_stream(&cx, &record, &[]).unwrap();
    reads.lock().unwrap().clear();
    assert!(matches!(volume.read(&cx, &stream, 0, 600), Err(FfsError::Cancelled)));
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
