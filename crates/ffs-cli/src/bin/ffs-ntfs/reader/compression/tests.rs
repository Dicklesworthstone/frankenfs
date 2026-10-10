use super::*;
use super::super::{FfsError, Stream};
use ffs_block::ByteDevice;
use ffs_ondisk::ntfs::{COMPRESSED, DATA, NtfsAttribute, NtfsNonResident, NtfsValue, SPARSE};
use ffs_types::ByteOffset;
use std::sync::{Arc, Mutex};

type Reads = Arc<Mutex<Vec<(u64, usize)>>>;
const BASE: u64 = 1024;
const VOLUME_BYTES: usize = 4096 * 512;
const UNIT: usize = 16 * 512;
const SIZE: usize = 2 * UNIT + 7000;
const VALID: usize = 2 * UNIT + 6000;

fn geometry(cluster_sectors: u8) -> NtfsGeometry {
    let mut boot = [0_u8; 512];
    boot[3..11].copy_from_slice(b"NTFS    ");
    boot[11..13].copy_from_slice(&512_u16.to_le_bytes());
    boot[13] = cluster_sectors;
    boot[40..48].copy_from_slice(&4096_u64.to_le_bytes());
    boot[48..56].copy_from_slice(&4_u64.to_le_bytes());
    boot[56..64].copy_from_slice(&128_u64.to_le_bytes());
    boot[64] = 0xF6;
    boot[68] = 0xF4;
    boot[510..].copy_from_slice(&[0x55, 0xAA]);
    NtfsGeometry::parse(&boot, VOLUME_BYTES as u64).unwrap()
}

fn mapped(pairs: &[u8], first: u64, last: u64, size: u64, initialized: u64) -> NtfsAttribute<'_> {
    NtfsAttribute {
        kind: DATA,
        id: 0,
        flags: COMPRESSED,
        name: Vec::new(),
        value: NtfsValue::NonResident(NtfsNonResident {
            first_vcn: first,
            last_vcn: last,
            compression_unit: 4,
            allocated_bytes: last.checked_add(1).unwrap_or(0) * 512,
            data_bytes: size,
            initialized_bytes: initialized,
            mapping_pairs: pairs,
        }),
    }
}

struct Memory {
    bytes: Vec<u8>,
    reads: Reads,
    fail_at: Option<u64>,
}
impl ByteDevice for Memory {
    fn len_bytes(&self) -> u64 { self.bytes.len() as u64 }
    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, data: &mut [u8]) -> Result<()> {
        self.reads.lock().unwrap().push((offset.0, data.len()));
        if self.fail_at == Some(offset.0) { return Err(FfsError::Cancelled); }
        let at = usize::try_from(offset.0).unwrap();
        let bytes = self.bytes.get(at..at + data.len())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
        data.copy_from_slice(bytes);
        Ok(())
    }
    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _data: &[u8]) -> Result<()> {
        panic!("compressed read attempted to write the image");
    }
    fn sync(&self, _cx: &Cx) -> Result<()> {
        panic!("compressed read attempted to flush the image");
    }
}

struct Fixture {
    source: Source,
    geometry: NtfsGeometry,
    expected: Vec<u8>,
    reads: Reads,
    pairs: Vec<u8>,
}
impl Fixture {
    fn new(fail_at: Option<u64>, damage: Option<usize>) -> Self {
        let mut bytes = vec![0xE7; BASE as usize + VOLUME_BYTES + 512];
        let mut raw: Vec<_> = (0..UNIT).map(|i| u8::try_from(i % 251).unwrap()).collect();
        raw[..6].copy_from_slice(&[3, 0xB0, 2, b'A', 0xFC, 0x0F]);
        let at = BASE as usize + 1000 * 512;
        bytes[at..at + UNIT].copy_from_slice(&raw);
        let literal: Vec<_> = (0..4096).map(|i| u8::try_from(i % 239).unwrap()).collect();
        let mut packed = vec![0; 9 * 512];
        packed[..2].copy_from_slice(&0x3FFF_u16.to_le_bytes());
        packed[2..4098].copy_from_slice(&literal);
        packed[4098..4104].copy_from_slice(&[3, 0xB0, 2, b'B', 0xFC, 0x0F]);
        if let Some(at) = damage { packed[at] ^= 0x80; }
        let at = BASE as usize + 1800 * 512;
        bytes[at..at + 4 * 512].copy_from_slice(&packed[..4 * 512]);
        let at = BASE as usize + 1700 * 512;
        bytes[at..at + 5 * 512].copy_from_slice(&packed[4 * 512..]);
        let mut expected = vec![0; SIZE];
        expected[..UNIT].copy_from_slice(&raw);
        expected[2 * UNIT..2 * UNIT + 4096].copy_from_slice(&literal);
        expected[2 * UNIT + 4096..VALID].fill(b'B');
        let reads: Reads = Arc::default();
        let source = Source {
            device: Box::new(Memory { bytes, reads: Arc::clone(&reads), fail_at }),
            base: BASE,
            length: VOLUME_BYTES as u64,
        };
        // Raw 16 clusters; sparse 16; packed 4+5 (backward physical delta),
        // then 7 sparse clusters. Compression crosses a physical run boundary.
        let pairs = vec![0x21, 16, 0xE8, 0x03, 0x01, 16,
            0x21, 4, 0x20, 0x03, 0x11, 5, 0x9C, 0x01, 7, 0];
        Self { source, geometry: geometry(1), expected, reads, pairs }
    }
    fn stream(&self, flags: u16) -> Stream {
        let mut attr = mapped(&self.pairs, 0, 47, SIZE as u64, VALID as u64);
        attr.flags = flags;
        Stream::from_attributes(&self.geometry, &[attr]).unwrap()
    }
    fn read(&self, stream: &Stream, offset: u64, size: usize) -> Result<Vec<u8>> {
        stream.read(&self.source, &self.geometry, &Cx::for_testing(), offset, size)
    }
}

#[test]
fn raw_sparse_and_fragmented_packed_units_preserve_ranges_eof_and_valid_data() {
    let fixture = Fixture::new(None, None);
    for flags in [COMPRESSED, COMPRESSED | SPARSE] {
        let stream = fixture.stream(flags);
        assert_eq!(stream.allocated, 25 * 512);
        assert_eq!(fixture.read(&stream, 0, SIZE + 512).unwrap(), fixture.expected);
        for start in [0, 1, 507, 4090, UNIT - 2, UNIT, 2 * UNIT - 2,
            2 * UNIT, 2 * UNIT + 4090, VALID - 3, VALID, SIZE] {
            let end = (start + 1031).min(SIZE);
            assert_eq!(fixture.read(&stream, start as u64, 1031).unwrap(),
                fixture.expected[start..end], "offset {start}, flags {flags:x}");
        }
        assert!(fixture.read(&stream, u64::MAX, 10).unwrap().is_empty());
        assert!(fixture.read(&stream, 0, super::super::MAX_READ + 1).is_err());
    }
}

#[test]
fn sparse_units_and_uninitialized_tails_do_not_issue_physical_reads() {
    let fixture = Fixture::new(None, None);
    let stream = fixture.stream(COMPRESSED);
    assert_eq!(fixture.read(&stream, UNIT as u64, UNIT).unwrap(), vec![0; UNIT]);
    assert_eq!(fixture.read(&stream, VALID as u64, SIZE).unwrap(), vec![0; SIZE - VALID]);
    assert!(fixture.reads.lock().unwrap().is_empty());
    assert_eq!(fixture.read(&stream, 507, 20).unwrap(), fixture.expected[507..527]);
    assert_eq!(*fixture.reads.lock().unwrap(), [(BASE + 1000 * 512 + 507, 20)]);
    fixture.reads.lock().unwrap().clear();
    let start = 2 * UNIT + 4090;
    assert_eq!(fixture.read(&stream, start as u64, 32).unwrap(), fixture.expected[start..start + 32]);
    assert_eq!(*fixture.reads.lock().unwrap(), [(BASE + 1800 * 512, 2048), (BASE + 1700 * 512, 2560)]);
}

#[test]
fn malformed_payload_and_cancellation_are_errors_not_partial_or_zero_success() {
    // Changing the high header byte clears the compression marker on the
    // second chunk, so it decodes to too few initialized bytes. Even a read
    // of its first byte must reject the incomplete initialized unit.
    let damaged = Fixture::new(None, Some(4099));
    let stream = damaged.stream(COMPRESSED);
    assert!(matches!(damaged.read(&stream, (2 * UNIT) as u64, 1), Err(FfsError::Corruption { .. })));
    let failed = Fixture::new(Some(BASE + 1700 * 512), None);
    let stream = failed.stream(COMPRESSED);
    assert!(matches!(failed.read(&stream, (2 * UNIT) as u64, 1), Err(FfsError::Cancelled)));
    assert_eq!(*failed.reads.lock().unwrap(), [(BASE + 1800 * 512, 2048), (BASE + 1700 * 512, 2560)]);
    failed.reads.lock().unwrap().clear();
    assert!(matches!(failed.read(&stream, 0, SIZE), Err(FfsError::Cancelled)));
    assert_eq!(*failed.reads.lock().unwrap(), [
        (BASE + 1000 * 512, UNIT), (BASE + 1800 * 512, 2048), (BASE + 1700 * 512, 2560),
    ]);
}

#[test]
fn invalid_unit_layouts_and_unsupported_transforms_fail_during_selection() {
    let geometry = geometry(1);
    for pairs in [
        vec![0x21, 1, 0xE8, 3, 0x01, 1, 0x11, 14, 1, 0], // Hole, then data inside a unit.
        vec![0x01, 1, 0x21, 15, 0xE8, 3, 0], // No prefix before the hole.
    ] {
        let attr = mapped(&pairs, 0, 15, UNIT as u64, UNIT as u64);
        assert!(matches!(Stream::from_attributes(&geometry, &[attr]), Err(FfsError::Corruption { .. })));
    }
    let attr = mapped(&[0x01, 15, 0], 0, 14, 1, 1);
    assert!(Stream::from_attributes(&geometry, &[attr]).is_err());
    for flags in [2, 0x4001, 0x0101] {
        let mut attr = mapped(&[0x01, 16, 0], 0, 15, 1, 1);
        attr.flags = flags;
        assert!(matches!(Stream::from_attributes(&geometry, &[attr]), Err(FfsError::UnsupportedFeature(_))));
    }
    let mut attr = mapped(&[0x01, 16, 0], 0, 15, 1, 1);
    attr.kind = 0xA0;
    assert!(Stream::from_attributes(&geometry, &[attr]).is_err());
    let mut attr = mapped(&[0x01, 16, 0], 0, 15, 1, 1);
    let NtfsValue::NonResident(value) = &mut attr.value else { panic!("nonresident"); };
    value.compression_unit = 3;
    assert!(Stream::from_attributes(&geometry, &[attr]).is_err());
}

#[test]
fn unit_mapping_does_not_expand_large_sparse_files() {
    let fixture = Fixture::new(None, None);
    let clusters = 1_048_576_u64;
    let attr = mapped(&[0x04, 0, 0, 0x10, 0, 0], 0, clusters - 1, clusters * 512, clusters * 512);
    let stream = Stream::from_attributes(&fixture.geometry, &[attr]).unwrap();
    assert_eq!(stream.allocated, 0);
    assert_eq!(fixture.read(&stream, 500_000_003, 1031).unwrap(), vec![0; 1031]);
    assert!(fixture.reads.lock().unwrap().is_empty());
}

#[test]
fn compression_units_can_span_attribute_extents_and_named_streams() {
    let fixture = Fixture::new(None, None);
    let first_pairs = [0x21, 16, 0xE8, 3, 0x01, 16, 0x21, 4, 0x20, 3, 0];
    let second_pairs = [0x21, 5, 0xA4, 6, 0x01, 7, 0];
    let mut first = mapped(&first_pairs, 0, 35, SIZE as u64, VALID as u64);
    let mut second = mapped(&second_pairs, 36, 47, u64::MAX, u64::MAX);
    first.name = vec![110, 111, 116, 101];
    second.name = first.name.clone();
    second.id = 1;
    let NtfsValue::NonResident(header) = &mut first.value else { panic!("nonresident"); };
    header.allocated_bytes = 48 * 512; // VCN zero describes the entire stream.
    let NtfsValue::NonResident(tail) = &mut second.value else { panic!("nonresident"); };
    tail.allocated_bytes = u64::MAX; // Undefined continuation sizes are ignored.
    let stream = Stream::from_attributes(&fixture.geometry, &[second, first]).unwrap();
    assert_eq!(fixture.read(&stream, 0, SIZE).unwrap(), fixture.expected);
}

#[test]
fn empty_compressed_stream_and_overlarge_clusters_have_explicit_behavior() {
    let fixture = Fixture::new(None, None);
    let attr = mapped(&[0], 0, u64::MAX, 0, 0);
    let stream = Stream::from_attributes(&fixture.geometry, &[attr]).unwrap();
    assert!(fixture.read(&stream, 0, 100).unwrap().is_empty());
    assert!(fixture.reads.lock().unwrap().is_empty());
    let attr = mapped(&[0], 0, u64::MAX, 0, 0);
    assert!(matches!(Stream::from_attributes(&geometry(16), &[attr]), Err(FfsError::UnsupportedFeature(_))));
}

#[test]
fn coalesced_raw_runs_allow_a_partial_final_compression_unit() {
    let fixture = Fixture::new(None, None);
    let size = UNIT + 1000;
    let attr = mapped(&[0x21, 19, 0xE8, 3, 0], 0, 18, size as u64, size as u64);
    let stream = Stream::from_attributes(&fixture.geometry, &[attr]).unwrap();
    let mut expected = fixture.expected[..UNIT].to_vec();
    expected.extend_from_slice(&[0xE7; 1000]);
    assert_eq!(fixture.read(&stream, 0, size + 100).unwrap(), expected);
    assert_eq!(fixture.read(&stream, (UNIT - 5) as u64, 50).unwrap(), expected[UNIT - 5..UNIT + 45]);
}

#[test]
fn four_kib_clusters_decode_full_sixty_four_kib_units() {
    let mut bytes = vec![0xE7; BASE as usize + VOLUME_BYTES + 512];
    let at = BASE as usize + 100 * 4096;
    for chunk in 0..16 {
        bytes[at + chunk * 6..at + chunk * 6 + 6]
            .copy_from_slice(&[3, 0xB0, 2, b'Z', 0xFC, 0x0F]);
    }
    let reads: Reads = Arc::default();
    let source = Source {
        device: Box::new(Memory { bytes, reads: Arc::clone(&reads), fail_at: None }),
        base: BASE,
        length: VOLUME_BYTES as u64,
    };
    let geometry = geometry(8);
    let mut attr = mapped(&[0x11, 1, 100, 0x01, 15, 0], 0, 15, 65_536, 65_536);
    let NtfsValue::NonResident(value) = &mut attr.value else { panic!("nonresident"); };
    value.allocated_bytes = 65_536;
    let stream = Stream::from_attributes(&geometry, &[attr]).unwrap();
    assert_eq!(stream.allocated, 4096);
    assert_eq!(stream.read(&source, &geometry, &Cx::for_testing(), 0, 65_536).unwrap(), vec![b'Z'; 65_536]);
    assert_eq!(*reads.lock().unwrap(), [(BASE + 100 * 4096, 4096)]);
}
