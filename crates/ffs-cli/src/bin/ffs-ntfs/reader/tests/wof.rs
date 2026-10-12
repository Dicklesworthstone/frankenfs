use super::attributes::{extension, list_entry};
use super::*;

const BACKING: &str = "WofCompressedData";

pub(in crate::reader) fn provider_value(algorithm: u32, flags: Option<u32>) -> Vec<u8> {
    let mut value = vec![0; 8];
    value[..4].copy_from_slice(&0x8000_0017_u32.to_le_bytes());
    for word in [1_u32, 2, 1, algorithm] {
        value.extend(word.to_le_bytes());
    }
    if let Some(flags) = flags {
        value.extend(flags.to_le_bytes());
    }
    let payload_bytes = u16::try_from(value.len() - 8).unwrap();
    value[4..6].copy_from_slice(&payload_bytes.to_le_bytes());
    value
}

pub(in crate::reader) fn repeated_xpress(byte: u8, length: usize) -> Vec<u8> {
    assert!((274..=65_536).contains(&length));
    // Native canonical codes: this literal = 0, distance-one long match = 1.
    let mut value = vec![0; 256];
    value[usize::from(byte) / 2] = if byte.is_multiple_of(2) { 1 } else { 0x10 };
    value[135] = 0x10;
    value.extend([0, 0x40, 0, 0, 0xFF]);
    value.extend(u16::try_from(length - 4).unwrap().to_le_bytes());
    value
}

pub(in crate::reader) fn placeholder(size: usize, initialized: usize) -> Vec<u8> {
    let clusters = size.div_ceil(512);
    let mut attr = mapped(
        &[1, u8::try_from(clusters).unwrap(), 0],
        clusters as u64,
        size as u64,
        initialized as u64,
        SPARSE,
    );
    attr[34..36].fill(0);
    attr[64..72].fill(0);
    attr
}

pub(in crate::reader) fn named_mapping(pairs: &[u8], clusters: usize, size: usize) -> Vec<u8> {
    let name: Vec<_> = BACKING.encode_utf16().collect();
    let start = (64 + name.len() * 2).next_multiple_of(8);
    let length = (start + pairs.len()).next_multiple_of(8);
    let mut attr = vec![0; length];
    attr[..4].copy_from_slice(&DATA.to_le_bytes());
    attr[4..8].copy_from_slice(&u32::try_from(length).unwrap().to_le_bytes());
    attr[8] = 1;
    attr[9] = u8::try_from(name.len()).unwrap();
    attr[10..12].copy_from_slice(&64_u16.to_le_bytes());
    attr[14..16].copy_from_slice(&1_u16.to_le_bytes());
    attr[24..32].copy_from_slice(&(clusters as u64 - 1).to_le_bytes());
    attr[32..34].copy_from_slice(&u16::try_from(start).unwrap().to_le_bytes());
    attr[40..48].copy_from_slice(&(clusters as u64 * 512).to_le_bytes());
    attr[48..56].copy_from_slice(&(size as u64).to_le_bytes());
    attr[56..64].copy_from_slice(&(size as u64).to_le_bytes());
    for (index, unit) in name.iter().enumerate() {
        attr[64 + index * 2..66 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    attr[start..start + pairs.len()].copy_from_slice(pairs);
    attr
}

pub(in crate::reader) fn encoded_chunks(chunk: usize) -> (Vec<u8>, Vec<u8>) {
    let compressed = repeated_xpress(b'A', chunk);
    let mut raw: Vec<_> = (0..chunk).map(|index| (index % 251) as u8).collect();
    // Exact stored length identifies a raw chunk even with this valid header.
    raw[..compressed.len()].copy_from_slice(&compressed);
    let tail = b"final partial native WOF chunk bytes!";
    assert_eq!(tail.len(), 37);
    let mut stored = Vec::new();
    stored.extend(u32::try_from(compressed.len()).unwrap().to_le_bytes());
    stored.extend(
        u32::try_from(compressed.len() + raw.len())
            .unwrap()
            .to_le_bytes(),
    );
    stored.extend(&compressed);
    stored.extend(&raw);
    stored.extend(tail);
    let mut expected = vec![b'A'; chunk];
    expected.extend(&raw);
    expected.extend(tail);
    (stored, expected)
}

fn native_attributes(
    algorithm: u32,
    logical: usize,
    initialized: usize,
    stored: usize,
) -> Vec<Vec<u8>> {
    let clusters = stored.div_ceil(512);
    let mut standard = [0; 72];
    standard[32..36].copy_from_slice(&0x600_u32.to_le_bytes());
    vec![
        resident(0x10, 2, "", &standard),
        placeholder(logical, initialized),
        named_mapping(
            &[
                0x21,
                1,
                180,
                0,
                0x11,
                u8::try_from(clusters - 1).unwrap(),
                0xD8,
                0,
            ],
            clusters,
            stored,
        ),
        resident(0xC0, 3, "", &provider_value(algorithm, Some(0))),
        resident(DATA, 4, "note", b"independent raw ADS"),
    ]
}

fn write_backing(image: &mut Image, stored: &[u8]) {
    let first = BASE + 180 * 512;
    image.bytes[first..first + 512].fill(0xE7);
    image.bytes[first..first + 512].copy_from_slice(&stored[..512]);
    let second = BASE + 140 * 512;
    let rest = &stored[512..];
    image.bytes[second..second + rest.len().next_multiple_of(512)].fill(0xE7);
    image.bytes[second..second + rest.len()].copy_from_slice(rest);
}

fn native_image(
    algorithm: u32,
    chunk: usize,
    initialized: Option<usize>,
) -> (Image, Vec<u8>, Vec<u8>) {
    let (stored, expected) = encoded_chunks(chunk);
    let mut image = Image::new();
    let attrs = native_attributes(
        algorithm,
        expected.len(),
        initialized.unwrap_or(expected.len()),
        stored.len(),
    );
    image.put_record(24, &file_record(24, &attrs));
    write_backing(&mut image, &stored);
    (image, stored, expected)
}

#[test]
fn all_xpress_modes_read_fragmented_raw_and_compressed_chunks_and_catalog_without_payload_io() {
    let cx = Cx::for_testing();
    for (algorithm, chunk) in [(0, 4096), (2, 8192), (3, 16_384)] {
        let (image, stored, expected) = native_image(algorithm, chunk, None);
        let reads: Reads = Arc::default();
        let volume = image.open(Arc::clone(&reads), None).unwrap();
        let record = volume.record(&cx, 24, Some(7)).unwrap();
        reads.lock().unwrap().clear();
        let stream = volume.data_stream(&cx, &record, &[]).unwrap();
        let catalog = volume.data_streams(&cx, &record).unwrap();
        assert_eq!(catalog.len(), 3);
        let logical = catalog[0].read_profile.as_ref().unwrap();
        assert_eq!(logical.size, expected.len() as u64);
        assert_eq!(logical.initialized, logical.size);
        assert_eq!(logical.allocated, stored.len().next_multiple_of(512) as u64);
        assert!(!logical.resident);
        assert!(reads.lock().unwrap().is_empty());
        assert_eq!(volume.read(&cx, &stream, 0, 65_536).unwrap(), expected);
        for (offset, size) in [(0, 1), (chunk - 3, 9), (2 * chunk - 3, 100)] {
            let end = (offset + size).min(expected.len());
            assert_eq!(
                volume.read(&cx, &stream, offset as u64, size).unwrap(),
                expected[offset..end],
            );
        }
        assert_eq!(
            volume.read(&cx, &stream, u64::MAX, 5).unwrap(),
            [] as [u8; 0]
        );
        assert_eq!(
            volume.read(&cx, &stream, expected.len() as u64, 1).unwrap(),
            [] as [u8; 0]
        );
        let raw = volume
            .data_stream(&cx, &record, &BACKING.encode_utf16().collect::<Vec<_>>())
            .unwrap();
        assert_eq!(volume.read(&cx, &raw, 0, 65_536).unwrap(), stored);
        assert!(reads.lock().unwrap().iter().all(|(at, size)| {
            *at >= BASE as u64 && *at + *size as u64 <= (BASE + LENGTH) as u64
        }));
    }
}

#[test]
fn native_valid_data_length_hides_uninitialized_bytes_without_reading_sparse_placeholder() {
    let cx = Cx::for_testing();
    let (image, _, mut expected) = native_image(0, 4096, Some(4090));
    expected[4090..].fill(0);
    let reads: Reads = Arc::default();
    let volume = image.open(Arc::clone(&reads), None).unwrap();
    let record = volume.record(&cx, 24, None).unwrap();
    let stream = volume.data_stream(&cx, &record, &[]).unwrap();
    assert_eq!(stream.initialized, 4090);
    reads.lock().unwrap().clear();
    assert_eq!(volume.read(&cx, &stream, 0, 20_000).unwrap(), expected);
    assert_eq!(
        *reads.lock().unwrap(),
        [
            ((BASE + 180 * 512) as u64, 4),
            ((BASE + 180 * 512 + 8) as u64, 263),
        ]
    );
    reads.lock().unwrap().clear();
    assert_eq!(volume.read(&cx, &stream, 4090, 100).unwrap(), vec![0; 100]);
    assert!(reads.lock().unwrap().is_empty());
}

#[test]
fn known_file_provider_preserves_raw_ads_for_unsupported_codec_but_not_efs_or_other_providers() {
    let cx = Cx::for_testing();
    for algorithm in [1, 4, u32::MAX] {
        let (image, stored, _) = native_image(algorithm, 4096, None);
        let volume = image.volume();
        let record = volume.record(&cx, 24, None).unwrap();
        assert!(matches!(
            volume.data_stream(&cx, &record, &[]),
            Err(FfsError::UnsupportedFeature(_))
        ));
        let raw = volume
            .data_stream(&cx, &record, &BACKING.encode_utf16().collect::<Vec<_>>())
            .unwrap();
        assert_eq!(volume.read(&cx, &raw, 0, 10_000).unwrap(), stored);
        let catalog = volume.data_streams(&cx, &record).unwrap();
        assert!(catalog[0].read_profile.is_err());
        assert!(catalog[1..].iter().all(|entry| entry.read_profile.is_ok()));
    }
    for case in 0..4 {
        let (mut image, stored, expected) = native_image(0, 4096, None);
        let mut attrs = native_attributes(0, expected.len(), expected.len(), stored.len());
        let mut point = provider_value(0, Some(0));
        match case {
            0 => {
                let mut standard = [0; 72];
                standard[32..36].copy_from_slice(&0x4600_u32.to_le_bytes());
                attrs[0] = resident(0x10, 2, "", &standard);
            }
            1 => point[12..16].copy_from_slice(&1_u32.to_le_bytes()),
            2 => point[24..28].copy_from_slice(&1_u32.to_le_bytes()),
            _ => point[..4].copy_from_slice(&0x9000_001A_u32.to_le_bytes()),
        }
        attrs[3] = resident(0xC0, 3, "", &point);
        image.put_record(24, &file_record(24, &attrs));
        let reads: Reads = Arc::default();
        let volume = image.open(Arc::clone(&reads), None).unwrap();
        let record = volume.record(&cx, 24, None).unwrap();
        reads.lock().unwrap().clear();
        for name in [Vec::new(), BACKING.encode_utf16().collect()] {
            assert!(matches!(
                volume.data_stream(&cx, &record, &name),
                Err(FfsError::UnsupportedFeature(_))
            ));
        }
        assert!(reads.lock().unwrap().is_empty());
    }
}

#[test]
fn corrupt_chunk_offsets_and_late_decode_failures_never_return_a_successful_prefix() {
    let cx = Cx::for_testing();
    for first_end in [0_u32, 5000, u32::MAX] {
        let (mut image, _, _) = native_image(0, 4096, None);
        let at = BASE + 180 * 512;
        image.bytes[at..at + 4].copy_from_slice(&first_end.to_le_bytes());
        let reads: Reads = Arc::default();
        let volume = image.open(Arc::clone(&reads), None).unwrap();
        let record = volume.record(&cx, 24, None).unwrap();
        let stream = volume.data_stream(&cx, &record, &[]).unwrap();
        reads.lock().unwrap().clear();
        assert!(matches!(
            volume.read(&cx, &stream, 0, 1),
            Err(FfsError::Corruption { .. })
        ));
        assert_eq!(*reads.lock().unwrap(), [(at as u64, 4)]);
    }
    let (mut image, _, _) = native_image(0, 4096, None);
    // The decoder must validate the complete first chunk even for a one-byte read.
    let at = BASE + 180 * 512 + 8 + 261;
    image.bytes[at..at + 2].copy_from_slice(&4093_u16.to_le_bytes());
    let volume = image.volume();
    let record = volume.record(&cx, 24, None).unwrap();
    let stream = volume.data_stream(&cx, &record, &[]).unwrap();
    assert!(matches!(
        volume.read(&cx, &stream, 0, 1),
        Err(FfsError::Corruption { .. })
    ));

    let (mut image, _, _) = native_image(0, 4096, None);
    // First chunk decodes, but the second offset is less than its predecessor.
    image.bytes[BASE + 180 * 512 + 4..BASE + 180 * 512 + 8].copy_from_slice(&262_u32.to_le_bytes());
    let volume = image.volume();
    let record = volume.record(&cx, 24, None).unwrap();
    let stream = volume.data_stream(&cx, &record, &[]).unwrap();
    assert!(matches!(
        volume.read(&cx, &stream, 0, 5000),
        Err(FfsError::Corruption { .. })
    ));
}

#[test]
fn table_payload_and_later_raw_extent_cancellation_are_propagated_without_retry() {
    let cx = Cx::for_testing();
    for offset in [BASE + 180 * 512, BASE + 180 * 512 + 8, BASE + 140 * 512] {
        let (image, _, _) = native_image(0, 4096, None);
        let reads: Reads = Arc::default();
        let volume = image.open(Arc::clone(&reads), Some(offset as u64)).unwrap();
        let record = volume.record(&cx, 24, None).unwrap();
        let stream = volume.data_stream(&cx, &record, &[]).unwrap();
        reads.lock().unwrap().clear();
        assert!(matches!(
            volume.read(&cx, &stream, 0, 9000),
            Err(FfsError::Cancelled)
        ));
        assert_eq!(
            reads
                .lock()
                .unwrap()
                .iter()
                .filter(|(at, _)| *at == offset as u64)
                .count(),
            1
        );
    }
}

#[test]
fn nonresident_provider_metadata_cancellation_fails_catalog_and_data_open() {
    let cx = Cx::for_testing();
    let (mut image, stored, expected) = native_image(0, 4096, None);
    let mut attrs = native_attributes(0, expected.len(), expected.len(), stored.len());
    let point = provider_value(0, None);
    let at = BASE + 190 * 512;
    image.bytes[at..at + point.len()].copy_from_slice(&point);
    let mut reparse = mapped(
        &[0x21, 1, 190, 0, 0],
        1,
        point.len() as u64,
        point.len() as u64,
        0,
    );
    reparse[..4].copy_from_slice(&0xC0_u32.to_le_bytes());
    reparse[14..16].copy_from_slice(&3_u16.to_le_bytes());
    attrs[3] = reparse;
    image.put_record(24, &file_record(24, &attrs));
    let volume = image.open(Arc::default(), Some(at as u64)).unwrap();
    let record = volume.record(&cx, 24, None).unwrap();
    assert!(matches!(
        volume.data_streams(&cx, &record),
        Err(FfsError::Cancelled)
    ));
    assert!(matches!(
        volume.data_stream(&cx, &record, &[]),
        Err(FfsError::Cancelled)
    ));
}

#[test]
fn provider_and_fragmented_backing_in_attribute_list_extensions_keep_native_identity() {
    let cx = Cx::for_testing();
    let (mut image, stored, expected) = native_image(0, 4096, None);
    let attrs = native_attributes(0, expected.len(), expected.len(), stored.len());
    let clusters = stored.len().div_ceil(512);
    let mut first = named_mapping(&[0x21, 1, 180, 0, 0], clusters, stored.len());
    first[24..32].fill(0);
    let mut last = named_mapping(
        &[0x21, u8::try_from(clusters - 1).unwrap(), 140, 0, 0],
        clusters,
        0,
    );
    last[14..16].copy_from_slice(&5_u16.to_le_bytes());
    last[16..24].copy_from_slice(&1_u64.to_le_bytes());
    last[40..64].fill(0xFF); // Only VCN zero owns the native size fields.
    let mut list = list_entry(0x10, 24, 2, 0, "");
    list.extend(list_entry(DATA, 24, 0, 0, ""));
    list.extend(list_entry(DATA, 24, 1, 0, BACKING));
    list.extend(list_entry(DATA, 27, 5, 1, BACKING));
    list.extend(list_entry(DATA, 24, 4, 0, "note"));
    list.extend(list_entry(0xC0, 27, 3, 0, ""));
    image.put_record(
        24,
        &file_record(
            24,
            &[
                attrs[0].clone(),
                attrs[1].clone(),
                first,
                attrs[4].clone(),
                resident(ATTRIBUTE_LIST, 9, "", &list),
            ],
        ),
    );
    let extension_record = extension(27, 24, &[last, attrs[3].clone()]);
    image.put_record(27, &extension_record);
    let before = image.bytes.clone();
    let volume = image.volume();
    let record = volume.record(&cx, 24, Some(7)).unwrap();
    let stream = volume.data_stream(&cx, &record, &[]).unwrap();
    assert_eq!(volume.read(&cx, &stream, 0, 10_000).unwrap(), expected);
    let catalog = volume.data_streams(&cx, &record).unwrap();
    assert_eq!(catalog[1].attribute_extents, 2);

    let mut stale = Image { bytes: before };
    let mut wrong = extension_record;
    wrong[32..40].copy_from_slice(&(24_u64 | (8_u64 << 48)).to_le_bytes());
    stale.put_record(27, &wrong);
    let volume = stale.volume();
    let record = volume.record(&cx, 24, None).unwrap();
    assert!(matches!(
        volume.data_stream(&cx, &record, &[]),
        Err(FfsError::Corruption { .. })
    ));
}

#[test]
fn single_partial_compressed_chunk_uses_exact_logical_length_and_resident_backing() {
    let cx = Cx::for_testing();
    for logical in [300, 299] {
        let mut image = Image::new();
        let mut standard = [0; 72];
        standard[32..36].copy_from_slice(&0x600_u32.to_le_bytes());
        image.put_record(
            24,
            &file_record(
                24,
                &[
                    resident(0x10, 2, "", &standard),
                    placeholder(logical, logical),
                    resident(DATA, 1, BACKING, &repeated_xpress(b'Q', 300)),
                    resident(0xC0, 3, "", &provider_value(0, None)),
                ],
            ),
        );
        let volume = image.volume();
        let record = volume.record(&cx, 24, None).unwrap();
        let stream = volume.data_stream(&cx, &record, &[]).unwrap();
        assert_eq!(stream.allocated, 0);
        let result = volume.read(&cx, &stream, 0, 500);
        if logical == 300 {
            assert_eq!(result.unwrap(), vec![b'Q'; 300]);
        } else {
            assert!(matches!(result, Err(FfsError::Corruption { .. })));
        }
    }
}

#[test]
fn backing_and_placeholder_admission_rejects_incomplete_or_transformed_values_without_payload_io() {
    let cx = Cx::for_testing();
    for case in 0..5 {
        let (mut image, stored, expected) = native_image(0, 4096, None);
        let mut attrs = native_attributes(0, expected.len(), expected.len(), stored.len());
        match case {
            0 => {
                attrs[1] = mapped(
                    &[0x21, 17, 200, 0, 0],
                    17,
                    expected.len() as u64,
                    expected.len() as u64,
                    0,
                )
            }
            1 => attrs[2][56..64].copy_from_slice(&(stored.len() as u64 - 1).to_le_bytes()),
            2 => attrs[2][12..14].copy_from_slice(&0x4000_u16.to_le_bytes()),
            3 => attrs[2][12..14].copy_from_slice(&SPARSE.to_le_bytes()),
            _ => {
                attrs.remove(2);
            }
        }
        image.put_record(24, &file_record(24, &attrs));
        let reads: Reads = Arc::default();
        let volume = image.open(Arc::clone(&reads), None).unwrap();
        let record = volume.record(&cx, 24, None).unwrap();
        reads.lock().unwrap().clear();
        assert!(volume.data_stream(&cx, &record, &[]).is_err());
        assert!(reads.lock().unwrap().is_empty());
    }
}

#[test]
fn actual_image_and_adjacent_partitions_remain_byte_identical_after_wof_reads() {
    let (image, _, expected) = native_image(2, 8192, None);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("wof.img");
    std::fs::write(&path, &image.bytes).unwrap();
    let cx = Cx::for_testing();
    let volume = NtfsVolume::open(&cx, &path, BASE as u64, Some(LENGTH as u64)).unwrap();
    let record = volume.record(&cx, 24, Some(7)).unwrap();
    let stream = volume.data_stream(&cx, &record, &[]).unwrap();
    assert_eq!(volume.read(&cx, &stream, 0, 30_000).unwrap(), expected);
    assert_eq!(std::fs::read(&path).unwrap(), image.bytes);
}
