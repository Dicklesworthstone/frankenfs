use super::*;

fn provider(algorithm: u32, flags: Option<u32>) -> NtfsReparsePoint {
    let mut bytes = Vec::new();
    for value in [1_u32, 2, 1, algorithm] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    if let Some(flags) = flags {
        bytes.extend_from_slice(&flags.to_le_bytes());
    }
    NtfsReparsePoint {
        tag: TAG,
        guid: None,
        data: NtfsReparseData::Opaque(bytes),
    }
}

#[test]
fn native_file_provider_versions_identify_xpress_and_preserve_raw_codec_choices() {
    for flags in [None, Some(0)] {
        for (algorithm, expected) in [(0, 4096), (2, 8192), (3, 16_384)] {
            let value = FileProvider::parse(&provider(algorithm, flags)).unwrap();
            assert_eq!(value.algorithm, algorithm);
            assert_eq!(value.chunk_bytes().unwrap(), expected);
        }
        // Provider identity is still known when its logical codec is absent.
        // Explicitly selected named DATA remains a stored native value.
        for algorithm in [1, 4, u32::MAX] {
            let value = FileProvider::parse(&provider(algorithm, flags)).unwrap();
            assert_eq!(value.algorithm, algorithm);
            assert!(value.chunk_bytes().is_err());
        }
    }
}

#[test]
fn other_providers_flags_versions_and_metadata_shapes_are_never_admitted() {
    for flags in [1, u32::MAX] {
        assert!(FileProvider::parse(&provider(0, Some(flags))).is_err());
    }
    for (at, word) in [(0, 0_u32), (0, 2), (4, 1), (4, 3), (8, 0), (8, 2)] {
        let mut point = provider(0, None);
        let NtfsReparseData::Opaque(bytes) = &mut point.data else {
            panic!("opaque")
        };
        bytes[at..at + 4].copy_from_slice(&word.to_le_bytes());
        assert!(FileProvider::parse(&point).is_err());
    }
    for length in (0..=24).filter(|length| !matches!(length, 16 | 20)) {
        let mut point = provider(0, Some(0));
        let NtfsReparseData::Opaque(bytes) = &mut point.data else {
            panic!("opaque")
        };
        bytes.resize(length, 0);
        assert!(FileProvider::parse(&point).is_err(), "length {length}");
    }
    let mut point = provider(0, None);
    point.tag = 0x9000_001A;
    assert!(FileProvider::parse(&point).is_err());
    point.tag = TAG;
    point.guid = Some([0; 16]);
    assert!(FileProvider::parse(&point).is_err());
}

#[test]
fn native_table_omits_first_and_final_offsets_and_keeps_partial_chunk_size() {
    let layout = ChunkLayout::new(8192 + 37, 8 + 263 + 4096 + 37, 4096).unwrap();
    assert_eq!(
        (layout.chunks, layout.table_bytes, layout.offset_bytes),
        (3, 8, 4)
    );
    assert_eq!(layout.table_window(0).unwrap(), (0, 4));
    assert_eq!(layout.table_window(1).unwrap(), (0, 8));
    assert_eq!(layout.table_window(2).unwrap(), (4, 4));
    assert_eq!(
        layout.chunk_range(0, &263_u32.to_le_bytes()).unwrap(),
        (8, 263, 4096)
    );
    let mut middle = 263_u32.to_le_bytes().to_vec();
    middle.extend_from_slice(&4359_u32.to_le_bytes());
    assert_eq!(layout.chunk_range(1, &middle).unwrap(), (271, 4096, 4096));
    assert_eq!(
        layout.chunk_range(2, &4359_u32.to_le_bytes()).unwrap(),
        (4367, 37, 37)
    );
    assert!(layout.table_window(3).is_err());

    let single = ChunkLayout::new(300, 263, 4096).unwrap();
    assert_eq!(single.table_window(0).unwrap(), (0, 0));
    assert_eq!(single.chunk_range(0, &[]).unwrap(), (0, 263, 300));
}

#[test]
fn four_gib_boundary_uses_native_u64_offsets_without_allocating_the_table() {
    let narrow = ChunkLayout::new(u64::from(u32::MAX), 4_299_161_595, 4096).unwrap();
    assert_eq!((narrow.offset_bytes, narrow.table_bytes), (4, 4_194_300));
    let logical = (1_u64 << 32) + 17;
    let wide = ChunkLayout::new(logical, logical + 8_388_608, 4096).unwrap();
    assert_eq!(
        (wide.chunks, wide.offset_bytes, wide.table_bytes),
        (1_048_577, 8, 8_388_608)
    );
    assert_eq!(wide.table_window(1_048_576).unwrap(), (8_388_600, 8));
    assert_eq!(
        wide.chunk_range(1_048_576, &(1_u64 << 32).to_le_bytes())
            .unwrap(),
        ((1_u64 << 32) + 8_388_608, 17, 17),
    );
    assert!(wide.chunk_range(1_048_576, &0_u32.to_le_bytes()).is_err());
    assert!(
        wide.chunk_range(1_048_576, &u64::MAX.to_le_bytes())
            .is_err()
    );
}

#[test]
fn bad_chunk_ranges_cannot_be_read_as_zeroes_or_adjacent_file_bytes() {
    let layout = ChunkLayout::new(8192 + 37, 8 + 263 + 4096 + 37, 4096).unwrap();
    for boundary in [0_u32, 4097, 4397, u32::MAX] {
        assert!(layout.chunk_range(0, &boundary.to_le_bytes()).is_err());
    }
    for (start, end) in [(263_u32, 263_u32), (264, 263), (1, 4396), (263, u32::MAX)] {
        let mut pair = start.to_le_bytes().to_vec();
        pair.extend_from_slice(&end.to_le_bytes());
        assert!(layout.chunk_range(1, &pair).is_err());
    }
    assert!(layout.chunk_range(0, &[1, 0, 0]).is_err());
    assert!(layout.chunk_range(2, &4358_u32.to_le_bytes()).is_err()); // 38 > final 37.
    assert!(layout.chunk_range(2, &4396_u32.to_le_bytes()).is_err()); // Empty final chunk.
}

#[test]
fn empty_and_impossible_file_lengths_have_explicit_bounded_behavior() {
    let empty = ChunkLayout::new(0, 0, 4096).unwrap();
    assert_eq!(
        (empty.chunks, empty.table_bytes, empty.payload_bytes),
        (0, 0, 0)
    );
    assert!(empty.table_window(0).is_err());
    assert!(ChunkLayout::new(0, 1, 4096).is_err());
    assert!(ChunkLayout::new(8192, 3, 4096).is_err());
    assert!(ChunkLayout::new(8192, 5, 4096).is_err());
    assert!(ChunkLayout::new(8192, 4 + 8193, 4096).is_err());
    for chunk in [0, 1, 2048, 32768, usize::MAX] {
        assert!(ChunkLayout::new(1, 1, chunk).is_err());
    }
}
