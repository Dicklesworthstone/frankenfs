#![expect(
    clippy::single_range_in_vec_init,
    reason = "expected allocation maps are lists that may hold a single range"
)]

use super::*;

fn words(values: &[u64], order: Endian) -> Vec<u8> {
    values.iter().flat_map(|word| order.encode(*word)).collect()
}

fn decode(values: &[u64], order: Endian, v2: bool) -> Result<Vec<Record>, ParseError> {
    Records::new(&words(values, order), order, v2)?.collect()
}

#[test]
fn bonus_lengths_signed_counts_and_histograms_are_independent_of_obsolete_identity() {
    for order in [Endian::Little, Endian::Big] {
        for length in [0, 8, u64::MAX - 7] {
            for allocated in [i64::MIN, -1, 0, 512, i64::MAX] {
                let raw = words(&[u64::MAX, length, allocated.cast_unsigned()], order);
                let header = Header::parse(&raw, order).unwrap();
                assert_eq!((header.length, header.allocated, header.histogram), (length, allocated, None));
                let mut extended = raw;
                extended.resize(320, 0);
                extended[64 + 31 * 8..].copy_from_slice(&order.encode(73));
                assert_eq!(Header::parse(&extended, order).unwrap().histogram.unwrap()[31], 73);
                extended[24] = 1;
                assert!(Header::parse(&extended, order).is_err());
            }
        }
        assert!(Header::parse(&words(&[0, 9, 0], order), order).is_err());
    }
    for length in 0..=321 {
        if !matches!(length, 24 | 320) {
            assert!(Header::parse(&vec![0; length], Endian::Little).is_err());
        }
    }
}

#[test]
fn one_word_zero_is_an_allocation_and_high_offset_bit_is_not_debug() {
    for order in [Endian::Little, Endian::Big] {
        for offset in [0, 1, (1 << 46) - 1, 1 << 46, (1 << 47) - 1] {
            for run in [1, 2, 32768] {
                for action in [0_u64, 1] {
                    let records = decode(&[(offset << 16) | (action << 15) | (run - 1)], order, false).unwrap();
                    assert_eq!(records, [Record::Extent(Extent {
                        kind: if action == 0 { MapType::Allocate } else { MapType::Free },
                        vdev: None, offset_units: offset, run_units: run,
                    })]);
                }
            }
        }
    }
}

#[test]
fn two_word_maxima_and_native_vdev_ids_do_not_lose_bits() {
    for order in [Endian::Little, Endian::Big] {
        for offset in [0, 1 << 47, (1 << 63) - 1] {
            for run in [1, 32769, 1_u64 << 36] {
                for vdev in [0, 1, 0x00ff_ffff] {
                    for action in [0_u64, 1] {
                        let raw = [(3 << 62) | ((run - 1) << 24) | vdev, (action << 63) | offset];
                        assert_eq!(decode(&raw, order, true).unwrap(), [Record::Extent(Extent {
                            kind: if action == 0 { MapType::Allocate } else { MapType::Free },
                            vdev: Some(vdev as u32), offset_units: offset, run_units: run,
                        })]);
                        assert!(decode(&raw, order, false).is_err());
                    }
                }
            }
        }
    }
}

#[test]
fn debug_and_block_padding_are_not_allocation_entries() {
    for order in [Endian::Little, Endian::Big] {
        let debug = (2_u64 << 62) | (1 << 60) | (1023 << 50) | ((1 << 50) - 1);
        assert_eq!(decode(&[debug, 2 << 62, 0], order, true).unwrap(), [
            Record::Debug { kind: MapType::Free, txg: (1 << 50) - 1, sync_pass: 1023 },
            Record::Debug { kind: MapType::Allocate, txg: 0, sync_pass: 0 },
            Record::Extent(Extent { kind: MapType::Allocate, vdev: None, offset_units: 0, run_units: 1 }),
        ]);
        for bad in [(2 << 62) | (2 << 60) | 1, (2 << 62) | (1 << 60), (2 << 62) | (1 << 50)] {
            assert!(decode(&[bad], order, true).is_err());
        }
    }
}

#[test]
fn partial_records_cannot_cross_blocks_and_errors_are_terminal() {
    for order in [Endian::Little, Endian::Big] {
        let raw = words(&[0, 3 << 62], order);
        let mut records = Records::new(&raw, order, true).unwrap();
        assert!(records.next().unwrap().is_ok());
        assert!(records.next().unwrap().is_err());
        assert!(records.next().is_none());
        assert!(records.next().is_none());
        let padded = words(&[2 << 62; 64], order);
        assert_eq!(Records::new(&padded, order, true).unwrap().count(), 64);
        assert!(decode(&[(3 << 62) | (1 << 60), 0], order, true).is_err());
        assert!(decode(&[(3 << 62) | (1 << 61), 0], order, true).is_err());
    }
    for length in 1..16 {
        if length != 8 { assert!(Records::new(&vec![0; length], Endian::Little, true).is_err()); }
    }
    assert!(Records::new(&[], Endian::Little, true).unwrap().next().is_none());
}

#[test]
fn checked_unit_translation_cannot_wrap_or_escape_the_selected_region() {
    let entry = Extent { kind: MapType::Allocate, vdev: None, offset_units: 2, run_units: 3 };
    assert_eq!(entry.byte_range(4096, 4096, 9).unwrap(), 5120..6656);
    for (start, size, shift) in [(1, 4096, 9), (4096, 1, 9), (0, 0, 9), (0, 4096, 64), (u64::MAX - 7, 16, 0)] {
        assert!(entry.byte_range(start, size, shift).is_err());
    }
    for (offset, run) in [(0, 0), (8, 1), (7, 2), (1_u64 << 63, 1), (0, 1_u64 << 63)] {
        let bad = Extent { offset_units: offset, run_units: run, ..entry };
        assert!(bad.byte_range(4096, 4096, 9).is_err());
    }
}

#[test]
fn range_map_merges_neighbors_splits_frees_and_reuses_allocations() {
    let mut map = AllocationMap::new(4096, 8192, 9, 8).unwrap();
    map.apply(MapType::Allocate, 4096..5120).unwrap();
    map.apply(MapType::Allocate, 6144..8192).unwrap();
    map.apply(MapType::Allocate, 5120..6144).unwrap();
    assert_eq!(map.ranges().collect::<Vec<_>>(), [4096..8192]);
    map.apply(MapType::Free, 5120..6144).unwrap();
    assert_eq!(map.ranges().collect::<Vec<_>>(), [4096..5120, 6144..8192]);
    assert_eq!(map.allocated_bytes(), 3072);
    map.apply(MapType::Allocate, 5120..6144).unwrap();
    map.apply(MapType::Free, 4096..8192).unwrap();
    assert_eq!((map.range_count(), map.allocated_bytes()), (0, 0));
}

#[test]
#[expect(clippy::reversed_empty_ranges, reason = "a reversed range is deliberately invalid input")]
fn invalid_ranges_double_allocation_and_double_free_leave_the_map_unchanged() {
    let mut map = AllocationMap::new(4096, 4096, 9, 8).unwrap();
    map.apply(MapType::Allocate, 4096..5120).unwrap();
    map.apply(MapType::Allocate, 6144..7168).unwrap();
    for (kind, range) in [
        (MapType::Allocate, 4608..5632), (MapType::Allocate, 3584..4096),
        (MapType::Allocate, 8192..8704), (MapType::Allocate, 5121..6144),
        (MapType::Free, 4096..7168), (MapType::Free, 5120..6144),
        (MapType::Free, 4096..4096), (MapType::Free, 5120..4096),
    ] {
        let before = map.clone();
        assert!(map.apply(kind, range).is_err());
        assert_eq!(map, before);
    }
}

#[test]
fn range_budget_counts_splits_but_permits_coalescing_at_capacity() {
    let mut map = AllocationMap::new(0, 8192, 9, 1).unwrap();
    map.apply(MapType::Allocate, 0..4096).unwrap();
    let before = map.clone();
    assert!(map.apply(MapType::Free, 512..1024).is_err());
    assert_eq!(map, before);
    assert!(map.apply(MapType::Allocate, 4608..5120).is_err());
    assert_eq!(map, before);
    map.apply(MapType::Allocate, 4096..5120).unwrap();
    assert_eq!(map.ranges().collect::<Vec<_>>(), [0..5120]);
    map.apply(MapType::Free, 0..512).unwrap();
    assert_eq!(map.ranges().collect::<Vec<_>>(), [512..5120]);
}

#[test]
fn all_small_bitmap_states_match_independent_allocation_and_free_semantics() {
    for mask in 0_u64..256 {
        let mut baseline = AllocationMap::new(0, 8, 0, 8).unwrap();
        for bit in 0..8 {
            if mask & (1 << bit) != 0 { baseline.apply(MapType::Allocate, bit..bit + 1).unwrap(); }
        }
        for start in 0..8 {
            for end in start + 1..=8 {
                let selected = ((1 << (end - start)) - 1) << start;
                for kind in [MapType::Allocate, MapType::Free] {
                    let admitted = if kind == MapType::Allocate { mask & selected == 0 } else { mask & selected == selected };
                    let mut map = baseline.clone();
                    assert_eq!(map.apply(kind, start..end).is_ok(), admitted);
                    if !admitted { assert_eq!(map, baseline); continue; }
                    let expected = if kind == MapType::Allocate { mask | selected } else { mask & !selected };
                    let mut actual = 0_u64;
                    for range in map.ranges() { for bit in range { actual |= 1 << bit; } }
                    assert_eq!(actual, expected);
                    assert_eq!(map.allocated_bytes(), u64::from(expected.count_ones()));
                }
            }
        }
    }
}

#[test]
fn enormous_sparse_regions_cost_ranges_not_sectors() {
    let mut map = AllocationMap::new(0, 1_u64 << 63, 9, 2).unwrap();
    map.apply(MapType::Allocate, 0..1_u64 << 63).unwrap();
    map.apply(MapType::Free, 512..(1_u64 << 63) - 512).unwrap();
    assert_eq!(map.range_count(), 2);
    assert_eq!(map.allocated_bytes(), 1024);
    assert_eq!(map.ranges().collect::<Vec<_>>(), [0..512, (1_u64 << 63) - 512..1_u64 << 63]);
}
