//! Independent mapping capture plus bounded reconstruction adversaries.
//!
//! The twenty map vectors were emitted by the verbatim OpenZFS zfs-2.3.0
//! vdev_raidz_map_alloc function in a small C isolation harness, compiled with
//! gcc -std=c11 -O2 -Wall -Wextra -Werror and executed successfully.
//! Native source blob: 6103f780e6bc9b6a7ca88f8d2265076bd94d04c4.
//! Harness blob: 87fef865322b5da72b815da6cdbff9592bebbebd.
//! Exact capture blob: cb2711393a6f00c23e1ea6354e7cee99212ebe9a.
//! This is native-function capture, not native pool or mount interoperability.

use super::*;

type NativeColumn = (usize, u64, usize, usize);
type NativeCase = (usize, u8, u64, usize, u64, &'static [NativeColumn]);

const NATIVE_MAPS: &[NativeCase] = &[
    (2, 9, 0, 512, 1024, &[(0, 0, 512, 512), (1, 0, 512, 512)]),
    (3, 9, 0, 512, 1024, &[(0, 0, 512, 512), (1, 0, 512, 512)]),
    (
        3,
        9,
        512,
        1024,
        2048,
        &[(1, 0, 512, 1024), (2, 0, 512, 512), (0, 512, 512, 512)],
    ),
    (
        4,
        9,
        1536,
        1024,
        2048,
        &[
            (3, 0, 512, 512),
            (0, 512, 512, 512),
            (1, 512, 512, 512),
            (2, 512, 0, 512),
        ],
    ),
    (
        4,
        9,
        0,
        2560,
        4096,
        &[
            (0, 0, 1024, 1024),
            (1, 0, 1024, 1024),
            (2, 0, 1024, 1024),
            (3, 0, 512, 1024),
        ],
    ),
    (
        5,
        9,
        1_048_576,
        2048,
        3072,
        &[
            (4, 209_408, 512, 512),
            (3, 209_408, 512, 1024),
            (0, 209_920, 512, 512),
            (1, 209_920, 512, 512),
            (2, 209_920, 512, 512),
        ],
    ),
    (
        8,
        9,
        1_052_160,
        5120,
        6144,
        &[
            (0, 131_584, 1024, 1024),
            (7, 131_072, 1024, 1024),
            (1, 131_584, 1024, 1024),
            (2, 131_584, 1024, 1024),
            (3, 131_584, 512, 512),
            (4, 131_584, 512, 512),
            (5, 131_584, 512, 512),
            (6, 131_584, 512, 512),
        ],
    ),
    (
        3,
        12,
        4096,
        512,
        8192,
        &[(1, 0, 4096, 4096), (2, 0, 4096, 4096)],
    ),
    (
        5,
        12,
        1_064_960,
        12_800,
        24_576,
        &[
            (1, 212_992, 4096, 4096),
            (0, 212_992, 4096, 8192),
            (2, 212_992, 4096, 4096),
            (3, 212_992, 4096, 4096),
            (4, 212_992, 4096, 4096),
        ],
    ),
    (
        8,
        16,
        1_507_328,
        512,
        131_072,
        &[(0, 196_608, 65_536, 65_536), (7, 131_072, 65_536, 65_536)],
    ),
    (
        8,
        16,
        1_048_576,
        16_777_216,
        19_267_584,
        &[
            (1, 131_072, 2_424_832, 2_424_832),
            (0, 131_072, 2_424_832, 2_424_832),
            (2, 131_072, 2_424_832, 2_424_832),
            (3, 131_072, 2_424_832, 2_424_832),
            (4, 131_072, 2_424_832, 2_424_832),
            (5, 131_072, 2_359_296, 2_424_832),
            (6, 131_072, 2_359_296, 2_359_296),
            (7, 131_072, 2_359_296, 2_359_296),
        ],
    ),
    (
        6,
        9,
        2560,
        3584,
        5120,
        &[
            (5, 0, 1024, 1024),
            (0, 512, 1024, 1024),
            (1, 512, 1024, 1024),
            (2, 512, 512, 1024),
            (3, 512, 512, 512),
            (4, 512, 512, 512),
        ],
    ),
    (
        7,
        12,
        24_576,
        33_280,
        49_152,
        &[
            (6, 0, 8192, 8192),
            (0, 4096, 8192, 8192),
            (1, 4096, 8192, 8192),
            (2, 4096, 8192, 8192),
            (3, 4096, 4096, 8192),
            (4, 4096, 4096, 4096),
            (5, 4096, 4096, 4096),
        ],
    ),
    (
        2,
        16,
        1_048_576,
        16_777_216,
        33_554_432,
        &[
            (1, 524_288, 16_777_216, 16_777_216),
            (0, 524_288, 16_777_216, 16_777_216),
        ],
    ),
    (
        3,
        9,
        2_097_152,
        2560,
        4096,
        &[
            (1, 698_880, 1536, 1536),
            (2, 698_880, 1536, 1536),
            (0, 699_392, 1024, 1024),
        ],
    ),
    (
        4,
        12,
        1_044_480,
        16_384,
        24_576,
        &[
            (3, 258_048, 8192, 8192),
            (0, 262_144, 8192, 8192),
            (1, 262_144, 4096, 4096),
            (2, 262_144, 4096, 4096),
        ],
    ),
    (
        4,
        12,
        1_048_576,
        16_384,
        24_576,
        &[
            (1, 262_144, 8192, 8192),
            (0, 262_144, 8192, 8192),
            (2, 262_144, 4096, 4096),
            (3, 262_144, 4096, 4096),
        ],
    ),
    (
        8,
        9,
        0,
        32_768,
        37_888,
        &[
            (0, 0, 5120, 5120),
            (1, 0, 5120, 5120),
            (2, 0, 4608, 4608),
            (3, 0, 4608, 4608),
            (4, 0, 4608, 4608),
            (5, 0, 4608, 4608),
            (6, 0, 4608, 4608),
            (7, 0, 4608, 4608),
        ],
    ),
    (
        5,
        12,
        0,
        4096,
        8192,
        &[(0, 0, 4096, 4096), (1, 0, 4096, 4096)],
    ),
    (
        5,
        12,
        0,
        8192,
        16_384,
        &[
            (0, 0, 4096, 4096),
            (1, 0, 4096, 4096),
            (2, 0, 4096, 4096),
            (3, 0, 0, 4096),
        ],
    ),
];

#[test]
fn maps_match_twenty_executed_native_function_captures() {
    for &(width, ashift, offset, physical, allocated, columns) in NATIVE_MAPS {
        let map = Raidz1Map::new(offset, physical, ashift, width).unwrap();
        assert_eq!(map.allocated_bytes(), allocated);
        let actual: Vec<_> = map
            .columns()
            .iter()
            .map(|column| {
                (
                    column.child_id,
                    column.offset,
                    column.bytes,
                    column.allocated_bytes,
                )
            })
            .collect();
        assert_eq!(
            actual, columns,
            "width={width}, ashift={ashift}, offset={offset}, PSIZE={physical}"
        );
        let mut logical = 0;
        for (index, column) in map.columns().iter().enumerate() {
            if index == 0 || columns[index].2 == 0 {
                assert_eq!(column.data_offset, None);
            } else {
                assert_eq!(column.data_offset, Some(logical));
                logical += columns[index].2;
            }
        }
        assert_eq!(logical, map.aligned_bytes());
        assert_eq!(logical, physical.next_multiple_of(1 << ashift));
    }
}

fn striped_bytes() -> [Vec<u8>; 4] {
    // Independently specified native P vector: 12^56^9a=de, 34^78=4c.
    // The final data column is short; its absent tail contributes zeroes.
    [
        [vec![0xde; 512], vec![0x4c; 512]].concat(),
        [vec![0x12; 512], vec![0x34; 512]].concat(),
        [vec![0x56; 512], vec![0x78; 512]].concat(),
        vec![0x9a; 512],
    ]
}

#[test]
fn every_single_data_erasure_and_corruption_hypothesis_reconstructs_long_and_short_columns() {
    let storage = striped_bytes();
    let expected = storage[1..].concat();
    for offset in [0, 1536, 1 << 20, (1 << 20) + 1536] {
        let map = Raidz1Map::new(offset, 2560, 9, 4).unwrap();
        let columns: Vec<_> = storage
            .iter()
            .map(|column| Some(column.as_slice()))
            .collect();
        assert_eq!(map.assemble(&columns, None).unwrap(), expected);
        for erased in 1..4 {
            let mut missing = columns.clone();
            missing[erased] = None;
            assert_eq!(map.assemble(&missing, Some(erased)).unwrap(), expected);
            assert!(map.assemble(&missing, None).is_err());
            let corrupt = vec![0xff; storage[erased].len()];
            let mut damaged = columns.clone();
            damaged[erased] = Some(&corrupt);
            assert_ne!(map.assemble(&damaged, None).unwrap(), expected);
            assert_eq!(map.assemble(&damaged, Some(erased)).unwrap(), expected);
        }
    }
}

#[test]
fn missing_parity_allows_intact_data_but_a_second_required_erasure_fails() {
    let map = Raidz1Map::new(0, 2560, 9, 4).unwrap();
    let storage = striped_bytes();
    let expected = storage[1..].concat();
    let columns: Vec<_> = storage
        .iter()
        .map(|column| Some(column.as_slice()))
        .collect();
    let mut missing = columns.clone();
    missing[0] = None;
    assert_eq!(map.assemble(&missing, None).unwrap(), expected);
    for erased in 1..4 {
        assert!(map.assemble(&missing, Some(erased)).is_err());
        missing[erased] = None;
        assert!(map.assemble(&missing, Some(erased)).is_err());
        missing[erased] = columns[erased];
    }
    for first in 1..4 {
        for second in first + 1..4 {
            let mut missing = columns.clone();
            missing[first] = None;
            missing[second] = None;
            assert!(map.assemble(&missing, Some(first)).is_err());
            assert!(map.assemble(&missing, Some(second)).is_err());
        }
    }
    assert!(map.assemble(&columns, Some(0)).is_err());
    assert!(map.assemble(&columns, Some(4)).is_err());
}

#[test]
fn original_psize_excludes_sector_padding_and_skip_sectors() {
    let map = Raidz1Map::new(4096, 512, 12, 3).unwrap();
    let mut parity = vec![0x2a; 4096];
    let mut data = parity.clone();
    data[512..].fill(0xa5);
    parity[512..].fill(0x5a);
    assert_eq!(
        map.assemble(&[None, Some(&data)], None).unwrap(),
        [0x2a; 512]
    );
    assert_eq!(
        map.assemble(&[Some(&parity), None], Some(1)).unwrap(),
        [0x2a; 512]
    );
    assert_eq!(map.aligned_bytes(), 4096);
    assert_eq!(map.allocated_bytes(), 8192);

    let map = Raidz1Map::new(0, 8192, 12, 5).unwrap();
    let parity = vec![0x33; 4096];
    let first = vec![0x11; 4096];
    let second = vec![0x22; 4096];
    let expected = [first.clone(), second.clone()].concat();
    let columns = [
        Some(parity.as_slice()),
        Some(first.as_slice()),
        Some(second.as_slice()),
        None,
    ];
    assert_eq!(map.columns()[3].bytes, 0);
    assert_eq!(map.columns()[3].allocated_bytes, 4096);
    assert_eq!(map.assemble(&columns, None).unwrap(), expected);
    let mut missing = columns;
    missing[1] = None;
    assert_eq!(map.assemble(&missing, Some(1)).unwrap(), expected);
    assert!(map.assemble(&columns, Some(3)).is_err());
    let mut padded = columns;
    padded[3] = Some(&parity);
    assert!(map.assemble(&padded, None).is_err());
}

#[test]
fn malformed_or_incomplete_column_spans_are_not_reconstructed() {
    let map = Raidz1Map::new(0, 2560, 9, 4).unwrap();
    let storage = striped_bytes();
    let columns: Vec<_> = storage
        .iter()
        .map(|column| Some(column.as_slice()))
        .collect();
    assert!(map.assemble(&columns[..3], None).is_err());
    let mut additional = columns.clone();
    additional.push(None);
    assert!(map.assemble(&additional, None).is_err());
    for index in 0..4 {
        let mut short = columns.clone();
        short[index] = Some(&storage[index][..storage[index].len() - 1]);
        assert!(map.assemble(&short, None).is_err());
        assert!(map.assemble(&short, Some(1)).is_err());
        let oversized = vec![0; storage[index].len() + 512];
        let mut extra = columns.clone();
        extra[index] = Some(&oversized);
        assert!(map.assemble(&extra, None).is_err());
    }
}

#[test]
fn invalid_geometry_and_overflow_cannot_create_a_raidz_map() {
    for width in [0, 1, 9, usize::MAX] {
        assert!(Raidz1Map::new(0, 512, 9, width).is_err());
    }
    for ashift in [0, 8, 17, 63, u8::MAX] {
        assert!(Raidz1Map::new(0, 512, ashift, 3).is_err());
    }
    for physical in [0, 1, 511, 513, MAX_BLOCK_BYTES + 512, usize::MAX] {
        assert!(Raidz1Map::new(0, physical, 9, 3).is_err());
    }
    for offset in [1, 511, u64::MAX, u64::MAX - 511] {
        assert!(Raidz1Map::new(offset, 512, 9, 3).is_err());
    }
    assert!(Raidz1Map::new(512, 512, 12, 3).is_err());
    let largest = Raidz1Map::new(0, MAX_BLOCK_BYTES, 16, 2).unwrap();
    assert_eq!(largest.aligned_bytes(), MAX_BLOCK_BYTES);
    assert_eq!(largest.allocated_bytes(), (MAX_BLOCK_BYTES * 2) as u64);
}
