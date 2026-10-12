use super::attributes::{extension, list_entry};
use super::*;

const SECURITY_LENGTH: usize = 2048 * 512;
const COPY_DISTANCE: usize = 0x4_0000;
const SDS_SIZE: usize = COPY_DISTANCE + 720 + 116;
const INDEX_LCN: usize = 1500;
const DESCRIPTOR_HASH: u32 = 0xF1C7_5D8C;
const DESCRIPTOR: [u8; 96] = [
    1, 0, 4, 128, 20, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 48, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 5, 18, 0,
    0, 0, 1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 32, 2, 0, 0, 2, 0, 48, 0, 2, 0, 0, 0, 1, 18, 20, 0,
    2, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 3, 20, 0, 255, 1, 31, 0, 1, 1, 0, 0, 0, 0,
    0, 5, 18, 0, 0, 0,
];
const SDS_PAIRS: &[u8] = &[0x21, 1, 88, 2, 0x22, 255, 1, 200, 0, 0x21, 2, 88, 2, 0];

fn standard(id: u32, flags: u32) -> [u8; 72] {
    let mut value = [0; 72];
    value[32..36].copy_from_slice(&flags.to_le_bytes());
    value[52..56].copy_from_slice(&id.to_le_bytes());
    value
}

fn security_header(id: u32, offset: u64) -> [u8; 20] {
    let mut value = [0; 20];
    value[..4].copy_from_slice(&DESCRIPTOR_HASH.to_le_bytes());
    value[4..8].copy_from_slice(&id.to_le_bytes());
    value[8..16].copy_from_slice(&offset.to_le_bytes());
    value[16..20].copy_from_slice(&116_u32.to_le_bytes());
    value
}

fn index_key(id: u32, offset: u64, child: Option<u64>) -> Vec<u8> {
    let length = if child.is_some() { 48 } else { 40 };
    let mut value = vec![0; length];
    value[..2].copy_from_slice(&20_u16.to_le_bytes());
    value[2..4].copy_from_slice(&20_u16.to_le_bytes());
    value[8..10].copy_from_slice(&(length as u16).to_le_bytes());
    value[10..12].copy_from_slice(&4_u16.to_le_bytes());
    value[12..14].copy_from_slice(&u16::from(child.is_some()).to_le_bytes());
    value[16..20].copy_from_slice(&id.to_le_bytes());
    value[20..40].copy_from_slice(&security_header(id, offset));
    if let Some(child) = child {
        value[40..48].copy_from_slice(&child.to_le_bytes());
    }
    value
}

fn terminal(child: Option<u64>) -> Vec<u8> {
    let length = if child.is_some() { 24 } else { 16 };
    let mut value = vec![0; length];
    value[8..10].copy_from_slice(&(length as u16).to_le_bytes());
    value[12..14].copy_from_slice(&(2 | u16::from(child.is_some())).to_le_bytes());
    if let Some(child) = child {
        value[16..24].copy_from_slice(&child.to_le_bytes());
    }
    value
}

fn index_root(entries: &[Vec<u8>], internal: bool) -> Vec<u8> {
    let mut value = vec![0; 32];
    value[4..8].copy_from_slice(&16_u32.to_le_bytes());
    value[8..12].copy_from_slice(&4096_u32.to_le_bytes());
    value[12] = 8;
    value[16..20].copy_from_slice(&16_u32.to_le_bytes());
    value[28] = u8::from(internal);
    for entry in entries {
        value.extend_from_slice(entry);
    }
    let used = (value.len() - 16) as u32;
    value[20..24].copy_from_slice(&used.to_le_bytes());
    value[24..28].copy_from_slice(&used.to_le_bytes());
    value
}

fn index_block(vcn: u64, entries: &[Vec<u8>], internal: bool) -> Vec<u8> {
    let mut value = vec![0; 4096];
    value[..4].copy_from_slice(b"INDX");
    value[4..6].copy_from_slice(&40_u16.to_le_bytes());
    value[6..8].copy_from_slice(&9_u16.to_le_bytes());
    value[16..24].copy_from_slice(&vcn.to_le_bytes());
    value[24..28].copy_from_slice(&40_u32.to_le_bytes());
    value[32..36].copy_from_slice(&4072_u32.to_le_bytes());
    value[36] = u8::from(internal);
    let mut at = 64;
    for entry in entries {
        value[at..at + entry.len()].copy_from_slice(entry);
        at += entry.len();
    }
    value[28..32].copy_from_slice(&((at - 24) as u32).to_le_bytes());
    value[40..42].copy_from_slice(&0x1357_u16.to_le_bytes());
    for sector in 1..=8 {
        let tail = sector * 512 - 2;
        let original = [value[tail], value[tail + 1]];
        value[40 + sector * 2..42 + sector * 2].copy_from_slice(&original);
        value[tail..tail + 2].copy_from_slice(&0x1357_u16.to_le_bytes());
    }
    value
}

fn named_mapping(
    kind: u32,
    id: u16,
    name: &str,
    clusters: u64,
    size: u64,
    pairs: &[u8],
    sparse: bool,
) -> Vec<u8> {
    let units: Vec<_> = name.encode_utf16().collect();
    let name_start = if sparse { 72 } else { 64 };
    let pairs_start = (name_start + units.len() * 2).next_multiple_of(8);
    let length = (pairs_start + pairs.len()).next_multiple_of(8);
    let mut value = vec![0; length];
    value[..4].copy_from_slice(&kind.to_le_bytes());
    value[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    value[8] = 1;
    value[9] = units.len() as u8;
    value[10..12].copy_from_slice(&(name_start as u16).to_le_bytes());
    value[12..14].copy_from_slice(&(if sparse { SPARSE } else { 0 }).to_le_bytes());
    value[14..16].copy_from_slice(&id.to_le_bytes());
    value[24..32].copy_from_slice(&(clusters - 1).to_le_bytes());
    value[32..34].copy_from_slice(&(pairs_start as u16).to_le_bytes());
    value[40..48].copy_from_slice(&(clusters * 512).to_le_bytes());
    value[48..56].copy_from_slice(&size.to_le_bytes());
    value[56..64].copy_from_slice(&size.to_le_bytes());
    if sparse {
        value[34..36].copy_from_slice(&4_u16.to_le_bytes());
        value[64..72].copy_from_slice(&2048_u64.to_le_bytes());
    }
    for (index, unit) in units.iter().enumerate() {
        value[name_start + index * 2..name_start + index * 2 + 2]
            .copy_from_slice(&unit.to_le_bytes());
    }
    value[pairs_start..pairs_start + pairs.len()].copy_from_slice(pairs);
    value
}

fn sds_attribute() -> Vec<u8> {
    named_mapping(DATA, 0, "$SDS", 514, SDS_SIZE as u64, SDS_PAIRS, false)
}

fn resident_sii() -> Vec<u8> {
    resident(
        0x90,
        1,
        "$SII",
        &index_root(
            &[
                index_key(0x100, 464, None),
                index_key(0x200, 592, None),
                index_key(0x300, 720, None),
                terminal(None),
            ],
            false,
        ),
    )
}

fn secure_record(external: bool, bitmap: u8) -> Vec<u8> {
    if !external {
        return file_record(9, &[sds_attribute(), resident_sii()]);
    }
    file_record(
        9,
        &[
            sds_attribute(),
            resident(
                0x90,
                1,
                "$SII",
                &index_root(&[index_key(0x200, 592, Some(0)), terminal(Some(8))], true),
            ),
            named_mapping(0xA0, 2, "$SII", 16, 8192, &[0x21, 16, 220, 5, 0], false),
            resident(0xB0, 3, "$SII", &[bitmap]),
        ],
    )
}

fn sds_physical(offset: usize) -> usize {
    let vcn = offset / 512;
    let lcn = match vcn {
        0 => 600,
        1..=511 => 800 + vcn - 1,
        _ => 1400 + vcn - 512,
    };
    BASE + lcn * 512 + offset % 512
}

fn put_sds(image: &mut Image, id: u32, offset: usize) {
    let mut value = security_header(id, offset as u64).to_vec();
    value.extend_from_slice(&DESCRIPTOR);
    for copy in [0, COPY_DISTANCE] {
        for (index, &byte) in value.iter().enumerate() {
            image.bytes[sds_physical(offset + copy + index)] = byte;
        }
    }
}

fn security_image(external: bool) -> Image {
    let mut image = Image::new();
    image.bytes.resize(BASE + SECURITY_LENGTH + 512, 0);
    image.bytes[BASE + SECURITY_LENGTH..].fill(0xD2);
    image.bytes[BASE + 40..BASE + 48].copy_from_slice(&2047_u64.to_le_bytes());
    image.put_record(9, &secure_record(external, 3));
    for number in [24, 25] {
        image.put_record(
            number,
            &file_record(
                number as u32,
                &[
                    named_mapping(DATA, 0, "", 1, 512, &[0x21, 1, 164, 6, 0], false),
                    resident(0x10, 2, "", &standard(0x100, 0)),
                ],
            ),
        );
    }
    image.bytes[BASE + 1700 * 512..BASE + 1701 * 512].fill(0xA7);
    for (id, offset) in [(0x100, 464), (0x200, 592), (0x300, 720)] {
        put_sds(&mut image, id, offset);
    }
    if external {
        for (number, vcn, id, offset) in [(0, 0, 0x100, 464), (1, 8, 0x300, 720)] {
            let value = index_block(vcn, &[index_key(id, offset, None), terminal(None)], false);
            let at = BASE + INDEX_LCN * 512 + number * 4096;
            image.bytes[at..at + 4096].copy_from_slice(&value);
        }
    }
    image
}

fn open_security(image: Image, reads: Reads, fail_at: Option<u64>) -> Result<NtfsVolume> {
    NtfsVolume::from_device(
        &Cx::for_testing(),
        Box::new(Memory {
            bytes: image.bytes,
            reads,
            fail_at,
        }),
        BASE as u64,
        SECURITY_LENGTH as u64,
    )
}

#[test]
fn shared_security_reads_resident_and_multilevel_sii_without_file_data_io() {
    let cx = Cx::for_testing();
    for external in [false, true] {
        let reads: Reads = Arc::default();
        let volume = open_security(security_image(external), Arc::clone(&reads), None).unwrap();
        for number in [24, 25] {
            let record = volume.record(&cx, number, Some(7)).unwrap();
            reads.lock().unwrap().clear();
            let info = volume.security_descriptor(&cx, &record).unwrap();
            assert_eq!(info.source, "secure_sds");
            assert_eq!(info.security_id, Some(0x100));
            assert_eq!(info.hash, Some(DESCRIPTOR_HASH));
            assert_eq!(info.sds_offset, Some(464));
            assert_eq!(info.bytes, DESCRIPTOR);
            assert_eq!(info.descriptor.owner.unwrap().to_string(), "S-1-5-18");
            assert_eq!(info.descriptor.dacl.ace_count, Some(2));
            let trace = reads.lock().unwrap();
            assert!(
                !trace
                    .iter()
                    .any(|(at, _)| *at == (BASE + 1700 * 512) as u64)
            );
            let sds_reads: Vec<_> = trace
                .iter()
                .copied()
                .filter(|(at, _)| {
                    *at >= (BASE + 600 * 512) as u64 && *at < (BASE + INDEX_LCN * 512) as u64
                })
                .collect();
            assert_eq!(
                sds_reads,
                [
                    ((BASE + 600 * 512 + 464) as u64, 48),
                    ((BASE + 800 * 512) as u64, 68),
                    ((BASE + 1400 * 512 + 464) as u64, 116),
                ]
            );
        }
    }
}

#[test]
fn legacy_security_uses_exact_resident_or_nonresident_attribute_for_zero_id() {
    let cx = Cx::for_testing();
    for length in [48, 72] {
        for mapped in [false, true] {
            let mut image = security_image(false);
            let attribute = if mapped {
                image.bytes[BASE + 1600 * 512..BASE + 1600 * 512 + DESCRIPTOR.len()]
                    .copy_from_slice(&DESCRIPTOR);
                named_mapping(0x50, 3, "", 1, 96, &[0x21, 1, 64, 6, 0], false)
            } else {
                resident(0x50, 3, "", &DESCRIPTOR)
            };
            image.put_record(
                24,
                &file_record(
                    24,
                    &[
                        resident(0x10, 2, "", &standard(0, 0)[..length]),
                        resident(DATA, 0, "", b"unrelated file bytes"),
                        attribute,
                    ],
                ),
            );
            let reads: Reads = Arc::default();
            let volume = open_security(image, Arc::clone(&reads), None).unwrap();
            let record = volume.record(&cx, 24, None).unwrap();
            reads.lock().unwrap().clear();
            let info = volume.security_descriptor(&cx, &record).unwrap();
            assert_eq!(info.bytes, DESCRIPTOR);
            assert_eq!(info.source, "security_descriptor_attribute");
            assert_eq!(info.security_id, None);
            assert_eq!(info.hash, None);
            assert_eq!(info.sds_offset, None);
            assert_eq!(reads.lock().unwrap().len(), usize::from(mapped));
        }
    }
}

#[test]
fn security_identity_sii_and_split_sds_resolve_through_extension_catalogs() {
    let cx = Cx::for_testing();
    let mut image = security_image(false);
    let mut file_list = list_entry(0x10, 30, 2, 0, "");
    file_list.extend(list_entry(DATA, 24, 0, 0, ""));
    image.put_record(
        24,
        &file_record(
            24,
            &[
                resident(ATTRIBUTE_LIST, 10, "", &file_list),
                resident(DATA, 0, "", b"file bytes"),
            ],
        ),
    );
    image.put_record(
        30,
        &extension(30, 24, &[resident(0x10, 2, "", &standard(0x100, 0))]),
    );
    let mut first = named_mapping(
        DATA,
        0,
        "$SDS",
        514,
        SDS_SIZE as u64,
        &[0x21, 1, 88, 2, 0x22, 255, 1, 200, 0, 0],
        false,
    );
    first[24..32].copy_from_slice(&511_u64.to_le_bytes());
    let mut last = named_mapping(DATA, 0, "$SDS", 514, 0, &[0x21, 2, 120, 5, 0], false);
    last[16..24].copy_from_slice(&512_u64.to_le_bytes());
    last[40..64].fill(0xFF);
    let mut secure_list = list_entry(DATA, 9, 0, 0, "$SDS");
    secure_list.extend(list_entry(DATA, 31, 0, 512, "$SDS"));
    secure_list.extend(list_entry(0x90, 31, 1, 0, "$SII"));
    image.put_record(
        9,
        &file_record(9, &[resident(ATTRIBUTE_LIST, 10, "", &secure_list), first]),
    );
    image.put_record(31, &extension(31, 9, &[last, resident_sii()]));
    let volume = open_security(image, Arc::default(), None).unwrap();
    let record = volume.record(&cx, 24, None).unwrap();
    assert_eq!(
        volume.security_descriptor(&cx, &record).unwrap().bytes,
        DESCRIPTOR
    );
}

#[test]
fn security_refuses_stale_extensions_and_never_falls_back_from_a_nonzero_id() {
    let cx = Cx::for_testing();
    for stale_extension in [false, true] {
        let mut image = security_image(false);
        let mut attributes = vec![
            resident(DATA, 0, "", b"file bytes"),
            resident(0x50, 3, "", &DESCRIPTOR),
        ];
        if stale_extension {
            let mut list = list_entry(0x10, 30, 2, 0, "");
            list.extend(list_entry(DATA, 24, 0, 0, ""));
            list.extend(list_entry(0x50, 24, 3, 0, ""));
            attributes.push(resident(ATTRIBUTE_LIST, 10, "", &list));
            let mut extension = extension(30, 24, &[resident(0x10, 2, "", &standard(0x100, 0))]);
            extension[16] = 8;
            image.put_record(30, &extension);
        } else {
            attributes.push(resident(0x10, 2, "", &standard(0x101, 0)));
        }
        image.put_record(24, &file_record(24, &attributes));
        let reads: Reads = Arc::default();
        let volume = open_security(image, Arc::clone(&reads), None).unwrap();
        let record = volume.record(&cx, 24, None).unwrap();
        reads.lock().unwrap().clear();
        assert!(matches!(
            volume.security_descriptor(&cx, &record),
            Err(FfsError::Corruption { .. })
        ));
        assert!(
            reads
                .lock()
                .unwrap()
                .iter()
                .all(|(at, _)| *at < (BASE + 600 * 512) as u64)
        );
    }
}

#[test]
fn sds_headers_hashes_duplicate_bytes_and_initialized_ranges_are_enforced() {
    let cx = Cx::for_testing();
    for case in 0..5 {
        let mut image = security_image(false);
        match case {
            0 => {
                for copy in [0, COPY_DISTANCE] {
                    image.bytes[sds_physical(464 + copy + 4)] ^= 1;
                }
            }
            1 => {
                for copy in [0, COPY_DISTANCE] {
                    image.bytes[sds_physical(464 + copy + 80)] ^= 1;
                }
            }
            2 => image.bytes[sds_physical(464 + COPY_DISTANCE + 80)] ^= 1,
            3 => {
                let mut sds = sds_attribute();
                sds[56..64].copy_from_slice(&((COPY_DISTANCE + 464 + 115) as u64).to_le_bytes());
                image.put_record(9, &file_record(9, &[sds, resident_sii()]));
            }
            _ => {
                let mut sds = sds_attribute();
                sds[48..56].copy_from_slice(&((COPY_DISTANCE + 464 + 115) as u64).to_le_bytes());
                sds[56..64].copy_from_slice(&((COPY_DISTANCE + 464 + 115) as u64).to_le_bytes());
                image.put_record(9, &file_record(9, &[sds, resident_sii()]));
            }
        }
        let reads: Reads = Arc::default();
        let volume = open_security(image, Arc::clone(&reads), None).unwrap();
        let record = volume.record(&cx, 24, None).unwrap();
        reads.lock().unwrap().clear();
        assert!(
            matches!(
                volume.security_descriptor(&cx, &record),
                Err(FfsError::Corruption { .. })
            ),
            "case {case}"
        );
        if case >= 3 {
            assert!(
                reads
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|(at, _)| *at < (BASE + 600 * 512) as u64)
            );
        }
    }
}

#[test]
fn sds_sparse_gaps_are_admitted_but_a_sparse_descriptor_is_not_read_as_zeroes() {
    let cx = Cx::for_testing();
    for selected_hole in [false, true] {
        let mut image = security_image(false);
        let pairs: &[u8] = if selected_hole {
            &[0x01, 1, 0x22, 255, 1, 32, 3, 0x21, 2, 88, 2, 0]
        } else {
            &[
                0x21, 1, 88, 2, 0x21, 1, 200, 0, 0x02, 254, 1, 0x21, 2, 88, 2, 0,
            ]
        };
        let sds = named_mapping(DATA, 0, "$SDS", 514, SDS_SIZE as u64, pairs, true);
        image.put_record(9, &file_record(9, &[sds, resident_sii()]));
        let reads: Reads = Arc::default();
        let volume = open_security(image, Arc::clone(&reads), None).unwrap();
        let record = volume.record(&cx, 24, None).unwrap();
        reads.lock().unwrap().clear();
        let result = volume.security_descriptor(&cx, &record);
        if selected_hole {
            assert!(matches!(result, Err(FfsError::Corruption { .. })));
            assert!(
                reads
                    .lock()
                    .unwrap()
                    .iter()
                    .all(|(at, _)| *at < (BASE + 600 * 512) as u64)
            );
        } else {
            assert_eq!(result.unwrap().bytes, DESCRIPTOR);
        }
    }
}

#[test]
fn sii_tree_cycles_parent_bounds_bitmap_and_fixups_fail_before_sds_reads() {
    let cx = Cx::for_testing();
    for case in 0..7 {
        let mut image = security_image(true);
        match case {
            0 => image.put_record(9, &secure_record(true, 2)),
            1 => image.put_record(9, &secure_record(true, 7)),
            2 => {
                let cycle = index_block(0, &[terminal(Some(0))], true);
                let at = BASE + INDEX_LCN * 512;
                image.bytes[at..at + 4096].copy_from_slice(&cycle);
            }
            3 => {
                let misplaced =
                    index_block(0, &[index_key(0x300, 720, None), terminal(None)], false);
                let at = BASE + INDEX_LCN * 512;
                image.bytes[at..at + 4096].copy_from_slice(&misplaced);
            }
            4 => image.bytes[BASE + INDEX_LCN * 512 + 4095] ^= 1,
            5 => image.bytes[BASE + INDEX_LCN * 512 + 4096 + 16] = 0,
            _ => {
                let out_of_bounds = index_block(0, &[terminal(Some(16))], true);
                let at = BASE + INDEX_LCN * 512;
                image.bytes[at..at + 4096].copy_from_slice(&out_of_bounds);
                image.put_record(9, &secure_record(true, 7));
            }
        }
        let reads: Reads = Arc::default();
        let volume = open_security(image, Arc::clone(&reads), None).unwrap();
        let record = volume.record(&cx, 24, None).unwrap();
        reads.lock().unwrap().clear();
        assert!(
            matches!(
                volume.security_descriptor(&cx, &record),
                Err(FfsError::Corruption { .. })
            ),
            "case {case}"
        );
        assert!(reads.lock().unwrap().iter().all(|(at, _)| {
            *at < (BASE + 600 * 512) as u64 || *at >= (BASE + INDEX_LCN * 512) as u64
        }));
    }
}

#[test]
fn security_inspection_preserves_efs_and_reparse_data_provider_boundaries() {
    let cx = Cx::for_testing();
    for flags in [0x400_u32, 0x4000] {
        let mut image = security_image(false);
        let mut attributes = vec![
            resident(0x10, 2, "", &standard(0x100, flags)),
            named_mapping(DATA, 0, "", 1, 512, &[0x21, 1, 164, 6, 0], false),
        ];
        if flags == 0x400 {
            attributes.push(resident(0xC0, 3, "", &[0x17, 0, 0, 0x80, 0, 0, 0, 0]));
        }
        image.put_record(24, &file_record(24, &attributes));
        let reads: Reads = Arc::default();
        let volume = open_security(image, Arc::clone(&reads), None).unwrap();
        let record = volume.record(&cx, 24, None).unwrap();
        reads.lock().unwrap().clear();
        assert_eq!(
            volume.security_descriptor(&cx, &record).unwrap().bytes,
            DESCRIPTOR
        );
        assert!(matches!(
            volume.data_stream(&cx, &record, &[]),
            Err(FfsError::UnsupportedFeature(_))
        ));
        assert!(
            !reads
                .lock()
                .unwrap()
                .iter()
                .any(|(at, _)| *at == (BASE + 1700 * 512) as u64)
        );
    }
}

#[test]
fn security_metadata_cancellation_propagates_from_index_primary_and_duplicate_io() {
    let cx = Cx::for_testing();
    for fail_at in [
        BASE + INDEX_LCN * 512,
        BASE + 600 * 512 + 464,
        BASE + 800 * 512,
        BASE + 1400 * 512 + 464,
    ] {
        let reads: Reads = Arc::default();
        let volume = open_security(
            security_image(true),
            Arc::clone(&reads),
            Some(fail_at as u64),
        )
        .unwrap();
        let record = volume.record(&cx, 24, None).unwrap();
        assert!(matches!(
            volume.security_descriptor(&cx, &record),
            Err(FfsError::Cancelled)
        ));
        assert_eq!(reads.lock().unwrap().last().unwrap().0, fail_at as u64);
    }
}

#[test]
fn security_reports_exact_standard_fields_legacy_presence_and_secure_generation() {
    let cx = Cx::for_testing();
    for length in [48, 72] {
        let mut image = security_image(false);
        image.put_record(
            24,
            &file_record(
                24,
                &[
                    resident(0x10, 2, "", &standard(0, 0)[..length]),
                    resident(0x50, 3, "", &DESCRIPTOR),
                ],
            ),
        );
        let volume = open_security(image, Arc::default(), None).unwrap();
        let record = volume.record(&cx, 24, Some(7)).unwrap();
        let info = volume.security_descriptor(&cx, &record).unwrap();
        assert_eq!(info.standard_security_id, (length == 72).then_some(0));
        assert_eq!(info.security_id, None);
        assert!(info.legacy_attribute_present);
        assert!(info.secure_reference.is_none());
    }
    for legacy_present in [false, true] {
        let mut image = security_image(false);
        let mut attributes = vec![resident(0x10, 2, "", &standard(0x100, 0))];
        if legacy_present {
            attributes.push(resident(0x50, 3, "", &DESCRIPTOR));
        }
        image.put_record(24, &file_record(24, &attributes));
        let mut secure = secure_record(false, 0);
        secure[16..18].copy_from_slice(&91_u16.to_le_bytes());
        image.put_record(9, &secure);
        let volume = open_security(image, Arc::default(), None).unwrap();
        let record = volume.record(&cx, 24, Some(7)).unwrap();
        let info = volume.security_descriptor(&cx, &record).unwrap();
        assert_eq!(info.standard_security_id, Some(0x100));
        assert_eq!(info.security_id, Some(0x100));
        assert_eq!(info.legacy_attribute_present, legacy_present);
        let reference = info.secure_reference.unwrap();
        assert_eq!((reference.record, reference.sequence), (9, 91));
        assert_eq!(
            info.descriptor.dacl.aces[0]
                .sid
                .as_ref()
                .unwrap()
                .to_string(),
            "S-1-1-0"
        );
    }
}

#[test]
fn sii_bitmap_must_cover_allocation_even_without_children_or_any_set_bits() {
    let cx = Cx::for_testing();
    for bitmap in [&[][..], &[0][..]] {
        let mut image = security_image(false);
        let blocks = if bitmap.is_empty() { 1_u8 } else { 9 };
        let clusters = blocks * 8;
        let allocation = named_mapping(
            0xA0,
            2,
            "$SII",
            u64::from(clusters),
            u64::from(clusters) * 512,
            &[0x21, clusters, 220, 5, 0],
            false,
        );
        image.put_record(
            9,
            &file_record(
                9,
                &[
                    sds_attribute(),
                    resident_sii(),
                    allocation,
                    resident(0xB0, 3, "$SII", bitmap),
                ],
            ),
        );
        let reads: Reads = Arc::default();
        let volume = open_security(image, Arc::clone(&reads), None).unwrap();
        let record = volume.record(&cx, 24, None).unwrap();
        reads.lock().unwrap().clear();
        let error = volume.security_descriptor(&cx, &record).unwrap_err();
        assert!(matches!(error, FfsError::Corruption { .. }));
        assert!(error.to_string().contains("bitmap does not cover"));
        assert!(
            reads
                .lock()
                .unwrap()
                .iter()
                .all(|(at, _)| *at < (BASE + 600 * 512) as u64)
        );
    }
}

#[test]
fn malformed_known_trustees_fail_after_matching_native_hashes_and_sds_copies() {
    let cx = Cx::for_testing();
    for shared in [false, true] {
        let mut image = security_image(false);
        let mut damaged = DESCRIPTOR;
        damaged[64] = 2; // A deny ACE with a bounded but invalid SID revision.
        if shared {
            let hash = ffs_ondisk::ntfs_security::security_hash(&damaged);
            let mut entry = security_header(0x100, 464).to_vec();
            entry[..4].copy_from_slice(&hash.to_le_bytes());
            entry.extend_from_slice(&damaged);
            for copy in [0, COPY_DISTANCE] {
                for (index, &byte) in entry.iter().enumerate() {
                    image.bytes[sds_physical(464 + copy + index)] = byte;
                }
            }
            let mut key = index_key(0x100, 464, None);
            key[20..24].copy_from_slice(&hash.to_le_bytes());
            image.put_record(
                9,
                &file_record(
                    9,
                    &[
                        sds_attribute(),
                        resident(0x90, 1, "$SII", &index_root(&[key, terminal(None)], false)),
                    ],
                ),
            );
        } else {
            image.put_record(
                24,
                &file_record(
                    24,
                    &[
                        resident(0x10, 2, "", &standard(0, 0)),
                        resident(0x50, 3, "", &damaged),
                    ],
                ),
            );
        }
        let volume = open_security(image, Arc::default(), None).unwrap();
        let record = volume.record(&cx, 24, None).unwrap();
        assert!(
            matches!(
                volume.security_descriptor(&cx, &record),
                Err(FfsError::Corruption { .. })
            ),
            "shared={shared}"
        );
    }
}

#[test]
fn secure_metadata_cannot_use_a_reparse_or_efs_provider_to_supply_sds_bytes() {
    let cx = Cx::for_testing();
    for provider in [
        resident(0xC0, 3, "", &[0x17, 0, 0, 0x80, 0, 0, 0, 0]),
        resident(0x10, 3, "", &standard(0, 0x4000)),
    ] {
        let mut image = security_image(false);
        image.put_record(
            9,
            &file_record(9, &[sds_attribute(), resident_sii(), provider]),
        );
        let reads: Reads = Arc::default();
        let volume = open_security(image, Arc::clone(&reads), None).unwrap();
        let record = volume.record(&cx, 24, None).unwrap();
        reads.lock().unwrap().clear();
        assert!(matches!(
            volume.security_descriptor(&cx, &record),
            Err(FfsError::UnsupportedFeature(_))
        ));
        assert!(
            reads
                .lock()
                .unwrap()
                .iter()
                .all(|(at, _)| *at < (BASE + 600 * 512) as u64)
        );
    }
}

#[test]
fn security_and_decoded_ace_inspection_preserve_the_image_and_adjacent_bytes() {
    let image = security_image(true);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("security-aces.img");
    std::fs::write(&path, &image.bytes).unwrap();
    let cx = Cx::for_testing();
    let volume = NtfsVolume::open(&cx, &path, BASE as u64, Some(SECURITY_LENGTH as u64)).unwrap();
    let record = volume.record(&cx, 24, Some(7)).unwrap();
    let info = volume.security_descriptor(&cx, &record).unwrap();
    assert_eq!(info.bytes, DESCRIPTOR);
    assert_eq!(info.descriptor.dacl.aces.len(), 2);
    assert_eq!(std::fs::read(&path).unwrap(), image.bytes);
}
