use super::*;

const NAMESPACE_LENGTH: usize = 1024 * 512;
const INDEX_START: usize = BASE + 220 * 512;

fn name_value(parent: u64, name: &str, namespace: u8) -> Vec<u8> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let mut value = vec![0; 66 + units.len() * 2];
    value[..8].copy_from_slice(&((7_u64 << 48) | parent).to_le_bytes());
    value[64] = units.len() as u8;
    value[65] = namespace;
    for (i, unit) in units.iter().enumerate() {
        value[66 + i * 2..68 + i * 2].copy_from_slice(&unit.to_le_bytes());
    }
    value
}

fn key(number: u64, parent: u64, name: &str, namespace: u8, child: Option<u64>) -> Vec<u8> {
    let value = name_value(parent, name, namespace);
    let length = (16 + value.len()).next_multiple_of(8) + if child.is_some() { 8 } else { 0 };
    let mut entry = vec![0; length];
    entry[..8].copy_from_slice(&((7_u64 << 48) | number).to_le_bytes());
    entry[8..10].copy_from_slice(&(length as u16).to_le_bytes());
    entry[10..12].copy_from_slice(&(value.len() as u16).to_le_bytes());
    entry[12..14].copy_from_slice(&u16::from(child.is_some()).to_le_bytes());
    entry[16..16 + value.len()].copy_from_slice(&value);
    if let Some(child) = child { entry[length - 8..].copy_from_slice(&child.to_le_bytes()); }
    entry
}

fn terminal(child: Option<u64>) -> Vec<u8> {
    let length = if child.is_some() { 24 } else { 16 };
    let mut entry = vec![0; length];
    entry[8..10].copy_from_slice(&(length as u16).to_le_bytes());
    entry[12..14].copy_from_slice(&(2 | u16::from(child.is_some())).to_le_bytes());
    if let Some(child) = child { entry[length - 8..].copy_from_slice(&child.to_le_bytes()); }
    entry
}

fn index_root(entries: &[Vec<u8>], internal: bool) -> Vec<u8> {
    let mut value = vec![0; 32];
    value[..4].copy_from_slice(&0x30_u32.to_le_bytes());
    value[4..8].copy_from_slice(&1_u32.to_le_bytes());
    value[8..12].copy_from_slice(&4096_u32.to_le_bytes());
    value[12] = 8;
    for entry in entries { value.extend_from_slice(entry); }
    let used = (value.len() - 16) as u32;
    value[16..20].copy_from_slice(&16_u32.to_le_bytes());
    value[20..24].copy_from_slice(&used.to_le_bytes());
    value[24..28].copy_from_slice(&used.to_le_bytes());
    value[28..32].copy_from_slice(&u32::from(internal).to_le_bytes());
    value
}

fn index_node(vcn: u64, entries: &[Vec<u8>], internal: bool) -> Vec<u8> {
    let mut raw = vec![0; 4096];
    raw[..4].copy_from_slice(b"INDX");
    raw[4..6].copy_from_slice(&40_u16.to_le_bytes());
    raw[6..8].copy_from_slice(&9_u16.to_le_bytes());
    raw[16..24].copy_from_slice(&vcn.to_le_bytes());
    raw[24..28].copy_from_slice(&40_u32.to_le_bytes());
    raw[32..36].copy_from_slice(&4072_u32.to_le_bytes());
    raw[36..40].copy_from_slice(&u32::from(internal).to_le_bytes());
    let mut at = 64;
    for entry in entries {
        raw[at..at + entry.len()].copy_from_slice(entry);
        at += entry.len();
    }
    raw[28..32].copy_from_slice(&((at - 24) as u32).to_le_bytes());
    for part in 1..=8 {
        let saved = [raw[part * 512 - 2], raw[part * 512 - 1]];
        raw[40 + part * 2..42 + part * 2].copy_from_slice(&saved);
        raw[part * 512 - 2..part * 512].copy_from_slice(&0x2468_u16.to_le_bytes());
    }
    raw[40..42].copy_from_slice(&0x2468_u16.to_le_bytes());
    raw
}

fn root_keys() -> Vec<Vec<u8>> {
    vec![key(24, 5, "A.txt", 1, None), key(24, 5, "A~1.TXT", 2, None),
         key(29, 5, "mixed", 0, None), key(27, 5, "Subdir", 1, None),
         key(25, 5, "Ä.bin", 1, None), terminal(None)]
}

fn directory_record(number: u32, attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut record = file_record(number, attrs);
    record[22..24].copy_from_slice(&3_u16.to_le_bytes());
    record
}

fn root_record(external: bool, bitmap: u8) -> Vec<u8> {
    if !external {
        return directory_record(5, &[resident(0x90, 0, "$I30", &index_root(&root_keys(), false))]);
    }
    let mut allocation = mapped(&[0x21, 24, 220, 0, 0], 24, 12288, 12288, 0);
    let pairs = allocation[64..].to_vec();
    allocation.resize((72 + pairs.len()).next_multiple_of(8), 0);
    let length = allocation.len() as u32;
    allocation[..4].copy_from_slice(&0xA0_u32.to_le_bytes());
    allocation[4..8].copy_from_slice(&length.to_le_bytes());
    allocation[9] = 4;
    allocation[10..12].copy_from_slice(&64_u16.to_le_bytes());
    allocation[14..16].copy_from_slice(&1_u16.to_le_bytes());
    allocation[32..34].copy_from_slice(&72_u16.to_le_bytes());
    allocation[64..72].copy_from_slice(&[36, 0, 73, 0, 51, 0, 48, 0]);
    allocation[72..72 + pairs.len()].copy_from_slice(&pairs);
    directory_record(5, &[resident(0x90, 0, "$I30", &index_root(&[terminal(Some(0))], true)),
        allocation, resident(0xB0, 2, "$I30", &[bitmap])])
}

fn namespace_image(external: bool) -> Image {
    let mut image = Image::new();
    image.bytes.resize(BASE + NAMESPACE_LENGTH + 512, 0);
    image.bytes[BASE + 40..BASE + 48].copy_from_slice(&1023_u64.to_le_bytes());
    for unit in 0..=u16::MAX {
        let upper = if (97..=122).contains(&unit) { unit - 32 }
            else if unit == 0xE4 { 0xC4 } else { unit };
        let at = BASE + 300 * 512 + usize::from(unit) * 2;
        image.bytes[at..at + 2].copy_from_slice(&upper.to_le_bytes());
    }
    image.put_record(10, &file_record(10, &[
        mapped(&[0x22, 0, 1, 44, 1, 0], 256, 131072, 131072, 0)
    ]));
    image.put_record(24, &file_record(24, &[resident(DATA, 0, "", b"resident!"),
        resident(DATA, 1, "note", b"named stream"),
        resident(0x30, 2, "", &name_value(5, "A.txt", 1)),
        resident(0x30, 3, "", &name_value(5, "A~1.TXT", 2))]));
    image.put_record(25, &file_record(25, &[
        mapped(&[0x21, 1, 180, 0, 0x11, 1, 0xF6, 0], 2, 600, 600, 0),
        resident(0x30, 1, "", &name_value(5, "Ä.bin", 1))]));
    let nested = index_root(&[key(28, 27, "NESTED.BIN", 1, None), terminal(None)], false);
    image.put_record(27, &directory_record(27, &[resident(0x90, 0, "$I30", &nested),
        resident(0x30, 1, "", &name_value(5, "Subdir", 1))]));
    image.put_record(28, &file_record(28, &[resident(DATA, 0, "", b"deep data"),
        resident(0x30, 1, "", &name_value(27, "NESTED.BIN", 1))]));
    image.put_record(29, &file_record(29, &[resident(DATA, 0, "", b"posix"),
        resident(0x30, 1, "", &name_value(5, "mixed", 0))]));
    image.put_record(5, &root_record(external, 7));
    if external {
        let keys = root_keys();
        let nodes = [index_node(0, &[key(27, 5, "Subdir", 1, Some(8)), terminal(Some(16))], true),
            index_node(8, &[keys[0].clone(), keys[1].clone(), keys[2].clone(), terminal(None)], false),
            index_node(16, &[keys[4].clone(), terminal(None)], false)];
        for (index, node) in nodes.iter().enumerate() {
            let at = INDEX_START + index * 4096;
            image.bytes[at..at + 4096].copy_from_slice(node);
        }
    }
    image
}

fn open(image: Image, reads: Reads, fail_at: Option<u64>) -> Result<NtfsVolume> {
    NtfsVolume::from_device(&Cx::for_testing(), Box::new(Memory { bytes: image.bytes, reads, fail_at }),
        BASE as u64, NAMESPACE_LENGTH as u64)
}

#[test]
fn resident_and_multilevel_indexes_resolve_names_aliases_and_nested_paths() {
    let cx = Cx::for_testing();
    for external in [false, true] {
        let volume = open(namespace_image(external), Arc::default(), None).unwrap();
        let root = volume.resolve(&cx, "/").unwrap();
        let entries = volume.list_directory(&cx, &root).unwrap();
        assert_eq!(entries.len(), 5);
        assert_eq!(volume.resolve(&cx, "/a.TXT").unwrap().number, 24);
        assert_eq!(volume.resolve(&cx, "/a~1.txt").unwrap().number, 24);
        assert_eq!(volume.resolve(&cx, "/ä.BIN").unwrap().number, 25);
        assert_eq!(volume.resolve(&cx, "/mixed").unwrap().number, 29);
        assert!(matches!(volume.resolve(&cx, "/MIXED"), Err(FfsError::NotFound)));
        let nested = volume.resolve(&cx, "/subdir/nested.bin").unwrap();
        let data = volume.data_stream(&cx, &nested, &[]).unwrap();
        assert_eq!(volume.read(&cx, &data, 0, 100).unwrap(), b"deep data");
        assert!(matches!(volume.resolve(&cx, "/a.txt/child"), Err(FfsError::NotDirectory)));
        assert!(matches!(volume.resolve(&cx, "/a.txt/"), Err(FfsError::NotDirectory)));
        assert!(volume.resolve(&cx, "/../a.txt").is_err());
    }
}

#[test]
fn index_cycles_bitmap_disagreement_stale_vbn_and_torn_blocks_are_errors() {
    let cx = Cx::for_testing();
    for case in 0..5 {
        let mut image = namespace_image(true);
        match case {
            0 => image.put_record(5, &root_record(true, 0)),
            1 => image.put_record(5, &root_record(true, 15)),
            2 => {
                let cycle = index_node(0, &[terminal(Some(0))], true);
                image.bytes[INDEX_START..INDEX_START + 4096].copy_from_slice(&cycle);
            }
            3 => image.bytes[INDEX_START + 4096 + 16] = 0,
            _ => image.bytes[INDEX_START + 2 * 4096 + 4095] ^= 1,
        }
        let volume = open(image, Arc::default(), None).unwrap();
        let root = volume.record(&cx, 5, None).unwrap();
        assert!(matches!(volume.list_directory(&cx, &root), Err(FfsError::Corruption { .. })), "case {case}");
    }
}

#[test]
fn index_links_must_match_sequence_and_target_filename_parent() {
    let cx = Cx::for_testing();
    for stale in [false, true] {
        let mut image = namespace_image(false);
        if stale {
            let at = Image::record_offset(24) + 16;
            image.bytes[at] = 8;
        } else {
            image.put_record(25, &file_record(25, &[resident(DATA, 0, "", b"not that child"),
                resident(0x30, 1, "", &name_value(27, "Ä.bin", 1))]));
        }
        let volume = open(image, Arc::default(), None).unwrap();
        assert!(matches!(volume.resolve(&cx, "/a.txt"), Err(FfsError::Corruption { .. })));
    }
}

#[test]
fn native_upcase_damage_and_reparse_traversal_are_not_silently_ignored() {
    let cx = Cx::for_testing();
    let mut image = namespace_image(false);
    let at = BASE + 300 * 512 + usize::from(b'a') * 2;
    image.bytes[at..at + 2].copy_from_slice(&97_u16.to_le_bytes());
    assert!(open(image, Arc::default(), None).unwrap().resolve(&cx, "/a.txt").is_err());
    let mut image = namespace_image(false);
    image.put_record(29, &file_record(29, &[resident(DATA, 0, "", b"posix"),
        resident(0x30, 1, "", &name_value(5, "mixed", 0)), resident(0xC0, 2, "", &[0; 8])]));
    assert!(matches!(open(image, Arc::default(), None).unwrap().resolve(&cx, "/mixed"),
        Err(FfsError::UnsupportedFeature(_))));
}

#[test]
fn index_read_cancellation_is_propagated_without_partial_directory_success() {
    let cx = Cx::for_testing();
    let reads: Reads = Arc::default();
    let volume = open(namespace_image(true), Arc::clone(&reads), Some(INDEX_START as u64 + 4096)).unwrap();
    let root = volume.record(&cx, 5, None).unwrap();
    reads.lock().unwrap().clear();
    assert!(matches!(volume.list_directory(&cx, &root), Err(FfsError::Cancelled)));
    assert_eq!(reads.lock().unwrap().iter().filter(|(offset, _)| *offset >= INDEX_START as u64).count(), 2);
}

// Split existing native-layout fixtures rather than generating new index keys
// that merely mirror the resolver's implementation.
fn split_namespace_image() -> Image {
    use super::attributes::{extension, list_entry};
    let mut image = namespace_image(true);
    let restored = ffs_ondisk::ntfs::restore_record(&root_record(true, 7), b"FILE").unwrap();
    let mut at = 56;
    let mut attrs = Vec::new();
    while u32::from_le_bytes(restored[at..at + 4].try_into().unwrap()) != u32::MAX {
        let length = u32::from_le_bytes(restored[at + 4..at + 8].try_into().unwrap()) as usize;
        attrs.push(restored[at..at + length].to_vec());
        at += length;
    }
    let mut list = list_entry(0x90, 5, 0, 0, "$I30");
    list.extend(list_entry(0xA0, 31, 1, 0, "$I30"));
    list.extend(list_entry(0xB0, 31, 2, 0, "$I30"));
    image.put_record(5, &directory_record(5, &[resident(ATTRIBUTE_LIST, 10, "", &list), attrs[0].clone()]));
    image.put_record(31, &extension(31, 5, &attrs[1..]));
    let mut list = list_entry(0x30, 30, 2, 0, "");
    list.extend(list_entry(0x30, 30, 3, 0, ""));
    list.extend(list_entry(DATA, 24, 0, 0, ""));
    list.extend(list_entry(DATA, 24, 1, 0, "note"));
    image.put_record(24, &file_record(24, &[resident(ATTRIBUTE_LIST, 10, "", &list),
        resident(DATA, 0, "", b"resident!"), resident(DATA, 1, "note", b"named stream")]));
    image.put_record(30, &extension(30, 24, &[
        resident(0x30, 2, "", &name_value(5, "A.txt", 1)),
        resident(0x30, 3, "", &name_value(5, "A~1.TXT", 2)),
    ]));
    image
}

#[test]
fn extension_backed_indexes_and_file_names_support_path_reads_and_aliases() {
    let cx = Cx::for_testing();
    let volume = open(split_namespace_image(), Arc::default(), None).unwrap();
    let root = volume.resolve(&cx, "/").unwrap();
    assert_eq!(volume.list_directory(&cx, &root).unwrap().len(), 5);
    for path in ["/a.txt", "/A~1.txt"] {
        let file = volume.resolve(&cx, path).unwrap();
        assert_eq!(file.number, 24);
        let stream = volume.data_stream(&cx, &file, &[]).unwrap();
        assert_eq!(volume.read(&cx, &stream, 0, 100).unwrap(), b"resident!");
    }
    assert_eq!(volume.resolve(&cx, "/subdir/nested.bin").unwrap().number, 28);
}

#[test]
fn untrusted_file_name_extension_prevents_partial_directory_success() {
    let cx = Cx::for_testing();
    let mut image = split_namespace_image();
    image.bytes[Image::record_offset(30) + 16] = 8;
    let volume = open(image, Arc::default(), None).unwrap();
    let root = volume.record(&cx, 5, None).unwrap();
    assert!(matches!(volume.list_directory(&cx, &root), Err(FfsError::Corruption { .. })));
}

#[test]
fn reparse_attributes_cannot_hide_in_an_extension_record() {
    use super::attributes::{extension, list_entry};
    let cx = Cx::for_testing();
    let mut image = namespace_image(false);
    let mut list = list_entry(0x30, 29, 1, 0, "");
    list.extend(list_entry(DATA, 29, 0, 0, ""));
    list.extend(list_entry(0xC0, 30, 2, 0, ""));
    image.put_record(29, &file_record(29, &[resident(ATTRIBUTE_LIST, 10, "", &list),
        resident(DATA, 0, "", b"posix"), resident(0x30, 1, "", &name_value(5, "mixed", 0))]));
    image.put_record(30, &extension(30, 29, &[resident(0xC0, 2, "", &[0; 8])]));
    let volume = open(image, Arc::default(), None).unwrap();
    assert!(matches!(volume.resolve(&cx, "/mixed"), Err(FfsError::UnsupportedFeature(_))));
}

#[test]
fn native_upcase_selection_follows_its_attribute_list() {
    use super::attributes::{extension, list_entry};
    let cx = Cx::for_testing();
    let mut image = namespace_image(false);
    image.put_record(10, &file_record(10, &[resident(ATTRIBUTE_LIST, 10, "",
        &list_entry(DATA, 30, 0, 0, ""))]));
    image.put_record(30, &extension(30, 10, &[
        mapped(&[0x22, 0, 1, 44, 1, 0], 256, 131072, 131072, 0)
    ]));
    let volume = open(image, Arc::default(), None).unwrap();
    assert_eq!(volume.resolve(&cx, "/ä.BIN").unwrap().number, 25);
}
