//! Constructed native FILE/INDX images, not Windows or kernel-mount evidence.

use super::*;
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_types::ByteOffset;
use std::sync::{Arc, Mutex};

const BASE: usize = 1024;
const LENGTH: usize = 1024 * 512;
const LEFT: usize = BASE + 220 * 512;
const RIGHT: usize = LEFT + 4096;
const UPCASE: usize = BASE + 300 * 512;
type Reads = Arc<Mutex<Vec<(u64, usize)>>>;

fn record_at(number: usize) -> usize {
    BASE + 4 * 512 + number * 1024
}

fn resident(kind: u32, id: u16, name: &str, value: &[u8]) -> Vec<u8> {
    let units: Vec<_> = name.encode_utf16().collect();
    let start = (24 + units.len() * 2).next_multiple_of(8);
    let length = (start + value.len()).next_multiple_of(8);
    let mut raw = vec![0; length];
    raw[..4].copy_from_slice(&kind.to_le_bytes());
    raw[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    raw[9] = units.len() as u8;
    raw[10..12].copy_from_slice(&24_u16.to_le_bytes());
    raw[14..16].copy_from_slice(&id.to_le_bytes());
    raw[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
    raw[20..22].copy_from_slice(&(start as u16).to_le_bytes());
    for (index, unit) in units.into_iter().enumerate() {
        raw[24 + index * 2..26 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    raw[start..start + value.len()].copy_from_slice(value);
    raw
}

fn mapped(kind: u32, id: u16, name: &str, pairs: &[u8], clusters: u64, size: u64) -> Vec<u8> {
    let units: Vec<_> = name.encode_utf16().collect();
    let start = (64 + units.len() * 2).next_multiple_of(8);
    let length = (start + pairs.len()).next_multiple_of(8);
    let mut raw = vec![0; length];
    raw[..4].copy_from_slice(&kind.to_le_bytes());
    raw[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    raw[8] = 1;
    raw[9] = units.len() as u8;
    raw[10..12].copy_from_slice(&64_u16.to_le_bytes());
    raw[14..16].copy_from_slice(&id.to_le_bytes());
    raw[24..32].copy_from_slice(&(clusters - 1).to_le_bytes());
    raw[32..34].copy_from_slice(&(start as u16).to_le_bytes());
    raw[40..48].copy_from_slice(&(clusters * 512).to_le_bytes());
    raw[48..56].copy_from_slice(&size.to_le_bytes());
    raw[56..64].copy_from_slice(&size.to_le_bytes());
    for (index, unit) in units.into_iter().enumerate() {
        raw[64 + index * 2..66 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    raw[start..start + pairs.len()].copy_from_slice(pairs);
    raw
}

fn protect(raw: &mut [u8], usa: usize) {
    for sector in 1..=raw.len() / 512 {
        let saved = [raw[sector * 512 - 2], raw[sector * 512 - 1]];
        raw[usa + sector * 2..usa + sector * 2 + 2].copy_from_slice(&saved);
        raw[sector * 512 - 2..sector * 512].copy_from_slice(&0x1357_u16.to_le_bytes());
    }
    raw[usa..usa + 2].copy_from_slice(&0x1357_u16.to_le_bytes());
}

fn record(number: u32, directory: bool, attributes: &[Vec<u8>]) -> Vec<u8> {
    let mut raw = vec![0; 1024];
    raw[..4].copy_from_slice(b"FILE");
    raw[4..6].copy_from_slice(&48_u16.to_le_bytes());
    raw[6..8].copy_from_slice(&3_u16.to_le_bytes());
    raw[16..18].copy_from_slice(&7_u16.to_le_bytes());
    raw[18..20].copy_from_slice(&1_u16.to_le_bytes());
    raw[20..22].copy_from_slice(&56_u16.to_le_bytes());
    raw[22..24].copy_from_slice(&(if directory { 3_u16 } else { 1 }).to_le_bytes());
    raw[28..32].copy_from_slice(&1024_u32.to_le_bytes());
    raw[44..48].copy_from_slice(&number.to_le_bytes());
    let mut at = 56;
    for attr in attributes {
        raw[at..at + attr.len()].copy_from_slice(attr);
        at += attr.len();
    }
    raw[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    raw[24..28].copy_from_slice(&((at + 8) as u32).to_le_bytes());
    protect(&mut raw, 48);
    raw
}

fn filename(parent: u64, name: &str, namespace: u8) -> Vec<u8> {
    let units: Vec<_> = name.encode_utf16().collect();
    let mut raw = vec![0; 66 + units.len() * 2];
    raw[..8].copy_from_slice(&((7_u64 << 48) | parent).to_le_bytes());
    raw[64] = units.len() as u8;
    raw[65] = namespace;
    for (index, unit) in units.into_iter().enumerate() {
        raw[66 + index * 2..68 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    raw
}

fn key(number: u64, parent: u64, name: &str, namespace: u8, child: Option<u64>) -> Vec<u8> {
    let value = filename(parent, name, namespace);
    let length = (16 + value.len()).next_multiple_of(8) + usize::from(child.is_some()) * 8;
    let mut raw = vec![0; length];
    raw[..8].copy_from_slice(&((7_u64 << 48) | number).to_le_bytes());
    raw[8..10].copy_from_slice(&(length as u16).to_le_bytes());
    raw[10..12].copy_from_slice(&(value.len() as u16).to_le_bytes());
    raw[12..14].copy_from_slice(&u16::from(child.is_some()).to_le_bytes());
    raw[16..16 + value.len()].copy_from_slice(&value);
    if let Some(vcn) = child {
        raw[length - 8..].copy_from_slice(&vcn.to_le_bytes());
    }
    raw
}

fn terminal(child: Option<u64>) -> Vec<u8> {
    let length = if child.is_some() { 24 } else { 16 };
    let mut raw = vec![0; length];
    raw[8..10].copy_from_slice(&(length as u16).to_le_bytes());
    raw[12..14].copy_from_slice(&(2 | u16::from(child.is_some())).to_le_bytes());
    if let Some(vcn) = child {
        raw[length - 8..].copy_from_slice(&vcn.to_le_bytes());
    }
    raw
}

fn root(entries: &[Vec<u8>], internal: bool) -> Vec<u8> {
    let mut raw = vec![0; 32];
    raw[..4].copy_from_slice(&0x30_u32.to_le_bytes());
    raw[4..8].copy_from_slice(&1_u32.to_le_bytes());
    raw[8..12].copy_from_slice(&4096_u32.to_le_bytes());
    raw[12] = 8;
    raw[16..20].copy_from_slice(&16_u32.to_le_bytes());
    raw[28..32].copy_from_slice(&u32::from(internal).to_le_bytes());
    for entry in entries {
        raw.extend_from_slice(entry);
    }
    let used = (raw.len() - 16) as u32;
    raw[20..24].copy_from_slice(&used.to_le_bytes());
    raw[24..28].copy_from_slice(&used.to_le_bytes());
    raw
}

fn node(vcn: u64, entries: &[Vec<u8>]) -> Vec<u8> {
    let mut raw = vec![0; 4096];
    raw[..4].copy_from_slice(b"INDX");
    raw[4..6].copy_from_slice(&40_u16.to_le_bytes());
    raw[6..8].copy_from_slice(&9_u16.to_le_bytes());
    raw[16..24].copy_from_slice(&vcn.to_le_bytes());
    raw[24..28].copy_from_slice(&40_u32.to_le_bytes());
    raw[32..36].copy_from_slice(&4072_u32.to_le_bytes());
    let mut at = 64;
    for entry in entries {
        raw[at..at + entry.len()].copy_from_slice(entry);
        at += entry.len();
    }
    raw[28..32].copy_from_slice(&((at - 24) as u32).to_le_bytes());
    protect(&mut raw, 40);
    raw
}

struct Device {
    bytes: Vec<u8>,
    reads: Reads,
    fail: Option<(u64, bool)>,
}

impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_exact_at(&self, _: &Cx, at: ByteOffset, out: &mut [u8]) -> Result<()> {
        self.reads.lock().unwrap().push((at.0, out.len()));
        if let Some((offset, cancel)) = self.fail
            && offset == at.0
        {
            return Err(if cancel {
                FfsError::Cancelled
            } else {
                FfsError::Io(std::io::Error::other("indexed fixture I/O failure"))
            });
        }
        let start = usize::try_from(at.0).unwrap();
        let bytes = self
            .bytes
            .get(start..start + out.len())
            .ok_or_else(|| corrupt(0, "fixture read exceeds volume"))?;
        out.copy_from_slice(bytes);
        Ok(())
    }
    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> Result<()> {
        panic!("indexed lookup attempted a backing write")
    }
    fn sync(&self, _: &Cx) -> Result<()> {
        panic!("indexed lookup attempted a backing sync")
    }
}

struct Image(Vec<u8>);

impl Image {
    fn put(&mut self, number: usize, bytes: &[u8]) {
        let at = record_at(number);
        self.0[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn file(&mut self, number: u32, parent: u64, name: &str, namespace: u8) {
        self.put(
            number as usize,
            &record(
                number,
                false,
                &[
                    resident(0x80, 0, "", b"native indexed payload"),
                    resident(0x30, 1, "", &filename(parent, name, namespace)),
                ],
            ),
        );
    }

    fn index(&mut self, entries: &[Vec<u8>], bitmap: u8) {
        self.put(
            5,
            &record(
                5,
                true,
                &[
                    resident(0x90, 0, "$I30", &root(entries, true)),
                    mapped(0xA0, 1, "$I30", &[0x21, 16, 220, 0, 0], 16, 8192),
                    resident(0xB0, 2, "$I30", &[bitmap]),
                ],
            ),
        );
    }

    fn new(external: bool) -> Self {
        let mut image = Self(vec![0; BASE + LENGTH + 512]);
        let boot = &mut image.0[BASE..BASE + 512];
        boot[3..11].copy_from_slice(b"NTFS    ");
        boot[11..13].copy_from_slice(&512_u16.to_le_bytes());
        boot[13] = 1;
        boot[21] = 0xF8;
        boot[36] = 0x80;
        boot[38] = 0x80;
        boot[40..48].copy_from_slice(&1023_u64.to_le_bytes());
        boot[48..56].copy_from_slice(&4_u64.to_le_bytes());
        boot[56..64].copy_from_slice(&128_u64.to_le_bytes());
        boot[64] = 0xF6;
        boot[68] = 0xF4;
        boot[510..512].copy_from_slice(&[0x55, 0xAA]);
        let mft = record(
            0,
            false,
            &[mapped(0x80, 0, "", &[0x11, 64, 4, 0], 64, 32768)],
        );
        image.put(0, &mft);
        image.0[BASE + 128 * 512..BASE + 130 * 512].copy_from_slice(&mft);
        let mut version = [0; 12];
        version[8..10].copy_from_slice(&[3, 1]);
        image.put(3, &record(3, false, &[resident(0x70, 0, "", &version)]));
        image.put(
            10,
            &record(
                10,
                false,
                &[mapped(0x80, 0, "", &[0x22, 0, 1, 44, 1, 0], 256, 131_072)],
            ),
        );
        for unit in 0..=u16::MAX {
            let upper = match unit {
                97..=122 => unit - 32,
                0xE4 => 0xC4,
                _ => unit,
            };
            let at = UPCASE + usize::from(unit) * 2;
            image.0[at..at + 2].copy_from_slice(&upper.to_le_bytes());
        }
        image.put(
            24,
            &record(
                24,
                false,
                &[
                    resident(0x80, 0, "", b"native indexed payload"),
                    resident(0x30, 1, "", &filename(5, "A.txt", 1)),
                    resident(0x30, 2, "", &filename(5, "A~1.TXT", 2)),
                ],
            ),
        );
        for (number, name, ns) in [
            (25, "Z.txt", 1),
            (26, "M.txt", 1),
            (28, "Ä.bin", 1),
            (29, "mixed", 0),
        ] {
            image.file(number, 5, name, ns);
        }
        image.file(30, 27, "child", 1);
        image.put(
            27,
            &record(
                27,
                true,
                &[
                    resident(
                        0x90,
                        0,
                        "$I30",
                        &root(&[key(30, 27, "child", 1, None), terminal(None)], false),
                    ),
                    resident(0x30, 1, "", &filename(5, "Subdir", 1)),
                ],
            ),
        );
        let target: Vec<_> = "Subdir/child".encode_utf16().collect();
        let mut link = vec![0; 20];
        link[..4].copy_from_slice(&0xA000_000C_u32.to_le_bytes());
        link[4..6].copy_from_slice(&(12 + target.len() as u16 * 2).to_le_bytes());
        link[10..12].copy_from_slice(&(target.len() as u16 * 2).to_le_bytes());
        link[16..20].copy_from_slice(&1_u32.to_le_bytes());
        for unit in target {
            link.extend_from_slice(&unit.to_le_bytes());
        }
        image.put(
            31,
            &record(
                31,
                false,
                &[
                    resident(0x30, 0, "", &filename(5, "link", 1)),
                    resident(0xC0, 1, "", &link),
                ],
            ),
        );
        let left = vec![
            key(24, 5, "A.txt", 1, None),
            key(24, 5, "A~1.TXT", 2, None),
            key(31, 5, "link", 1, None),
        ];
        let right = vec![
            key(29, 5, "mixed", 0, None),
            key(27, 5, "Subdir", 1, None),
            key(25, 5, "Z.txt", 1, None),
            key(28, 5, "Ä.bin", 1, None),
        ];
        if external {
            image.index(&[key(26, 5, "M.txt", 1, Some(0)), terminal(Some(8))], 3);
            let mut left = left;
            left.push(terminal(None));
            let mut right = right;
            right.push(terminal(None));
            image.0[LEFT..LEFT + 4096].copy_from_slice(&node(0, &left));
            image.0[RIGHT..RIGHT + 4096].copy_from_slice(&node(8, &right));
        } else {
            let mut all = left;
            all.push(key(26, 5, "M.txt", 1, None));
            all.extend(right);
            all.push(terminal(None));
            image.put(
                5,
                &record(5, true, &[resident(0x90, 0, "$I30", &root(&all, false))]),
            );
        }
        image
    }

    fn open(self, fail: Option<(u64, bool)>) -> (NtfsVolume, Reads) {
        let reads = Arc::default();
        let volume = NtfsVolume::from_device(
            &Cx::for_testing(),
            Box::new(Device {
                bytes: self.0,
                reads: Arc::clone(&reads),
                fail,
            }),
            BASE as u64,
            LENGTH as u64,
        )
        .unwrap();
        reads.lock().unwrap().clear();
        (volume, reads)
    }
}

#[test]
fn indexed_native_resident_external_alias_unicode_posix_and_symlink_paths() {
    let cx = Cx::for_testing();
    for external in [false, true] {
        let (volume, _) = Image::new(external).open(None);
        for (path, expected) in [
            ("/a.TXT", 24),
            ("/a~1.txt", 24),
            ("/ä.BIN", 28),
            ("/m.txt", 26),
            ("/mixed", 29),
            ("/subdir/CHILD", 30),
            ("/link", 30),
        ] {
            assert_eq!(volume.resolve(&cx, path).unwrap().number, expected);
            assert_eq!(volume.resolve_indexed(&cx, path).unwrap().number, expected);
        }
        assert_eq!(
            volume
                .resolve_indexed_no_follow(&cx, "/link")
                .unwrap()
                .number,
            31
        );
        let target = volume.resolve_indexed(&cx, "/a.txt").unwrap();
        let stream = volume.data_stream(&cx, &target, &[]).unwrap();
        assert_eq!(
            volume.read(&cx, &stream, 0, 4096).unwrap(),
            b"native indexed payload"
        );
        assert!(matches!(
            volume.resolve_indexed(&cx, "/MIXED"),
            Err(FfsError::NotFound(_))
        ));
        assert!(matches!(
            volume.resolve_indexed(&cx, "/a.txt/"),
            Err(FfsError::NotDirectory)
        ));
        assert!(volume.resolve_indexed(&cx, "/../a.txt").is_err());
    }
}

#[test]
fn indexed_reads_only_selected_branch_and_target_but_strict_keeps_full_validation() {
    let cx = Cx::for_testing();
    for failure in [RIGHT, record_at(25)] {
        let (volume, reads) = Image::new(true).open(Some((failure as u64, false)));
        assert_eq!(volume.resolve_indexed(&cx, "/a.txt").unwrap().number, 24);
        let actual = reads.lock().unwrap().clone();
        assert!(actual.iter().any(|&(at, _)| at == LEFT as u64));
        assert!(!actual.iter().any(|&(at, _)| at == RIGHT as u64));
        for sibling in [25, 26, 27, 28, 29, 30, 31] {
            assert!(
                !actual
                    .iter()
                    .any(|&(at, _)| at == record_at(sibling) as u64)
            );
        }
        assert!(volume.resolve(&cx, "/a.txt").is_err());
    }
}

fn equal_range() -> Image {
    let mut image = Image::new(true);
    for (number, name) in [(24, "AA"), (26, "Aa"), (25, "aA")] {
        image.file(number, 5, name, 1);
    }
    image.index(&[key(26, 5, "Aa", 1, Some(0)), terminal(Some(8))], 3);
    image.0[LEFT..LEFT + 4096]
        .copy_from_slice(&node(0, &[key(24, 5, "AA", 1, None), terminal(None)]));
    image.0[RIGHT..RIGHT + 4096]
        .copy_from_slice(&node(8, &[key(25, 5, "aA", 1, None), terminal(None)]));
    image
}

#[test]
fn indexed_exact_priority_and_ambiguity_cross_equal_separators() {
    let cx = Cx::for_testing();
    let (volume, reads) = equal_range().open(None);
    for (path, expected) in [("/AA", 24), ("/Aa", 26), ("/aA", 25)] {
        reads.lock().unwrap().clear();
        assert_eq!(volume.resolve_indexed(&cx, path).unwrap().number, expected);
        let actual = reads.lock().unwrap();
        assert!(actual.iter().any(|&(at, _)| at == LEFT as u64));
        assert!(actual.iter().any(|&(at, _)| at == RIGHT as u64));
    }
    assert!(matches!(
        volume.resolve_indexed(&cx, "/aa"),
        Err(FfsError::Corruption { .. })
    ));
    let (volume, _) = equal_range().open(Some((RIGHT as u64, false)));
    // An early exact match cannot hide a failure in the rest of its equal range.
    assert!(volume.resolve_indexed(&cx, "/AA").is_err());
}

#[test]
fn indexed_rejects_duplicate_exact_targets_and_invalid_selected_identities() {
    let cx = Cx::for_testing();
    for case in 0..4 {
        let mut image = Image::new(true);
        match case {
            0 => {
                image.file(25, 5, "A.txt", 1);
                image.0[LEFT..LEFT + 4096].copy_from_slice(&node(
                    0,
                    &[
                        key(24, 5, "A.txt", 1, None),
                        key(25, 5, "A.txt", 1, None),
                        terminal(None),
                    ],
                ));
            }
            1 => image.0[record_at(24) + 16] = 8,
            2 => image.file(24, 27, "A.txt", 1),
            _ => image.0[record_at(24) + 510] ^= 1,
        }
        let (volume, _) = image.open(None);
        assert!(
            matches!(
                volume.resolve_indexed(&cx, "/a.txt"),
                Err(FfsError::Corruption { .. })
            ),
            "case {case}"
        );
    }
}

#[test]
fn indexed_rejects_local_order_bounds_bitmap_alias_and_torn_index_damage() {
    let cx = Cx::for_testing();
    for case in 0..6 {
        let mut image = Image::new(true);
        match case {
            0 => image.0[LEFT..LEFT + 4096].copy_from_slice(&node(
                0,
                &[
                    key(31, 5, "link", 1, None),
                    key(24, 5, "A.txt", 1, None),
                    terminal(None),
                ],
            )),
            1 => image.0[LEFT..LEFT + 4096]
                .copy_from_slice(&node(0, &[key(25, 5, "Z.txt", 1, None), terminal(None)])),
            2 => image.index(&[key(26, 5, "M.txt", 1, Some(0)), terminal(Some(8))], 2),
            3 => image.index(&[key(26, 5, "M.txt", 1, Some(0)), terminal(Some(0))], 3),
            4 => image.0[LEFT + 510] ^= 1,
            _ => image.0[LEFT..LEFT + 4096]
                .copy_from_slice(&node(0, &[key(24, 27, "A.txt", 1, None), terminal(None)])),
        }
        let (volume, reads) = image.open(None);
        assert!(
            matches!(
                volume.resolve_indexed(&cx, "/a.txt"),
                Err(FfsError::Corruption { .. })
            ),
            "case {case}"
        );
        assert!(
            !reads
                .lock()
                .unwrap()
                .iter()
                .any(|&(at, _)| at == record_at(24) as u64)
        );
    }
}

#[test]
fn indexed_miss_and_separator_hit_do_not_open_irrelevant_children() {
    let cx = Cx::for_testing();
    let (volume, reads) = Image::new(true).open(None);
    assert_eq!(volume.resolve_indexed(&cx, "/m.txt").unwrap().number, 26);
    // Equality includes both adjacent children: there could be a later exact match.
    assert!(
        reads
            .lock()
            .unwrap()
            .iter()
            .any(|&(at, _)| at == LEFT as u64)
    );
    assert!(
        reads
            .lock()
            .unwrap()
            .iter()
            .any(|&(at, _)| at == RIGHT as u64)
    );
    reads.lock().unwrap().clear();
    assert!(matches!(
        volume.resolve_indexed(&cx, "/B.txt"),
        Err(FfsError::NotFound(_))
    ));
    let actual = reads.lock().unwrap();
    assert!(!actual.iter().any(|&(at, _)| at == RIGHT as u64));
    for number in 24..32 {
        assert!(!actual.iter().any(|&(at, _)| at == record_at(number) as u64));
    }
}

#[test]
fn indexed_cancellation_is_terminal_and_malformed_upcase_is_not_bypassed() {
    let cx = Cx::for_testing();
    for location in [LEFT, record_at(24)] {
        let (volume, reads) = Image::new(true).open(Some((location as u64, true)));
        assert!(matches!(
            volume.resolve_indexed(&cx, "/a.txt"),
            Err(FfsError::Cancelled)
        ));
        assert_eq!(reads.lock().unwrap().last().unwrap().0, location as u64);
    }
    let (volume, reads) = Image::new(true).open(None);
    let cancelled = Cx::for_testing();
    cancelled.cancel_with(asupersync::types::CancelKind::User, Some("indexed lookup"));
    assert!(matches!(
        volume.resolve_indexed(&cancelled, "/a.txt"),
        Err(FfsError::Cancelled)
    ));
    assert!(reads.lock().unwrap().is_empty());
    let mut image = Image::new(true);
    image.0[UPCASE + 97 * 2..UPCASE + 97 * 2 + 2].copy_from_slice(&97_u16.to_le_bytes());
    let (volume, _) = image.open(None);
    assert!(volume.resolve_indexed(&cx, "/A.txt").is_err());
}

fn same_reference_filename_image(complete: bool, reversed: bool) -> Image {
    let mut image = Image::new(true);
    let mut attributes = vec![
        resident(0x80, 0, "", b"native indexed payload"),
        resident(0x30, 1, "", &filename(5, "A.TXT", 1)),
    ];
    if complete {
        attributes.push(resident(0x30, 2, "", &filename(5, "A.TXT", 2)));
    }
    image.put(24, &record(24, false, &attributes));

    let mut entries = vec![key(24, 5, "A.TXT", 1, None), key(24, 5, "A.TXT", 2, None)];
    if reversed {
        entries.reverse();
    }
    entries.push(terminal(None));
    image.0[LEFT..LEFT + 4096].copy_from_slice(&node(0, &entries));
    image
}

#[test]
fn indexed_rejects_unmatched_same_reference_filename_in_both_orders() {
    let cx = Cx::for_testing();
    let mut indexed_results = Vec::new();

    for reversed in [false, true] {
        let (volume, _) = same_reference_filename_image(false, reversed).open(None);
        for path in ["/A.TXT", "/a.txt"] {
            assert!(
                matches!(volume.resolve(&cx, path), Err(FfsError::Corruption { .. })),
                "strict lookup accepted unmatched identity: reversed={reversed}, path={path}"
            );
            // Execute every order/query combination before asserting, so the
            // planted-red output exposes the order-dependent admission.
            indexed_results.push((
                reversed,
                path,
                volume
                    .resolve_indexed(&cx, path)
                    .map(|record| record.number),
            ));
        }
    }

    assert!(
        indexed_results
            .iter()
            .all(|(_, _, result)| matches!(result, Err(FfsError::Corruption { .. }))),
        "indexed lookup accepted an unmatched FILE_NAME identity: {indexed_results:?}"
    );
}

#[test]
fn indexed_accepts_matching_same_reference_filenames_in_both_orders() {
    let cx = Cx::for_testing();

    for reversed in [false, true] {
        let (volume, _) = same_reference_filename_image(true, reversed).open(None);
        for path in ["/A.TXT", "/a.txt"] {
            assert_eq!(volume.resolve(&cx, path).unwrap().number, 24);
            assert_eq!(volume.resolve_indexed(&cx, path).unwrap().number, 24);
        }
    }
}
