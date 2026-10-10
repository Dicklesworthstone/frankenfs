use super::*;
use crate::reader::{ByteOffset, Storage};
use ffs_block::ByteDevice;
use std::sync::{Arc, Mutex};

const BASE: usize = 1024;
const LENGTH: usize = 1024 * 512;
const SEQUENCE: u16 = 7;
type Reads = Arc<Mutex<Vec<(u64, usize)>>>;

fn resident(kind: u32, id: u16, name: &str, value: &[u8]) -> Vec<u8> {
    let name: Vec<_> = name.encode_utf16().collect();
    let start = (24 + name.len() * 2).next_multiple_of(8);
    let length = (start + value.len()).next_multiple_of(8);
    let mut attr = vec![0; length];
    attr[..4].copy_from_slice(&kind.to_le_bytes());
    attr[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    attr[9] = name.len() as u8;
    attr[10..12].copy_from_slice(&24_u16.to_le_bytes());
    attr[14..16].copy_from_slice(&id.to_le_bytes());
    attr[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
    attr[20..22].copy_from_slice(&(start as u16).to_le_bytes());
    for (index, unit) in name.iter().enumerate() {
        attr[24 + index * 2..26 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    attr[start..start + value.len()].copy_from_slice(value);
    attr
}

fn mapped(pairs: &[u8], clusters: u64, size: u64, compressed: bool) -> Vec<u8> {
    let start = if compressed { 72_usize } else { 64 };
    let length = (start + pairs.len()).next_multiple_of(8);
    let mut attr = vec![0; length];
    attr[..4].copy_from_slice(&DATA.to_le_bytes());
    attr[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    attr[8] = 1;
    attr[24..32].copy_from_slice(&(clusters - 1).to_le_bytes());
    attr[32..34].copy_from_slice(&(start as u16).to_le_bytes());
    attr[40..48].copy_from_slice(&(clusters * 512).to_le_bytes());
    attr[48..56].copy_from_slice(&size.to_le_bytes());
    attr[56..64].copy_from_slice(&size.to_le_bytes());
    if compressed {
        attr[12..14].copy_from_slice(&1_u16.to_le_bytes());
        attr[34..36].copy_from_slice(&4_u16.to_le_bytes());
        attr[64..72].copy_from_slice(&512_u64.to_le_bytes());
    }
    attr[start..start + pairs.len()].copy_from_slice(pairs);
    attr
}

fn standard() -> Vec<u8> {
    let mut info = [0; 72];
    for (index, time) in [
        UNIX_FILETIME,
        UNIX_FILETIME + 123,
        UNIX_FILETIME + 10_000_000,
        UNIX_FILETIME - 1,
    ]
    .iter()
    .enumerate()
    {
        info[index * 8..index * 8 + 8].copy_from_slice(&time.to_le_bytes());
    }
    resident(0x10, 500, "", &info)
}

fn filename(parent: u64, name: &str, namespace: u8) -> Vec<u8> {
    let units: Vec<_> = name.encode_utf16().collect();
    let mut bytes = vec![0; 66 + units.len() * 2];
    bytes[..8].copy_from_slice(&((u64::from(SEQUENCE) << 48) | parent).to_le_bytes());
    bytes[64] = units.len() as u8;
    bytes[65] = namespace;
    for (index, unit) in units.iter().enumerate() {
        bytes[66 + index * 2..68 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    bytes
}

fn index(children: &[(u32, &str, u8)], parent: u64) -> Vec<u8> {
    let mut root = vec![0; 32];
    root[..4].copy_from_slice(&0x30_u32.to_le_bytes());
    root[4..8].copy_from_slice(&1_u32.to_le_bytes());
    root[8..12].copy_from_slice(&4096_u32.to_le_bytes());
    root[12] = 8;
    root[16..20].copy_from_slice(&16_u32.to_le_bytes());
    for &(record, name, namespace) in children {
        let value = filename(parent, name, namespace);
        let length = (16 + value.len()).next_multiple_of(8);
        let mut entry = vec![0; length];
        entry[..8]
            .copy_from_slice(&((u64::from(SEQUENCE) << 48) | u64::from(record)).to_le_bytes());
        entry[8..10].copy_from_slice(&(length as u16).to_le_bytes());
        entry[10..12].copy_from_slice(&(value.len() as u16).to_le_bytes());
        entry[16..16 + value.len()].copy_from_slice(&value);
        root.extend(entry);
    }
    let mut last = [0; 16];
    last[8] = 16;
    last[12] = 2;
    root.extend(last);
    let used = root.len() as u32 - 16;
    root[20..24].copy_from_slice(&used.to_le_bytes());
    root[24..28].copy_from_slice(&used.to_le_bytes());
    resident(0x90, 40, "$I30", &root)
}

fn record(number: u32, directory: bool, links: u16, attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut raw = vec![0; 1024];
    raw[..4].copy_from_slice(b"FILE");
    raw[4..6].copy_from_slice(&48_u16.to_le_bytes());
    raw[6..8].copy_from_slice(&3_u16.to_le_bytes());
    raw[16..18].copy_from_slice(&SEQUENCE.to_le_bytes());
    raw[18..20].copy_from_slice(&links.to_le_bytes());
    raw[20..22].copy_from_slice(&56_u16.to_le_bytes());
    raw[22..24].copy_from_slice(&(if directory { 3_u16 } else { 1 }).to_le_bytes());
    raw[28..32].copy_from_slice(&1024_u32.to_le_bytes());
    raw[44..48].copy_from_slice(&number.to_le_bytes());
    let mut at = 56;
    for attr in attrs {
        raw[at..at + attr.len()].copy_from_slice(attr);
        at += attr.len();
    }
    raw[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    raw[24..28].copy_from_slice(&((at + 8) as u32).to_le_bytes());
    raw[48..50].copy_from_slice(&0x1234_u16.to_le_bytes());
    for part in 1..=2 {
        let saved = [raw[part * 512 - 2], raw[part * 512 - 1]];
        raw[48 + part * 2..50 + part * 2].copy_from_slice(&saved);
        raw[part * 512 - 2..part * 512].copy_from_slice(&0x1234_u16.to_le_bytes());
    }
    raw
}

fn put(image: &mut [u8], number: u32, bytes: &[u8]) {
    let at = BASE + 4 * 512 + number as usize * 1024;
    image[at..at + 1024].copy_from_slice(bytes);
}

fn image() -> Vec<u8> {
    let mut image = vec![0; BASE + LENGTH + 512];
    image[..BASE].fill(0xD1);
    image[BASE + LENGTH..].fill(0xD2);
    let boot = &mut image[BASE..BASE + 512];
    boot[3..11].copy_from_slice(b"NTFS    ");
    boot[11..13].copy_from_slice(&512_u16.to_le_bytes());
    boot[13] = 1;
    boot[21] = 0xF8;
    boot[40..48].copy_from_slice(&1023_u64.to_le_bytes());
    boot[48..56].copy_from_slice(&4_u64.to_le_bytes());
    boot[56..64].copy_from_slice(&128_u64.to_le_bytes());
    boot[64] = 0xF6;
    boot[68] = 0xF4;
    boot[510..512].copy_from_slice(&[0x55, 0xAA]);
    let mft = record(
        0,
        false,
        1,
        &[
            mapped(&[0x11, 80, 4, 0], 80, 40960, false),
            resident(0xB0, 1, "", &[0xFF, 0, 0, 0x0F, 0x80]),
        ],
    );
    put(&mut image, 0, &mft);
    image[BASE + 128 * 512..BASE + 130 * 512].copy_from_slice(&mft);
    let mut info = [0; 12];
    info[8..10].copy_from_slice(&[3, 1]);
    put(
        &mut image,
        3,
        &record(3, false, 1, &[resident(0x70, 0, "", &info)]),
    );
    put(
        &mut image,
        5,
        &record(
            5,
            true,
            1,
            &[
                standard(),
                index(
                    &[
                        (24, "hello.txt", 1),
                        (24, "HELLO~1.TXT", 2),
                        (26, "packed.bin", 1),
                        (27, "Subdir", 1),
                        (28, "Ä.bin", 1),
                        (29, "mixed", 0),
                    ],
                    5,
                ),
            ],
        ),
    );
    let mut bitmap = [0; 128];
    bitmap[0] = 0xAF;
    bitmap[127] = 0xC0; // Bit 1023 is padding and must not affect the count.
    put(
        &mut image,
        6,
        &record(6, false, 1, &[resident(DATA, 0, "", &bitmap)]),
    );
    put(
        &mut image,
        10,
        &record(
            10,
            false,
            1,
            &[mapped(&[0x22, 0, 1, 44, 1, 0], 256, 131072, false)],
        ),
    );
    for unit in 0..=u16::MAX {
        let upper = if (97..=122).contains(&unit) {
            unit - 32
        } else if unit == 0xE4 {
            0xC4
        } else {
            unit
        };
        let at = BASE + 300 * 512 + usize::from(unit) * 2;
        image[at..at + 2].copy_from_slice(&upper.to_le_bytes());
    }
    put(
        &mut image,
        24,
        &record(
            24,
            false,
            2,
            &[
                standard(),
                resident(DATA, 0, "", b"hello"),
                resident(0x30, 2, "", &filename(5, "hello.txt", 1)),
                resident(0x30, 3, "", &filename(5, "HELLO~1.TXT", 2)),
                resident(0x30, 4, "", &filename(27, "link.txt", 1)),
            ],
        ),
    );
    put(
        &mut image,
        25,
        &record(
            25,
            false,
            1,
            &[
                standard(),
                mapped(&[0x21, 1, 88, 2, 0x11, 1, 0xF6, 0], 2, 600, false),
                resident(0x30, 2, "", &filename(27, "payload.bin", 1)),
            ],
        ),
    );
    image[BASE + 600 * 512..BASE + 601 * 512].fill(b'A');
    image[BASE + 590 * 512..BASE + 591 * 512].fill(b'B');
    put(
        &mut image,
        26,
        &record(
            26,
            false,
            1,
            &[
                standard(),
                mapped(&[0x21, 1, 98, 2, 1, 15, 0], 16, 8192, true),
                resident(0x30, 2, "", &filename(5, "packed.bin", 1)),
            ],
        ),
    );
    let at = BASE + 610 * 512;
    image[at..at + 12]
        .copy_from_slice(&[3, 0xB0, 2, b'C', 0xFC, 0x0F, 3, 0xB0, 2, b'D', 0xFC, 0x0F]);
    put(
        &mut image,
        27,
        &record(
            27,
            true,
            1,
            &[
                standard(),
                index(&[(24, "link.txt", 1), (25, "payload.bin", 1)], 27),
                resident(0x30, 2, "", &filename(5, "Subdir", 1)),
            ],
        ),
    );
    for (number, name, namespace) in [(28, "Ä.bin", 1), (29, "mixed", 0)] {
        put(
            &mut image,
            number,
            &record(
                number,
                false,
                1,
                &[
                    standard(),
                    resident(DATA, 0, "", b"native"),
                    resident(0x30, 2, "", &filename(5, name, namespace)),
                ],
            ),
        );
    }
    image
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
        let start = usize::try_from(offset.0).map_err(|_| corrupt(0, "test offset"))?;
        let bytes = self
            .bytes
            .get(start..start + data.len())
            .ok_or_else(|| corrupt(0, "test read past image"))?;
        data.copy_from_slice(bytes);
        Ok(())
    }
    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _data: &[u8]) -> Result<()> {
        panic!("NTFS FsOps attempted a write");
    }
    fn sync(&self, _cx: &Cx) -> Result<()> {
        panic!("NTFS FsOps attempted a flush");
    }
}

fn open(bytes: Vec<u8>, reads: Reads, fail_at: Option<u64>) -> Result<NtfsFs> {
    let cx = Cx::for_testing();
    let volume = NtfsVolume::from_device(
        &cx,
        Box::new(Memory {
            bytes,
            reads,
            fail_at,
        }),
        BASE as u64,
        LENGTH as u64,
    )?;
    NtfsFs::new(&cx, volume, 123, 456)
}

#[test]
fn root_alias_hard_link_native_names_parent_and_metadata() {
    let cx = Cx::for_testing();
    let fs = open(image(), Arc::default(), None).unwrap();
    let mut scope = RequestScope::empty();
    let root = fs.getattr(&cx, &mut scope, ROOT).unwrap();
    assert_eq!(
        (root.ino, root.uid, root.gid, root.perm),
        (ROOT, 123, 456, 0o555)
    );
    let file = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new("HELLO.txt"))
        .unwrap();
    assert_eq!(
        (file.size, file.blocks, file.nlink, file.perm),
        (5, 0, 2, 0o444)
    );
    assert_eq!(
        file.mtime.duration_since(UNIX_EPOCH).unwrap().as_nanos(),
        12300
    );
    assert_eq!(file.ctime.duration_since(UNIX_EPOCH).unwrap().as_secs(), 1);
    assert_eq!(
        UNIX_EPOCH.duration_since(file.atime).unwrap().as_nanos(),
        100
    );
    assert_eq!(
        fs.lookup(&cx, &mut scope, ROOT, OsStr::new("hello~1.txt"))
            .unwrap()
            .ino,
        file.ino
    );
    let dir = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new("subdir"))
        .unwrap();
    assert_eq!(
        fs.lookup(&cx, &mut scope, dir.ino, OsStr::new("link.txt"))
            .unwrap()
            .ino,
        file.ino
    );
    assert_eq!(
        fs.lookup(&cx, &mut scope, dir.ino, OsStr::new(".."))
            .unwrap()
            .ino,
        ROOT
    );
    assert_eq!(
        fs.lookup(&cx, &mut scope, ROOT, OsStr::new("ä.BIN"))
            .unwrap()
            .size,
        6
    );
    assert!(matches!(
        fs.lookup(&cx, &mut scope, ROOT, OsStr::new("MIXED")),
        Err(FfsError::NotFound(_))
    ));
    assert!(
        fs.lookup(&cx, &mut scope, ROOT, OsStr::new("mixed"))
            .is_ok()
    );
    assert!(
        fs.getattr(&cx, &mut scope, InodeNumber(file.ino.0 + (1 << 32)))
            .is_err()
    );
    assert!(fs.getattr(&cx, &mut scope, InodeNumber(0)).is_err());
    assert!(fs.getattr(&cx, &mut scope, InodeNumber(u64::MAX)).is_err());
}

#[test]
fn fragmented_and_compressed_reads_share_the_native_stream_pipeline() {
    let cx = Cx::for_testing();
    let fs = open(image(), Arc::default(), None).unwrap();
    let mut scope = RequestScope::empty();
    let dir = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new("Subdir"))
        .unwrap();
    let file = fs
        .lookup(&cx, &mut scope, dir.ino, OsStr::new("payload.bin"))
        .unwrap();
    assert_eq!((file.size, file.blocks), (600, 2));
    let mut expected = vec![b'A'; 512];
    expected.extend([b'B'; 88]);
    assert_eq!(
        fs.read(&cx, &mut scope, file.ino, 0, 4096).unwrap(),
        expected
    );
    assert_eq!(
        fs.read(&cx, &mut scope, file.ino, 510, 100).unwrap(),
        expected[510..]
    );
    let compressed = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new("packed.bin"))
        .unwrap();
    assert_eq!((compressed.size, compressed.blocks), (8192, 1));
    assert_eq!(
        fs.read(&cx, &mut scope, compressed.ino, 4094, 4).unwrap(),
        b"CCDD"
    );
    assert!(
        fs.read(&cx, &mut scope, compressed.ino, u64::MAX, 4)
            .unwrap()
            .is_empty()
    );
    assert!(matches!(
        fs.read(&cx, &mut scope, ROOT, 0, 4),
        Err(FfsError::IsDirectory)
    ));
}

#[test]
fn cookies_resume_and_read_only_operations_never_write() {
    let cx = Cx::for_testing();
    let fs = open(image(), Arc::default(), None).unwrap();
    let mut scope = RequestScope::empty();
    let page = fs.readdir(&cx, &mut scope, ROOT, 0).unwrap();
    assert_eq!(page.len(), 8);
    assert_eq!(page.end_cookie(), Some(8));
    for (index, entry) in page.iter().enumerate() {
        assert_eq!(entry.offset, index as u64 + 1);
        let tail = fs.readdir(&cx, &mut scope, ROOT, entry.offset).unwrap();
        assert_eq!(tail.len(), page.len() - index - 1);
        if let Some(first) = tail.first() {
            assert_eq!(*first, page[index + 1]);
        }
    }
    let file = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new("hello.txt"))
        .unwrap();
    assert!(fs.open(&cx, &mut scope, file.ino, libc::O_RDONLY).is_ok());
    for flags in [libc::O_WRONLY, libc::O_RDWR, libc::O_TRUNC, libc::O_CREAT] {
        assert!(matches!(
            fs.open(&cx, &mut scope, file.ino, flags),
            Err(FfsError::ReadOnly)
        ));
    }
    assert!(matches!(
        fs.write(&cx, &mut scope, file.ino, 0, b"bad"),
        Err(FfsError::ReadOnly)
    ));
    assert!(matches!(
        fs.unlink(&cx, &mut scope, ROOT, OsStr::new("hello.txt")),
        Err(FfsError::ReadOnly)
    ));
    fs.fsync(&cx, &mut scope, file.ino, 0, false).unwrap();
    fs.fsyncdir(&cx, &mut scope, ROOT, 0, false).unwrap();
    assert_eq!(
        fs.lseek(&cx, &mut scope, file.ino, 1, SeekWhence::Data)
            .unwrap(),
        1
    );
    assert_eq!(
        fs.lseek(&cx, &mut scope, file.ino, 1, SeekWhence::Hole)
            .unwrap(),
        5
    );
    assert!(
        fs.lseek(&cx, &mut scope, file.ino, 5, SeekWhence::Hole)
            .is_err()
    );
}

#[test]
fn allocation_bitmaps_ignore_tail_padding_and_require_initialized_coverage() {
    let cx = Cx::for_testing();
    let fs = open(image(), Arc::default(), None).unwrap();
    let mut scope = RequestScope::empty();
    let stat = fs.statfs(&cx, &mut scope, ROOT).unwrap();
    assert_eq!(
        (stat.blocks, stat.blocks_free, stat.files, stat.files_free),
        (1023, 1016, 40, 27)
    );
    let short = Stream {
        storage: Storage::Resident(vec![0]),
        size: 1,
        initialized: 0,
        allocated: 1,
    };
    assert!(fs.count_free(&cx, &short, 8).is_err());
}

#[test]
fn reparse_and_cancellation_never_return_successful_data() {
    let cx = Cx::for_testing();
    let fs = open(image(), Arc::default(), Some((BASE + 590 * 512) as u64)).unwrap();
    let mut scope = RequestScope::empty();
    let dir = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new("Subdir"))
        .unwrap();
    let file = fs
        .lookup(&cx, &mut scope, dir.ino, OsStr::new("payload.bin"))
        .unwrap();
    assert!(matches!(
        fs.read(&cx, &mut scope, file.ino, 0, 600),
        Err(FfsError::Cancelled)
    ));
    let mut bytes = image();
    put(
        &mut bytes,
        29,
        &record(
            29,
            false,
            1,
            &[
                standard(),
                resident(DATA, 0, "", b"native"),
                resident(0x30, 2, "", &filename(5, "mixed", 0)),
                resident(0xC0, 3, "", &[0; 8]),
            ],
        ),
    );
    let fs = open(bytes, Arc::default(), None).unwrap();
    assert!(matches!(
        fs.lookup(&cx, &mut scope, ROOT, OsStr::new("mixed")),
        Err(FfsError::UnsupportedFeature(_))
    ));
}

#[test]
fn filetime_conversion_is_exact_on_both_sides_of_unix_epoch() {
    assert_eq!(filetime(UNIX_FILETIME).unwrap(), UNIX_EPOCH);
    assert_eq!(
        filetime(UNIX_FILETIME + 1)
            .unwrap()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        100
    );
    assert_eq!(
        UNIX_EPOCH
            .duration_since(filetime(UNIX_FILETIME - 1).unwrap())
            .unwrap()
            .as_nanos(),
        100
    );
    assert!(filetime(u64::MAX).is_err());
}

#[test]
fn warm_lookup_readdir_and_statfs_do_not_rescan_native_metadata() {
    let cx = Cx::for_testing();
    let reads: Reads = Arc::default();
    let fs = open(image(), Arc::clone(&reads), None).unwrap();
    let mut scope = RequestScope::empty();
    let file = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new("hello.txt"))
        .unwrap();
    fs.statfs(&cx, &mut scope, ROOT).unwrap();
    fs.open(&cx, &mut scope, file.ino, libc::O_RDONLY).unwrap();
    reads.lock().unwrap().clear();
    for _ in 0..10 {
        assert_eq!(
            fs.lookup(&cx, &mut scope, ROOT, OsStr::new("HELLO.TXT"))
                .unwrap()
                .ino,
            file.ino
        );
        assert_eq!(
            fs.lookup(&cx, &mut scope, ROOT, OsStr::new("hello~1.txt"))
                .unwrap()
                .ino,
            file.ino
        );
        assert_eq!(fs.readdir(&cx, &mut scope, ROOT, 2).unwrap().len(), 6);
        assert_eq!(fs.read(&cx, &mut scope, file.ino, 0, 50).unwrap(), b"hello");
        assert_eq!(fs.statfs(&cx, &mut scope, ROOT).unwrap().blocks_free, 1016);
    }
    assert!(reads.lock().unwrap().is_empty());
    let cache = fs.cache().unwrap();
    assert!(cache.directory_bytes <= DIRECTORY_CACHE_BYTES);
    assert!(cache.directories.len() <= MAX_CACHED_DIRECTORIES);
    assert!(cache.attributes.len() <= MAX_CACHED_ATTRIBUTES);
    assert!(cache.streams.len() <= MAX_CACHED_STREAMS);
}

#[test]
fn cached_streams_keep_data_io_and_cancellation_live() {
    let cx = Cx::for_testing();
    let reads: Reads = Arc::default();
    let fs = open(image(), Arc::clone(&reads), Some((BASE + 590 * 512) as u64)).unwrap();
    let mut scope = RequestScope::empty();
    let dir = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new("Subdir"))
        .unwrap();
    let file = fs
        .lookup(&cx, &mut scope, dir.ino, OsStr::new("payload.bin"))
        .unwrap();
    fs.open(&cx, &mut scope, file.ino, libc::O_RDONLY).unwrap();
    reads.lock().unwrap().clear();
    for _ in 0..2 {
        assert!(matches!(
            fs.read(&cx, &mut scope, file.ino, 510, 4),
            Err(FfsError::Cancelled)
        ));
    }
    assert_eq!(
        *reads.lock().unwrap(),
        [
            ((BASE + 600 * 512 + 510) as u64, 2),
            ((BASE + 590 * 512) as u64, 2),
            ((BASE + 600 * 512 + 510) as u64, 2),
            ((BASE + 590 * 512) as u64, 2),
        ]
    );
}

#[test]
fn root_aliases_and_inconsistent_directory_parents_refuse_mounting() {
    let mut bytes = image();
    put(
        &mut bytes,
        5,
        &record(
            5,
            true,
            1,
            &[
                standard(),
                index(&[(5, "LOOP", 1)], 5),
                resident(0x30, 2, "", &filename(5, "LOOP", 1)),
            ],
        ),
    );
    assert!(open(bytes, Arc::default(), None).is_err());
    let mut bytes = image();
    put(
        &mut bytes,
        27,
        &record(
            27,
            true,
            1,
            &[
                standard(),
                index(&[], 27),
                resident(0x30, 2, "", &filename(5, "Subdir", 1)),
                resident(0x30, 3, "", &filename(27, "LOOP", 1)),
            ],
        ),
    );
    assert!(open(bytes, Arc::default(), None).is_err());
}

#[test]
fn a_sparse_bitmap_cannot_turn_missing_allocation_metadata_into_free_space() {
    let cx = Cx::for_testing();
    let fs = open(image(), Arc::default(), None).unwrap();
    let bitmap = Stream {
        storage: Storage::Mapped(vec![crate::reader::NtfsRun {
            vcn: 0,
            clusters: 1,
            lcn: None,
        }]),
        size: 512,
        initialized: 512,
        allocated: 0,
    };
    assert!(matches!(
        fs.count_free(&cx, &bitmap, 8),
        Err(FfsError::Corruption { .. })
    ));
}

#[test]
fn stream_eviction_keeps_the_limit_and_reloads_exact_data() {
    let cx = Cx::for_testing();
    let mut bytes = image();
    for number in 30..40 {
        put(
            &mut bytes,
            number,
            &record(
                number,
                false,
                1,
                &[standard(), resident(DATA, 0, "", &number.to_le_bytes())],
            ),
        );
    }
    let fs = open(bytes, Arc::default(), None).unwrap();
    let mut scope = RequestScope::empty();
    for number in 30..40 {
        let ino = fs
            .inode(NtfsReference {
                record: number,
                sequence: SEQUENCE,
            })
            .unwrap();
        fs.open(&cx, &mut scope, ino, libc::O_RDONLY).unwrap();
        assert_eq!(
            fs.read(&cx, &mut scope, ino, 0, 4).unwrap(),
            (number as u32).to_le_bytes()
        );
    }
    let first = fs
        .inode(NtfsReference {
            record: 30,
            sequence: SEQUENCE,
        })
        .unwrap();
    {
        let cache = fs.cache().unwrap();
        assert_eq!(cache.streams.len(), MAX_CACHED_STREAMS);
        assert!(!cache.streams.contains_key(&first));
    }
    assert_eq!(
        fs.read(&cx, &mut scope, first, 0, 4).unwrap(),
        30_u32.to_le_bytes()
    );
    assert_eq!(fs.cache().unwrap().streams.len(), MAX_CACHED_STREAMS);
}
