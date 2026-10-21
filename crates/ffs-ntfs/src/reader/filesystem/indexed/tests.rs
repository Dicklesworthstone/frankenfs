//! Constructed native images through FsOps, not kernel-mount/native-OS proof.

use super::*;
use crate::reader::{ByteOffset, NtfsVolume};
use ffs_block::ByteDevice;
use ffs_core::{FsOps, RequestScope};
use std::sync::{Arc, Mutex};

const BASE: usize = 1024;
const LENGTH: usize = 2 * 1024 * 1024;
const INDEX: usize = BASE + 700 * 512;
const SEQUENCE: u16 = 7;

#[derive(Default)]
struct Trace {
    reads: Vec<(u64, usize)>,
    fail: Option<(u64, bool)>,
}

struct Device {
    bytes: Arc<Vec<u8>>,
    trace: Arc<Mutex<Trace>>,
}

impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 { self.bytes.len() as u64 }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        let mut trace = self.trace.lock().unwrap();
        trace.reads.push((offset.0, out.len()));
        if let Some((at, cancel)) = trace.fail
            && offset.0 == at
        {
            return Err(if cancel { FfsError::Cancelled } else {
                FfsError::Io(std::io::Error::other("selected metadata read failed"))
            });
        }
        drop(trace);
        let at = usize::try_from(offset.0).map_err(|_| corrupt(0, "fixture offset"))?;
        let end = at.checked_add(out.len()).ok_or_else(|| corrupt(0, "fixture overflow"))?;
        out.copy_from_slice(self.bytes.get(at..end).ok_or_else(|| corrupt(0, "fixture bounds"))?);
        checkpoint(cx)
    }

    fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> Result<()> {
        panic!("indexed NTFS FsOps wrote its image")
    }

    fn sync(&self, _: &Cx) -> Result<()> {
        panic!("indexed NTFS FsOps synchronized its image")
    }
}

fn protected(mut raw: Vec<u8>, usa: usize) -> Vec<u8> {
    let count = raw.len() / 512 + 1;
    raw[4..6].copy_from_slice(&(usa as u16).to_le_bytes());
    raw[6..8].copy_from_slice(&(count as u16).to_le_bytes());
    raw[usa..usa + 2].copy_from_slice(&0x1357_u16.to_le_bytes());
    for sector in 1..count {
        let at = sector * 512 - 2;
        let saved = [raw[at], raw[at + 1]];
        raw[usa + 2 * sector..usa + 2 * sector + 2].copy_from_slice(&saved);
        raw[at..at + 2].copy_from_slice(&0x1357_u16.to_le_bytes());
    }
    raw
}

fn resident(kind: u32, id: u16, name: &str, value: &[u8]) -> Vec<u8> {
    let units: Vec<_> = name.encode_utf16().collect();
    let start = (24 + units.len() * 2).next_multiple_of(8);
    let length = (start + value.len()).next_multiple_of(8);
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&kind.to_le_bytes());
    bytes[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    bytes[9] = units.len() as u8;
    bytes[10..12].copy_from_slice(&24_u16.to_le_bytes());
    bytes[14..16].copy_from_slice(&id.to_le_bytes());
    bytes[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
    bytes[20..22].copy_from_slice(&(start as u16).to_le_bytes());
    for (i, unit) in units.iter().enumerate() {
        bytes[24 + 2 * i..26 + 2 * i].copy_from_slice(&unit.to_le_bytes());
    }
    bytes[start..start + value.len()].copy_from_slice(value);
    bytes
}

fn mapped(kind: u32, id: u16, name: &str, lcn: u16, clusters: u16) -> Vec<u8> {
    let units: Vec<_> = name.encode_utf16().collect();
    let start = (64 + units.len() * 2).next_multiple_of(8);
    let length = (start + 6).next_multiple_of(8);
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&kind.to_le_bytes());
    bytes[4..8].copy_from_slice(&(length as u32).to_le_bytes());
    bytes[8] = 1;
    bytes[9] = units.len() as u8;
    bytes[10..12].copy_from_slice(&64_u16.to_le_bytes());
    bytes[14..16].copy_from_slice(&id.to_le_bytes());
    bytes[24..32].copy_from_slice(&(u64::from(clusters) - 1).to_le_bytes());
    bytes[32..34].copy_from_slice(&(start as u16).to_le_bytes());
    for at in [40, 48, 56] {
        bytes[at..at + 8].copy_from_slice(&(u64::from(clusters) * 512).to_le_bytes());
    }
    for (i, unit) in units.iter().enumerate() {
        bytes[64 + 2 * i..66 + 2 * i].copy_from_slice(&unit.to_le_bytes());
    }
    bytes[start] = 0x22;
    bytes[start + 1..start + 3].copy_from_slice(&clusters.to_le_bytes());
    bytes[start + 3..start + 5].copy_from_slice(&lcn.to_le_bytes());
    bytes
}

fn file(number: u32, directory: bool, attrs: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![0; 1024];
    bytes[..4].copy_from_slice(b"FILE");
    bytes[16..18].copy_from_slice(&SEQUENCE.to_le_bytes());
    bytes[18..20].copy_from_slice(&2_u16.to_le_bytes());
    bytes[20..22].copy_from_slice(&56_u16.to_le_bytes());
    bytes[22..24].copy_from_slice(&(if directory { 3_u16 } else { 1 }).to_le_bytes());
    bytes[28..32].copy_from_slice(&1024_u32.to_le_bytes());
    bytes[44..48].copy_from_slice(&number.to_le_bytes());
    let mut at = 56;
    for attr in attrs {
        bytes[at..at + attr.len()].copy_from_slice(attr);
        at += attr.len();
    }
    bytes[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    bytes[24..28].copy_from_slice(&((at + 8) as u32).to_le_bytes());
    protected(bytes, 48)
}

fn standard(flags: u32) -> Vec<u8> {
    let mut bytes = [0; 72];
    bytes[32..36].copy_from_slice(&flags.to_le_bytes());
    resident(0x10, 500, "", &bytes)
}

fn filename(parent: u64, name: &str, namespace: u8) -> Vec<u8> {
    let units: Vec<_> = name.encode_utf16().collect();
    let mut bytes = vec![0; 66 + units.len() * 2];
    bytes[..8].copy_from_slice(&((7_u64 << 48) | parent).to_le_bytes());
    bytes[64] = units.len() as u8;
    bytes[65] = namespace;
    for (i, unit) in units.iter().enumerate() {
        bytes[66 + 2 * i..68 + 2 * i].copy_from_slice(&unit.to_le_bytes());
    }
    bytes
}

fn key(number: u64, parent: u64, name: &str, namespace: u8, child: Option<u64>) -> Vec<u8> {
    let value = filename(parent, name, namespace);
    let length = (16 + value.len()).next_multiple_of(8) + usize::from(child.is_some()) * 8;
    let mut bytes = vec![0; length];
    bytes[..8].copy_from_slice(&((7_u64 << 48) | number).to_le_bytes());
    bytes[8..10].copy_from_slice(&(length as u16).to_le_bytes());
    bytes[10..12].copy_from_slice(&(value.len() as u16).to_le_bytes());
    bytes[12..14].copy_from_slice(&u16::from(child.is_some()).to_le_bytes());
    bytes[16..16 + value.len()].copy_from_slice(&value);
    if let Some(vcn) = child { bytes[length - 8..].copy_from_slice(&vcn.to_le_bytes()); }
    bytes
}

fn terminal(child: Option<u64>) -> Vec<u8> {
    let length = if child.is_some() { 24 } else { 16 };
    let mut bytes = vec![0; length];
    bytes[8..10].copy_from_slice(&(length as u16).to_le_bytes());
    bytes[12..14].copy_from_slice(&(2 | u16::from(child.is_some())).to_le_bytes());
    if let Some(vcn) = child { bytes[length - 8..].copy_from_slice(&vcn.to_le_bytes()); }
    bytes
}

fn root(entries: &[Vec<u8>], internal: bool) -> Vec<u8> {
    let mut bytes = vec![0; 32];
    bytes[..4].copy_from_slice(&0x30_u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&1_u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&4096_u32.to_le_bytes());
    bytes[12] = 8;
    bytes[16..20].copy_from_slice(&16_u32.to_le_bytes());
    bytes[28..32].copy_from_slice(&u32::from(internal).to_le_bytes());
    for entry in entries { bytes.extend(entry); }
    let used = (bytes.len() - 16) as u32;
    bytes[20..24].copy_from_slice(&used.to_le_bytes());
    bytes[24..28].copy_from_slice(&used.to_le_bytes());
    resident(0x90, 40, "$I30", &bytes)
}

fn node(vcn: u64, entries: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![0; 4096];
    bytes[..4].copy_from_slice(b"INDX");
    bytes[16..24].copy_from_slice(&vcn.to_le_bytes());
    bytes[24..28].copy_from_slice(&40_u32.to_le_bytes());
    bytes[32..36].copy_from_slice(&4072_u32.to_le_bytes());
    let mut at = 64;
    for entry in entries {
        bytes[at..at + entry.len()].copy_from_slice(entry);
        at += entry.len();
    }
    bytes[28..32].copy_from_slice(&((at - 24) as u32).to_le_bytes());
    protected(bytes, 40)
}

fn file_at(number: u32) -> usize { BASE + 4 * 512 + number as usize * 1024 }
fn put(bytes: &mut [u8], number: u32, record: &[u8]) {
    let at = file_at(number);
    bytes[at..at + 1024].copy_from_slice(record);
}

fn image(external: bool) -> Vec<u8> {
    let mut bytes = vec![0; BASE + LENGTH + 512];
    bytes[..BASE].fill(0xD1);
    bytes[BASE + LENGTH..].fill(0xD2);
    let boot = &mut bytes[BASE..BASE + 512];
    boot[3..11].copy_from_slice(b"NTFS    ");
    boot[11..13].copy_from_slice(&512_u16.to_le_bytes());
    boot[13] = 1;
    boot[21] = 0xF8;
    boot[40..48].copy_from_slice(&((LENGTH / 512 - 1) as u64).to_le_bytes());
    boot[48..56].copy_from_slice(&4_u64.to_le_bytes());
    boot[56..64].copy_from_slice(&128_u64.to_le_bytes());
    boot[64] = 0xF6;
    boot[68] = 0xF4;
    boot[510..512].copy_from_slice(&[0x55, 0xAA]);
    let mft = file(0, false, &[mapped(0x80, 0, "", 4, 80)]);
    put(&mut bytes, 0, &mft);
    bytes[BASE + 128 * 512..BASE + 130 * 512].copy_from_slice(&mft);
    put(&mut bytes, 2, &file(2, false, &[mapped(0x80, 0, "", 192, 64)]));
    bytes[BASE + 192 * 512..BASE + 256 * 512].fill(0xFF);
    let mut info = [0; 12];
    info[8..10].copy_from_slice(&[3, 1]);
    put(&mut bytes, 3, &file(3, false, &[resident(0x70, 0, "", &info)]));
    put(&mut bytes, 10, &file(10, false, &[mapped(0x80, 0, "", 300, 256)]));
    for unit in 0..=u16::MAX {
        let upper = if (97..=122).contains(&unit) { unit - 32 }
            else if unit == 0xE4 { 0xC4 } else { unit };
        let at = BASE + 300 * 512 + usize::from(unit) * 2;
        bytes[at..at + 2].copy_from_slice(&upper.to_le_bytes());
    }
    let mut left = vec![key(24, 5, "Alpha", 1, None), key(24, 5, "ALPHA~1", 2, None), key(31, 5, "link", 1, None)];
    let mut right = vec![key(27, 5, "Subdir", 1, None), key(28, 5, "Zeta", 1, None), key(29, 5, "Ä.bin", 1, None)];
    if external {
        put(&mut bytes, 5, &file(5, true, &[
            standard(0), root(&[key(26, 5, "middle", 0, Some(0)), terminal(Some(8))], true),
            mapped(0xA0, 41, "$I30", 700, 16), resident(0xB0, 42, "$I30", &[3]),
        ]));
        left.push(terminal(None));
        right.push(terminal(None));
        bytes[INDEX..INDEX + 4096].copy_from_slice(&node(0, &left));
        bytes[INDEX + 4096..INDEX + 8192].copy_from_slice(&node(8, &right));
    } else {
        left.push(key(26, 5, "middle", 0, None));
        left.extend(right);
        left.push(terminal(None));
        put(&mut bytes, 5, &file(5, true, &[standard(0), root(&left, false)]));
    }
    put(&mut bytes, 24, &file(24, false, &[
        standard(0), resident(0x80, 0, "", b"alpha-data"),
        resident(0x30, 1, "", &filename(5, "Alpha", 1)),
        resident(0x30, 2, "", &filename(5, "ALPHA~1", 2)),
        resident(0x30, 3, "", &filename(27, "hardlink", 1)),
    ]));
    for (number, name, namespace) in [(26, "middle", 0), (28, "Zeta", 1), (29, "Ä.bin", 1)] {
        put(&mut bytes, number, &file(number, false, &[
            standard(0), resident(0x80, 0, "", name.as_bytes()),
            resident(0x30, 1, "", &filename(5, name, namespace)),
        ]));
    }
    put(&mut bytes, 27, &file(27, true, &[
        standard(0), root(&[key(24, 27, "hardlink", 1, None), terminal(None)], false),
        resident(0x30, 1, "", &filename(5, "Subdir", 1)),
    ]));
    let mut reparse = vec![0; 20];
    reparse[..4].copy_from_slice(&0xA000_000C_u32.to_le_bytes());
    reparse[4..6].copy_from_slice(&22_u16.to_le_bytes());
    reparse[10..12].copy_from_slice(&10_u16.to_le_bytes());
    reparse[16..20].copy_from_slice(&1_u32.to_le_bytes());
    for unit in "Alpha".encode_utf16() { reparse.extend(unit.to_le_bytes()); }
    put(&mut bytes, 31, &file(31, false, &[
        standard(0x400), resident(0xC0, 0, "", &reparse),
        resident(0x30, 1, "", &filename(5, "link", 1)),
    ]));
    bytes
}

fn open(bytes: Arc<Vec<u8>>, trace: &Arc<Mutex<Trace>>, indexed: bool) -> Result<NtfsFs> {
    let cx = Cx::for_testing();
    let volume = NtfsVolume::from_device(&cx, Box::new(Device { bytes, trace: Arc::clone(trace) }), BASE as u64, LENGTH as u64)?;
    if indexed { NtfsFs::new_indexed(&cx, volume, 123, 456) }
    else { NtfsFs::new(&cx, volume, 123, 456) }
}

fn lookup(fs: &NtfsFs, parent: InodeNumber, name: &str) -> Result<InodeAttr> {
    fs.lookup(&Cx::for_testing(), &mut RequestScope::empty(), parent, OsStr::new(name))
}

#[test]
fn indexed_fsops_preserves_native_identity_aliases_hardlinks_and_readonly_operations() {
    let cx = Cx::for_testing();
    for external in [false, true] {
        let bytes = Arc::new(image(external));
        let trace = Arc::new(Mutex::new(Trace::default()));
        let strict = open(Arc::clone(&bytes), &trace, false).unwrap();
        let indexed = open(Arc::clone(&bytes), &trace, true).unwrap();
        for name in ["Alpha", "ALPHA", "alpha~1", "middle", "subdir", "ä.BIN", "link"] {
            let a = lookup(&strict, ROOT, name).unwrap();
            let b = lookup(&indexed, ROOT, name).unwrap();
            assert_eq!((a.ino, a.kind, a.size, a.generation, a.perm), (b.ino, b.kind, b.size, b.generation, b.perm));
            assert_eq!((b.uid, b.gid), (123, 456));
        }
        assert!(matches!(lookup(&indexed, ROOT, "MIDDLE"), Err(FfsError::NotFound(_))));
        let alpha = lookup(&indexed, ROOT, "Alpha").unwrap();
        let directory = lookup(&indexed, ROOT, "Subdir").unwrap();
        assert_eq!(lookup(&indexed, directory.ino, "hardlink").unwrap().ino, alpha.ino);
        assert_eq!(lookup(&indexed, directory.ino, "..").unwrap().ino, ROOT);
        assert_eq!(lookup(&indexed, directory.ino, ".").unwrap().ino, directory.ino);
        assert_eq!(lookup(&indexed, ROOT, "..").unwrap().ino, ROOT);
        let mut scope = RequestScope::empty();
        assert_eq!(indexed.read(&cx, &mut scope, alpha.ino, 3, 4).unwrap(), b"ha-d");
        assert!(indexed.open(&cx, &mut scope, alpha.ino, libc::O_RDONLY).is_ok());
        for flags in [libc::O_WRONLY, libc::O_RDWR, libc::O_TRUNC, libc::O_CREAT] {
            assert!(matches!(indexed.open(&cx, &mut scope, alpha.ino, flags), Err(FfsError::ReadOnly)));
        }
        assert!(matches!(indexed.write(&cx, &mut scope, alpha.ino, 0, b"changed"), Err(FfsError::ReadOnly)));
        let link = lookup(&indexed, ROOT, "link").unwrap();
        assert_eq!(link.kind, FileType::Symlink);
        assert_ne!(link.ino, alpha.ino);
        assert_eq!(indexed.readlink(&cx, &mut scope, link.ino).unwrap(), b"Alpha");
        assert!(indexed.read(&cx, &mut scope, link.ino, 0, 1).is_err());
        indexed.fsync(&cx, &mut scope, alpha.ino, 0, false).unwrap();
        indexed.fsyncdir(&cx, &mut scope, ROOT, 0, false).unwrap();
        assert_eq!(bytes.as_slice(), image(external));
    }
}

#[test]
fn indexed_mount_and_lookup_do_not_open_siblings_but_readdir_still_rejects_their_damage() {
    let mut bytes = image(true);
    bytes[file_at(28) + 16] = 8; // Same name but a stale native sequence.
    let bytes = Arc::new(bytes);
    let trace = Arc::new(Mutex::new(Trace::default()));
    assert!(open(Arc::clone(&bytes), &trace, false).is_err());
    trace.lock().unwrap().reads.clear();
    let fs = open(Arc::clone(&bytes), &trace, true).unwrap();
    assert!(!trace.lock().unwrap().reads.iter().any(|(at, _)| *at == INDEX as u64 || *at == (INDEX + 4096) as u64 || *at == file_at(24) as u64));
    trace.lock().unwrap().reads.clear();
    let file = lookup(&fs, ROOT, "Alpha").unwrap();
    assert!(matches!(lookup(&fs, ROOT, "B-missing"), Err(FfsError::NotFound(_))));
    let reads = trace.lock().unwrap().reads.clone();
    assert!(reads.iter().any(|(at, _)| *at == INDEX as u64));
    assert!(!reads.iter().any(|(at, _)| *at == (INDEX + 4096) as u64 || *at == file_at(28) as u64 || *at == file_at(31) as u64));
    assert!(fs.cache().unwrap().directories.is_empty());
    assert!(matches!(fs.readdir(&Cx::for_testing(), &mut RequestScope::empty(), ROOT, 0), Err(FfsError::Corruption { .. })));
    assert!(fs.cache().unwrap().directories.is_empty());
    assert_eq!(lookup(&fs, ROOT, "Alpha").unwrap().ino, file.ino);
    assert!(matches!(lookup(&fs, ROOT, "Zeta"), Err(FfsError::Corruption { .. })));
}

#[test]
fn indexed_fsops_enumeration_cookies_remain_complete_after_selected_lookups() {
    let fs = open(Arc::new(image(true)), &Arc::default(), true).unwrap();
    lookup(&fs, ROOT, "Alpha").unwrap();
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let entries = fs.readdir(&cx, &mut scope, ROOT, 0).unwrap();
    assert_eq!(entries.len(), 9);
    assert_eq!(entries.end_cookie(), Some(9));
    for (i, entry) in entries.iter().enumerate() {
        assert_eq!(entry.offset, i as u64 + 1);
        let rest = fs.readdir(&cx, &mut scope, ROOT, entry.offset).unwrap();
        assert_eq!(rest.len(), entries.len() - i - 1);
        assert_eq!(rest.end_cookie(), Some(9));
    }
    assert_eq!(fs.cache().unwrap().directories.len(), 1);
}

#[test]
fn indexed_fsops_selected_read_errors_and_cancellation_cannot_use_warm_metadata_as_success() {
    for cancel in [false, true] {
        let trace = Arc::new(Mutex::new(Trace::default()));
        let fs = open(Arc::new(image(true)), &trace, true).unwrap();
        lookup(&fs, ROOT, "Alpha").unwrap();
        trace.lock().unwrap().reads.clear();
        trace.lock().unwrap().fail = Some((INDEX as u64, cancel));
        let result = lookup(&fs, ROOT, "Alpha");
        if cancel { assert!(matches!(result, Err(FfsError::Cancelled))); }
        else { assert!(matches!(result, Err(FfsError::Io(_)))); }
        assert_eq!(trace.lock().unwrap().reads.last().unwrap().0, INDEX as u64);
        assert!(fs.cache().unwrap().directories.is_empty());
        trace.lock().unwrap().fail = None;
        assert!(lookup(&fs, ROOT, "Alpha").is_ok());
        let cx = Cx::for_testing();
        cx.cancel_with(asupersync::types::CancelKind::User, Some("indexed mount lookup"));
        trace.lock().unwrap().reads.clear();
        assert!(matches!(fs.lookup(&cx, &mut RequestScope::empty(), ROOT, OsStr::new("Alpha")), Err(FfsError::Cancelled)));
        assert!(trace.lock().unwrap().reads.is_empty());
    }
}

#[test]
fn indexed_mount_keeps_log_upcase_root_order_and_child_allocation_admission() {
    for case in 0..4 {
        let mut bytes = image(true);
        match case {
            0 => bytes[BASE + 192 * 512 + 32_767] = 0, // Not a completely erased log.
            1 => bytes[BASE + 300 * 512 + usize::from(b'a') * 2] = b'a',
            2 => put(&mut bytes, 5, &file(5, true, &[
                standard(0), root(&[key(28, 5, "Zeta", 1, None), key(24, 5, "Alpha", 1, None), terminal(None)], false),
            ])),
            _ => put(&mut bytes, 5, &file(5, true, &[
                standard(0), root(&[key(26, 5, "middle", 0, Some(0)), terminal(Some(8))], true),
                mapped(0xA0, 41, "$I30", 700, 16), resident(0xB0, 42, "$I30", &[1]),
            ])),
        }
        let trace = Arc::new(Mutex::new(Trace::default()));
        assert!(open(Arc::new(bytes), &trace, true).is_err(), "admission case {case}");
        assert!(!trace.lock().unwrap().reads.iter().any(|(at, _)| *at == INDEX as u64 || *at == (INDEX + 4096) as u64));
    }
}

#[test]
fn indexed_mount_retains_directory_ancestry_and_host_component_refusals() {
    let mut bytes = image(true);
    put(&mut bytes, 27, &file(27, true, &[
        standard(0), root(&[terminal(None)], false),
        resident(0x30, 1, "", &filename(5, "Subdir", 1)),
        resident(0x30, 2, "", &filename(27, "self", 1)),
    ]));
    let fs = open(Arc::new(bytes), &Arc::default(), true).unwrap();
    assert!(matches!(lookup(&fs, ROOT, "Subdir"), Err(FfsError::Corruption { .. })));
    for name in ["", "a/b", "a\\b", "a\0b"] {
        assert!(matches!(lookup(&fs, ROOT, name), Err(FfsError::Format(_))));
    }
    assert!(matches!(lookup(&fs, ROOT, &"a".repeat(256)), Err(FfsError::NameTooLong)));
    let file = lookup(&fs, ROOT, "Alpha").unwrap();
    assert!(matches!(lookup(&fs, file.ino, "child"), Err(FfsError::NotDirectory)));
    use std::os::unix::ffi::OsStrExt;
    assert!(matches!(fs.lookup(&Cx::for_testing(), &mut RequestScope::empty(), ROOT, OsStr::from_bytes(&[0xFF])), Err(FfsError::UnsupportedFeature(_))));
}

#[test]
fn indexed_fsops_checks_the_selected_native_spelling_not_only_the_request() {
    for surrogate in [false, true] {
        let mut bytes = image(false);
        let stored = if surrogate { "X".to_owned() } else { "\u{0800}".repeat(100) };
        let requested = if surrogate { "X".to_owned() } else { "A".repeat(100) };
        let mut value = filename(5, &stored, 1);
        let mut entry = key(24, 5, &stored, 1, None);
        let (unit, folded) = if surrogate { (0xD800_u16, b'X') } else { (0x0800, b'A') };
        if surrogate {
            value[66..68].copy_from_slice(&unit.to_le_bytes());
            entry[82..84].copy_from_slice(&unit.to_le_bytes());
        }
        let at = BASE + 300 * 512 + usize::from(unit) * 2;
        bytes[at..at + 2].copy_from_slice(&u16::from(folded).to_le_bytes());
        put(&mut bytes, 5, &file(5, true, &[standard(0), root(&[entry, terminal(None)], false)]));
        put(&mut bytes, 24, &file(24, false, &[
            standard(0), resident(0x80, 0, "", b"data"), resident(0x30, 1, "", &value),
        ]));
        let fs = open(Arc::new(bytes), &Arc::default(), true).unwrap();
        let result = lookup(&fs, ROOT, &requested);
        if surrogate { assert!(matches!(result, Err(FfsError::UnsupportedFeature(_)))); }
        else { assert!(matches!(result, Err(FfsError::NameTooLong))); }
    }
}
