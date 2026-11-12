//! Independently encoded, image-backed public recovery fixtures. Not Windows evidence.
use super::*;
use ffs_block::ByteDevice;
use ffs_types::ByteOffset;
use reader::FfsError;
use std::sync::{Arc, Mutex};

const PAGE: usize = 4096;
const LOG_BYTES: usize = 50 * PAGE;
const BASE: usize = 4096;
const VOLUME_BYTES: usize = 4 * 1024 * 1024;
const LOG_LCN: usize = 512;
const RING: usize = 34 * PAGE;
const POSITIONS: [usize; 5] = [64, 216, 328, 440, 528];

#[derive(Default)]
struct Trace {
    writes: usize,
    fail_at: Option<u64>,
}
struct Memory {
    bytes: Vec<u8>,
    trace: Arc<Mutex<Trace>>,
}
impl ByteDevice for Memory {
    fn len_bytes(&self) -> u64 {
        self.bytes.len() as u64
    }
    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        if self.trace.lock().unwrap().fail_at == Some(offset.0) {
            return Err(FfsError::Cancelled);
        }
        let at = usize::try_from(offset.0).map_err(|_| corrupt(0, "fixture offset"))?;
        let end = at
            .checked_add(out.len())
            .ok_or_else(|| corrupt(0, "fixture length"))?;
        out.copy_from_slice(
            self.bytes
                .get(at..end)
                .ok_or_else(|| corrupt(0, "fixture bounds"))?,
        );
        Ok(())
    }
    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _bytes: &[u8]) -> Result<()> {
        self.trace.lock().unwrap().writes += 1;
        panic!("native public recovery attempted a backing write");
    }
    fn sync(&self, _cx: &Cx) -> Result<()> {
        self.trace.lock().unwrap().writes += 1;
        panic!("native public recovery attempted backing synchronization");
    }
}

fn protected(mut bytes: Vec<u8>, usa: usize, token: u16) -> Vec<u8> {
    let count = bytes.len() / 512 + 1;
    bytes[4..6].copy_from_slice(&(usa as u16).to_le_bytes());
    bytes[6..8].copy_from_slice(&(count as u16).to_le_bytes());
    bytes[usa..usa + 2].copy_from_slice(&token.to_le_bytes());
    for sector in 1..count {
        let at = sector * 512 - 2;
        let saved = [bytes[at], bytes[at + 1]];
        bytes[usa + 2 * sector..usa + 2 * sector + 2].copy_from_slice(&saved);
        bytes[at..at + 2].copy_from_slice(&token.to_le_bytes());
    }
    bytes
}

fn resident(kind: u32, id: u16, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; (24 + value.len()).next_multiple_of(8)];
    let length = bytes.len() as u32;
    bytes[..4].copy_from_slice(&kind.to_le_bytes());
    bytes[4..8].copy_from_slice(&length.to_le_bytes());
    bytes[14..16].copy_from_slice(&id.to_le_bytes());
    bytes[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
    bytes[20..22].copy_from_slice(&24_u16.to_le_bytes());
    bytes[24..24 + value.len()].copy_from_slice(value);
    bytes
}

fn mapped(lcn: u16, clusters: u16) -> Vec<u8> {
    let mut bytes = vec![0; 72];
    bytes[..4].copy_from_slice(&DATA.to_le_bytes());
    bytes[4..8].copy_from_slice(&72_u32.to_le_bytes());
    bytes[8] = 1;
    bytes[24..32].copy_from_slice(&(u64::from(clusters) - 1).to_le_bytes());
    bytes[32..34].copy_from_slice(&64_u16.to_le_bytes());
    for at in [40, 48, 56] {
        bytes[at..at + 8].copy_from_slice(&(u64::from(clusters) * 512).to_le_bytes());
    }
    bytes[64] = 0x22;
    bytes[65..67].copy_from_slice(&clusters.to_le_bytes());
    bytes[67..69].copy_from_slice(&lcn.to_le_bytes());
    bytes
}

fn file(number: u32, attributes: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![0; 1024];
    bytes[..4].copy_from_slice(b"FILE");
    bytes[16..18].copy_from_slice(&7_u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&1_u16.to_le_bytes());
    bytes[20..22].copy_from_slice(&64_u16.to_le_bytes());
    bytes[22..24].copy_from_slice(&1_u16.to_le_bytes());
    bytes[28..32].copy_from_slice(&1024_u32.to_le_bytes());
    bytes[40..42].copy_from_slice(&2_u16.to_le_bytes());
    bytes[44..48].copy_from_slice(&number.to_le_bytes());
    let mut at = 64;
    for attribute in attributes {
        bytes[at..at + attribute.len()].copy_from_slice(attribute);
        at += attribute.len();
    }
    bytes[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    bytes[24..28].copy_from_slice(&((at + 8) as u32).to_le_bytes());
    protected(bytes, 48, 0xCAFE)
}

fn lsn(index: usize) -> u64 {
    (1_u64 << 15) | ((RING + POSITIONS[index]) as u64 / 8)
}

fn change(number: u64, redo: &[u8], undo: &[u8]) -> Vec<u8> {
    let mut data = vec![0; 64];
    data[..2].copy_from_slice(&7_u16.to_le_bytes());
    data[2..4].copy_from_slice(&7_u16.to_le_bytes());
    data[4..6].copy_from_slice(&48_u16.to_le_bytes());
    data[6..8].copy_from_slice(&8_u16.to_le_bytes());
    data[8..10].copy_from_slice(&56_u16.to_le_bytes());
    data[10..12].copy_from_slice(&8_u16.to_le_bytes());
    data[12..14].copy_from_slice(&24_u16.to_le_bytes());
    data[14..16].copy_from_slice(&2_u16.to_le_bytes());
    data[16..18].copy_from_slice(&64_u16.to_le_bytes());
    data[18..20].copy_from_slice(&24_u16.to_le_bytes());
    data[24..32].copy_from_slice(&(number * 2).to_le_bytes());
    data[32..40].copy_from_slice(&(128 + number * 2).to_le_bytes());
    data[40..48].copy_from_slice(&(129 + number * 2).to_le_bytes());
    data[48..56].copy_from_slice(redo);
    data[56..64].copy_from_slice(undo);
    data
}

fn restart_page(clean: bool) -> Vec<u8> {
    let mut page = vec![0; PAGE];
    page[..4].copy_from_slice(b"RSTR");
    page[16..20].copy_from_slice(&(PAGE as u32).to_le_bytes());
    page[20..24].copy_from_slice(&(PAGE as u32).to_le_bytes());
    page[24..26].copy_from_slice(&64_u16.to_le_bytes());
    page[28..30].copy_from_slice(&2_u16.to_le_bytes());
    let area = &mut page[64..288];
    area[..8].copy_from_slice(&lsn(1).to_le_bytes());
    area[8..10].copy_from_slice(&1_u16.to_le_bytes());
    area[10..12].copy_from_slice(&u16::MAX.to_le_bytes());
    area[14..16].copy_from_slice(&(if clean { 2_u16 } else { 0 }).to_le_bytes());
    area[16..20].copy_from_slice(&49_u32.to_le_bytes());
    area[20..22].copy_from_slice(&224_u16.to_le_bytes());
    area[22..24].copy_from_slice(&64_u16.to_le_bytes());
    area[24..32].copy_from_slice(&(LOG_BYTES as u64).to_le_bytes());
    area[32..36].copy_from_slice(&64_u32.to_le_bytes());
    area[36..38].copy_from_slice(&48_u16.to_le_bytes());
    area[38..40].copy_from_slice(&64_u16.to_le_bytes());
    area[64..72].copy_from_slice(&lsn(0).to_le_bytes());
    area[72..80].copy_from_slice(&lsn(1).to_le_bytes());
    area[80..82].copy_from_slice(&u16::MAX.to_le_bytes());
    area[82..84].copy_from_slice(&u16::MAX.to_le_bytes());
    area[84..86].copy_from_slice(&9_u16.to_le_bytes());
    area[92..96].copy_from_slice(&8_u32.to_le_bytes());
    area[96..104].copy_from_slice(b"N\0T\0F\0S\0");
    protected(page, 32, 0xBEEF)
}

fn journal_page(last: usize, decision: u16) -> Vec<u8> {
    let mut dump = vec![0; 104];
    dump[..2].copy_from_slice(&0x1D_u16.to_le_bytes());
    dump[4..6].copy_from_slice(&40_u16.to_le_bytes());
    dump[6..8].copy_from_slice(&64_u16.to_le_bytes());
    dump[40..42].copy_from_slice(&40_u16.to_le_bytes());
    dump[42..44].copy_from_slice(&1_u16.to_le_bytes());
    dump[44..46].copy_from_slice(&1_u16.to_le_bytes());
    dump[64..68].copy_from_slice(&u32::MAX.to_le_bytes());
    dump[72..76].copy_from_slice(&DATA.to_le_bytes());
    dump[80..88].copy_from_slice(&(7_u64 << 48).to_le_bytes());
    let mut checkpoint = vec![0; 64];
    checkpoint[..4].copy_from_slice(&1_u32.to_le_bytes());
    checkpoint[8..16].copy_from_slice(&lsn(1).to_le_bytes());
    checkpoint[16..24].copy_from_slice(&lsn(0).to_le_bytes());
    checkpoint[48..52].copy_from_slice(&64_u32.to_le_bytes());
    let mut commit = vec![0; 40];
    commit[..2].copy_from_slice(&decision.to_le_bytes());
    let payloads = [
        dump,
        checkpoint,
        change(42, b"winner!!", b"original"),
        commit,
        change(43, b"loserbad", b"original"),
    ];
    let mut page = vec![0; PAGE];
    page[..4].copy_from_slice(b"RCRD");
    page[8..16].copy_from_slice(&lsn(last).to_le_bytes());
    page[16..20].copy_from_slice(&1_u32.to_le_bytes());
    page[20..22].copy_from_slice(&1_u16.to_le_bytes());
    page[22..24].copy_from_slice(&1_u16.to_le_bytes());
    let end = POSITIONS[last] + 48 + payloads[last].len();
    page[24..26].copy_from_slice(&(end as u16).to_le_bytes());
    page[32..40].copy_from_slice(&lsn(last).to_le_bytes());
    for index in 0..=last {
        let at = POSITIONS[index];
        let data = &payloads[index];
        page[at..at + 8].copy_from_slice(&lsn(index).to_le_bytes());
        if index == 3 {
            page[at + 8..at + 16].copy_from_slice(&lsn(2).to_le_bytes());
            page[at + 16..at + 24].copy_from_slice(&lsn(2).to_le_bytes());
        }
        page[at + 24..at + 28].copy_from_slice(&(data.len() as u32).to_le_bytes());
        page[at + 28..at + 30].copy_from_slice(&9_u16.to_le_bytes());
        page[at + 32..at + 36].copy_from_slice(&(if index == 1 { 2_u32 } else { 1 }).to_le_bytes());
        let owner = if index == 1 {
            0_u32
        } else if index == 4 {
            64
        } else {
            24
        };
        page[at + 36..at + 40].copy_from_slice(&owner.to_le_bytes());
        page[at + 48..at + 48 + data.len()].copy_from_slice(data);
    }
    protected(page, 40, 0xABCD)
}

fn image(bank: bool, decision: u16) -> Vec<u8> {
    let mut bytes = vec![0; BASE + VOLUME_BYTES + PAGE];
    bytes[..BASE].fill(0xD1);
    bytes[BASE + VOLUME_BYTES..].fill(0xD2);
    let boot = &mut bytes[BASE..BASE + 512];
    boot[3..11].copy_from_slice(b"NTFS    ");
    boot[11..13].copy_from_slice(&512_u16.to_le_bytes());
    boot[13] = 1;
    boot[40..48].copy_from_slice(&((VOLUME_BYTES / 512) as u64).to_le_bytes());
    boot[48..56].copy_from_slice(&128_u64.to_le_bytes());
    boot[56..64].copy_from_slice(&8_u64.to_le_bytes());
    boot[64] = 246;
    boot[68] = 244;
    boot[510..512].copy_from_slice(&0xAA55_u16.to_le_bytes());
    let mut info = [0; 12];
    info[8..10].copy_from_slice(&[3, 1]);
    info[10] = 1;
    let mft = file(0, &[mapped(128, 128), resident(0xB0, 1, &[0xFF; 8])]);
    bytes[BASE + 8 * 512..BASE + 8 * 512 + 1024].copy_from_slice(&mft);
    for (number, record) in [
        (0, mft),
        (
            2,
            file(2, &[mapped(LOG_LCN as u16, (LOG_BYTES / 512) as u16)]),
        ),
        (3, file(3, &[resident(0x70, 0, &info)])),
        (6, file(6, &[mapped(400, 2)])),
        (42, file(42, &[resident(DATA, 0, b"original")])),
        (43, file(43, &[resident(DATA, 0, b"loserbad")])),
    ] {
        let at = BASE + 128 * 512 + number * 1024;
        bytes[at..at + 1024].copy_from_slice(&record);
    }
    bytes[BASE + 400 * 512..BASE + 402 * 512].fill(0xFF);
    let log = &mut bytes[BASE + LOG_LCN * 512..BASE + LOG_LCN * 512 + LOG_BYTES];
    log.fill(0xFF);
    log[..PAGE].copy_from_slice(&restart_page(false));
    log[PAGE..2 * PAGE].copy_from_slice(&restart_page(false));
    if bank {
        log[RING..RING + PAGE].copy_from_slice(&journal_page(1, decision));
        let mut copy = journal_page(4, decision);
        copy[60..64].copy_from_slice(&(RING as u32).to_le_bytes());
        log[2 * PAGE..3 * PAGE].copy_from_slice(&copy);
    } else {
        log[RING..RING + PAGE].copy_from_slice(&journal_page(4, decision));
    }
    bytes
}

fn open(bytes: Vec<u8>, trace: &Arc<Mutex<Trace>>) -> Result<NtfsVolume> {
    NtfsVolume::from_device_with_options(
        &Cx::for_testing(),
        Box::new(Memory {
            bytes,
            trace: Arc::clone(trace),
        }),
        BASE as u64,
        VOLUME_BYTES as u64,
        true,
    )
}

fn value(volume: &NtfsVolume, number: u64) -> Vec<u8> {
    let cx = Cx::for_testing();
    let file = volume.record(&cx, number, Some(7)).unwrap();
    let stream = volume.data_stream(&cx, &file, &[]).unwrap();
    volume.read(&cx, &stream, 0, 64).unwrap()
}

fn mount_filename(name: &str) -> Vec<u8> {
    let units: Vec<_> = name.encode_utf16().collect();
    let mut bytes = vec![0; 66 + units.len() * 2];
    bytes[..8].copy_from_slice(&((7_u64 << 48) | 5).to_le_bytes());
    bytes[40..48].copy_from_slice(&8_u64.to_le_bytes());
    bytes[48..56].copy_from_slice(&8_u64.to_le_bytes());
    bytes[64] = units.len() as u8;
    bytes[65] = 1;
    for (index, unit) in units.iter().enumerate() {
        bytes[66 + index * 2..68 + index * 2].copy_from_slice(&unit.to_le_bytes());
    }
    bytes
}

fn mount_index() -> Vec<u8> {
    let mut value = vec![0; 32];
    value[..4].copy_from_slice(&0x30_u32.to_le_bytes());
    value[4..8].copy_from_slice(&1_u32.to_le_bytes());
    value[8..12].copy_from_slice(&4096_u32.to_le_bytes());
    value[12] = 8;
    value[16..20].copy_from_slice(&16_u32.to_le_bytes());
    for (number, name) in [(43_u64, "loser"), (42, "winner")] {
        let name = mount_filename(name);
        let mut entry = vec![0; (16 + name.len()).next_multiple_of(8)];
        let length = entry.len() as u16;
        entry[..8].copy_from_slice(&((7_u64 << 48) | number).to_le_bytes());
        entry[8..10].copy_from_slice(&length.to_le_bytes());
        entry[10..12].copy_from_slice(&(name.len() as u16).to_le_bytes());
        entry[16..16 + name.len()].copy_from_slice(&name);
        value.extend(entry);
    }
    let mut end = [0; 16];
    end[8] = 16;
    end[12] = 2;
    value.extend(end);
    let length = value.len() as u32 - 16;
    value[20..24].copy_from_slice(&length.to_le_bytes());
    value[24..28].copy_from_slice(&length.to_le_bytes());

    let mut attribute = vec![0; (32 + value.len()).next_multiple_of(8)];
    let length = attribute.len() as u32;
    attribute[..4].copy_from_slice(&0x90_u32.to_le_bytes());
    attribute[4..8].copy_from_slice(&length.to_le_bytes());
    attribute[9] = 4;
    attribute[10..12].copy_from_slice(&24_u16.to_le_bytes());
    attribute[14..16].copy_from_slice(&1_u16.to_le_bytes());
    attribute[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
    attribute[20..22].copy_from_slice(&32_u16.to_le_bytes());
    attribute[24..32].copy_from_slice(&[b'$', 0, b'I', 0, b'3', 0, b'0', 0]);
    attribute[32..32 + value.len()].copy_from_slice(&value);
    attribute
}

fn mountable_image(bank: bool, decision: u16) -> Vec<u8> {
    let mut bytes = image(bank, decision);
    let mut standard = [0; 72];
    for field in 0..4 {
        standard[field * 8..field * 8 + 8]
            .copy_from_slice(&116_444_736_000_000_000_u64.to_le_bytes());
    }
    let standard = resident(0x10, 0, &standard);
    let mut root_name = mount_filename(".");
    root_name[40..56].fill(0);
    root_name[65] = 3;
    let mut root = file(
        5,
        &[
            standard.clone(),
            resident(0x30, 2, &root_name),
            mount_index(),
        ],
    );
    root[22..24].copy_from_slice(&3_u16.to_le_bytes());
    root[40..42].copy_from_slice(&3_u16.to_le_bytes());
    let upcase = file(10, &[mapped(1024, 256)]);
    for (number, record) in [(5, root), (10, upcase)] {
        let at = BASE + 128 * 512 + number * 1024;
        bytes[at..at + 1024].copy_from_slice(&record);
    }
    for unit in 0..=u16::MAX {
        let upper = if (97..=122).contains(&unit) {
            unit - 32
        } else {
            unit
        };
        let at = BASE + 1024 * 512 + usize::from(unit) * 2;
        bytes[at..at + 2].copy_from_slice(&upper.to_le_bytes());
    }
    for (number, name, data, action) in [
        (42, "winner", &b"original"[..], 2),
        (43, "loser", &b"loserbad"[..], 4),
    ] {
        let filename = resident(0x30, 1, &mount_filename(name));
        let data_offset = (64 + standard.len() + filename.len()) as u16;
        let mut record = file(
            number,
            &[standard.clone(), filename, resident(DATA, 2, data)],
        );
        record[40..42].copy_from_slice(&3_u16.to_le_bytes());
        let at = BASE + 128 * 512 + number as usize * 1024;
        bytes[at..at + 1024].copy_from_slice(&record);
        let page = if bank { 2 * PAGE } else { RING };
        let at = BASE + LOG_LCN * 512 + page + POSITIONS[action] + 48 + 16;
        bytes[at..at + 2].copy_from_slice(&data_offset.to_le_bytes());
    }
    bytes
}

#[test]
fn recovered_fsops_expose_complete_redo_undo_without_backing_writes() {
    use crate::NtfsFs;
    use ffs_core::{FsOps, RequestScope};
    use ffs_types::InodeNumber;
    use std::ffi::OsStr;

    let cx = Cx::for_testing();
    for bank in [false, true] {
        for indexed in [false, true] {
            let trace = Arc::new(Mutex::new(Trace::default()));
            let original = mountable_image(bank, 0x1A);
            let volume = open(original.clone(), &trace).unwrap();
            let fs = if indexed {
                NtfsFs::new_recovered_indexed(&cx, volume, 123, 456)
            } else {
                NtfsFs::new_recovered(&cx, volume, 123, 456)
            }
            .unwrap();
            let mut scope = RequestScope::empty();
            let root = InodeNumber(1);
            let entries = fs.readdir(&cx, &mut scope, root, 0).unwrap();
            assert!(entries.iter().any(|entry| entry.name == b"winner"));
            assert!(entries.iter().any(|entry| entry.name == b"loser"));
            for (name, expected) in [("WINNER", b"winner!!"), ("LOSER", b"original")] {
                let file = fs.lookup(&cx, &mut scope, root, OsStr::new(name)).unwrap();
                assert_eq!((file.uid, file.gid, file.size), (123, 456, 8));
                assert_eq!(fs.read(&cx, &mut scope, file.ino, 0, 64).unwrap(), expected);
                assert_eq!(
                    fs.read(&cx, &mut scope, file.ino, 2, 3).unwrap(),
                    &expected[2..5]
                );
                assert_eq!(fs.read(&cx, &mut scope, file.ino, 8, 1).unwrap(), b"");
                assert!(matches!(
                    fs.write(&cx, &mut scope, file.ino, 0, b"change"),
                    Err(FfsError::ReadOnly)
                ));
                fs.fsync(&cx, &mut scope, file.ino, 0, false).unwrap();
            }
            assert!(matches!(
                fs.create(&cx, &mut scope, root, OsStr::new("new"), 0o644, 0, 0),
                Err(FfsError::ReadOnly)
            ));
            assert!(matches!(
                fs.unlink(&cx, &mut scope, root, OsStr::new("winner")),
                Err(FfsError::ReadOnly)
            ));
            fs.fsyncdir(&cx, &mut scope, root, 0, false).unwrap();
            assert_eq!(fs.volume().volume_flags, 1);
            assert!(
                !fs.volume()
                    .logfile_recovery
                    .as_ref()
                    .unwrap()
                    .restart
                    .is_clean()
            );
            let mut backing = vec![0; VOLUME_BYTES];
            fs.volume()
                .source
                .device
                .read_exact_at(&cx, ByteOffset(0), &mut backing)
                .unwrap();
            assert_eq!(backing, original[BASE..BASE + VOLUME_BYTES]);
            assert_eq!(trace.lock().unwrap().writes, 0);
        }
    }
}

#[test]
fn recovered_fsops_do_not_weaken_clean_only_constructors() {
    use crate::NtfsFs;

    for indexed in [false, true] {
        let trace = Arc::new(Mutex::new(Trace::default()));
        let volume = open(mountable_image(true, 0x1A), &trace).unwrap();
        let result = if indexed {
            NtfsFs::new_indexed(&Cx::for_testing(), volume, 0, 0)
        } else {
            NtfsFs::new(&Cx::for_testing(), volume, 0, 0)
        };
        assert!(matches!(result, Err(FfsError::UnsupportedFeature(_))));
        assert_eq!(trace.lock().unwrap().writes, 0);
    }
}

#[test]
fn recovered_fsops_cannot_be_authorized_by_public_diagnostic_metadata() {
    let trace = Arc::new(Mutex::new(Trace::default()));
    let mut recovered = open(mountable_image(false, 0x1A), &trace).unwrap();
    let mut bytes = mountable_image(false, 0x1A);
    let flags = BASE + 128 * 512 + 3 * 1024 + 64 + 24 + 10;
    bytes[flags..flags + 2].fill(0);
    let mut volume = NtfsVolume::from_device(
        &Cx::for_testing(),
        Box::new(Memory {
            bytes,
            trace: Arc::clone(&trace),
        }),
        BASE as u64,
        VOLUME_BYTES as u64,
    )
    .unwrap();
    volume.logfile_recovery = recovered.logfile_recovery.take();
    assert!(matches!(
        crate::NtfsFs::new_recovered(&Cx::for_testing(), volume, 0, 0),
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert_eq!(trace.lock().unwrap().writes, 0);
}

#[test]
fn recovered_fsops_reject_geometry_or_flags_changed_after_recovery() {
    for change_geometry in [false, true] {
        let trace = Arc::new(Mutex::new(Trace::default()));
        let bytes = mountable_image(false, 0x1A);
        let mut volume = open(bytes.clone(), &trace).unwrap();
        if change_geometry {
            let mut boot = bytes[BASE..BASE + 512].to_vec();
            boot[72..80].copy_from_slice(&1_u64.to_le_bytes());
            volume.geometry = reader::NtfsGeometry::parse(&boot, VOLUME_BYTES as u64).unwrap();
        } else {
            volume.volume_flags = 0;
        }
        assert!(matches!(
            crate::NtfsFs::new_recovered_indexed(&Cx::for_testing(), volume, 0, 0),
            Err(FfsError::UnsupportedFeature(_))
        ));
        assert_eq!(trace.lock().unwrap().writes, 0);
    }
}

#[test]
fn recovered_fsops_refuse_unsupported_torn_and_cancelled_recovery() {
    for fault in 0..4 {
        let trace = Arc::new(Mutex::new(Trace::default()));
        let mut bytes = mountable_image(true, if fault == 0 { 0x19 } else { 0x1A });
        let tail = BASE + LOG_LCN * 512 + 2 * PAGE;
        match fault {
            1 => bytes[tail + 511] ^= 1,
            2 => {
                let at = tail + POSITIONS[4] + 48;
                bytes[at..at + 2].copy_from_slice(&0x15_u16.to_le_bytes());
            }
            3 => trace.lock().unwrap().fail_at = Some(tail as u64),
            _ => {}
        }
        let result = open(bytes, &trace)
            .and_then(|volume| crate::NtfsFs::new_recovered(&Cx::for_testing(), volume, 0, 0));
        assert!(
            result.is_err(),
            "invalid recovery case {fault} admitted a view"
        );
        if fault == 3 {
            assert!(matches!(result, Err(FfsError::Cancelled)));
        }
        assert_eq!(trace.lock().unwrap().writes, 0);
    }
}

#[test]
fn public_constructor_uses_checkpoint_and_post_restart_commit_before_loser_undo() {
    for bank in [false, true] {
        let trace = Arc::new(Mutex::new(Trace::default()));
        let bytes = image(bank, 0x1A);
        let original = bytes.clone();
        let volume = open(bytes, &trace).unwrap();
        let plan = volume.logfile_recovery.as_ref().unwrap();
        assert_eq!(plan.restart.current_lsn, lsn(4));
        assert_eq!(plan.restart.client_restart_lsn, lsn(1));
        assert_eq!(plan.committed_transactions, [24]);
        assert_eq!(plan.aborted_transactions, [64]);
        assert_eq!((plan.redo_actions.len(), plan.undo_actions.len()), (2, 1));
        assert_eq!(value(&volume, 42), b"winner!!");
        assert_eq!(value(&volume, 43), b"original");
        assert!(!plan.restart.is_clean());
        assert_eq!(volume.volume_flags, 1);
        let mut underlying = vec![0; VOLUME_BYTES];
        volume
            .source
            .device
            .read_exact_at(&Cx::for_testing(), ByteOffset(0), &mut underlying)
            .unwrap();
        assert_eq!(underlying, original[BASE..BASE + VOLUME_BYTES]);
        assert_eq!(trace.lock().unwrap().writes, 0);
    }
}

#[test]
fn unresolved_prepared_transaction_is_not_turned_into_a_loser_or_empty_plan() {
    let trace = Arc::new(Mutex::new(Trace::default()));
    assert!(matches!(
        open(image(true, 0x19), &trace),
        Err(FfsError::UnsupportedFeature(_))
    ));
    assert_eq!(trace.lock().unwrap().writes, 0);
}

#[test]
fn checkpoint_stream_identity_and_resolved_mft_mapping_are_required() {
    for mutation in 0..3 {
        let trace = Arc::new(Mutex::new(Trace::default()));
        let mut bytes = image(false, 0x1A);
        let page = BASE + LOG_LCN * 512 + RING;
        match mutation {
            0 => bytes[page + 64 + 48 + 80..page + 64 + 48 + 88]
                .copy_from_slice(&((7_u64 << 48) | 6).to_le_bytes()),
            1 => bytes[page + 328 + 48 + 32..page + 328 + 48 + 40]
                .copy_from_slice(&999_u64.to_le_bytes()),
            _ => bytes[BASE + 400 * 512 + 212 / 8] &= !(1 << (212 % 8)),
        }
        assert!(
            open(bytes, &trace).is_err(),
            "invalid native authority {mutation}"
        );
        assert_eq!(trace.lock().unwrap().writes, 0);
    }
}

#[test]
fn torn_or_cancelled_log_reads_cannot_fall_back_to_the_older_restart_plan() {
    for cancellation in [false, true] {
        let trace = Arc::new(Mutex::new(Trace::default()));
        let mut bytes = image(true, 0x1A);
        let at = BASE + LOG_LCN * 512 + 2 * PAGE;
        if cancellation {
            trace.lock().unwrap().fail_at = Some(at as u64);
        } else {
            bytes[at + 511] ^= 1;
        }
        let result = open(bytes, &trace);
        if cancellation {
            assert!(matches!(result, Err(FfsError::Cancelled)));
        } else {
            assert!(matches!(result, Err(FfsError::Corruption { .. })));
        }
        assert_eq!(trace.lock().unwrap().writes, 0);
    }
}

#[test]
fn public_recovery_requires_checkpoint_targets_even_when_envelope_preflight_succeeds() {
    let trace = Arc::new(Mutex::new(Trace::default()));
    let mut bytes = image(false, 0x1A);
    for page in [0, PAGE] {
        let at = BASE + LOG_LCN * 512 + page;
        bytes[at + 64 + 72..at + 64 + 80].fill(0);
    }
    assert!(open(bytes, &trace).is_err());
    assert_eq!(trace.lock().unwrap().writes, 0);
}

#[test]
fn erased_and_clean_journals_are_verified_noops_not_fabricated_replay() {
    for erased in [false, true] {
        let trace = Arc::new(Mutex::new(Trace::default()));
        let mut bytes = image(false, 0x1A);
        let start = BASE + LOG_LCN * 512;
        bytes[start..start + LOG_BYTES].fill(0xFF);
        if !erased {
            bytes[start..start + PAGE].copy_from_slice(&restart_page(true));
            bytes[start + PAGE..start + 2 * PAGE].copy_from_slice(&restart_page(true));
        }
        let volume = open(bytes, &trace).unwrap();
        if erased {
            assert!(volume.logfile_recovery.is_none());
        } else {
            let plan = volume.logfile_recovery.as_ref().unwrap();
            assert!(plan.restart.is_clean());
            assert!(plan.redo_actions.is_empty() && plan.undo_actions.is_empty());
        }
        assert_eq!(value(&volume, 42), b"original");
        assert_eq!(value(&volume, 43), b"loserbad");
        assert_eq!(trace.lock().unwrap().writes, 0);
    }
}

fn table_dump(opcode: u16, entry: &[u8]) -> Vec<u8> {
    let table_bytes = 24 + entry.len();
    let mut data = vec![0; 40 + table_bytes];
    data[..2].copy_from_slice(&opcode.to_le_bytes());
    data[4..6].copy_from_slice(&40_u16.to_le_bytes());
    data[6..8].copy_from_slice(&(table_bytes as u16).to_le_bytes());
    data[40..42].copy_from_slice(&(entry.len() as u16).to_le_bytes());
    data[42..44].copy_from_slice(&1_u16.to_le_bytes());
    data[44..46].copy_from_slice(&1_u16.to_le_bytes());
    data[64..].copy_from_slice(entry);
    data
}

#[test]
fn checkpoint_only_loser_exports_undo_and_redo_before_the_analysis_start() {
    let positions = [64_usize, 216, 328, 488, 640];
    let lsns = positions.map(|at| (1_u64 << 15) | ((RING + at) as u64 / 8));
    let mut attribute = [0; 40];
    attribute[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    attribute[8..12].copy_from_slice(&DATA.to_le_bytes());
    attribute[16..24].copy_from_slice(&(7_u64 << 48).to_le_bytes());
    let mut dirty = [0; 48];
    dirty[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    dirty[4..8].copy_from_slice(&24_u32.to_le_bytes());
    dirty[8..12].copy_from_slice(&1024_u32.to_le_bytes());
    dirty[12..16].copy_from_slice(&2_u32.to_le_bytes());
    dirty[16..24].copy_from_slice(&86_u64.to_le_bytes());
    dirty[24..32].copy_from_slice(&lsns[1].to_le_bytes());
    dirty[32..40].copy_from_slice(&214_u64.to_le_bytes());
    dirty[40..48].copy_from_slice(&215_u64.to_le_bytes());
    let mut transaction = [0; 40];
    transaction[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    transaction[4] = 1; // Active at the checkpoint, without a later record.
    for at in [8, 16, 24] {
        transaction[at..at + 8].copy_from_slice(&lsns[1].to_le_bytes());
    }
    let mut checkpoint = vec![0; 64];
    checkpoint[..4].copy_from_slice(&1_u32.to_le_bytes());
    checkpoint[8..16].copy_from_slice(&lsns[4].to_le_bytes());
    checkpoint[16..24].copy_from_slice(&lsns[0].to_le_bytes());
    checkpoint[32..40].copy_from_slice(&lsns[2].to_le_bytes());
    checkpoint[40..48].copy_from_slice(&lsns[3].to_le_bytes());
    checkpoint[48..52].copy_from_slice(&64_u32.to_le_bytes());
    checkpoint[56..60].copy_from_slice(&72_u32.to_le_bytes());
    checkpoint[60..64].copy_from_slice(&64_u32.to_le_bytes());
    let payloads = [
        table_dump(0x1D, &attribute),
        change(43, b"loserbad", b"original"),
        table_dump(0x1F, &dirty),
        table_dump(0x20, &transaction),
        checkpoint,
    ];
    let mut page = vec![0; PAGE];
    page[..4].copy_from_slice(b"RCRD");
    page[8..16].copy_from_slice(&lsns[4].to_le_bytes());
    page[16..20].copy_from_slice(&1_u32.to_le_bytes());
    page[20..22].copy_from_slice(&1_u16.to_le_bytes());
    page[22..24].copy_from_slice(&1_u16.to_le_bytes());
    page[24..26].copy_from_slice(&752_u16.to_le_bytes());
    page[32..40].copy_from_slice(&lsns[4].to_le_bytes());
    for (index, data) in payloads.iter().enumerate() {
        let at = positions[index];
        page[at..at + 8].copy_from_slice(&lsns[index].to_le_bytes());
        page[at + 24..at + 28].copy_from_slice(&(data.len() as u32).to_le_bytes());
        page[at + 28..at + 30].copy_from_slice(&9_u16.to_le_bytes());
        let kind = if index == 4 { 2_u32 } else { 1 };
        page[at + 32..at + 36].copy_from_slice(&kind.to_le_bytes());
        let owner = if index == 4 {
            0_u32
        } else if index == 1 {
            24
        } else {
            64
        };
        page[at + 36..at + 40].copy_from_slice(&owner.to_le_bytes());
        page[at + 48..at + 48 + data.len()].copy_from_slice(data);
    }
    let mut bytes = image(false, 0x1A);
    let start = BASE + LOG_LCN * 512;
    let restart = restart_page(false);
    for at in [start, start + PAGE] {
        bytes[at..at + PAGE].copy_from_slice(&restart);
        // These restart fields precede the first protected trailer.
        bytes[at + 64..at + 72].copy_from_slice(&lsns[4].to_le_bytes());
        bytes[at + 128..at + 136].copy_from_slice(&lsns[0].to_le_bytes());
        bytes[at + 136..at + 144].copy_from_slice(&lsns[4].to_le_bytes());
    }
    bytes[start + RING..start + RING + PAGE].copy_from_slice(&protected(page, 40, 0xBCDE));
    let trace = Arc::new(Mutex::new(Trace::default()));
    let original = bytes.clone();
    let volume = open(bytes, &trace).unwrap();
    let plan = volume.logfile_recovery.as_ref().unwrap();
    assert_eq!(plan.restart.current_lsn, lsns[4]);
    assert_eq!(plan.aborted_transactions, [24]);
    assert_eq!(plan.committed_transactions, [] as [u32; 0]);
    assert_eq!((plan.redo_actions.len(), plan.undo_actions.len()), (1, 1));
    assert_eq!(plan.redo_actions[0].lsn, lsns[1]);
    assert_eq!(plan.undo_actions[0].lsn, lsns[1]);
    assert_eq!(value(&volume, 43), b"original");
    let mut backing = vec![0; VOLUME_BYTES];
    volume
        .source
        .device
        .read_exact_at(&Cx::for_testing(), ByteOffset(0), &mut backing)
        .unwrap();
    assert_eq!(backing, original[BASE..BASE + VOLUME_BYTES]);
    assert_eq!(trace.lock().unwrap().writes, 0);
}

// A native checkpoint plus OpenNonresidentAttribute binds the external edits
// to directory 42's $I30 stream. These bytes are encoded independently of the
// production FILE/INDX editors and are not a native Windows recovery capture.
const INDEX_LCN: u16 = 1536;

fn named_resident(kind: u32, id: u16, value: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; (32 + value.len()).next_multiple_of(8)];
    let length = bytes.len() as u32;
    bytes[..4].copy_from_slice(&kind.to_le_bytes());
    bytes[4..8].copy_from_slice(&length.to_le_bytes());
    bytes[9] = 4;
    bytes[10..12].copy_from_slice(&24_u16.to_le_bytes());
    bytes[14..16].copy_from_slice(&id.to_le_bytes());
    bytes[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
    bytes[20..22].copy_from_slice(&32_u16.to_le_bytes());
    bytes[24..32].copy_from_slice(&[b'$', 0, b'I', 0, b'3', 0, b'0', 0]);
    bytes[32..32 + value.len()].copy_from_slice(value);
    bytes
}

fn directory_name(parent: u64, name: &str, directory: bool) -> Vec<u8> {
    let mut value = mount_filename(name);
    value[..8].copy_from_slice(&((7_u64 << 48) | parent).to_le_bytes());
    if directory {
        value[40..56].fill(0);
        value[56..60].copy_from_slice(&0x1000_0000_u32.to_le_bytes());
    }
    value
}

fn directory_entry(number: u64, name: &[u8]) -> Vec<u8> {
    let mut entry = vec![0; (16 + name.len()).next_multiple_of(8)];
    let length = entry.len() as u16;
    entry[..8].copy_from_slice(&((7_u64 << 48) | number).to_le_bytes());
    entry[8..10].copy_from_slice(&length.to_le_bytes());
    entry[10..12].copy_from_slice(&(name.len() as u16).to_le_bytes());
    entry[16..16 + name.len()].copy_from_slice(name);
    entry
}

fn directory_root(entries: &[Vec<u8>], external: bool) -> Vec<u8> {
    let mut value = vec![0; 32];
    value[..4].copy_from_slice(&0x30_u32.to_le_bytes());
    value[4..8].copy_from_slice(&1_u32.to_le_bytes());
    value[8..12].copy_from_slice(&(PAGE as u32).to_le_bytes());
    value[12] = 8;
    value[16..20].copy_from_slice(&16_u32.to_le_bytes());
    value[28] = u8::from(external);
    for entry in entries {
        value.extend(entry);
    }
    let mut terminal = vec![0; if external { 24 } else { 16 }];
    terminal[8] = terminal.len() as u8;
    terminal[12] = if external { 3 } else { 2 };
    value.extend(terminal);
    let used = value.len() as u32 - 16;
    value[20..24].copy_from_slice(&used.to_le_bytes());
    value[24..28].copy_from_slice(&used.to_le_bytes());
    named_resident(0x90, 2, &value)
}

fn directory_block() -> Vec<u8> {
    let mut bytes = vec![0; PAGE];
    bytes[..4].copy_from_slice(b"INDX");
    bytes[24..28].copy_from_slice(&40_u32.to_le_bytes());
    bytes[32..36].copy_from_slice(&((PAGE - 24) as u32).to_le_bytes());
    let entry = directory_entry(43, &directory_name(42, "alpha", false));
    let end = 64 + entry.len();
    bytes[64..end].copy_from_slice(&entry);
    bytes[end + 8..end + 10].copy_from_slice(&16_u16.to_le_bytes());
    bytes[end + 12..end + 14].copy_from_slice(&2_u16.to_le_bytes());
    bytes[28..32].copy_from_slice(&((end + 16 - 24) as u32).to_le_bytes());
    protected(bytes, 40, 0xA5A5)
}

fn external_change(number: u64, name: &str, offset: u16) -> Vec<u8> {
    let entry = directory_entry(number, &directory_name(42, name, false));
    let mut data = vec![0; 96 + entry.len()];
    data[..2].copy_from_slice(&0x0E_u16.to_le_bytes());
    data[2..4].copy_from_slice(&0x0F_u16.to_le_bytes());
    data[4..6].copy_from_slice(&96_u16.to_le_bytes());
    data[6..8].copy_from_slice(&(entry.len() as u16).to_le_bytes());
    data[8..10].copy_from_slice(&((96 + entry.len()) as u16).to_le_bytes());
    data[12..14].copy_from_slice(&64_u16.to_le_bytes());
    data[14..16].copy_from_slice(&8_u16.to_le_bytes());
    data[18..20].copy_from_slice(&offset.to_le_bytes());
    for index in 0..8 {
        data[32 + index * 8..40 + index * 8]
            .copy_from_slice(&(u64::from(INDEX_LCN) + index as u64).to_le_bytes());
    }
    data[96..].copy_from_slice(&entry);
    data
}

fn directory_journal(data_offset: u16, loser: bool) -> Vec<u8> {
    let mut attribute = [0; 40];
    attribute[..4].copy_from_slice(&u32::MAX.to_le_bytes());
    attribute[8..12].copy_from_slice(&DATA.to_le_bytes());
    attribute[16..24].copy_from_slice(&(7_u64 << 48).to_le_bytes());
    let mut checkpoint = vec![0; 64];
    checkpoint[..4].copy_from_slice(&1_u32.to_le_bytes());
    checkpoint[8..16].copy_from_slice(&lsn(1).to_le_bytes());
    checkpoint[16..24].copy_from_slice(&lsn(0).to_le_bytes());
    checkpoint[48..52].copy_from_slice(&64_u32.to_le_bytes());
    let mut opened = vec![0; 88];
    opened[..2].copy_from_slice(&0x1C_u16.to_le_bytes());
    opened[4..6].copy_from_slice(&40_u16.to_le_bytes());
    opened[6..8].copy_from_slice(&40_u16.to_le_bytes());
    opened[8..10].copy_from_slice(&80_u16.to_le_bytes());
    opened[10..12].copy_from_slice(&8_u16.to_le_bytes());
    opened[12..14].copy_from_slice(&64_u16.to_le_bytes());
    opened[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
    opened[44..48].copy_from_slice(&(PAGE as u32).to_le_bytes());
    opened[48..52].copy_from_slice(&0xA0_u32.to_le_bytes());
    opened[56..64].copy_from_slice(&((7_u64 << 48) | 0x002A).to_le_bytes());
    opened[80..88].copy_from_slice(&[b'$', 0, b'I', 0, b'3', 0, b'0', 0]);
    let mut data = change(43, b"winner!!", b"original");
    data[16..18].copy_from_slice(&data_offset.to_le_bytes());
    let mut commit = vec![0; 40];
    commit[..2].copy_from_slice(&0x1A_u16.to_le_bytes());
    let mut payloads = vec![
        table_dump(0x1D, &attribute),
        checkpoint,
        opened,
        data,
        external_change(44, "beta", 160),
        commit,
    ];
    if loser {
        payloads.push(external_change(45, "gamma", 256));
    }
    let mut next = 64;
    let positions: Vec<_> = payloads
        .iter()
        .map(|data| {
            let at = next;
            next += (48 + data.len()).next_multiple_of(8);
            at
        })
        .collect();
    let lsns: Vec<_> = positions
        .iter()
        .map(|at| (1_u64 << 15) | ((RING + at) as u64 / 8))
        .collect();
    assert_eq!((lsns[0], lsns[1]), (lsn(0), lsn(1)));
    let mut page = vec![0; PAGE];
    page[..4].copy_from_slice(b"RCRD");
    for at in [8, 32] {
        page[at..at + 8].copy_from_slice(&lsns.last().unwrap().to_le_bytes());
    }
    page[16..20].copy_from_slice(&1_u32.to_le_bytes());
    page[20..22].copy_from_slice(&1_u16.to_le_bytes());
    page[22..24].copy_from_slice(&1_u16.to_le_bytes());
    page[24..26].copy_from_slice(&(next as u16).to_le_bytes());
    for (index, data) in payloads.iter().enumerate() {
        let at = positions[index];
        page[at..at + 8].copy_from_slice(&lsns[index].to_le_bytes());
        if (3..=5).contains(&index) {
            for link in [8, 16] {
                page[at + link..at + link + 8].copy_from_slice(&lsns[index - 1].to_le_bytes());
            }
        }
        page[at + 24..at + 28].copy_from_slice(&(data.len() as u32).to_le_bytes());
        page[at + 28..at + 30].copy_from_slice(&9_u16.to_le_bytes());
        let kind = if index == 1 { 2_u32 } else { 1 };
        page[at + 32..at + 36].copy_from_slice(&kind.to_le_bytes());
        let owner = if index == 1 {
            0_u32
        } else if index == 6 {
            64
        } else {
            24
        };
        page[at + 36..at + 40].copy_from_slice(&owner.to_le_bytes());
        page[at + 48..at + 48 + data.len()].copy_from_slice(data);
    }
    protected(page, 40, 0xBCDE)
}

fn directory_image(loser: bool) -> Vec<u8> {
    let mut bytes = mountable_image(false, 0x1A);
    let mut standard = [0; 72];
    for field in 0..4 {
        standard[field * 8..field * 8 + 8]
            .copy_from_slice(&116_444_736_000_000_000_u64.to_le_bytes());
    }
    let standard = resident(0x10, 0, &standard);
    let mut allocation = vec![0; 80];
    allocation[..64].copy_from_slice(&mapped(INDEX_LCN, 8)[..64]);
    allocation[..4].copy_from_slice(&0xA0_u32.to_le_bytes());
    allocation[4..8].copy_from_slice(&80_u32.to_le_bytes());
    allocation[9] = 4;
    allocation[10..12].copy_from_slice(&64_u16.to_le_bytes());
    allocation[14..16].copy_from_slice(&3_u16.to_le_bytes());
    allocation[32..34].copy_from_slice(&72_u16.to_le_bytes());
    allocation[64..72].copy_from_slice(&[b'$', 0, b'I', 0, b'3', 0, b'0', 0]);
    allocation[72..80].copy_from_slice(&mapped(INDEX_LCN, 8)[64..72]);
    let tree_name = directory_name(5, "tree", true);
    let mut root = file(
        5,
        &[
            standard.clone(),
            resident(0x30, 1, &directory_name(5, ".", true)),
            directory_root(&[directory_entry(42, &tree_name)], false),
        ],
    );
    root[22..24].copy_from_slice(&3_u16.to_le_bytes());
    root[40..42].copy_from_slice(&3_u16.to_le_bytes());
    let mut directory = file(
        42,
        &[
            standard.clone(),
            resident(0x30, 1, &tree_name),
            directory_root(&[], true),
            allocation,
            named_resident(0xB0, 4, &[1]),
        ],
    );
    directory[22..24].copy_from_slice(&3_u16.to_le_bytes());
    directory[40..42].copy_from_slice(&5_u16.to_le_bytes());
    for (number, record) in [(5, root), (42, directory)] {
        let at = BASE + 128 * 512 + number * 1024;
        bytes[at..at + 1024].copy_from_slice(&record);
    }
    let mut data_offset = 0;
    for (number, name) in [(43, "alpha"), (44, "beta"), (45, "gamma")] {
        let filename = resident(0x30, 1, &directory_name(42, name, false));
        if number == 43 {
            data_offset = (64 + standard.len() + filename.len()) as u16;
        }
        let mut record = file(
            number,
            &[standard.clone(), filename, resident(DATA, 2, b"original")],
        );
        record[40..42].copy_from_slice(&3_u16.to_le_bytes());
        let at = BASE + 128 * 512 + number as usize * 1024;
        bytes[at..at + 1024].copy_from_slice(&record);
    }
    let at = BASE + usize::from(INDEX_LCN) * 512;
    bytes[at..at + PAGE].copy_from_slice(&directory_block());
    let at = BASE + LOG_LCN * 512 + RING;
    bytes[at..at + PAGE].copy_from_slice(&directory_journal(data_offset, loser));
    bytes
}

#[test]
fn dirty_external_directory_and_file_replay_publish_one_read_only_fsops_view() {
    use crate::NtfsFs;
    use ffs_core::{FsOps, RequestScope};
    use ffs_types::InodeNumber;
    use std::ffi::OsStr;

    let cx = Cx::for_testing();
    for loser in [false, true] {
        for indexed in [false, true] {
            let trace = Arc::new(Mutex::new(Trace::default()));
            let original = directory_image(loser);
            assert!(matches!(
                NtfsVolume::from_device(
                    &cx,
                    Box::new(Memory {
                        bytes: original.clone(),
                        trace: Arc::clone(&trace)
                    }),
                    BASE as u64,
                    VOLUME_BYTES as u64,
                ),
                Err(FfsError::UnsupportedFeature(_))
            ));
            let volume = open(original.clone(), &trace).unwrap();
            let plan = volume.logfile_recovery.as_ref().unwrap();
            assert_eq!(plan.redo_actions.len(), if loser { 3 } else { 2 });
            assert_eq!(plan.undo_actions.len(), usize::from(loser));
            assert_eq!(plan.redo_actions[1].op, NtfsLogOp::AddIndexEntryAllocation);
            let fs = if indexed {
                NtfsFs::new_recovered_indexed(&cx, volume, 123, 456)
            } else {
                NtfsFs::new_recovered(&cx, volume, 123, 456)
            }
            .unwrap();
            let mut scope = RequestScope::empty();
            let directory = fs
                .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("TREE"))
                .unwrap();
            let entries = fs.readdir(&cx, &mut scope, directory.ino, 0).unwrap();
            assert!(entries.iter().any(|entry| entry.name == b"alpha"));
            assert!(entries.iter().any(|entry| entry.name == b"beta"));
            assert!(!entries.iter().any(|entry| entry.name == b"gamma"));
            for (name, expected) in [("ALPHA", b"winner!!"), ("BETA", b"original")] {
                let file = fs
                    .lookup(&cx, &mut scope, directory.ino, OsStr::new(name))
                    .unwrap();
                assert_eq!(fs.read(&cx, &mut scope, file.ino, 0, 64).unwrap(), expected);
                assert!(matches!(
                    fs.write(&cx, &mut scope, file.ino, 0, b"x"),
                    Err(FfsError::ReadOnly)
                ));
            }
            assert!(matches!(
                fs.lookup(&cx, &mut scope, directory.ino, OsStr::new("gamma")),
                Err(FfsError::NotFound(_))
            ));
            assert_eq!(fs.volume().volume_flags, 1);
            let mut backing = vec![0; VOLUME_BYTES];
            fs.volume()
                .source
                .device
                .read_exact_at(&cx, ByteOffset(0), &mut backing)
                .unwrap();
            assert_eq!(backing, original[BASE..BASE + VOLUME_BYTES]);
            assert_eq!(trace.lock().unwrap().writes, 0);
        }
    }
}

#[test]
fn combined_file_and_external_index_redo_is_idempotent() {
    let trace = Arc::new(Mutex::new(Trace::default()));
    let mut bytes = directory_image(false);
    let first = open(bytes.clone(), &trace).unwrap();
    for (&sector, data) in &first.source.overlay {
        let at = BASE + sector as usize * 512;
        bytes[at..at + 512].copy_from_slice(data);
    }
    let second = open(bytes, &trace).unwrap();
    assert_eq!(first.source.overlay, second.source.overlay);
    assert_eq!(value(&second, 43), b"winner!!");
    let cx = Cx::for_testing();
    let directory = second.record(&cx, 42, Some(7)).unwrap();
    let entries = second.list_directory(&cx, &directory).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(trace.lock().unwrap().writes, 0);
}

#[test]
fn final_directory_identity_or_io_failure_restores_the_previous_complete_view() {
    let cx = Cx::for_testing();
    for fault in 0..5 {
        let cancellation = fault == 4;
        let trace = Arc::new(Mutex::new(Trace::default()));
        let mut bytes = directory_image(false);
        // Open without replay to inspect the publication boundary itself.
        let flags = BASE + 128 * 512 + 3 * 1024 + 64 + 24 + 10;
        bytes[flags..flags + 2].fill(0);
        let target = BASE + 128 * 512 + 44 * 1024;
        match fault {
            0 => {
                // The inserted INDX key remains "beta"; its untouched target's
                // FILE_NAME becomes "zeta". Node replay alone cannot see it.
                let name = target + 64 + 96 + 24 + 66;
                bytes[name..name + 2].copy_from_slice(&u16::from(b'z').to_le_bytes());
            }
            1 => bytes[target + 16..target + 18].copy_from_slice(&8_u16.to_le_bytes()),
            2 => {
                // The only reachable block is zero. Local replay has no reason
                // to visit the second allocated-but-unreachable bitmap bit.
                bytes[BASE + 128 * 512 + 42 * 1024 + 464] = 3;
            }
            3 => {
                // Both names match their FILEs and each node parses, but the
                // final in-order sequence is zebra,beta instead of beta,zebra.
                for (index, unit) in "zebra".encode_utf16().enumerate() {
                    let file = BASE + 128 * 512 + 43 * 1024 + 64 + 96 + 24 + 66 + index * 2;
                    let key = BASE + usize::from(INDEX_LCN) * 512 + 64 + 16 + 66 + index * 2;
                    bytes[file..file + 2].copy_from_slice(&unit.to_le_bytes());
                    bytes[key..key + 2].copy_from_slice(&unit.to_le_bytes());
                }
            }
            _ => {}
        }
        let mut volume = NtfsVolume::from_device(
            &cx,
            Box::new(Memory {
                bytes,
                trace: Arc::clone(&trace),
            }),
            BASE as u64,
            VOLUME_BYTES as u64,
        )
        .unwrap();
        let prepared = volume.native_recovery_stage(&cx).unwrap().unwrap();
        assert!(!prepared.overlay.is_empty());
        volume.source.overlay.insert(0, [0xA1; 512]);
        let previous = volume.source.overlay.clone();
        if cancellation {
            trace.lock().unwrap().fail_at = Some(target as u64);
        }
        let result = recovery_apply::publish_recovered(&cx, &mut volume, prepared);
        assert!(if cancellation {
            matches!(result, Err(FfsError::Cancelled))
        } else {
            matches!(result, Err(FfsError::Corruption { .. }))
        });
        assert_eq!(volume.source.overlay, previous);
        assert!(volume.logfile_recovery.is_none());
        assert_eq!(value(&volume, 43), b"original");
        assert_eq!(trace.lock().unwrap().writes, 0);
    }
}

#[test]
fn external_public_recovery_refuses_stale_mapping_allocation_and_torn_targets() {
    for fault in 0..6 {
        let trace = Arc::new(Mutex::new(Trace::default()));
        let mut bytes = directory_image(false);
        let journal = BASE + LOG_LCN * 512 + RING;
        match fault {
            0 => {
                // Native open-attribute slot names a stale directory sequence.
                let at = journal + 328 + 48 + 56;
                bytes[at..at + 8].copy_from_slice(&((8_u64 << 48) | 0x002A).to_le_bytes());
            }
            1 => {
                // A log claim cannot redirect the export to an arbitrary LCN.
                let at = journal + 576 + 48 + 32;
                bytes[at..at + 8].copy_from_slice(&1600_u64.to_le_bytes());
            }
            2 => bytes[BASE + 400 * 512 + usize::from(INDEX_LCN) / 8] &= !1,
            3 => bytes[BASE + 128 * 512 + 42 * 1024 + 464] = 0,
            4 => bytes[BASE + usize::from(INDEX_LCN) * 512 + 511] ^= 1,
            _ => bytes[BASE + 128 * 512 + 43 * 1024 + 1023] ^= 1,
        }
        assert!(
            open(bytes, &trace).is_err(),
            "invalid external replay case {fault}"
        );
        assert_eq!(trace.lock().unwrap().writes, 0);
    }
}

#[test]
fn final_directory_validation_shares_one_budget_across_all_directory_walks() {
    let cx = Cx::for_testing();
    let trace = Arc::new(Mutex::new(Trace::default()));
    let volume = open(directory_image(false), &trace).unwrap();
    // Repeated valid walks exercise the aggregate budget without building a
    // giant fixture. Public preparation deduplicates these native references.
    let references = vec![
        reader::NtfsReference {
            record: 42,
            sequence: 7
        };
        16_385
    ];
    assert!(matches!(
        volume.validate_recovered_directories(&cx, &references),
        Err(FfsError::UnsupportedFeature(detail)) if detail.contains("64 MiB")
    ));
    assert_eq!(value(&volume, 43), b"winner!!");
    assert_eq!(trace.lock().unwrap().writes, 0);
}
