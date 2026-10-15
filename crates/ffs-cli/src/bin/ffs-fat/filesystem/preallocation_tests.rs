//! Synthetic native images through the actual FsOps and FAT write paths.
//! Pending/durable fault injection is not a hardware or native-OS oracle.

use super::*;
use ffs_block::ByteDevice;
use ffs_ondisk::fat::FatGeometry;
use ffs_types::ByteOffset;

type Pages = BTreeMap<u64, [u8; 512]>;

#[derive(Default)]
struct Disk {
    durable: Pages,
    pending: Pages,
    reads: usize,
    attempts: usize,
    fail_at: Option<usize>,
    tear: usize,
    drop_write_at: Option<u64>,
    cancel_after_clean: bool,
    fail_read_after_clean: bool,
    fail_read: bool,
    state_offset: u64,
}

impl Disk {
    fn read(&self, mut at: u64, mut output: &mut [u8]) {
        while !output.is_empty() {
            let within = (at % 512) as usize;
            let count = output.len().min(512 - within);
            if let Some(page) = self.pending.get(&(at / 512)).or_else(|| self.durable.get(&(at / 512))) {
                output[..count].copy_from_slice(&page[within..within + count]);
            } else {
                output[..count].fill(0);
            }
            at += count as u64;
            output = &mut output[count..];
        }
    }

    fn put(&mut self, mut at: u64, mut input: &[u8]) {
        while !input.is_empty() {
            let within = (at % 512) as usize;
            let count = input.len().min(512 - within);
            let old = self.durable.get(&(at / 512)).copied().unwrap_or([0; 512]);
            self.pending.entry(at / 512).or_insert(old)[within..within + count]
                .copy_from_slice(&input[..count]);
            at += count as u64;
            input = &input[count..];
        }
    }

    fn persist(&mut self) {
        self.durable.append(&mut self.pending);
    }
}

#[derive(Clone)]
struct Device {
    disk: Arc<Mutex<Disk>>,
    length: u64,
}

impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 { self.length }

    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        assert!(at.0 + bytes.len() as u64 <= self.length);
        let mut disk = self.disk.lock().unwrap();
        disk.reads += 1;
        if disk.fail_read {
            return Err(std::io::Error::other("injected preallocation read failure").into());
        }
        disk.read(at.0, bytes);
        Ok(())
    }

    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> Result<()> {
        checkpoint(cx)?;
        assert!(at.0 + bytes.len() as u64 <= self.length);
        let mut disk = self.disk.lock().unwrap();
        disk.attempts += 1;
        if disk.drop_write_at == Some(at.0) {
            return Ok(());
        }
        if disk.fail_at == Some(disk.attempts) {
            let count = disk.tear.min(bytes.len());
            disk.put(at.0, &bytes[..count]);
            return Err(std::io::Error::other("injected preallocation write failure").into());
        }
        disk.put(at.0, bytes);
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        let mut disk = self.disk.lock().unwrap();
        disk.attempts += 1;
        if disk.fail_at == Some(disk.attempts) {
            return Err(std::io::Error::other("injected preallocation sync failure").into());
        }
        disk.persist();
        let mut flag = [0];
        disk.read(disk.state_offset, &mut flag);
        if flag[0] & 1 == 0 {
            if std::mem::take(&mut disk.cancel_after_clean) {
                cx.cancel_with(asupersync::types::CancelKind::User, Some("after clean preallocation sync"));
            }
            if std::mem::take(&mut disk.fail_read_after_clean) {
                disk.fail_read = true;
            }
        }
        Ok(())
    }
}

fn record(name: &[u8; 11], cluster: u32, size: u32, attributes: u8) -> [u8; 32] {
    let mut bytes = [0; 32];
    bytes[..11].copy_from_slice(name);
    bytes[11] = attributes;
    for at in [16, 18, 24] {
        bytes[at..at + 2].copy_from_slice(&0x21_u16.to_le_bytes());
    }
    bytes[20..22].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
    bytes[26..28].copy_from_slice(&(cluster as u16).to_le_bytes());
    bytes[28..32].copy_from_slice(&size.to_le_bytes());
    bytes
}

struct Image {
    device: Device,
    geometry: FatGeometry,
    base: u64,
}

impl Image {
    fn new(kind: FatKind, sector: u32, active: bool) -> Self {
        let clusters = if kind == FatKind::Fat16 { 5000_u32 } else { 70_000 };
        let reserved = if kind == FatKind::Fat16 { 1_u32 } else { 32 };
        let fat = ((u64::from(clusters) + 2) * u64::from(kind.entry_bytes()))
            .div_ceil(u64::from(sector)) as u32;
        let roots = if kind == FatKind::Fat16 { (sector / 32).max(32) as u16 } else { 0 };
        let total = reserved + 2 * fat + (u32::from(roots) * 32).div_ceil(sector) + clusters;
        let mut boot = [0; 512];
        boot[..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        boot[3..11].copy_from_slice(b"MSWIN4.1");
        boot[11..13].copy_from_slice(&(sector as u16).to_le_bytes());
        boot[13] = 1;
        boot[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
        boot[16] = 2;
        boot[17..19].copy_from_slice(&roots.to_le_bytes());
        boot[21] = 0xF8;
        boot[510..512].copy_from_slice(&[0x55, 0xAA]);
        if kind == FatKind::Fat16 {
            boot[19..21].copy_from_slice(&(total as u16).to_le_bytes());
            boot[22..24].copy_from_slice(&(fat as u16).to_le_bytes());
            boot[38] = 0x29;
            boot[54..62].copy_from_slice(b"FAT16   ");
        } else {
            boot[32..36].copy_from_slice(&total.to_le_bytes());
            boot[36..40].copy_from_slice(&fat.to_le_bytes());
            boot[40..42].copy_from_slice(&(if active { 0x81_u16 } else { 0 }).to_le_bytes());
            boot[44..48].copy_from_slice(&2_u32.to_le_bytes());
            boot[48..50].copy_from_slice(&1_u16.to_le_bytes());
            boot[50..52].copy_from_slice(&6_u16.to_le_bytes());
            boot[66] = 0x29;
            boot[82..90].copy_from_slice(b"FAT32   ");
        }
        let length = u64::from(total) * u64::from(sector);
        let geometry = FatGeometry::parse(&boot, length).unwrap();
        let base = 1024;
        let mut disk = Disk { state_offset: base + if kind == FatKind::Fat16 { 37 } else { 65 }, ..Disk::default() };
        disk.put(0, &[0xA7; 512]);
        disk.put(base + length, &[0xB9; 512]);
        disk.put(base, &boot);
        if kind == FatKind::Fat32 {
            disk.put(base + 6 * u64::from(sector), &boot);
            let mut info = [0; 512];
            info[..4].copy_from_slice(&0x4161_5252_u32.to_le_bytes());
            info[484..488].copy_from_slice(&0x6141_7272_u32.to_le_bytes());
            info[488..496].fill(0xFF);
            info[508..512].copy_from_slice(&0xAA55_0000_u32.to_le_bytes());
            disk.put(base + u64::from(sector), &info);
        }
        let end = if kind == FatKind::Fat16 { 0xFFFF_u32 } else { 0x0FFF_FFFF };
        let width = kind.entry_bytes() as usize;
        for copy in 0..2_u32 {
            let start = base + u64::from(reserved + copy * fat) * u64::from(sector);
            for cluster in 0..16_u32 {
                let value = match cluster {
                    0 => end & !7,
                    1 | 5 | 8 => end,
                    2 if kind == FatKind::Fat32 => end,
                    _ => 0,
                };
                let value = value | if kind == FatKind::Fat32 { (10 + copy) << 28 } else { 0 };
                disk.put(start + u64::from(cluster) * width as u64, &value.to_le_bytes()[..width]);
            }
        }
        let root = base + geometry.fixed_root()
            .map_or_else(|| geometry.cluster_offset(2).unwrap(), |(at, _)| at);
        let mut keep = record(b"KEEP    BIN", 5, 4, 0x20);
        // Native FAT16 EA index / FAT32 reserved cluster bits must survive.
        keep[20..22].copy_from_slice(&0xA000_u16.to_le_bytes());
        disk.put(root, &keep);
        disk.put(root + 32, &record(b"SUB        ", 8, 0, 0x10));
        disk.put(base + geometry.cluster_offset(5).unwrap(), &vec![0xCC; sector as usize]);
        disk.put(base + geometry.cluster_offset(5).unwrap(), b"SAFE");
        // The allocator starts at 2 (FAT16) or 3 (FAT32). Poison free storage.
        for cluster in [3, 4, 6, 7] {
            disk.put(base + geometry.cluster_offset(cluster).unwrap(), &vec![0xD3; sector as usize]);
        }
        let sub = base + geometry.cluster_offset(8).unwrap();
        disk.put(sub, &record(b".          ", 8, 0, 0x10));
        disk.put(sub + 32, &record(b"..         ", 0, 0, 0x10));
        disk.persist();
        Self {
            device: Device { disk: Arc::new(Mutex::new(disk)), length: base + length + 512 },
            geometry,
            base,
        }
    }

    fn volume(&self) -> FatVolume {
        FatVolume::from_device(&Cx::for_testing(), Box::new(self.device.clone()),
            self.base, self.geometry.volume_bytes()).unwrap()
    }

    fn mount(&self) -> (FatFs, InodeNumber) {
        let cx = Cx::for_testing();
        let fs = FatFs::new_with_mode(&cx, self.volume(), 1000, 1000, true).unwrap();
        let ino = fs.lookup(&cx, &mut RequestScope::empty(), ROOT, OsStr::new("KEEP.BIN"))
            .unwrap().ino;
        fs.read(&cx, &mut RequestScope::empty(), ino, 0, 4).unwrap();
        fs.statfs(&cx, &mut RequestScope::empty(), ROOT).unwrap();
        self.device.disk.lock().unwrap().attempts = 0;
        (fs, ino)
    }

    fn bytes(&self, at: u64, count: usize) -> Vec<u8> {
        let mut bytes = vec![0; count];
        self.device.disk.lock().unwrap().read(at, &mut bytes);
        bytes
    }

    fn guards(&self) {
        assert_eq!(self.bytes(0, 512), [0xA7; 512]);
        assert_eq!(self.bytes(self.base + self.geometry.volume_bytes(), 512), [0xB9; 512]);
        assert_eq!(self.bytes(self.base + self.geometry.cluster_offset(5).unwrap(), 4), b"SAFE");
    }
}

fn free(fs: &FatFs) -> u64 {
    let check = fs.volume.check(&Cx::for_testing()).unwrap();
    assert!(check.clean && check.complete && check.namespace_complete, "{check:?}");
    check.free_clusters
}

fn native_chain(fs: &FatFs, path: &str) -> FileChain {
    let cx = Cx::for_testing();
    let entry = fs.volume.resolve(&cx, path).unwrap().unwrap();
    fs.volume.file_chain(&cx, &entry).unwrap()
}

#[test]
fn allocation_modes_preserve_payload_and_refresh_capacity_on_both_dialects() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512, 4096] {
            for active in [false, true] {
                if active && kind == FatKind::Fat16 { continue; }
                for mode in [0, libc::FALLOC_FL_KEEP_SIZE] {
                    let image = Image::new(kind, sector, active);
                    let (fs, ino) = image.mount();
                    let cx = Cx::for_testing();
                    let mut scope = RequestScope::empty();
                    let before = fs.getattr(&cx, &mut scope, ino).unwrap();
                    let before_free = free(&fs);
                    let entry = fs.volume.resolve(&cx, "/KEEP.BIN").unwrap().unwrap();
                    let raw = image.bytes(image.base + entry.offset, 32);
                    let fat0 = image.bytes(image.base + image.geometry.entry_offset(0, 2).unwrap() - 8, sector as usize);
                    let end = 2 * u64::from(sector) + 8;
                    fs.fallocate(&cx, &mut scope, ino, u64::from(sector) + 3,
                        u64::from(sector) + 5, mode).unwrap();
                    let after = fs.getattr(&cx, &mut scope, ino).unwrap();
                    assert_eq!(after.size, if mode == 0 { end } else { 4 });
                    assert_eq!(after.blocks, 3 * u64::from(sector) / 512);
                    assert_eq!(before_free - free(&fs), 2);
                    assert_eq!(fs.statfs(&cx, &mut scope, ROOT).unwrap().blocks_free, before_free - 2);
                    let mut expected = b"SAFE".to_vec();
                    expected.resize(after.size as usize, 0);
                    assert_eq!(fs.read(&cx, &mut scope, ino, 0, end as u32 + 1).unwrap(), expected);
                    let updated = image.bytes(image.base + entry.offset, 32);
                    assert_eq!(&updated[20..22], &raw[20..22]);
                    if mode != 0 {
                        assert_eq!(updated, raw);
                        assert_eq!(after.mtime, before.mtime);
                    }
                    let chain = native_chain(&fs, "/KEEP.BIN");
                    assert_eq!(chain.clusters[0], 5);
                    for &cluster in &chain.clusters[1..] {
                        assert_eq!(image.bytes(image.base + image.geometry.cluster_offset(cluster).unwrap(), sector as usize), vec![0; sector as usize]);
                        if kind == FatKind::Fat32 {
                            for copy in if active { 1..2 } else { 0..2 } {
                                let at = image.base + image.geometry.entry_offset(copy, cluster).unwrap();
                                let value = u32::from_le_bytes(image.bytes(at, 4).try_into().unwrap());
                                assert_eq!(value >> 28, 10 + u32::from(copy));
                            }
                        }
                    }
                    if active {
                        assert_eq!(image.bytes(image.base + image.geometry.entry_offset(0, 2).unwrap() - 8, sector as usize), fat0);
                    }
                    let attempts = image.device.disk.lock().unwrap().attempts;
                    fs.fallocate(&cx, &mut scope, ino, 0, end, mode).unwrap();
                    assert_eq!(image.device.disk.lock().unwrap().attempts, attempts, "already reserved must not write or sync");
                    fs.write(&cx, &mut scope, ino, u64::from(sector) + 1, b"X").unwrap();
                    assert_eq!(free(&fs), before_free - 2);
                    assert_eq!(native_chain(&fs, "/KEEP.BIN").clusters, chain.clusters);
                    let grown = fs.getattr(&cx, &mut scope, ino).unwrap();
                    let mut expected = b"SAFE".to_vec();
                    expected.resize(grown.size as usize, 0);
                    expected[sector as usize + 1] = b'X';
                    assert_eq!(fs.read(&cx, &mut scope, ino, 0, grown.size as u32).unwrap(), expected);
                    image.guards();
                }
            }
        }
    }
}

#[test]
fn empty_long_name_reservations_survive_reopen_and_are_reclaimed_on_unlink() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let image = Image::new(kind, 512, false);
        let (fs, _) = image.mount();
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        let name = "A reserved empty file.bin";
        let ino = fs.create(&cx, &mut scope, ROOT, OsStr::new(name), 0o644, 1000, 1000).unwrap().ino;
        let before = free(&fs);
        let alias = fs.volume.resolve(&cx, &format!("/{name}")).unwrap().unwrap().short_alias().unwrap();
        fs.fallocate(&cx, &mut scope, ino, 700, 900, libc::FALLOC_FL_KEEP_SIZE).unwrap();
        assert_eq!(fs.getattr(&cx, &mut scope, ino).unwrap().size, 0);
        assert_eq!(fs.getattr(&cx, &mut scope, ino).unwrap().blocks, 4);
        assert!(fs.read(&cx, &mut scope, ino, 0, 2000).unwrap().is_empty());
        assert_eq!(fs.lookup(&cx, &mut scope, ROOT, OsStr::new(&alias)).unwrap().ino, ino);
        let reopened = image.volume();
        let entry = reopened.resolve(&cx, &format!("/{alias}")).unwrap().unwrap();
        assert_ne!(entry.native.first_cluster, 0);
        assert_eq!(reopened.file_chain(&cx, &entry).unwrap().clusters.len(), 4);
        assert_eq!(reopened.check(&cx).unwrap().preallocated_clusters, 4);
        fs.fallocate(&cx, &mut scope, ino, 0, 1500, 0).unwrap();
        assert_eq!(free(&fs), before - 4);
        assert_eq!(fs.read(&cx, &mut scope, ino, 0, 1500).unwrap(), vec![0; 1500]);
        fs.unlink(&cx, &mut scope, ROOT, OsStr::new(name)).unwrap();
        assert_eq!(free(&fs), before);
        image.guards();
    }
}

#[test]
fn reserved_space_remains_writable_after_the_volume_becomes_full() {
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let image = Image::new(kind, 512, kind == FatKind::Fat32);
        let (fs, ino) = image.mount();
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        let before = free(&fs);
        let end = (before + 1) * 512;
        fs.fallocate(&cx, &mut scope, ino, 0, end, libc::FALLOC_FL_KEEP_SIZE).unwrap();
        assert_eq!(free(&fs), 0);
        assert_eq!(fs.getattr(&cx, &mut scope, ino).unwrap().size, 4);
        let attempts = image.device.disk.lock().unwrap().attempts;
        assert!(matches!(fs.fallocate(&cx, &mut scope, ino, end, 1, libc::FALLOC_FL_KEEP_SIZE), Err(FfsError::NoSpace)));
        assert_eq!(image.device.disk.lock().unwrap().attempts, attempts);
        fs.write(&cx, &mut scope, ino, end - 1, b"Z").unwrap();
        assert_eq!(free(&fs), 0);
        assert_eq!(fs.read(&cx, &mut scope, ino, end - 8, 8).unwrap(), b"\0\0\0\0\0\0\0Z");
        fs.setattr(&cx, &mut scope, ino, &SetAttrRequest { size: Some(2), ..Default::default() }).unwrap();
        assert_eq!(free(&fs), before);
        assert_eq!(fs.read(&cx, &mut scope, ino, 0, 4).unwrap(), b"SA");
        image.guards();
    }
}

#[test]
fn invalid_allocation_requests_do_not_mutate_or_poison_the_mount() {
    let image = Image::new(FatKind::Fat32, 4096, true);
    let (fs, ino) = image.mount();
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let before = image.device.disk.lock().unwrap().durable.clone();
    for (offset, length, mode, errno) in [
        (0, 0, 0, libc::EINVAL),
        (u64::MAX, 1, 0, libc::EFBIG),
        (u64::from(u32::MAX), 1, 1, libc::EFBIG),
        (0, 1, libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE, libc::EOPNOTSUPP),
        (0, 1, libc::FALLOC_FL_ZERO_RANGE, libc::EOPNOTSUPP),
        (0, 1, -1, libc::EOPNOTSUPP),
    ] {
        assert!(matches!(fs.fallocate(&cx, &mut scope, ino, offset, length, mode), Err(FfsError::Io(error)) if error.raw_os_error() == Some(errno)));
    }
    assert!(matches!(fs.fallocate(&cx, &mut scope, ROOT, 0, 512, 0), Err(FfsError::IsDirectory)));
    assert!(matches!(fs.fallocate(&cx, &mut scope, ino, 0, u64::from(u32::MAX), 1), Err(FfsError::NoSpace)));
    let cancelled = Cx::for_testing();
    cancelled.cancel_with(asupersync::types::CancelKind::User, Some("preallocation refusal"));
    assert!(matches!(fs.fallocate(&cancelled, &mut scope, ino, 0, 8192, 1), Err(FfsError::Cancelled)));
    {
        let disk = image.device.disk.lock().unwrap();
        assert_eq!(disk.attempts, 0);
        assert_eq!(disk.durable, before);
        assert!(disk.pending.is_empty());
    }
    fs.fallocate(&cx, &mut scope, ino, 0, 8192, 1).unwrap();
    fs.setattr(&cx, &mut scope, ino, &SetAttrRequest { mode: Some(0o444), ..Default::default() }).unwrap();
    let attempts = image.device.disk.lock().unwrap().attempts;
    assert!(matches!(fs.fallocate(&cx, &mut scope, ino, 0, 16384, 0), Err(FfsError::PermissionDenied)));
    assert_eq!(image.device.disk.lock().unwrap().attempts, attempts);
    assert_eq!(fs.read(&cx, &mut scope, ino, 0, 4).unwrap(), b"SAFE");
    image.guards();
}

fn stopped(fs: &FatFs, image: &Image, ino: InodeNumber) {
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let counts = { let disk = image.device.disk.lock().unwrap(); (disk.reads, disk.attempts) };
    assert!(matches!(fs.read(&cx, &mut scope, ino, 0, 4), Err(FfsError::Io(_))));
    assert!(matches!(fs.getattr(&cx, &mut scope, ino), Err(FfsError::Io(_))));
    assert!(matches!(fs.statfs(&cx, &mut scope, ROOT), Err(FfsError::Io(_))));
    assert!(matches!(fs.fallocate(&cx, &mut scope, ino, 0, 4096, 1), Err(FfsError::Io(_))));
    assert!(matches!(fs.flush_on_destroy(&cx), Err(FfsError::Io(_))));
    let disk = image.device.disk.lock().unwrap();
    assert_eq!((disk.reads, disk.attempts), counts);
}

#[test]
fn allocation_write_sync_cuts_quarantine_the_mount_and_preserve_old_payload() {
    for mode in [0, libc::FALLOC_FL_KEEP_SIZE] {
        let baseline = Image::new(FatKind::Fat32, 512, true);
        let (fs, ino) = baseline.mount();
        fs.fallocate(&Cx::for_testing(), &mut RequestScope::empty(), ino, 0, 1600, mode).unwrap();
        let count = baseline.device.disk.lock().unwrap().attempts;
        assert!(count > 8);
        for fail in 1..=count {
            for tear in [0, 17, 511] {
                let image = Image::new(FatKind::Fat32, 512, true);
                let (fs, ino) = image.mount();
                {
                    let mut disk = image.device.disk.lock().unwrap();
                    disk.fail_at = Some(fail);
                    disk.tear = tear;
                }
                assert!(fs.fallocate(&Cx::for_testing(), &mut RequestScope::empty(), ino, 0, 1600, mode).is_err(), "cut {fail}, tear {tear}, mode {mode}");
                stopped(&fs, &image, ino);
                image.guards();
                for retain in [false, true] {
                    let durable = {
                        let disk = image.device.disk.lock().unwrap();
                        let mut bytes = disk.durable.clone();
                        if retain { bytes.extend(disk.pending.clone()); }
                        bytes
                    };
                    let device = Device { disk: Arc::new(Mutex::new(Disk { durable, ..Disk::default() })), length: image.device.length };
                    if let Ok(reopened) = FatVolume::from_device(&Cx::for_testing(), Box::new(device), image.base, image.geometry.volume_bytes()) {
                        let cx = Cx::for_testing();
                        let check = reopened.check(&cx).unwrap();
                        // Incomplete native metadata may require recovery. Only
                        // a fully clean outcome is eligible for content checks.
                        if check.clean && check.complete && check.namespace_complete {
                            let entry = reopened.resolve(&cx, "/KEEP.BIN").unwrap().unwrap();
                            let chain = reopened.file_chain(&cx, &entry).unwrap();
                            let bytes = reopened.read(&cx, &chain, 0, 1601).unwrap();
                            assert!(bytes.len() == 4 || (mode == 0 && bytes.len() == 1600));
                            assert_eq!(&bytes[..4], b"SAFE");
                            assert!(bytes[4..].iter().all(|byte| *byte == 0));
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn lost_initialization_and_failed_cache_publication_never_report_success() {
    let image = Image::new(FatKind::Fat32, 512, true);
    let (fs, ino) = image.mount();
    let first_free = image.base + image.geometry.cluster_offset(3).unwrap();
    image.device.disk.lock().unwrap().drop_write_at = Some(first_free);
    assert!(fs.fallocate(&Cx::for_testing(), &mut RequestScope::empty(), ino, 0, 1500, 1).is_err());
    let at = image.base + image.geometry.entry_offset(1, 3).unwrap();
    let value = u32::from_le_bytes(image.bytes(at, 4).try_into().unwrap());
    assert_eq!(value & 0x0FFF_FFFF, 0, "uninitialized cluster must not be published");
    stopped(&fs, &image, ino);
    image.guards();

    for cancel in [false, true] {
        let image = Image::new(FatKind::Fat32, 512, false);
        let (fs, ino) = image.mount();
        {
            let mut disk = image.device.disk.lock().unwrap();
            disk.cancel_after_clean = cancel;
            disk.fail_read_after_clean = !cancel;
        }
        assert!(fs.fallocate(&Cx::for_testing(), &mut RequestScope::empty(), ino, 0, 1500, 1).is_err());
        stopped(&fs, &image, ino);
        image.device.disk.lock().unwrap().fail_read = false;
        let reopened = image.volume();
        let cx = Cx::for_testing();
        let entry = reopened.resolve(&cx, "/KEEP.BIN").unwrap().unwrap();
        let chain = reopened.file_chain(&cx, &entry).unwrap();
        assert_eq!((chain.size, chain.clusters.len()), (4, 3));
        assert_eq!(reopened.read(&cx, &chain, 0, 1500).unwrap(), b"SAFE");
        assert!(reopened.check(&cx).unwrap().clean);
        image.guards();
    }
}
