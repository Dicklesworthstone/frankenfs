use super::*;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

#[test]
fn selected_oem_names_resolve_and_read_in_both_fat_formats() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = check::checked_image(kind);
        let root = image.root_location();
        image.record(root, b"\x90T\x9b     TXT", 5, 1029, false);
        image.bytes[root + 12] = 0x18;
        let volume = image.volume().with_oem_code_page(FatOemCodePage::Cp850);
        let entry = volume.resolve(&cx, "/ÉTØ.TXT").unwrap().unwrap();
        assert_eq!(entry.name().unwrap(), "étø.txt");
        assert_eq!(entry.native.short_name, *b"\x90T\x9b     TXT");
        let chain = volume.file_chain(&cx, &entry).unwrap();
        assert_eq!(volume.read(&cx, &chain, 0, 2048).unwrap(), payload());
        assert!(matches!(
            volume.resolve(&cx, "/ÉT¢.TXT"),
            Err(FfsError::NotFound(_))
        ));
        let report = volume.check(&cx).unwrap();
        assert!(report.clean);
        assert_eq!(report.oem_code_page, "850");

        let mut image = Image::new(kind);
        image.record(root, b"\x05       TXT", 5, 1029, false);
        let volume = image.volume().with_oem_code_page(FatOemCodePage::Cp437);
        assert_eq!(
            volume
                .resolve(&cx, "/Σ.txt")
                .unwrap()
                .unwrap()
                .name()
                .unwrap(),
            "σ.TXT"
        );
        let catalog =
            crate::native_catalog(&cx, &volume, &crate::EntrySlots::default(), 1024).unwrap();
        assert_eq!(catalog["oem_code_page"], "437");
        assert_eq!(catalog["entries"][0]["short_name_bytes"][0], 5);
        assert_eq!(catalog["entries"][0]["short_alias"], "σ.TXT");
    }
}

#[test]
fn oem_case_collisions_fail_lookup_and_are_reported_without_lost_reachability() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = check::checked_image(kind);
        let root = image.root_location();
        image.record(root, b"\x90COLE   TXT", 5, 1029, false);
        image.record(root + 64, b"\x82COLE   TXT", 0, 0, false);
        let volume = image.volume().with_oem_code_page(FatOemCodePage::Cp437);
        assert!(matches!(
            volume.lookup(&cx, Directory::Root, "école.txt"),
            Err(FfsError::Corruption { .. })
        ));
        let report = volume.check(&cx).unwrap();
        assert!(report.complete);
        assert!(!report.clean);
        assert_eq!(report.lost_clusters, Some(0));
        let collisions: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.kind == "name_collision")
            .collect();
        assert_eq!(collisions.len(), 1);
        assert_eq!(
            collisions[0].other_entry_offset,
            Some(root as u64 - volume.base)
        );
    }
}

#[test]
fn default_ascii_policy_keeps_oem_names_losslessly_accessible_by_slot_only() {
    let cx = Cx::for_testing();
    let mut image = Image::new(FatKind::Fat16);
    let root = image.root_location();
    image.record(root, b"\x90COLE   TXT", 5, 1029, false);
    let volume = image.volume();
    assert!(matches!(
        volume.resolve(&cx, "/ÉCOLE.TXT"),
        Err(FfsError::UnsupportedFeature(_))
    ));
    let selector = crate::EntrySlots(vec![root as u64 - volume.base]);
    let entry = selector.resolve(&cx, &volume).unwrap().unwrap();
    let chain = volume.file_chain(&cx, &entry).unwrap();
    assert_eq!(volume.read(&cx, &chain, 0, 2048).unwrap(), payload());
    assert!(volume.check(&cx).unwrap().clean);
}

struct Image {
    bytes: Vec<u8>,
    kind: FatKind,
    base: usize,
    length: usize,
    fat_start: usize,
    fat_sectors: usize,
    root: usize,
    data: usize,
}

impl Image {
    fn new(kind: FatKind) -> Self {
        let (reserved, fat_sectors, total, root_entries) = match kind {
            FatKind::Fat16 => (1, 20, 5043, 32),
            FatKind::Fat32 => (32, 600, 71_232, 0),
        };
        let base = 1024;
        let length = total * 512;
        let root = (reserved + fat_sectors * 2) * 512;
        let data = root + root_entries * 32;
        let mut bytes = vec![0; base + length + 512];
        bytes[..base].fill(0xA7);
        bytes[base + length..].fill(0xB9);
        let b = &mut bytes[base..base + 512];
        b[..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        b[3..11].copy_from_slice(b"MSWIN4.1");
        b[11..13].copy_from_slice(&512_u16.to_le_bytes());
        b[13] = 1;
        b[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
        b[16] = 2;
        b[17..19].copy_from_slice(&(root_entries as u16).to_le_bytes());
        b[21] = 0xF8;
        b[510..512].copy_from_slice(&[0x55, 0xAA]);
        match kind {
            FatKind::Fat16 => {
                b[19..21].copy_from_slice(&(total as u16).to_le_bytes());
                b[22..24].copy_from_slice(&(fat_sectors as u16).to_le_bytes());
                b[38] = 0x29;
                b[54..62].copy_from_slice(b"FAT16   ");
            }
            FatKind::Fat32 => {
                b[32..36].copy_from_slice(&(total as u32).to_le_bytes());
                b[36..40].copy_from_slice(&(fat_sectors as u32).to_le_bytes());
                b[44..48].copy_from_slice(&2_u32.to_le_bytes());
                b[48..50].copy_from_slice(&1_u16.to_le_bytes());
                b[50..52].copy_from_slice(&6_u16.to_le_bytes());
                b[66] = 0x29;
                b[82..90].copy_from_slice(b"FAT32   ");
            }
        }
        let mut image = Self {
            bytes,
            kind,
            base,
            length,
            fat_start: reserved * 512,
            fat_sectors,
            root,
            data,
        };
        let first = match kind {
            FatKind::Fat16 => 0xFFF8,
            FatKind::Fat32 => 0x0FFF_FFF8,
        };
        image.set_link(0, first);
        image.set_link(1, image.end());
        if kind == FatKind::Fat32 {
            image.set_link(2, image.end());
            image.copy_backup();
        }
        image.set_link(5, 9);
        image.set_link(9, 7);
        image.set_link(7, image.end());
        image.set_link(3, image.end());
        image.set_link(11, image.end());
        let root = image.root_location();
        image.record(root, b"HELLO   TXT", 5, 1029, false);
        image.record(root + 32, b"SUBDIR     ", 3, 0, true);
        image.record(root + 64, b"EMPTY   TXT", 0, 0, false);
        let subdir = image.cluster(3);
        image.record(subdir, b".          ", 3, 0, true);
        image.record(subdir + 32, b"..         ", 0, 0, true);
        image.record(subdir + 64, b"NESTED  BIN", 11, 4, false);
        for (cluster, byte) in [(5, b'A'), (9, b'B'), (7, b'C')] {
            let at = image.cluster(cluster);
            image.bytes[at..at + 512].fill(byte);
        }
        let nested = image.cluster(11);
        image.bytes[nested..nested + 4].copy_from_slice(b"FAT!");
        image
    }

    fn end(&self) -> u32 {
        match self.kind {
            FatKind::Fat16 => 0xFFFF,
            FatKind::Fat32 => 0x0FFF_FFFF,
        }
    }

    fn cluster(&self, number: u32) -> usize {
        self.base + self.data + (number as usize - 2) * 512
    }

    fn root_location(&self) -> usize {
        self.base + self.root
    }

    fn record(&mut self, at: usize, name: &[u8; 11], first: u32, size: u32, directory: bool) {
        let slot = &mut self.bytes[at..at + 32];
        slot[..11].copy_from_slice(name);
        slot[11] = if directory { 0x10 } else { 0x20 };
        slot[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
        slot[26..28].copy_from_slice(&(first as u16).to_le_bytes());
        slot[28..32].copy_from_slice(&size.to_le_bytes());
    }

    fn set_copy_link(&mut self, copy: usize, cluster: u32, value: u32) {
        let width = self.kind.entry_bytes() as usize;
        let at =
            self.base + self.fat_start + copy * self.fat_sectors * 512 + cluster as usize * width;
        self.bytes[at..at + width].copy_from_slice(&value.to_le_bytes()[..width]);
    }

    fn set_link(&mut self, cluster: u32, value: u32) {
        for copy in 0..2 {
            self.set_copy_link(copy, cluster, value);
        }
    }

    fn copy_backup(&mut self) {
        let boot = self.bytes[self.base..self.base + 512].to_vec();
        self.bytes[self.base + 6 * 512..self.base + 7 * 512].copy_from_slice(&boot);
    }

    fn volume(self) -> FatVolume {
        let length = self.length as u64;
        let base = self.base as u64;
        FatVolume::from_device(
            &Cx::for_testing(),
            Box::new(Memory {
                bytes: Arc::new(self.bytes),
                reads: Arc::new(AtomicUsize::new(0)),
                fail_at: None,
            }),
            base,
            length,
        )
        .unwrap()
    }
}

struct Memory {
    bytes: Arc<Vec<u8>>,
    reads: Arc<AtomicUsize>,
    fail_at: Option<u64>,
}

impl ByteDevice for Memory {
    fn len_bytes(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_exact_at(&self, _cx: &Cx, offset: ByteOffset, dst: &mut [u8]) -> Result<()> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if self.fail_at == Some(offset.0) {
            return Err(FfsError::Cancelled);
        }
        let start =
            usize::try_from(offset.0).map_err(|_| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        let end = start
            .checked_add(dst.len())
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        let bytes = self
            .bytes
            .get(start..end)
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        dst.copy_from_slice(bytes);
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _src: &[u8]) -> Result<()> {
        panic!("a read-only FAT operation attempted to write");
    }

    fn sync(&self, _cx: &Cx) -> Result<()> {
        panic!("a read-only FAT operation attempted to flush");
    }
}

fn payload() -> Vec<u8> {
    let mut bytes = vec![b'A'; 512];
    bytes.extend_from_slice(&[b'B'; 512]);
    bytes.extend_from_slice(&[b'C'; 5]);
    bytes
}

#[test]
fn fat16_and_fat32_read_fragmented_files_nested_paths_and_eof() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let volume = Image::new(kind).volume();
        let entries = volume.list(&cx, Directory::Root).unwrap();
        assert_eq!(entries.len(), 3);
        let entry = volume.resolve(&cx, "/hello.txt").unwrap().unwrap();
        let chain = volume.file_chain(&cx, &entry).unwrap();
        assert_eq!(chain.clusters, [5, 9, 7]);
        assert_eq!(volume.read(&cx, &chain, 0, 4096).unwrap(), payload());
        assert_eq!(
            volume.read(&cx, &chain, 510, 520).unwrap(),
            payload()[510..]
        );
        assert_eq!(volume.read(&cx, &chain, 1029, 1).unwrap(), [] as [u8; 0]);
        assert_eq!(
            volume.read(&cx, &chain, u64::MAX, 10).unwrap(),
            [] as [u8; 0]
        );
        let nested = volume.resolve(&cx, "/SUBDIR/nested.bin").unwrap().unwrap();
        let chain = volume.file_chain(&cx, &nested).unwrap();
        assert_eq!(volume.read(&cx, &chain, 0, 4).unwrap(), b"FAT!");
        let empty = volume.resolve(&cx, "/empty.txt").unwrap().unwrap();
        assert_eq!(
            volume.file_chain(&cx, &empty).unwrap().clusters,
            [] as [u32; 0]
        );
        assert!(matches!(
            volume.resolve(&cx, "/HELLO.TXT/child"),
            Err(FfsError::NotDirectory)
        ));
        assert!(matches!(
            volume.resolve(&cx, "/missing"),
            Err(FfsError::NotFound(_))
        ));
        assert!(volume.resolve(&cx, "/../HELLO.TXT").is_err());
    }
}

#[test]
fn live_chain_rejects_free_bad_reserved_out_of_range_and_premature_end() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let bad = match kind {
            FatKind::Fat16 => [0, 1, 0xFFF7, 0xFFF0, 5002, 0xFFFF],
            FatKind::Fat32 => [0, 1, 0x0FFF_FFF7, 0x0FFF_FFF0, 70_002, 0x0FFF_FFFF],
        };
        for value in bad {
            let mut image = Image::new(kind);
            image.set_link(5, value);
            let volume = image.volume();
            let file = volume.resolve(&cx, "/HELLO.TXT").unwrap().unwrap();
            assert!(
                matches!(
                    volume.file_chain(&cx, &file),
                    Err(FfsError::Corruption { .. })
                ),
                "{kind:?} {value:x}"
            );
        }
    }
}

#[test]
fn cycles_and_mirror_disagreement_fail_before_data_is_returned() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = Image::new(kind);
        image.set_link(7, 9);
        let volume = image.volume();
        let file = volume.resolve(&cx, "/HELLO.TXT").unwrap().unwrap();
        assert!(
            volume
                .file_chain(&cx, &file)
                .unwrap_err()
                .to_string()
                .contains("cyclic")
        );
        let mut image = Image::new(kind);
        image.set_copy_link(1, 5, image.end());
        let volume = image.volume();
        let file = volume.resolve(&cx, "/HELLO.TXT").unwrap().unwrap();
        assert!(
            volume
                .file_chain(&cx, &file)
                .unwrap_err()
                .to_string()
                .contains("copies disagree")
        );
    }
}

#[test]
fn active_fat32_ignores_inactive_copy_and_masks_reserved_bits() {
    let mut image = Image::new(FatKind::Fat32);
    image.bytes[image.base + 40..image.base + 42].copy_from_slice(&0x81_u16.to_le_bytes());
    image.copy_backup();
    image.set_copy_link(0, 0, 0);
    image.set_copy_link(0, 5, 0);
    image.set_copy_link(1, 5, 0xA000_0009);
    let volume = image.volume();
    let cx = Cx::for_testing();
    let file = volume.resolve(&cx, "/HELLO.TXT").unwrap().unwrap();
    let chain = volume.file_chain(&cx, &file).unwrap();
    assert_eq!(volume.read(&cx, &chain, 0, 4096).unwrap(), payload());
}

#[test]
fn partition_range_overflow_and_truncation_do_not_issue_io() {
    let cx = Cx::for_testing();
    let reads = Arc::new(AtomicUsize::new(0));
    for (base, length) in [(u64::MAX, 512), (1, 1024), (0, 511)] {
        let result = FatVolume::from_device(
            &cx,
            Box::new(Memory {
                bytes: Arc::new(vec![0; 1024]),
                reads: Arc::clone(&reads),
                fail_at: None,
            }),
            base,
            length,
        );
        assert!(result.is_err());
    }
    assert_eq!(reads.load(Ordering::Relaxed), 0);
}

#[test]
fn read_cancellation_is_not_successful_short_data_or_mirror_retry() {
    let cx = Cx::for_testing();
    let image = Image::new(FatKind::Fat16);
    let fail_at = image.cluster(9) as u64;
    let reads = Arc::new(AtomicUsize::new(0));
    let volume = FatVolume::from_device(
        &cx,
        Box::new(Memory {
            bytes: Arc::new(image.bytes),
            reads: Arc::clone(&reads),
            fail_at: Some(fail_at),
        }),
        image.base as u64,
        image.length as u64,
    )
    .unwrap();
    let entry = volume.resolve(&cx, "/HELLO.TXT").unwrap().unwrap();
    let chain = volume.file_chain(&cx, &entry).unwrap();
    let before = reads.load(Ordering::Relaxed);
    assert!(matches!(
        volume.read(&cx, &chain, 0, 1029),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(reads.load(Ordering::Relaxed) - before, 2);
}

#[test]
fn extra_allocation_is_accounted_but_never_exposed_as_slack() {
    let mut image = Image::new(FatKind::Fat16);
    image.set_link(7, 12);
    image.set_link(12, image.end());
    let volume = image.volume();
    let cx = Cx::for_testing();
    let entry = volume.resolve(&cx, "/HELLO.TXT").unwrap().unwrap();
    let chain = volume.file_chain(&cx, &entry).unwrap();
    assert_eq!(chain.clusters, [5, 9, 7, 12]);
    assert_eq!(volume.read(&cx, &chain, 0, 4096).unwrap(), payload());
    assert_eq!(volume.free_clusters(&cx).unwrap(), 5000 - 6);
}

#[test]
fn actual_file_reads_leave_image_and_adjacent_partitions_unchanged() {
    let image = Image::new(FatKind::Fat16);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("disk.img");
    std::fs::write(&path, &image.bytes).unwrap();
    let cx = Cx::for_testing();
    let volume = FatVolume::open(&cx, &path, image.base as u64, Some(image.length as u64)).unwrap();
    let entry = volume.resolve(&cx, "/HELLO.TXT").unwrap().unwrap();
    let chain = volume.file_chain(&cx, &entry).unwrap();
    assert_eq!(volume.read(&cx, &chain, 0, 4096).unwrap(), payload());
    assert_eq!(std::fs::read(&path).unwrap(), image.bytes);
}

#[test]
fn dirty_fat_and_conflicting_backup_refuse_admission_without_writes() {
    let cx = Cx::for_testing();
    for conflict in [false, true] {
        let mut image = Image::new(FatKind::Fat32);
        if conflict {
            let backup_root = image.base + 6 * 512 + 44;
            image.bytes[backup_root..backup_root + 4].copy_from_slice(&3_u32.to_le_bytes());
        } else {
            image.set_link(1, 0x07FF_FFFF);
        }
        let result = FatVolume::from_device(
            &cx,
            Box::new(Memory {
                bytes: Arc::new(image.bytes),
                reads: Arc::new(AtomicUsize::new(0)),
                fail_at: None,
            }),
            image.base as u64,
            image.length as u64,
        );
        assert!(result.is_err());
    }
}

#[test]
fn long_names_cross_sectors_and_fat32_root_clusters_without_losing_alias_identity() {
    use ffs_ondisk::fat::short_name_checksum;

    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = Image::new(kind);
        let first_sector = image.root_location();
        let second_sector = if kind == FatKind::Fat32 {
            image.set_link(2, 4);
            image.set_link(4, image.end());
            image.cluster(4)
        } else {
            first_sector + 512
        };
        for position in (first_sector..first_sector + 512).step_by(32) {
            image.bytes[position..position + 32].fill(0);
            image.bytes[position] = 0xE5;
        }
        let text: Vec<u16> = "Long fragmented name.txt".encode_utf16().collect();
        let alias = *b"LONGFR~1TXT";
        let checksum = short_name_checksum(&alias);
        for (ordinal, position) in [(0x42_u8, first_sector + 480), (1, second_sector)] {
            let slot = &mut image.bytes[position..position + 32];
            slot.fill(0);
            slot[0] = ordinal;
            slot[11] = 0x0F;
            slot[13] = checksum;
            let start = usize::from((ordinal & 0x1F) - 1) * 13;
            for (index, offset) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
                .into_iter()
                .enumerate()
            {
                let at = start + index;
                let unit =
                    text.get(at)
                        .copied()
                        .unwrap_or(if at == text.len() { 0 } else { 0xFFFF });
                slot[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
            }
        }
        image.record(second_sector + 32, &alias, 5, 1029, false);
        image.bytes[second_sector + 64] = 0;
        let volume = image.volume();
        let entries = volume.list(&cx, Directory::Root).unwrap();
        assert_eq!(entries.len(), 1);
        let named = volume
            .lookup(&cx, Directory::Root, "Long fragmented name.txt")
            .unwrap();
        let aliased = volume.lookup(&cx, Directory::Root, "longfr~1.txt").unwrap();
        assert_eq!(named.offset, aliased.offset);
        assert_eq!(
            volume
                .read(&cx, &volume.file_chain(&cx, &named).unwrap(), 0, 2048)
                .unwrap(),
            payload()
        );
    }
}

#[test]
fn directory_end_markers_do_not_hide_corrupt_allocation_tails() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let invalid = match kind {
            FatKind::Fat16 => [0, 1, 0xFFF7, 0xFFF0, 5002, 4],
            FatKind::Fat32 => [0, 1, 0x0FFF_FFF7, 0x0FFF_FFF0, 70_002, 4],
        };
        let directories = std::iter::once((Directory::Cluster(3), 3))
            .chain((kind == FatKind::Fat32).then_some((Directory::Root, 2)));
        for (directory, first) in directories {
            for value in invalid {
                let mut image = Image::new(kind);
                image.set_link(first, 4);
                image.set_link(4, value);
                let volume = image.volume();
                assert!(
                    matches!(
                        volume.list(&cx, directory),
                        Err(FfsError::Corruption { .. })
                    ),
                    "{kind:?} {directory:?}: trailing link {value:x}"
                );
            }
        }
    }
}

#[test]
fn directory_end_markers_do_not_hide_mirror_disagreement() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = Image::new(kind);
        image.set_link(3, 4);
        image.set_link(4, image.end());
        image.set_copy_link(1, 4, 0);
        let volume = image.volume();
        assert!(
            volume
                .list(&cx, Directory::Cluster(3))
                .unwrap_err()
                .to_string()
                .contains("copies disagree")
        );
    }
}

#[test]
fn valid_directory_tail_allocation_does_not_expose_or_read_unused_slots() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = Image::new(kind);
        image.set_link(3, 4);
        image.set_link(4, image.end());
        let tail = image.cluster(4);
        image.bytes[tail..tail + 512].fill(0xFF);
        let volume = FatVolume::from_device(
            &cx,
            Box::new(Memory {
                bytes: Arc::new(image.bytes),
                reads: Arc::new(AtomicUsize::new(0)),
                fail_at: Some(tail as u64),
            }),
            image.base as u64,
            image.length as u64,
        )
        .unwrap();
        let entries = volume.list(&cx, Directory::Cluster(3)).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name().unwrap(), "NESTED.BIN");
        assert_eq!(
            volume.directory_size(&cx, Directory::Cluster(3)).unwrap(),
            1024
        );
    }
}

#[test]
fn directory_allocation_work_is_bounded_even_after_an_early_end_marker() {
    let cx = Cx::for_testing();
    let mut image = Image::new(FatKind::Fat16);
    let limit = (MAX_DIRECTORY_SLOTS * 32 / 512) as u32;
    for cluster in 3..3 + limit {
        image.set_link(cluster, cluster + 1);
    }
    image.set_link(3 + limit, image.end());
    let volume = image.volume();
    assert!(matches!(
        volume.list(&cx, Directory::Cluster(3)),
        Err(FfsError::UnsupportedFeature(_))
    ));
}

#[test]
fn directory_tail_validation_propagates_cancellation_before_publishing_names() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = Image::new(kind);
        image.set_link(3, 300);
        image.set_link(300, image.end());
        let fat_sector = 300 * kind.entry_bytes() as usize / 512 * 512;
        let fail_at = (image.base + image.fat_start + fat_sector) as u64;
        let volume = FatVolume::from_device(
            &cx,
            Box::new(Memory {
                bytes: Arc::new(image.bytes),
                reads: Arc::new(AtomicUsize::new(0)),
                fail_at: Some(fail_at),
            }),
            image.base as u64,
            image.length as u64,
        )
        .unwrap();
        assert!(matches!(
            volume.list(&cx, Directory::Cluster(3)),
            Err(FfsError::Cancelled)
        ));
    }
}

fn slot_selector(offsets: &[usize]) -> crate::EntrySlots {
    crate::EntrySlots::parse(
        &offsets
            .iter()
            .map(usize::to_string)
            .collect::<Vec<_>>()
            .join(","),
    )
    .unwrap()
}

fn write_native_lfn(
    image: &mut Image,
    start: usize,
    alias: &[u8; 11],
    units: &[u16],
    cluster: u32,
) -> usize {
    let count = units.len().div_ceil(13);
    let checksum = ffs_ondisk::fat::short_name_checksum(alias);
    for index in 0..count {
        let ordinal = count - index;
        let position = start + index * 32;
        let slot = &mut image.bytes[position..position + 32];
        slot.fill(0);
        slot[0] = ordinal as u8 | if index == 0 { 0x40 } else { 0 };
        slot[11] = 0x0F;
        slot[13] = checksum;
        for (unit_index, offset) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
            .into_iter()
            .enumerate()
        {
            let at = (ordinal - 1) * 13 + unit_index;
            let unit = units
                .get(at)
                .copied()
                .unwrap_or(if at == units.len() { 0 } else { 0xFFFF });
            slot[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
        }
    }
    let position = start + count * 32;
    image.record(position, alias, cluster, 4, false);
    image.set_link(cluster, image.end());
    position
}

#[test]
fn native_catalog_and_extraction_preserve_oem_surrogates_and_long_utf8_names() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = Image::new(kind);
        let base = image.base;
        let root = image.root_location();
        let subdir = image.cluster(3);
        image.bytes[root] = 0x82;
        image.bytes[root + 32] = 0x83;
        image.bytes[subdir + 64] = 0x05;
        let raw = write_native_lfn(&mut image, root + 96, b"RAW     BIN", &[0xD800, 0x0061], 12);
        let wide = vec![0x4E00; 100];
        let long = write_native_lfn(&mut image, root + 160, b"LONG    BIN", &wide, 13);
        for (cluster, bytes) in [(12, b"RAW!"), (13, b"UTF8")] {
            let at = image.cluster(cluster);
            image.bytes[at..at + 4].copy_from_slice(bytes);
        }
        let volume = image.volume();
        assert!(matches!(
            volume.resolve(&cx, "/HELLO.TXT"),
            Err(FfsError::UnsupportedFeature(_))
        ));
        let catalog =
            crate::native_catalog(&cx, &volume, &crate::EntrySlots::default(), base as u64)
                .unwrap();
        assert_eq!(catalog["entry_offset_origin"], "selected_volume");
        assert_eq!(catalog["volume_offset"], base as u64);
        assert!(catalog["directory_entry_slots"].is_null());
        let entries = catalog["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 5);
        assert_eq!(entries[0]["short_name_bytes"][0], 0x82);
        assert!(entries[0]["name"].is_null());
        assert!(entries[0]["short_alias"].is_null());
        assert_eq!(
            entries[3]["long_name_utf16"],
            serde_json::json!([0xD800, 0x0061])
        );
        assert!(entries[3]["name"].is_null());
        assert_eq!(entries[4]["long_name_utf16"], serde_json::json!(wide));
        assert!(entries[4]["name"].is_null());
        for entry in [0, 1, 3, 4] {
            assert!(entries[entry]["display_error"].as_str().is_some());
        }
        for (index, offset, expected) in [
            (0, root - base, payload()),
            (2, root + 64 - base, Vec::new()),
            (3, raw - base, b"RAW!".to_vec()),
            (4, long - base, b"UTF8".to_vec()),
        ] {
            let encoded = entries[index]["entry_slots"].as_str().unwrap();
            assert_eq!(encoded, offset.to_string());
            let selector = crate::EntrySlots::parse(encoded).unwrap();
            let mut output = Vec::new();
            crate::extract_slots(&cx, &volume, &selector, &mut output).unwrap();
            assert_eq!(output, expected, "{kind:?}: {encoded}");
        }
        let directory =
            crate::EntrySlots::parse(entries[1]["entry_slots"].as_str().unwrap()).unwrap();
        let nested = crate::native_catalog(&cx, &volume, &directory, base as u64).unwrap();
        let entry = &nested["entries"][0];
        let expected = format!("{},{}", root + 32 - base, subdir + 64 - base);
        assert_eq!(entry["entry_slots"], expected);
        assert_eq!(entry["short_name_bytes"][0], 0x05);
        assert!(entry["name"].is_null());
        let selected = crate::EntrySlots::parse(entry["entry_slots"].as_str().unwrap()).unwrap();
        let mut output = Vec::new();
        crate::extract_slots(&cx, &volume, &selected, &mut output).unwrap();
        assert_eq!(output, b"FAT!");
        assert!(matches!(
            slot_selector(&[root + 96 - base]).resolve(&cx, &volume),
            Err(FfsError::NotFound(_))
        ));
    }
}

#[test]
fn native_slots_reject_nonmembers_deleted_labels_dot_entries_and_end_marker_slack() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = Image::new(kind);
        let base = image.base;
        let root = image.root_location();
        let subdir = image.cluster(3);
        image.record(root + 96, b"VOLUME     ", 0, 0, false);
        image.bytes[root + 96 + 11] = 0x08;
        image.record(root + 128, b"DELETED TXT", 0, 0, false);
        image.bytes[root + 128] = 0xE5;
        image.bytes[root + 160] = 0x41;
        image.bytes[root + 160 + 11] = 0x0F;
        // The live namespace ends at +192. These plausible records after it
        // and in an unrelated data cluster must never become extractable.
        image.record(root + 224, b"SLACK   TXT", 5, 1029, false);
        let forged = image.cluster(13);
        image.record(forged, b"FORGED  TXT", 5, 1029, false);
        let volume = FatVolume::from_device(
            &cx,
            Box::new(Memory {
                bytes: Arc::new(image.bytes),
                reads: Arc::new(AtomicUsize::new(0)),
                fail_at: Some(forged as u64),
            }),
            base as u64,
            image.length as u64,
        )
        .unwrap();
        for offsets in [
            vec![0],
            vec![root + 96 - base],
            vec![root + 128 - base],
            vec![root + 160 - base],
            vec![root + 192 - base],
            vec![root + 224 - base],
            vec![forged - base],
            vec![subdir + 64 - base],
            vec![root + 32 - base, root - base],
            vec![root + 32 - base, subdir - base],
            vec![root + 32 - base, subdir + 32 - base],
        ] {
            let mut output = Vec::new();
            assert!(
                matches!(
                    crate::extract_slots(&cx, &volume, &slot_selector(&offsets), &mut output),
                    Err(FfsError::NotFound(_))
                ),
                "{kind:?}: {offsets:?}"
            );
            assert!(output.is_empty());
        }
        let mut output = Vec::new();
        assert!(matches!(
            crate::extract_slots(
                &cx,
                &volume,
                &slot_selector(&[root - base, subdir + 64 - base]),
                &mut output,
            ),
            Err(FfsError::NotDirectory)
        ));
        for selector in [
            crate::EntrySlots::default(),
            slot_selector(&[root + 32 - base]),
        ] {
            assert!(matches!(
                crate::extract_slots(&cx, &volume, &selector, &mut output),
                Err(FfsError::IsDirectory)
            ));
        }
        assert!(output.is_empty());
        assert!(matches!(
            crate::native_catalog(&cx, &volume, &slot_selector(&[root - base]), base as u64),
            Err(FfsError::NotDirectory)
        ));
    }
}

#[test]
fn native_slot_resolution_rejects_directory_ancestor_links() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = Image::new(kind);
        let base = image.base;
        let root = image.root_location();
        let subdir = image.cluster(3);
        image.record(subdir + 64, b"BACK       ", 3, 0, true);
        let volume = image.volume();
        let selector = slot_selector(&[root + 32 - base, subdir + 64 - base]);
        assert!(matches!(
            selector.resolve(&cx, &volume),
            Err(FfsError::Corruption { .. })
        ));
        assert!(matches!(
            crate::native_catalog(&cx, &volume, &selector, base as u64),
            Err(FfsError::Corruption { .. })
        ));
    }
}

#[test]
fn native_catalog_keeps_structural_record_and_name_corruption_fatal() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for bad_name in [false, true] {
            let mut image = Image::new(kind);
            let base = image.base;
            let root = image.root_location();
            if bad_name {
                write_native_lfn(
                    &mut image,
                    root + 96,
                    b"BAD     BIN",
                    &[0x0041, 0x002F, 0x0042],
                    12,
                );
            } else {
                image.bytes[root + 32 + 11] = 0xC0;
            }
            let volume = image.volume();
            assert!(matches!(
                crate::native_catalog(&cx, &volume, &crate::EntrySlots::default(), base as u64),
                Err(FfsError::Corruption { .. })
            ));
            let mut output = Vec::new();
            // A valid early slot cannot bypass damage later in its parent.
            assert!(matches!(
                crate::extract_slots(&cx, &volume, &slot_selector(&[root - base]), &mut output,),
                Err(FfsError::Corruption { .. })
            ));
            assert!(output.is_empty());
        }
    }
}

#[test]
fn native_extraction_validates_allocation_and_directory_tails_before_output() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for damage in 0..4 {
            let mut image = Image::new(kind);
            let base = image.base;
            let root = image.root_location();
            let subdir = image.cluster(3);
            let selector = if damage == 3 {
                image.set_link(3, 4);
                image.set_link(4, 0);
                slot_selector(&[root + 32 - base, subdir + 64 - base])
            } else {
                match damage {
                    0 => image.set_link(7, 9),
                    1 => image.set_link(5, image.end()),
                    _ => image.set_copy_link(1, 5, image.end()),
                }
                slot_selector(&[root - base])
            };
            let volume = image.volume();
            let mut output = Vec::new();
            assert!(
                matches!(
                    crate::extract_slots(&cx, &volume, &selector, &mut output),
                    Err(FfsError::Corruption { .. })
                ),
                "{kind:?}: damage {damage}"
            );
            assert!(output.is_empty());
        }
    }
}

#[test]
fn native_extraction_propagates_payload_cancellation() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let image = Image::new(kind);
        let selector = slot_selector(&[image.root_location() - image.base]);
        let fail_at = image.cluster(9) as u64;
        let volume = FatVolume::from_device(
            &cx,
            Box::new(Memory {
                bytes: Arc::new(image.bytes),
                reads: Arc::new(AtomicUsize::new(0)),
                fail_at: Some(fail_at),
            }),
            image.base as u64,
            image.length as u64,
        )
        .unwrap();
        let mut output = Vec::new();
        assert!(matches!(
            crate::extract_slots(&cx, &volume, &selector, &mut output),
            Err(FfsError::Cancelled)
        ));
        assert!(output.is_empty());
    }
}

#[test]
fn native_catalog_and_extraction_leave_file_images_and_adjacent_bytes_unchanged() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        let mut image = Image::new(kind);
        let root = image.root_location();
        image.bytes[root] = 0x82;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("native-names.img");
        std::fs::write(&path, &image.bytes).unwrap();
        let volume =
            FatVolume::open(&cx, &path, image.base as u64, Some(image.length as u64)).unwrap();
        let catalog = crate::native_catalog(
            &cx,
            &volume,
            &crate::EntrySlots::default(),
            image.base as u64,
        )
        .unwrap();
        let selector =
            crate::EntrySlots::parse(catalog["entries"][0]["entry_slots"].as_str().unwrap())
                .unwrap();
        let mut output = Vec::new();
        crate::extract_slots(&cx, &volume, &selector, &mut output).unwrap();
        assert_eq!(output, payload());
        assert_eq!(std::fs::read(&path).unwrap(), image.bytes);
    }
}

mod check;
mod filesystem;
