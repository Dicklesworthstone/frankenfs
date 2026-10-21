//! Shared growth callers must verify allocation before attaching it or publishing EOF.
//! Reuse the constructed native images and pending/durable device from the parent.

use super::*;
use ffs_ondisk::fat::FatEntry;

#[derive(Clone, Copy, Debug)]
enum Action {
    Truncate,
    Write,
    Allocate,
    Reserve,
    Zero,
    Copy,
}

const ACTIONS: [Action; 6] = [
    Action::Truncate,
    Action::Write,
    Action::Allocate,
    Action::Reserve,
    Action::Zero,
    Action::Copy,
];

fn target_size(image: &Image) -> u64 {
    (image.chain.len() as u64 + 2) * u64::from(image.geometry.cluster_bytes()) + 17
}

fn execute(cx: &Cx, volume: &FatVolume, action: Action, end: u64) -> Result<()> {
    match action {
        Action::Truncate => truncate_in_volume(cx, volume, "/target.bin", end, NOW),
        Action::Write => {
            write_range_in_volume(cx, volume, "/target.bin", end - 4, b"TAIL", NOW).map(|_| ())
        }
        Action::Allocate => volume.preallocate(cx, "/target.bin", 0, end, 0, NOW),
        Action::Reserve => {
            volume.preallocate(cx, "/target.bin", 0, end, libc::FALLOC_FL_KEEP_SIZE, NOW)
        }
        Action::Zero => {
            let old = volume.resolve(cx, "/target.bin")?.unwrap().native.size;
            volume.preallocate(
                cx,
                "/target.bin",
                u64::from(old),
                end - u64::from(old),
                libc::FALLOC_FL_ZERO_RANGE,
                NOW,
            )
        }
        Action::Copy => volume
            .copy_range(cx, "/other.bin", 0, "/target.bin", end - 4, 4, NOW)
            .map(|copied| assert_eq!(copied, 4)),
    }
}

fn selected(image: &Image) -> std::ops::Range<u8> {
    if image.geometry.mirrored() {
        0..image.geometry.fat_count()
    } else {
        image.geometry.active_fat()..image.geometry.active_fat() + 1
    }
}

fn word_in_write(image: &Image, at: u64, bytes: &[u8], copy: u8, cluster: u32) -> Option<FatEntry> {
    let position = BASE + image.geometry.entry_offset(copy, cluster).unwrap();
    let width = image.geometry.kind().entry_bytes() as usize;
    if position < at || position + width as u64 > at + bytes.len() as u64 {
        return None;
    }
    let within = (position - at) as usize;
    let mut raw = [0; 4];
    raw[..width].copy_from_slice(&bytes[within..within + width]);
    Some(image.geometry.kind().decode_entry(u32::from_le_bytes(raw)))
}

/// Ignore earlier dirty-marker sector writes and later writes to the same
/// physical FAT sector. Select the first actual publication of this link.
fn link_writes(image: &Image, cluster: u32, value: FatEntry) -> Vec<usize> {
    let storage = image.device.storage.lock().unwrap();
    selected(image)
        .map(|copy| {
            storage
                .writes
                .iter()
                .find(|(_, at, bytes)| {
                    word_in_write(image, *at, bytes, copy, cluster) == Some(value)
                })
                .expect("successful probe published the selected native link")
                .0
        })
        .collect()
}

fn probe(kind: FatKind, sector: u32, active: bool, action: Action) -> (Image, Vec<u32>) {
    let image = fixture(kind, sector, active, 768);
    let volume = image.device.open().unwrap();
    execute(&Cx::for_testing(), &volume, action, target_size(&image)).unwrap();
    let entry = volume
        .resolve(&Cx::for_testing(), "/target.bin")
        .unwrap()
        .unwrap();
    let chain = volume
        .file_chain(&Cx::for_testing(), &entry)
        .unwrap()
        .clusters;
    let added = chain[image.chain.len()..].to_vec();
    assert_eq!(added.len(), 3);
    (image, added)
}

fn assert_not_published(image: &Image, original: &[u8]) {
    assert_eq!(image.device.bytes(image.entry, 32), original);
    assert!(
        publications(image).is_empty(),
        "must stop BEFORE changing native EOF or head"
    );
    assert_eq!(
        image
            .device
            .bytes(BASE + image.geometry.cluster_offset(4).unwrap(), 4),
        b"SAFE"
    );
}

#[test]
fn shared_growth_paths_keep_prefix_preallocation_and_account_for_only_added_clusters() {
    let cx = Cx::for_testing();
    for kind in [FatKind::Fat16, FatKind::Fat32] {
        for sector in [512, 4096] {
            for action in ACTIONS {
                let image = fixture(kind, sector, kind == FatKind::Fat32, 768);
                let volume = image.device.open().unwrap();
                let free = volume.free_clusters(&cx).unwrap();
                let end = target_size(&image);
                execute(&cx, &volume, action, end).unwrap();
                let entry = volume.resolve(&cx, "/target.bin").unwrap().unwrap();
                let chain = volume.file_chain(&cx, &entry).unwrap();
                assert_eq!(&chain.clusters[..image.chain.len()], image.chain.as_slice());
                assert_eq!(chain.clusters.len(), image.chain.len() + 3);
                assert_eq!(volume.free_clusters(&cx).unwrap(), free - 3);
                let mut expected = image.payload.clone();
                if !matches!(action, Action::Reserve) {
                    expected.resize(end as usize, 0);
                    match action {
                        Action::Write => expected[end as usize - 4..].copy_from_slice(b"TAIL"),
                        Action::Copy => expected[end as usize - 4..].copy_from_slice(b"SAFE"),
                        _ => {}
                    }
                }
                assert_eq!(
                    volume.read(&cx, &chain, 0, end as usize).unwrap(),
                    expected,
                    "{kind:?} {sector} {action:?}"
                );
                assert!(volume.check(&cx).unwrap().clean);
            }
        }
    }
}

#[test]
fn dropped_detached_links_stop_every_growth_caller_before_attachment_or_eof() {
    for (kind, active) in [
        (FatKind::Fat16, false),
        (FatKind::Fat32, false),
        (FatKind::Fat32, true),
    ] {
        for action in ACTIONS {
            let (success, added) = probe(kind, 512, active, action);
            for attempt in link_writes(&success, added[0], FatEntry::Next(added[1])) {
                let image = fixture(kind, 512, active, 768);
                let volume = image.device.open().unwrap();
                let record = image.device.bytes(image.entry, 32);
                let old = allocation(&image);
                image.device.storage.lock().unwrap().fault = Some((attempt, Fault::Drop));
                assert!(
                    execute(&Cx::for_testing(), &volume, action, target_size(&image)).is_err(),
                    "{kind:?} {action:?} {attempt}"
                );
                assert_not_published(&image, &record);
                assert_old_allocation(&image, &old);
                let storage = image.device.storage.lock().unwrap();
                for copy in selected(&image) {
                    assert!(!storage.writes.iter().any(|(_, at, bytes)| {
                        word_in_write(&image, *at, bytes, copy, *image.chain.last().unwrap())
                            == Some(FatEntry::Next(added[0]))
                    }));
                }
            }
        }
    }
}

#[test]
fn dropped_attachment_links_stop_every_growth_caller_before_eof_publication() {
    for (kind, active) in [
        (FatKind::Fat16, false),
        (FatKind::Fat32, false),
        (FatKind::Fat32, true),
    ] {
        for action in ACTIONS {
            let (success, added) = probe(kind, 512, active, action);
            for attempt in link_writes(
                &success,
                *success.chain.last().unwrap(),
                FatEntry::Next(added[0]),
            ) {
                let image = fixture(kind, 512, active, 768);
                let volume = image.device.open().unwrap();
                let record = image.device.bytes(image.entry, 32);
                image.device.storage.lock().unwrap().fault = Some((attempt, Fault::Drop));
                assert!(execute(&Cx::for_testing(), &volume, action, target_size(&image)).is_err());
                assert_not_published(&image, &record);
            }
        }
    }
}

fn empty_fixture(kind: FatKind, active: bool) -> Image {
    let mut image = fixture(kind, 512, active, 768);
    let width = kind.entry_bytes() as usize;
    let mut changes = Vec::new();
    for copy in selected(&image) {
        for &cluster in &image.chain {
            let at = BASE + image.geometry.entry_offset(copy, cluster).unwrap();
            let mut word = [0; 4];
            word[..width].copy_from_slice(&image.device.bytes(at, width));
            let high = u32::from_le_bytes(word)
                & if kind == FatKind::Fat32 {
                    0xF000_0000
                } else {
                    0
                };
            changes.push((at, high.to_le_bytes()[..width].to_vec()));
        }
    }
    let mut record = image.device.bytes(image.entry, 32);
    if kind == FatKind::Fat32 {
        let high = u16::from_le_bytes([record[20], record[21]]) & 0xF000;
        record[20..22].copy_from_slice(&high.to_le_bytes());
    }
    record[26..32].fill(0);
    {
        let mut storage = image.device.storage.lock().unwrap();
        for (at, bytes) in changes {
            storage.put(at, &bytes);
        }
        storage.put(image.entry, &record);
        storage.persist();
    }
    image.chain.clear();
    image.payload.clear();
    assert!(
        image
            .device
            .open()
            .unwrap()
            .check(&Cx::for_testing())
            .unwrap()
            .clean
    );
    image
}

#[test]
fn first_allocation_does_not_publish_a_head_over_unverified_new_links() {
    for (kind, active) in [
        (FatKind::Fat16, false),
        (FatKind::Fat32, false),
        (FatKind::Fat32, true),
    ] {
        let success = empty_fixture(kind, active);
        let volume = success.device.open().unwrap();
        execute(
            &Cx::for_testing(),
            &volume,
            Action::Write,
            target_size(&success),
        )
        .unwrap();
        let entry = volume
            .resolve(&Cx::for_testing(), "/target.bin")
            .unwrap()
            .unwrap();
        let chain = volume.file_chain(&Cx::for_testing(), &entry).unwrap();
        for attempt in link_writes(
            &success,
            chain.clusters[0],
            FatEntry::Next(chain.clusters[1]),
        ) {
            let image = empty_fixture(kind, active);
            let volume = image.device.open().unwrap();
            let record = image.device.bytes(image.entry, 32);
            image.device.storage.lock().unwrap().fault = Some((attempt, Fault::Drop));
            assert!(
                execute(
                    &Cx::for_testing(),
                    &volume,
                    Action::Write,
                    target_size(&image)
                )
                .is_err()
            );
            assert_not_published(&image, &record);
            assert_eq!(entry_size(&image), 0);
        }
    }
}

#[test]
fn failed_growth_link_readback_and_cancellation_stop_before_directory_publication() {
    let (success, added) = probe(FatKind::Fat16, 512, false, Action::Write);
    let detached = *link_writes(&success, added[0], FatEntry::Next(added[1]))
        .last()
        .unwrap();
    let attached = *link_writes(
        &success,
        *success.chain.last().unwrap(),
        FatEntry::Next(added[0]),
    )
    .last()
    .unwrap();
    for boundary in [detached, attached] {
        for cancel in [false, true] {
            let image = fixture(FatKind::Fat16, 512, false, 768);
            let volume = image.device.open().unwrap();
            let record = image.device.bytes(image.entry, 32);
            {
                let mut storage = image.device.storage.lock().unwrap();
                if cancel {
                    storage.fault = Some((boundary, Fault::Cancel));
                } else {
                    storage.read_failure = Some((
                        boundary + 1,
                        BASE + image.geometry.entry_offset(0, image.chain[0]).unwrap(),
                    ));
                }
            }
            assert!(
                execute(
                    &Cx::for_testing(),
                    &volume,
                    Action::Write,
                    target_size(&image)
                )
                .is_err()
            );
            assert_not_published(&image, &record);
            assert_eq!(
                image.device.storage.lock().unwrap().attempts,
                boundary + usize::from(!cancel)
            );
        }
    }
}

/// Simulate an acknowledged write misdirecting a FAT word at a sync boundary.
/// Native reads must detect it, including corruption of a retained old link.
struct CorruptAfterSync {
    inner: Device,
    attempt: usize,
    position: u64,
    value: Vec<u8>,
}

impl ByteDevice for CorruptAfterSync {
    fn len_bytes(&self) -> u64 {
        self.inner.len_bytes()
    }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        self.inner.read_exact_at(cx, at, bytes)
    }
    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        self.inner.write_all_at(cx, at, bytes)
    }
    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        self.inner.sync(cx)?;
        let mut storage = self.inner.storage.lock().unwrap();
        if storage.attempts == self.attempt {
            storage.put(self.position, &self.value);
            storage.persist();
        }
        Ok(())
    }
}

fn corrupting_volume(image: &Image, attempt: usize) -> FatVolume {
    FatVolume::from_device(
        &Cx::for_testing(),
        Box::new(CorruptAfterSync {
            inner: image.device.clone(),
            attempt,
            position: BASE
                + image
                    .geometry
                    .entry_offset(image.geometry.active_fat(), image.chain[0])
                    .unwrap(),
            value: vec![0; image.geometry.kind().entry_bytes() as usize],
        }),
        BASE,
        image.geometry.volume_bytes(),
    )
    .unwrap()
}

#[test]
fn detached_publication_rechecks_retained_links_not_only_the_new_run() {
    let (success, added) = probe(FatKind::Fat32, 4096, true, Action::Truncate);
    let sync = *link_writes(&success, added[0], FatEntry::Next(added[1]))
        .last()
        .unwrap()
        + 1;
    let image = fixture(FatKind::Fat32, 4096, true, 768);
    let volume = corrupting_volume(&image, sync);
    let record = image.device.bytes(image.entry, 32);
    assert!(
        execute(
            &Cx::for_testing(),
            &volume,
            Action::Truncate,
            target_size(&image)
        )
        .is_err()
    );
    assert_not_published(&image, &record);
    assert_eq!(image.device.storage.lock().unwrap().attempts, sync);
}

#[test]
fn growth_inside_existing_preallocation_verifies_links_after_the_data_barrier() {
    let success = fixture(FatKind::Fat16, 512, false, 768);
    let volume = success.device.open().unwrap();
    execute(&Cx::for_testing(), &volume, Action::Truncate, 1536).unwrap();
    let sync = success
        .device
        .storage
        .lock()
        .unwrap()
        .writes
        .iter()
        .filter(|(_, at, _)| {
            success.chain.iter().any(|&c| {
                let start = BASE + success.geometry.cluster_offset(c).unwrap();
                *at >= start && *at < start + 512
            })
        })
        .map(|(attempt, _, _)| *attempt)
        .max()
        .unwrap()
        + 1;
    let image = fixture(FatKind::Fat16, 512, false, 768);
    let volume = corrupting_volume(&image, sync);
    let record = image.device.bytes(image.entry, 32);
    assert!(execute(&Cx::for_testing(), &volume, Action::Truncate, 1536).is_err());
    assert_not_published(&image, &record);
    assert_eq!(image.device.storage.lock().unwrap().attempts, sync);
}

#[test]
fn mounted_growth_link_failure_keeps_native_eof_and_quarantines_cached_access() {
    let (success, added) = probe(FatKind::Fat16, 512, false, Action::Write);
    let attempt = link_writes(
        &success,
        *success.chain.last().unwrap(),
        FatEntry::Next(added[0]),
    )[0];
    let image = fixture(FatKind::Fat16, 512, false, 768);
    let record = image.device.bytes(image.entry, 32);
    let cx = Cx::for_testing();
    let fs = crate::filesystem::FatFs::new_with_mode(&cx, image.device.open().unwrap(), 0, 0, true)
        .unwrap();
    let mut scope = RequestScope::empty();
    let ino = fs
        .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("TARGET.BIN"))
        .unwrap()
        .ino;
    assert_eq!(
        fs.read(&cx, &mut scope, ino, 0, 768).unwrap(),
        image.payload
    );
    fs.statfs(&cx, &mut scope, ino).unwrap();
    image.device.storage.lock().unwrap().fault = Some((attempt, Fault::Drop));
    assert!(
        fs.write(&cx, &mut scope, ino, target_size(&image) - 4, b"TAIL")
            .is_err()
    );
    assert_not_published(&image, &record);
    assert_eq!(
        fs.getattr(&cx, &mut scope, ino).unwrap_err().to_errno(),
        libc::EIO
    );
    assert_eq!(
        fs.read(&cx, &mut scope, ino, 0, 1).unwrap_err().to_errno(),
        libc::EIO
    );
    assert_eq!(
        fs.statfs(&cx, &mut scope, ino).unwrap_err().to_errno(),
        libc::EIO
    );
}
