use super::*;
use ffs_block::ByteDevice;
use ffs_types::ByteOffset;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::sync::{OnceLock, Weak};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Default)]
struct Probe {
    owner: OnceLock<Weak<FatFs>>,
    require_exclusive: AtomicBool,
    checked_reads: AtomicUsize,
    writes: AtomicUsize,
    syncs: AtomicUsize,
    fail_sync: AtomicBool,
}

struct Device {
    file: File,
    length: u64,
    probe: Arc<Probe>,
}

impl ByteDevice for Device {
    fn len_bytes(&self) -> u64 { self.length }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        if self.probe.require_exclusive.load(Ordering::Acquire) {
            let owner = self.probe.owner.get().and_then(Weak::upgrade).expect("mounted owner");
            // This observes the real operation gate at backing I/O, including
            // source reads before the first payload write. The inherited
            // chunked read/write fallback holds a reader here and fails this.
            assert!(matches!(owner.operations.try_read(), Err(std::sync::TryLockError::WouldBlock)));
            assert!(matches!(owner.operations.try_write(), Err(std::sync::TryLockError::WouldBlock)));
            self.probe.checked_reads.fetch_add(1, Ordering::AcqRel);
        }
        self.file.read_exact_at(bytes, at.0)?;
        checkpoint(cx)
    }
    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> Result<()> {
        checkpoint(cx)?;
        self.probe.writes.fetch_add(1, Ordering::AcqRel);
        self.file.write_all_at(bytes, at.0)?;
        checkpoint(cx)
    }
    fn sync(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        self.probe.syncs.fetch_add(1, Ordering::AcqRel);
        if self.probe.fail_sync.swap(false, Ordering::AcqRel) {
            return Err(std::io::Error::other("injected mounted-copy sync failure").into());
        }
        self.file.sync_all()?;
        checkpoint(cx)
    }
}

fn mounted() -> (tempfile::TempDir, Arc<FatFs>, Arc<Probe>) {
    let (directory, original) = writable_fat16();
    drop(original);
    let image = directory.path().join("volume.fat");
    let file = OpenOptions::new().read(true).write(true).open(image).unwrap();
    let length = file.metadata().unwrap().len();
    let probe = Arc::new(Probe::default());
    let cx = Cx::for_testing();
    let volume = FatVolume::from_device(&cx, Box::new(Device {
        file, length, probe: Arc::clone(&probe),
    }), 0, length).unwrap();
    let fs = Arc::new(FatFs::new_with_mode(&cx, volume, 1000, 1000, true).unwrap());
    probe.owner.set(Arc::downgrade(&fs)).ok().expect("set owner once");
    (directory, fs, probe)
}

#[test]
fn fsops_copy_is_exclusive_from_source_reads_through_cache_publication() {
    let (_directory, fs, probe) = mounted();
    let cx = Cx::for_testing();
    let input = create_file(&fs, "INPUT.BIN");
    let output = create_file(&fs, "OUTPUT.BIN");
    // More than one fallback chunk, but less than the FAT16 fixture capacity.
    let size = 1024 * 1024 + 513;
    let payload: Vec<_> = (0..size).map(|at| (at % 251) as u8).collect();
    fs.write(&cx, &mut RequestScope::empty(), input, 0, &payload).unwrap();
    fs.write(&cx, &mut RequestScope::empty(), output, 0, b"old").unwrap();
    fs.setattr(&cx, &mut RequestScope::empty(), input,
        &SetAttrRequest { mode: Some(0o444), ..Default::default() }).unwrap();
    let before_input = fs.node(&cx, input).unwrap().entry.unwrap().native;
    let before_free = fs.statfs(&cx, &mut RequestScope::empty(), ROOT).unwrap().blocks_free;
    let before_output = fs.node(&cx, output).unwrap().entry.unwrap().offset;
    assert_eq!(fs.getattr(&cx, &mut RequestScope::empty(), output).unwrap().size, 3);
    probe.require_exclusive.store(true, Ordering::Release);
    let ops: &dyn FsOps = fs.as_ref();
    let copied = ops.copy_file_range(&cx, &mut RequestScope::empty(), input, 17, output, 9, size as u64).unwrap();
    probe.require_exclusive.store(false, Ordering::Release);
    assert!(probe.checked_reads.load(Ordering::Acquire) > 0);
    assert_eq!(copied, size as u64 - 17);
    let mut expected = b"old".to_vec();
    expected.resize(9, 0);
    expected.extend_from_slice(&payload[17..]);
    assert_eq!(fs.read(&cx, &mut RequestScope::empty(), output, 0, expected.len() as u32).unwrap(), expected);
    assert_eq!(fs.getattr(&cx, &mut RequestScope::empty(), output).unwrap().size, expected.len() as u64);
    assert_eq!(fs.node(&cx, output).unwrap().entry.unwrap().offset, before_output);
    assert_eq!(fs.node(&cx, input).unwrap().entry.unwrap().native, before_input);
    assert_eq!(fs.read(&cx, &mut RequestScope::empty(), input, 0, size as u32).unwrap(), payload);
    assert!(fs.statfs(&cx, &mut RequestScope::empty(), ROOT).unwrap().blocks_free < before_free);
    assert!(fs.volume.check(&cx).unwrap().clean);
}

#[test]
fn fsops_copy_noops_and_refusals_preserve_usable_mount_and_native_bytes() {
    let (directory, fs, probe) = mounted();
    let cx = Cx::for_testing();
    let input = create_file(&fs, "INPUT.BIN");
    let output = create_file(&fs, "OUTPUT.BIN");
    fs.write(&cx, &mut RequestScope::empty(), input, 0, b"source").unwrap();
    let before = std::fs::read(directory.path().join("volume.fat")).unwrap();
    let writes = probe.writes.load(Ordering::Acquire);
    let syncs = probe.syncs.load(Ordering::Acquire);
    assert_eq!(fs.copy_file_range(&cx, &mut RequestScope::empty(), input, u64::MAX, output, u64::MAX, 0).unwrap(), 0);
    assert_eq!(fs.copy_file_range(&cx, &mut RequestScope::empty(), input, 6, output, 4096, 10).unwrap(), 0);
    for (source, at_in, target, at_out, length) in [
        (input, 0, input, 1, 3),
        (input, 0, output, u64::from(u32::MAX), 1),
        (input, u64::MAX, output, 0, 1),
        (ROOT, 0, output, 0, 1),
        (InodeNumber(u64::MAX), 0, output, 0, 1),
    ] {
        assert!(fs.copy_file_range(&cx, &mut RequestScope::empty(), source, at_in, target, at_out, length).is_err());
    }
    assert_eq!(probe.writes.load(Ordering::Acquire), writes);
    assert_eq!(probe.syncs.load(Ordering::Acquire), syncs);
    assert_eq!(std::fs::read(directory.path().join("volume.fat")).unwrap(), before);
    assert_eq!(fs.copy_file_range(&cx, &mut RequestScope::empty(), input, 1, output, 0, 3).unwrap(), 3);
    assert_eq!(fs.read(&cx, &mut RequestScope::empty(), output, 0, 8).unwrap(), b"our");
}

#[test]
fn fsops_failed_copy_quarantines_read_cache_sync_and_further_copies() {
    let (_directory, fs, probe) = mounted();
    let cx = Cx::for_testing();
    let input = create_file(&fs, "INPUT.BIN");
    let output = create_file(&fs, "OUTPUT.BIN");
    fs.write(&cx, &mut RequestScope::empty(), input, 0, &[0xAB; 1024]).unwrap();
    fs.write(&cx, &mut RequestScope::empty(), output, 0, &[0xCD; 1024]).unwrap();
    fs.getattr(&cx, &mut RequestScope::empty(), output).unwrap();
    fs.statfs(&cx, &mut RequestScope::empty(), ROOT).unwrap();
    probe.fail_sync.store(true, Ordering::Release);
    assert!(fs.copy_file_range(&cx, &mut RequestScope::empty(), input, 0, output, 0, 1024).is_err());
    let writes = probe.writes.load(Ordering::Acquire);
    let syncs = probe.syncs.load(Ordering::Acquire);
    assert!(fs.getattr(&cx, &mut RequestScope::empty(), output).is_err());
    assert!(fs.statfs(&cx, &mut RequestScope::empty(), ROOT).is_err());
    assert!(fs.read(&cx, &mut RequestScope::empty(), input, 0, 1).is_err());
    assert!(fs.copy_file_range(&cx, &mut RequestScope::empty(), input, 0, output, 0, 1).is_err());
    assert!(fs.copy_file_range(&cx, &mut RequestScope::empty(), input, 0, output, 0, 0).is_err());
    assert!(fs.fsync(&cx, &mut RequestScope::empty(), output, 0, false).is_err());
    assert!(fs.flush_on_destroy(&cx).is_err());
    assert_eq!(probe.writes.load(Ordering::Acquire), writes);
    assert_eq!(probe.syncs.load(Ordering::Acquire), syncs);
}

#[test]
fn concurrent_copy_and_source_write_never_mix_source_generations() {
    let (_directory, fs) = writable_fat16();
    let cx = Cx::for_testing();
    let input = create_file(&fs, "INPUT.BIN");
    let output = create_file(&fs, "OUTPUT.BIN");
    let size = 1024 * 1024 + 513;
    let old = vec![0x11; size];
    let new = vec![0x77; size];
    fs.write(&cx, &mut RequestScope::empty(), input, 0, &old).unwrap();
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|threads| {
        let copy = threads.spawn(|| {
            let cx = Cx::for_testing();
            barrier.wait();
            fs.copy_file_range(&cx, &mut RequestScope::empty(), input, 0, output, 0, size as u64).unwrap()
        });
        let write = threads.spawn(|| {
            let cx = Cx::for_testing();
            barrier.wait();
            fs.write(&cx, &mut RequestScope::empty(), input, 0, &new).unwrap();
        });
        assert_eq!(copy.join().unwrap(), size as u64);
        write.join().unwrap();
    });
    let actual = fs.read(&cx, &mut RequestScope::empty(), output, 0, size as u32).unwrap();
    assert!(actual == old || actual == new);
    assert_eq!(fs.read(&cx, &mut RequestScope::empty(), input, 0, size as u32).unwrap(), new);
    assert!(fs.volume.check(&cx).unwrap().clean);
}
