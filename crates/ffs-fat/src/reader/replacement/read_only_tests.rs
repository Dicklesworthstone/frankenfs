//! End-to-end protection admission, native reads and mutation publication.
//! Handcrafted native volumes are surrounded by unrelated partition sentinels;
//! these are real codec/file-descriptor tests, not native-OS interchange evidence.

use super::*;
use ffs_core::{FsOps, RequestScope};
use ffs_ondisk::fat::FatOemCodePage;
use ffs_types::InodeNumber;
use std::ffi::OsStr;
use std::sync::Mutex;

use ffs_repair::sidecar::live::SidecarImageDevice;

const VOLUME_BYTES: usize = 8192 * 512;
const VOLUME_BASE: u64 = 512;
const ROOT_OFFSET: usize = 65 * 512;
const DATA_OFFSET: usize = 97 * 512;
const PAYLOAD: &[u8] =
    b"Native FAT16 protected reads must never need permission to modify the backing image.";

struct Fixture {
    _directory: tempfile::TempDir,
    image: PathBuf,
    sidecar: PathBuf,
    source: PathBuf,
    volume_bytes: u64,
}

impl Fixture {
    fn new() -> Self {
        let mut bytes = vec![0; VOLUME_BYTES + 1024];
        bytes[..512].fill(0xa7);
        bytes[VOLUME_BYTES + 512..].fill(0xb9);
        let volume = &mut bytes[512..VOLUME_BYTES + 512];
        volume[..3].copy_from_slice(&[0xeb, 0x3c, 0x90]);
        volume[3..11].copy_from_slice(b"MSWIN4.1");
        volume[11..13].copy_from_slice(&512_u16.to_le_bytes());
        volume[13] = 1;
        volume[14..16].copy_from_slice(&1_u16.to_le_bytes());
        volume[16] = 2;
        volume[17..19].copy_from_slice(&512_u16.to_le_bytes());
        volume[19..21].copy_from_slice(&8192_u16.to_le_bytes());
        volume[21] = 0xf8;
        volume[22..24].copy_from_slice(&32_u16.to_le_bytes());
        volume[24..26].copy_from_slice(&32_u16.to_le_bytes());
        volume[26..28].copy_from_slice(&64_u16.to_le_bytes());
        volume[36] = 0x80;
        volume[38] = 0x29;
        volume[39..43].copy_from_slice(&0x1234_abcd_u32.to_le_bytes());
        volume[43..54].copy_from_slice(b"NO NAME    ");
        volume[54..62].copy_from_slice(b"FAT16   ");
        volume[510..512].copy_from_slice(&[0x55, 0xaa]);
        for copy in 0..2 {
            let start = (1 + copy * 32) * 512;
            for (index, value) in [0xfff8_u16, 0xffff, 0xffff].into_iter().enumerate() {
                volume[start + index * 2..start + index * 2 + 2]
                    .copy_from_slice(&value.to_le_bytes());
            }
        }
        let entry = &mut volume[ROOT_OFFSET..ROOT_OFFSET + 32];
        entry[..11].copy_from_slice(b"PAYLOAD BIN");
        entry[11] = 0x20;
        entry[26..28].copy_from_slice(&2_u16.to_le_bytes());
        entry[28..32].copy_from_slice(&u32::try_from(PAYLOAD.len()).unwrap().to_le_bytes());
        volume[DATA_OFFSET..DATA_OFFSET + PAYLOAD.len()].copy_from_slice(PAYLOAD);
        Self::from_bytes(bytes, VOLUME_BYTES as u64)
    }

    fn fat32() -> Self {
        let sectors = 32_u32 + 2 * 548 + 70_000;
        let length = u64::from(sectors) * 512;
        let mut bytes = vec![0; length as usize + 1024];
        bytes[..512].fill(0xa7);
        bytes[length as usize + 512..].fill(0xb9);
        let volume = &mut bytes[512..length as usize + 512];
        let mut boot = [0_u8; 512];
        boot[..3].copy_from_slice(&[0xeb, 0x58, 0x90]);
        boot[3..11].copy_from_slice(b"MSWIN4.1");
        boot[11..13].copy_from_slice(&512_u16.to_le_bytes());
        boot[13] = 1;
        boot[14..16].copy_from_slice(&32_u16.to_le_bytes());
        boot[16] = 2;
        boot[21] = 0xf8;
        boot[32..36].copy_from_slice(&sectors.to_le_bytes());
        boot[36..40].copy_from_slice(&548_u32.to_le_bytes());
        boot[44..48].copy_from_slice(&2_u32.to_le_bytes());
        boot[48..50].copy_from_slice(&1_u16.to_le_bytes());
        boot[50..52].copy_from_slice(&6_u16.to_le_bytes());
        boot[64] = 0x80;
        boot[66] = 0x29;
        boot[67..71].copy_from_slice(&0x1234_abcd_u32.to_le_bytes());
        boot[71..82].copy_from_slice(b"NO NAME    ");
        boot[82..90].copy_from_slice(b"FAT32   ");
        boot[510..512].copy_from_slice(&[0x55, 0xaa]);
        volume[..512].copy_from_slice(&boot);
        volume[6 * 512..7 * 512].copy_from_slice(&boot);
        let mut info = [0_u8; 512];
        info[..4].copy_from_slice(&0x4161_5252_u32.to_le_bytes());
        info[484..488].copy_from_slice(&0x6141_7272_u32.to_le_bytes());
        info[488..496].fill(0xff);
        info[508..512].copy_from_slice(&0xaa55_0000_u32.to_le_bytes());
        volume[512..1024].copy_from_slice(&info);
        volume[7 * 512..8 * 512].copy_from_slice(&info);
        for copy in 0..2 {
            let start = (32 + copy * 548) * 512;
            for (index, value) in [0x0fff_fff8_u32, 0x0fff_ffff, 0x0fff_ffff, 0x0fff_ffff]
                .into_iter()
                .enumerate()
            {
                volume[start + index * 4..start + index * 4 + 4]
                    .copy_from_slice(&value.to_le_bytes());
            }
        }
        let root = (32 + 2 * 548) * 512;
        let entry = &mut volume[root..root + 32];
        entry[..11].copy_from_slice(b"PAYLOAD BIN");
        entry[11] = 0x20;
        entry[26..28].copy_from_slice(&3_u16.to_le_bytes());
        entry[28..32].copy_from_slice(&u32::try_from(PAYLOAD.len()).unwrap().to_le_bytes());
        volume[root + 512..root + 512 + PAYLOAD.len()].copy_from_slice(PAYLOAD);
        Self::from_bytes(bytes, length)
    }

    fn from_bytes(bytes: Vec<u8>, volume_bytes: u64) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let image = directory.path().join("partitioned-fat.img");
        let sidecar = directory.path().join("partitioned-fat.ffsrq");
        let source = directory.path().join("replacement.bin");
        std::fs::write(&image, bytes).unwrap();
        std::fs::write(&source, b"explicit replacement source").unwrap();
        ffs_repair::sidecar::protect(
            &Cx::for_testing(),
            &image,
            &sidecar,
            ffs_repair::sidecar::SidecarOptions {
                block_size: 4096,
                group_blocks: 16,
                repair_symbols: 4,
            },
        )
        .unwrap();
        Self {
            _directory: directory,
            image,
            sidecar,
            source,
            volume_bytes,
        }
    }

    fn args(&self) -> ImageArgs {
        ImageArgs {
            image: self.image.clone(),
            offset: VOLUME_BASE,
            length: Some(self.volume_bytes),
            oem_code_page: FatOemCodePage::Ascii,
            sidecar: Some(self.sidecar.clone()),
        }
    }

    fn snapshot(&self) -> (Vec<u8>, Vec<u8>, Stamp, Stamp) {
        (
            std::fs::read(&self.image).unwrap(),
            std::fs::read(&self.sidecar).unwrap(),
            Stamp::of(&std::fs::metadata(&self.image).unwrap()),
            Stamp::of(&std::fs::metadata(&self.sidecar).unwrap()),
        )
    }
}

#[test]
fn fat16_protected_read_only_mount_recovers_in_memory_without_native_writes() {
    let fixture = Fixture::new();
    let cx = Cx::for_testing();
    let admitted = fixture.snapshot();
    let volume = fixture.args().open(&cx).unwrap();
    let check = volume.check(&cx).unwrap();
    assert!(check.clean && check.complete && check.namespace_complete);
    sync_volume(&cx, &volume).unwrap();
    assert_eq!(fixture.snapshot(), admitted);
    let fs = crate::filesystem::FatFs::new(&cx, volume, 1000, 1000).unwrap();
    let mut scope = RequestScope::empty();
    let entry = fs
        .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("PAYLOAD.BIN"))
        .unwrap();
    // Simulate corruption after generation admission, not permission to restore
    // a source that already differed from the sidecar when opened.
    File::options()
        .write(true)
        .open(&fixture.image)
        .unwrap()
        .write_all_at(&vec![0xfe; PAYLOAD.len()], VOLUME_BASE + DATA_OFFSET as u64)
        .unwrap();
    let before = fixture.snapshot();
    for _ in 0..2 {
        assert_eq!(
            fs.read(
                &cx,
                &mut scope,
                entry.ino,
                0,
                u32::try_from(PAYLOAD.len()).unwrap(),
            )
            .unwrap(),
            PAYLOAD
        );
        fs.fsync(&cx, &mut scope, entry.ino, 0, false).unwrap();
        assert_eq!(fixture.snapshot(), before);
    }
    assert!(matches!(
        fs.write(&cx, &mut scope, entry.ino, 0, b"not authorized"),
        Err(FfsError::ReadOnly)
    ));
    fs.flush_on_destroy(&cx).unwrap();
    drop(fs);
    assert_eq!(fixture.snapshot(), before);
    assert!(before.0[..512].iter().all(|byte| *byte == 0xa7));
    assert!(
        before.0[VOLUME_BYTES + 512..]
            .iter()
            .all(|byte| *byte == 0xb9)
    );
}

#[test]
fn fat16_protected_dry_run_shares_read_only_ownership_and_preserves_both_files() {
    let fixture = Fixture::new();
    let cx = Cx::for_testing();
    let reader = fixture.args().open(&cx).unwrap();
    let before = fixture.snapshot();
    let args = ReplaceArgs {
        image: fixture.args(),
        path: "/PAYLOAD.BIN".to_owned(),
        source: fixture.source.clone(),
        create: false,
        offline_image: true,
        dry_run: true,
    };
    // An existing shared reader must not turn a non-mutating preflight into
    // an exclusive-writer admission failure.
    let report = replace(&cx, &args).unwrap();
    assert_eq!(report["dry_run"], true);
    assert_eq!(fixture.snapshot(), before);
    assert!(open_volume(&cx, &fixture.args(), true).is_err());
    drop(reader);
    assert_eq!(fixture.snapshot(), before);

    // Writable operations still acquire exclusive ownership and retain their
    // existing write-through protected device rather than the read-only mode.
    let writable = open_volume(&cx, &fixture.args(), true).unwrap();
    create_in_volume(
        &cx,
        &writable,
        "/CREATED.TXT",
        b"new data",
        1_700_000_000,
        false,
    )
    .unwrap();
    drop(writable);
    assert!(
        ffs_repair::sidecar::verify(&cx, &fixture.image, &fixture.sidecar)
            .unwrap()
            .is_healthy()
    );
    let reader = fixture.args().open(&cx).unwrap();
    let entry = reader.resolve(&cx, "/CREATED.TXT").unwrap().unwrap();
    let chain = reader.file_chain(&cx, &entry).unwrap();
    assert_eq!(reader.read(&cx, &chain, 0, 8).unwrap(), b"new data");
}

#[derive(Clone, Copy)]
enum Failure {
    Io,
    Cancel,
}

impl Failure {
    fn error(self, cx: &Cx) -> FfsError {
        match self {
            Self::Io => std::io::Error::other("injected native barrier failure").into(),
            Self::Cancel => {
                cx.set_cancel_requested(true);
                FfsError::Cancelled
            }
        }
    }
}

#[derive(Default)]
struct BarrierTrace {
    holds: usize,
    barriers: Vec<([u8; 8], u64)>,
    fail_after: Option<(usize, Failure)>,
    fail_seal: Option<Failure>,
    cancel_after: Option<usize>,
}

struct TracedProtection {
    inner: Arc<SidecarImageDevice>,
    archive: PathBuf,
    trace: Arc<Mutex<BarrierTrace>>,
}

fn archive_state(path: &Path) -> ([u8; 8], u64) {
    let file = File::open(path).unwrap();
    let mut magic = [0; 8];
    file.read_exact_at(&mut magic, 0).unwrap();
    (magic, file.metadata().unwrap().ino())
}

impl ByteDevice for TracedProtection {
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
        {
            let mut trace = self.trace.lock().unwrap();
            if trace.holds == 0
                && let Some(failure) = trace.fail_seal.take()
            {
                return Err(failure.error(cx));
            }
        }
        self.inner.sync(cx)?;
        let state = archive_state(&self.archive);
        let mut trace = self.trace.lock().unwrap();
        trace.barriers.push(state);
        if trace.cancel_after == Some(trace.barriers.len()) {
            trace.cancel_after = None;
            cx.set_cancel_requested(true);
        }
        if let Some((cut, failure)) = trace.fail_after
            && cut == trace.barriers.len()
        {
            trace.fail_after = None;
            return Err(failure.error(cx));
        }
        // Match the real file device's trailing checkpoint. This cooperative
        // signal differs from an explicit returned I/O/Cancelled failure above.
        checkpoint(cx)
    }

    fn begin_durability_commit(&self, cx: &Cx) -> ffs_error::Result<()> {
        self.inner.begin_durability_commit(cx)?;
        self.trace.lock().unwrap().holds += 1;
        Ok(())
    }

    fn complete_durability_commit(&self) {
        self.inner.complete_durability_commit();
        self.trace.lock().unwrap().holds -= 1;
    }

    fn abort_durability_commit(&self) {
        self.inner.abort_durability_commit();
        self.trace.lock().unwrap().holds -= 1;
    }
}

struct ProtectedVolume {
    volume: FatVolume,
    protection: Arc<SidecarImageDevice>,
    trace: Arc<Mutex<BarrierTrace>>,
}

impl ProtectedVolume {
    fn open(fixture: &Fixture) -> Self {
        let cx = Cx::for_testing();
        let protection =
            Arc::new(SidecarImageDevice::open(&cx, &fixture.image, &fixture.sidecar).unwrap());
        let trace = Arc::new(Mutex::new(BarrierTrace::default()));
        let volume = FatVolume::from_device(
            &cx,
            Box::new(TracedProtection {
                inner: Arc::clone(&protection),
                archive: fixture.sidecar.clone(),
                trace: Arc::clone(&trace),
            }),
            VOLUME_BASE,
            fixture.volume_bytes,
        )
        .unwrap();
        Self {
            volume,
            protection,
            trace,
        }
    }

    fn committed<T>(
        &self,
        fixture: &Fixture,
        operation: impl FnOnce(&Cx, &FatVolume) -> Result<T>,
    ) -> T {
        let before = archive_state(&fixture.sidecar);
        assert_eq!(&before.0, b"FFSRQSC2");
        let generation = self.protection.ack_status().epoch_generation;
        self.trace.lock().unwrap().barriers.clear();
        let cx = Cx::for_testing();
        let result = operation(&cx, &self.volume).unwrap();
        let trace = self.trace.lock().unwrap();
        assert!(trace.barriers.len() >= 3);
        assert_eq!(trace.holds, 0);
        let (sealed, intermediate) = trace.barriers.split_last().unwrap();
        for &(magic, inode) in intermediate {
            assert_eq!(&magic, b"FFSRQPD2", "intermediate native state was sealed");
            assert_eq!(inode, before.1, "intermediate sync replaced the archive");
        }
        assert_eq!(&sealed.0, b"FFSRQSC2");
        assert_ne!(sealed.1, before.1);
        assert_eq!(archive_state(&fixture.sidecar), *sealed);
        drop(trace);
        let status = self.protection.ack_status();
        assert!(status.native_durable && status.protected_durable);
        assert_eq!(status.epoch_generation, generation + 1);
        let report = self.volume.check(&cx).unwrap();
        assert!(report.clean && report.complete && report.namespace_complete);
        result
    }
}

fn read_payload(volume: &FatVolume, path: &str) -> Vec<u8> {
    let cx = Cx::for_testing();
    let entry = volume.resolve(&cx, path).unwrap().unwrap();
    let chain = volume.file_chain(&cx, &entry).unwrap();
    volume.read(&cx, &chain, 0, 8192).unwrap()
}

#[test]
fn protected_native_mutations_seal_once_after_every_native_barrier() {
    const NOW: u64 = 1_700_000_000;
    for fixture in [Fixture::new(), Fixture::fat32()] {
        let protected = ProtectedVolume::open(&fixture);
        protected.committed(&fixture, |cx, volume| {
            create_in_volume(cx, volume, "/COPY.BIN", &[0x42; 1536], NOW, false)
        });
        protected.committed(&fixture, |cx, volume| {
            replace_in_volume(cx, volume, "/PAYLOAD.BIN", &[0x11; 1536], NOW)
        });
        protected.committed(&fixture, |cx, volume| {
            write_range_in_volume(cx, volume, "/PAYLOAD.BIN", 2048, &[0x22; 128], NOW)
        });
        let mut expected = vec![0x11; 1536];
        expected.resize(2048, 0);
        expected.extend_from_slice(&[0x22; 128]);
        assert_eq!(read_payload(&protected.volume, "/PAYLOAD.BIN"), expected);
        protected.committed(&fixture, |cx, volume| {
            truncate_in_volume(cx, volume, "/PAYLOAD.BIN", 1024, NOW)
        });
        protected.committed(&fixture, |cx, volume| {
            volume.preallocate(cx, "/PAYLOAD.BIN", 0, 4096, libc::FALLOC_FL_KEEP_SIZE, NOW)
        });
        protected.committed(&fixture, |cx, volume| {
            volume.preallocate(
                cx,
                "/PAYLOAD.BIN",
                256,
                256,
                libc::FALLOC_FL_ZERO_RANGE,
                NOW,
            )
        });
        protected.committed(&fixture, |cx, volume| {
            volume.preallocate(
                cx,
                "/PAYLOAD.BIN",
                512,
                512,
                libc::FALLOC_FL_INSERT_RANGE,
                NOW,
            )
        });
        protected.committed(&fixture, |cx, volume| {
            volume.preallocate(
                cx,
                "/PAYLOAD.BIN",
                512,
                512,
                libc::FALLOC_FL_COLLAPSE_RANGE,
                NOW,
            )
        });
        protected.committed(&fixture, |cx, volume| {
            volume.copy_range(cx, "/PAYLOAD.BIN", 0, "/COPY.BIN", 0, 1024, NOW)
        });
        expected = vec![0x11; 1024];
        expected[256..512].fill(0);
        assert_eq!(read_payload(&protected.volume, "/PAYLOAD.BIN"), expected);
        expected.extend_from_slice(&[0x42; 512]);
        assert_eq!(read_payload(&protected.volume, "/COPY.BIN"), expected);
        protected.committed(&fixture, |cx, volume| {
            set_attr_in_volume(cx, volume, "/PAYLOAD.BIN", None, Some(NOW + 4), None)
        });
        protected.committed(&fixture, |cx, volume| {
            mkdir_in_volume(cx, volume, "/DIR", NOW, false)
        });
        protected.committed(&fixture, |cx, volume| {
            rename_in_volume(cx, volume, "/PAYLOAD.BIN", "/SHORT.BIN", false)
        });
        protected.committed(&fixture, |cx, volume| {
            rename_in_volume(cx, volume, "/SHORT.BIN", "/short.bin", false)
        });
        protected.committed(&fixture, |cx, volume| {
            rename_in_volume(cx, volume, "/short.bin", "/DIR/MOVED.BIN", false)
        });
        protected.committed(&fixture, |cx, volume| {
            volume.rename_exchange(cx, "/COPY.BIN", "/DIR/MOVED.BIN", false)
        });
        protected.committed(&fixture, |cx, volume| {
            unlink_in_volume(cx, volume, "/COPY.BIN", false)
        });
        protected.committed(&fixture, |cx, volume| {
            unlink_in_volume(cx, volume, "/DIR/MOVED.BIN", false)
        });
        protected.committed(&fixture, |cx, volume| {
            rmdir_in_volume(cx, volume, "/DIR", false)
        });
        drop(protected);
        let cx = Cx::for_testing();
        assert!(
            ffs_repair::sidecar::verify(&cx, &fixture.image, &fixture.sidecar)
                .unwrap()
                .is_healthy()
        );
        let bytes = std::fs::read(&fixture.image).unwrap();
        assert!(bytes[..512].iter().all(|byte| *byte == 0xa7));
        assert!(
            bytes[fixture.volume_bytes as usize + 512..]
                .iter()
                .all(|byte| *byte == 0xb9)
        );
        drop(fixture.args().open(&cx).unwrap());
    }
}

#[test]
fn protected_native_barrier_errors_and_cancellation_never_seal_partial_mutations() {
    let fixture = Fixture::new();
    let pristine = fixture.snapshot();
    let protected = ProtectedVolume::open(&fixture);
    protected.committed(&fixture, |cx, volume| {
        replace_in_volume(cx, volume, "/PAYLOAD.BIN", &[0x51; 1024], 1_700_000_000)
    });
    let count = protected.trace.lock().unwrap().barriers.len();
    drop(protected);
    // Cut the initial dirty-state barrier, a publication barrier, and the LAST
    // native barrier (where clean bytes may already be durable). Inject both
    // I/O failure and late cancellation after the underlying sync succeeded.
    for cut in [1, count / 2, count - 1] {
        for failure in [Failure::Io, Failure::Cancel] {
            std::fs::write(&fixture.image, &pristine.0).unwrap();
            std::fs::write(&fixture.sidecar, &pristine.1).unwrap();
            let protected = ProtectedVolume::open(&fixture);
            protected.trace.lock().unwrap().fail_after = Some((cut, failure));
            let cx = Cx::for_testing();
            assert!(
                replace_in_volume(
                    &cx,
                    &protected.volume,
                    "/PAYLOAD.BIN",
                    &[0x51; 1024],
                    1_700_000_000
                )
                .is_err()
            );
            assert_eq!(&archive_state(&fixture.sidecar).0, b"FFSRQPD2");
            let status = protected.protection.ack_status();
            assert!(!status.native_durable && !status.protected_durable);
            assert_eq!(status.epoch_generation, 1);
            assert_eq!(protected.trace.lock().unwrap().holds, 0);
            let before = fixture.snapshot();
            assert!(sync_volume(&Cx::for_testing(), &protected.volume).is_err());
            assert_eq!(
                fixture.snapshot(),
                before,
                "retry sealed an aborted native epoch"
            );
            drop(protected);
            let error =
                SidecarImageDevice::open(&Cx::for_testing(), &fixture.image, &fixture.sidecar)
                    .unwrap_err();
            assert!(error.to_string().contains("unfinished"));
        }
    }
}

#[test]
fn late_cancellation_preserves_native_and_mounted_protection_acknowledgments() {
    const NOW: u64 = 1_700_000_000;
    const REPLACEMENT: &[u8] = b"committed";
    for fixture in [Fixture::new(), Fixture::fat32()] {
        let pristine = fixture.snapshot();
        let protected = ProtectedVolume::open(&fixture);
        protected.committed(&fixture, |cx, volume| {
            write_range_in_volume(cx, volume, "/PAYLOAD.BIN", 0, REPLACEMENT, NOW)
        });
        let count = protected.trace.lock().unwrap().barriers.len();
        drop(protected);
        let mut expected = PAYLOAD.to_vec();
        expected[..REPLACEMENT.len()].copy_from_slice(REPLACEMENT);

        // The final native clean barrier and the following protection barrier
        // both have real trailing cancellation points. The mount keeps the
        // outer hold through cache publication, then seals on a later fsync.
        for cut in [count - 1, count] {
            for mounted in [false, true] {
                std::fs::write(&fixture.image, &pristine.0).unwrap();
                std::fs::write(&fixture.sidecar, &pristine.1).unwrap();
                {
                    let ProtectedVolume {
                        volume,
                        protection,
                        trace,
                    } = ProtectedVolume::open(&fixture);
                    trace.lock().unwrap().cancel_after = Some(cut);
                    let cx = Cx::for_testing();
                    if mounted {
                        let fs =
                            crate::filesystem::FatFs::new_with_mode(&cx, volume, 1000, 1000, true)
                                .unwrap();
                        let mut scope = RequestScope::empty();
                        let ino = fs
                            .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("PAYLOAD.BIN"))
                            .unwrap()
                            .ino;
                        assert_eq!(
                            fs.write(&cx, &mut scope, ino, 0, REPLACEMENT).unwrap() as usize,
                            REPLACEMENT.len()
                        );
                        let status = protection.ack_status();
                        assert!(status.native_durable && !status.protected_durable);
                        assert_eq!(&archive_state(&fixture.sidecar).0, b"FFSRQPD2");
                        let fresh = Cx::for_testing();
                        assert_eq!(fs.read(&fresh, &mut scope, ino, 0, 8192).unwrap(), expected);
                        let native = std::fs::read(&fixture.image).unwrap();
                        fs.fsync(&fresh, &mut scope, ino, 0, false).unwrap();
                        assert_eq!(
                            std::fs::read(&fixture.image).unwrap(),
                            native,
                            "sealing must not replay native writes"
                        );
                    } else {
                        assert_eq!(
                            write_range_in_volume(
                                &cx,
                                &volume,
                                "/PAYLOAD.BIN",
                                0,
                                REPLACEMENT,
                                NOW
                            )
                            .unwrap(),
                            REPLACEMENT.len()
                        );
                        assert_eq!(read_payload(&volume, "/PAYLOAD.BIN"), expected);
                    }
                    assert!(
                        matches!(checkpoint(&cx), Err(FfsError::Cancelled)),
                        "mask must preserve the pending signal"
                    );
                    let trace = trace.lock().unwrap();
                    assert!(
                        trace.cancel_after.is_none(),
                        "the intended cancellation point was reached"
                    );
                    assert_eq!(trace.holds, 0);
                    let (sealed, intermediate) = trace.barriers.split_last().unwrap();
                    assert_eq!(&sealed.0, b"FFSRQSC2");
                    assert!(intermediate.iter().all(|state| &state.0 == b"FFSRQPD2"));
                    let status = protection.ack_status();
                    assert!(status.native_durable && status.protected_durable);
                }
                let fresh = Cx::for_testing();
                assert!(
                    ffs_repair::sidecar::verify(&fresh, &fixture.image, &fixture.sidecar)
                        .unwrap()
                        .is_healthy()
                );
                let reopened = fixture.args().open(&fresh).unwrap();
                assert_eq!(read_payload(&reopened, "/PAYLOAD.BIN"), expected);
                let check = reopened.check(&fresh).unwrap();
                assert!(check.clean && check.complete && check.namespace_complete);
            }
        }
    }
}

#[test]
fn protected_native_commit_survives_seal_failure_without_replaying_the_mutation() {
    for failure in [Failure::Io, Failure::Cancel] {
        let fixture = Fixture::new();
        let protected = ProtectedVolume::open(&fixture);
        protected.trace.lock().unwrap().fail_seal = Some(failure);
        let cx = Cx::for_testing();
        let error = create_in_volume(
            &cx,
            &protected.volume,
            "/COMMIT.BIN",
            b"committed once",
            1_700_000_000,
            false,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("native FAT mutation committed"));
        assert_eq!(
            read_payload(&protected.volume, "/COMMIT.BIN"),
            b"committed once"
        );
        let status = protected.protection.ack_status();
        assert!(status.native_durable && !status.protected_durable);
        assert_eq!(status.epoch_generation, 1);
        assert_eq!(&archive_state(&fixture.sidecar).0, b"FFSRQPD2");
        let bytes = std::fs::read(&fixture.image).unwrap();
        sync_volume(&Cx::for_testing(), &protected.volume).unwrap();
        assert_eq!(std::fs::read(&fixture.image).unwrap(), bytes);
        let status = protected.protection.ack_status();
        assert!(status.native_durable && status.protected_durable);
        assert_eq!(status.epoch_generation, 2);
        drop(protected);
        let reopened = fixture.args().open(&Cx::for_testing()).unwrap();
        assert_eq!(read_payload(&reopened, "/COMMIT.BIN"), b"committed once");
    }
}

#[test]
fn protected_native_writer_respects_the_outer_mount_commit_until_fsync() {
    let fixture = Fixture::new();
    let protected = ProtectedVolume::open(&fixture);
    let cx = Cx::for_testing();
    let fs =
        crate::filesystem::FatFs::new_with_mode(&cx, protected.volume, 1000, 1000, true).unwrap();
    let mut scope = RequestScope::empty();
    let entry = fs
        .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new("PAYLOAD.BIN"))
        .unwrap();
    fs.write(&cx, &mut scope, entry.ino, 0, b"new").unwrap();
    let status = protected.protection.ack_status();
    assert!(status.native_durable && !status.protected_durable);
    assert_eq!(status.epoch_generation, 1);
    assert_eq!(&archive_state(&fixture.sidecar).0, b"FFSRQPD2");
    fs.fsync(&cx, &mut scope, entry.ino, 0, false).unwrap();
    let status = protected.protection.ack_status();
    assert!(status.native_durable && status.protected_durable);
    assert_eq!(status.epoch_generation, 2);
    assert_eq!(fs.read(&cx, &mut scope, entry.ino, 0, 3).unwrap(), b"new");
}
