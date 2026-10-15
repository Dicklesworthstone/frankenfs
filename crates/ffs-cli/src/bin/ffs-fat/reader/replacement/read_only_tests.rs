//! End-to-end admission, native FAT reads and real dry-run writer preflight.
//! The handcrafted FAT16 volume is surrounded by unrelated partition sentinels.

use super::*;
use ffs_core::{FsOps, RequestScope};
use ffs_ondisk::fat::FatOemCodePage;
use ffs_types::InodeNumber;
use std::ffi::OsStr;

const VOLUME_BYTES: usize = 8192 * 512;
const VOLUME_BASE: u64 = 512;
const ROOT_OFFSET: usize = 65 * 512;
const DATA_OFFSET: usize = 97 * 512;
const PAYLOAD: &[u8] = b"Native FAT16 protected reads must never need permission to modify the backing image.";

struct Fixture {
    _directory: tempfile::TempDir,
    image: PathBuf,
    sidecar: PathBuf,
    source: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let image = directory.path().join("partitioned-fat16.img");
        let sidecar = directory.path().join("partitioned-fat16.ffsrq");
        let source = directory.path().join("replacement.bin");
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
        }
    }

    fn args(&self) -> ImageArgs {
        ImageArgs {
            image: self.image.clone(),
            offset: VOLUME_BASE,
            length: Some(VOLUME_BYTES as u64),
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
    assert!(before.0[VOLUME_BYTES + 512..].iter().all(|byte| *byte == 0xb9));
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
