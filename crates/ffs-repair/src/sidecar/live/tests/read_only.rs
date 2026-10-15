//! Exercise the real sidecar codec and real file descriptors. Fault injection
//! deliberately uses an unrelated handle; production callers must remain offline.

use super::*;
use std::os::unix::fs::PermissionsExt;

#[derive(Debug, PartialEq, Eq)]
struct SavedFile {
    bytes: Vec<u8>,
    device: u64,
    inode: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

fn saved(path: &Path) -> SavedFile {
    let bytes = std::fs::read(path).unwrap();
    let metadata = std::fs::metadata(path).unwrap();
    SavedFile {
        bytes,
        device: metadata.dev(),
        inode: metadata.ino(),
        modified: (metadata.mtime(), metadata.mtime_nsec()),
        changed: (metadata.ctime(), metadata.ctime_nsec()),
    }
}

fn open_read_only(fixture: &Fixture) -> SidecarImageDevice {
    SidecarImageDevice::open_read_only(&Cx::for_testing(), &fixture.image, &fixture.sidecar)
        .unwrap()
}

#[test]
fn read_only_descriptors_have_no_write_capability() {
    let fixture = Fixture::new();
    for path in [&fixture.image, &fixture.sidecar] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o444)).unwrap();
    }
    let image = saved(&fixture.image);
    let archive = saved(&fixture.sidecar);
    let device = open_read_only(&fixture);
    // Permissions alone are not proof when tests run as root. These attempts
    // must fail because BOTH descriptors were opened O_RDONLY.
    assert!(device.image.write_all_at(&[0], 0).is_err());
    assert!(device.state.lock().archive.file.write_all_at(&[0], 0).is_err());
    let mut bytes = [0; 90];
    device
        .read_exact_at(&Cx::for_testing(), ByteOffset(500), &mut bytes)
        .unwrap();
    assert_eq!(bytes.as_slice(), &fixture.original[500..590]);
    drop(device);
    assert_eq!(saved(&fixture.image), image);
    assert_eq!(saved(&fixture.sidecar), archive);
}

#[test]
fn read_only_owners_share_locks_but_exclude_writable_owners_and_aliases() {
    let fixture = Fixture::new();
    let alias = fixture.image.with_extension("read-only-alias");
    std::fs::hard_link(&fixture.image, &alias).unwrap();
    let cx = Cx::for_testing();
    let first = open_read_only(&fixture);
    let second = SidecarImageDevice::open_read_only(&cx, &alias, &fixture.sidecar).unwrap();
    assert!(SidecarImageDevice::open(&cx, &fixture.image, &fixture.sidecar).is_err());
    drop(first);
    assert!(SidecarImageDevice::open(&cx, &alias, &fixture.sidecar).is_err());
    drop(second);
    drop(SidecarImageDevice::open(&cx, &fixture.image, &fixture.sidecar).unwrap());
}

#[test]
fn read_only_reconstructs_multiple_groups_and_partial_tail_without_writeback() {
    let fixture = Fixture::new();
    let device = open_read_only(&fixture);
    let cx = Cx::for_testing();
    fixture.damage(512, &[0xab; 512]);
    fixture.damage(5 * 512, &[0xcd; 512]);
    fixture.damage(9 * 512, &[0xef; 512]);
    fixture.damage(16 * 512, &[0xfe; 37]);
    let image = saved(&fixture.image);
    let archive = saved(&fixture.sidecar);
    assert_ne!(image.bytes, fixture.original);
    for _ in 0..2 {
        let mut bytes = vec![0; fixture.original.len()];
        device.read_exact_at(&cx, ByteOffset(0), &mut bytes).unwrap();
        assert_eq!(bytes, fixture.original);
        device.sync(&cx).unwrap();
        assert_eq!(saved(&fixture.image), image);
        assert_eq!(saved(&fixture.sidecar), archive);
    }
    drop(device);
    assert_eq!(saved(&fixture.image), image);
    assert_eq!(saved(&fixture.sidecar), archive);
    // RAM reconstruction did not heal the file or grant a new mount permission
    // to silently roll back a mismatch at admission.
    assert!(SidecarImageDevice::open_read_only(&cx, &fixture.image, &fixture.sidecar).is_err());
}

#[test]
fn read_only_failure_preserves_output_and_every_recoverable_prefix() {
    let fixture = Fixture::new();
    let device = open_read_only(&fixture);
    fixture.damage(512, &[0xab; 512]);
    fixture.damage(8 * 512, &[0xfe; 8 * 512]);
    let image = saved(&fixture.image);
    let archive = saved(&fixture.sidecar);
    let mut bytes = vec![0xa5; fixture.original.len()];
    assert!(
        device
            .read_exact_at(&Cx::for_testing(), ByteOffset(0), &mut bytes)
            .is_err()
    );
    assert!(bytes.iter().all(|byte| *byte == 0xa5));
    assert_eq!(saved(&fixture.image), image);
    assert_eq!(saved(&fixture.sidecar), archive);
}

#[test]
fn read_only_cannot_mutate_or_rebuild_protection_even_with_damaged_parity() {
    let fixture = Fixture::new();
    let device = open_read_only(&fixture);
    let cx = Cx::for_testing();
    fixture.damage_parity(&device, 0, 0);
    let image = saved(&fixture.image);
    let archive = saved(&fixture.sidecar);
    for bytes in [b"".as_slice(), b"replacement".as_slice()] {
        assert!(matches!(
            device.write_all_at(&cx, ByteOffset(0), bytes),
            Err(FfsError::ReadOnly)
        ));
    }
    assert!(matches!(device.scrub(&cx), Err(FfsError::ReadOnly)));
    let mut cursor = ProtectionScrubCursor::default();
    assert!(matches!(
        device.scrub_step(&cx, &mut cursor),
        Err(FfsError::ReadOnly)
    ));
    assert!(cursor.epoch.is_none());
    assert_eq!(cursor.next_group, 0);
    assert_eq!(cursor.report, ProtectionScrubReport::default());
    // The internal publication seam must also refuse before creating a temp
    // archive, fencing, synchronizing, or replacing a path.
    {
        let mut state = device.state.lock();
        assert!(matches!(
            device.refresh(&cx, &mut state),
            Err(FfsError::ReadOnly)
        ));
    }
    device.sync(&cx).unwrap();
    assert_eq!(saved(&fixture.image), image);
    assert_eq!(saved(&fixture.sidecar), archive);
}

#[test]
fn read_only_keeps_admission_generation_and_pending_epoch_refusals() {
    let fixture = Fixture::new();
    fixture.damage(0, &[0x55; 5]);
    let image = saved(&fixture.image);
    let archive = saved(&fixture.sidecar);
    let cx = Cx::for_testing();
    assert!(SidecarImageDevice::open_read_only(&cx, &fixture.image, &fixture.sidecar).is_err());
    assert_eq!(saved(&fixture.image), image);
    assert_eq!(saved(&fixture.sidecar), archive);
    // Release the suite's flock-holder gate before admitting another fixture;
    // a waiting child-process writer must not face recursive reader admission.
    drop(fixture);

    let fixture = Fixture::new();
    let device = fixture.open();
    device.write_all_at(&cx, ByteOffset(0), &[0x41; 10]).unwrap();
    drop(device);
    let image = saved(&fixture.image);
    let archive = saved(&fixture.sidecar);
    let error =
        SidecarImageDevice::open_read_only(&cx, &fixture.image, &fixture.sidecar).unwrap_err();
    assert!(error.to_string().contains("unfinished"));
    assert_eq!(saved(&fixture.image), image);
    assert_eq!(saved(&fixture.sidecar), archive);
}

#[test]
fn read_only_rejects_transplanted_generations_even_after_caching_hashes() {
    let fixture = Fixture::new();
    let (_, record, offset) = alternate_generation(&fixture);
    std::fs::write(&fixture.image, &fixture.original).unwrap();
    let device = open_read_only(&fixture);
    let cx = Cx::for_testing();
    let mut bytes = [0; 512];
    device
        .read_exact_at(&cx, ByteOffset(10 * 512), &mut bytes)
        .unwrap();
    fixture.damage(10 * 512, &[0x83; 512]);
    File::options()
        .write(true)
        .open(&fixture.sidecar)
        .unwrap()
        .write_all_at(&record, offset)
        .unwrap();
    let image = saved(&fixture.image);
    let archive = saved(&fixture.sidecar);
    bytes.fill(0xa5);
    assert!(
        device
            .read_exact_at(&cx, ByteOffset(10 * 512), &mut bytes)
            .is_err()
    );
    assert_eq!(bytes, [0xa5; 512]);
    assert_eq!(saved(&fixture.image), image);
    assert_eq!(saved(&fixture.sidecar), archive);
}

#[test]
fn read_only_cancelled_reads_and_syncs_preserve_evidence() {
    let fixture = Fixture::new();
    let device = open_read_only(&fixture);
    fixture.damage(512, &[0xab; 512]);
    let image = saved(&fixture.image);
    let archive = saved(&fixture.sidecar);
    let cx = Cx::for_testing();
    cx.set_cancel_requested(true);
    let mut bytes = [0xa5; 512];
    assert!(matches!(
        device.read_exact_at(&cx, ByteOffset(512), &mut bytes),
        Err(FfsError::Cancelled)
    ));
    assert!(matches!(device.sync(&cx), Err(FfsError::Cancelled)));
    assert_eq!(bytes, [0xa5; 512]);
    assert_eq!(saved(&fixture.image), image);
    assert_eq!(saved(&fixture.sidecar), archive);
}
