//! Formatter-backed FsOps regressions. These do not claim a kernel FUSE mount.

use super::*;
use crate::filesystem::ROOT;
use crate::reader::{FatVolume, ImageArgs};
use clap::Parser as _;
use ffs_block::ByteDevice;
use ffs_core::vfs::ReleaseRequest;
use ffs_core::{FsOps, RequestScope, SetAttrRequest};
use ffs_ondisk::fat::FatOemCodePage;
use ffs_types::ByteOffset;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

fn fixture(kind: &str) -> (tempfile::TempDir, ImageArgs, FatFs) {
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("lifetime.fat");
    let cli = crate::Cli::try_parse_from([
        "ffs-fat",
        "format",
        image.to_str().unwrap(),
        "--kind",
        kind,
        "--size-mib",
        if kind == "fat16" { "4" } else { "64" },
    ])
    .unwrap();
    let crate::Command::Format { options } = cli.command else {
        panic!("expected formatter");
    };
    let cx = Cx::for_testing();
    crate::formatter::create(&cx, &options).unwrap();
    let args = ImageArgs {
        image,
        offset: 0,
        length: None,
        oem_code_page: FatOemCodePage::Ascii,
        sidecar: None,
    };
    let fs = mount(&args);
    (directory, args, fs)
}

fn mount(args: &ImageArgs) -> FatFs {
    let cx = Cx::for_testing();
    let volume = crate::reader::replacement::open_volume(&cx, args, true).unwrap();
    FatFs::new_with_mode(&cx, volume, 1000, 1000, true).unwrap()
}

fn create(fs: &FatFs, parent: InodeNumber, name: &str, bytes: &[u8]) -> InodeNumber {
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let ino = fs
        .create(&cx, &mut scope, parent, OsStr::new(name), 0o644, 1000, 1000)
        .unwrap()
        .ino;
    fs.write(&cx, &mut scope, ino, 0, bytes).unwrap();
    ino
}

fn open(fs: &FatFs, ino: InodeNumber) -> u64 {
    fs.open(
        &Cx::for_testing(),
        &mut RequestScope::empty(),
        ino,
        libc::O_RDWR,
    )
    .unwrap()
    .0
}

fn release(fs: &FatFs, ino: InodeNumber, fh: u64) -> Result<()> {
    fs.release(
        &Cx::for_testing(),
        &mut RequestScope::empty(),
        ReleaseRequest {
            ino,
            fh,
            flags: libc::O_RDWR,
            lock_owner: None,
            flush: false,
        },
    )
}

fn read(fs: &FatFs, ino: InodeNumber) -> Vec<u8> {
    fs.read(
        &Cx::for_testing(),
        &mut RequestScope::empty(),
        ino,
        0,
        16_384,
    )
    .unwrap()
}

fn clean(fs: &FatFs) -> u64 {
    let check = fs.volume.check(&Cx::for_testing()).unwrap();
    assert!(
        check.clean && check.complete && check.namespace_complete,
        "{check:?}"
    );
    assert_eq!(check.lost_clusters, Some(0));
    check.free_clusters
}

fn expect_errno<T>(result: Result<T>, expected: i32) {
    assert_eq!(result.err().expect("expected refusal").to_errno(), expected);
}

#[test]
fn unlinked_file_survives_two_handles_and_all_native_data_mutations_until_last_close() {
    for kind in ["fat16", "fat32"] {
        let (_directory, _args, fs) = fixture(kind);
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        let old = create(&fs, ROOT, "OPEN.BIN", b"original");
        let first = open(&fs, old);
        let second = open(&fs, old);
        assert_ne!(first, second);
        assert_ne!(first, 0);
        let free = clean(&fs);
        fs.unlink(&cx, &mut scope, ROOT, OsStr::new("OPEN.BIN"))
            .unwrap();
        expect_errno(
            fs.lookup(&cx, &mut scope, ROOT, OsStr::new("open.bin")),
            libc::ENOENT,
        );
        assert_eq!(clean(&fs), free, "unlink must not reclaim live allocation");
        assert_eq!(fs.getattr(&cx, &mut scope, old).unwrap().nlink, 0);
        assert_eq!(read(&fs, old), b"original");
        let new = create(&fs, ROOT, "OPEN.BIN", b"replacement");
        assert_ne!(new, old);
        fs.write(&cx, &mut scope, old, 12, b"tail").unwrap();
        assert_eq!(read(&fs, old), b"original\0\0\0\0tail");
        fs.fallocate(&cx, &mut scope, old, 0, 8192, libc::FALLOC_FL_KEEP_SIZE)
            .unwrap();
        assert_eq!(fs.getattr(&cx, &mut scope, old).unwrap().size, 16);
        fs.setattr(
            &cx,
            &mut scope,
            old,
            &SetAttrRequest {
                size: Some(3),
                ..Default::default()
            },
        )
        .unwrap();
        fs.setattr(
            &cx,
            &mut scope,
            old,
            &SetAttrRequest {
                size: Some(20),
                ..Default::default()
            },
        )
        .unwrap();
        let mut expected = b"ori".to_vec();
        expected.resize(20, 0);
        assert_eq!(read(&fs, old), expected);
        assert_eq!(
            fs.copy_file_range(&cx, &mut scope, new, 0, old, 4, 5)
                .unwrap(),
            5
        );
        expected[4..9].copy_from_slice(b"repla");
        assert_eq!(read(&fs, old), expected);
        assert_eq!(read(&fs, new), b"replacement");
        fs.fsync(&cx, &mut scope, old, first, false).unwrap();
        let free = clean(&fs);
        release(&fs, old, first).unwrap();
        assert_eq!(clean(&fs), free);
        assert_eq!(read(&fs, old), expected);
        assert!(!fs.finalize_unlinked_inode(&cx, &mut scope, old).unwrap());
        let blocks = fs.getattr(&cx, &mut scope, old).unwrap().blocks;
        release(&fs, old, second).unwrap();
        expect_errno(fs.getattr(&cx, &mut scope, old), libc::ENOENT);
        let cluster_sectors = u64::from(fs.volume.geometry.cluster_bytes()) / 512;
        assert_eq!(clean(&fs), free + blocks / cluster_sectors);
        assert!(!fs.finalize_unlinked_inode(&cx, &mut scope, old).unwrap());
        assert_eq!(read(&fs, new), b"replacement");
    }
}

#[test]
fn transport_pins_outlive_backend_release_and_unknown_handles_cannot_unpin_another_inode() {
    let (_directory, _args, fs) = fixture("fat16");
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let old = create(&fs, ROOT, "HELD.BIN", b"held");
    let other = create(&fs, ROOT, "OTHER.BIN", b"other");
    let pins = Arc::new(AtomicU64::new(1));
    let live = Arc::clone(&pins);
    fs.install_open_handle_oracle(Arc::new(move |ino| {
        if ino == old {
            live.load(Ordering::SeqCst)
        } else {
            0
        }
    }));
    let handle = open(&fs, old);
    expect_errno(release(&fs, other, handle), libc::EBADF);
    fs.unlink(&cx, &mut scope, ROOT, OsStr::new("HELD.BIN"))
        .unwrap();
    release(&fs, old, handle).unwrap();
    let free = clean(&fs);
    assert!(!fs.finalize_unlinked_inode(&cx, &mut scope, old).unwrap());
    assert_eq!(read(&fs, old), b"held");
    // A second installation cannot discard the first transport's outstanding pins.
    fs.install_open_handle_oracle(Arc::new(|_| 0));
    assert!(!fs.finalize_unlinked_inode(&cx, &mut scope, old).unwrap());
    pins.store(0, Ordering::SeqCst);
    assert!(fs.finalize_unlinked_inode(&cx, &mut scope, old).unwrap());
    assert!(clean(&fs) > free);
    assert!(!fs.finalize_unlinked_inode(&cx, &mut scope, old).unwrap());
    assert_eq!(read(&fs, other), b"other");
}

#[test]
fn oracle_only_create_lifetime_is_retained_even_without_a_backend_open() {
    let (_directory, _args, fs) = fixture("fat16");
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let ino = create(&fs, ROOT, "CREATE.BIN", b"create response pins this object");
    let pins = Arc::new(AtomicU64::new(1));
    let live = Arc::clone(&pins);
    fs.install_open_handle_oracle(Arc::new(move |which| {
        if which == ino {
            live.load(Ordering::SeqCst)
        } else {
            0
        }
    }));
    fs.unlink(&cx, &mut scope, ROOT, OsStr::new("CREATE.BIN"))
        .unwrap();
    release(&fs, ino, 0).unwrap();
    assert_eq!(read(&fs, ino), b"create response pins this object");
    pins.store(0, Ordering::SeqCst);
    assert!(fs.finalize_unlinked_inode(&cx, &mut scope, ino).unwrap());
    clean(&fs);
}

#[test]
fn recovery_records_are_unreachable_by_public_names_and_cannot_be_clobbered() {
    let (_directory, args, fs) = fixture("fat16");
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let existing = create(&fs, ROOT, "F0000000.DEL", b"real user file");
    let held = create(
        &fs,
        ROOT,
        "Detailed long original name.bin",
        b"retained data",
    );
    let handle = open(&fs, held);
    fs.unlink(
        &cx,
        &mut scope,
        ROOT,
        OsStr::new("Detailed long original name.bin"),
    )
    .unwrap();
    let recovery = fs.node(&cx, held).unwrap().entry.unwrap();
    assert_ne!(recovery.name().unwrap(), "F0000000.DEL");
    let intruder = create(&fs, ROOT, "INTRUDER.BIN", b"must not replace retained data");
    let before = std::fs::read(&args.image).unwrap();
    let hidden = recovery.name().unwrap();
    for name in [
        hidden.clone(),
        hidden.to_ascii_lowercase(),
        recovery.short_alias().unwrap(),
    ] {
        expect_errno(
            fs.lookup(&cx, &mut scope, ROOT, OsStr::new(&name)),
            libc::ENOENT,
        );
        expect_errno(
            fs.unlink(&cx, &mut scope, ROOT, OsStr::new(&name)),
            libc::ENOENT,
        );
        expect_errno(
            fs.rename(
                &cx,
                &mut scope,
                ROOT,
                OsStr::new("INTRUDER.BIN"),
                ROOT,
                OsStr::new(&name),
            ),
            libc::EEXIST,
        );
        expect_errno(
            fs.rename2(
                &cx,
                &mut scope,
                ROOT,
                OsStr::new("INTRUDER.BIN"),
                ROOT,
                OsStr::new(&name),
                libc::RENAME_EXCHANGE,
            ),
            libc::ENOENT,
        );
        assert!(
            fs.create(&cx, &mut scope, ROOT, OsStr::new(&name), 0o644, 1000, 1000)
                .is_err()
        );
    }
    let page = fs.readdir(&cx, &mut scope, ROOT, 0).unwrap();
    assert!(!page.iter().any(|entry| entry.ino == held));
    assert!(page.iter().any(|entry| entry.ino == existing));
    assert_eq!(std::fs::read(&args.image).unwrap(), before);
    assert_eq!(read(&fs, held), b"retained data");
    assert_eq!(read(&fs, intruder), b"must not replace retained data");
    release(&fs, held, handle).unwrap();
    assert_eq!(read(&fs, existing), b"real user file");
    clean(&fs);
}

#[test]
fn pinned_rename_overwrite_preserves_both_objects_across_directories_and_aliases() {
    for kind in ["fat16", "fat32"] {
        let (_directory, _args, fs) = fixture(kind);
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        let parent = fs
            .mkdir(
                &cx,
                &mut scope,
                ROOT,
                OsStr::new("PARENT"),
                0o755,
                1000,
                1000,
            )
            .unwrap()
            .ino;
        let source = create(&fs, parent, "SOURCE.BIN", b"new version");
        let target = create(&fs, ROOT, "Long destination name.bin", b"old version");
        let alias = fs
            .node(&cx, target)
            .unwrap()
            .entry
            .unwrap()
            .short_alias()
            .unwrap();
        let handle = open(&fs, target);
        let free = clean(&fs);
        fs.rename(
            &cx,
            &mut scope,
            parent,
            OsStr::new("SOURCE.BIN"),
            ROOT,
            OsStr::new(&alias),
        )
        .unwrap();
        assert_eq!(
            fs.lookup(
                &cx,
                &mut scope,
                ROOT,
                OsStr::new("Long destination name.bin")
            )
            .unwrap()
            .ino,
            source
        );
        expect_errno(
            fs.lookup(&cx, &mut scope, parent, OsStr::new("SOURCE.BIN")),
            libc::ENOENT,
        );
        assert_eq!(read(&fs, source), b"new version");
        assert_eq!(read(&fs, target), b"old version");
        assert_eq!(fs.getattr(&cx, &mut scope, target).unwrap().nlink, 0);
        assert_eq!(clean(&fs), free);
        fs.write(&cx, &mut scope, target, 0, b"OLD").unwrap();
        assert_eq!(read(&fs, source), b"new version");
        assert_eq!(read(&fs, target), b"OLD version");
        release(&fs, target, handle).unwrap();
        assert_eq!(read(&fs, source), b"new version");
        assert!(clean(&fs) > free);
        fs.rmdir(&cx, &mut scope, ROOT, OsStr::new("PARENT"))
            .unwrap();
    }
}

#[test]
fn full_fat16_root_and_data_area_still_allow_pinned_overwrite_without_temporary_space() {
    let (_directory, _args, fs) = fixture("fat16");
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let source = create(&fs, ROOT, "SOURCE.BIN", b"source");
    let target = create(&fs, ROOT, "TARGET.BIN", b"target");
    let filler = create(&fs, ROOT, "FILLER.BIN", &[]);
    let free = clean(&fs);
    let cluster = u64::from(fs.volume.geometry.cluster_bytes());
    fs.fallocate(&cx, &mut scope, filler, 0, free * cluster, 0)
        .unwrap();
    assert_eq!(clean(&fs), 0);
    let mut full = false;
    for number in 0..1024 {
        let name = format!("N{number:07}.B");
        match fs.create(&cx, &mut scope, ROOT, OsStr::new(&name), 0o644, 1000, 1000) {
            Ok(_) => {}
            Err(error) => {
                assert!(
                    error.to_string().contains("full FAT16 fixed root"),
                    "{error}"
                );
                full = true;
                break;
            }
        }
    }
    assert!(full);
    assert!(
        fs.create(
            &cx,
            &mut scope,
            ROOT,
            OsStr::new("NOSLOT.BIN"),
            0o644,
            1000,
            1000
        )
        .is_err()
    );
    let handle = open(&fs, target);
    fs.rename(
        &cx,
        &mut scope,
        ROOT,
        OsStr::new("SOURCE.BIN"),
        ROOT,
        OsStr::new("TARGET.BIN"),
    )
    .unwrap();
    assert_eq!(read(&fs, target), b"target");
    assert_eq!(read(&fs, source), b"source");
    assert_eq!(clean(&fs), 0);
    // Explicit profile limit: a retained recovery record still reserves a slot.
    assert!(
        fs.create(
            &cx,
            &mut scope,
            ROOT,
            OsStr::new("NOSLOT.BIN"),
            0o644,
            1000,
            1000
        )
        .is_err()
    );
    release(&fs, target, handle).unwrap();
    assert_eq!(clean(&fs), 1);
    let reused = create(&fs, ROOT, "SOURCE.BIN", b"new owner");
    assert_ne!(reused, target);
    assert_eq!(read(&fs, reused), b"new owner");
    assert_eq!(read(&fs, source), b"source");
    let held = open(&fs, reused);
    fs.unlink(&cx, &mut scope, ROOT, OsStr::new("SOURCE.BIN"))
        .unwrap();
    assert_eq!(read(&fs, reused), b"new owner");
    assert_eq!(clean(&fs), 0);
    release(&fs, reused, held).unwrap();
    assert_eq!(clean(&fs), 1);
}

#[test]
fn retained_children_follow_parent_rename_and_readonly_metadata_does_not_prevent_last_close() {
    let (_directory, _args, fs) = fixture("fat16");
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let parent = fs
        .mkdir(&cx, &mut scope, ROOT, OsStr::new("OLD"), 0o755, 1000, 1000)
        .unwrap()
        .ino;
    let child = create(&fs, parent, "CHILD.BIN", b"retained");
    let handle = open(&fs, child);
    fs.unlink(&cx, &mut scope, parent, OsStr::new("CHILD.BIN"))
        .unwrap();
    assert_eq!(fs.readdir(&cx, &mut scope, parent, 0).unwrap().len(), 2);
    // Physical-parent lifetime is an explicit limit of this native-record profile.
    expect_errno(
        fs.rmdir(&cx, &mut scope, ROOT, OsStr::new("OLD")),
        libc::ENOTEMPTY,
    );
    fs.rename(
        &cx,
        &mut scope,
        ROOT,
        OsStr::new("OLD"),
        ROOT,
        OsStr::new("MOVED"),
    )
    .unwrap();
    fs.write(&cx, &mut scope, child, 8, b" after move").unwrap();
    assert_eq!(read(&fs, child), b"retained after move");
    fs.setattr(
        &cx,
        &mut scope,
        child,
        &SetAttrRequest {
            mode: Some(0o444),
            ..Default::default()
        },
    )
    .unwrap();
    release(&fs, child, handle).unwrap();
    fs.rmdir(&cx, &mut scope, ROOT, OsStr::new("MOVED"))
        .unwrap();
    clean(&fs);
}

#[test]
fn abrupt_mount_drop_keeps_exact_recovery_records_and_new_mount_never_autodeletes_by_prefix() {
    let (_directory, args, fs) = fixture("fat16");
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    create(&fs, ROOT, "F0000000.DEL", b"unrelated user data");
    let ino = create(&fs, ROOT, "LOSTNAME.BIN", b"acknowledged contents");
    open(&fs, ino);
    fs.unlink(&cx, &mut scope, ROOT, OsStr::new("LOSTNAME.BIN"))
        .unwrap();
    fs.write(&cx, &mut scope, ino, 21, b" retained").unwrap();
    let payload = read(&fs, ino);
    let recovery = fs.node(&cx, ino).unwrap().entry.unwrap().name().unwrap();
    clean(&fs);
    // Drop without the transport's orderly destroy callback. Native mutation
    // itself was successful and synchronized; this is not a storage-cut model.
    drop(fs);
    let fs = mount(&args);
    let restored = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new(&recovery))
        .unwrap();
    assert_eq!(restored.nlink, 1);
    assert_eq!(read(&fs, restored.ino), payload);
    let ordinary = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new("F0000000.DEL"))
        .unwrap();
    assert_eq!(read(&fs, ordinary.ino), b"unrelated user data");
    fs.flush_on_destroy(&cx).unwrap();
    assert_eq!(read(&fs, restored.ino), payload);
    clean(&fs);
}

#[test]
fn orderly_destroy_reclaims_only_records_created_by_this_mount() {
    let (_directory, _args, fs) = fixture("fat16");
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let ordinary = create(&fs, ROOT, "F0000000.DEL", b"keep");
    for name in ["A.BIN", "B.BIN"] {
        let ino = create(&fs, ROOT, name, b"temporary");
        open(&fs, ino);
        fs.unlink(&cx, &mut scope, ROOT, OsStr::new(name)).unwrap();
    }
    let free = clean(&fs);
    fs.flush_on_destroy(&cx).unwrap();
    assert_eq!(clean(&fs), free + 2);
    assert_eq!(read(&fs, ordinary), b"keep");
    assert!(locked(&fs.lifetime).unwrap().retained.is_empty());
}

#[test]
fn handle_and_retention_capacity_refuse_before_destructive_operations() {
    let (_directory, args, fs) = fixture("fat16");
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let ino = create(&fs, ROOT, "KEEP.BIN", b"must survive O_TRUNC refusal");
    let before = std::fs::read(&args.image).unwrap();
    locked(&fs.lifetime).unwrap().next_handle = u64::MAX;
    expect_errno(
        fs.open(&cx, &mut scope, ino, libc::O_RDWR | libc::O_TRUNC),
        libc::EOVERFLOW,
    );
    assert_eq!(std::fs::read(&args.image).unwrap(), before);
    locked(&fs.lifetime).unwrap().next_handle = 0;
    {
        let _reservation = fs.reserve_open(ino).unwrap();
    }
    assert!(!fs.pinned(ino).unwrap(), "failed open must drop its pin");
    let handle = open(&fs, ino);
    {
        let mut state = locked(&fs.lifetime).unwrap();
        for index in 0..MAX_RETAINED {
            state.retained.insert(
                InodeNumber(index as u64 + 10),
                Retained {
                    slot: u64::MAX - index as u64,
                    visible_to_handles: false,
                },
            );
        }
    }
    expect_errno(
        fs.unlink(&cx, &mut scope, ROOT, OsStr::new("KEEP.BIN")),
        libc::ENOSPC,
    );
    assert_eq!(std::fs::read(&args.image).unwrap(), before);
    assert_eq!(read(&fs, ino), b"must survive O_TRUNC refusal");
    locked(&fs.lifetime).unwrap().retained.clear();
    release(&fs, ino, handle).unwrap();
    fs.unlink(&cx, &mut scope, ROOT, OsStr::new("KEEP.BIN"))
        .unwrap();
    clean(&fs);
}

#[derive(Clone)]
struct FaultDevice(Arc<Mutex<FaultState>>);
struct FaultState {
    bytes: Vec<u8>,
    attempts: usize,
    fail_at: Option<usize>,
}
impl ByteDevice for FaultDevice {
    fn len_bytes(&self) -> u64 {
        self.0.lock().unwrap().bytes.len() as u64
    }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, out: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        let state = self.0.lock().unwrap();
        let at = usize::try_from(at.0).unwrap();
        out.copy_from_slice(&state.bytes[at..at + out.len()]);
        Ok(())
    }
    fn write_all_at(&self, cx: &Cx, at: ByteOffset, data: &[u8]) -> Result<()> {
        checkpoint(cx)?;
        let mut state = self.0.lock().unwrap();
        state.attempts += 1;
        let fail = state.fail_at == Some(state.attempts);
        let count = if fail { data.len().min(17) } else { data.len() };
        let at = usize::try_from(at.0).unwrap();
        state.bytes[at..at + count].copy_from_slice(&data[..count]);
        if fail {
            return Err(std::io::Error::other("injected retention write failure").into());
        }
        Ok(())
    }
    fn sync(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        let mut state = self.0.lock().unwrap();
        state.attempts += 1;
        if state.fail_at == Some(state.attempts) {
            return Err(std::io::Error::other("injected retention sync failure").into());
        }
        Ok(())
    }
}

fn faulty(bytes: &[u8]) -> (FatFs, FaultDevice, InodeNumber, u64) {
    let cx = Cx::for_testing();
    let device = FaultDevice(Arc::new(Mutex::new(FaultState {
        bytes: bytes.to_vec(),
        attempts: 0,
        fail_at: None,
    })));
    let volume =
        FatVolume::from_device(&cx, Box::new(device.clone()), 0, bytes.len() as u64).unwrap();
    let fs = FatFs::new_with_mode(&cx, volume, 1000, 1000, true).unwrap();
    let ino = fs
        .lookup(
            &cx,
            &mut RequestScope::empty(),
            ROOT,
            OsStr::new("HELD.BIN"),
        )
        .unwrap()
        .ino;
    let handle = open(&fs, ino);
    (fs, device, ino, handle)
}

#[test]
fn every_retention_write_or_sync_failure_fences_cached_reads_and_preserves_payload_storage() {
    let (_directory, args, fs) = fixture("fat16");
    let payload = vec![0xA7; 1033];
    let ino = create(&fs, ROOT, "HELD.BIN", &payload);
    let entry = fs.node(&Cx::for_testing(), ino).unwrap().entry.unwrap();
    let chain = fs.volume.file_chain(&Cx::for_testing(), &entry).unwrap();
    let geometry = fs.volume.geometry.clone();
    drop(fs);
    let baseline = std::fs::read(&args.image).unwrap();
    let cx = Cx::for_testing();
    let (success, device, _, _) = faulty(&baseline);
    success
        .unlink(
            &cx,
            &mut RequestScope::empty(),
            ROOT,
            OsStr::new("HELD.BIN"),
        )
        .unwrap();
    let total = device.0.lock().unwrap().attempts;
    assert!(total > 4);
    for cut in 1..=total {
        let (fs, device, ino, _) = faulty(&baseline);
        assert_eq!(read(&fs, ino), payload); // populate the chain cache before failure
        device.0.lock().unwrap().fail_at = Some(cut);
        assert!(
            fs.unlink(
                &cx,
                &mut RequestScope::empty(),
                ROOT,
                OsStr::new("HELD.BIN")
            )
            .is_err()
        );
        expect_errno(
            fs.read(&cx, &mut RequestScope::empty(), ino, 0, 16),
            libc::EIO,
        );
        expect_errno(
            fs.fsync(&cx, &mut RequestScope::empty(), ino, 0, false),
            libc::EIO,
        );
        let state = device.0.lock().unwrap();
        assert_eq!(state.attempts, cut, "no implicit cleanup writes");
        for &cluster in &chain.clusters {
            let at = geometry.cluster_offset(cluster).unwrap() as usize;
            let end = at + geometry.cluster_bytes() as usize;
            assert_eq!(&state.bytes[at..end], &baseline[at..end]);
        }
    }
}

#[test]
fn final_reclamation_failure_and_preflight_cancellation_never_report_success() {
    let (_directory, args, fs) = fixture("fat16");
    create(&fs, ROOT, "HELD.BIN", b"payload");
    drop(fs);
    let baseline = std::fs::read(&args.image).unwrap();
    let cx = Cx::for_testing();
    let (fs, device, ino, handle) = faulty(&baseline);
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    assert!(
        fs.unlink(
            &cancelled,
            &mut RequestScope::empty(),
            ROOT,
            OsStr::new("HELD.BIN")
        )
        .is_err()
    );
    assert_eq!(device.0.lock().unwrap().attempts, 0);
    assert_eq!(read(&fs, ino), b"payload");
    fs.unlink(
        &cx,
        &mut RequestScope::empty(),
        ROOT,
        OsStr::new("HELD.BIN"),
    )
    .unwrap();
    {
        let mut state = device.0.lock().unwrap();
        state.fail_at = Some(state.attempts + 1);
    }
    assert!(release(&fs, ino, handle).is_err());
    expect_errno(fs.flush_on_destroy(&cx), libc::EIO);
    expect_errno(fs.getattr(&cx, &mut RequestScope::empty(), ino), libc::EIO);
}
