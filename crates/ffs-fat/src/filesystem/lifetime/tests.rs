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
fn create_open_pins_survive_unlink_until_cancelled_last_release() {
    for kind in ["fat16", "fat32"] {
        let (_directory, args, fs) = fixture(kind);
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        let ops: &dyn FsOps = &fs;
        assert!(ops.requires_stateful_open());
        let free_before = clean(&fs);
        let (attr, first, reply_flags) = ops
            .create_open(
                &cx,
                &mut scope,
                ROOT,
                OsStr::new("CREATED.BIN"),
                0o100_644,
                1000,
                1000,
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
            )
            .unwrap();
        assert_ne!(first, 0);
        assert_eq!(reply_flags, 0);
        let mut contents = vec![b'a'; 2048];
        fs.write(&cx, &mut scope, attr.ino, 0, &contents).unwrap();
        let second = open(&fs, attr.ino);
        assert_ne!(first, second);
        fs.unlink(&cx, &mut scope, ROOT, OsStr::new("CREATED.BIN"))
            .unwrap();
        expect_errno(
            fs.lookup(&cx, &mut scope, ROOT, OsStr::new("CREATED.BIN")),
            libc::ENOENT,
        );
        assert_eq!(fs.getattr(&cx, &mut scope, attr.ino).unwrap().nlink, 0);
        fs.write(&cx, &mut scope, attr.ino, 10, b"changed").unwrap();
        contents[10..17].copy_from_slice(b"changed");
        assert_eq!(read(&fs, attr.ino), contents);
        let replacement = create(&fs, ROOT, "CREATED.BIN", b"new identity");
        assert_ne!(replacement, attr.ino);
        expect_errno(release(&fs, replacement, first), libc::EBADF);
        assert_eq!(read(&fs, attr.ino), contents);

        let cancelled = Cx::for_testing();
        cancelled.set_cancel_requested(true);
        for (index, handle) in [first, second].into_iter().enumerate() {
            let mut cleanup = ops
                .begin_request_scope(&cancelled, ffs_core::vfs::RequestOp::Release)
                .unwrap();
            ops.release(
                &cancelled,
                &mut cleanup,
                ReleaseRequest {
                    ino: attr.ino,
                    fh: handle,
                    flags: libc::O_RDWR,
                    lock_owner: None,
                    flush: false,
                },
            )
            .unwrap();
            ops.end_request_scope(&cancelled, ffs_core::vfs::RequestOp::Release, cleanup)
                .unwrap();
            assert!(
                cancelled.checkpoint().is_err(),
                "cleanup must preserve cancellation"
            );
            if index == 0 {
                assert_eq!(read(&fs, attr.ino), contents);
                assert!(fs.retained(attr.ino).unwrap());
            }
        }
        expect_errno(fs.getattr(&cx, &mut scope, attr.ino), libc::ENOENT);
        expect_errno(release(&fs, attr.ino, second), libc::EBADF);
        assert_eq!(read(&fs, replacement), b"new identity");
        {
            let state = locked(&fs.lifetime).unwrap();
            assert!(state.handles.is_empty());
            assert!(state.counts.is_empty());
            assert!(state.retained.is_empty());
        }
        fs.unlink(&cx, &mut scope, ROOT, OsStr::new("CREATED.BIN"))
            .unwrap();
        assert_eq!(clean(&fs), free_before);
        drop(fs);
        let reopened = mount(&args);
        assert_eq!(clean(&reopened), free_before);
        assert!(
            reopened
                .volume
                .list(&cx, Directory::Root)
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn create_open_preflights_capacity_and_drops_failed_reservations_without_native_changes() {
    for kind in ["fat16", "fat32"] {
        let (_directory, args, fs) = fixture(kind);
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        let ino = create(&fs, ROOT, "KEEP.BIN", b"preserve native data");
        let before = std::fs::read(&args.image).unwrap();
        for (name, mode, flags, expected) in [
            ("NEW.BIN", 0o644, libc::O_ACCMODE, libc::EINVAL),
            ("NEW.BIN", 0o444, libc::O_RDWR, libc::EACCES),
            ("invalid?.txt", 0o644, libc::O_RDWR, libc::EINVAL),
            ("KEEP.BIN", 0o644, libc::O_RDWR, libc::EEXIST),
        ] {
            expect_errno(
                fs.create_open(
                    &cx,
                    &mut scope,
                    ROOT,
                    OsStr::new(name),
                    mode,
                    1000,
                    1000,
                    flags,
                ),
                expected,
            );
            let state = locked(&fs.lifetime).unwrap();
            assert!(state.handles.is_empty());
            assert!(state.counts.is_empty());
        }
        expect_errno(
            fs.open(&cx, &mut scope, ino, libc::O_ACCMODE | libc::O_TRUNC),
            libc::EINVAL,
        );
        locked(&fs.lifetime).unwrap().next_handle = u64::MAX;
        expect_errno(
            fs.create_open(
                &cx,
                &mut scope,
                ROOT,
                OsStr::new("NEW.BIN"),
                0o644,
                1000,
                1000,
                libc::O_RDWR,
            ),
            libc::EOVERFLOW,
        );
        {
            let mut state = locked(&fs.lifetime).unwrap();
            state.next_handle = MAX_HANDLES as u64;
            for handle in 1..=MAX_HANDLES as u64 {
                state.handles.insert(handle, ino);
            }
            state.counts.insert(ino, MAX_HANDLES as u64);
        }
        expect_errno(
            fs.create_open(
                &cx,
                &mut scope,
                ROOT,
                OsStr::new("NEW.BIN"),
                0o644,
                1000,
                1000,
                libc::O_RDWR,
            ),
            libc::EMFILE,
        );
        {
            let mut state = locked(&fs.lifetime).unwrap();
            state.handles.clear();
            state.counts.clear();
        }
        let cancelled = Cx::for_testing();
        cancelled.set_cancel_requested(true);
        expect_errno(
            fs.create_open(
                &cancelled,
                &mut scope,
                ROOT,
                OsStr::new("NEW.BIN"),
                0o644,
                1000,
                1000,
                libc::O_RDWR,
            ),
            libc::EINTR,
        );
        assert_eq!(std::fs::read(&args.image).unwrap(), before);
        assert_eq!(read(&fs, ino), b"preserve native data");
        expect_errno(
            fs.lookup(&cx, &mut scope, ROOT, OsStr::new("NEW.BIN")),
            libc::ENOENT,
        );

        let (attr, handle, _) = fs
            .create_open(
                &cx,
                &mut scope,
                ROOT,
                OsStr::new("READONLY.BIN"),
                0o444,
                1000,
                1000,
                libc::O_RDONLY,
            )
            .unwrap();
        assert_ne!(handle, 0);
        assert_eq!(attr.perm, 0o444);
        assert!(fs.pinned(attr.ino).unwrap());
        release(&fs, attr.ino, handle).unwrap();
        assert!(!fs.pinned(attr.ino).unwrap());
        clean(&fs);
    }
}

#[test]
fn readonly_open_requires_release_and_cancellation_does_not_leak_its_handle() {
    for kind in ["fat16", "fat32"] {
        let (_directory, args, fs) = fixture(kind);
        create(&fs, ROOT, "READ.BIN", b"immutable native data");
        drop(fs);
        let before = std::fs::read(&args.image).unwrap();
        let cx = Cx::for_testing();
        let volume = args.open(&cx).unwrap();
        let fs = FatFs::new(&cx, volume, 1000, 1000).unwrap();
        let ops: &dyn FsOps = &fs;
        assert!(ops.requires_stateful_open());
        let mut scope = RequestScope::empty();
        let ino = ops
            .lookup(&cx, &mut scope, ROOT, OsStr::new("READ.BIN"))
            .unwrap()
            .ino;
        let (handle, _) = ops.open(&cx, &mut scope, ino, libc::O_RDONLY).unwrap();
        assert_ne!(handle, 0);
        let cancelled = Cx::for_testing();
        cancelled.set_cancel_requested(true);
        let mut cleanup = ops
            .begin_request_scope(&cancelled, ffs_core::vfs::RequestOp::Release)
            .unwrap();
        ops.release(
            &cancelled,
            &mut cleanup,
            ReleaseRequest {
                ino,
                fh: handle,
                flags: libc::O_RDONLY,
                lock_owner: None,
                flush: false,
            },
        )
        .unwrap();
        assert!(cancelled.checkpoint().is_err());
        assert!(locked(&fs.lifetime).unwrap().handles.is_empty());
        assert!(locked(&fs.lifetime).unwrap().counts.is_empty());
        assert_eq!(read(&fs, ino), b"immutable native data");
        assert_eq!(std::fs::read(&args.image).unwrap(), before);
    }
}

fn mkdir(fs: &FatFs, parent: InodeNumber, name: &str) -> InodeNumber {
    fs.mkdir(
        &Cx::for_testing(),
        &mut RequestScope::empty(),
        parent,
        OsStr::new(name),
        0o755,
        1000,
        1000,
    )
    .unwrap()
    .ino
}

fn pin_directory(fs: &FatFs, ino: InodeNumber) -> Arc<AtomicU64> {
    // OPENDIR lifetime is represented by the transport's inode-reference
    // oracle, not a regular-file backend open handle.
    let pins = Arc::new(AtomicU64::new(1));
    let live = Arc::clone(&pins);
    fs.install_open_handle_oracle(Arc::new(move |which| {
        if which == ino {
            live.load(Ordering::SeqCst)
        } else {
            0
        }
    }));
    pins
}

fn assert_held_directory(fs: &FatFs, ino: InodeNumber, parent: InodeNumber) {
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let attr = fs.getattr(&cx, &mut scope, ino).unwrap();
    assert_eq!(attr.ino, ino);
    assert_eq!(attr.kind, ffs_core::FileType::Directory);
    assert_eq!(attr.nlink, 0);
    assert!(attr.blocks > 0);
    for (name, expected) in [(".", ino), ("..", parent)] {
        assert_eq!(
            fs.lookup(&cx, &mut scope, ino, OsStr::new(name))
                .unwrap()
                .ino,
            expected
        );
    }
    let entries: Vec<_> = fs
        .readdir(&cx, &mut scope, ino, 0)
        .unwrap()
        .iter()
        .map(|entry| (entry.name.clone(), entry.ino))
        .collect();
    assert_eq!(entries, [(b".".to_vec(), ino), (b"..".to_vec(), parent)]);
    assert!(fs.readdir(&cx, &mut scope, ino, 2).unwrap().is_empty());
}

#[test]
fn removed_directory_keeps_identity_allocation_and_parent_until_last_transport_reference() {
    for kind in ["fat16", "fat32"] {
        let (_directory, args, fs) = fixture(kind);
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        let parent = mkdir(&fs, ROOT, "PARENT");
        let held = mkdir(&fs, parent, "HELD");
        let original = fs.node(&cx, held).unwrap().entry.unwrap();
        let source = create(&fs, ROOT, "SOURCE.BIN", b"unchanged source");
        let pins = pin_directory(&fs, held);
        let free = clean(&fs);
        fs.rmdir(&cx, &mut scope, parent, OsStr::new("HELD"))
            .unwrap();
        assert_held_directory(&fs, held, parent);
        assert_eq!(clean(&fs), free);
        assert_eq!(fs.getattr(&cx, &mut scope, parent).unwrap().nlink, 2);
        expect_errno(
            fs.lookup(&cx, &mut scope, parent, OsStr::new("HELD")),
            libc::ENOENT,
        );
        let hidden = fs.node(&cx, held).unwrap().entry.unwrap().name().unwrap();
        let before = std::fs::read(&args.image).unwrap();
        expect_errno(
            fs.rmdir(&cx, &mut scope, parent, OsStr::new(&hidden)),
            libc::ENOENT,
        );
        expect_errno(
            fs.create(&cx, &mut scope, held, OsStr::new("NEW"), 0o644, 1000, 1000),
            libc::ENOENT,
        );
        expect_errno(
            fs.mkdir(&cx, &mut scope, held, OsStr::new("NEW"), 0o755, 1000, 1000),
            libc::ENOENT,
        );
        expect_errno(
            fs.rename(
                &cx,
                &mut scope,
                ROOT,
                OsStr::new("SOURCE.BIN"),
                held,
                OsStr::new("NEW"),
            ),
            libc::ENOENT,
        );
        expect_errno(
            fs.rename2(
                &cx,
                &mut scope,
                held,
                OsStr::new("NEW"),
                ROOT,
                OsStr::new("SOURCE.BIN"),
                libc::RENAME_EXCHANGE,
            ),
            libc::ENOENT,
        );
        // FAT has no native hard/symbolic links; removed parents cannot
        // acquire children through those unsupported entry points either.
        assert!(
            fs.link(&cx, &mut scope, source, held, OsStr::new("LINK"))
                .is_err()
        );
        assert!(
            fs.symlink(
                &cx,
                &mut scope,
                held,
                OsStr::new("LINK"),
                std::path::Path::new("target"),
                1000,
                1000,
            )
            .is_err()
        );
        assert_eq!(std::fs::read(&args.image).unwrap(), before);
        assert_eq!(read(&fs, source), b"unchanged source");
        let replacement = mkdir(&fs, parent, "HELD");
        assert_ne!(replacement, held);
        assert_ne!(
            fs.node(&cx, replacement)
                .unwrap()
                .entry
                .unwrap()
                .native
                .first_cluster,
            original.native.first_cluster
        );
        fs.rename(
            &cx,
            &mut scope,
            ROOT,
            OsStr::new("PARENT"),
            ROOT,
            OsStr::new("MOVED"),
        )
        .unwrap();
        assert_held_directory(&fs, held, parent);
        fs.fsyncdir(&cx, &mut scope, held, 0, false).unwrap();
        release(&fs, held, 0).unwrap();
        assert!(!fs.finalize_unlinked_inode(&cx, &mut scope, held).unwrap());
        // Metadata through an already-held inode remains supported. Final
        // reclamation must not become a new user rmdir permission decision.
        fs.setattr(
            &cx,
            &mut scope,
            held,
            &SetAttrRequest {
                mode: Some(0o555),
                ..Default::default()
            },
        )
        .unwrap();
        let free = clean(&fs);
        pins.store(0, Ordering::SeqCst);
        assert!(fs.finalize_unlinked_inode(&cx, &mut scope, held).unwrap());
        assert_eq!(clean(&fs), free + 1);
        expect_errno(fs.getattr(&cx, &mut scope, held), libc::ENOENT);
        assert!(!fs.finalize_unlinked_inode(&cx, &mut scope, held).unwrap());
        assert_eq!(
            fs.lookup(&cx, &mut scope, parent, OsStr::new("HELD"))
                .unwrap()
                .ino,
            replacement
        );
    }
}

#[test]
fn overwritten_directory_preserves_original_parent_and_reaps_implicit_parent_pins() {
    for kind in ["fat16", "fat32"] {
        let (_directory, _args, fs) = fixture(kind);
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        let from = mkdir(&fs, ROOT, "FROM");
        let to = mkdir(&fs, ROOT, "TO");
        let source = mkdir(&fs, from, "SOURCE");
        let child = create(&fs, source, "CHILD.BIN", b"source child survives");
        let held = mkdir(&fs, to, "Long destination directory");
        let alias = fs
            .node(&cx, held)
            .unwrap()
            .entry
            .unwrap()
            .short_alias()
            .unwrap();
        let pins = pin_directory(&fs, held);
        let free = clean(&fs);
        fs.rename(
            &cx,
            &mut scope,
            from,
            OsStr::new("SOURCE"),
            to,
            OsStr::new(&alias),
        )
        .unwrap();
        assert_eq!(
            fs.lookup(
                &cx,
                &mut scope,
                to,
                OsStr::new("Long destination directory")
            )
            .unwrap()
            .ino,
            source
        );
        assert_eq!(
            fs.node(&cx, held).unwrap().parent,
            from,
            "native recovery location"
        );
        assert_held_directory(&fs, held, to);
        assert_eq!(fs.getattr(&cx, &mut scope, from).unwrap().nlink, 2);
        assert_eq!(fs.getattr(&cx, &mut scope, to).unwrap().nlink, 3);
        assert_eq!(clean(&fs), free);
        assert_eq!(read(&fs, child), b"source child survives");
        fs.rename(
            &cx,
            &mut scope,
            to,
            OsStr::new("Long destination directory"),
            ROOT,
            OsStr::new("MOVED"),
        )
        .unwrap();
        // TO is physically empty. Its only pin is the displaced directory's
        // logical '..'; final FORGET for TO may precede HELD's final FORGET.
        fs.rmdir(&cx, &mut scope, ROOT, OsStr::new("TO")).unwrap();
        assert_held_directory(&fs, to, ROOT);
        assert_held_directory(&fs, held, to);
        assert!(!fs.finalize_unlinked_inode(&cx, &mut scope, to).unwrap());
        assert_eq!(clean(&fs), free);
        let replacement_parent = mkdir(&fs, ROOT, "TO");
        assert_ne!(replacement_parent, to);
        assert_held_directory(&fs, held, to);
        let free = clean(&fs);
        pins.store(0, Ordering::SeqCst);
        assert!(fs.finalize_unlinked_inode(&cx, &mut scope, held).unwrap());
        assert_eq!(clean(&fs), free + 2, "child and original parent reclaimed");
        expect_errno(fs.getattr(&cx, &mut scope, held), libc::ENOENT);
        expect_errno(fs.getattr(&cx, &mut scope, to), libc::ENOENT);
        assert_eq!(read(&fs, child), b"source child survives");
        fs.rmdir(&cx, &mut scope, ROOT, OsStr::new("FROM")).unwrap();
        assert_eq!(
            fs.lookup(&cx, &mut scope, ROOT, OsStr::new("TO"))
                .unwrap()
                .ino,
            replacement_parent
        );
        clean(&fs);
    }
}

#[test]
fn directory_retention_preflight_refusals_preserve_the_native_namespace() {
    let (_directory, args, fs) = fixture("fat16");
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    mkdir(&fs, ROOT, "SOURCE");
    let held = mkdir(&fs, ROOT, "HELD");
    create(&fs, held, "CHILD.BIN", b"do not remove this child");
    create(&fs, ROOT, "FILE.BIN", b"not a directory");
    let _pins = pin_directory(&fs, held);
    let before = std::fs::read(&args.image).unwrap();
    expect_errno(
        fs.rmdir(&cx, &mut scope, ROOT, OsStr::new("HELD")),
        libc::ENOTEMPTY,
    );
    for (source, destination, error) in [
        ("SOURCE", "HELD", libc::ENOTEMPTY),
        ("FILE.BIN", "HELD", libc::EISDIR),
        ("HELD", "FILE.BIN", libc::ENOTDIR),
    ] {
        expect_errno(
            fs.rename(
                &cx,
                &mut scope,
                ROOT,
                OsStr::new(source),
                ROOT,
                OsStr::new(destination),
            ),
            error,
        );
    }
    let cancelled = Cx::for_testing();
    cancelled.set_cancel_requested(true);
    assert!(
        fs.rmdir(&cancelled, &mut scope, ROOT, OsStr::new("HELD"))
            .is_err()
    );
    assert_eq!(std::fs::read(&args.image).unwrap(), before);
    assert!(locked(&fs.lifetime).unwrap().retained.is_empty());

    fs.unlink(&cx, &mut scope, held, OsStr::new("CHILD.BIN"))
        .unwrap();
    let before = std::fs::read(&args.image).unwrap();
    {
        let mut state = locked(&fs.lifetime).unwrap();
        for index in 0..MAX_RETAINED {
            state.retained.insert(
                InodeNumber(index as u64 + 10),
                Retained {
                    slot: u64::MAX - index as u64,
                    visible_to_handles: false,
                    directory_parent: None,
                },
            );
        }
    }
    expect_errno(
        fs.rmdir(&cx, &mut scope, ROOT, OsStr::new("HELD")),
        libc::ENOSPC,
    );
    expect_errno(
        fs.rename(
            &cx,
            &mut scope,
            ROOT,
            OsStr::new("SOURCE"),
            ROOT,
            OsStr::new("HELD"),
        ),
        libc::ENOSPC,
    );
    assert_eq!(std::fs::read(&args.image).unwrap(), before);
    locked(&fs.lifetime).unwrap().retained.clear();
    fs.setattr(
        &cx,
        &mut scope,
        held,
        &SetAttrRequest {
            mode: Some(0o555),
            ..Default::default()
        },
    )
    .unwrap();
    let before = std::fs::read(&args.image).unwrap();
    expect_errno(
        fs.rmdir(&cx, &mut scope, ROOT, OsStr::new("HELD")),
        libc::EACCES,
    );
    expect_errno(
        fs.rename(
            &cx,
            &mut scope,
            ROOT,
            OsStr::new("SOURCE"),
            ROOT,
            OsStr::new("HELD"),
        ),
        libc::EACCES,
    );
    assert_eq!(std::fs::read(&args.image).unwrap(), before);
    assert_eq!(fs.getattr(&cx, &mut scope, held).unwrap().nlink, 2);
    clean(&fs);
}

#[test]
fn directory_recovery_records_survive_reopen_and_destroy_uses_only_live_ownership() {
    let (_directory, args, fs) = fixture("fat16");
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let ordinary = mkdir(&fs, ROOT, "F0000000.DEL");
    create(&fs, ordinary, "KEEP.BIN", b"ordinary user directory");
    let held = mkdir(&fs, ROOT, "HELD");
    let _pins = pin_directory(&fs, held);
    fs.rmdir(&cx, &mut scope, ROOT, OsStr::new("HELD")).unwrap();
    let recovery = fs.node(&cx, held).unwrap().entry.unwrap().name().unwrap();
    assert_ne!(recovery, "F0000000.DEL");
    clean(&fs);
    // Successful native mutation followed by dropping the mount, not a
    // storage-cut or live kernel-mount qualification claim.
    drop(fs);
    let fs = mount(&args);
    let restored = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new(&recovery))
        .unwrap();
    assert_eq!(restored.nlink, 2);
    fs.flush_on_destroy(&cx).unwrap();
    assert_eq!(fs.getattr(&cx, &mut scope, restored.ino).unwrap().nlink, 2);
    let ordinary = fs
        .lookup(&cx, &mut scope, ROOT, OsStr::new("F0000000.DEL"))
        .unwrap()
        .ino;
    let child = fs
        .lookup(&cx, &mut scope, ordinary, OsStr::new("KEEP.BIN"))
        .unwrap()
        .ino;
    assert_eq!(read(&fs, child), b"ordinary user directory");
    let _pins = pin_directory(&fs, restored.ino);
    fs.rmdir(&cx, &mut scope, ROOT, OsStr::new(&recovery))
        .unwrap();
    let free = clean(&fs);
    fs.flush_on_destroy(&cx).unwrap();
    assert_eq!(clean(&fs), free + 1);
    expect_errno(fs.getattr(&cx, &mut scope, restored.ino), libc::ENOENT);
    assert_eq!(read(&fs, child), b"ordinary user directory");
    assert!(locked(&fs.lifetime).unwrap().retained.is_empty());
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
                    directory_parent: None,
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

fn faulty_fs(bytes: &[u8]) -> (FatFs, FaultDevice) {
    let cx = Cx::for_testing();
    let device = FaultDevice(Arc::new(Mutex::new(FaultState {
        bytes: bytes.to_vec(),
        attempts: 0,
        fail_at: None,
    })));
    let volume =
        FatVolume::from_device(&cx, Box::new(device.clone()), 0, bytes.len() as u64).unwrap();
    let fs = FatFs::new_with_mode(&cx, volume, 1000, 1000, true).unwrap();
    (fs, device)
}

fn faulty(bytes: &[u8]) -> (FatFs, FaultDevice, InodeNumber, u64) {
    let (fs, device) = faulty_fs(bytes);
    let cx = Cx::for_testing();
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
fn every_directory_retention_cut_fences_the_mount_and_keeps_initialized_clusters() {
    let (_directory, args, fs) = fixture("fat16");
    let cx = Cx::for_testing();
    let held = mkdir(&fs, ROOT, "HELD");
    let source = mkdir(&fs, ROOT, "SOURCE");
    let spans: Vec<_> = [held, source]
        .into_iter()
        .map(|ino| {
            let cluster = fs
                .node(&cx, ino)
                .unwrap()
                .entry
                .unwrap()
                .native
                .first_cluster;
            let start = fs.volume.geometry.cluster_offset(cluster).unwrap() as usize;
            start..start + fs.volume.geometry.cluster_bytes() as usize
        })
        .collect();
    drop(fs);
    let baseline = std::fs::read(&args.image).unwrap();
    let prepare = || {
        let (fs, device) = faulty_fs(&baseline);
        let ino = fs
            .lookup(&cx, &mut RequestScope::empty(), ROOT, OsStr::new("HELD"))
            .unwrap()
            .ino;
        let pins = pin_directory(&fs, ino);
        (fs, device, ino, pins)
    };
    for overwrite in [false, true] {
        let remove = |fs: &FatFs| {
            if overwrite {
                fs.rename(
                    &cx,
                    &mut RequestScope::empty(),
                    ROOT,
                    OsStr::new("SOURCE"),
                    ROOT,
                    OsStr::new("HELD"),
                )
            } else {
                fs.rmdir(&cx, &mut RequestScope::empty(), ROOT, OsStr::new("HELD"))
            }
        };
        let (success, device, ino, _pins) = prepare();
        remove(&success).unwrap();
        assert_held_directory(&success, ino, ROOT);
        clean(&success);
        let total = device.0.lock().unwrap().attempts;
        assert!(total > 4);
        for cut in 1..=total {
            let (fs, device, ino, _pins) = prepare();
            device.0.lock().unwrap().fail_at = Some(cut);
            assert!(remove(&fs).is_err(), "overwrite={overwrite}, cut={cut}");
            expect_errno(fs.getattr(&cx, &mut RequestScope::empty(), ino), libc::EIO);
            expect_errno(
                fs.readdir(&cx, &mut RequestScope::empty(), ino, 0),
                libc::EIO,
            );
            expect_errno(
                fs.finalize_unlinked_inode(&cx, &mut RequestScope::empty(), ino),
                libc::EIO,
            );
            let state = device.0.lock().unwrap();
            assert_eq!(state.attempts, cut, "no implicit cleanup after failure");
            for span in &spans {
                assert_eq!(&state.bytes[span.clone()], &baseline[span.clone()]);
            }
        }
        let (fs, device, ino, pins) = prepare();
        remove(&fs).unwrap();
        pins.store(0, Ordering::SeqCst);
        {
            let mut state = device.0.lock().unwrap();
            state.fail_at = Some(state.attempts + 1);
        }
        assert!(
            fs.finalize_unlinked_inode(&cx, &mut RequestScope::empty(), ino)
                .is_err()
        );
        expect_errno(fs.flush_on_destroy(&cx), libc::EIO);
    }
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
