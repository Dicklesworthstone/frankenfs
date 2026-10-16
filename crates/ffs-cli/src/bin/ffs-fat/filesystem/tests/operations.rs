//! Native formatter-backed allocation and conditional-rename FsOps regressions.
//! These exercise the production native engine, not a second test allocator.

use super::*;

fn writable_fat(kind: &str) -> (tempfile::TempDir, FatFs) {
    if kind == "fat16" {
        return writable_fat16();
    }
    use clap::Parser as _;

    assert_eq!(kind, "fat32");
    let cx = Cx::for_testing();
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("volume.fat");
    let cli = crate::Cli::try_parse_from([
        "ffs-fat", "format", image.to_str().unwrap(),
        "--kind", "fat32", "--size-mib", "64",
    ]).unwrap();
    let crate::Command::Format { options } = cli.command else {
        panic!("expected formatter options");
    };
    crate::formatter::create(&cx, &options).unwrap();
    let args = crate::reader::ImageArgs {
        image,
        offset: 0,
        length: None,
        oem_code_page: ffs_ondisk::fat::FatOemCodePage::Ascii,
        sidecar: None,
    };
    let volume = crate::reader::replacement::open_volume(&cx, &args, true).unwrap();
    let fs = FatFs::new_with_mode(&cx, volume, 1000, 1000, true).unwrap();
    (directory, fs)
}

fn expect_errno<T>(result: Result<T>, errno: i32) {
    match result {
        Ok(_) => panic!("expected errno {errno}"),
        Err(error) => assert_eq!(error.to_errno(), errno, "{error}"),
    }
}

fn raw_image(directory: &tempfile::TempDir) -> Vec<u8> {
    std::fs::read(directory.path().join("volume.fat")).unwrap()
}

#[test]
fn fallocate_grows_dense_native_allocation_and_preserves_existing_payload() {
    for kind in ["fat16", "fat32"] {
        let (directory, fs) = writable_fat(kind);
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        let ino = create_file(&fs, "ALLOC.BIN");
        let original = vec![0x93; 701];
        fs.write(&cx, &mut scope, ino, 0, &original).unwrap();
        let before = fs.volume.file_chain(
            &cx, &fs.volume.resolve(&cx, "/ALLOC.BIN").unwrap().unwrap(),
        ).unwrap();
        let free_before = fs.statfs(&cx, &mut scope, ROOT).unwrap().blocks_free;
        let end = 4096 + 1033;
        let ops: &dyn FsOps = &fs;
        ops.fallocate(&cx, &mut scope, ino, 4096, 1033, 0).unwrap();
        let attr = ops.getattr(&cx, &mut scope, ino).unwrap();
        assert_eq!(attr.size, end);
        let mut expected = original;
        expected.resize(end as usize, 0);
        assert_eq!(ops.read(&cx, &mut scope, ino, 0, end as u32).unwrap(), expected);
        let after = fs.volume.file_chain(
            &cx, &fs.volume.resolve(&cx, "/ALLOC.BIN").unwrap().unwrap(),
        ).unwrap();
        assert_eq!(&after.clusters[..before.clusters.len()], &before.clusters);
        let required = end.div_ceil(u64::from(fs.volume.geometry.cluster_bytes()));
        assert_eq!(after.clusters.len() as u64, required);
        assert_eq!(
            free_before - ops.statfs(&cx, &mut scope, ROOT).unwrap().blocks_free,
            required - before.clusters.len() as u64,
        );
        // A covered subrange neither shrinks nor rewrites payload/metadata.
        let image_before = raw_image(&directory);
        ops.fallocate(&cx, &mut scope, ino, 77, 64, 0).unwrap();
        ops.fallocate(&cx, &mut scope, ino, 0, end, 0).unwrap();
        assert_eq!(raw_image(&directory), image_before);
        assert_eq!(ops.getattr(&cx, &mut scope, ino).unwrap(), attr);
        let check = fs.volume.check(&cx).unwrap();
        assert!(check.clean && check.complete && check.namespace_complete);
    }
}

#[test]
fn writes_within_preallocated_file_need_no_additional_native_clusters() {
    for kind in ["fat16", "fat32"] {
        let (_directory, fs) = writable_fat(kind);
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        let ino = create_file(&fs, "RESERVED.BIN");
        fs.fallocate(&cx, &mut scope, ino, 0, 8193, 0).unwrap();
        let free = fs.statfs(&cx, &mut scope, ROOT).unwrap().blocks_free;
        let payload = vec![0x6D; 4097];
        fs.write(&cx, &mut scope, ino, 2047, &payload).unwrap();
        assert_eq!(fs.statfs(&cx, &mut scope, ROOT).unwrap().blocks_free, free);
        assert_eq!(fs.getattr(&cx, &mut scope, ino).unwrap().size, 8193);
        let mut expected = vec![0; 8193];
        expected[2047..6144].copy_from_slice(&payload);
        assert_eq!(fs.read(&cx, &mut scope, ino, 0, 8193).unwrap(), expected);
        assert!(fs.volume.check(&cx).unwrap().clean);
    }
}

#[test]
fn fallocate_invalid_ranges_and_unsupported_modes_are_byte_preserving() {
    for kind in ["fat16", "fat32"] {
        let (directory, fs) = writable_fat(kind);
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        let ino = create_file(&fs, "KEEP.BIN");
        fs.write(&cx, &mut scope, ino, 0, b"unchanged").unwrap();
        let image_before = raw_image(&directory);
        for (offset, length, mode, errno) in [
            (0, 0, 0, libc::EINVAL),
            (u64::MAX, 2, 0, libc::EFBIG),
            (u64::from(u32::MAX), 1, 0, libc::EFBIG),
            (0, u64::from(u32::MAX) + 1, 0, libc::EFBIG),
            (0, 4096, libc::FALLOC_FL_PUNCH_HOLE | libc::FALLOC_FL_KEEP_SIZE, libc::EOPNOTSUPP),
            (0, 4096, libc::FALLOC_FL_ZERO_RANGE, libc::EOPNOTSUPP),
            (0, 4096, -1, libc::EOPNOTSUPP),
        ] {
            expect_errno(fs.fallocate(&cx, &mut scope, ino, offset, length, mode), errno);
        }
        expect_errno(fs.fallocate(&cx, &mut scope, ROOT, 0, 1, 0), libc::EISDIR);
        let cancelled = Cx::for_testing();
        cancelled.cancel_with(asupersync::types::CancelKind::User, Some("allocation preflight"));
        assert!(matches!(
            fs.fallocate(&cancelled, &mut scope, ino, 0, 4096, 0),
            Err(FfsError::Cancelled),
        ));
        assert_eq!(raw_image(&directory), image_before);
        assert_eq!(fs.read(&cx, &mut scope, ino, 0, 32).unwrap(), b"unchanged");
        // The concurrent native implementation also supports KEEP_SIZE.
        // Preserve that stronger contract instead of reinstating the older
        // mode-zero-only adapter from the saved patch.
        fs.fallocate(&cx, &mut scope, ino, 0, 4096, libc::FALLOC_FL_KEEP_SIZE).unwrap();
        assert_eq!(fs.getattr(&cx, &mut scope, ino).unwrap().size, 9);
        assert!(fs.getattr(&cx, &mut scope, ino).unwrap().blocks >= 8);
        assert_eq!(fs.read(&cx, &mut scope, ino, 0, 32).unwrap(), b"unchanged");
        // Refusal did not accidentally fence a healthy mount.
        fs.fallocate(&cx, &mut scope, ino, 0, 32, 0).unwrap();
    }
}

#[test]
fn fallocate_capacity_and_permissions_refuse_before_any_native_mutation() {
    for kind in ["fat16", "fat32"] {
        let (directory, fs) = writable_fat(kind);
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        let ino = create_file(&fs, "CAPACITY.BIN");
        fs.write(&cx, &mut scope, ino, 0, b"original").unwrap();
        let impossible = (u64::from(fs.volume.geometry.cluster_count()) + 1)
            * u64::from(fs.volume.geometry.cluster_bytes());
        assert!(impossible <= u64::from(u32::MAX));
        let image_before = raw_image(&directory);
        expect_errno(fs.fallocate(&cx, &mut scope, ino, 0, impossible, 0), libc::ENOSPC);
        assert_eq!(raw_image(&directory), image_before);
        assert_eq!(fs.read(&cx, &mut scope, ino, 0, 32).unwrap(), b"original");
        fs.setattr(&cx, &mut scope, ino, &SetAttrRequest {
            mode: Some(0o444), ..Default::default()
        }).unwrap();
        let readonly_before = raw_image(&directory);
        expect_errno(fs.fallocate(&cx, &mut scope, ino, 0, 4096, 0), libc::EACCES);
        assert_eq!(raw_image(&directory), readonly_before);
        drop(fs);
        let args = crate::reader::ImageArgs {
            image: directory.path().join("volume.fat"), offset: 0, length: None,
            oem_code_page: ffs_ondisk::fat::FatOemCodePage::Ascii, sidecar: None,
        };
        let volume = args.open(&cx).unwrap();
        let readonly = FatFs::new(&cx, volume, 1000, 1000).unwrap();
        let ino = readonly.lookup(&cx, &mut scope, ROOT, OsStr::new("CAPACITY.BIN")).unwrap().ino;
        expect_errno(readonly.fallocate(&cx, &mut scope, ino, 0, 4096, 0), libc::EROFS);
        assert_eq!(raw_image(&directory), readonly_before);
    }
}

#[test]
fn noreplace_rejects_existing_names_aliases_and_self_without_native_changes() {
    for kind in ["fat16", "fat32"] {
        let (directory, fs) = writable_fat(kind);
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        let source = create_file(&fs, "SOURCE.BIN");
        fs.write(&cx, &mut scope, source, 0, b"source data").unwrap();
        let target = create_file(&fs, "Long destination name.bin");
        fs.write(&cx, &mut scope, target, 0, b"destination data").unwrap();
        let alias = fs.node(&cx, target).unwrap().entry.unwrap().short_alias().unwrap();
        let image_before = raw_image(&directory);
        let ops: &dyn FsOps = &fs;
        for name in ["Long destination name.bin", "long destination name.bin", &alias, "source.bin"] {
            expect_errno(ops.rename2(
                &cx, &mut scope, ROOT, OsStr::new("SOURCE.BIN"), ROOT,
                OsStr::new(name), libc::RENAME_NOREPLACE,
            ), libc::EEXIST);
        }
        for flags in [libc::RENAME_WHITEOUT, 3, 5, u32::MAX] {
            expect_errno(ops.rename2(
                &cx, &mut scope, ROOT, OsStr::new("SOURCE.BIN"), ROOT,
                OsStr::new("NEW.BIN"), flags,
            ), libc::EINVAL);
        }
        expect_errno(ops.rename2(
            &cx, &mut scope, ROOT, OsStr::new("SOURCE.BIN"), ROOT,
            OsStr::new("NEW.BIN"), libc::RENAME_EXCHANGE,
        ), libc::ENOENT);
        expect_errno(ops.rename2(
            &cx, &mut scope, ROOT, OsStr::new("MISSING.BIN"), ROOT,
            OsStr::new("NEW.BIN"), libc::RENAME_NOREPLACE,
        ), libc::ENOENT);
        assert_eq!(raw_image(&directory), image_before);
        assert_eq!(ops.read(&cx, &mut scope, source, 0, 64).unwrap(), b"source data");
        assert_eq!(ops.read(&cx, &mut scope, target, 0, 64).unwrap(), b"destination data");
        ops.rename2(&cx, &mut scope, ROOT, OsStr::new("SOURCE.BIN"), ROOT,
            OsStr::new("Long destination name.bin"), 0).unwrap();
        assert_eq!(ops.lookup(&cx, &mut scope, ROOT, OsStr::new(&alias)).unwrap().ino, source);
        expect_errno(ops.read(&cx, &mut scope, target, 0, 1), libc::ENOENT);
        assert!(fs.volume.check(&cx).unwrap().clean);
    }
}

#[test]
fn noreplace_cross_directory_moves_preserve_cached_descendant_identity() {
    for kind in ["fat16", "fat32"] {
        let (_directory, fs) = writable_fat(kind);
        let cx = Cx::for_testing();
        let mut scope = RequestScope::empty();
        let from = fs.mkdir(&cx, &mut scope, ROOT, OsStr::new("FROM"), 0o755, 1000, 1000).unwrap();
        let target = fs.mkdir(&cx, &mut scope, ROOT, OsStr::new("TARGET"), 0o755, 1000, 1000).unwrap();
        let child = fs.create(&cx, &mut scope, from.ino, OsStr::new("CHILD.BIN"), 0o644, 1000, 1000).unwrap();
        fs.write(&cx, &mut scope, child.ino, 0, b"child").unwrap();
        expect_errno(fs.rename2(
            &cx, &mut scope, ROOT, OsStr::new("FROM"), ROOT, OsStr::new("TARGET"),
            libc::RENAME_NOREPLACE,
        ), libc::EEXIST);
        fs.rename2(
            &cx, &mut scope, ROOT, OsStr::new("FROM"), target.ino, OsStr::new("MOVED"),
            libc::RENAME_NOREPLACE,
        ).unwrap();
        assert_eq!(fs.lookup(&cx, &mut scope, target.ino, OsStr::new("MOVED")).unwrap().ino, from.ino);
        assert_eq!(fs.lookup(&cx, &mut scope, from.ino, OsStr::new("..")).unwrap().ino, target.ino);
        assert_eq!(fs.lookup(&cx, &mut scope, from.ino, OsStr::new("CHILD.BIN")).unwrap().ino, child.ino);
        fs.write(&cx, &mut scope, child.ino, 5, b" survives").unwrap();
        assert_eq!(fs.read(&cx, &mut scope, child.ino, 0, 64).unwrap(), b"child survives");
        let check = fs.volume.check(&cx).unwrap();
        assert!(check.clean && check.complete && check.namespace_complete);
    }
}

#[test]
fn fat32_concurrent_noreplace_rename_has_exactly_one_winner() {
    let (_directory, fs) = writable_fat("fat32");
    let cx = Cx::for_testing();
    let mut scope = RequestScope::empty();
    let names = ["LEFT.BIN", "RIGHT.BIN"];
    let payloads: [&[u8]; 2] = [b"left content", b"right content"];
    let sources = names.map(|name| create_file(&fs, name));
    for index in 0..2 {
        fs.write(&cx, &mut scope, sources[index], 0, payloads[index]).unwrap();
    }
    let barrier = std::sync::Barrier::new(2);
    let outcomes = std::thread::scope(|threads| {
        let mut handles = Vec::new();
        for name in names {
            let fs = &fs;
            let barrier = &barrier;
            handles.push(threads.spawn(move || {
                let cx = Cx::for_testing();
                barrier.wait();
                fs.rename2(&cx, &mut RequestScope::empty(), ROOT, OsStr::new(name), ROOT,
                    OsStr::new("WINNER.BIN"), libc::RENAME_NOREPLACE)
            }));
        }
        handles.into_iter().map(|handle| handle.join().unwrap()).collect::<Vec<_>>()
    });
    assert_eq!(outcomes.iter().filter(|result| result.is_ok()).count(), 1);
    let winner = outcomes.iter().position(Result::is_ok).unwrap();
    let loser = 1 - winner;
    assert_eq!(outcomes[loser].as_ref().unwrap_err().to_errno(), libc::EEXIST);
    assert_eq!(fs.lookup(&cx, &mut scope, ROOT, OsStr::new("WINNER.BIN")).unwrap().ino, sources[winner]);
    assert_eq!(fs.lookup(&cx, &mut scope, ROOT, OsStr::new(names[loser])).unwrap().ino, sources[loser]);
    expect_errno(fs.lookup(&cx, &mut scope, ROOT, OsStr::new(names[winner])), libc::ENOENT);
    for index in 0..2 {
        assert_eq!(fs.read(&cx, &mut scope, sources[index], 0, 64).unwrap(), payloads[index]);
    }
    let check = fs.volume.check(&cx).unwrap();
    assert!(check.clean && check.complete && check.namespace_complete);
    assert_eq!(check.files, 2);
}
