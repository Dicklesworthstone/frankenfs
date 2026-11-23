//! Independent ntfs-3g consumption of retained files and native cleanup results.

use super::{command_available, run_cli_binary, sha256_file};
use asupersync::Cx;
use ffs_core::{FsOps, RequestScope};
use ffs_ntfs::NtfsFs;
use ffs_ntfs::transaction::{NtfsTransactionEngine, NtfsWriteOptions};
use ffs_types::InodeNumber;
use std::ffi::OsStr;
use std::fs;
use std::path::Path;
use std::process::Output;

fn checked(tool: &str, args: &[&str]) -> Output {
    let output = run_cli_binary(Path::new(tool), args);
    assert!(
        output.status.success(),
        "{tool} {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

fn names(image: &str) -> Vec<String> {
    String::from_utf8(checked("ntfsls", &["-a", "-p", "/", image]).stdout)
        .unwrap()
        .lines()
        .map(|line| line.trim().to_owned())
        .collect()
}

fn writable(cx: &Cx, image: &Path) -> NtfsTransactionEngine {
    NtfsTransactionEngine::open(
        cx,
        image,
        0,
        None,
        NtfsWriteOptions {
            offline_image: true,
            allow_write: true,
            recover_dirty: true,
        },
    )
    .unwrap()
}

#[test]
#[ignore = "requires ntfs-3g mkntfs, ntfscp, ntfscat, ntfsls and ntfsfix; checks retained native files, streams and allocation reclamation"]
fn native_ntfs_orphan_retention_and_reopen_cleanup_preserve_interchange() {
    for tool in ["mkntfs", "ntfscp", "ntfscat", "ntfsls", "ntfsfix"] {
        assert!(
            command_available(tool),
            "native NTFS orphan test requires {tool}"
        );
    }
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("native.img");
    let payload_file = directory.path().join("payload.bin");
    fs::File::create(&image)
        .unwrap()
        .set_len(64 * 1024 * 1024)
        .unwrap();
    let native_path = image.to_str().unwrap();
    checked(
        "mkntfs",
        &["-F", "-Q", "-s", "512", "-c", "4096", native_path],
    );
    let mut payload: Vec<_> = (0_u32..9000).map(|index| (index % 251) as u8).collect();
    for (path, stream, bytes) in [
        ("/held.bin", None, payload.as_slice()),
        (
            "/held.bin",
            Some("content"),
            b"native alternate stream".as_slice(),
        ),
        (
            "/.ffs-unlinked-legacy",
            None,
            b"keep legacy prefix file".as_slice(),
        ),
    ] {
        fs::write(&payload_file, bytes).unwrap();
        let mut args = Vec::new();
        if let Some(stream) = stream {
            args.extend(["-N", stream]);
        }
        args.extend([native_path, payload_file.to_str().unwrap(), path]);
        checked("ntfscp", &args);
    }
    let cx = Cx::for_testing();
    let engine = writable(&cx, &image);
    let target = engine.resolve_path_reference(&cx, "/held.bin").unwrap();
    let fs = NtfsFs::from_engine(&cx, engine, 1000, 1000).unwrap();
    let mut scope = RequestScope::empty();
    let root = InodeNumber(1);
    let base = fs
        .lookup(&cx, &mut scope, root, OsStr::new("held.bin"))
        .unwrap();
    let handle = fs.open(&cx, &mut scope, base.ino, libc::O_RDWR).unwrap().0;
    fs.unlink(&cx, &mut scope, root, OsStr::new("held.bin"))
        .unwrap();
    fs.write(&cx, &mut scope, base.ino, 0, b"kept").unwrap();
    payload[..4].copy_from_slice(b"kept");
    fs.fsync(&cx, &mut scope, base.ino, handle, false).unwrap();
    // No release or destroy flush: preserve the committed image that outlives
    // the process's handle table. Native tools run only after the writer drops.
    drop(fs);
    let listing = names(native_path);
    assert!(!listing.iter().any(|name| name == "held.bin"));
    let retained: Vec<_> = listing
        .iter()
        .filter(|name| {
            name.starts_with(".ffs-unlinked-") && name.as_str() != ".ffs-unlinked-legacy"
        })
        .collect();
    assert_eq!(retained.len(), 1);
    let retained_path = format!("/{}", retained[0]);
    assert_eq!(
        checked("ntfscat", &[native_path, &retained_path]).stdout,
        payload
    );
    assert_eq!(
        checked("ntfscat", &["-n", "content", native_path, &retained_path]).stdout,
        b"native alternate stream"
    );
    let marker = checked(
        "ntfscat",
        &["-n", "$FrankenFS.Orphan", native_path, &retained_path],
    )
    .stdout;
    assert_eq!(marker.len(), 144);
    assert_eq!(&marker[..16], b"FFS_NTFS_ORPHAN\0");
    let before_bitmap = checked("ntfscat", &["-i", "6", native_path]).stdout;
    let before_mft = checked("ntfscat", &["-i", "0", "-a", "176", native_path]).stdout;
    let slot = usize::try_from(target.record).unwrap();
    assert_ne!(before_mft[slot / 8] & (1 << (slot % 8)), 0);
    checked("ntfsfix", &["-n", native_path]);
    println!("native retained image sha256={}", sha256_file(&image));

    let fs = NtfsFs::from_engine(&cx, writable(&cx, &image), 1000, 1000).unwrap();
    assert!(fs.last_durable_token().unwrap().is_some());
    drop(fs);
    let remaining = names(native_path);
    let remaining_retained: Vec<_> = remaining
        .iter()
        .filter(|name| name.starts_with(".ffs-unlinked-"))
        .map(String::as_str)
        .collect();
    assert_eq!(remaining_retained, [".ffs-unlinked-legacy"]);
    let after_bitmap = checked("ntfscat", &["-i", "6", native_path]).stdout;
    let allocated = |bitmap: &[u8]| {
        bitmap
            .iter()
            .map(|byte| u64::from(byte.count_ones()))
            .sum::<u64>()
    };
    assert!(allocated(&after_bitmap) + 3 <= allocated(&before_bitmap));
    let after_mft = checked("ntfscat", &["-i", "0", "-a", "176", native_path]).stdout;
    assert_eq!(after_mft[slot / 8] & (1 << (slot % 8)), 0);
    assert_eq!(
        checked("ntfscat", &[native_path, "/.ffs-unlinked-legacy"]).stdout,
        b"keep legacy prefix file"
    );
    checked("ntfsfix", &["-n", native_path]);
    println!("native reclaimed image sha256={}", sha256_file(&image));

    // Reverse direction too: native mutation after cleanup remains readable
    // through a fresh FrankenFS writer, with no further cleanup commit.
    fs::write(&payload_file, b"native rewrite after cleanup").unwrap();
    checked(
        "ntfscp",
        &[
            native_path,
            payload_file.to_str().unwrap(),
            "/.ffs-unlinked-legacy",
        ],
    );
    let fs = NtfsFs::from_engine(&cx, writable(&cx, &image), 1000, 1000).unwrap();
    assert!(fs.last_durable_token().unwrap().is_none());
    let legacy = fs
        .lookup(&cx, &mut scope, root, OsStr::new(".ffs-unlinked-legacy"))
        .unwrap();
    assert_eq!(
        fs.read(&cx, &mut scope, legacy.ino, 0, 128).unwrap(),
        b"native rewrite after cleanup"
    );
}
