use super::super::super::super::{SliceSource, create_in_volume, open_volume, unlink_in_volume};
use super::*;
use clap::Parser as _;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

const NOW: u64 = 1_700_000_000;

fn fixture(kind: &str) -> (tempfile::TempDir, crate::reader::ImageArgs, FatVolume) {
    let directory = tempfile::tempdir().unwrap();
    let image = directory.path().join("copy.fat");
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
        panic!("format");
    };
    crate::formatter::create(&Cx::for_testing(), &options).unwrap();
    let args = crate::reader::ImageArgs {
        image,
        offset: 0,
        length: None,
        oem_code_page: ffs_ondisk::fat::FatOemCodePage::Ascii,
        sidecar: None,
    };
    let volume = open_volume(&Cx::for_testing(), &args, true).unwrap();
    (directory, args, volume)
}

fn pattern(length: usize) -> Vec<u8> {
    (0..length).map(|at| ((at * 37 + 19) % 251) as u8).collect()
}

fn read(volume: &FatVolume, path: &str) -> Vec<u8> {
    let cx = Cx::for_testing();
    let entry = volume.resolve(&cx, path).unwrap().unwrap();
    let chain = volume.file_chain(&cx, &entry).unwrap();
    volume
        .read(&cx, &chain, 0, entry.native.size as usize)
        .unwrap()
}

fn healthy(volume: &FatVolume) {
    let cx = Cx::for_testing();
    super::super::super::validate_edit_state(&cx, volume).unwrap();
    let check = volume.check(&cx).unwrap();
    assert!(check.clean && check.complete && check.namespace_complete);
}

#[test]
fn copy_projection_matches_independent_materialized_windows() {
    let cx = Cx::for_testing();
    let input = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let original = b"retain prefix and suffix";
    let input_device = SliceSource(input);
    let original_device = SliceSource(original);
    for (from, to, length) in [
        (3, 0, 7),
        (0, 3, 26),
        (1, 32, 25),
        (2, 22, 3),
        (0, 0, 0),
        (26, u64::MAX, 0),
    ] {
        let source = CopySource::new(&input_device, &original_device, from, to, length).unwrap();
        let mut expected = original.to_vec();
        if length != 0 {
            expected.resize(expected.len().max((to + length) as usize), 0);
            expected[to as usize..(to + length) as usize]
                .copy_from_slice(&input[from as usize..(from + length) as usize]);
        }
        assert_eq!(source.len_bytes(), expected.len() as u64);
        for start in 0..=expected.len() {
            for end in start..=expected.len() {
                let mut actual = vec![0xA5; end - start];
                source
                    .read_exact_at(&cx, ByteOffset(start as u64), &mut actual)
                    .unwrap();
                assert_eq!(actual, expected[start..end]);
            }
        }
    }
}

#[test]
fn copy_projection_refuses_invalid_ranges_cancellation_and_source_io_errors() {
    let cx = Cx::for_testing();
    let bytes = SliceSource(b"abc");
    assert!(CopySource::new(&bytes, &bytes, 2, 0, 2).is_err());
    assert!(CopySource::new(&bytes, &bytes, u64::MAX, 0, 2).is_err());
    assert!(CopySource::new(&bytes, &bytes, 0, u64::MAX, 2).is_err());
    for (same, input, output, len, ok) in [
        (true, 0, 3, 3, true),
        (true, 0, 2, 3, false),
        (true, 2, 0, 3, false),
        (false, 0, 0, 3, true),
        (false, 0, u64::MAX, 1, false),
        (true, u64::MAX, u64::MAX, 0, true),
    ] {
        assert_eq!(validate_ranges(same, input, output, len).is_ok(), ok);
    }
    let source = CopySource::new(&bytes, &bytes, 0, 5, 3).unwrap();
    let mut output = [0xA5; 2];
    assert!(
        source
            .read_exact_at(&cx, ByteOffset(7), &mut output)
            .is_err()
    );
    assert_eq!(output, [0xA5; 2]);
    assert!(matches!(
        source.write_all_at(&cx, ByteOffset(0), b"x"),
        Err(FfsError::ReadOnly)
    ));
    cx.set_cancel_requested(true);
    assert!(matches!(
        source.read_exact_at(&cx, ByteOffset(0), &mut output),
        Err(FfsError::Cancelled)
    ));
    assert_eq!(output, [0xA5; 2]);

    struct FailedInput;
    impl ByteDevice for FailedInput {
        fn len_bytes(&self) -> u64 {
            3
        }
        fn read_exact_at(
            &self,
            _cx: &Cx,
            _at: ByteOffset,
            _bytes: &mut [u8],
        ) -> ffs_error::Result<()> {
            Err(std::io::Error::other("injected input failure").into())
        }
        fn write_all_at(&self, _cx: &Cx, _at: ByteOffset, _bytes: &[u8]) -> ffs_error::Result<()> {
            panic!("copy must never write its input")
        }
        fn sync(&self, _cx: &Cx) -> ffs_error::Result<()> {
            panic!("copy must never sync its input")
        }
    }
    let source = CopySource::new(&FailedInput, &bytes, 0, 0, 3).unwrap();
    assert!(matches!(
        source.read_exact_at(&Cx::for_testing(), ByteOffset(0), &mut output),
        Err(FfsError::Io(_))
    ));
}

#[test]
fn native_copy_preserves_source_and_initializes_fragmented_growth_on_both_widths() {
    for kind in ["fat16", "fat32"] {
        let (_directory, _args, volume) = fixture(kind);
        let cx = Cx::for_testing();
        let cluster = volume.geometry.cluster_bytes() as usize;
        let input = pattern(4 * cluster + 37);
        let original = vec![0xC3; cluster + 11];
        create_in_volume(&cx, &volume, "/Source with an alias.bin", &input, NOW, true).unwrap();
        create_in_volume(
            &cx,
            &volume,
            "/BLOCKER.BIN",
            &vec![0xD4; cluster * 2],
            NOW,
            false,
        )
        .unwrap();
        create_in_volume(&cx, &volume, "/OUTPUT.BIN", &original, NOW, false).unwrap();
        let before_input = volume
            .resolve(&cx, "/Source with an alias.bin")
            .unwrap()
            .unwrap();
        let source_chain = volume.file_chain(&cx, &before_input).unwrap().clusters;
        let before_output = volume.resolve(&cx, "/OUTPUT.BIN").unwrap().unwrap();
        let old_chain = volume.file_chain(&cx, &before_output).unwrap().clusters;
        unlink_in_volume(&cx, &volume, "/BLOCKER.BIN", false).unwrap();
        let free = volume.free_clusters(&cx).unwrap();
        let from = format!("/{}", before_input.short_alias().unwrap());
        let offset = original.len() + cluster + 5;
        let copied = volume
            .copy_range(
                &cx,
                &from,
                17,
                "/OUTPUT.BIN",
                offset as u64,
                input.len() as u64 + 100,
                NOW + 2,
            )
            .unwrap();
        assert_eq!(copied, input.len() as u64 - 17);
        let mut expected = original;
        expected.resize(offset + copied as usize, 0);
        expected[offset..].copy_from_slice(&input[17..]);
        assert_eq!(read(&volume, "/OUTPUT.BIN"), expected);
        assert_eq!(read(&volume, &from), input);
        let after_input = volume.resolve(&cx, &from).unwrap().unwrap();
        assert_eq!(after_input.native, before_input.native);
        assert_eq!(
            volume.file_chain(&cx, &after_input).unwrap().clusters,
            source_chain
        );
        let after_output = volume.resolve(&cx, "/OUTPUT.BIN").unwrap().unwrap();
        let chain = volume.file_chain(&cx, &after_output).unwrap();
        assert_eq!(&chain.clusters[..old_chain.len()], old_chain.as_slice());
        assert!(chain.clusters.windows(2).any(|pair| pair[1] != pair[0] + 1));
        assert_eq!(
            volume.free_clusters(&cx).unwrap(),
            free - (chain.clusters.len() - old_chain.len()) as u64
        );
        healthy(&volume);
    }
}

#[test]
fn full_volume_copy_reuses_allocation_and_enospc_leaves_destination_unchanged() {
    let (_directory, args, volume) = fixture("fat16");
    let cx = Cx::for_testing();
    let input = pattern(2048);
    let mut expected = vec![0xC3; 4096];
    create_in_volume(&cx, &volume, "/INPUT.BIN", &input, NOW, false).unwrap();
    create_in_volume(&cx, &volume, "/OUTPUT.BIN", &expected, NOW, false).unwrap();
    let filler = volume.free_clusters(&cx).unwrap() * u64::from(volume.geometry.cluster_bytes());
    create_in_volume(
        &cx,
        &volume,
        "/FILLER.BIN",
        &vec![0xD4; filler as usize],
        NOW,
        false,
    )
    .unwrap();
    assert_eq!(volume.free_clusters(&cx).unwrap(), 0);
    let entry = volume.resolve(&cx, "/OUTPUT.BIN").unwrap().unwrap();
    let chain = volume.file_chain(&cx, &entry).unwrap().clusters;
    let before = std::fs::read(&args.image).unwrap();
    let error = volume
        .copy_range(&cx, "/INPUT.BIN", 0, "/OUTPUT.BIN", 4096, 1024, NOW)
        .unwrap_err();
    assert!(matches!(
        error.downcast_ref::<FfsError>(),
        Some(FfsError::NoSpace)
    ));
    assert_eq!(std::fs::read(&args.image).unwrap(), before);
    assert_eq!(
        volume
            .copy_range(&cx, "/INPUT.BIN", 37, "/OUTPUT.BIN", 137, 1024, NOW)
            .unwrap(),
        1024
    );
    expected[137..1161].copy_from_slice(&input[37..1061]);
    assert_eq!(read(&volume, "/OUTPUT.BIN"), expected);
    assert_eq!(read(&volume, "/INPUT.BIN"), input);
    let entry = volume.resolve(&cx, "/OUTPUT.BIN").unwrap().unwrap();
    assert_eq!(volume.file_chain(&cx, &entry).unwrap().clusters, chain);
    assert_eq!(volume.free_clusters(&cx).unwrap(), 0);
    healthy(&volume);
}

#[test]
fn same_file_copy_uses_native_alias_identity_and_zero_eof_requests_do_not_mutate() {
    let (_directory, _args, volume) = fixture("fat16");
    let cx = Cx::for_testing();
    let mut expected = pattern(16 * 1024);
    let path = "/One native copy buffer.bin";
    create_in_volume(&cx, &volume, path, &expected, NOW, false).unwrap();
    let entry = volume.resolve(&cx, path).unwrap().unwrap();
    let alias = format!("/{}", entry.short_alias().unwrap());
    let (volume, epoch) = volume.with_mutation_observer();
    for (input, output, len) in [(1, 33, 17), (512, 0, 512), (2048, 8192, 777)] {
        let source = expected[input..input + len].to_vec();
        expected[output..output + len].copy_from_slice(&source);
        assert_eq!(
            volume
                .copy_range(
                    &cx,
                    path,
                    input as u64,
                    &alias,
                    output as u64,
                    len as u64,
                    NOW
                )
                .unwrap(),
            len as u64
        );
        assert_eq!(read(&volume, path), expected);
    }
    let before = epoch.load(Ordering::Acquire);
    for (input, output, len) in [(0, 0, 1), (0, 1, 512), (128, 0, 1024)] {
        let error = volume
            .copy_range(&cx, path, input, &alias, output, len, NOW)
            .unwrap_err();
        assert!(
            matches!(error.downcast_ref::<FfsError>(), Some(FfsError::Io(error)) if error.raw_os_error() == Some(libc::EINVAL))
        );
    }
    assert_eq!(
        volume
            .copy_range(&cx, path, 20_000, &alias, 30_000, 10, NOW)
            .unwrap(),
        0
    );
    assert_eq!(
        volume
            .copy_range(&cx, path, u64::MAX, &alias, u64::MAX, 0, NOW)
            .unwrap(),
        0
    );
    assert_eq!(epoch.load(Ordering::Acquire), before);
    assert_eq!(read(&volume, path), expected);
    healthy(&volume);
}

#[test]
fn fat32_copy_streams_more_than_the_reader_request_limit() {
    let (_directory, _args, volume) = fixture("fat32");
    let cx = Cx::for_testing();
    let input = pattern(16 * 1024 * 1024 + 8193);
    create_in_volume(&cx, &volume, "/LARGE.BIN", &input, NOW, false).unwrap();
    create_in_volume(&cx, &volume, "/COPY.BIN", &[], NOW, false).unwrap();
    let count = volume
        .copy_range(
            &cx,
            "/LARGE.BIN",
            37,
            "/COPY.BIN",
            9,
            u64::MAX - 37,
            NOW + 2,
        )
        .unwrap();
    assert_eq!(count, input.len() as u64 - 37);
    let entry = volume.resolve(&cx, "/COPY.BIN").unwrap().unwrap();
    let chain = volume.file_chain(&cx, &entry).unwrap();
    assert_eq!(u64::from(chain.size), count + 9);
    assert_eq!(volume.read(&cx, &chain, 0, 9).unwrap(), [0; 9]);
    let mut at = 0;
    while at < count {
        let size = (count - at).min(65_536) as usize;
        assert_eq!(
            volume.read(&cx, &chain, at + 9, size).unwrap(),
            input[at as usize + 37..at as usize + 37 + size]
        );
        at += size as u64;
    }
    healthy(&volume);
}

#[test]
fn native_copy_refuses_policy_overflow_and_cross_links_before_writes() {
    let (_directory, _args, volume) = fixture("fat16");
    let cx = Cx::for_testing();
    create_in_volume(&cx, &volume, "/INPUT.BIN", &pattern(2048), NOW, false).unwrap();
    create_in_volume(&cx, &volume, "/OUTPUT.BIN", &[0xC3; 1024], NOW, false).unwrap();
    create_in_volume(&cx, &volume, "/READONLY.BIN", b"protected", NOW, true).unwrap();
    let (volume, epoch) = volume.with_mutation_observer();
    for (from, input, to, output, len) in [
        ("/INPUT.BIN", u64::MAX, "/OUTPUT.BIN", 0, 1),
        ("/INPUT.BIN", 0, "/OUTPUT.BIN", u64::MAX, 1),
        ("/INPUT.BIN", 0, "/OUTPUT.BIN", u64::from(u32::MAX) - 3, 8),
        ("/INPUT.BIN", 0, "/READONLY.BIN", 0, 1),
        ("/", 0, "/OUTPUT.BIN", 0, 1),
        ("/INPUT.BIN", 0, "/", 0, 1),
        ("/MISSING.BIN", 0, "/OUTPUT.BIN", 0, 1),
    ] {
        assert!(
            volume
                .copy_range(&cx, from, input, to, output, len, NOW)
                .is_err()
        );
        assert_eq!(epoch.load(Ordering::Acquire), 0);
    }
    let input = volume.resolve(&cx, "/INPUT.BIN").unwrap().unwrap();
    let output = volume.resolve(&cx, "/OUTPUT.BIN").unwrap().unwrap();
    volume
        .device
        .write_all_at(
            &cx,
            ByteOffset(output.offset + 26),
            &(input.native.first_cluster as u16).to_le_bytes(),
        )
        .unwrap();
    let before = epoch.load(Ordering::Acquire);
    assert!(
        volume
            .copy_range(&cx, "/INPUT.BIN", 0, "/OUTPUT.BIN", 0, 512, NOW)
            .is_err()
    );
    assert_eq!(epoch.load(Ordering::Acquire), before);
}

struct Disk {
    bytes: Vec<u8>,
    durable: Vec<u8>,
    operations: usize,
    fail: Option<usize>,
    tear: usize,
    drop_write_at: Option<u64>,
    dropped_writes: Vec<(u64, usize)>,
}

#[derive(Clone)]
struct FaultDevice(Arc<Mutex<Disk>>, u64);

impl FaultDevice {
    fn new(bytes: Vec<u8>) -> Self {
        let length = bytes.len() as u64;
        Self(
            Arc::new(Mutex::new(Disk {
                durable: bytes.clone(),
                bytes,
                operations: 0,
                fail: None,
                tear: 0,
                drop_write_at: None,
                dropped_writes: Vec::new(),
            })),
            length,
        )
    }
    fn volume(&self) -> FatVolume {
        FatVolume::from_device(&Cx::for_testing(), Box::new(self.clone()), 0, self.1).unwrap()
    }
}

impl ByteDevice for FaultDevice {
    fn len_bytes(&self) -> u64 {
        self.1
    }
    fn read_exact_at(&self, cx: &Cx, at: ByteOffset, bytes: &mut [u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let state = self.0.lock().unwrap();
        bytes.copy_from_slice(&state.bytes[at.0 as usize..at.0 as usize + bytes.len()]);
        Ok(())
    }
    fn write_all_at(&self, cx: &Cx, at: ByteOffset, bytes: &[u8]) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let mut state = self.0.lock().unwrap();
        state.operations += 1;
        let fail = state.fail == Some(state.operations);
        let count = if fail {
            state.tear.min(bytes.len())
        } else {
            bytes.len()
        };
        let dropped = state.drop_write_at.is_some_and(|target| {
            target
                .checked_sub(at.0)
                .is_some_and(|within| within < count as u64)
        });
        if dropped {
            state.dropped_writes.push((at.0, count));
        } else {
            state.bytes[at.0 as usize..at.0 as usize + count].copy_from_slice(&bytes[..count]);
        }
        if fail {
            return Err(std::io::Error::other("injected copy write failure").into());
        }
        Ok(())
    }
    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        checkpoint(cx)?;
        let mut state = self.0.lock().unwrap();
        state.operations += 1;
        if state.fail == Some(state.operations) {
            return Err(std::io::Error::other("injected copy sync failure").into());
        }
        state.durable = state.bytes.clone();
        Ok(())
    }
}

#[test]
fn native_copy_fault_cuts_preserve_source_and_never_admit_partial_clean_output() {
    let (_directory, args, volume) = fixture("fat16");
    let cx = Cx::for_testing();
    let input = pattern(2048);
    let old = vec![0xC3; 1536];
    create_in_volume(&cx, &volume, "/INPUT.BIN", &input, NOW, false).unwrap();
    create_in_volume(&cx, &volume, "/OUTPUT.BIN", &old, NOW, false).unwrap();
    let baseline = std::fs::read(&args.image).unwrap();
    let mut expected = old.clone();
    expected[120..1120].copy_from_slice(&input[..1000]);
    let success = FaultDevice::new(baseline.clone());
    success
        .volume()
        .copy_range(&cx, "/INPUT.BIN", 0, "/OUTPUT.BIN", 120, 1000, NOW)
        .unwrap();
    let operations = success.0.lock().unwrap().operations;
    assert!(operations > 5);
    for cut in 1..=operations {
        for tear in [0, 1, 511] {
            let device = FaultDevice::new(baseline.clone());
            let volume = device.volume();
            {
                let mut state = device.0.lock().unwrap();
                state.fail = Some(cut);
                state.tear = tear;
            }
            assert!(
                volume
                    .copy_range(&cx, "/INPUT.BIN", 0, "/OUTPUT.BIN", 120, 1000, NOW)
                    .is_err()
            );
            assert_eq!(read(&volume, "/INPUT.BIN"), input);
            let actual = read(&volume, "/OUTPUT.BIN");
            assert_eq!(&actual[..120], &old[..120]);
            assert_eq!(&actual[1120..], &old[1120..]);
            for pending in [false, true] {
                let snapshot = {
                    let state = device.0.lock().unwrap();
                    if pending {
                        state.bytes.clone()
                    } else {
                        state.durable.clone()
                    }
                };
                let restart = FaultDevice::new(snapshot);
                if let Ok(volume) =
                    FatVolume::from_device(&cx, Box::new(restart.clone()), 0, restart.1)
                {
                    let actual = read(&volume, "/OUTPUT.BIN");
                    assert!(actual == old || actual == expected);
                    assert_eq!(read(&volume, "/INPUT.BIN"), input);
                    healthy(&volume);
                }
            }
        }
    }
    let device = FaultDevice::new(baseline);
    let volume = device.volume();
    // Drop the first destination payload write by native byte address. Dirty
    // publication may add barriers without moving this fault onto a sync call.
    let output = volume.resolve(&cx, "/OUTPUT.BIN").unwrap().unwrap();
    let payload_at = volume.base
        + volume
            .geometry
            .cluster_offset(output.native.first_cluster)
            .unwrap()
        + 120;
    let first_count = (u64::from(volume.geometry.cluster_bytes()) - 120).min(1000) as usize;
    device.0.lock().unwrap().drop_write_at = Some(payload_at);
    assert!(
        volume
            .copy_range(&cx, "/INPUT.BIN", 0, "/OUTPUT.BIN", 120, 1000, NOW)
            .is_err()
    );
    assert_eq!(
        device.0.lock().unwrap().dropped_writes,
        [(payload_at, first_count)]
    );
    assert_eq!(read(&volume, "/INPUT.BIN"), input);
    let actual = read(&volume, "/OUTPUT.BIN");
    assert_eq!(&actual[..120], &old[..120]);
    assert_eq!(&actual[1120..], &old[1120..]);
}
