#![forbid(unsafe_code)]
//! A standalone application consuming the public read-only native-image API.
//! File reads emit exact bytes; directory listings emit NUL-delimited names.

use asupersync::{Budget, Cx};
use clap::{Parser, Subcommand};
use ffs::{
    FileType, ImageSource, InodeAttr, InodeNumber, ReadOnlyBackend, ReadOnlyFs,
    ReadOnlyOpenOptions, RequestScope, ZfsReadOptions, open_read_only,
};
use ffs_error::FfsError;
use std::error::Error;
use std::ffi::OsString;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Debug, Parser)]
#[command(about = "Read or mount an offline native image through the public ffs facade")]
struct Args {
    image: PathBuf,
    #[arg(long, default_value_t = 0)]
    offset: u64,
    #[arg(long)]
    length: Option<u64>,
    /// External ext4 journal: byte offset and positive byte length, or `rest`.
    #[arg(
        long,
        num_args = 3,
        value_names = ["PATH", "OFFSET", "LENGTH"],
        action = clap::ArgAction::Set,
        conflicts_with_all = ["btrfs_device", "ntfs_indexed_lookup", "zfs_dataset", "zfs_snapshot"]
    )]
    ext4_journal: Vec<OsString>,
    /// Repeat for each btrfs member: byte offset and positive length, or `rest`.
    #[arg(
        long,
        num_args = 3,
        value_names = ["PATH", "OFFSET", "LENGTH"],
        conflicts_with_all = ["ntfs_indexed_lookup", "zfs_dataset", "zfs_snapshot"]
    )]
    btrfs_device: Vec<OsString>,
    /// Opt into NTFS index-directed lookup; does not certify unvisited siblings.
    #[arg(long, conflicts_with_all = ["zfs_dataset", "zfs_snapshot"])]
    ntfs_indexed_lookup: bool,
    /// Repeat for each raw ZFS dataset-name component.
    #[arg(long)]
    zfs_dataset: Vec<OsString>,
    #[arg(long)]
    zfs_snapshot: Option<OsString>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Stat {
        path: PathBuf,
    },
    List {
        path: PathBuf,
    },
    Read {
        path: PathBuf,
        #[arg(long, default_value_t = 0)]
        start: u64,
        #[arg(long)]
        bytes: Option<u64>,
        /// Select exact native NTFS DATA; absent selectors use ordinary FsOps.
        #[arg(long, conflicts_with = "stream_utf16")]
        stream: Option<String>,
        #[arg(long, value_parser = ffs::ntfs::StreamName::parse, conflicts_with = "stream")]
        stream_utf16: Option<ffs::ntfs::StreamName>,
    },
    /// Require a write attempt to fail with the read-only error. Use a scratch image.
    RefuseWrite {
        path: PathBuf,
    },
    /// Mount read-only in the foreground until unmounted; keep the image offline.
    Mount {
        /// An existing empty directory.
        mountpoint: PathBuf,
    },
}

fn invalid(detail: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, detail)
}

fn image_sources(values: &[OsString]) -> Result<Vec<ImageSource>> {
    let (triples, remainder) = values.as_chunks::<3>();
    if !remainder.is_empty() {
        return Err(invalid("each auxiliary image needs PATH OFFSET LENGTH").into());
    }
    triples
        .iter()
        .map(|triple| {
            let offset = triple[1]
                .to_str()
                .and_then(|value| value.parse::<u64>().ok())
                .ok_or_else(|| invalid("auxiliary image OFFSET must be an unsigned byte count"))?;
            let length = match triple[2].to_str() {
                Some("rest") => None,
                Some(value) => {
                    let length = value
                        .parse::<u64>()
                        .ok()
                        .filter(|length| *length > 0)
                        .ok_or_else(|| {
                            invalid("auxiliary image LENGTH must be positive bytes or rest")
                        })?;
                    offset
                        .checked_add(length)
                        .ok_or_else(|| invalid("auxiliary image range overflows"))?;
                    Some(length)
                }
                None => {
                    return Err(
                        invalid("auxiliary image LENGTH must be positive bytes or rest").into(),
                    );
                }
            };
            Ok(ImageSource {
                path: PathBuf::from(&triple[0]),
                offset,
                length,
            })
        })
        .collect()
}

impl Args {
    fn backend(&self) -> Result<ReadOnlyBackend> {
        if !self.ext4_journal.is_empty() {
            Ok(ReadOnlyBackend::Ext4 {
                external_journal: image_sources(&self.ext4_journal)?.pop(),
            })
        } else if !self.btrfs_device.is_empty() {
            Ok(ReadOnlyBackend::Btrfs {
                root: ffs::BtrfsMountSelection::DefaultRoot,
                additional_devices: image_sources(&self.btrfs_device)?,
            })
        } else if self.ntfs_indexed_lookup {
            Ok(ReadOnlyBackend::Ntfs {
                indexed_lookup: true,
            })
        } else if self.zfs_dataset.is_empty() && self.zfs_snapshot.is_none() {
            Ok(ReadOnlyBackend::Auto)
        } else {
            Ok(ReadOnlyBackend::Zfs(ZfsReadOptions {
                dataset: self
                    .zfs_dataset
                    .iter()
                    .map(|name| name.as_encoded_bytes().to_vec())
                    .collect(),
                snapshot: self
                    .zfs_snapshot
                    .as_ref()
                    .map(|name| name.as_encoded_bytes().to_vec()),
                ..ZfsReadOptions::default()
            }))
        }
    }
}

fn read_only_mountpoint(
    image: &Path,
    backend: &ReadOnlyBackend,
    mountpoint: &Path,
) -> Result<PathBuf> {
    let mountpoint = mountpoint.canonicalize()?;
    if !mountpoint.is_dir() {
        return Err(invalid("mountpoint must be an existing empty directory").into());
    }
    let auxiliary: &[ImageSource] = match backend {
        ReadOnlyBackend::Ext4 { external_journal } => external_journal.as_slice(),
        ReadOnlyBackend::Btrfs {
            additional_devices, ..
        } => additional_devices,
        ReadOnlyBackend::Zfs(options) => &options.additional_images,
        _ => &[],
    };
    for path in std::iter::once(image).chain(auxiliary.iter().map(|source| source.path.as_path())) {
        if path.canonicalize()?.starts_with(&mountpoint) {
            return Err(invalid("mountpoint would hide its backing image").into());
        }
    }
    if std::fs::read_dir(&mountpoint)?
        .next()
        .transpose()?
        .is_some()
    {
        return Err(invalid("mountpoint must be an existing empty directory").into());
    }
    Ok(mountpoint)
}

fn lookup(
    cx: &Cx,
    opened: &ReadOnlyFs,
    scope: &mut RequestScope,
    path: &Path,
) -> Result<InodeAttr> {
    let mut attr = opened.filesystem.getattr(cx, scope, InodeNumber(1))?;
    for component in path.components() {
        match component {
            Component::Normal(name) => {
                attr = opened.filesystem.lookup(cx, scope, attr.ino, name)?;
            }
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(invalid("use an image-root path without parent components").into());
            }
        }
    }
    // Exercise the independent getattr path as well as lookup's returned attrs.
    Ok(opened.filesystem.getattr(cx, scope, attr.ino)?)
}

fn read(
    cx: &Cx,
    opened: &ReadOnlyFs,
    scope: &mut RequestScope,
    attr: &InodeAttr,
    start: u64,
    count: Option<u64>,
) -> Result<()> {
    if attr.kind != FileType::RegularFile {
        return Err(
            invalid("read requires a regular file; symbolic links are not followed").into(),
        );
    }
    let end = match count {
        Some(count) => start
            .checked_add(count)
            .ok_or_else(|| invalid("read range overflows"))?
            .min(attr.size),
        None => attr.size,
    };
    let mut position = start;
    let mut output = io::stdout().lock();
    while position < end {
        let requested = u32::try_from((end - position).min(65_536))?;
        let bytes = opened
            .filesystem
            .read(cx, scope, attr.ino, position, requested)?;
        if bytes.is_empty() || bytes.len() > usize::try_from(requested)? {
            return Err(
                io::Error::other("native read did not cover its declared file range").into(),
            );
        }
        output.write_all(&bytes)?;
        position += u64::try_from(bytes.len())?;
    }
    output.flush()?;
    Ok(())
}

fn list(cx: &Cx, opened: &ReadOnlyFs, scope: &mut RequestScope, ino: InodeNumber) -> Result<()> {
    let mut offset = 0;
    let mut output = io::stdout().lock();
    loop {
        let page = opened.filesystem.readdir(cx, scope, ino, offset)?;
        if page.is_empty() {
            break;
        }
        let next = page
            .as_slice()
            .last()
            .ok_or_else(|| invalid("empty directory page"))?
            .offset;
        if next == offset {
            return Err(io::Error::other("directory continuation made no progress").into());
        }
        for entry in &page {
            output.write_all(&entry.name)?;
            output.write_all(&[0])?;
        }
        offset = next;
    }
    output.flush()?;
    Ok(())
}

fn read_stream(
    cx: &Cx,
    opened: &ReadOnlyFs,
    path: &Path,
    name: &ffs::ntfs::StreamName,
    start: u64,
    count: Option<u64>,
    indexed_lookup: bool,
) -> Result<()> {
    let volume = opened
        .ntfs_volume()
        .ok_or_else(|| invalid("native stream selection requires NTFS"))?;
    let path = path
        .to_str()
        .ok_or_else(|| invalid("NTFS path must be UTF-8"))?;
    let record = if indexed_lookup {
        volume.resolve_indexed_no_follow(cx, path)?
    } else {
        volume.resolve_no_follow(cx, path)?
    };
    let stream = volume.data_stream(cx, &record, name.as_units())?;
    let end = match count {
        Some(count) => start
            .checked_add(count)
            .ok_or_else(|| invalid("read range overflows"))?
            .min(stream.size),
        None => stream.size,
    };
    let mut position = start;
    let mut output = io::stdout().lock();
    while position < end {
        let requested = usize::try_from((end - position).min(65_536))?;
        let bytes = volume.read(cx, &stream, position, requested)?;
        if bytes.is_empty() || bytes.len() > requested {
            return Err(io::Error::other("native stream ended before its declared size").into());
        }
        output.write_all(&bytes)?;
        position += u64::try_from(bytes.len())?;
    }
    output.flush()?;
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let backend = args.backend()?;
    let mountpoint = match &args.command {
        Command::Mount { mountpoint } => {
            Some(read_only_mountpoint(&args.image, &backend, mountpoint)?)
        }
        _ => None,
    };
    // The application owns the runtime and supplies its context to the library.
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()?;
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    let opened = open_read_only(
        &cx,
        &args.image,
        &ReadOnlyOpenOptions {
            offset: args.offset,
            length: args.length,
            backend,
            ..ReadOnlyOpenOptions::default()
        },
    )?;
    let mut scope = RequestScope::empty();
    match args.command {
        Command::Stat { path } => {
            let attr = lookup(&cx, &opened, &mut scope, &path)?;
            println!("{}\t{:?}\t{}", opened.format, attr.kind, attr.size);
        }
        Command::List { path } => {
            let attr = lookup(&cx, &opened, &mut scope, &path)?;
            list(&cx, &opened, &mut scope, attr.ino)?;
        }
        Command::Read {
            path,
            start,
            bytes,
            stream,
            stream_utf16,
        } => {
            let attr = lookup(&cx, &opened, &mut scope, &path)?;
            if stream.is_some() || stream_utf16.is_some() {
                if attr.kind != FileType::RegularFile {
                    return Err(invalid("stream read requires a regular file").into());
                }
                let name = ffs::ntfs::StreamName::select(stream.as_deref(), stream_utf16)
                    .map_err(|error| invalid(&error))?;
                read_stream(
                    &cx,
                    &opened,
                    &path,
                    &name,
                    start,
                    bytes,
                    args.ntfs_indexed_lookup,
                )?;
            } else {
                read(&cx, &opened, &mut scope, &attr, start, bytes)?;
            }
        }
        Command::RefuseWrite { path } => {
            let attr = lookup(&cx, &opened, &mut scope, &path)?;
            match opened
                .filesystem
                .write(&cx, &mut scope, attr.ino, 0, b"forbidden")
            {
                Err(FfsError::ReadOnly) => {}
                Err(error) => return Err(error.into()),
                Ok(_) => return Err(io::Error::other("write unexpectedly succeeded").into()),
            }
        }
        Command::Mount { .. } => {
            let mountpoint = mountpoint.ok_or_else(|| invalid("mountpoint was not admitted"))?;
            // Transfer the already admitted, bounded and locked FsOps handle.
            // The transport has no option here to enable native mutation.
            ffs_fuse::mount(
                opened.filesystem,
                mountpoint,
                &ffs_fuse::MountOptions {
                    read_only: true,
                    allow_other: false,
                    dev: false,
                    suid: false,
                    ..ffs_fuse::MountOptions::default()
                },
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexed_ntfs_selection_keeps_bounded_raw_stream_arguments() {
        let args = Args::try_parse_from([
            "native_reader",
            "image.img",
            "--offset",
            "4096",
            "--length",
            "67108864",
            "--ntfs-indexed-lookup",
            "read",
            "/payload.bin",
            "--stream-utf16",
            "006e,006f,0074,0065",
            "--start",
            "507",
            "--bytes",
            "1031",
        ])
        .unwrap();
        assert!(args.ntfs_indexed_lookup);
        assert_eq!((args.offset, args.length), (4096, Some(67_108_864)));
        let Command::Read {
            stream_utf16,
            start,
            bytes,
            ..
        } = args.command
        else {
            panic!("expected read arguments");
        };
        assert_eq!((start, bytes), (507, Some(1031)));
        assert_eq!(stream_utf16.unwrap().as_units(), [0x6e, 0x6f, 0x74, 0x65]);
    }

    #[test]
    fn ntfs_and_zfs_selections_cannot_silently_override_each_other() {
        for option in ["--zfs-dataset", "--zfs-snapshot"] {
            let error = Args::try_parse_from([
                "native_reader",
                "image.img",
                "--ntfs-indexed-lookup",
                option,
                "data",
                "stat",
                "/",
            ])
            .unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
        }
    }

    #[test]
    fn read_only_mount_keeps_bounded_and_native_view_selection() {
        for selection in [None, Some("--ntfs-indexed-lookup")] {
            let mut arguments = vec![
                "native_reader",
                "disk.img",
                "--offset",
                "4096",
                "--length",
                "67108864",
            ];
            arguments.extend(selection);
            arguments.extend(["mount", "/mnt/native"]);
            let args = Args::try_parse_from(arguments).unwrap();
            assert_eq!((args.offset, args.length), (4096, Some(67_108_864)));
            assert_eq!(args.ntfs_indexed_lookup, selection.is_some());
            let Command::Mount { mountpoint } = args.command else {
                panic!("expected mount arguments");
            };
            assert_eq!(mountpoint, PathBuf::from("/mnt/native"));
        }
        let args = Args::try_parse_from([
            "native_reader",
            "pool.img",
            "--zfs-dataset",
            "archive",
            "--zfs-snapshot",
            "before",
            "mount",
            "/mnt/snapshot",
        ])
        .unwrap();
        assert_eq!(args.zfs_dataset, [OsString::from("archive")]);
        assert_eq!(args.zfs_snapshot, Some(OsString::from("before")));
        assert!(matches!(args.command, Command::Mount { .. }));
    }

    #[test]
    fn read_only_mount_has_no_write_or_privilege_switches() {
        for option in [
            "--rw",
            "--read-write",
            "--allow-other",
            "--dev",
            "--suid",
            "--writeback-cache",
        ] {
            let error = Args::try_parse_from([
                "native_reader",
                "image.img",
                "mount",
                "/mnt/native",
                option,
            ])
            .unwrap_err();
            assert_eq!(error.kind(), clap::error::ErrorKind::UnknownArgument);
        }
    }

    #[test]
    fn mountpoint_admits_empty_directory_and_refuses_hidden_backing_or_contents() {
        let root = tempfile::Builder::new()
            .prefix("ffs-public-mountpoint-")
            .tempdir()
            .unwrap()
            .keep();
        let image = root.join("backing.img");
        std::fs::File::create_new(&image).unwrap();
        let mountpoint = root.join("mount");
        std::fs::create_dir(&mountpoint).unwrap();
        let backend = ReadOnlyBackend::Auto;
        assert_eq!(
            read_only_mountpoint(&image, &backend, &mountpoint).unwrap(),
            mountpoint.canonicalize().unwrap()
        );
        assert!(read_only_mountpoint(&image, &backend, &root.join("missing")).is_err());
        assert!(read_only_mountpoint(&image, &backend, &image).is_err());
        assert_eq!(
            read_only_mountpoint(&image, &backend, &root)
                .unwrap_err()
                .to_string(),
            "mountpoint would hide its backing image"
        );
        std::fs::File::create_new(mountpoint.join("visible.txt")).unwrap();
        assert_eq!(
            read_only_mountpoint(&image, &backend, &mountpoint)
                .unwrap_err()
                .to_string(),
            "mountpoint must be an existing empty directory"
        );
    }

    #[test]
    fn auxiliary_sources_keep_independent_bounds_in_the_selected_backend() {
        let args = Args::try_parse_from([
            "native_reader",
            "data.img",
            "--offset",
            "4096",
            "--length",
            "67108864",
            "--ext4-journal",
            "journal image.img",
            "8192",
            "32768",
            "read",
            "/hello.txt",
        ])
        .unwrap();
        assert_eq!((args.offset, args.length), (4096, Some(67_108_864)));
        let ReadOnlyBackend::Ext4 { external_journal } = args.backend().unwrap() else {
            panic!("expected external journal selection");
        };
        let journal = external_journal.unwrap();
        assert_eq!(journal.path, PathBuf::from("journal image.img"));
        assert_eq!((journal.offset, journal.length), (8192, Some(32768)));

        let args = Args::try_parse_from([
            "native_reader",
            "sprout.img",
            "--btrfs-device",
            "first seed.img",
            "8192",
            "1048576",
            "--btrfs-device",
            "second.img",
            "16384",
            "rest",
            "mount",
            "/mnt/native",
        ])
        .unwrap();
        let ReadOnlyBackend::Btrfs {
            root,
            additional_devices,
        } = args.backend().unwrap()
        else {
            panic!("expected btrfs member selection");
        };
        assert_eq!(root, ffs::BtrfsMountSelection::DefaultRoot);
        assert_eq!(additional_devices.len(), 2);
        assert_eq!(additional_devices[0].path, PathBuf::from("first seed.img"));
        assert_eq!(
            (additional_devices[0].offset, additional_devices[0].length),
            (8192, Some(1048576))
        );
        assert_eq!(additional_devices[1].path, PathBuf::from("second.img"));
        assert_eq!(
            (additional_devices[1].offset, additional_devices[1].length),
            (16384, None)
        );
    }

    #[test]
    fn auxiliary_sources_refuse_bad_geometry_and_incomplete_or_duplicate_journals() {
        for option in ["--ext4-journal", "--btrfs-device"] {
            for (offset, length) in [
                ("nonsense", "rest"),
                ("18446744073709551616", "1"),
                ("0", "0"),
                ("0", "all"),
                ("0", "18446744073709551616"),
                ("18446744073709551615", "1"),
            ] {
                let args = Args::try_parse_from([
                    "native_reader",
                    "image.img",
                    option,
                    "member.img",
                    offset,
                    length,
                    "stat",
                    "/",
                ])
                .unwrap();
                assert!(args.backend().is_err(), "{option} {offset} {length}");
            }
            for values in [&["member.img"][..], &["member.img", "4096"][..]] {
                let mut arguments = vec!["native_reader", "image.img", option];
                arguments.extend(values);
                assert!(Args::try_parse_from(arguments).is_err());
            }
        }
        let error = Args::try_parse_from([
            "native_reader",
            "image.img",
            "--ext4-journal",
            "a.img",
            "0",
            "rest",
            "--ext4-journal",
            "b.img",
            "0",
            "rest",
            "stat",
            "/",
        ])
        .unwrap_err();
        assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
    }

    #[test]
    fn auxiliary_format_selections_never_silently_override_another_format() {
        let selections: &[&[&str]] = &[
            &["--ext4-journal", "journal.img", "0", "rest"],
            &["--btrfs-device", "seed.img", "4096", "32768"],
            &["--ntfs-indexed-lookup"],
            &["--zfs-dataset", "data"],
            &["--zfs-snapshot", "before"],
        ];
        for first in 0..2 {
            for second in 0..selections.len() {
                if first == second {
                    continue;
                }
                for (left, right) in [(first, second), (second, first)] {
                    let mut arguments = vec!["native_reader", "image.img"];
                    arguments.extend(selections[left]);
                    arguments.extend(selections[right]);
                    arguments.extend(["stat", "/"]);
                    let error = Args::try_parse_from(arguments).unwrap_err();
                    assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
                }
            }
        }
    }

    #[test]
    fn mountpoint_refuses_an_auxiliary_backing_file_it_would_hide() {
        let root = tempfile::tempdir().unwrap().keep();
        let image = root.join("primary.img");
        std::fs::File::create_new(&image).unwrap();
        let mountpoint = root.join("mount");
        std::fs::create_dir(&mountpoint).unwrap();
        let auxiliary = mountpoint.join("member.img");
        std::fs::File::create_new(&auxiliary).unwrap();
        for option in ["--ext4-journal", "--btrfs-device"] {
            let args = Args::try_parse_from([
                OsString::from("native_reader"),
                image.as_os_str().to_owned(),
                OsString::from(option),
                auxiliary.as_os_str().to_owned(),
                OsString::from("0"),
                OsString::from("rest"),
                OsString::from("mount"),
                mountpoint.as_os_str().to_owned(),
            ])
            .unwrap();
            assert_eq!(
                read_only_mountpoint(&image, &args.backend().unwrap(), &mountpoint)
                    .unwrap_err()
                    .to_string(),
                "mountpoint would hide its backing image"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn auxiliary_paths_preserve_native_bytes_and_geometry_requires_ascii_numbers() {
        use std::os::unix::ffi::OsStringExt;
        let path = OsString::from_vec(b"member-\xff.img".to_vec());
        let mut arguments: Vec<OsString> = ["native_reader", "primary.img", "--btrfs-device"]
            .into_iter()
            .map(OsString::from)
            .collect();
        arguments.push(path.clone());
        arguments.extend(["8192", "rest", "stat", "/"].map(OsString::from));
        let args = Args::try_parse_from(arguments).unwrap();
        let ReadOnlyBackend::Btrfs {
            additional_devices, ..
        } = args.backend().unwrap()
        else {
            panic!("expected btrfs member selection");
        };
        assert_eq!(additional_devices[0].path.as_os_str(), path);
        let invalid_number = OsString::from_vec(vec![0xff]);
        assert!(image_sources(&[path.clone(), invalid_number.clone(), "rest".into()]).is_err());
        assert!(image_sources(&[path, "0".into(), invalid_number]).is_err());
    }
}
