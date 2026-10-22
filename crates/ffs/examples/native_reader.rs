#![forbid(unsafe_code)]
//! A standalone application consuming the public read-only native-image API.
//! File reads emit exact bytes; directory listings emit NUL-delimited names.

use asupersync::{Budget, Cx};
use clap::{Parser, Subcommand};
use ffs::{
    FileType, InodeAttr, InodeNumber, ReadOnlyBackend, ReadOnlyFs, ReadOnlyOpenOptions,
    RequestScope, ZfsReadOptions, open_read_only,
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

fn read_only_mountpoint(image: &Path, mountpoint: &Path) -> Result<PathBuf> {
    let mountpoint = mountpoint.canonicalize()?;
    if !mountpoint.is_dir() {
        return Err(invalid("mountpoint must be an existing empty directory").into());
    }
    if image.canonicalize()?.starts_with(&mountpoint) {
        return Err(invalid("mountpoint would hide its backing image").into());
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
    // The application owns the runtime and supplies its context to the library.
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()?;
    let cx = runtime.request_cx_with_budget(Budget::INFINITE);
    let backend = if args.ntfs_indexed_lookup {
        ReadOnlyBackend::Ntfs {
            indexed_lookup: true,
        }
    } else if args.zfs_dataset.is_empty() && args.zfs_snapshot.is_none() {
        ReadOnlyBackend::Auto
    } else {
        ReadOnlyBackend::Zfs(ZfsReadOptions {
            dataset: args
                .zfs_dataset
                .iter()
                .map(|name| name.as_encoded_bytes().to_vec())
                .collect(),
            snapshot: args
                .zfs_snapshot
                .as_ref()
                .map(|name| name.as_encoded_bytes().to_vec()),
            ..ZfsReadOptions::default()
        })
    };
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
        Command::Mount { mountpoint } => {
            let mountpoint = read_only_mountpoint(&args.image, &mountpoint)?;
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
        assert_eq!(
            read_only_mountpoint(&image, &mountpoint).unwrap(),
            mountpoint.canonicalize().unwrap()
        );
        assert!(read_only_mountpoint(&image, &root.join("missing")).is_err());
        assert!(read_only_mountpoint(&image, &image).is_err());
        assert_eq!(
            read_only_mountpoint(&image, &root).unwrap_err().to_string(),
            "mountpoint would hide its backing image"
        );
        std::fs::File::create_new(mountpoint.join("visible.txt")).unwrap();
        assert_eq!(
            read_only_mountpoint(&image, &mountpoint)
                .unwrap_err()
                .to_string(),
            "mountpoint must be an existing empty directory"
        );
    }
}
