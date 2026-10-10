#![forbid(unsafe_code)]
//! Native, read-only NTFS 3.1 inspection, directory traversal and stream extraction.

mod reader;

use anyhow::{Context, Result, bail};
use asupersync::Cx;
use clap::{Args, Parser, Subcommand};
use ffs_ondisk::ntfs::{DATA, NtfsFileRecord, NtfsValue};
use reader::NtfsVolume;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "ffs-ntfs",
    about = "Inspect immutable NTFS images and extract streams without replay or writes"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Args)]
struct ImageArgs {
    image: PathBuf,
    /// Byte offset of an already selected NTFS volume, not a sector number.
    #[arg(long, default_value_t = 0)]
    offset: u64,
    /// Restrict all reads to this many bytes of the selected volume.
    #[arg(long)]
    length: Option<u64>,
    /// Confirm the image is immutable and not mounted by another writer.
    #[arg(long, required = true)]
    offline_image: bool,
}
impl ImageArgs {
    fn open(&self, cx: &Cx) -> Result<NtfsVolume> {
        if !self.offline_image {
            bail!(
                "--offline-image is required; an advisory lock does not prevent unrelated writers"
            );
        }
        NtfsVolume::open(cx, &self.image, self.offset, self.length)
            .with_context(|| format!("opening offline NTFS image {}", self.image.display()))
    }
}

#[derive(Debug, Args)]
struct RecordArgs {
    #[command(flatten)]
    image: ImageArgs,
    /// MFT record number, not an on-disk byte offset or a host path.
    record: u64,
    /// Refuse a stale file reference if the sequence number differs.
    #[arg(long)]
    sequence: Option<u16>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Check geometry, MFT bootstrap/mirror agreement and volume version/flags.
    Inspect {
        #[command(flatten)]
        image: ImageArgs,
    },
    /// List a directory through native $I30 indexes, retaining raw UTF-16 names.
    Ls {
        #[command(flatten)]
        image: ImageArgs,
        #[arg(default_value = "/")]
        path: String,
    },
    /// Resolve an image path with its native UpCase table and extract DATA.
    Read {
        #[command(flatten)]
        image: ImageArgs,
        path: String,
        #[arg(long, default_value = "")]
        stream: String,
        #[arg(long, default_value_t = 0)]
        start: u64,
        #[arg(long)]
        bytes: Option<u64>,
    },
    /// Show the attributes and native UTF-16 stream names of an in-use MFT record.
    Record {
        #[command(flatten)]
        file: RecordArgs,
    },
    /// Stream logical DATA bytes to stdout, including sparse/uninitialized zeroes.
    Cat {
        #[command(flatten)]
        file: RecordArgs,
        /// Exact native stream name. Empty selects the unnamed DATA stream.
        #[arg(long, default_value = "")]
        stream: String,
        /// Logical starting byte within the stream.
        #[arg(long, default_value_t = 0)]
        start: u64,
        /// Maximum number of output bytes; defaults to the remaining stream.
        #[arg(long)]
        bytes: Option<u64>,
    },
    /// Mount an immutable image using FrankenFS's native read-only FUSE adapter.
    Mount {
        #[command(flatten)]
        image: ImageArgs,
        /// Existing empty directory; must not contain the backing image.
        mountpoint: PathBuf,
        /// Synthetic host ownership, not an NTFS SID/ACL mapping.
        #[arg(long, default_value_t = 0)]
        uid: u32,
        #[arg(long, default_value_t = 0)]
        gid: u32,
    },
}

fn json(value: &serde_json::Value) -> Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, value)?;
    writeln!(out)?;
    Ok(())
}

fn stream_to_stdout(
    cx: &Cx,
    volume: &NtfsVolume,
    record: &NtfsFileRecord,
    name: &str,
    start: u64,
    bytes: Option<u64>,
) -> Result<()> {
    let name: Vec<u16> = name.encode_utf16().collect();
    if name.len() > 255 || name.contains(&0) {
        bail!("invalid NTFS stream name");
    }
    let stream = volume.data_stream(cx, record, &name)?;
    let length = stream
        .size
        .saturating_sub(start)
        .min(bytes.unwrap_or(u64::MAX));
    let mut done = 0_u64;
    let mut out = io::stdout().lock();
    while done < length {
        let count = (length - done).min(1024 * 1024) as usize;
        let data = volume.read(cx, &stream, start + done, count)?;
        if data.is_empty() {
            bail!("NTFS stream ended before the validated logical EOF");
        }
        out.write_all(&data)?;
        done += data.len() as u64;
    }
    out.flush()?;
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cx = Cx::for_request();
    match cli.command {
        Command::Inspect { image } => {
            let volume = image.open(&cx)?;
            let g = &volume.geometry;
            json(&serde_json::json!({
                "format": "NTFS", "version": "3.1", "read_only": true,
                "volume_offset": image.offset, "volume_bytes": g.volume_bytes(),
                "sector_bytes": g.sector_bytes(), "cluster_bytes": g.cluster_bytes(),
                "record_bytes": g.record_bytes(), "index_bytes": g.index_bytes(),
                "serial": format!("{:016x}", g.serial()), "mft_cluster": g.mft_cluster(),
                "mirror_cluster": g.mirror_cluster(), "initialized_mft_records": volume.record_count(),
                "mft_mirror_record_zero_matches": true, "volume_flags": 0,
                "scope": "offline MFT/stream read profile; not a filesystem check or recovery validation"
            }))?;
        }
        Command::Ls { image, path } => {
            let volume = image.open(&cx)?;
            let record = volume.resolve(&cx, &path)?;
            let entries = volume.list_directory(&cx, &record)?;
            let report: Vec<_> = entries
                .into_iter()
                .map(|entry| {
                    serde_json::json!({
                        "record": entry.reference.record, "sequence": entry.reference.sequence,
                        "name": String::from_utf16(&entry.filename.name).ok(),
                        "name_utf16": entry.filename.name, "namespace": entry.filename.namespace,
                        "directory": entry.directory
                    })
                })
                .collect();
            json(&serde_json::json!(report))?;
        }
        Command::Read {
            image,
            path,
            stream,
            start,
            bytes,
        } => {
            let volume = image.open(&cx)?;
            let record = volume.resolve(&cx, &path)?;
            stream_to_stdout(&cx, &volume, &record, &stream, start, bytes)?;
        }
        Command::Record { file } => {
            let volume = file.image.open(&cx)?;
            let record = volume.record(&cx, file.record, file.sequence)?;
            let mut attributes = Vec::new();
            for attr in record.attributes()? {
                let (resident, size, initialized, first_vcn, last_vcn) = match &attr.value {
                    NtfsValue::Resident(data) => {
                        (true, data.len() as u64, data.len() as u64, None, None)
                    }
                    NtfsValue::NonResident(value) => (
                        false,
                        value.data_bytes,
                        value.initialized_bytes,
                        Some(value.first_vcn),
                        Some(value.last_vcn),
                    ),
                };
                let readability = if attr.kind == DATA {
                    match volume.data_stream(&cx, &record, &attr.name) {
                        Ok(stream) => Some(
                            serde_json::json!({"admitted": true, "allocated_bytes": stream.allocated}),
                        ),
                        Err(ffs_error::FfsError::Cancelled) => {
                            return Err(ffs_error::FfsError::Cancelled.into());
                        }
                        Err(error) => {
                            Some(serde_json::json!({"admitted": false, "error": error.to_string()}))
                        }
                    }
                } else {
                    None
                };
                attributes.push(serde_json::json!({
                    "type": format!("{:#x}", attr.kind), "instance": attr.id, "flags": attr.flags,
                    "name": String::from_utf16(&attr.name).ok(), "name_utf16": attr.name,
                    "resident": resident, "size": size, "initialized": initialized,
                    "first_vcn": first_vcn, "last_vcn": last_vcn, "read_profile": readability
                }));
            }
            json(
                &serde_json::json!({"record": record.number, "sequence": record.sequence,
                "directory": record.is_directory(), "hard_links": record.hard_links,
                "base_record": record.base.record, "base_sequence": record.base.sequence,
                "attributes": attributes, "scope": "record metadata; listing does not certify stream readability"}),
            )?;
        }
        Command::Cat {
            file,
            stream,
            start,
            bytes,
        } => {
            let volume = file.image.open(&cx)?;
            let record = volume.record(&cx, file.record, file.sequence)?;
            stream_to_stdout(&cx, &volume, &record, &stream, start, bytes)?;
        }
        Command::Mount {
            image,
            mountpoint,
            uid,
            gid,
        } => {
            let mountpoint = mountpoint
                .canonicalize()
                .context("resolve NTFS mountpoint")?;
            if !mountpoint.is_dir()
                || std::fs::read_dir(&mountpoint)?
                    .next()
                    .transpose()?
                    .is_some()
            {
                bail!("NTFS mountpoint must be an existing empty directory");
            }
            if image.image.canonicalize()?.starts_with(&mountpoint) {
                bail!("NTFS mountpoint would hide its backing image");
            }
            let volume = image.open(&cx)?;
            let fs = reader::filesystem::NtfsFs::new(&cx, volume, uid, gid)?;
            let options = ffs_fuse::MountOptions {
                read_only: true,
                allow_other: false,
                auto_unmount: true,
                ..ffs_fuse::MountOptions::default()
            };
            eprintln!(
                "experimental NTFS read-only mount: offline immutable image required; no log replay or native ACL enforcement"
            );
            let _ = ffs_fuse::mount(Box::new(fs), &mountpoint, &options)?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_mount_requires_offline_acknowledgement_and_refuses_write_options() {
        assert!(Cli::try_parse_from(["ffs-ntfs", "mount", "disk.img", "/mnt/ntfs"]).is_err());
        let cli = Cli::try_parse_from([
            "ffs-ntfs",
            "mount",
            "disk.img",
            "/mnt/ntfs",
            "--offline-image",
            "--offset",
            "1024",
            "--length",
            "65536",
            "--uid",
            "123",
            "--gid",
            "456",
        ])
        .unwrap();
        let Command::Mount {
            image,
            mountpoint,
            uid,
            gid,
        } = cli.command
        else {
            panic!("mount");
        };
        assert_eq!(
            (image.offset, image.length, uid, gid),
            (1024, Some(65536), 123, 456)
        );
        assert_eq!(mountpoint, PathBuf::from("/mnt/ntfs"));
        assert!(
            Cli::try_parse_from([
                "ffs-ntfs",
                "mount",
                "disk.img",
                "/mnt/ntfs",
                "--offline-image",
                "--rw",
            ])
            .is_err()
        );
    }
    #[test]
    fn cli_requires_offline_acknowledgement_and_accepts_record_ranges() {
        assert!(Cli::try_parse_from(["ffs-ntfs", "inspect", "disk.img"]).is_err());
        let cli = Cli::try_parse_from([
            "ffs-ntfs",
            "cat",
            "disk.img",
            "24",
            "--offline-image",
            "--sequence",
            "7",
            "--stream",
            "note",
            "--start",
            "512",
            "--bytes",
            "1024",
        ])
        .unwrap();
        let Command::Cat {
            file,
            stream,
            start,
            bytes,
        } = cli.command
        else {
            panic!("cat");
        };
        assert_eq!((file.record, file.sequence), (24, Some(7)));
        assert_eq!((stream.as_str(), start, bytes), ("note", 512, Some(1024)));
        assert!(
            Cli::try_parse_from(["ffs-ntfs", "inspect", "disk.img", "--offline-image", "--rw"])
                .is_err()
        );
    }
    #[test]
    fn cli_accepts_directory_and_path_reads_without_reinterpreting_numeric_cat() {
        let cli = Cli::try_parse_from(["ffs-ntfs", "ls", "disk.img", "--offline-image"]).unwrap();
        let Command::Ls { path, .. } = cli.command else {
            panic!("ls");
        };
        assert_eq!(path, "/");
        let cli = Cli::try_parse_from([
            "ffs-ntfs",
            "read",
            "disk.img",
            "/folder/Ä.bin",
            "--offline-image",
            "--stream",
            "note",
            "--start",
            "3",
            "--bytes",
            "2",
        ])
        .unwrap();
        let Command::Read {
            path,
            stream,
            start,
            bytes,
            ..
        } = cli.command
        else {
            panic!("read");
        };
        assert_eq!(
            (path.as_str(), stream.as_str(), start, bytes),
            ("/folder/Ä.bin", "note", 3, Some(2))
        );
        assert!(Cli::try_parse_from(["ffs-ntfs", "read", "disk.img", "/a"]).is_err());
    }
}
