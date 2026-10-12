#![forbid(unsafe_code)]
//! Native, read-only NTFS 3.1 inspection, directory traversal and stream extraction.

mod reader;
mod stream_name;

use anyhow::{Context, Result, bail};
use asupersync::Cx;
use clap::{Args, Parser, Subcommand};
use ffs_ondisk::ntfs::reparse::{NtfsReparseData, NtfsReparsePoint};
use ffs_ondisk::ntfs::{DATA, NtfsFileRecord, NtfsValue};
use reader::NtfsVolume;
use std::io::{self, Write};
use std::path::PathBuf;
use stream_name::StreamName;

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
        /// Exact Unicode stream name. Omit both selectors for unnamed DATA.
        #[arg(long, conflicts_with = "stream_utf16")]
        stream: Option<String>,
        /// Exact UTF-16 units, comma-separated four-digit hex (for example d800,0061).
        #[arg(long, value_parser = StreamName::parse, conflicts_with = "stream")]
        stream_utf16: Option<StreamName>,
        #[arg(long, default_value_t = 0)]
        start: u64,
        #[arg(long)]
        bytes: Option<u64>,
    },
    /// Show a relative symbolic link's target without following the final link.
    Readlink {
        #[command(flatten)]
        image: ImageArgs,
        path: String,
    },
    /// Enumerate logical DATA streams, including streams in extension records.
    Streams {
        #[command(flatten)]
        file: RecordArgs,
    },
    /// Retrieve the native security descriptor without projecting host permissions.
    Security {
        #[command(flatten)]
        file: RecordArgs,
        /// Write exact self-relative descriptor bytes instead of the JSON report.
        #[arg(long)]
        raw: bool,
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
        /// Exact Unicode stream name. Omit both selectors for unnamed DATA.
        #[arg(long, conflicts_with = "stream_utf16")]
        stream: Option<String>,
        /// Exact UTF-16 units, comma-separated four-digit hex (for example d800,0061).
        #[arg(long, value_parser = StreamName::parse, conflicts_with = "stream")]
        stream_utf16: Option<StreamName>,
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

fn security_json(info: &reader::security::SecurityDescriptorInfo) -> serde_json::Value {
    let descriptor = &info.descriptor;
    let acl = |value: &ffs_ondisk::ntfs_security::NtfsAcl| {
        let state = if !value.present {
            "absent"
        } else if value.offset == 0 {
            "null"
        } else {
            "present"
        };
        let aces: Vec<_> = value
            .aces
            .iter()
            .map(|ace| {
                serde_json::json!({
                    "kind": ace.kind,
                    "flags": ace.flags,
                    "size": ace.size,
                    "layout": if ace.sid.is_some() { "sid" } else { "opaque" },
                    "mask": ace.mask,
                    "sid": ace.sid.as_ref().map(ToString::to_string),
                    "object_flags": ace.object_flags,
                    "object_type_bytes": ace.object_type,
                    "inherited_object_type_bytes": ace.inherited_object_type,
                    "opaque_bytes": ace.opaque,
                })
            })
            .collect();
        serde_json::json!({
            "present": value.present,
            "offset": value.offset,
            "revision": value.revision,
            "ace_count": value.ace_count,
            "state": state,
            "size": value.size,
            "aces": aces,
            "unused_bytes": value.padding,
        })
    };
    serde_json::json!({
        "source": info.source,
        "security_id": info.security_id,
        "standard_security_id": info.standard_security_id,
        "legacy_attribute_present": info.legacy_attribute_present,
        "secure_reference": info.secure_reference.as_ref().map(|reference| {
            serde_json::json!({"record": reference.record, "sequence": reference.sequence})
        }),
        "hash": info.hash,
        "sds_offset": info.sds_offset,
        "descriptor_bytes": info.bytes,
        "control": descriptor.control,
        "resource_manager_control": descriptor.resource_manager_control,
        "owner": descriptor.owner.as_ref().map(ToString::to_string),
        "group": descriptor.group.as_ref().map(ToString::to_string),
        "sacl": acl(&descriptor.sacl),
        "dacl": acl(&descriptor.dacl),
        "access_evaluated": false,
        "scope": "native security metadata; no access evaluation or host ACL projection",
    })
}

fn reparse_json(point: &NtfsReparsePoint) -> serde_json::Value {
    let data = match &point.data {
        NtfsReparseData::SymbolicLink {
            substitute,
            print,
            relative,
        } => serde_json::json!({
            "kind": "symbolic_link", "relative": relative,
            "substitute": String::from_utf16(substitute).ok(), "substitute_utf16": substitute,
            "print": String::from_utf16(print).ok(), "print_utf16": print
        }),
        NtfsReparseData::MountPoint { substitute, print } => serde_json::json!({
            "kind": "mount_point",
            "substitute": String::from_utf16(substitute).ok(), "substitute_utf16": substitute,
            "print": String::from_utf16(print).ok(), "print_utf16": print
        }),
        NtfsReparseData::Opaque(bytes) => serde_json::json!({
            "kind": "opaque_provider", "payload_bytes": bytes
        }),
    };
    serde_json::json!({
        "tag": format!("{:#010x}", point.tag),
        "name_surrogate": point.is_name_surrogate(),
        "guid_bytes": point.guid, "data": data
    })
}

fn stream_to_stdout(
    cx: &Cx,
    volume: &NtfsVolume,
    record: &NtfsFileRecord,
    name: &[u16],
    start: u64,
    bytes: Option<u64>,
) -> Result<()> {
    if name.len() > 255 || name.contains(&0) {
        bail!("invalid NTFS stream name");
    }
    let stream = volume.data_stream(cx, record, name)?;
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
                        "directory": entry.directory,
                        "reparse_tag": entry.reparse_tag.map(|tag| format!("{tag:#010x}"))
                    })
                })
                .collect();
            json(&serde_json::json!(report))?;
        }
        Command::Read {
            image,
            path,
            stream,
            stream_utf16,
            start,
            bytes,
        } => {
            let stream =
                StreamName::select(stream.as_deref(), stream_utf16).map_err(anyhow::Error::msg)?;
            let volume = image.open(&cx)?;
            let record = volume.resolve(&cx, &path)?;
            stream_to_stdout(&cx, &volume, &record, stream.as_units(), start, bytes)?;
        }
        Command::Readlink { image, path } => {
            let volume = image.open(&cx)?;
            let record = volume.resolve_no_follow(&cx, &path)?;
            let target = volume.readlink(&cx, &record)?;
            let mut out = io::stdout().lock();
            out.write_all(&target)?;
            writeln!(out)?;
        }
        Command::Streams { file } => {
            let volume = file.image.open(&cx)?;
            let record = volume.record(&cx, file.record, file.sequence)?;
            let streams: Vec<_> = volume
                .data_streams(&cx, &record)?
                .into_iter()
                .map(|stream| {
                    let read_profile = match stream.read_profile {
                        Ok(metadata) => serde_json::json!({
                            "admitted": true,
                            "resident": metadata.resident,
                            "size": metadata.size,
                            "initialized": metadata.initialized,
                            "allocated_bytes": metadata.allocated,
                        }),
                        Err(error) => serde_json::json!({
                            "admitted": false, "error": error,
                        }),
                    };
                    serde_json::json!({
                        "name": String::from_utf16(&stream.name).ok(),
                        "name_utf16": stream.name,
                        "attribute_extents": stream.attribute_extents,
                        "read_profile": read_profile,
                    })
                })
                .collect();
            json(&serde_json::json!({
                "record": record.number,
                "sequence": record.sequence,
                "streams": streams,
                "scope": "complete DATA catalog; metadata admission does not verify payload bytes",
            }))?;
        }
        Command::Security { file, raw } => {
            let volume = file.image.open(&cx)?;
            let record = volume.record(&cx, file.record, file.sequence)?;
            let info = volume.security_descriptor(&cx, &record)?;
            if raw {
                let mut out = io::stdout().lock();
                out.write_all(&info.bytes)?;
                out.flush()?;
            } else {
                json(&serde_json::json!({
                    "record": record.number,
                    "sequence": record.sequence,
                    "security_descriptor": security_json(&info),
                }))?;
            }
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
                "attributes": attributes,
                "reparse_point": volume.reparse_point(&cx, &record)?.as_ref().map(reparse_json),
                "scope": "record metadata; listing does not certify stream readability"}),
            )?;
        }
        Command::Cat {
            file,
            stream,
            stream_utf16,
            start,
            bytes,
        } => {
            let stream =
                StreamName::select(stream.as_deref(), stream_utf16).map_err(anyhow::Error::msg)?;
            let volume = file.image.open(&cx)?;
            let record = volume.record(&cx, file.record, file.sequence)?;
            stream_to_stdout(&cx, &volume, &record, stream.as_units(), start, bytes)?;
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
    fn cli_security_keeps_native_record_identity_and_requires_offline_image() {
        assert!(Cli::try_parse_from(["ffs-ntfs", "security", "disk.img", "24"]).is_err());
        assert!(
            Cli::try_parse_from(["ffs-ntfs", "security", "disk.img", "--offline-image"]).is_err()
        );
        let cli = Cli::try_parse_from([
            "ffs-ntfs",
            "security",
            "disk.img",
            "24",
            "--offline-image",
            "--sequence",
            "7",
            "--offset",
            "1024",
            "--length",
            "65536",
            "--raw",
        ])
        .unwrap();
        let Command::Security { file, raw } = cli.command else {
            panic!("security");
        };
        assert_eq!((file.record, file.sequence), (24, Some(7)));
        assert_eq!((file.image.offset, file.image.length), (1024, Some(65536)));
        assert!(raw);
        let cli =
            Cli::try_parse_from(["ffs-ntfs", "security", "disk.img", "24", "--offline-image"])
                .unwrap();
        assert!(matches!(cli.command, Command::Security { raw: false, .. }));
        assert!(
            Cli::try_parse_from([
                "ffs-ntfs",
                "security",
                "disk.img",
                "24",
                "--offline-image",
                "--rw",
            ])
            .is_err()
        );
    }

    #[test]
    fn security_json_preserves_absent_null_and_empty_acl_distinctions() {
        for (control, acl_bytes, expected_present, expected_count) in [
            (0x8000_u16, Vec::new(), false, None),
            (0x8004, Vec::new(), true, None),
            (0x8004, vec![2, 0, 8, 0, 0, 0, 0, 0], true, Some(0_u16)),
        ] {
            let mut bytes = vec![0_u8; 20];
            bytes[0] = 1;
            bytes[2..4].copy_from_slice(&control.to_le_bytes());
            if !acl_bytes.is_empty() {
                bytes[16..20].copy_from_slice(&20_u32.to_le_bytes());
                bytes.extend_from_slice(&acl_bytes);
            }
            let info = reader::security::SecurityDescriptorInfo {
                source: "security_descriptor_attribute",
                security_id: None,
                standard_security_id: None,
                legacy_attribute_present: true,
                secure_reference: None,
                hash: None,
                sds_offset: None,
                descriptor: ffs_ondisk::ntfs_security::NtfsSecurityDescriptor::parse(&bytes)
                    .unwrap(),
                bytes: bytes.clone(),
            };
            let report = security_json(&info);
            assert_eq!(report["descriptor_bytes"], serde_json::json!(bytes));
            assert_eq!(report["dacl"]["present"], expected_present);
            assert_eq!(
                report["dacl"]["ace_count"],
                serde_json::json!(expected_count)
            );
            assert_eq!(
                report["dacl"]["offset"],
                if acl_bytes.is_empty() { 0 } else { 20 }
            );
            assert_eq!(report["sacl"]["present"], false);
            assert!(report["owner"].is_null());
            assert!(report["group"].is_null());
            assert!(report["security_id"].is_null());
            assert!(report["sds_offset"].is_null());
        }
    }

    #[test]
    fn security_json_preserves_ordered_known_and_opaque_aces_without_access_decisions() {
        let mut bytes = vec![
            1, 0, 4, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0,
        ];
        bytes.extend_from_slice(&[4, 0, 76, 0, 2, 0, 0, 0]);
        bytes.extend_from_slice(&[11, 3, 60, 0, 1, 0, 0, 0, 3, 0, 0, 0]);
        bytes.extend_from_slice(&[0xA1; 16]);
        bytes.extend_from_slice(&[0xB2; 16]);
        bytes.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0]);
        bytes.extend_from_slice(b"artx");
        bytes.extend_from_slice(&[0xFE, 0x40, 8, 0, 0xDE, 0xAD, 0xBE, 0xEF]);
        let info = reader::security::SecurityDescriptorInfo {
            source: "security_descriptor_attribute",
            security_id: None,
            standard_security_id: Some(0),
            legacy_attribute_present: true,
            secure_reference: None,
            hash: None,
            sds_offset: None,
            descriptor: ffs_ondisk::ntfs_security::NtfsSecurityDescriptor::parse(&bytes).unwrap(),
            bytes: bytes.clone(),
        };
        let report = security_json(&info);
        assert_eq!(report["descriptor_bytes"], serde_json::json!(bytes));
        assert_eq!(report["standard_security_id"], 0);
        assert!(report["security_id"].is_null());
        assert_eq!(report["legacy_attribute_present"], true);
        assert_eq!(report["dacl"]["state"], "present");
        assert_eq!(report["sacl"]["state"], "absent");
        assert_eq!(report["dacl"]["aces"][0]["kind"], 11);
        assert_eq!(report["dacl"]["aces"][0]["flags"], 3);
        assert_eq!(report["dacl"]["aces"][0]["sid"], "S-1-5-18");
        assert_eq!(report["dacl"]["aces"][0]["mask"], 1);
        assert_eq!(
            report["dacl"]["aces"][0]["object_type_bytes"],
            serde_json::json!(vec![0xA1; 16])
        );
        assert_eq!(
            report["dacl"]["aces"][0]["inherited_object_type_bytes"],
            serde_json::json!(vec![0xB2; 16])
        );
        assert_eq!(
            report["dacl"]["aces"][0]["opaque_bytes"],
            serde_json::json!([97, 114, 116, 120])
        );
        assert_eq!(report["dacl"]["aces"][1]["layout"], "opaque");
        assert!(report["dacl"]["aces"][1]["mask"].is_null());
        assert!(report["dacl"]["aces"][1]["sid"].is_null());
        assert_eq!(
            report["dacl"]["aces"][1]["opaque_bytes"],
            serde_json::json!([222, 173, 190, 239])
        );
        assert_eq!(report["access_evaluated"], false);
    }

    #[test]
    fn cli_readlink_requires_offline_image_and_keeps_the_final_path_literal() {
        assert!(Cli::try_parse_from(["ffs-ntfs", "readlink", "disk.img", "/link"]).is_err());
        let cli = Cli::try_parse_from([
            "ffs-ntfs",
            "readlink",
            "disk.img",
            "/Subdir/link",
            "--offline-image",
        ])
        .unwrap();
        let Command::Readlink { path, .. } = cli.command else {
            panic!("readlink");
        };
        assert_eq!(path, "/Subdir/link");
        let point = NtfsReparsePoint {
            tag: 0xA000_000C,
            guid: None,
            data: NtfsReparseData::SymbolicLink {
                substitute: vec![0xD800],
                print: vec![u16::from(b'x')],
                relative: true,
            },
        };
        let value = reparse_json(&point);
        assert_eq!(
            value["data"]["substitute_utf16"],
            serde_json::json!([0xD800])
        );
        assert!(value["data"]["substitute"].is_null());
        assert_eq!(value["data"]["print"], "x");
    }

    #[test]
    fn cli_streams_requires_offline_image_and_preserves_record_sequence() {
        assert!(Cli::try_parse_from(["ffs-ntfs", "streams", "disk.img", "24"]).is_err());
        let cli = Cli::try_parse_from([
            "ffs-ntfs",
            "streams",
            "disk.img",
            "24",
            "--offline-image",
            "--sequence",
            "7",
        ])
        .unwrap();
        let Command::Streams { file } = cli.command else {
            panic!("streams");
        };
        assert_eq!((file.record, file.sequence), (24, Some(7)));
        assert!(
            Cli::try_parse_from(["ffs-ntfs", "streams", "disk.img", "--offline-image"]).is_err()
        );
    }

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
            stream_utf16,
            start,
            bytes,
        } = cli.command
        else {
            panic!("cat");
        };
        assert_eq!((file.record, file.sequence), (24, Some(7)));
        assert_eq!(
            (stream.as_deref(), start, bytes),
            (Some("note"), 512, Some(1024))
        );
        assert!(stream_utf16.is_none());
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
            (path.as_str(), stream.as_deref(), start, bytes),
            ("/folder/Ä.bin", Some("note"), 3, Some(2))
        );
        assert!(Cli::try_parse_from(["ffs-ntfs", "read", "disk.img", "/a"]).is_err());
    }

    #[test]
    fn cli_raw_stream_selectors_preserve_units_in_path_and_record_reads() {
        for (command, target) in [("cat", "24"), ("read", "/file")] {
            let cli = Cli::try_parse_from([
                "ffs-ntfs",
                command,
                "disk.img",
                target,
                "--offline-image",
                "--stream-utf16",
                "d800,006E",
                "--start",
                "3",
                "--bytes",
                "2",
            ])
            .unwrap();
            let (stream, native, start, bytes) = match cli.command {
                Command::Read {
                    stream,
                    stream_utf16,
                    start,
                    bytes,
                    ..
                }
                | Command::Cat {
                    stream,
                    stream_utf16,
                    start,
                    bytes,
                    ..
                } => (stream, stream_utf16, start, bytes),
                _ => panic!("stream extraction"),
            };
            assert!(stream.is_none());
            assert_eq!(native.unwrap().as_units(), [0xD800, 0x006E]);
            assert_eq!((start, bytes), (3, Some(2)));
            assert!(
                Cli::try_parse_from([
                    "ffs-ntfs",
                    command,
                    "disk.img",
                    target,
                    "--offline-image",
                    "--stream",
                    "note",
                    "--stream-utf16",
                    "006E",
                ])
                .is_err()
            );
            assert!(
                Cli::try_parse_from([
                    "ffs-ntfs",
                    command,
                    "disk.img",
                    target,
                    "--offline-image",
                    "--stream-utf16",
                    "0000",
                ])
                .is_err()
            );
        }
    }
}
