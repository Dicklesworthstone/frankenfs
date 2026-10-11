//! ZPL path commands; host paths are never resolved from native directory data.

use super::{CandidateArgs, Cx, Result, bail, json};
use clap::{Args, Subcommand};
use ffs_ondisk::zfs_zpl::{Kind, Metadata};
use std::ffi::OsString;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

#[derive(Debug, Args)]
pub struct FileArgs {
    #[command(flatten)]
    candidate: CandidateArgs,
    /// Head dataset name relative to the pool. Empty selects the pool root.
    #[arg(long, default_value = "")]
    dataset: String,
    /// Exact native snapshot name. Omit to read the selected committed head.
    #[arg(long)]
    snapshot: Option<OsString>,
    /// Native path inside this dataset, not a host path. Symlinks are not followed.
    path: PathBuf,
}

#[derive(Debug, Subcommand)]
pub enum FileCommand {
    /// List validated native snapshots of one dataset; no import or rewind.
    Snapshots {
        #[command(flatten)]
        candidate: CandidateArgs,
        #[arg(long, default_value = "")]
        dataset: String,
    },
    /// List an admitted ZPL directory using native micro/fat-ZAP entries.
    Ls {
        #[command(flatten)]
        file: FileArgs,
    },
    /// Inspect native file metadata. UID/GID and modes are not ACL enforcement.
    Stat {
        #[command(flatten)]
        file: FileArgs,
    },
    /// Extract regular-file bytes bounded by ZPL_SIZE, not allocation geometry.
    Read {
        #[command(flatten)]
        file: FileArgs,
        #[arg(long, default_value_t = 0)]
        start: u64,
        #[arg(long)]
        bytes: Option<u64>,
    },
    /// Output the native symlink target without resolving or following it.
    Readlink {
        #[command(flatten)]
        file: FileArgs,
    },
}
enum Output {
    List,
    Stat,
    Read(u64, Option<u64>),
    Link,
}

fn metadata_json(number: u64, metadata: &Metadata) -> serde_json::Value {
    let times: Vec<_> = metadata
        .times
        .iter()
        .map(|time| serde_json::json!({"seconds": time.seconds, "nanoseconds": time.nanos}))
        .collect();
    serde_json::json!({"object": number, "kind": format!("{:?}", metadata.kind),
        "mode": metadata.mode, "size": metadata.size, "parent": metadata.parent,
        "links": metadata.links, "generation": metadata.generation, "flags": metadata.flags,
        "native_uid": metadata.uid, "native_gid": metadata.gid,
        "times_access_modify_change_create": times})
}
fn dataset_components(name: &str) -> Result<Vec<Vec<u8>>> {
    if name.is_empty() {
        return Ok(Vec::new());
    }
    if name.len() > 65_536 {
        bail!("dataset path is too long");
    }
    let mut result = Vec::new();
    for part in name.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.contains(['\0', '@', '#']) {
            bail!("expected a relative head dataset name, not a snapshot or host path");
        }
        result.push(part.as_bytes().to_vec());
        if result.len() > 64 {
            bail!("dataset path is too deep");
        }
    }
    Ok(result)
}
impl FileCommand {
    pub(super) fn run(self, cx: &Cx) -> Result<()> {
        let (file, output) = match self {
            Self::Snapshots { candidate, dataset } => {
                let components = dataset_components(&dataset)?;
                let leaf = candidate.image.open(cx)?;
                let mut pool = leaf.objects(cx, candidate.label, candidate.slot, candidate.pool_guid)?;
                let snapshots: Vec<_> = pool.snapshots(cx, &components)?.into_iter().map(|row| {
                    serde_json::json!({"name": std::str::from_utf8(&row.name).ok(), "name_bytes": row.name,
                        "object": row.object, "guid": row.guid.to_string(), "creation_txg": row.creation_txg,
                        "creation_time": row.creation_time, "root_birth": row.root_birth,
                        "referenced_bytes": row.referenced_bytes, "flags": row.flags, "objectset_kind": row.objectset_kind})
                }).collect();
                return json(&serde_json::json!({"pool_guid": candidate.pool_guid.to_string(), "dataset": dataset,
                    "txg": pool.txg, "snapshots": snapshots, "scope": "named snapshot roots in this committed pool view"}));
            }
            Self::Ls { file } => (file, Output::List),
            Self::Stat { file } => (file, Output::Stat),
            Self::Read { file, start, bytes } => (file, Output::Read(start, bytes)),
            Self::Readlink { file } => (file, Output::Link),
        };
        let components = dataset_components(&file.dataset)?;
        let c = file.candidate;
        let leaf = c.image.open(cx)?;
        let mut pool = leaf.objects(cx, c.label, c.slot, c.pool_guid)?;
        let txg = pool.txg;
        let mut view = match file.snapshot.as_deref() {
            Some(name) => pool.zpl_snapshot(cx, &components, name.as_bytes())?,
            None => pool.zpl(cx, &components)?,
        };
        let snapshot_name = file.snapshot.as_deref().and_then(|name| name.to_str());
        let snapshot_bytes = file.snapshot.as_deref().map(OsStrExt::as_bytes);
        let object = view.resolve(cx, file.path.as_os_str().as_bytes())?;
        match output {
            Output::List => {
                let entries: Vec<_> = view.list(cx, object)?.into_iter().map(|entry| {
                    serde_json::json!({"name": std::str::from_utf8(&entry.name).ok(),
                        "name_bytes": entry.name, "metadata": metadata_json(entry.object, &entry.metadata)})
                }).collect();
                json(
                    &serde_json::json!({"dataset_guid": view.dataset_guid.to_string(),
                    "txg": txg, "view_txg": view.view_txg(), "snapshot": snapshot_name, "snapshot_name_bytes": snapshot_bytes,
                    "zpl_version": view.version, "directory_object": object, "entries": entries}),
                )?;
            }
            Output::Stat => {
                let (metadata, allocated) = view.stat(cx, object)?;
                json(
                    &serde_json::json!({"dataset_guid": view.dataset_guid.to_string(), "txg": txg,
                    "view_txg": view.view_txg(), "snapshot": snapshot_name, "snapshot_name_bytes": snapshot_bytes,
                    "zpl_version": view.version, "metadata": metadata_json(object, &metadata),
                    "dnode_used_bytes": allocated, "scope": "native metadata; not host ACL enforcement"}),
                )?;
            }
            Output::Link => {
                let bytes = view.readlink(cx, object)?;
                let mut out = io::stdout().lock();
                out.write_all(&bytes)?;
                out.flush()?;
            }
            Output::Read(start, bytes) => {
                let (metadata, _) = view.stat(cx, object)?;
                if metadata.kind != Kind::Regular {
                    bail!("read requires a regular file; symlinks are not followed");
                }
                let length = metadata
                    .size
                    .saturating_sub(start)
                    .min(bytes.unwrap_or(u64::MAX));
                let mut done = 0_u64;
                let mut out = io::stdout().lock();
                while done < length {
                    let count = (length - done).min(1024 * 1024) as usize;
                    let data = view.read(cx, object, start + done, count)?;
                    if data.len() != count {
                        bail!("ZPL reader returned a short range before validated EOF");
                    }
                    out.write_all(&data)?;
                    done += data.len() as u64;
                }
                out.flush()?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Cli, Command};
    use clap::Parser;
    #[test]
    fn snapshot_selection_is_separate_from_dataset_paths_and_still_requires_a_candidate() {
        let options = ["--offline-image", "--pool-guid", "123", "--label", "0", "--slot", "2", "--dataset", "data"];
        let parsed = Cli::try_parse_from(["ffs-zfs", "snapshots", "leaf.img"].into_iter().chain(options)).unwrap();
        assert!(matches!(parsed.command, Command::File(FileCommand::Snapshots { .. })));
        for command in ["ls", "stat", "read", "readlink"] {
            let parsed = Cli::try_parse_from(["ffs-zfs", command, "leaf.img", "/file"].into_iter()
                .chain(options).chain(["--snapshot", "before"])).unwrap();
            let file = match parsed.command {
                Command::File(FileCommand::Ls { file } | FileCommand::Stat { file }
                    | FileCommand::Read { file, .. } | FileCommand::Readlink { file }) => file,
                _ => panic!("file command"),
            };
            assert_eq!(file.snapshot.as_deref().map(OsStrExt::as_bytes), Some(b"before".as_slice()));
        }
        assert!(Cli::try_parse_from(["ffs-zfs", "snapshots", "leaf.img", "--offline-image"]).is_err());
    }
    #[test]
    fn path_commands_retain_explicit_candidate_and_native_file_ranges() {
        let base = [
            "ffs-zfs",
            "read",
            "leaf.img",
            "/dir/file.bin",
            "--offline-image",
            "--pool-guid",
            "123",
            "--label",
            "0",
            "--slot",
            "2",
            "--dataset",
            "data",
        ];
        let args: Vec<_> = base
            .into_iter()
            .chain(["--start", "510", "--bytes", "600"])
            .collect();
        let parsed = Cli::try_parse_from(args).unwrap();
        let Command::File(FileCommand::Read { file, start, bytes }) = parsed.command else {
            panic!("read");
        };
        assert_eq!(
            (file.dataset.as_str(), start, bytes),
            ("data", 510, Some(600))
        );
        assert_eq!(file.path.as_os_str().as_bytes(), b"/dir/file.bin");
        assert!(Cli::try_parse_from(["ffs-zfs", "read", "leaf.img", "/file"]).is_err());
        assert!(Cli::try_parse_from(base.into_iter().chain(["--rw"])).is_err());
    }
    #[test]
    fn dataset_selection_cannot_be_a_host_path_or_snapshot() {
        assert_eq!(dataset_components("").unwrap(), [] as [Vec<u8>; 0]);
        assert_eq!(
            dataset_components("data/nested").unwrap(),
            [b"data".to_vec(), b"nested".to_vec()]
        );
        for name in [
            "/data",
            "data/",
            "data//nested",
            "../data",
            "data@snap",
            "data#bookmark",
            "a\0b",
        ] {
            assert!(dataset_components(name).is_err(), "{name:?}");
        }
    }
}
