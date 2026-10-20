#![forbid(unsafe_code)]
//! Native read-only ZFS label inspection and explicit MOS-root extraction.

macro_rules! companion_bin_tests {
    ($($item:item)*) => {
        $($item)*
    };
}

mod allocation_commands;
mod file_commands;
mod filesystem;
mod properties_commands;
mod reader;

use anyhow::{Context, Result, bail};
use asupersync::Cx;
use clap::{Args, Parser, Subcommand};
use ffs_error::FfsError;
use ffs_ondisk::zfs::UBERBLOCK_RING_BYTES;
use reader::{Leaf, Pool};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Parser)]
#[command(
    name = "ffs-zfs",
    about = "Inspect offline ZFS leaves without importing, replaying or writing"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
struct ReadOnlySidecar(ffs_repair::sidecar::live::SidecarImageDevice);

impl ffs_block::ByteDevice for ReadOnlySidecar {
    fn len_bytes(&self) -> u64 {
        self.0.len_bytes()
    }
    fn read_exact_at(
        &self,
        cx: &Cx,
        offset: ffs_types::ByteOffset,
        data: &mut [u8],
    ) -> ffs_error::Result<()> {
        self.0.read_exact_at(cx, offset, data)
    }
    fn write_all_at(
        &self,
        _cx: &Cx,
        _offset: ffs_types::ByteOffset,
        _data: &[u8],
    ) -> ffs_error::Result<()> {
        Err(FfsError::ReadOnly)
    }
    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)
    }
}

#[derive(Debug, Args)]
struct ImageArgs {
    /// Immutable regular image containing a selected physical vdev.
    image: PathBuf,
    #[arg(long, default_value_t = 0)]
    offset: u64,
    #[arg(long)]
    length: Option<u64>,
    /// Acknowledge no kernel or external writer will modify the image.
    #[arg(long, required = true)]
    offline_image: bool,
    /// Optional RaptorQ sidecar archive for read-verification and repair.
    #[arg(long)]
    sidecar: Option<PathBuf>,
}
impl ImageArgs {
    fn open(&self, cx: &Cx) -> Result<Leaf> {
        if !self.offline_image {
            bail!("--offline-image is required");
        }
        if let Some(sidecar) = &self.sidecar {
            // Blocking caller writes in the wrapper does not prevent an inner
            // writable reader from healing the image. Remove that authority.
            let device = ffs_repair::sidecar::live::SidecarImageDevice::open_read_only(
                cx,
                &self.image,
                sidecar,
            )
            .with_context(|| {
                format!(
                    "admitting ZFS image {} with sidecar {}",
                    self.image.display(),
                    sidecar.display()
                )
            })?;
            let size = ffs_block::ByteDevice::len_bytes(&device);
            return Leaf::from_device(
                cx,
                Box::new(ReadOnlySidecar(device)),
                self.offset,
                self.length
                    .unwrap_or_else(|| size.saturating_sub(self.offset)),
            )
            .context("opening sidecar-protected ZFS leaf");
        }
        Leaf::open(cx, &self.image, self.offset, self.length).context("opening selected ZFS leaf")
    }
}
#[derive(Debug, Args)]
struct CandidateArgs {
    #[command(flatten)]
    image: ImageArgs,
    /// Automatically import the highest-TXG active/exported uberblock across all 4 labels.
    #[arg(long)]
    auto_import: bool,
    /// Replay uncommitted ZIL intent-log blocks onto ZPL head dataset views.
    #[arg(long)]
    pub replay_zil: bool,
    #[arg(long, default_value_t = 0, required_unless_present = "auto_import")]
    label: usize,
    #[arg(long, default_value_t = 0, required_unless_present = "auto_import")]
    slot: usize,
    /// Expected pool GUID; optional when --auto-import is set.
    #[arg(long, default_value_t = 0, required_unless_present = "auto_import")]
    pool_guid: u64,
    /// Additional immutable images of every other leaf in one mirror, RAIDZ1/2/3, or striped pool.
    /// The same --offset and --length select the volume range in every image.
    #[arg(
        long = "member",
        visible_aliases = ["mirror-member", "raidz-member", "striped-member"],
        value_name = "IMAGE"
    )]
    members: Vec<PathBuf>,
    /// Explicitly absent child GUID of one exported mirror; repeat for every missing disk.
    /// Requires an explicit candidate and never enables import, replay or healing.
    #[arg(
        long = "missing-mirror-member",
        value_name = "GUID",
        conflicts_with_all = ["auto_import", "replay_zil"]
    )]
    missing_mirror_members: Vec<u64>,
    /// Explicitly absent child GUID of one exported RAIDZ1/2/3 group.
    /// Repeat for every missing disk; missing count must fit native parity.
    #[arg(
        long = "missing-raidz-member",
        value_name = "GUID",
        conflicts_with_all = ["auto_import", "replay_zil", "missing_mirror_members"]
    )]
    missing_raidz_members: Vec<u64>,
}
impl CandidateArgs {
    fn open(&self, cx: &Cx) -> Result<Pool> {
        if self.members.len() > 7 {
            bail!("at most seven additional member images are supported");
        }
        if !self.missing_raidz_members.is_empty() {
            Pool::check_raidz_survivors(self.members.len() + 1, &self.missing_raidz_members)?;
            if !self.missing_mirror_members.is_empty()
                || self.auto_import || self.replay_zil || self.pool_guid == 0
            {
                bail!("missing RAIDZ members require explicit pool/candidate selection without mirror declarations, import or replay");
            }
        }
        if !self.missing_mirror_members.is_empty() {
            Pool::check_mirror_survivors(self.members.len() + 1, &self.missing_mirror_members)?;
            if self.auto_import || self.replay_zil || self.pool_guid == 0 {
                bail!("missing mirror members require explicit pool/candidate selection without import or replay");
            }
        }
        let mut leaves = Vec::with_capacity(self.members.len() + 1);
        leaves.push(self.image.open(cx)?);
        for path in &self.members {
            leaves.push(
                Leaf::open(cx, path, self.image.offset, self.image.length)
                    .with_context(|| format!("opening ZFS member {}", path.display()))?,
            );
        }
        if !self.missing_raidz_members.is_empty() {
            let pool = Pool::from_raidz_survivors(cx, leaves, self.missing_raidz_members.clone())
                .context("admitting explicitly missing ZFS RAIDZ members")?;
            eprintln!(
                "explicit missing-RAIDZ extraction: pool_guid={} label={} slot={} absent_guids={:?}; selected committed view only, not newest-state authority, log recovery or pool import",
                self.pool_guid, self.label, self.slot, self.missing_raidz_members
            );
            Ok(pool)
        } else if self.missing_mirror_members.is_empty() {
            Pool::from_leaves(leaves).context("opening explicitly supplied ZFS members")
        } else {
            let pool = Pool::from_mirror_survivors(cx, leaves, self.missing_mirror_members.clone())
                .context("admitting explicitly missing ZFS mirror members")?;
            eprintln!(
                "explicit missing-mirror extraction: pool_guid={} label={} slot={} absent_guids={:?}; selected committed view only, not newest-state authority or pool import",
                self.pool_guid, self.label, self.slot, self.missing_mirror_members
            );
            Ok(pool)
        }
    }

    fn expected_pool_guid(&self) -> Option<u64> {
        (self.pool_guid != 0).then_some(self.pool_guid)
    }

    fn root(&self, cx: &Cx) -> Result<reader::RootBlock> {
        let pool = self.open(cx)?;
        if self.auto_import {
            Ok(pool.import_active(cx, self.expected_pool_guid())?.2)
        } else {
            Ok(pool.root(cx, self.label, self.slot, self.pool_guid)?)
        }
    }

    fn objects(&self, cx: &Cx) -> Result<reader::dmu::Objects> {
        let pool = self.open(cx)?;
        if self.auto_import {
            Ok(pool.import_objects(cx, self.expected_pool_guid())?)
        } else {
            Ok(pool.objects(cx, self.label, self.slot, self.pool_guid)?)
        }
    }

    fn reject_hidden_images(&self, mountpoint: &Path) -> Result<()> {
        for path in std::iter::once(&self.image.image).chain(&self.members) {
            if path.canonicalize()?.starts_with(mountpoint) {
                bail!("ZFS mountpoint would hide a backing image");
            }
        }
        Ok(())
    }
}
#[derive(Debug, Subcommand)]
enum Command {
    #[command(flatten)]
    Allocation(allocation_commands::AllocationCommand),
    #[command(flatten)]
    File(file_commands::FileCommand),
    #[command(flatten)]
    Properties(properties_commands::PropertyCommand),
    /// Inventory checksum-valid configurations and uberblock candidates, not pool authority.
    Inspect {
        #[command(flatten)]
        image: ImageArgs,
    },
    /// Extract one checked META object-set block.
    Root {
        #[command(flatten)]
        candidate: CandidateArgs,
    },
    /// Inspect one native MOS dnode and its exact bonus bytes.
    Object {
        #[command(flatten)]
        candidate: CandidateArgs,
        number: u64,
    },
    /// Extract an explicit raw DMU range, not a ZPL file or inferred logical EOF.
    ObjectRead {
        #[command(flatten)]
        candidate: CandidateArgs,
        number: u64,
        #[arg(long, default_value_t = 0)]
        start: u64,
        /// Required explicit count; maximum 16 MiB.
        #[arg(long)]
        bytes: usize,
    },
    /// Enumerate complete micro/fat-ZAP string keys and typed integer arrays.
    Zap {
        #[command(flatten)]
        candidate: CandidateArgs,
        number: u64,
    },
    /// Inventory DSL head datasets beneath this MOS.
    Datasets {
        #[command(flatten)]
        candidate: CandidateArgs,
    },
}
fn json(value: &serde_json::Value) -> Result<()> {
    let mut out = io::stdout().lock();
    serde_json::to_writer_pretty(&mut out, value)?;
    writeln!(out)?;
    Ok(())
}
fn main() -> Result<()> {
    let cli = Cli::parse();
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .map_err(|err| anyhow::anyhow!("failed to build ffs-zfs runtime: {err}"))?;
    let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    match cli.command {
        Command::Allocation(command) => command.run(&cx)?,
        Command::File(command) => command.run(&cx)?,
        Command::Properties(command) => command.run(&cx)?,
        Command::Inspect { image } => {
            let leaf = image.open(&cx)?;
            let mut labels = Vec::new();
            let mut valid = 0;
            for index in 0..4 {
                match leaf.label(&cx, index) {
                    Ok(label) => {
                        valid += 1;
                        let config = &label.config;
                        let mut candidates = Vec::new();
                        let mut rejected = 0;
                        for slot in 0..UBERBLOCK_RING_BYTES / label.slot_bytes {
                            match leaf.uberblock(&cx, &label, slot) {
                                Ok(ub) => candidates.push(serde_json::json!({
                                    "slot": slot, "txg": ub.txg, "timestamp": ub.timestamp,
                                    "byte_order": format!("{:?}", ub.order), "guid_sum": ub.guid_sum.to_string(),
                                    "root_logical_bytes": ub.root.logical_bytes(), "root_physical_bytes": ub.root.physical_bytes(),
                                    "root_compression": ub.root.compression(), "root_checksum": ub.root.checksum_type()
                                })),
                                Err(FfsError::Cancelled) => return Err(FfsError::Cancelled.into()),
                                Err(_) => rejected += 1,
                            }
                        }
                        labels.push(serde_json::json!({
                            "label": index, "offset": label.offset, "checksum_valid": true,
                            "byte_order": format!("{:?}", label.order), "slot_bytes": label.slot_bytes,
                            "pool_name": config.text("name"), "pool_guid": config.unsigned("pool_guid").map(|guid| guid.to_string()),
                            "leaf_guid": config.unsigned("guid").map(|guid| guid.to_string()),
                            "version": config.unsigned("version"), "state": config.unsigned("state"), "config_txg": config.unsigned("txg"),
                            "vdev_type": config.list("vdev_tree").and_then(|tree| tree.text("type")),
                            "read_features": config.list("features_for_read").map(|features| features.fields.keys().collect::<Vec<_>>()),
                            "candidates": candidates, "empty_invalid_or_unsupported_slots": rejected
                        }));
                    }
                    Err(FfsError::Cancelled) => return Err(FfsError::Cancelled.into()),
                    Err(error) => labels.push(serde_json::json!({"label": index, "accepted": false, "error": error.to_string()})),
                }
            }
            let report = serde_json::json!({"format": "ZFS", "read_only": true,
                "scope": "label and uberblock candidates only; no pool import, root authority or dataset validation",
                "valid_configurations": valid, "labels": labels});
            let mut out = io::stdout().lock();
            serde_json::to_writer_pretty(&mut out, &report)?;
            writeln!(out)?;
            if valid == 0 {
                bail!("no supported checksum-valid ZFS label configuration");
            }
        }
        Command::Root { candidate } => {
            let root = candidate.root(&cx)?;
            if let Some(stripe) = &root.raidz {
                eprintln!(
                    "checked candidate txg={} copy={} raidz{}_dva_offset={} allocated_bytes={} bytes={} parity_read={} reconstructed_children={:?}; not a pool import",
                    root.uberblock.txg,
                    root.copy_index,
                    stripe.columns.iter().filter(|column| column.parity).count(),
                    stripe.dva_offset,
                    stripe.allocated_bytes,
                    root.data.len(),
                    stripe.parity_read,
                    stripe.reconstructed_children,
                );
                for column in &stripe.columns {
                    eprintln!(
                        "  child={} member_guid={} vdev_offset={} bytes={} role={}",
                        column.child_id,
                        column.member_guid,
                        column.physical_offset,
                        column.bytes,
                        if column.bytes == 0 {
                            "skip"
                        } else if column.parity {
                            "parity"
                        } else {
                            "data"
                        },
                    );
                }
            } else {
                eprintln!(
                    "checked candidate txg={} copy={} member_guid={} vdev_offset={} bytes={}; not a pool import",
                    root.uberblock.txg,
                    root.copy_index,
                    root.member_guid,
                    root.physical_offset,
                    root.data.len()
                );
            }
            let mut out = io::stdout().lock();
            out.write_all(&root.data)?;
            out.flush()?;
        }
        Command::Object { candidate, number } => {
            let mut view = candidate.objects(&cx)?;
            let node = view.object(&cx, number)?;
            json(&serde_json::json!({"object": number, "txg": view.txg,
                "object_type": node.object_type(), "bonus_type": node.bonus_type(),
                "slots": node.slots(), "levels": node.levels(), "data_block_bytes": node.data_bytes(),
                "max_block_id": node.max_block(), "used_bytes": node.used_bytes(),
                "byte_order": format!("{:?}", node.order()), "bonus": node.bonus(),
                "has_spill": node.spill().is_some(),
                "scope": "native MOS dnode metadata; allocation geometry is not file EOF"}))?;
        }
        Command::ObjectRead {
            candidate,
            number,
            start,
            bytes,
        } => {
            let mut view = candidate.objects(&cx)?;
            let data = view.read(&cx, number, start, bytes)?;
            let mut out = io::stdout().lock();
            out.write_all(&data)?;
            out.flush()?;
        }
        Command::Zap { candidate, number } => {
            let mut view = candidate.objects(&cx)?;
            let entries: Vec<_> = view.zap_values(&cx, number)?.into_iter().map(|entry| serde_json::json!({
                "name": std::str::from_utf8(&entry.name).ok(), "name_bytes": entry.name,
                "integer_bytes": entry.integer_bytes, "values": entry.values, "collision": entry.collision
            })).collect();
            json(&serde_json::json!({"object": number, "txg": view.txg, "entries": entries}))?;
        }
        Command::Datasets { candidate } => {
            let mut view = candidate.objects(&cx)?;
            let pool_guid = view.pool_guid();
            let datasets: Vec<_> = view.datasets(&cx)?.into_iter().map(|entry| {
                let name = entry.components.iter().map(|part| std::str::from_utf8(part))
                    .collect::<std::result::Result<Vec<_>, _>>().ok().map(|parts| parts.join("/"));
                serde_json::json!({"relative_name": name, "components_bytes": entry.components,
                    "directory_object": entry.directory_object, "dataset_object": entry.head_object,
                    "guid": entry.guid.to_string(), "creation_txg": entry.creation_txg,
                    "flags": entry.flags, "objectset_kind": entry.objectset_kind, "root_birth": entry.root_birth})
            }).collect();
            json(
                &serde_json::json!({"pool_guid": pool_guid.to_string(), "txg": view.txg,
                "datasets": datasets, "scope": "verified DSL head inventory; no snapshots, import or ZPL mount"}),
            )?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_read_only_admission_coexists_with_a_retained_reader() {
        use ffs_repair::sidecar::live::SidecarImageDevice;
        use ffs_repair::sidecar::{SidecarOptions, protect};

        let directory = tempfile::tempdir().unwrap();
        let image = directory.path().join("source.img");
        let archive = directory.path().join("source.ffs-rq");
        let original = vec![0_u8; 4096];
        std::fs::write(&image, &original).unwrap();
        let cx = Cx::for_testing();
        protect(
            &cx,
            &image,
            &archive,
            SidecarOptions {
                block_size: 512,
                group_blocks: 8,
                repair_symbols: 4,
            },
        )
        .unwrap();
        let before = std::fs::read(&archive).unwrap();
        let _reader = SidecarImageDevice::open_read_only(&cx, &image, &archive).unwrap();
        let args = ImageArgs {
            image: image.clone(),
            offset: 0,
            length: Some(1),
            offline_image: true,
            sidecar: Some(archive.clone()),
        };
        let Err(error) = args.open(&cx) else {
            panic!("one-byte native volume must be refused");
        };
        // An exclusive writable open fails at sidecar admission. A genuine
        // read-only caller reaches native geometry admission while sharing locks.
        assert!(
            error
                .to_string()
                .contains("opening sidecar-protected ZFS leaf")
        );
        assert_eq!(std::fs::read(&image).unwrap(), original);
        assert_eq!(std::fs::read(&archive).unwrap(), before);
        assert!(SidecarImageDevice::open(&cx, &image, &archive).is_err());
    }

    #[test]
    fn cli_requires_explicit_immutable_image_and_root_identity() {
        assert!(Cli::try_parse_from(["ffs-zfs", "inspect", "leaf.img"]).is_err());
        assert!(Cli::try_parse_from(["ffs-zfs", "root", "leaf.img", "--offline-image"]).is_err());
        assert!(
            Cli::try_parse_from(["ffs-zfs", "inspect", "leaf.img", "--offline-image", "--rw"])
                .is_err()
        );
        let cli = Cli::try_parse_from([
            "ffs-zfs",
            "root",
            "disk.img",
            "--offline-image",
            "--offset",
            "1048576",
            "--length",
            "67108864",
            "--label",
            "2",
            "--slot",
            "3",
            "--pool-guid",
            "123",
        ])
        .unwrap();
        let Command::Root { candidate } = cli.command else {
            panic!("root");
        };
        assert_eq!(
            (
                candidate.image.offset,
                candidate.image.length,
                candidate.label,
                candidate.slot,
                candidate.pool_guid
            ),
            (1_048_576, Some(67_108_864), 2, 3, 123)
        );
        assert_eq!(candidate.members, [] as [PathBuf; 0]);
    }
    #[test]
    fn object_commands_require_root_identity_and_explicit_range_length() {
        let base = [
            "ffs-zfs",
            "object-read",
            "leaf.img",
            "7",
            "--offline-image",
            "--label",
            "0",
            "--slot",
            "2",
            "--pool-guid",
            "123",
        ];
        assert!(Cli::try_parse_from(base).is_err());
        let args: Vec<_> = base
            .into_iter()
            .chain(["--start", "510", "--bytes", "1026"])
            .collect();
        let cli = Cli::try_parse_from(args).unwrap();
        let Command::ObjectRead {
            number,
            start,
            bytes,
            ..
        } = cli.command
        else {
            panic!("object-read");
        };
        assert_eq!((number, start, bytes), (7, 510, 1026));
        assert!(
            Cli::try_parse_from(["ffs-zfs", "datasets", "leaf.img", "--offline-image"]).is_err()
        );
        assert!(
            Cli::try_parse_from([
                "ffs-zfs",
                "datasets",
                "leaf.img",
                "--offline-image",
                "--label",
                "0",
                "--slot",
                "2",
                "--pool-guid",
                "123"
            ])
            .is_ok()
        );
    }

    #[test]
    fn member_selection_reaches_every_raw_command_with_explicit_bounds() {
        let options = [
            "--offline-image",
            "--offset",
            "1048576",
            "--length",
            "67108864",
            "--label",
            "1",
            "--slot",
            "2",
            "--pool-guid",
            "123",
            "--member",
            "second.img",
            "--raidz-member",
            "third.img",
        ];
        for command in [
            vec!["root", "first.img"],
            vec!["object", "first.img", "7"],
            vec!["object-read", "first.img", "7", "--bytes", "32"],
            vec!["zap", "first.img", "7"],
            vec!["datasets", "first.img"],
        ] {
            let parsed =
                Cli::try_parse_from(std::iter::once("ffs-zfs").chain(command).chain(options))
                    .unwrap();
            let (Command::Root { candidate }
            | Command::Object { candidate, .. }
            | Command::ObjectRead { candidate, .. }
            | Command::Zap { candidate, .. }
            | Command::Datasets { candidate }) = parsed.command
            else {
                panic!("raw pool command");
            };
            assert_eq!(candidate.image.image, PathBuf::from("first.img"));
            assert_eq!(
                (candidate.image.offset, candidate.image.length),
                (1_048_576, Some(67_108_864))
            );
            assert_eq!(
                (candidate.label, candidate.slot, candidate.pool_guid),
                (1, 2, 123)
            );
            assert!(candidate.image.offline_image);
            assert_eq!(
                candidate.members,
                [PathBuf::from("second.img"), PathBuf::from("third.img")]
            );
        }
        assert!(
            Cli::try_parse_from([
                "ffs-zfs",
                "inspect",
                "first.img",
                "--offline-image",
                "--mirror-member",
                "second.img",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "ffs-zfs",
                "root",
                "first.img",
                "--mirror-member",
                "second.img",
                "--label",
                "1",
                "--slot",
                "2",
                "--pool-guid",
                "123",
            ])
            .is_err()
        );
    }

    #[test]
    fn all_member_spellings_append_to_one_explicit_member_set() {
        let cli = Cli::try_parse_from([
            "ffs-zfs",
            "root",
            "first.img",
            "--offline-image",
            "--pool-guid",
            "123",
            "--label",
            "0",
            "--slot",
            "2",
            "--member",
            "second.img",
            "--mirror-member",
            "third.img",
            "--raidz-member",
            "fourth.img",
        ])
        .unwrap();
        let Command::Root { candidate } = cli.command else {
            panic!("root");
        };
        assert_eq!(
            candidate.members,
            [
                PathBuf::from("second.img"),
                PathBuf::from("third.img"),
                PathBuf::from("fourth.img")
            ]
        );
    }

    #[test]
    fn member_count_is_bounded_before_any_image_is_opened() {
        let candidate = CandidateArgs {
            image: ImageArgs {
                image: PathBuf::from("unopened-primary.img"),
                offset: 0,
                length: None,
                offline_image: true,
                sidecar: None,
            },
            auto_import: false,
            replay_zil: false,
            label: 0,
            slot: 0,
            pool_guid: 1,
            members: vec![PathBuf::from("unopened-member.img"); 8],
            missing_mirror_members: Vec::new(),
            missing_raidz_members: Vec::new(),
        };
        let Err(error) = candidate.open(&Cx::for_testing()) else {
            panic!("an oversized member set must fail before image I/O");
        };
        assert_eq!(
            error.to_string(),
            "at most seven additional member images are supported"
        );
    }

    #[test]
    fn mountpoint_guard_checks_all_members_and_resolves_host_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let mountpoint = directory.path().join("mount");
        std::fs::create_dir(&mountpoint).unwrap();
        let outside = directory.path().join("first.img");
        let inside = mountpoint.join("second.img");
        for path in [&outside, &inside] {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .unwrap();
        }
        let alias = directory.path().join("member-alias.img");
        std::os::unix::fs::symlink(&inside, &alias).unwrap();
        let mut candidate = CandidateArgs {
            image: ImageArgs {
                image: outside.clone(),
                offset: 0,
                length: None,
                offline_image: true,
                sidecar: None,
            },
            auto_import: false,
            replay_zil: false,
            label: 0,
            slot: 0,
            pool_guid: 1,
            members: vec![outside],
            missing_mirror_members: Vec::new(),
            missing_raidz_members: Vec::new(),
        };
        let mountpoint = mountpoint.canonicalize().unwrap();
        candidate.reject_hidden_images(&mountpoint).unwrap();
        candidate.members = vec![alias];
        assert_eq!(
            candidate
                .reject_hidden_images(&mountpoint)
                .unwrap_err()
                .to_string(),
            "ZFS mountpoint would hide a backing image"
        );
        candidate.members.clear();
        candidate.image.image = inside;
        assert!(candidate.reject_hidden_images(&mountpoint).is_err());
    }

    #[test]
    fn missing_mirror_cli_keeps_explicit_identity_and_conflicts_with_import_and_replay() {
        let options = [
            "--offline-image", "--pool-guid", "123", "--label", "0", "--slot", "2",
            "--missing-mirror-member", "1002", "--missing-mirror-member", "1003",
        ];
        for command in [
            vec!["root", "first.img"],
            vec!["object", "first.img", "7"],
            vec!["object-read", "first.img", "7", "--bytes", "32"],
            vec!["zap", "first.img", "7"],
            vec!["datasets", "first.img"],
        ] {
            let cli = Cli::try_parse_from(std::iter::once("ffs-zfs").chain(command).chain(options))
                .unwrap();
            let (Command::Root { candidate }
            | Command::Object { candidate, .. }
            | Command::ObjectRead { candidate, .. }
            | Command::Zap { candidate, .. }
            | Command::Datasets { candidate }) = cli.command else {
                panic!("raw candidate command");
            };
            assert_eq!(candidate.missing_mirror_members, [1002, 1003]);
            assert_eq!((candidate.pool_guid, candidate.label, candidate.slot), (123, 0, 2));
            assert!(!candidate.auto_import && !candidate.replay_zil);
        }
        for command in [
            vec!["ls", "first.img", "/"],
            vec!["read", "first.img", "/file"],
            vec!["mount", "first.img", "/mnt/extraction"],
        ] {
            assert!(Cli::try_parse_from(std::iter::once("ffs-zfs").chain(command).chain(options)).is_ok());
        }
        for conflict in ["--auto-import", "--replay-zil", "--rw"] {
            assert!(Cli::try_parse_from(["ffs-zfs", "root", "first.img"].into_iter()
                .chain(options).chain([conflict])).is_err());
        }
        assert!(Cli::try_parse_from([
            "ffs-zfs", "root", "first.img", "--offline-image", "--missing-mirror-member", "1002"
        ]).is_err());
        assert!(Cli::try_parse_from([
            "ffs-zfs", "inspect", "first.img", "--offline-image", "--missing-mirror-member", "1002"
        ]).is_err());
    }

    #[test]
    fn missing_mirror_invalid_requests_fail_before_any_image_open() {
        for (missing, count, auto, replay, guid, reason) in [
            (vec![0], 0, false, false, 123, "nonzero and unique"),
            (vec![1002, 1002], 0, false, false, 123, "nonzero and unique"),
            (vec![1002], 7, false, false, 123, "at most eight total"),
            (vec![1002], 0, true, false, 123, "without import or replay"),
            (vec![1002], 0, false, true, 123, "without import or replay"),
            (vec![1002], 0, false, false, 0, "without import or replay"),
        ] {
            let candidate = CandidateArgs {
                image: ImageArgs {
                    image: PathBuf::from("unopened-mirror-primary.img"),
                    offset: 0,
                    length: None,
                    offline_image: true,
                    sidecar: None,
                },
                auto_import: auto,
                replay_zil: replay,
                label: 0,
                slot: 2,
                pool_guid: guid,
                members: vec![PathBuf::from("unopened-mirror-member.img"); count],
                missing_mirror_members: missing,
                missing_raidz_members: Vec::new(),
            };
            let Err(error) = candidate.open(&Cx::for_testing()) else {
                panic!("invalid mirror selection must fail before image I/O");
            };
            assert!(error.to_string().contains(reason), "{error}");
        }
    }
}

#[cfg(test)]
mod missing_raidz_cli_tests;
