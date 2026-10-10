#![forbid(unsafe_code)]
//! Native read-only ZFS label inspection and explicit MOS-root extraction.

mod reader;

use anyhow::{Context, Result, bail};
use asupersync::Cx;
use clap::{Args, Parser, Subcommand};
use ffs_error::FfsError;
use ffs_ondisk::zfs::UBERBLOCK_RING_BYTES;
use reader::Leaf;
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "ffs-zfs",
    about = "Inspect offline ZFS leaves without importing, replaying or writing"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
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
}
impl ImageArgs {
    fn open(&self, cx: &Cx) -> Result<Leaf> {
        if !self.offline_image {
            bail!("--offline-image is required");
        }
        Leaf::open(cx, &self.image, self.offset, self.length).context("opening selected ZFS leaf")
    }
}
#[derive(Debug, Subcommand)]
enum Command {
    /// Inventory checksum-valid configurations and uberblock candidates, not pool authority.
    Inspect {
        #[command(flatten)]
        image: ImageArgs,
    },
    /// Extract one checked META object-set block. No automatic TXG selection or import.
    Root {
        #[command(flatten)]
        image: ImageArgs,
        #[arg(long)]
        label: usize,
        #[arg(long)]
        slot: usize,
        /// Expected pool GUID as a decimal integer from inspect.
        #[arg(long)]
        pool_guid: u64,
    },
}
fn main() -> Result<()> {
    let cli = Cli::parse();
    let cx = Cx::for_request();
    match cli.command {
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
        Command::Root {
            image,
            label,
            slot,
            pool_guid,
        } => {
            let leaf = image.open(&cx)?;
            let root = leaf.root(&cx, label, slot, pool_guid)?;
            eprintln!(
                "checked candidate txg={} copy={} vdev_offset={} bytes={}; not a pool import",
                root.uberblock.txg,
                root.copy_index,
                root.physical_offset,
                root.data.len()
            );
            let mut out = io::stdout().lock();
            out.write_all(&root.data)?;
            out.flush()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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
        let Command::Root {
            image,
            label,
            slot,
            pool_guid,
        } = cli.command
        else {
            panic!("root");
        };
        assert_eq!(
            (image.offset, image.length, label, slot, pool_guid),
            (1_048_576, Some(67_108_864), 2, 3, 123)
        );
    }
}
