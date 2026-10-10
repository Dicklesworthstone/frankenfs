#![forbid(unsafe_code)]
//! Experimental native FAT16/FAT32 reader. No filesystem mutation is supported.

mod filesystem;
mod reader;

use anyhow::{Context, Result, bail};
use asupersync::Cx;
use clap::{Args, Parser, Subcommand};
use reader::{Directory, FatVolume};
use std::io::{self, Write};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "ffs-fat",
    about = "Read offline FAT16/FAT32 images without modifying them"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Args)]
struct ImageArgs {
    /// Offline regular image file. Do not use an image mounted by another writer.
    image: PathBuf,
    /// Byte offset of an explicitly selected volume inside the image.
    #[arg(long, default_value_t = 0)]
    offset: u64,
    /// Maximum byte length of that volume; defaults to the remaining image.
    #[arg(long)]
    length: Option<u64>,
}

impl ImageArgs {
    fn open(&self, cx: &Cx) -> Result<FatVolume> {
        FatVolume::open(cx, &self.image, self.offset, self.length)
            .with_context(|| format!("opening offline FAT volume in {}", self.image.display()))
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate boot geometry, clean-state admission and FAT reserved records.
    Inspect {
        #[command(flatten)]
        image: ImageArgs,
    },
    /// List a directory as JSON, preserving safely representable native names.
    Ls {
        #[command(flatten)]
        image: ImageArgs,
        #[arg(default_value = "/")]
        path: String,
    },
    /// Stream a file's logical bytes to stdout; diagnostics go to stderr.
    Cat {
        #[command(flatten)]
        image: ImageArgs,
        path: String,
    },
    /// Mount an immutable image through the existing FrankenFS FUSE adapter.
    Mount {
        #[command(flatten)]
        image: ImageArgs,
        /// Existing empty directory, outside the image's own path.
        mountpoint: PathBuf,
        /// Confirm the image will not be modified by a kernel mount or another program.
        #[arg(long, required = true)]
        offline_image: bool,
        /// Synthetic Unix ownership; never written into native FAT metadata.
        #[arg(long, default_value_t = 0)]
        uid: u32,
        #[arg(long, default_value_t = 0)]
        gid: u32,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cx = Cx::for_request();
    match cli.command {
        Command::Inspect { image } => {
            let volume = image.open(&cx)?;
            let geometry = &volume.geometry;
            let free_clusters = volume.free_clusters(&cx)?;
            let report = serde_json::json!({
                "format": format!("{:?}", geometry.kind()),
                "read_only": true,
                "volume_offset": image.offset,
                "volume_bytes": geometry.volume_bytes(),
                "sector_bytes": geometry.sector_bytes(),
                "cluster_bytes": geometry.cluster_bytes(),
                "data_clusters": geometry.cluster_count(),
                "free_clusters": free_clusters,
                "fat_copies": geometry.fat_count(),
                "mirrored": geometry.mirrored(),
                "active_fat": geometry.active_fat(),
                "fs_info_sector": geometry.fs_info_sector(),
                "backup_boot_sector": geometry.backup_boot_sector(),
                "scope": "boot admission and FAT free count; not a full filesystem check"
            });
            serde_json::to_writer_pretty(io::stdout().lock(), &report)?;
            println!();
        }
        Command::Ls { image, path } => {
            let volume = image.open(&cx)?;
            let directory = volume
                .resolve(&cx, &path)?
                .map_or(Ok(Directory::Root), |entry| entry.directory())?;
            let entries = volume.list(&cx, directory)?;
            let mut report = Vec::with_capacity(entries.len());
            for entry in entries {
                report.push(serde_json::json!({
                    "name": entry.name()?,
                    "short_alias": entry.native.ascii_short_name(),
                    "directory": entry.native.is_directory(),
                    "size": entry.native.size,
                    "first_cluster": entry.native.first_cluster,
                    "entry_offset": entry.offset
                }));
            }
            serde_json::to_writer_pretty(io::stdout().lock(), &report)?;
            println!();
        }
        Command::Cat { image, path } => {
            let volume = image.open(&cx)?;
            let Some(entry) = volume.resolve(&cx, &path)? else {
                bail!("cannot read the FAT root directory as a file");
            };
            let chain = volume.file_chain(&cx, &entry)?;
            let mut stdout = io::stdout().lock();
            let mut offset = 0_u64;
            while offset < u64::from(chain.size) {
                let bytes = volume.read(&cx, &chain, offset, 1024 * 1024)?;
                stdout.write_all(&bytes)?;
                offset += bytes.len() as u64;
            }
            stdout.flush()?;
        }
        Command::Mount {
            image,
            mountpoint,
            offline_image,
            uid,
            gid,
        } => {
            if !offline_image {
                bail!("--offline-image is required; shared locks do not exclude unrelated writers");
            }
            let mountpoint = mountpoint
                .canonicalize()
                .context("resolve FAT mountpoint")?;
            if !mountpoint.is_dir()
                || std::fs::read_dir(&mountpoint)?
                    .next()
                    .transpose()?
                    .is_some()
            {
                bail!("FAT mountpoint must be an existing empty directory");
            }
            if image.image.canonicalize()?.starts_with(&mountpoint) {
                bail!("mountpoint would hide the backing image");
            }
            let volume = image.open(&cx)?;
            let fs = filesystem::FatFs::new(&cx, volume, uid, gid)?;
            let options = ffs_fuse::MountOptions {
                read_only: true,
                allow_other: false,
                auto_unmount: true,
                ..ffs_fuse::MountOptions::default()
            };
            eprintln!(
                "experimental FAT read-only mount; modification times use a UTC wall-clock projection"
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
    fn clap_accepts_explicit_ranges_and_has_no_write_switch() {
        let cli = Cli::try_parse_from([
            "ffs-fat",
            "cat",
            "disk.img",
            "--offset",
            "1024",
            "--length",
            "4096",
            "/hello.txt",
        ])
        .unwrap();
        let Command::Cat { image, path } = cli.command else {
            panic!("expected cat");
        };
        assert_eq!((image.offset, image.length), (1024, Some(4096)));
        assert_eq!(path, "/hello.txt");
        assert!(Cli::try_parse_from(["ffs-fat", "cat", "disk.img", "/hello.txt", "--rw"]).is_err());
        assert!(Cli::try_parse_from(["ffs-fat", "mount", "disk.img", "/mnt/fat"]).is_err());
        assert!(
            Cli::try_parse_from([
                "ffs-fat",
                "mount",
                "disk.img",
                "/mnt/fat",
                "--offline-image"
            ])
            .is_ok()
        );
    }
}
