#![forbid(unsafe_code)]
//! Command transport for the reusable native FAT engine.

use anyhow::{Context, Result, bail};
use asupersync::types::CancelKind;
use clap::Parser;
use ffs_fat::{
    Cli, Command, Directory, FatFs, extract_slots, formatter, native_catalog, reader, resize,
    stream_file,
};
use std::io::{self, Write};

fn main() -> Result<()> {
    let cli = Cli::parse();
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .map_err(|err| anyhow::anyhow!("failed to build ffs-fat runtime: {err}"))?;
    let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    // A process owns its signal policy. The library only observes the supplied
    // context, so repeated operations never install competing global handlers.
    // FUSE mounts retain the transport's own signal/unmount lifecycle.
    if !matches!(&cli.command, Command::Mount { .. }) {
        let signal = cx.clone();
        ctrlc::set_handler(move || {
            signal.cancel_with(CancelKind::User, Some("FAT command interrupted by Ctrl+C"));
        })
        .context("installing FAT cancellation handler; no image mutation started")?;
    }
    match cli.command {
        Command::Resize { options } => {
            let report = resize::run(&cx, &options)?;
            let mut output = io::stdout().lock();
            serde_json::to_writer_pretty(&mut output, &report)
                .context("FAT resize completed; writing its report failed")?;
            writeln!(output).context("FAT resize completed; finishing its report failed")?;
        }
        Command::Recover { options } => {
            let report = reader::recovery::recover(&cx, &options)?;
            let mut output = io::stdout().lock();
            serde_json::to_writer_pretty(&mut output, &report)
                .context("FAT recovery completed; writing its report failed")?;
            writeln!(output).context("FAT recovery completed; finishing its report failed")?;
        }
        Command::RepairParents { options } => {
            let report = reader::recovery::repair_parents(&cx, &options)?;
            let mut output = io::stdout().lock();
            serde_json::to_writer_pretty(&mut output, &report)
                .context("FAT parent repair completed; writing its report failed")?;
            writeln!(output).context("FAT parent repair completed; finishing its report failed")?;
        }
        Command::Replace { options } => {
            let report = reader::replacement::replace(&cx, &options)?;
            let mut output = io::stdout().lock();
            serde_json::to_writer_pretty(&mut output, &report)
                .context("FAT operation completed; writing the report failed")?;
            writeln!(output).context("FAT operation completed; finishing the report failed")?;
        }
        Command::Mkdir { options } => {
            let report = reader::replacement::run_mkdir(&cx, &options)?;
            let mut output = io::stdout().lock();
            serde_json::to_writer_pretty(&mut output, &report)
                .context("FAT directory operation completed; writing the report failed")?;
            writeln!(output)
                .context("FAT directory operation completed; finishing the report failed")?;
        }
        Command::Unlink { options } => {
            let report = reader::replacement::run_unlink(&cx, &options)?;
            let mut output = io::stdout().lock();
            serde_json::to_writer_pretty(&mut output, &report)
                .context("FAT unlink operation completed; writing the report failed")?;
            writeln!(output)
                .context("FAT unlink operation completed; finishing the report failed")?;
        }
        Command::Rmdir { options } => {
            let report = reader::replacement::run_rmdir(&cx, &options)?;
            let mut output = io::stdout().lock();
            serde_json::to_writer_pretty(&mut output, &report)
                .context("FAT rmdir operation completed; writing the report failed")?;
            writeln!(output)
                .context("FAT rmdir operation completed; finishing the report failed")?;
        }
        Command::Rename { options } => {
            let report = reader::replacement::run_rename(&cx, &options)?;
            let mut output = io::stdout().lock();
            serde_json::to_writer_pretty(&mut output, &report)
                .context("FAT rename operation completed; writing the report failed")?;
            writeln!(output)
                .context("FAT rename operation completed; finishing the report failed")?;
        }
        Command::Format { options } => {
            let report = formatter::create(&cx, &options)?;
            let mut output = io::stdout().lock();
            serde_json::to_writer_pretty(&mut output, &report).context(
                "FAT image initialized, synchronized and verified; writing the success report failed",
            )?;
            writeln!(output).context(
                "FAT image initialized, synchronized and verified; finishing the success report failed",
            )?;
        }
        Command::Inspect { image } => {
            let volume = image.open(&cx)?;
            let geometry = &volume.geometry;
            let free_clusters = volume.free_clusters(&cx)?;
            let report = serde_json::json!({
                "format": format!("{:?}", geometry.kind()),
                "read_only": true,
                "oem_code_page": volume.oem_code_page().label(),
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
        Command::Check { image } => {
            let report = reader::recovery::check(&cx, &image)?;
            serde_json::to_writer_pretty(io::stdout().lock(), &report)?;
            println!();
            if !report.clean {
                bail!(
                    "FAT allocation check {}; no changes were made",
                    report.status
                );
            }
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
                    "short_alias": entry.short_alias(),
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
            stream_file(&cx, &volume, &entry, &mut io::stdout().lock())?;
        }
        Command::Catalog { image, entry_slots } => {
            let volume = image.open(&cx)?;
            let report =
                native_catalog(&cx, &volume, &entry_slots.unwrap_or_default(), image.offset)?;
            serde_json::to_writer_pretty(io::stdout().lock(), &report)?;
            println!();
        }
        Command::Extract { image, entry_slots } => {
            let volume = image.open(&cx)?;
            extract_slots(&cx, &volume, &entry_slots, &mut io::stdout().lock())?;
        }
        Command::Mount {
            image,
            mountpoint,
            offline_image,
            rw,
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
            let volume = if rw {
                reader::replacement::open_volume(&cx, &image, true)?
            } else {
                image.open(&cx)?
            };
            let fs = FatFs::new_with_mode(&cx, volume, uid, gid, rw)?;
            let options = ffs_fuse::MountOptions {
                read_only: !rw,
                allow_other: false,
                auto_unmount: true,
                ..ffs_fuse::MountOptions::default()
            };
            eprintln!(
                "experimental FAT {} mount; native FAT timestamps use a UTC wall-clock projection",
                if rw { "read-write" } else { "read-only" }
            );
            let _ = ffs_fuse::mount(Box::new(fs), &mountpoint, &options)?;
        }
    }
    Ok(())
}
