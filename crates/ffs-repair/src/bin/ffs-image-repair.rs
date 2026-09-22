//! Offline image protection without writing parity into filesystem space.

use asupersync::Cx;
use clap::{Parser, Subcommand};
use ffs_error::{FfsError, Result};
use ffs_repair::sidecar::{SidecarOptions, protect, verify};
use ffs_repair::sidecar_restore::restore;
use serde::Serialize;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "ffs-image-repair",
    about = "External RaptorQ protection for offline filesystem images"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Save a protection point in a new sidecar; never modify the image.
    Protect {
        image: PathBuf,
        sidecar: PathBuf,
        /// Confirm that the image is unmounted and has no external writers.
        #[arg(long, required = true)]
        offline: bool,
        #[arg(long, default_value_t = 4096)]
        block_size: u32,
        #[arg(long, default_value_t = 256)]
        group_blocks: u32,
        #[arg(long, default_value_t = 16)]
        repair_symbols: u32,
    },
    /// Compare the current image and parity with a saved protection point.
    Verify { image: PathBuf, sidecar: PathBuf },
    /// Reconstruct the saved generation in a NEW file, preserving the source.
    Restore {
        image: PathBuf,
        sidecar: PathBuf,
        output: PathBuf,
        /// Confirm the source is offline and restoration targets the saved generation.
        #[arg(long, required = true)]
        offline: bool,
    },
}

fn emit(value: &impl Serialize) -> Result<()> {
    let json = serde_json::to_string_pretty(value)
        .map_err(|error| FfsError::Format(error.to_string()))?;
    println!("{json}");
    Ok(())
}

fn run(cli: Cli) -> Result<u8> {
    // The standalone consumer owns its capability root. All library work
    // receives this explicit context, including the cancellation signal.
    let cx = Cx::for_testing();
    let cancellation = cx.clone();
    ctrlc::set_handler(move || cancellation.set_cancel_requested(true))
        .map_err(|error| FfsError::Io(std::io::Error::other(error)))?;
    match cli.command {
        Command::Protect {
            image,
            sidecar,
            offline: _,
            block_size,
            group_blocks,
            repair_symbols,
        } => {
            let options = SidecarOptions {
                block_size,
                group_blocks,
                repair_symbols,
            };
            emit(&protect(&cx, &image, &sidecar, options)?)?;
            Ok(0)
        }
        Command::Verify { image, sidecar } => {
            let report = verify(&cx, &image, &sidecar)?;
            emit(&report)?;
            Ok(if report.is_healthy() { 0 } else { 2 })
        }
        Command::Restore {
            image,
            sidecar,
            output,
            offline: _,
        } => {
            emit(&restore(&cx, &image, &sidecar, &output)?)?;
            Ok(0)
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("ffs-image-repair: {error}");
            ExitCode::from(if matches!(error, FfsError::Cancelled) {
                130
            } else {
                4
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutating_commands_require_an_explicit_offline_acknowledgement() {
        assert!(Cli::try_parse_from(["ffs-image-repair", "protect", "a", "b"]).is_err());
        assert!(Cli::try_parse_from(["ffs-image-repair", "restore", "a", "b", "c"]).is_err());
        assert!(Cli::try_parse_from([
            "ffs-image-repair",
            "restore",
            "a",
            "b",
            "c",
            "--offline"
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["ffs-image-repair", "verify", "a", "b"]).is_ok());
    }
}
