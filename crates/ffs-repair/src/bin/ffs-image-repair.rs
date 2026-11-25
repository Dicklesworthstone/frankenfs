//! Offline image protection without writing parity into filesystem space.

use clap::{Parser, Subcommand};
use ffs_error::{FfsError, Result};
use ffs_repair::por::PorKey;
use ffs_repair::sidecar::live::{
    StorageSetMemberSpec, StorageSetProtectRequest, StorageSetVerifyReport, protect_storage_set,
    verify_storage_set,
};
use ffs_repair::sidecar::{
    MemberRole, NativeCommitBinding, ProtectedViewIdentity, SidecarOptions, StorageSetTopology,
    TrustPolicy, protect, verify,
};
use ffs_repair::sidecar_restore::restore;
use serde::Serialize;
use std::path::{Path, PathBuf};
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
    /// Protect a multi-member offline storage set and publish its FFSRQSM3 manifest.
    ProtectSet {
        manifest: PathBuf,
        /// Primary member pair (<IMAGE> <SIDECAR>) plus any additional data members.
        #[arg(long = "member", num_args = 2, value_names = ["IMAGE", "SIDECAR"], required = true)]
        members: Vec<PathBuf>,
        /// Optional external log member pairs (<IMAGE> <SIDECAR>).
        #[arg(long = "log-member", num_args = 2, value_names = ["IMAGE", "SIDECAR"])]
        log_members: Vec<PathBuf>,
        /// Optional special member pairs (<IMAGE> <SIDECAR>).
        #[arg(long = "special-member", num_args = 2, value_names = ["IMAGE", "SIDECAR"])]
        special_members: Vec<PathBuf>,
        #[arg(long, default_value = "raw")]
        filesystem: String,
        /// Bind the mount view to this ZFS dataset path relative to the pool root.
        #[arg(long)]
        zfs_dataset: Option<String>,
        #[arg(long)]
        trust_key_file: Option<PathBuf>,
        /// Confirm that every member image is unmounted and has no external writers.
        #[arg(long, required = true)]
        offline: bool,
        #[arg(long, default_value_t = 4096)]
        block_size: u32,
        #[arg(long, default_value_t = 256)]
        group_blocks: u32,
        #[arg(long, default_value_t = 16)]
        repair_symbols: u32,
    },
    /// Verify a multi-member storage-set manifest (FFSRQSM3) and all bound sidecars.
    VerifySet {
        manifest: PathBuf,
        #[arg(long = "member", num_args = 2, value_names = ["IMAGE", "SIDECAR"], required = true)]
        members: Vec<PathBuf>,
        #[arg(long = "log-member", num_args = 2, value_names = ["IMAGE", "SIDECAR"])]
        log_members: Vec<PathBuf>,
        #[arg(long = "special-member", num_args = 2, value_names = ["IMAGE", "SIDECAR"])]
        special_members: Vec<PathBuf>,
        #[arg(long)]
        trust_key_file: Option<PathBuf>,
        #[arg(long)]
        require_trusted_root: bool,
    },
}

fn load_por_key(path: &Path) -> Result<PorKey> {
    let raw = std::fs::read(path)?;
    if raw.len() == 32 {
        let mut key = [0_u8; 32];
        key.copy_from_slice(&raw);
        return Ok(key);
    }
    let trimmed = std::str::from_utf8(&raw)
        .map_err(|_| FfsError::Corruption {
            block: 0,
            detail: "trust key file must be 32 raw bytes or 64 hex characters".into(),
        })?
        .trim();
    if trimmed.len() != 64 {
        return Err(FfsError::Corruption {
            block: 0,
            detail: "trust key file must be 32 raw bytes or 64 hex characters".into(),
        });
    }
    let mut key = [0_u8; 32];
    for (idx, slot) in key.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&trimmed[idx * 2..idx * 2 + 2], 16).map_err(|_| {
            FfsError::Corruption {
                block: 0,
                detail: "invalid hex digit in trust key file".into(),
            }
        })?;
    }
    Ok(key)
}

fn collect_specs(
    data: &[PathBuf],
    logs: &[PathBuf],
    specials: &[PathBuf],
) -> Vec<StorageSetMemberSpec> {
    let mut specs = Vec::new();
    for pair in data.as_chunks::<2>().0 {
        specs.push(StorageSetMemberSpec {
            role: MemberRole::Data,
            image_path: pair[0].clone(),
            sidecar_path: pair[1].clone(),
            native_member_id: [0_u8; 16],
            offset: 0,
            length: None,
        });
    }
    for pair in logs.as_chunks::<2>().0 {
        specs.push(StorageSetMemberSpec {
            role: MemberRole::Log,
            image_path: pair[0].clone(),
            sidecar_path: pair[1].clone(),
            native_member_id: [0_u8; 16],
            offset: 0,
            length: None,
        });
    }
    for pair in specials.as_chunks::<2>().0 {
        specs.push(StorageSetMemberSpec {
            role: MemberRole::Special,
            image_path: pair[0].clone(),
            sidecar_path: pair[1].clone(),
            native_member_id: [0_u8; 16],
            offset: 0,
            length: None,
        });
    }
    specs
}

#[derive(Serialize)]
struct VerifySetJson<'a> {
    manifest: &'a ffs_repair::sidecar::StorageSetManifest,
    member_reports: &'a [ffs_repair::sidecar::SidecarReport],
    healthy: bool,
}

impl<'a> From<&'a StorageSetVerifyReport> for VerifySetJson<'a> {
    fn from(report: &'a StorageSetVerifyReport) -> Self {
        Self {
            manifest: &report.manifest,
            member_reports: &report.member_reports,
            healthy: report.is_healthy(),
        }
    }
}

fn emit(value: &impl Serialize) -> Result<()> {
    let json =
        serde_json::to_string_pretty(value).map_err(|error| FfsError::Format(error.to_string()))?;
    println!("{json}");
    Ok(())
}

fn run(cli: Cli) -> Result<u8> {
    // The standalone consumer owns its capability root. All library work
    // receives this explicit context, including the cancellation signal.
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .map_err(|error| FfsError::Io(std::io::Error::other(error.to_string())))?;
    let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
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
        Command::ProtectSet {
            manifest,
            members,
            log_members,
            special_members,
            filesystem,
            zfs_dataset,
            trust_key_file,
            offline: _,
            block_size,
            group_blocks,
            repair_symbols,
        } => {
            let signing_key = trust_key_file.as_deref().map(load_por_key).transpose()?;
            let specs = collect_specs(&members, &log_members, &special_members);
            let filesystem = match (zfs_dataset.is_some(), filesystem.as_str()) {
                (true, "raw") => "zfs".to_owned(),
                (true, other) if other != "zfs" => {
                    return Err(FfsError::Format(
                        "--zfs-dataset requires a ZFS storage set".into(),
                    ));
                }
                _ => filesystem,
            };
            let view = zfs_dataset
                .as_deref()
                .map(ProtectedViewIdentity::from_zfs_dataset)
                .transpose()?
                .unwrap_or_default();
            let topology = if specs.len() == 1 {
                StorageSetTopology::SingleData
            } else if filesystem == "zfs" {
                let width = u8::try_from(specs.len()).map_err(|_| FfsError::Corruption {
                    block: 0,
                    detail: "ZFS mirror width exceeds u8".into(),
                })?;
                StorageSetTopology::ZfsMirror { width }
            } else {
                let count = u32::try_from(specs.len()).map_err(|_| FfsError::Corruption {
                    block: 0,
                    detail: "member count exceeds u32".into(),
                })?;
                StorageSetTopology::BtrfsDevices { num_devices: count }
            };
            let req = StorageSetProtectRequest {
                manifest_path: manifest,
                filesystem,
                topology,
                view,
                native_binding: NativeCommitBinding::UninterpretedRaw,
                members: specs,
                options: SidecarOptions {
                    block_size,
                    group_blocks,
                    repair_symbols,
                },
                signing_key,
            };
            emit(&protect_storage_set(&cx, &req)?)?;
            Ok(0)
        }
        Command::VerifySet {
            manifest,
            members,
            log_members,
            special_members,
            trust_key_file,
            require_trusted_root,
        } => {
            let specs = collect_specs(&members, &log_members, &special_members);
            let pairs: Vec<(PathBuf, PathBuf)> = specs
                .into_iter()
                .map(|s| (s.image_path, s.sidecar_path))
                .collect();
            let key = trust_key_file.as_deref().map(load_por_key).transpose()?;
            let policy = match (require_trusted_root, key) {
                (_, Some(k)) => TrustPolicy::RequireTrustedRoot { key: k },
                (true, None) => {
                    return Err(FfsError::Corruption {
                        block: 0,
                        detail: "--require-trusted-root requires --trust-key-file".into(),
                    });
                }
                (false, None) => TrustPolicy::AllowUnauthenticated,
            };
            let report = verify_storage_set(&cx, &manifest, &pairs, policy)?;
            emit(&VerifySetJson::from(&report))?;
            Ok(if report.is_healthy() { 0 } else { 2 })
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
    fn protect_set_binds_the_selected_dataset_before_publication() {
        let dir = tempfile::tempdir().unwrap();
        let image = dir.path().join("member");
        let sidecar = dir.path().join("sidecar");
        let manifest = dir.path().join("manifest");
        std::fs::write(&image, [0x31; 8192]).unwrap();
        let run_for = |dataset: &str| {
            run(Cli::try_parse_from([
                "ffs-image-repair",
                "protect-set",
                manifest.to_str().unwrap(),
                "--member",
                image.to_str().unwrap(),
                sidecar.to_str().unwrap(),
                "--offline",
                "--zfs-dataset",
                dataset,
            ])
            .unwrap())
        };
        assert!(run_for("home/../users").is_err());
        assert!(!manifest.exists() && !sidecar.exists());
        assert_eq!(run_for("/home/users/").unwrap(), 0);
        let saved = ffs_repair::sidecar::StorageSetManifest::decode(
            &std::fs::read(&manifest).unwrap(),
            TrustPolicy::AllowUnauthenticated,
        )
        .unwrap();
        assert_eq!(saved.filesystem, "zfs");
        assert_eq!(saved.view.zfs_dataset, ["home", "users"]);
    }

    #[test]
    fn mutating_commands_require_an_explicit_offline_acknowledgement() {
        assert!(Cli::try_parse_from(["ffs-image-repair", "protect", "a", "b"]).is_err());
        assert!(Cli::try_parse_from(["ffs-image-repair", "restore", "a", "b", "c"]).is_err());
        assert!(
            Cli::try_parse_from(["ffs-image-repair", "restore", "a", "b", "c", "--offline"])
                .is_ok()
        );
        assert!(Cli::try_parse_from(["ffs-image-repair", "verify", "a", "b"]).is_ok());
        assert!(
            Cli::try_parse_from([
                "ffs-image-repair",
                "protect-set",
                "m.manifest",
                "--member",
                "a",
                "b"
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "ffs-image-repair",
                "protect-set",
                "m.manifest",
                "--member",
                "a",
                "b",
                "--offline"
            ])
            .is_ok()
        );
    }
}
