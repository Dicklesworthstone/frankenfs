//! Offline image protection without writing parity into filesystem space.

use clap::{Parser, Subcommand};
use ffs_error::{FfsError, Result};
use ffs_ondisk::fat::{FatGeometry, FatKind};
use ffs_ondisk::ntfs::NtfsGeometry;
use ffs_ondisk::zfs::{
    LABEL_CONFIG_BYTES, LABEL_CONFIG_OFFSET, UBERBLOCK_RING_BYTES, UBERBLOCK_RING_OFFSET,
    Uberblock, label_offsets, nvlist::NvList, uberblock_bytes, verify_label_checksum,
};
use ffs_ondisk::{BtrfsSuperblock, Ext4Superblock};
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
use ffs_types::{
    BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE, EXT4_SUPERBLOCK_OFFSET, EXT4_SUPERBLOCK_SIZE,
};
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Mutex, OnceLock};

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
        /// Fail closed if the member image(s) cannot yield a native superblock/label binding
        /// matching `--filesystem`.
        #[arg(long)]
        require_native_binding: bool,
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

static ACTIVE_CANCEL_CX: Mutex<Option<asupersync::Cx>> = Mutex::new(None);
static CTRLC_INSTALLED: OnceLock<()> = OnceLock::new();

struct ActiveCancelGuard;

impl ActiveCancelGuard {
    fn install(cx: &asupersync::Cx) -> Result<Self> {
        if let Ok(mut slot) = ACTIVE_CANCEL_CX.lock() {
            *slot = Some(cx.clone());
        }
        if CTRLC_INSTALLED.get().is_none() {
            match ctrlc::set_handler(|| {
                if let Ok(slot) = ACTIVE_CANCEL_CX.lock()
                    && let Some(active) = slot.as_ref()
                {
                    active.set_cancel_requested(true);
                }
            }) {
                Ok(()) | Err(ctrlc::Error::MultipleHandlers) => {
                    let _ = CTRLC_INSTALLED.set(());
                }
                Err(error) => {
                    if let Ok(mut slot) = ACTIVE_CANCEL_CX.lock() {
                        *slot = None;
                    }
                    return Err(FfsError::Io(std::io::Error::other(error)));
                }
            }
        }
        Ok(Self)
    }
}

impl Drop for ActiveCancelGuard {
    fn drop(&mut self) {
        if let Ok(mut slot) = ACTIVE_CANCEL_CX.lock() {
            *slot = None;
        }
    }
}

#[derive(Debug)]
struct ExtractedNativeSet {
    binding: NativeCommitBinding,
    topology_hint: Option<StorageSetTopology>,
}

struct ZfsPoolLabelMeta {
    pool_guid: u64,
    top_guid: u64,
    version: u64,
    label_txg: u64,
    ashift: u8,
    asize: u64,
    vdev_children: u64,
    required_children: usize,
    vdev_type: Option<String>,
}

fn read_exact_range(path: &Path, offset: u64, out: &mut [u8]) -> Result<u64> {
    let mut file = File::open(path)?;
    let len = file.metadata()?.len();
    let end = offset
        .checked_add(u64::try_from(out.len()).unwrap_or(u64::MAX))
        .ok_or_else(|| FfsError::Format("range offset overflow".into()))?;
    if end > len {
        return Err(FfsError::Format(
            "image shorter than expected structure".into(),
        ));
    }
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(out)?;
    Ok(len)
}

#[allow(clippy::too_many_lines)]
fn extract_zfs_native_binding(
    specs: &mut [StorageSetMemberSpec],
) -> Result<Option<ExtractedNativeSet>> {
    let mut pending_member_guids: Vec<(usize, u64)> = Vec::new();
    let mut seen_guids = BTreeSet::new();
    let mut first_cfg: Option<ZfsPoolLabelMeta> = None;
    let mut best_ub: Option<(usize, Uberblock)> = None;
    let mut config_buf = vec![0_u8; LABEL_CONFIG_BYTES];
    let mut ring_buf = vec![0_u8; UBERBLOCK_RING_BYTES];

    for (idx, spec) in specs.iter().enumerate() {
        if spec.role != MemberRole::Data {
            continue;
        }
        let mut file = File::open(&spec.image_path)?;
        let len = file.metadata()?.len();
        let Ok(offsets) = label_offsets(len) else {
            return Ok(None);
        };
        let mut leaf_guid: Option<u64> = None;
        let mut leaf_pool_guid: Option<u64> = None;
        for label_offset in offsets {
            let config_offset = label_offset + LABEL_CONFIG_OFFSET;
            file.seek(SeekFrom::Start(config_offset))?;
            if file.read_exact(&mut config_buf).is_err() {
                continue;
            }
            if verify_label_checksum(&config_buf, config_offset).is_err() {
                continue;
            }
            let Ok(config) = NvList::parse(&config_buf[..config_buf.len() - 40]) else {
                continue;
            };
            let Some(tree) = config.list("vdev_tree") else {
                continue;
            };
            let Some(ashift_u64) = tree.unsigned("ashift") else {
                continue;
            };
            let Ok(ashift) = u8::try_from(ashift_u64) else {
                continue;
            };
            let Ok(slot_bytes) = uberblock_bytes(ashift) else {
                continue;
            };
            if leaf_guid.is_none() {
                let member_guid = config.unsigned("guid").unwrap_or(0);
                let label_pool_guid = config.unsigned("pool_guid").unwrap_or(0);
                leaf_guid = Some(member_guid);
                leaf_pool_guid = Some(label_pool_guid);
                if first_cfg.is_none() {
                    let top_guid = config.unsigned("top_guid").unwrap_or(0);
                    let version = config.unsigned("version").unwrap_or(0);
                    let label_txg = config.unsigned("txg").unwrap_or(0);
                    let vdev_children = config.unsigned("vdev_children").unwrap_or(1);
                    let required_children = match tree.fields.get("children") {
                        Some(ffs_ondisk::zfs::nvlist::Value::Lists(items)) => items.len(),
                        _ => 1,
                    };
                    let vdev_type = tree.text("type").map(str::to_owned);
                    let asize = tree.unsigned("asize").unwrap_or(0);
                    first_cfg = Some(ZfsPoolLabelMeta {
                        pool_guid: label_pool_guid,
                        top_guid,
                        version,
                        label_txg,
                        ashift,
                        asize,
                        vdev_children,
                        required_children,
                        vdev_type,
                    });
                }
            }
            let ring_offset = label_offset + UBERBLOCK_RING_OFFSET;
            file.seek(SeekFrom::Start(ring_offset))?;
            if file.read_exact(&mut ring_buf).is_err() {
                continue;
            }
            let slots = UBERBLOCK_RING_BYTES / slot_bytes;
            for slot in 0..slots {
                let start = slot * slot_bytes;
                let slot_offset = ring_offset + u64::try_from(start).unwrap_or(u64::MAX);
                if let Ok(ub) = Uberblock::parse(&ring_buf[start..start + slot_bytes], slot_offset)
                {
                    if ub.txg == 0 {
                        continue;
                    }
                    let better = best_ub
                        .as_ref()
                        .is_none_or(|(_, cur)| (ub.txg, ub.timestamp) > (cur.txg, cur.timestamp));
                    if better {
                        best_ub = Some((slot, ub));
                    }
                }
            }
        }
        let Some(m_guid) = leaf_guid else {
            return Ok(None);
        };
        if let (Some(expected), Some(actual_pool_guid)) = (&first_cfg, leaf_pool_guid)
            && expected.pool_guid != actual_pool_guid
        {
            return Err(FfsError::Format(format!(
                "ZFS member {idx} belongs to pool_guid {actual_pool_guid:#x}, expected {:#x}",
                expected.pool_guid
            )));
        }
        if m_guid != 0 && !seen_guids.insert(m_guid) {
            return Err(FfsError::Format(format!(
                "duplicate ZFS member GUID {m_guid:#x} in storage set"
            )));
        }
        pending_member_guids.push((idx, m_guid));
    }

    let (
        Some(ZfsPoolLabelMeta {
            pool_guid,
            top_guid,
            version,
            label_txg,
            ashift,
            asize,
            vdev_children,
            required_children,
            vdev_type,
        }),
        Some((slot, ub)),
    ) = (first_cfg, best_ub)
    else {
        return Ok(None);
    };

    // Commit per-member native GUIDs only after the entire storage set validates.
    let mut member_guids = Vec::with_capacity(pending_member_guids.len());
    for (idx, m_guid) in pending_member_guids {
        if m_guid != 0 {
            specs[idx].native_member_id[..8].copy_from_slice(&m_guid.to_le_bytes());
        }
        member_guids.push(m_guid);
    }

    let data_count = member_guids.len();
    let has_non_data = specs.len() != data_count;
    let is_group_vdev = matches!(vdev_type.as_deref(), Some("mirror" | "raidz" | "draid"));
    let topology_hint = if !has_non_data
        && data_count == 1
        && vdev_children <= 1
        && required_children <= 1
        && !is_group_vdev
    {
        Some(StorageSetTopology::ZfsSingleLeaf)
    } else if !has_non_data
        && vdev_children <= 1
        && vdev_type.as_deref() == Some("mirror")
        && data_count >= 2
        && data_count >= required_children
    {
        u8::try_from(data_count)
            .ok()
            .map(|width| StorageSetTopology::ZfsMirror { width })
    } else {
        Some(StorageSetTopology::ZfsMultiMemberReadOnly {
            vdev_children: u32::try_from(vdev_children).unwrap_or(u32::MAX),
            member_count: u32::try_from(specs.len()).unwrap_or(u32::MAX),
        })
    };

    let root_bp_blake3 = *blake3::hash(format!("{:?}", ub.root).as_bytes()).as_bytes();
    let published_slot = u32::try_from(slot).unwrap_or(u32::MAX);
    Ok(Some(ExtractedNativeSet {
        binding: NativeCommitBinding::Zfs {
            pool_guid,
            top_guid,
            member_guids,
            guid_sum: ub.guid_sum,
            version,
            ashift,
            asize,
            label_txg,
            committed_txg: ub.txg,
            published_slot,
            root_bp_blake3,
            generation: ub.txg,
            operation_digest: [0_u8; 32],
        },
        topology_hint,
    }))
}

#[allow(clippy::too_many_lines)]
fn extract_native_binding_for_set(
    filesystem: &str,
    specs: &mut [StorageSetMemberSpec],
) -> Result<Option<ExtractedNativeSet>> {
    let Some(primary) = specs.first() else {
        return Ok(None);
    };
    let primary_path = primary.image_path.clone();
    match filesystem {
        "ext4" => {
            let mut region = vec![0_u8; EXT4_SUPERBLOCK_SIZE];
            if read_exact_range(
                &primary_path,
                u64::try_from(EXT4_SUPERBLOCK_OFFSET).unwrap_or(1024),
                &mut region,
            )
            .is_err()
            {
                return Ok(None);
            }
            let Ok(sb) = Ext4Superblock::parse_superblock_region(&region) else {
                return Ok(None);
            };
            Ok(Some(ExtractedNativeSet {
                binding: NativeCommitBinding::Ext4 {
                    uuid: sb.uuid,
                    blocks_count: sb.blocks_count,
                    journal_uuid: sb.journal_uuid,
                    journal_inum: sb.journal_inum,
                    state: sb.state,
                },
                topology_hint: None,
            }))
        }
        "btrfs" => {
            let mut region = vec![0_u8; BTRFS_SUPER_INFO_SIZE];
            if read_exact_range(
                &primary_path,
                u64::try_from(BTRFS_SUPER_INFO_OFFSET).unwrap_or(65_536),
                &mut region,
            )
            .is_err()
            {
                return Ok(None);
            }
            let Ok(sb) = BtrfsSuperblock::parse_superblock_region(&region) else {
                return Ok(None);
            };
            Ok(Some(ExtractedNativeSet {
                binding: NativeCommitBinding::Btrfs {
                    fsid: sb.fsid,
                    generation: sb.generation,
                    root_bytenr: sb.root,
                    chunk_root_bytenr: sb.chunk_root,
                    log_root: sb.log_root,
                    num_devices: sb.num_devices,
                },
                topology_hint: None,
            }))
        }
        "fat16" | "fat32" => {
            let mut boot = [0_u8; 512];
            let Ok(len) = read_exact_range(&primary_path, 0, &mut boot) else {
                return Ok(None);
            };
            let Ok(geom) = FatGeometry::parse(&boot, len) else {
                return Ok(None);
            };
            let expected_kind = if filesystem == "fat32" {
                FatKind::Fat32
            } else {
                FatKind::Fat16
            };
            if geom.kind() != expected_kind {
                return Ok(None);
            }
            let ext_offset = if filesystem == "fat32" { 64 } else { 36 };
            let volume_id = if matches!(boot[ext_offset + 2], 0x28 | 0x29) {
                u32::from_le_bytes([
                    boot[ext_offset + 3],
                    boot[ext_offset + 4],
                    boot[ext_offset + 5],
                    boot[ext_offset + 6],
                ])
            } else {
                0
            };
            let total_sectors = if geom.sector_bytes() == 0 {
                0
            } else {
                len / u64::from(geom.sector_bytes())
            };
            Ok(Some(ExtractedNativeSet {
                binding: NativeCommitBinding::Fat {
                    kind: filesystem.to_owned(),
                    volume_id,
                    total_sectors,
                    clean: true,
                },
                topology_hint: None,
            }))
        }
        "ntfs" => {
            let mut boot = [0_u8; 512];
            let Ok(len) = read_exact_range(&primary_path, 0, &mut boot) else {
                return Ok(None);
            };
            let Ok(geo) = NtfsGeometry::parse(&boot, len) else {
                return Ok(None);
            };
            let boot_blake3 = *blake3::hash(&boot).as_bytes();
            Ok(Some(ExtractedNativeSet {
                binding: NativeCommitBinding::Ntfs {
                    volume_serial: geo.serial(),
                    volume_bytes: geo.volume_bytes(),
                    cluster_bytes: geo.cluster_bytes(),
                    record_bytes: geo.record_bytes(),
                    index_bytes: geo.index_bytes(),
                    mft_cluster: geo.mft_cluster(),
                    mirror_cluster: geo.mirror_cluster(),
                    boot_blake3,
                    transaction_id: 0,
                    commit_lsn: 0,
                    checkpoint_lsn: None,
                    generation: 0,
                    operation_digest: [0_u8; 32],
                },
                topology_hint: None,
            }))
        }
        "zfs" => extract_zfs_native_binding(specs),
        _ => Ok(None),
    }
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

#[allow(clippy::too_many_lines)]
fn run(cli: Cli) -> Result<u8> {
    // The standalone consumer owns its capability root. All library work
    // receives this explicit context, including the cancellation signal.
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .map_err(|error| FfsError::Io(std::io::Error::other(error.to_string())))?;
    let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    let _cancel_guard = ActiveCancelGuard::install(&cx)?;
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
            require_native_binding,
            block_size,
            group_blocks,
            repair_symbols,
        } => {
            let signing_key = trust_key_file.as_deref().map(load_por_key).transpose()?;
            let mut specs = collect_specs(&members, &log_members, &special_members);
            let filesystem = match (zfs_dataset.is_some(), filesystem.as_str()) {
                (true, "raw") => "zfs".to_owned(),
                (true, other) if other != "zfs" => {
                    return Err(FfsError::Format(
                        "--zfs-dataset requires a ZFS storage set".into(),
                    ));
                }
                _ => filesystem,
            };
            let (native_binding, topology_hint) = match extract_native_binding_for_set(
                &filesystem,
                &mut specs,
            )? {
                Some(extracted) => (extracted.binding, extracted.topology_hint),
                None if require_native_binding => {
                    return Err(FfsError::Format(format!(
                        "--require-native-binding failed: member image(s) did not parse as native '{filesystem}'"
                    )));
                }
                None => (NativeCommitBinding::UninterpretedRaw, None),
            };
            let view = zfs_dataset
                .as_deref()
                .map(ProtectedViewIdentity::from_zfs_dataset)
                .transpose()?
                .unwrap_or_default();
            let topology = if let Some(hint) = topology_hint {
                hint
            } else if specs.len() == 1 {
                StorageSetTopology::SingleData
            } else if filesystem == "ext4" && !log_members.is_empty() {
                StorageSetTopology::Ext4WithExternalLog
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
                native_binding,
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

    #[test]
    #[allow(clippy::too_many_lines)]
    fn protect_set_extracts_native_ntfs_and_fat_bindings_and_fails_closed_when_required() {
        let dir = tempfile::tempdir().unwrap();

        // 1. Valid NTFS VBR yields a real NativeCommitBinding::Ntfs with volume serial and boot_blake3.
        let ntfs_img = dir.path().join("vol.ntfs");
        let ntfs_rq = dir.path().join("vol.ntfs.ffsrq");
        let ntfs_manifest = dir.path().join("vol.ntfs.ffsrqsm");
        let ntfs_serial = 0x1122_3344_5566_7788_u64;
        let ntfs_boot =
            ffs_ondisk::ntfs::encode_ntfs_boot_sector(&ffs_ondisk::ntfs::NtfsBootSectorSpec {
                sector_bytes: 512,
                sectors_per_cluster: 8,
                total_sectors: 2047,
                mft_cluster: 4,
                mirror_cluster: 16,
                record_bytes: 1024,
                index_bytes: 4096,
                serial: ntfs_serial,
                hidden_sectors: 0,
            })
            .expect("encode ntfs boot sector");
        let mut ntfs_bytes = vec![0_u8; 2048 * 512];
        ntfs_bytes[..512].copy_from_slice(&ntfs_boot);
        std::fs::write(&ntfs_img, &ntfs_bytes).unwrap();
        assert_eq!(
            run(Cli::try_parse_from([
                "ffs-image-repair",
                "protect-set",
                ntfs_manifest.to_str().unwrap(),
                "--filesystem",
                "ntfs",
                "--member",
                ntfs_img.to_str().unwrap(),
                ntfs_rq.to_str().unwrap(),
                "--offline",
                "--require-native-binding",
            ])
            .unwrap())
            .unwrap(),
            0
        );
        let saved_ntfs = ffs_repair::sidecar::StorageSetManifest::decode(
            &std::fs::read(&ntfs_manifest).unwrap(),
            TrustPolicy::AllowUnauthenticated,
        )
        .unwrap();
        match saved_ntfs.native_binding {
            NativeCommitBinding::Ntfs {
                volume_serial,
                mft_cluster,
                boot_blake3,
                ..
            } => {
                assert_eq!(volume_serial, ntfs_serial);
                assert_eq!(mft_cluster, 4);
                assert_eq!(boot_blake3, *blake3::hash(&ntfs_boot).as_bytes());
            }
            other => panic!("expected NativeCommitBinding::Ntfs, got {other:?}"),
        }

        // 2. Valid FAT16 BPB yields NativeCommitBinding::Fat with real BS_VolID serial end-to-end.
        let fat16_img = dir.path().join("vol.fat16");
        let fat16_rq = dir.path().join("vol.fat16.ffsrq");
        let fat16_manifest = dir.path().join("vol.fat16.ffsrqsm");
        let fat16_serial = 0xCAFE_1234_u32;
        let fat16_sectors = 5_000_u16;
        let mut fat16_boot = [0_u8; 512];
        fat16_boot[0..3].copy_from_slice(&[0xEB, 0x3C, 0x90]);
        fat16_boot[3..11].copy_from_slice(b"FRANKEN ");
        fat16_boot[11..13].copy_from_slice(&512_u16.to_le_bytes());
        fat16_boot[13] = 1; // sectors per cluster
        fat16_boot[14..16].copy_from_slice(&1_u16.to_le_bytes()); // reserved sectors
        fat16_boot[16] = 2; // FAT count
        fat16_boot[17..19].copy_from_slice(&512_u16.to_le_bytes()); // root entries
        fat16_boot[19..21].copy_from_slice(&fat16_sectors.to_le_bytes());
        fat16_boot[21] = 0xF8; // media
        fat16_boot[22..24].copy_from_slice(&20_u16.to_le_bytes()); // sectors per FAT
        fat16_boot[38] = 0x29; // extended boot sig (FAT16 ext_offset=36)
        fat16_boot[39..43].copy_from_slice(&fat16_serial.to_le_bytes());
        fat16_boot[43..54].copy_from_slice(b"FAT16BIND  ");
        fat16_boot[54..62].copy_from_slice(b"FAT16   ");
        fat16_boot[510..512].copy_from_slice(&[0x55, 0xAA]);
        let mut fat16_file = File::create(&fat16_img).unwrap();
        fat16_file.set_len(u64::from(fat16_sectors) * 512).unwrap();
        std::io::Write::write_all(&mut fat16_file, &fat16_boot).unwrap();
        drop(fat16_file);
        assert_eq!(
            run(Cli::try_parse_from([
                "ffs-image-repair",
                "protect-set",
                fat16_manifest.to_str().unwrap(),
                "--filesystem",
                "fat16",
                "--member",
                fat16_img.to_str().unwrap(),
                fat16_rq.to_str().unwrap(),
                "--offline",
                "--require-native-binding",
            ])
            .unwrap())
            .unwrap(),
            0
        );
        let saved_fat16 = ffs_repair::sidecar::StorageSetManifest::decode(
            &std::fs::read(&fat16_manifest).unwrap(),
            TrustPolicy::AllowUnauthenticated,
        )
        .unwrap();
        match saved_fat16.native_binding {
            NativeCommitBinding::Fat {
                kind,
                volume_id,
                total_sectors: bound_sectors,
                ..
            } => {
                assert_eq!(kind, "fat16");
                assert_eq!(volume_id, fat16_serial);
                assert_eq!(bound_sectors, u64::from(fat16_sectors));
            }
            other => panic!("expected NativeCommitBinding::Fat (fat16), got {other:?}"),
        }

        // 3. Valid FAT32 BPB extracts BS_VolID at extended offset 64..71 directly.
        let fat32_img = dir.path().join("vol.fat32");
        let fat32_serial = 0xDEAD_BEEF_u32;
        let fat32_sectors = 70_000_u32;
        let mut fat32_boot = [0_u8; 512];
        fat32_boot[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        fat32_boot[3..11].copy_from_slice(b"FRANKEN ");
        fat32_boot[11..13].copy_from_slice(&512_u16.to_le_bytes());
        fat32_boot[13] = 1;
        fat32_boot[14..16].copy_from_slice(&32_u16.to_le_bytes());
        fat32_boot[16] = 2;
        fat32_boot[21] = 0xF8;
        fat32_boot[32..36].copy_from_slice(&fat32_sectors.to_le_bytes());
        fat32_boot[36..40].copy_from_slice(&550_u32.to_le_bytes());
        fat32_boot[44..48].copy_from_slice(&2_u32.to_le_bytes());
        fat32_boot[48..50].copy_from_slice(&1_u16.to_le_bytes());
        fat32_boot[50..52].copy_from_slice(&6_u16.to_le_bytes());
        fat32_boot[66] = 0x29;
        fat32_boot[67..71].copy_from_slice(&fat32_serial.to_le_bytes());
        fat32_boot[71..82].copy_from_slice(b"FAT32BIND  ");
        fat32_boot[82..90].copy_from_slice(b"FAT32   ");
        fat32_boot[510..512].copy_from_slice(&[0x55, 0xAA]);
        let mut fat32_file = File::create(&fat32_img).unwrap();
        fat32_file.set_len(u64::from(fat32_sectors) * 512).unwrap();
        std::io::Write::write_all(&mut fat32_file, &fat32_boot).unwrap();
        drop(fat32_file);
        let mut fat32_specs = vec![StorageSetMemberSpec {
            role: MemberRole::Data,
            image_path: fat32_img,
            sidecar_path: dir.path().join("vol.fat32.ffsrq"),
            native_member_id: [0_u8; 16],
            offset: 0,
            length: None,
        }];
        match extract_native_binding_for_set("fat32", &mut fat32_specs)
            .unwrap()
            .expect("FAT32 binding extracted")
            .binding
        {
            NativeCommitBinding::Fat {
                kind,
                volume_id,
                total_sectors: bound_sectors,
                ..
            } => {
                assert_eq!(kind, "fat32");
                assert_eq!(volume_id, fat32_serial);
                assert_eq!(bound_sectors, u64::from(fat32_sectors));
            }
            other => panic!("expected NativeCommitBinding::Fat (fat32), got {other:?}"),
        }

        // 4. Ext4 + `--log-member` classifies topology as Ext4WithExternalLog (not BtrfsDevices).
        let ext4_data = dir.path().join("ext4_data.img");
        let ext4_data_rq = dir.path().join("ext4_data.ffsrq");
        let ext4_log = dir.path().join("ext4_log.img");
        let ext4_log_rq = dir.path().join("ext4_log.ffsrq");
        let ext4_manifest = dir.path().join("ext4_extlog.ffsrqsm");
        std::fs::write(&ext4_data, vec![0x11_u8; 8192]).unwrap();
        std::fs::write(&ext4_log, vec![0x22_u8; 8192]).unwrap();
        assert_eq!(
            run(Cli::try_parse_from([
                "ffs-image-repair",
                "protect-set",
                ext4_manifest.to_str().unwrap(),
                "--filesystem",
                "ext4",
                "--member",
                ext4_data.to_str().unwrap(),
                ext4_data_rq.to_str().unwrap(),
                "--log-member",
                ext4_log.to_str().unwrap(),
                ext4_log_rq.to_str().unwrap(),
                "--offline",
            ])
            .unwrap())
            .unwrap(),
            0
        );
        let saved_ext4 = ffs_repair::sidecar::StorageSetManifest::decode(
            &std::fs::read(&ext4_manifest).unwrap(),
            TrustPolicy::AllowUnauthenticated,
        )
        .unwrap();
        assert_eq!(saved_ext4.topology, StorageSetTopology::Ext4WithExternalLog);

        // 5. Negative control: `--require-native-binding` fails closed on non-ext4 bytes
        //    without creating either manifest or sidecar.
        let bad_img = dir.path().join("garbage.img");
        let bad_rq = dir.path().join("garbage.ffsrq");
        let bad_manifest = dir.path().join("garbage.ffsrqsm");
        std::fs::write(&bad_img, vec![0x42_u8; 8192]).unwrap();
        assert!(
            run(Cli::try_parse_from([
                "ffs-image-repair",
                "protect-set",
                bad_manifest.to_str().unwrap(),
                "--filesystem",
                "ext4",
                "--member",
                bad_img.to_str().unwrap(),
                bad_rq.to_str().unwrap(),
                "--offline",
                "--require-native-binding",
            ])
            .unwrap())
            .is_err()
        );
        assert!(!bad_manifest.exists() && !bad_rq.exists());
    }
}
