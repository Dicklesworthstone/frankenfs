#![forbid(unsafe_code)]
//! Native NTFS 3.1 inspection, read-only mounts and explicitly admitted transactions.

mod allocation_commands;
mod ea_name;

#[cfg(test)]
mod indexed_tests;

use anyhow::{Context, Result, bail};
use asupersync::Cx;
use clap::{Args, Parser, Subcommand};
use ea_name::EaName;
use ffs_ntfs::transaction::MAX_FILE_EDIT_BYTES;
use ffs_ntfs::{
    NtfsDurableToken, NtfsTransactionEngine, NtfsTxOutcome, NtfsWriteOptions, StreamName, reader,
};
use ffs_ondisk::ntfs::reparse::{NtfsReparseData, NtfsReparsePoint};
use ffs_ondisk::ntfs::{DATA, NtfsFileRecord, NtfsReference, NtfsValue};
use reader::NtfsVolume;
use std::io::{self, Read, Write};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "ffs-ntfs",
    about = "Inspect, mount read-only, and transactionally edit offline NTFS images"
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
        Err(ffs_error::FfsError::ReadOnly)
    }
    fn sync(&self, cx: &Cx) -> ffs_error::Result<()> {
        cx.checkpoint().map_err(|_| ffs_error::FfsError::Cancelled)
    }
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
    /// Optional RaptorQ sidecar archive for read-verification and repair.
    #[arg(long)]
    sidecar: Option<PathBuf>,
    /// Apply supported NTFS $LogFile redo/undo to a read-only in-memory view.
    #[arg(long)]
    recover_logfile: bool,
}
impl ImageArgs {
    fn open(&self, cx: &Cx) -> Result<NtfsVolume> {
        if !self.offline_image {
            bail!(
                "--offline-image is required; an advisory lock does not prevent unrelated writers"
            );
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
                    "admitting NTFS image {} with sidecar {}",
                    self.image.display(),
                    sidecar.display()
                )
            })?;
            let size = ffs_block::ByteDevice::len_bytes(&device);
            return NtfsVolume::from_device_with_options(
                cx,
                Box::new(ReadOnlySidecar(device)),
                self.offset,
                self.length
                    .unwrap_or_else(|| size.saturating_sub(self.offset)),
                self.recover_logfile,
            )
            .with_context(|| {
                format!(
                    "opening sidecar-protected NTFS image {}",
                    self.image.display()
                )
            });
        }
        NtfsVolume::open_with_options(
            cx,
            &self.image,
            self.offset,
            self.length,
            self.recover_logfile,
        )
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

#[derive(Debug, Args)]
struct AdmissionProbeArgs {
    image: PathBuf,
    /// Byte offset of an already selected NTFS volume, not a sector number.
    #[arg(long, default_value_t = 0)]
    offset: u64,
    /// Restrict all reads to this many bytes of the selected volume.
    #[arg(long)]
    length: Option<u64>,
    /// Confirm the image is offline and not mounted by another writer.
    #[arg(long, required = true)]
    offline_image: bool,
}

#[derive(Debug, Args)]
struct TxWriteArgs {
    image: PathBuf,
    /// Byte offset of an already selected NTFS volume, not a sector number.
    #[arg(long, default_value_t = 0)]
    offset: u64,
    /// Restrict all operations to this many bytes of the selected volume.
    #[arg(long)]
    length: Option<u64>,
    /// Confirm the image is offline and not mounted by another writer.
    #[arg(long, required = true)]
    offline_image: bool,
    /// Explicitly authorize native on-disk NTFS journal and metadata mutations.
    #[arg(long, required = true)]
    allow_write: bool,
    /// Authorize persistent ARIES $LogFile redo/undo recovery before mutating if dirty.
    #[arg(long)]
    recover_dirty: bool,
}

impl TxWriteArgs {
    fn open(&self, cx: &Cx, force_recover_dirty: bool) -> Result<NtfsTransactionEngine> {
        if !self.offline_image || !self.allow_write {
            bail!("both --offline-image and --allow-write are required for native NTFS mutations");
        }
        NtfsTransactionEngine::open(
            cx,
            &self.image,
            self.offset,
            self.length,
            NtfsWriteOptions {
                offline_image: self.offline_image,
                allow_write: self.allow_write,
                recover_dirty: self.recover_dirty || force_recover_dirty,
            },
        )
        .with_context(|| {
            format!(
                "opening offline NTFS image {} for native transactions",
                self.image.display()
            )
        })
    }
}

#[derive(Debug, Args)]
struct PayloadArgs {
    /// Exact UTF-8 payload string.
    #[arg(long, conflicts_with_all = ["data_file", "empty"])]
    data: Option<String>,
    /// Read exact binary payload bytes from a host file.
    #[arg(long, conflicts_with_all = ["data", "empty"])]
    data_file: Option<PathBuf>,
    /// Explicitly specify a zero-byte payload.
    #[arg(long, conflicts_with_all = ["data", "data_file"])]
    empty: bool,
}

impl PayloadArgs {
    fn load(&self, require_explicit_selector: bool) -> Result<Vec<u8>> {
        if let Some(text) = &self.data {
            return Ok(text.as_bytes().to_vec());
        }
        if let Some(path) = &self.data_file {
            return std::fs::read(path)
                .with_context(|| format!("reading NTFS payload source {}", path.display()));
        }
        if self.empty || !require_explicit_selector {
            return Ok(Vec::new());
        }
        bail!("specify --data, --data-file, or --empty for a native NTFS write payload")
    }

    fn load_range(&self, start: u64) -> Result<Vec<u8>> {
        // Bound host-file reads before opening a writable image, including when
        // persistent recovery was requested. Empty writes admit any offset.
        let maximum = MAX_FILE_EDIT_BYTES.saturating_sub(start);
        let too_large = || {
            anyhow::anyhow!(
                "tx-write-range payload at --start {start} exceeds the {MAX_FILE_EDIT_BYTES}-byte edit limit"
            )
        };
        if let Some(text) = &self.data
            && u64::try_from(text.len())? > maximum
        {
            return Err(too_large());
        }
        let data = if let Some(path) = &self.data_file {
            let mut bytes = Vec::new();
            std::fs::File::open(path)
                .with_context(|| format!("opening NTFS payload source {}", path.display()))?
                .take(maximum + 1)
                .read_to_end(&mut bytes)
                .with_context(|| format!("reading NTFS payload source {}", path.display()))?;
            bytes
        } else {
            self.load(true)?
        };
        if u64::try_from(data.len())? > maximum {
            return Err(too_large());
        }
        Ok(data)
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Reconcile both $Secure indexes and verify every indexed security descriptor pair.
    CheckSecurity {
        #[command(flatten)]
        image: ImageArgs,
        /// Maximum entries in each native index; a limit never certifies a prefix.
        #[arg(long, default_value_t = 65_536, value_parser = clap::value_parser!(u64).range(1..=65_536))]
        max_entries: u64,
        /// Total metadata work cap, including both copies of every indexed descriptor.
        #[arg(long, default_value_t = 536_870_912, value_parser = clap::value_parser!(u64).range(1..=1_099_511_627_776))]
        max_metadata_bytes: u64,
        /// Also validate every allocated file's security ID or legacy descriptor.
        #[arg(long)]
        verify_file_references: bool,
        /// Maximum logical MFT slots for the reference pass (default: 1048576).
        #[arg(long, requires = "verify_file_references", value_parser = clap::value_parser!(u64).range(1..=16_777_216))]
        max_records: Option<u64>,
    },
    /// Cross-check native allocation, with optional record and namespace validation.
    CheckAllocation {
        #[command(flatten)]
        options: allocation_commands::AllocationArgs,
    },
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
        /// Locate this directory through selected index branches; its listing
        /// still validates every entry. Unvisited ancestor siblings are not checked.
        #[arg(long)]
        indexed_lookup: bool,
    },
    /// Resolve an image path with its native UpCase table and extract DATA.
    Read {
        #[command(flatten)]
        image: ImageArgs,
        path: String,
        /// Search selected native index branches, not every sibling record.
        /// This is not whole-directory consistency checking.
        #[arg(long)]
        indexed_lookup: bool,
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
        /// Search selected index branches while retaining the final link itself.
        /// Unvisited sibling metadata is not checked.
        #[arg(long)]
        indexed_lookup: bool,
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
    /// Enumerate native extended attributes or extract an exact binary EA value.
    Ea {
        #[command(flatten)]
        file: RecordArgs,
        /// Exact UTF-8 name bytes. Omit both selectors to enumerate every EA.
        #[arg(long, conflicts_with = "name_hex", group = "ea_name", value_parser = EaName::parse_text)]
        name: Option<EaName>,
        /// Exact native name bytes as consecutive hex pairs, e.g. 757365722e8241.
        #[arg(long, conflicts_with = "name", group = "ea_name", value_parser = EaName::parse_hex)]
        name_hex: Option<EaName>,
        /// Write the selected value's exact bytes instead of JSON; requires a name.
        #[arg(long, requires = "ea_name")]
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
    /// Probe native NTFS 3.1 writable admission without modifying a single byte.
    AdmitWrite {
        #[command(flatten)]
        probe: AdmissionProbeArgs,
    },
    /// Run persistent ARIES $LogFile redo/undo recovery and publish clean RSTR pages.
    Recover {
        #[command(flatten)]
        target: TxWriteArgs,
    },
    /// Create a regular file in an offline NTFS 3.1 image via a native logged transaction.
    TxCreate {
        #[command(flatten)]
        target: TxWriteArgs,
        parent_path: String,
        name: String,
        #[command(flatten)]
        payload: PayloadArgs,
    },
    /// Create a directory in an offline NTFS 3.1 image via a native logged transaction.
    TxMkdir {
        #[command(flatten)]
        target: TxWriteArgs,
        parent_path: String,
        name: String,
    },
    /// Overwrite an unnamed DATA stream in an offline NTFS 3.1 image via a native logged transaction.
    TxWrite {
        #[command(flatten)]
        target: TxWriteArgs,
        path: String,
        #[command(flatten)]
        payload: PayloadArgs,
    },
    /// Write bytes at a file offset, preserving the suffix and zero-filling any gap beyond EOF.
    TxWriteRange {
        #[command(flatten)]
        target: TxWriteArgs,
        path: String,
        /// Byte offset in the file, distinct from the volume's --offset. A nonempty write's resulting file must fit 16 MiB.
        #[arg(long)]
        start: u64,
        #[command(flatten)]
        payload: PayloadArgs,
    },
    /// Set an unnamed DATA stream's length, zero-filling growth through a native logged transaction.
    TxTruncate {
        #[command(flatten)]
        target: TxWriteArgs,
        path: String,
        /// New file size in bytes, from zero through 16 MiB.
        #[arg(long, value_parser = clap::value_parser!(u64).range(..=MAX_FILE_EDIT_BYTES))]
        size: u64,
    },
    /// Atomically rename an entry in an offline NTFS 3.1 image via a native logged transaction.
    TxRename {
        #[command(flatten)]
        target: TxWriteArgs,
        src_path: String,
        dst_path: String,
        #[arg(long, requires = "expected_sequence")]
        expected_record: Option<u64>,
        #[arg(long, requires = "expected_record")]
        expected_sequence: Option<u16>,
    },
    /// Unlink a regular file in an offline NTFS 3.1 image via a native logged transaction.
    TxUnlink {
        #[command(flatten)]
        target: TxWriteArgs,
        path: String,
    },
    /// Grow $MFT logical record capacity in an offline NTFS 3.1 image via a native logged transaction.
    TxGrowMft {
        #[command(flatten)]
        target: TxWriteArgs,
        #[arg(long, value_parser = clap::value_parser!(u32).range(1..=65_536))]
        records: u32,
    },
}

fn emit_tx_outcome<T>(
    operation: &str,
    engine: &NtfsTransactionEngine,
    outcome: NtfsTxOutcome<T>,
    encode_value: impl FnOnce(T) -> serde_json::Value,
) -> Result<()> {
    match outcome {
        NtfsTxOutcome::Committed { value, token } => {
            let verified = token.matches_engine(engine);
            if !verified {
                bail!("NTFS transaction token failed storage/view binding verification");
            }
            let result_value = encode_value(value);
            let report = token_report_json(operation, engine, &token, &result_value);
            json(&report)
        }
        NtfsTxOutcome::NotCommitted(err) => {
            bail!("NTFS transaction not_committed ({operation}): {err}")
        }
        NtfsTxOutcome::Uncertain {
            reason,
            transaction_id,
            commit_lsn,
        } => {
            bail!(
                "NTFS transaction uncertain ({operation}, tx={transaction_id}, commit_lsn={commit_lsn:#x}): {reason}"
            )
        }
    }
}

fn token_report_json(
    operation: &str,
    engine: &NtfsTransactionEngine,
    token: &NtfsDurableToken,
    result_value: &serde_json::Value,
) -> serde_json::Value {
    serde_json::json!({
        "format": "NTFS",
        "version": "3.1",
        "operation": operation,
        "outcome": "committed",
        "result": result_value,
        "token": token,
        "storage_identity": engine.storage_identity(),
        "recovery": engine.last_recovery(),
    })
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

fn ea_json(catalog: &reader::ea::EaCatalog, selected: Option<&[u8]>) -> Result<serde_json::Value> {
    let entries: Vec<_> = if let Some(name) = selected {
        vec![catalog.find(name).context("native EA name was not found")?]
    } else {
        catalog.entries.iter().collect()
    };
    let entries: Vec<_> = entries
        .into_iter()
        .map(|entry| {
            serde_json::json!({
                "name": std::str::from_utf8(&entry.name).ok(),
                "name_bytes": entry.name,
                "flags": entry.flags,
                "need_ea": entry.need_ea(),
                "value_length": entry.value.len(),
                "value_bytes": entry.value,
            })
        })
        .collect();
    Ok(serde_json::json!({
        "present": catalog.information.is_some(),
        "packed_bytes": catalog.information.map(|info| info.packed_bytes),
        "unpacked_bytes": catalog.information.map(|info| info.unpacked_bytes),
        "need_ea_count": catalog.information.map(|info| info.need_ea_count),
        "entries": entries,
        "scope": "native EA metadata; values do not project host security or DATA streams",
    }))
}

fn security_check_limits(
    image: &ImageArgs,
    entries: u64,
    metadata_bytes: u64,
) -> Result<reader::security::SecurityCheckLimits> {
    if image.sidecar.is_some() || image.recover_logfile {
        bail!(
            "security checking requires original image bytes without a sidecar or recovery overlay"
        );
    }
    let limits = reader::security::SecurityCheckLimits {
        entries: usize::try_from(entries)?,
        metadata_bytes,
    };
    limits.validate()?;
    Ok(limits)
}

fn security_check_json(
    report: &reader::security::SecurityCheckReport,
    offset: u64,
) -> serde_json::Value {
    serde_json::json!({
        "format": "NTFS",
        "operation": "check_security",
        "scope": "complete_sii_sdh_indexes_and_indexed_sds_pairs",
        "read_only": true,
        "backing_writes": false,
        "repair_performed": false,
        "replay_performed": false,
        "volume_offset": offset,
        "complete": true,
        "consistent": true,
        "secure_record": report.secure_reference.record,
        "secure_sequence": report.secure_reference.sequence,
        "security_ids": report.security_ids,
        "hash_entries": report.hash_entries,
        "index_blocks": report.index_blocks,
        "descriptor_bytes": report.descriptor_bytes,
        "metadata_bytes": report.metadata_bytes,
        "not_checked": [
            "unindexed SDS records, gaps and padding",
            "file STANDARD_INFORMATION security IDs and legacy SECURITY_DESCRIPTOR attributes",
            "cluster allocation ownership, namespace, journal state and native recovery",
            "access decisions, host ACL projection and writable admission"
        ]
    })
}

fn security_reference_check_json(
    report: &reader::security::SecurityReferenceReport,
    offset: u64,
) -> serde_json::Value {
    let mut output = security_check_json(&report.store, offset);
    output["scope"] = "sii_sdh_indexed_sds_and_allocated_file_security".into();
    output["complete"] = report.complete.into();
    output["consistent"] = report.is_consistent().into();
    output["metadata_bytes"] = report.metadata_bytes.into();
    output["file_references"] = serde_json::json!({
        "logical_records": report.logical_records,
        "initialized_records": report.initialized_records,
        "record_slots_examined": report.record_slots_examined,
        "base_records_examined": report.base_records_examined,
        "extension_records_examined": report.extension_records_examined,
        "shared_references_examined": report.shared_references_examined,
        "missing_shared_references": report.missing_shared_references,
        "legacy_descriptors_checked": report.legacy_descriptors_checked,
        "extensions_without_owner": report.extensions_without_owner,
        "limit_reached": report.limit_reached,
        "errors": report.errors,
        "unsupported": report.unsupported,
        "omitted_issues": report.omitted_issues,
        "issues": report.issues.iter().map(|issue| serde_json::json!({
            "record": issue.record,
            "category": issue.category,
            "security_id": issue.security_id,
            "detail": issue.detail,
        })).collect::<Vec<_>>(),
    });
    output["not_checked"] = serde_json::json!([
        "unindexed SDS records, gaps and padding",
        "cluster allocation ownership, namespace, journal state and native recovery",
        "access decisions, host ACL projection and writable admission"
    ]);
    output
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .blocking_threads(0, 0)
        .build()
        .map_err(|err| anyhow::anyhow!("failed to build ffs-ntfs runtime: {err}"))?;
    let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
    match cli.command {
        Command::CheckSecurity {
            image,
            max_entries,
            max_metadata_bytes,
            verify_file_references,
            max_records,
        } => {
            let limits = security_check_limits(&image, max_entries, max_metadata_bytes)?;
            let volume = image.open(&cx)?;
            if verify_file_references {
                let report = volume
                    .check_security_references(&cx, limits, max_records.unwrap_or(1_048_576))
                    .context("checking native NTFS security store and allocated file references")?;
                json(&security_reference_check_json(&report, image.offset))?;
                if !report.is_consistent() {
                    bail!("NTFS file security reference checking is inconsistent or incomplete");
                }
            } else {
                let report = volume.check_security(&cx, limits).context(
                    "checking complete native NTFS security indexes and descriptor pairs",
                )?;
                json(&security_check_json(&report, image.offset))?;
            }
        }
        Command::CheckAllocation { options } => allocation_commands::run(&cx, &options)?,
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
                "mft_mirror_record_zero_matches": true, "volume_flags": volume.volume_flags,
                "logfile_recovery": volume.logfile_recovery.as_ref().map(|plan| serde_json::json!({
                    "current_lsn": plan.restart.current_lsn,
                    "restart_lsn": plan.restart.client_restart_lsn,
                    "committed_transactions": plan.committed_transactions,
                    "aborted_transactions": plan.aborted_transactions,
                    "redo_actions": plan.redo_actions.len(),
                    "undo_actions": plan.undo_actions.len(),
                })),
                "scope": "offline MFT/stream read profile; not a filesystem check or recovery validation"
            }))?;
        }
        Command::Ls {
            image,
            path,
            indexed_lookup,
        } => {
            let volume = image.open(&cx)?;
            let record = if indexed_lookup {
                volume.resolve_indexed(&cx, &path)?
            } else {
                volume.resolve(&cx, &path)?
            };
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
            indexed_lookup,
            stream,
            stream_utf16,
            start,
            bytes,
        } => {
            let stream =
                StreamName::select(stream.as_deref(), stream_utf16).map_err(anyhow::Error::msg)?;
            let volume = image.open(&cx)?;
            let record = if indexed_lookup {
                volume.resolve_indexed(&cx, &path)?
            } else {
                volume.resolve(&cx, &path)?
            };
            stream_to_stdout(&cx, &volume, &record, stream.as_units(), start, bytes)?;
        }
        Command::Readlink {
            image,
            path,
            indexed_lookup,
        } => {
            let volume = image.open(&cx)?;
            let record = if indexed_lookup {
                volume.resolve_indexed_no_follow(&cx, &path)?
            } else {
                volume.resolve_no_follow(&cx, &path)?
            };
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
        Command::Ea {
            file,
            name,
            name_hex,
            raw,
        } => {
            let selected = name.or(name_hex);
            let volume = file.image.open(&cx)?;
            let record = volume.record(&cx, file.record, file.sequence)?;
            let catalog = volume.extended_attributes(&cx, &record)?;
            if raw {
                let name = selected
                    .as_ref()
                    .context("--raw requires an exact EA name")?;
                let entry = catalog
                    .find(name.as_bytes())
                    .context("native EA name was not found")?;
                let mut out = io::stdout().lock();
                out.write_all(&entry.value)?;
                out.flush()?;
            } else {
                json(&serde_json::json!({
                    "record": record.number,
                    "sequence": record.sequence,
                    "extended_attributes": ea_json(&catalog, selected.as_ref().map(EaName::as_bytes))?,
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
            let fs = if image.recover_logfile {
                reader::filesystem::NtfsFs::new_recovered(&cx, volume, uid, gid)?
            } else {
                reader::filesystem::NtfsFs::new(&cx, volume, uid, gid)?
            };
            let options = ffs_fuse::MountOptions {
                read_only: true,
                allow_other: false,
                auto_unmount: true,
                ..ffs_fuse::MountOptions::default()
            };
            eprintln!(
                "experimental NTFS read-only mount: {} view; offline immutable image required; native ACLs are not enforced",
                if image.recover_logfile {
                    "volatile log-recovery"
                } else {
                    "clean-log"
                }
            );
            let _ = ffs_fuse::mount(Box::new(fs), &mountpoint, &options)?;
        }
        Command::AdmitWrite { probe } => {
            if !probe.offline_image {
                bail!(
                    "--offline-image is required; an advisory lock does not prevent unrelated writers"
                );
            }
            let report = NtfsTransactionEngine::admit_read_only_probe(
                &cx,
                &probe.image,
                probe.offset,
                probe.length,
            )
            .with_context(|| {
                format!(
                    "probing native NTFS writable admission on {}",
                    probe.image.display()
                )
            })?;
            json(&serde_json::json!({
                "format": "NTFS",
                "version": "3.1",
                "operation": "admit_write",
                "read_only": true,
                "backing_writes": false,
                "volume_offset": probe.offset,
                "admission": report,
            }))?;
        }
        Command::Recover { target } => {
            let engine = target.open(&cx, true)?;
            engine.check_clean_consistency(&cx)?;
            json(&serde_json::json!({
                "format": "NTFS",
                "version": "3.1",
                "operation": "recover",
                "outcome": "clean",
                "storage_identity": engine.storage_identity(),
                "recovery": engine.last_recovery().cloned().unwrap_or_default(),
            }))?;
        }
        Command::TxCreate {
            target,
            parent_path,
            name,
            payload,
        } => {
            let initial_data = payload.load(false)?;
            let mut engine = target.open(&cx, false)?;
            let outcome = engine.create_file(&cx, &parent_path, &name, &initial_data);
            emit_tx_outcome("tx_create", &engine, outcome, |reference| {
                serde_json::json!({
                    "record": reference.record,
                    "sequence": reference.sequence,
                    "bytes": initial_data.len(),
                })
            })?;
        }
        Command::TxMkdir {
            target,
            parent_path,
            name,
        } => {
            let mut engine = target.open(&cx, false)?;
            let outcome = engine.mkdir(&cx, &parent_path, &name);
            emit_tx_outcome("tx_mkdir", &engine, outcome, |reference| {
                serde_json::json!({
                    "record": reference.record,
                    "sequence": reference.sequence,
                })
            })?;
        }
        Command::TxWrite {
            target,
            path,
            payload,
        } => {
            let data = payload.load(true)?;
            let mut engine = target.open(&cx, false)?;
            let outcome = engine.write_file_data(&cx, &path, &data);
            emit_tx_outcome("tx_write", &engine, outcome, |reference| {
                serde_json::json!({
                    "record": reference.record,
                    "sequence": reference.sequence,
                    "bytes": data.len(),
                })
            })?;
        }
        Command::TxWriteRange {
            target,
            path,
            start,
            payload,
        } => {
            let data = payload.load_range(start)?;
            let mut engine = target.open(&cx, false)?;
            let outcome = engine.write_file_range(&cx, &path, start, &data);
            emit_tx_outcome("tx_write_range", &engine, outcome, |reference| {
                serde_json::json!({
                    "record": reference.record,
                    "sequence": reference.sequence,
                    "start": start,
                    "bytes": data.len(),
                })
            })?;
        }
        Command::TxTruncate { target, path, size } => {
            let mut engine = target.open(&cx, false)?;
            let outcome = engine.truncate_file(&cx, &path, size);
            emit_tx_outcome("tx_truncate", &engine, outcome, |reference| {
                serde_json::json!({
                    "record": reference.record,
                    "sequence": reference.sequence,
                    "size": size,
                })
            })?;
        }
        Command::TxRename {
            target,
            src_path,
            dst_path,
            expected_record,
            expected_sequence,
        } => {
            let expected = match (expected_record, expected_sequence) {
                (Some(record), Some(sequence)) => Some(NtfsReference { record, sequence }),
                (None, None) => None,
                _ => bail!("--expected-record and --expected-sequence must be provided together"),
            };
            let mut engine = target.open(&cx, false)?;
            let outcome = engine.rename_entry(&cx, &src_path, &dst_path, expected);
            emit_tx_outcome("tx_rename", &engine, outcome, |reference| {
                serde_json::json!({
                    "record": reference.record,
                    "sequence": reference.sequence,
                })
            })?;
        }
        Command::TxUnlink { target, path } => {
            let mut engine = target.open(&cx, false)?;
            let outcome = engine.unlink_file(&cx, &path);
            emit_tx_outcome("tx_unlink", &engine, outcome, |reference| {
                serde_json::json!({
                    "record": reference.record,
                    "sequence": reference.sequence,
                })
            })?;
        }
        Command::TxGrowMft { target, records } => {
            let mut engine = target.open(&cx, false)?;
            let outcome = engine.grow_mft(&cx, records);
            emit_tx_outcome("tx_grow_mft", &engine, outcome, |logical_records| {
                serde_json::json!({
                    "added_records": records,
                    "logical_records": logical_records,
                })
            })?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_security_check_enforces_bounds_original_bytes_and_explicit_offline_image() {
        assert!(Cli::try_parse_from(["ffs-ntfs", "check-security", "disk.img"]).is_err());
        let cli = Cli::try_parse_from([
            "ffs-ntfs",
            "check-security",
            "disk.img",
            "--offline-image",
            "--offset",
            "1024",
            "--length",
            "65536",
            "--max-entries",
            "3",
            "--max-metadata-bytes",
            "4096",
        ])
        .unwrap();
        let Command::CheckSecurity {
            mut image,
            max_entries,
            max_metadata_bytes,
            verify_file_references,
            max_records,
        } = cli.command
        else {
            panic!("check-security");
        };
        let limits = security_check_limits(&image, max_entries, max_metadata_bytes).unwrap();
        assert!(!verify_file_references);
        assert_eq!(max_records, None);
        assert_eq!((limits.entries, limits.metadata_bytes), (3, 4096));
        assert_eq!((image.offset, image.length), (1024, Some(65536)));
        image.recover_logfile = true;
        assert!(security_check_limits(&image, max_entries, max_metadata_bytes).is_err());
        image.recover_logfile = false;
        image.sidecar = Some(PathBuf::from("disk.rq"));
        assert!(security_check_limits(&image, max_entries, max_metadata_bytes).is_err());
        for (flag, value) in [
            ("--max-entries", "0"),
            ("--max-entries", "65537"),
            ("--max-metadata-bytes", "0"),
        ] {
            assert!(
                Cli::try_parse_from([
                    "ffs-ntfs",
                    "check-security",
                    "disk.img",
                    "--offline-image",
                    flag,
                    value
                ])
                .is_err()
            );
        }
    }

    #[test]
    fn security_check_report_names_its_scope_without_claiming_volume_consistency() {
        let report = reader::security::SecurityCheckReport {
            secure_reference: ffs_ondisk::ntfs::NtfsReference {
                record: 9,
                sequence: 17,
            },
            security_ids: 3,
            hash_entries: 3,
            index_blocks: 4,
            descriptor_bytes: 288,
            metadata_bytes: 18000,
        };
        let json = security_check_json(&report, 1024);
        assert_eq!(json["secure_sequence"], 17);
        assert_eq!(json["hash_entries"], 3);
        assert_eq!(
            json["scope"],
            "complete_sii_sdh_indexes_and_indexed_sds_pairs"
        );
        assert_eq!(json["backing_writes"], false);
        assert_eq!(json["not_checked"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn file_security_reference_check_is_explicit_and_record_bounded() {
        assert!(
            Cli::try_parse_from([
                "ffs-ntfs",
                "check-security",
                "image.img",
                "--offline-image",
                "--max-records",
                "32",
            ])
            .is_err()
        );
        let cli = Cli::try_parse_from([
            "ffs-ntfs",
            "check-security",
            "image.img",
            "--offline-image",
            "--verify-file-references",
            "--max-records",
            "32",
        ])
        .unwrap();
        let Command::CheckSecurity {
            verify_file_references,
            max_records,
            ..
        } = cli.command
        else {
            panic!("check-security");
        };
        assert!(verify_file_references);
        assert_eq!(max_records, Some(32));
        for value in ["0", "16777217"] {
            assert!(
                Cli::try_parse_from([
                    "ffs-ntfs",
                    "check-security",
                    "image.img",
                    "--offline-image",
                    "--verify-file-references",
                    "--max-records",
                    value,
                ])
                .is_err()
            );
        }
    }

    #[test]
    fn file_reference_report_never_promotes_a_verified_store_over_missing_or_partial_files() {
        let mut report = reader::security::SecurityReferenceReport {
            store: reader::security::SecurityCheckReport {
                secure_reference: ffs_ondisk::ntfs::NtfsReference {
                    record: 9,
                    sequence: 7,
                },
                security_ids: 3,
                hash_entries: 3,
                index_blocks: 0,
                descriptor_bytes: 288,
                metadata_bytes: 2000,
            },
            logical_records: 32,
            initialized_records: 32,
            record_slots_examined: 32,
            base_records_examined: 5,
            extension_records_examined: 0,
            shared_references_examined: 3,
            missing_shared_references: 1,
            legacy_descriptors_checked: 2,
            extensions_without_owner: Some(0),
            metadata_bytes: 9000,
            complete: true,
            limit_reached: None,
            errors: 1,
            unsupported: 0,
            issues: vec![reader::security::SecurityReferenceIssue {
                record: 31,
                category: "missing_security_id",
                security_id: Some(1024),
                detail: "missing from complete native store".into(),
            }],
            omitted_issues: 0,
        };
        let json = security_reference_check_json(&report, 1024);
        assert_eq!(json["consistent"], false);
        assert_eq!(json["complete"], true);
        assert_eq!(json["metadata_bytes"], 9000);
        assert_eq!(json["file_references"]["issues"][0]["security_id"], 1024);
        assert_eq!(json["backing_writes"], false);
        assert_eq!(json["not_checked"].as_array().unwrap().len(), 3);
        report.complete = false;
        report.errors = 0;
        report.missing_shared_references = 0;
        report.extensions_without_owner = None;
        report.limit_reached = Some("metadata work budget");
        report.issues.clear();
        let json = security_reference_check_json(&report, 1024);
        assert_eq!(json["complete"], false);
        assert_eq!(json["consistent"], false);
        assert!(json["file_references"]["extensions_without_owner"].is_null());
        assert_eq!(
            json["file_references"]["limit_reached"],
            "metadata work budget"
        );
    }

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
            recover_logfile: false,
        };
        let Err(error) = args.open(&cx) else {
            panic!("one-byte native volume must be refused");
        };
        // An exclusive writable open fails at sidecar admission. A genuine
        // read-only caller reaches native geometry admission while sharing locks.
        assert!(
            error
                .to_string()
                .contains("opening sidecar-protected NTFS image")
        );
        assert_eq!(std::fs::read(&image).unwrap(), original);
        assert_eq!(std::fs::read(&archive).unwrap(), before);
        assert!(SidecarImageDevice::open(&cx, &image, &archive).is_err());
    }

    #[test]
    fn cli_ea_selectors_require_offline_identity_and_one_exact_name_for_raw_output() {
        assert!(Cli::try_parse_from(["ffs-ntfs", "ea", "disk.img", "24"]).is_err());
        assert!(
            Cli::try_parse_from([
                "ffs-ntfs",
                "ea",
                "disk.img",
                "24",
                "--offline-image",
                "--raw",
            ])
            .is_err()
        );
        let cli = Cli::try_parse_from([
            "ffs-ntfs",
            "ea",
            "disk.img",
            "24",
            "--offline-image",
            "--sequence",
            "7",
            "--offset",
            "1024",
            "--length",
            "65536",
            "--name-hex",
            "757365722e8241",
            "--raw",
        ])
        .unwrap();
        let Command::Ea {
            file,
            name,
            name_hex,
            raw,
        } = cli.command
        else {
            panic!("ea extraction");
        };
        assert_eq!((file.record, file.sequence), (24, Some(7)));
        assert_eq!((file.image.offset, file.image.length), (1024, Some(65536)));
        assert!(raw && name.is_none());
        assert_eq!(name_hex.unwrap().as_bytes(), b"user.\x82A");
        for selector in ["00", "aa,b1", "a"] {
            assert!(
                Cli::try_parse_from([
                    "ffs-ntfs",
                    "ea",
                    "disk.img",
                    "24",
                    "--offline-image",
                    "--name-hex",
                    selector,
                ])
                .is_err()
            );
        }
        assert!(
            Cli::try_parse_from([
                "ffs-ntfs",
                "ea",
                "disk.img",
                "24",
                "--offline-image",
                "--name",
                "user.A",
                "--name-hex",
                "757365722e41",
            ])
            .is_err()
        );
        let cli = Cli::try_parse_from([
            "ffs-ntfs",
            "ea",
            "disk.img",
            "24",
            "--offline-image",
            "--name",
            "user.A",
            "--raw",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Command::Ea {
                name: Some(_),
                name_hex: None,
                raw: true,
                ..
            }
        ));
        let cli =
            Cli::try_parse_from(["ffs-ntfs", "ea", "disk.img", "24", "--offline-image"]).unwrap();
        assert!(matches!(
            cli.command,
            Command::Ea {
                name: None,
                name_hex: None,
                raw: false,
                ..
            }
        ));
    }

    #[test]
    fn ea_json_preserves_native_names_binary_values_and_exact_absence() {
        use ffs_ondisk::ntfs::ea::{FILE_NEED_EA, NtfsEa, NtfsEaInformation};
        let catalog = reader::ea::EaCatalog {
            information: Some(NtfsEaInformation {
                packed_bytes: 20,
                need_ea_count: 1,
                unpacked_bytes: 32,
            }),
            entries: vec![
                NtfsEa {
                    name: vec![0x82, b'A'],
                    flags: FILE_NEED_EA,
                    value: vec![0, 0xFF, 1],
                },
                NtfsEa {
                    name: b"empty".to_vec(),
                    flags: 0,
                    value: Vec::new(),
                },
            ],
        };
        let report = ea_json(&catalog, None).unwrap();
        assert_eq!(report["present"], true);
        assert_eq!(report["need_ea_count"], 1);
        assert_eq!(report["entries"][0]["name"], serde_json::Value::Null);
        assert_eq!(
            report["entries"][0]["name_bytes"],
            serde_json::json!([0x82, b'A'])
        );
        assert_eq!(
            report["entries"][0]["value_bytes"],
            serde_json::json!([0, 255, 1])
        );
        assert_eq!(report["entries"][0]["need_ea"], true);
        assert_eq!(report["entries"][1]["value_length"], 0);
        let selected = ea_json(&catalog, Some(&[0x82, b'A'])).unwrap();
        assert_eq!(selected["entries"].as_array().unwrap().len(), 1);
        assert!(ea_json(&catalog, Some(b"EMPTY")).is_err());
        let absent = reader::ea::EaCatalog {
            information: None,
            entries: Vec::new(),
        };
        assert_eq!(ea_json(&absent, None).unwrap()["present"], false);
        assert!(ea_json(&absent, Some(b"empty")).is_err());
    }

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
        assert!(!image.recover_logfile);
        let recovered = Cli::try_parse_from([
            "ffs-ntfs",
            "mount",
            "disk.img",
            "/mnt/ntfs",
            "--offline-image",
            "--recover-logfile",
        ])
        .unwrap();
        let Command::Mount { image, .. } = recovered.command else {
            panic!("mount");
        };
        assert!(image.recover_logfile);
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
            let (Command::Read {
                stream,
                stream_utf16: native,
                start,
                bytes,
                ..
            }
            | Command::Cat {
                stream,
                stream_utf16: native,
                start,
                bytes,
                ..
            }) = cli.command
            else {
                panic!("stream extraction");
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

    #[test]
    fn cli_admit_write_requires_offline_image_rejects_write_flags_and_mutates_nothing() {
        assert!(Cli::try_parse_from(["ffs-ntfs", "admit-write", "disk.img"]).is_err());
        assert!(
            Cli::try_parse_from([
                "ffs-ntfs",
                "admit-write",
                "disk.img",
                "--offline-image",
                "--allow-write",
            ])
            .is_err()
        );
        let cli = Cli::try_parse_from([
            "ffs-ntfs",
            "admit-write",
            "disk.img",
            "--offline-image",
            "--offset",
            "1048576",
            "--length",
            "67108864",
        ])
        .unwrap();
        let Command::AdmitWrite { probe } = cli.command else {
            panic!("admit-write");
        };
        assert_eq!(
            (probe.offset, probe.length, probe.offline_image),
            (1_048_576, Some(67_108_864), true)
        );

        let dir = tempfile::tempdir().unwrap();
        let scratch = dir.path().join("non-ntfs.img");
        let original = vec![0xA5_u8; 4096];
        std::fs::write(&scratch, &original).unwrap();
        let cx = Cx::for_testing();
        assert!(NtfsTransactionEngine::admit_read_only_probe(&cx, &scratch, 0, None).is_err());
        assert_eq!(std::fs::read(&scratch).unwrap(), original);
    }

    #[test]
    fn cli_native_tx_subcommands_fail_closed_without_both_offline_and_allow_write() {
        let cases: &[&[&str]] = &[
            &["ffs-ntfs", "recover", "disk.img"],
            &["ffs-ntfs", "tx-create", "disk.img", "/", "a.txt"],
            &["ffs-ntfs", "tx-mkdir", "disk.img", "/", "sub"],
            &[
                "ffs-ntfs", "tx-write", "disk.img", "/a.txt", "--data", "abc",
            ],
            &[
                "ffs-ntfs",
                "tx-write-range",
                "disk.img",
                "/a.txt",
                "--start",
                "3",
                "--data",
                "abc",
            ],
            &[
                "ffs-ntfs",
                "tx-truncate",
                "disk.img",
                "/a.txt",
                "--size",
                "0",
            ],
            &["ffs-ntfs", "tx-rename", "disk.img", "/a.txt", "/b.txt"],
            &["ffs-ntfs", "tx-unlink", "disk.img", "/a.txt"],
            &["ffs-ntfs", "tx-grow-mft", "disk.img", "--records", "8"],
        ];
        for base in cases {
            assert!(
                Cli::try_parse_from(base.iter().copied()).is_err(),
                "missing both authorization flags must fail: {base:?}"
            );
            let mut only_offline = base.to_vec();
            only_offline.push("--offline-image");
            assert!(
                Cli::try_parse_from(only_offline).is_err(),
                "missing --allow-write must fail: {base:?}"
            );
            let mut only_write = base.to_vec();
            only_write.push("--allow-write");
            assert!(
                Cli::try_parse_from(only_write).is_err(),
                "missing --offline-image must fail: {base:?}"
            );
            let mut both = base.to_vec();
            both.extend(["--offline-image", "--allow-write"]);
            assert!(
                Cli::try_parse_from(both).is_ok(),
                "explicit dual authorization must parse: {base:?}"
            );
        }

        let dir = tempfile::tempdir().unwrap();
        let scratch = dir.path().join("guard.img");
        let original = vec![0x5A_u8; 4096];
        std::fs::write(&scratch, &original).unwrap();
        let cx = Cx::for_testing();
        for (offline_image, allow_write) in [(false, false), (true, false), (false, true)] {
            let args = TxWriteArgs {
                image: scratch.clone(),
                offset: 0,
                length: None,
                offline_image,
                allow_write,
                recover_dirty: false,
            };
            assert!(args.open(&cx, false).is_err());
        }
        assert_eq!(std::fs::read(&scratch).unwrap(), original);
    }

    #[test]
    fn cli_range_edits_distinguish_file_and_volume_offsets_and_enforce_sizes() {
        let cli = Cli::try_parse_from([
            "ffs-ntfs",
            "tx-write-range",
            "disk.img",
            "/a.bin",
            "--offline-image",
            "--allow-write",
            "--recover-dirty",
            "--offset",
            "1048576",
            "--length",
            "67108864",
            "--start",
            "4099",
            "--data-file",
            "payload.bin",
        ])
        .unwrap();
        let Command::TxWriteRange {
            target,
            path,
            start,
            payload,
        } = cli.command
        else {
            panic!("tx-write-range");
        };
        assert_eq!(
            (target.offset, target.length),
            (1_048_576, Some(67_108_864))
        );
        assert!(target.offline_image && target.allow_write && target.recover_dirty);
        assert_eq!((path.as_str(), start), ("/a.bin", 4099));
        assert_eq!(payload.data_file, Some(PathBuf::from("payload.bin")));

        let range_base = [
            "ffs-ntfs",
            "tx-write-range",
            "disk.img",
            "/a.bin",
            "--offline-image",
            "--allow-write",
            "--empty",
        ];
        assert!(Cli::try_parse_from(range_base).is_err());
        for start in ["-1", "18446744073709551616"] {
            assert!(Cli::try_parse_from(range_base.into_iter().chain(["--start", start])).is_err());
        }
        assert!(
            Cli::try_parse_from(range_base.into_iter().chain([
                "--start",
                "0",
                "--data",
                "conflicting payload",
            ]))
            .is_err()
        );
        let cli = Cli::try_parse_from(
            range_base
                .into_iter()
                .chain(["--start", "18446744073709551615"]),
        )
        .unwrap();
        let Command::TxWriteRange { start, payload, .. } = cli.command else {
            panic!("empty range write");
        };
        assert_eq!(start, u64::MAX);
        assert_eq!(payload.load_range(start).unwrap(), Vec::<u8>::new());

        let truncate_base = [
            "ffs-ntfs",
            "tx-truncate",
            "disk.img",
            "/a.bin",
            "--offline-image",
            "--allow-write",
        ];
        assert!(Cli::try_parse_from(truncate_base).is_err());
        for (argument, expected) in [("0", 0), ("16777216", MAX_FILE_EDIT_BYTES)] {
            let cli =
                Cli::try_parse_from(truncate_base.into_iter().chain(["--size", argument])).unwrap();
            let Command::TxTruncate { size, .. } = cli.command else {
                panic!("tx-truncate");
            };
            assert_eq!(size, expected);
        }
        for invalid in ["-1", "16777217", "18446744073709551615"] {
            assert!(
                Cli::try_parse_from(truncate_base.into_iter().chain(["--size", invalid])).is_err()
            );
        }
    }

    #[test]
    fn cli_range_payload_reads_are_binary_exact_and_bounded_before_image_open() {
        let directory = tempfile::tempdir().unwrap();
        let source = directory.path().join("payload.bin");
        let bytes = [0x00, 0xFF, 0x80, 0x41];
        std::fs::write(&source, bytes).unwrap();
        let payload = PayloadArgs {
            data: None,
            data_file: Some(source.clone()),
            empty: false,
        };
        assert_eq!(payload.load_range(MAX_FILE_EDIT_BYTES - 4).unwrap(), bytes);
        assert!(payload.load_range(MAX_FILE_EDIT_BYTES - 3).is_err());
        assert!(payload.load_range(u64::MAX).is_err());
        assert_eq!(std::fs::read(&source).unwrap(), bytes);

        let oversized = directory.path().join("oversized.bin");
        std::fs::File::create(&oversized)
            .unwrap()
            .set_len(MAX_FILE_EDIT_BYTES + 1)
            .unwrap();
        let payload = PayloadArgs {
            data: None,
            data_file: Some(oversized),
            empty: false,
        };
        assert!(payload.load_range(0).is_err());
        let payload = PayloadArgs {
            data: Some("é".into()),
            data_file: None,
            empty: false,
        };
        assert_eq!(
            payload.load_range(MAX_FILE_EDIT_BYTES - 2).unwrap(),
            "é".as_bytes()
        );
        assert!(payload.load_range(MAX_FILE_EDIT_BYTES - 1).is_err());
        let missing = PayloadArgs {
            data: None,
            data_file: None,
            empty: false,
        };
        assert!(missing.load_range(0).is_err());
    }

    #[test]
    fn cli_tx_payload_rename_expectation_and_mft_growth_bounds_are_enforced() {
        let missing_payload = PayloadArgs {
            data: None,
            data_file: None,
            empty: false,
        };
        assert_eq!(missing_payload.load(false).unwrap(), Vec::<u8>::new());
        assert!(missing_payload.load(true).is_err());
        let empty_payload = PayloadArgs {
            data: None,
            data_file: None,
            empty: true,
        };
        assert_eq!(empty_payload.load(true).unwrap(), Vec::<u8>::new());

        assert!(
            Cli::try_parse_from([
                "ffs-ntfs",
                "tx-write",
                "disk.img",
                "/a.txt",
                "--offline-image",
                "--allow-write",
                "--data",
                "abc",
                "--empty",
            ])
            .is_err()
        );
        assert!(
            Cli::try_parse_from([
                "ffs-ntfs",
                "tx-rename",
                "disk.img",
                "/a.txt",
                "/b.txt",
                "--offline-image",
                "--allow-write",
                "--expected-record",
                "24",
            ])
            .is_err()
        );
        let rename = Cli::try_parse_from([
            "ffs-ntfs",
            "tx-rename",
            "disk.img",
            "/a.txt",
            "/b.txt",
            "--offline-image",
            "--allow-write",
            "--expected-record",
            "24",
            "--expected-sequence",
            "2",
        ])
        .unwrap();
        let Command::TxRename {
            expected_record,
            expected_sequence,
            ..
        } = rename.command
        else {
            panic!("tx-rename");
        };
        assert_eq!((expected_record, expected_sequence), (Some(24), Some(2)));

        for invalid in ["0", "65537"] {
            assert!(
                Cli::try_parse_from([
                    "ffs-ntfs",
                    "tx-grow-mft",
                    "disk.img",
                    "--offline-image",
                    "--allow-write",
                    "--records",
                    invalid,
                ])
                .is_err()
            );
        }
    }
}
