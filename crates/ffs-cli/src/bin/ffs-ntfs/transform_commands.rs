//! CLI subcommands for NTFS transforms (sparse/hole-punch, LZNT1 compression),
//! native security (`$Secure` & access evaluation), reparse points, object IDs,
//! active `$UsnJrnl`, extended attributes (`$EA`), and explicit key-scoped EFS.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use asupersync::Cx;
use clap::Args;
use ffs_ntfs::efs::{NtfsEfsKey, StaticEfsKeyScope};
use ffs_ntfs::security_policy::{NtfsSecurityPatch, NtfsSidMap, NtfsSidPolicy, build_simple_ace};
use ffs_ntfs::transaction::{DEFAULT_NTFS_FILETIME, NtfsObjectIdData};
use ffs_ntfs::{NtfsTxOutcome, StreamName};
use ffs_ondisk::ntfs::reparse::{MOUNT_POINT_TAG, NtfsReparseData, NtfsReparsePoint, SYMLINK_TAG};
use ffs_ondisk::ntfs_security::{
    ACE_TYPE_ACCESS_ALLOWED, ACE_TYPE_ACCESS_DENIED, NtfsAccessToken, NtfsSid,
};

use super::{ImageArgs, PayloadArgs, TxWriteArgs, emit_tx_outcome, json, select_write_stream};

fn parse_hex_bytes(hex: &str, expected_len: Option<usize>) -> Result<Vec<u8>> {
    let trimmed = hex.trim().strip_prefix("0x").unwrap_or(hex.trim());
    if !trimmed.len().is_multiple_of(2) {
        bail!("hex string must have even length");
    }
    let mut out = Vec::with_capacity(trimmed.len() / 2);
    for chunk in trimmed.as_bytes().as_chunks::<2>().0 {
        let s = std::str::from_utf8(chunk).context("non-UTF8 hex digit")?;
        let byte = u8::from_str_radix(s, 16).with_context(|| format!("invalid hex byte {s:?}"))?;
        out.push(byte);
    }
    if let Some(exp) = expected_len
        && out.len() != exp
    {
        bail!("expected exactly {exp} bytes, got {}", out.len());
    }
    Ok(out)
}

fn parse_hex_16(hex: &str) -> Result<[u8; 16]> {
    let clean: String = hex.chars().filter(|c| *c != '-').collect();
    let bytes = parse_hex_bytes(&clean, Some(16))?;
    let mut arr = [0_u8; 16];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_u32_hex_or_dec(raw: &str) -> Result<u32> {
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16).with_context(|| format!("invalid hex u32 {raw:?}"))
    } else {
        raw.parse::<u32>()
            .with_context(|| format!("invalid decimal u32 {raw:?}"))
    }
}

fn parse_sid_string(text: &str) -> Result<NtfsSid> {
    let parts: Vec<&str> = text.trim().split('-').collect();
    if parts.len() < 4 || parts[0] != "S" || parts[1] != "1" {
        bail!("invalid NTFS SID syntax {text:?} (expected S-1-<auth>-<subauth>...)");
    }
    let authority: u64 = parts[2]
        .parse()
        .with_context(|| format!("invalid SID authority in {text:?}"))?;
    let mut subauthorities = Vec::with_capacity(parts.len() - 3);
    for part in &parts[3..] {
        let sub: u32 = part
            .parse()
            .with_context(|| format!("invalid SID subauthority {part:?} in {text:?}"))?;
        subauthorities.push(sub);
    }
    Ok(NtfsSid {
        authority,
        subauthorities,
    })
}

fn load_efs_key_from_file(path: &Path) -> Result<NtfsEfsKey> {
    let raw = std::fs::read(path)
        .with_context(|| format!("reading NTFS EFS key file {}", path.display()))?;
    if raw.len() == 32 {
        let mut arr = [0_u8; 32];
        arr.copy_from_slice(&raw);
        return Ok(NtfsEfsKey::from_raw_bytes(arr));
    }
    let text = std::str::from_utf8(&raw)
        .context("NTFS EFS key file must contain 32 raw bytes or 64 hex chars")?;
    Ok(NtfsEfsKey::from_hex(text)?)
}

/// Build an [`NtfsSidPolicy`] for `mount-write` from CLI arguments.
pub fn build_mount_sid_policy(
    uid: u32,
    gid: u32,
    sid_map: bool,
    enforce_acl: bool,
    uid_maps: &[String],
    gid_maps: &[String],
) -> Result<NtfsSidPolicy> {
    if !sid_map && !enforce_acl && uid_maps.is_empty() && gid_maps.is_empty() {
        return Ok(NtfsSidPolicy::Synthetic { uid, gid });
    }
    let mut map = NtfsSidMap {
        enforce_acl,
        fallback_uid: uid,
        fallback_gid: gid,
        ..NtfsSidMap::default()
    };
    for spec in uid_maps {
        let (u_str, s_str) = spec
            .split_once('=')
            .with_context(|| format!("invalid --uid-map {spec:?} (expected <uid>=<SID>)"))?;
        let u: u32 = u_str
            .parse()
            .with_context(|| format!("invalid uid in --uid-map {spec:?}"))?;
        map.uid_to_sid.insert(u, parse_sid_string(s_str)?);
    }
    for spec in gid_maps {
        let (g_str, s_str) = spec
            .split_once('=')
            .with_context(|| format!("invalid --gid-map {spec:?} (expected <gid>=<SID>)"))?;
        let g: u32 = g_str
            .parse()
            .with_context(|| format!("invalid gid in --gid-map {spec:?}"))?;
        map.gid_to_sid.insert(g, parse_sid_string(s_str)?);
    }
    Ok(NtfsSidPolicy::Mapped {
        caller_uid: uid,
        caller_gid: gid,
        map,
    })
}

#[derive(Debug, Args)]
pub struct TxSetSparseArgs {
    #[command(flatten)]
    pub target: TxWriteArgs,
    pub path: String,
    #[arg(long, conflicts_with = "stream_utf16")]
    pub stream: Option<String>,
    #[arg(long, value_parser = StreamName::parse, conflicts_with = "stream")]
    pub stream_utf16: Option<StreamName>,
    /// Enable (true) or disable/materialize (false) native SPARSE storage.
    #[arg(long)]
    pub enable: bool,
}

#[derive(Debug, Args)]
pub struct TxPunchHoleArgs {
    #[command(flatten)]
    pub target: TxWriteArgs,
    pub path: String,
    #[arg(long, conflicts_with = "stream_utf16")]
    pub stream: Option<String>,
    #[arg(long, value_parser = StreamName::parse, conflicts_with = "stream")]
    pub stream_utf16: Option<StreamName>,
    #[arg(long)]
    pub start: u64,
    #[arg(long)]
    pub length: u64,
    /// Automatically enable the SPARSE flag if not already set on the stream.
    #[arg(long)]
    pub auto_sparse: bool,
}

#[derive(Debug, Args)]
pub struct TxSetCompressionArgs {
    #[command(flatten)]
    pub target: TxWriteArgs,
    pub path: String,
    /// Enable (true) or disable (false) native NTFS LZNT1 compression.
    #[arg(long)]
    pub enable: bool,
}

#[derive(Debug, Args)]
pub struct TxSetSecurityArgs {
    #[command(flatten)]
    pub target: TxWriteArgs,
    pub path: String,
    /// Path to raw self-relative MS-DTYP SECURITY_DESCRIPTOR bytes.
    #[arg(long, conflicts_with_all = ["owner_sid", "group_sid", "posix_mode"])]
    pub descriptor_file: Option<PathBuf>,
    /// Set owner SID (e.g. S-1-5-88-1-1000).
    #[arg(long)]
    pub owner_sid: Option<String>,
    /// Set group SID (e.g. S-1-5-88-2-1000).
    #[arg(long)]
    pub group_sid: Option<String>,
    /// Apply POSIX octal mode bits (e.g. 0640 or 640) while preserving SACLs.
    #[arg(long)]
    pub posix_mode: Option<String>,
    /// Optional explicit ACE specification `<allow|deny>:<mask_hex>:<SID>` (repeatable).
    #[arg(long = "ace")]
    pub aces: Vec<String>,
}

#[derive(Debug, Args)]
pub struct CheckAccessArgs {
    #[command(flatten)]
    pub image: ImageArgs,
    pub path: String,
    /// Caller primary user SID (e.g. S-1-5-88-1-1000).
    #[arg(long)]
    pub user_sid: String,
    /// Caller supplementary group SIDs (repeatable).
    #[arg(long = "group-sid")]
    pub group_sids: Vec<String>,
    /// Desired MS-DTYP access mask (decimal or 0x hex, e.g. 0x00000001 for FILE_READ_DATA).
    #[arg(long)]
    pub mask: String,
}

#[derive(Debug, Args)]
pub struct TxSymlinkArgs {
    #[command(flatten)]
    pub target: TxWriteArgs,
    pub parent_path: String,
    pub name: String,
    /// Target path string stored inside IO_REPARSE_TAG_SYMLINK.
    #[arg(long)]
    pub link_target: String,
    /// Mark symlink as absolute instead of relative.
    #[arg(long)]
    pub absolute: bool,
    /// Create a directory symlink instead of a file symlink.
    #[arg(long)]
    pub directory: bool,
}

#[derive(Debug, Args)]
pub struct TxSetReparseArgs {
    #[command(flatten)]
    pub target: TxWriteArgs,
    pub path: String,
    /// Reparse tag (hex or decimal, e.g. 0xA0000003 for mount point, 0x9000101A for opaque).
    #[arg(long)]
    pub tag: String,
    /// Substitute name for SYMLINK/MOUNT_POINT tags.
    #[arg(long)]
    pub substitute: Option<String>,
    /// Print name for SYMLINK/MOUNT_POINT tags.
    #[arg(long)]
    pub print_name: Option<String>,
    /// Relative flag for SYMLINK tag.
    #[arg(long)]
    pub relative: bool,
    /// Hex payload bytes for opaque third-party reparse tags.
    #[arg(long)]
    pub opaque_hex: Option<String>,
    /// Optional 16-byte GUID (32 hex chars) required for non-Microsoft tags (bit 31 == 0).
    #[arg(long)]
    pub guid: Option<String>,
    /// Explicitly admit opaque/unknown reparse tags.
    #[arg(long)]
    pub allow_opaque: bool,
}

#[derive(Debug, Args)]
pub struct TxRemoveReparseArgs {
    #[command(flatten)]
    pub target: TxWriteArgs,
    pub path: String,
}

#[derive(Debug, Args)]
pub struct TxSetObjIdArgs {
    #[command(flatten)]
    pub target: TxWriteArgs,
    pub path: String,
    /// 16-byte Object ID GUID as hex (hyphens allowed).
    #[arg(long)]
    pub object_id: String,
    #[arg(long)]
    pub birth_volume_id: Option<String>,
    #[arg(long)]
    pub birth_object_id: Option<String>,
    #[arg(long)]
    pub domain_id: Option<String>,
}

#[derive(Debug, Args)]
pub struct TxRemoveObjIdArgs {
    #[command(flatten)]
    pub target: TxWriteArgs,
    pub path: String,
}

#[derive(Debug, Args)]
pub struct TxEnableUsnArgs {
    #[command(flatten)]
    pub target: TxWriteArgs,
    #[arg(long, default_value_t = 1_048_576)]
    pub maximum_size: u64,
    #[arg(long, default_value_t = 65_536)]
    pub allocation_delta: u64,
}

#[derive(Debug, Args)]
pub struct UsnSummaryArgs {
    #[command(flatten)]
    pub image: ImageArgs,
}

#[derive(Debug, Args)]
pub struct TxSetEaArgs {
    #[command(flatten)]
    pub target: TxWriteArgs,
    pub path: String,
    #[arg(long)]
    pub name: String,
    #[command(flatten)]
    pub payload: PayloadArgs,
    #[arg(long, default_value_t = 0)]
    pub flags: u8,
}

#[derive(Debug, Args)]
pub struct TxRemoveEaArgs {
    #[command(flatten)]
    pub target: TxWriteArgs,
    pub path: String,
    #[arg(long)]
    pub name: String,
}

#[derive(Debug, Args)]
pub struct EfsInfoArgs {
    #[command(flatten)]
    pub image: ImageArgs,
    pub path: String,
}

#[derive(Debug, Args)]
pub struct EfsReadArgs {
    #[command(flatten)]
    pub image: ImageArgs,
    pub path: String,
    /// Read raw stored ciphertext bytes instead of decrypting plaintext.
    #[arg(long, conflicts_with = "key_file")]
    pub raw_ciphertext: bool,
    /// Path to 32-byte raw or 64-char hex FEK file (never echoed in output).
    #[arg(long, conflicts_with = "raw_ciphertext")]
    pub key_file: Option<PathBuf>,
    #[arg(long, default_value_t = 0)]
    pub start: u64,
    #[arg(long)]
    pub bytes: Option<u64>,
}

#[derive(Debug, Args)]
pub struct TxEfsKeyArgs {
    #[command(flatten)]
    pub target: TxWriteArgs,
    pub path: String,
    /// Path to 32-byte raw or 64-char hex FEK file (never echoed in output).
    #[arg(long)]
    pub key_file: PathBuf,
}

#[derive(Debug, Args)]
pub struct TxEfsWriteArgs {
    #[command(flatten)]
    pub target: TxWriteArgs,
    pub path: String,
    /// Path to 32-byte raw or 64-char hex FEK file (never echoed in output).
    #[arg(long)]
    pub key_file: PathBuf,
    #[arg(long, default_value_t = 0)]
    pub start: u64,
    #[command(flatten)]
    pub payload: PayloadArgs,
}

pub fn run_tx_set_sparse(cx: &Cx, args: &TxSetSparseArgs) -> Result<()> {
    let stream = select_write_stream(args.stream.as_deref(), args.stream_utf16.clone())?;
    let mut engine = args.target.open(cx, false)?;
    let outcome = match engine.resolve_path_reference(cx, &args.path) {
        Ok(r) => engine.set_sparse_at(cx, r, stream.as_units(), args.enable, DEFAULT_NTFS_FILETIME),
        Err(err) => NtfsTxOutcome::NotCommitted(err),
    };
    emit_tx_outcome("tx_set_sparse", &engine, outcome, |()| {
        serde_json::json!({
            "path": args.path,
            "sparse": args.enable,
        })
    })
}

pub fn run_tx_punch_hole(cx: &Cx, args: &TxPunchHoleArgs) -> Result<()> {
    let stream = select_write_stream(args.stream.as_deref(), args.stream_utf16.clone())?;
    let mut engine = args.target.open(cx, false)?;
    let outcome = match engine.resolve_path_reference(cx, &args.path) {
        Ok(r) => engine.punch_hole_at(
            cx,
            r,
            stream.as_units(),
            args.start,
            args.length,
            args.auto_sparse,
            DEFAULT_NTFS_FILETIME,
        ),
        Err(err) => NtfsTxOutcome::NotCommitted(err),
    };
    emit_tx_outcome("tx_punch_hole", &engine, outcome, |reclaimed_clusters| {
        serde_json::json!({
            "path": args.path,
            "start": args.start,
            "length": args.length,
            "reclaimed_clusters": reclaimed_clusters,
        })
    })
}

pub fn run_tx_set_compression(cx: &Cx, args: &TxSetCompressionArgs) -> Result<()> {
    let mut engine = args.target.open(cx, false)?;
    let outcome = match engine.resolve_path_reference(cx, &args.path) {
        Ok(r) => engine.set_compression_at(cx, r, args.enable, DEFAULT_NTFS_FILETIME),
        Err(err) => NtfsTxOutcome::NotCommitted(err),
    };
    emit_tx_outcome("tx_set_compression", &engine, outcome, |()| {
        serde_json::json!({
            "path": args.path,
            "compressed": args.enable,
        })
    })
}

pub fn run_tx_set_security(cx: &Cx, args: &TxSetSecurityArgs) -> Result<()> {
    let mut engine = args.target.open(cx, false)?;
    let target_ref = engine.resolve_path_reference(cx, &args.path)?;
    if let Some(ref desc_path) = args.descriptor_file {
        let raw = std::fs::read(desc_path)
            .with_context(|| format!("reading security descriptor {}", desc_path.display()))?;
        let outcome = engine.set_security_at(cx, target_ref, &raw, DEFAULT_NTFS_FILETIME);
        return emit_tx_outcome("tx_set_security", &engine, outcome, |security_id| {
            serde_json::json!({
                "path": args.path,
                "security_id": security_id,
            })
        });
    }
    let vol = engine.volume_view(cx)?;
    let rec = vol.record(cx, target_ref.record, Some(target_ref.sequence))?;
    let mut patch = NtfsSecurityPatch::default();
    if let Some(ref s) = args.owner_sid {
        patch.owner = Some(parse_sid_string(s)?);
    }
    if let Some(ref s) = args.group_sid {
        patch.group = Some(parse_sid_string(s)?);
    }
    if let Some(ref mode_str) = args.posix_mode {
        let mode = u16::from_str_radix(mode_str.trim(), 8)
            .with_context(|| format!("invalid octal --posix-mode {mode_str:?}"))?;
        patch.posix_mode = Some((mode & 0o777, rec.is_directory()));
    }
    if !args.aces.is_empty() {
        let mut parsed_aces = Vec::with_capacity(args.aces.len());
        for spec in &args.aces {
            let parts: Vec<&str> = spec.splitn(3, ':').collect();
            if parts.len() != 3 {
                bail!("invalid --ace {spec:?} (expected <allow|deny>:<mask>:<SID>)");
            }
            let kind = match parts[0].to_ascii_lowercase().as_str() {
                "allow" => ACE_TYPE_ACCESS_ALLOWED,
                "deny" => ACE_TYPE_ACCESS_DENIED,
                other => bail!("unknown ACE kind {other:?} (expected allow or deny)"),
            };
            let mask = parse_u32_hex_or_dec(parts[1])?;
            let sid = parse_sid_string(parts[2])?;
            parsed_aces.push(build_simple_ace(kind, 0, mask, sid));
        }
        patch.replace_dacl = Some(parsed_aces);
    }
    let outcome = engine.patch_security_at(cx, target_ref, &patch, DEFAULT_NTFS_FILETIME);
    emit_tx_outcome("tx_set_security", &engine, outcome, |security_id| {
        serde_json::json!({
            "path": args.path,
            "security_id": security_id,
        })
    })
}

pub fn run_check_access(cx: &Cx, args: &CheckAccessArgs) -> Result<()> {
    let volume = args.image.open(cx)?;
    let rec = volume.resolve(cx, &args.path)?;
    let user = parse_sid_string(&args.user_sid)?;
    let mut groups = Vec::with_capacity(args.group_sids.len());
    for g in &args.group_sids {
        groups.push(parse_sid_string(g)?);
    }
    let mask = parse_u32_hex_or_dec(&args.mask)?;
    let token = NtfsAccessToken { user, groups };
    let sec_info = volume.security_descriptor(cx, &rec)?;
    let allowed =
        ffs_ondisk::ntfs_security::evaluate_dacl_access(&sec_info.descriptor, &token, mask)?;
    json(&serde_json::json!({
        "format": "NTFS",
        "operation": "check_access",
        "path": args.path,
        "record": rec.number,
        "desired_mask": format!("{mask:#010x}"),
        "allowed": allowed,
    }))
}

pub fn run_tx_symlink(cx: &Cx, args: &TxSymlinkArgs) -> Result<()> {
    let mut engine = args.target.open(cx, false)?;
    let name_utf16: Vec<u16> = args.name.encode_utf16().collect();
    let target_utf16: Vec<u16> = args.link_target.encode_utf16().collect();
    let outcome = match engine.resolve_path_reference(cx, &args.parent_path) {
        Ok(parent_ref) => engine.create_symlink_at(
            cx,
            parent_ref,
            &name_utf16,
            &target_utf16,
            !args.absolute,
            args.directory,
            DEFAULT_NTFS_FILETIME,
        ),
        Err(err) => NtfsTxOutcome::NotCommitted(err),
    };
    emit_tx_outcome("tx_symlink", &engine, outcome, |reference| {
        serde_json::json!({
            "record": reference.record,
            "sequence": reference.sequence,
            "target": args.link_target,
            "relative": !args.absolute,
            "directory": args.directory,
        })
    })
}

pub fn run_tx_set_reparse(cx: &Cx, args: &TxSetReparseArgs) -> Result<()> {
    let tag = parse_u32_hex_or_dec(&args.tag)?;
    let guid = match &args.guid {
        Some(g) => Some(parse_hex_16(g)?),
        None => None,
    };
    let data = if tag == SYMLINK_TAG {
        let sub = args
            .substitute
            .as_deref()
            .context("SYMLINK tag requires --substitute")?;
        let prt = args.print_name.as_deref().unwrap_or(sub);
        NtfsReparseData::SymbolicLink {
            substitute: sub.encode_utf16().collect(),
            print: prt.encode_utf16().collect(),
            relative: args.relative,
        }
    } else if tag == MOUNT_POINT_TAG {
        let sub = args
            .substitute
            .as_deref()
            .context("MOUNT_POINT tag requires --substitute")?;
        let prt = args.print_name.as_deref().unwrap_or(sub);
        NtfsReparseData::MountPoint {
            substitute: sub.encode_utf16().collect(),
            print: prt.encode_utf16().collect(),
        }
    } else {
        let bytes = match &args.opaque_hex {
            Some(hex) => parse_hex_bytes(hex, None)?,
            None => Vec::new(),
        };
        NtfsReparseData::Opaque(bytes)
    };
    let point = NtfsReparsePoint { tag, guid, data };
    let mut engine = args.target.open(cx, false)?;
    let outcome = match engine.resolve_path_reference(cx, &args.path) {
        Ok(r) => {
            engine.set_reparse_point_at(cx, r, &point, args.allow_opaque, DEFAULT_NTFS_FILETIME)
        }
        Err(err) => NtfsTxOutcome::NotCommitted(err),
    };
    emit_tx_outcome("tx_set_reparse", &engine, outcome, |()| {
        serde_json::json!({
            "path": args.path,
            "tag": format!("{tag:#010x}"),
        })
    })
}

pub fn run_tx_remove_reparse(cx: &Cx, args: &TxRemoveReparseArgs) -> Result<()> {
    let mut engine = args.target.open(cx, false)?;
    let outcome = match engine.resolve_path_reference(cx, &args.path) {
        Ok(r) => engine.remove_reparse_point_at(cx, r, DEFAULT_NTFS_FILETIME),
        Err(err) => NtfsTxOutcome::NotCommitted(err),
    };
    emit_tx_outcome(
        "tx_remove_reparse",
        &engine,
        outcome,
        |()| serde_json::json!({ "path": args.path }),
    )
}

pub fn run_tx_set_objid(cx: &Cx, args: &TxSetObjIdArgs) -> Result<()> {
    let objid = NtfsObjectIdData {
        object_id: parse_hex_16(&args.object_id)?,
        birth_volume_id: match &args.birth_volume_id {
            Some(s) => parse_hex_16(s)?,
            None => [0; 16],
        },
        birth_object_id: match &args.birth_object_id {
            Some(s) => parse_hex_16(s)?,
            None => [0; 16],
        },
        domain_id: match &args.domain_id {
            Some(s) => parse_hex_16(s)?,
            None => [0; 16],
        },
    };
    let mut engine = args.target.open(cx, false)?;
    let outcome = match engine.resolve_path_reference(cx, &args.path) {
        Ok(r) => engine.set_object_id_at(cx, r, objid, DEFAULT_NTFS_FILETIME),
        Err(err) => NtfsTxOutcome::NotCommitted(err),
    };
    emit_tx_outcome("tx_set_objid", &engine, outcome, |()| {
        serde_json::json!({
            "path": args.path,
            "object_id": args.object_id,
        })
    })
}

pub fn run_tx_remove_objid(cx: &Cx, args: &TxRemoveObjIdArgs) -> Result<()> {
    let mut engine = args.target.open(cx, false)?;
    let outcome = match engine.resolve_path_reference(cx, &args.path) {
        Ok(r) => engine.remove_object_id_at(cx, r, DEFAULT_NTFS_FILETIME),
        Err(err) => NtfsTxOutcome::NotCommitted(err),
    };
    emit_tx_outcome(
        "tx_remove_objid",
        &engine,
        outcome,
        |()| serde_json::json!({ "path": args.path }),
    )
}

pub fn run_tx_enable_usn(cx: &Cx, args: &TxEnableUsnArgs) -> Result<()> {
    let mut engine = args.target.open(cx, false)?;
    let outcome = engine.enable_usn_journal(
        cx,
        args.maximum_size,
        args.allocation_delta,
        DEFAULT_NTFS_FILETIME,
    );
    emit_tx_outcome("tx_enable_usn", &engine, outcome, |reference| {
        serde_json::json!({
            "record": reference.record,
            "sequence": reference.sequence,
            "maximum_size": args.maximum_size,
            "allocation_delta": args.allocation_delta,
        })
    })
}

pub fn run_usn_summary(cx: &Cx, args: &UsnSummaryArgs) -> Result<()> {
    let volume = args.image.open(cx)?;
    let summary = volume.usn_summary(cx)?;
    json(&serde_json::json!({
        "format": "NTFS",
        "operation": "usn_summary",
        "active": summary.is_some(),
        "summary": summary,
    }))
}

pub fn run_tx_set_ea(cx: &Cx, args: &TxSetEaArgs) -> Result<()> {
    let value = args.payload.load(false)?;
    let mut engine = args.target.open(cx, false)?;
    let outcome = match engine.resolve_path_reference(cx, &args.path) {
        Ok(r) => engine.set_ea_at(
            cx,
            r,
            args.name.as_bytes(),
            &value,
            args.flags,
            DEFAULT_NTFS_FILETIME,
        ),
        Err(err) => NtfsTxOutcome::NotCommitted(err),
    };
    emit_tx_outcome("tx_set_ea", &engine, outcome, |()| {
        serde_json::json!({
            "path": args.path,
            "name": args.name,
            "value_bytes": value.len(),
        })
    })
}

pub fn run_tx_remove_ea(cx: &Cx, args: &TxRemoveEaArgs) -> Result<()> {
    let mut engine = args.target.open(cx, false)?;
    let outcome = match engine.resolve_path_reference(cx, &args.path) {
        Ok(r) => engine.remove_ea_at(cx, r, args.name.as_bytes(), DEFAULT_NTFS_FILETIME),
        Err(err) => NtfsTxOutcome::NotCommitted(err),
    };
    emit_tx_outcome("tx_remove_ea", &engine, outcome, |removed| {
        serde_json::json!({
            "path": args.path,
            "name": args.name,
            "removed": removed,
        })
    })
}

pub fn run_efs_info(cx: &Cx, args: &EfsInfoArgs) -> Result<()> {
    let volume = args.image.open(cx)?;
    let rec = volume.resolve(cx, &args.path)?;
    let info = volume.efs_metadata(cx, &rec)?.map(|(_, i)| i);
    json(&serde_json::json!({
        "format": "NTFS",
        "operation": "efs_info",
        "path": args.path,
        "encrypted": info.is_some(),
        "efs": info,
    }))
}

pub fn run_efs_read(cx: &Cx, args: &EfsReadArgs) -> Result<()> {
    let volume = args.image.open(cx)?;
    let rec = volume.resolve(cx, &args.path)?;
    let max_bytes = usize::try_from(args.bytes.unwrap_or(16 * 1024 * 1024))
        .context("requested EFS read length exceeds usize")?;
    let data = if args.raw_ciphertext {
        let (_, cipher) = volume.read_raw_efs_ciphertext(cx, &rec, args.start, max_bytes)?;
        cipher
    } else if let Some(ref kf) = args.key_file {
        let key = load_efs_key_from_file(kf)?;
        let mut scope = StaticEfsKeyScope::new();
        scope.insert(key);
        volume.read_efs_plaintext(cx, &rec, &scope, args.start, max_bytes)?
    } else {
        bail!("efs-read requires either --raw-ciphertext or --key-file");
    };
    let mut out = io::stdout().lock();
    out.write_all(&data)?;
    out.flush()?;
    Ok(())
}

pub fn run_tx_efs_encrypt(cx: &Cx, args: &TxEfsKeyArgs) -> Result<()> {
    let key = load_efs_key_from_file(&args.key_file)?;
    let key_id_hex = key.key_id_hex();
    let mut engine = args.target.open(cx, false)?;
    let outcome = match engine.resolve_path_reference(cx, &args.path) {
        Ok(r) => engine.encrypt_file_at(cx, r, &key, DEFAULT_NTFS_FILETIME),
        Err(err) => NtfsTxOutcome::NotCommitted(err),
    };
    emit_tx_outcome("tx_efs_encrypt", &engine, outcome, |()| {
        serde_json::json!({
            "path": args.path,
            "key_id": key_id_hex,
            "fek": "[REDACTED]",
        })
    })
}

pub fn run_tx_efs_write(cx: &Cx, args: &TxEfsWriteArgs) -> Result<()> {
    let key = load_efs_key_from_file(&args.key_file)?;
    let key_id_hex = key.key_id_hex();
    let mut scope = StaticEfsKeyScope::new();
    scope.insert(key);
    let data = args.payload.load_range(args.start)?;
    let mut engine = args.target.open(cx, false)?;
    let outcome = match engine.resolve_path_reference(cx, &args.path) {
        Ok(r) => {
            engine.write_efs_stream_at(cx, r, &scope, args.start, &data, DEFAULT_NTFS_FILETIME)
        }
        Err(err) => NtfsTxOutcome::NotCommitted(err),
    };
    emit_tx_outcome("tx_efs_write", &engine, outcome, |new_size| {
        serde_json::json!({
            "path": args.path,
            "key_id": key_id_hex,
            "start": args.start,
            "written_bytes": data.len(),
            "new_size": new_size,
            "fek": "[REDACTED]",
        })
    })
}

pub fn run_tx_efs_decrypt(cx: &Cx, args: &TxEfsKeyArgs) -> Result<()> {
    let key = load_efs_key_from_file(&args.key_file)?;
    let key_id_hex = key.key_id_hex();
    let mut scope = StaticEfsKeyScope::new();
    scope.insert(key);
    let mut engine = args.target.open(cx, false)?;
    let outcome = match engine.resolve_path_reference(cx, &args.path) {
        Ok(r) => engine.decrypt_file_at(cx, r, &scope, DEFAULT_NTFS_FILETIME),
        Err(err) => NtfsTxOutcome::NotCommitted(err),
    };
    emit_tx_outcome("tx_efs_decrypt", &engine, outcome, |()| {
        serde_json::json!({
            "path": args.path,
            "key_id": key_id_hex,
            "fek": "[REDACTED]",
        })
    })
}
