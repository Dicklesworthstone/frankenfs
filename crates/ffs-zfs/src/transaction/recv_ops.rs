//! Bounded, resumable ZFS native `DMU_BACKUP_STREAM` receiver (`ffs-zfs recv`),
//! private `%recv` / `DS_FLAG_INCONSISTENT` staging, atomic promotion, abort cleanup,
//! and `receive_resume_token` inspection.
//!
//! Security boundary: untrusted stream headers (`drr_toname`, embedded XDR nvlists)
//! NEVER select host paths, devices, pools, key files, or import authority.

use super::dmu_cow::{
    DatasetCompression, DatasetFeatureUsage, DnodeCowSpec, MosFeatureState, PoolSpaceAllocator,
    SpaceDelta, StagedBlockWrite, StagedLeafUpdate, WriteBucket, allocate_object_id,
    allocated_leaf_blocks_in_range, collect_non_hole_bps_from, cow_update_dnode_with_staged_leaves,
    dmu_ot_is_byte_array, enqueue_into_dataset_deadlist, ensure_dnode_table_block_loaded,
    put_dnode_in_table, read_staged_or_committed_dnode, remove_dnode_from_table,
    write_dataset_objset_block, write_dataset_objset_block_raw_protected, zap_optional_u64,
};
use super::dsl_ops::{
    DMU_OT_DSL_DATASET, DMU_OT_DSL_DIR_CHILD_MAP, DMU_OT_DSL_DS_SNAP_MAP, DMU_OT_DSL_PROPS,
    DS_FLAG_UNIQUE_ACCURATE, ObjectSetWalkMode, activate_dataset_block_features,
    activate_initial_compression_feature, adjust_dsl_crypto_key_refcount, allocate_fresh_deadlist,
    bump_filesystem_limits_counter_if_present, dataset_block_feature_owners,
    dataset_feature_entries, derive_fsid_guid, derive_unique_guid,
    effective_compression_for_new_dataset, enforce_dataset_quotas_for_growth,
    enforce_pool_reservations_for_growth, free_deadlist_containers, free_mos_object_completely,
    link_dataset_to_origin_snapshot, lookup_pool_origin_snapshot, propagate_dsl_dir_space_delta,
    put_new_dsl_dir_in_mos, reject_busy, reject_einval, release_dataset_block_features,
    resolve_dataset_ids, stage_destroy_dataset_by_ids, validate_dsl_component,
    walk_objectset_above_txg, write_zap_dnode_in_mos,
};
use super::{
    ZfsDurableToken, ZfsPropertySetValue, ZfsTransactionEngine, ZfsTxOutcome, checkpoint, corrupt,
    parse_err, unsupported,
};
use crate::crypto::{ZfsDatasetCryptoInfo, encode_dsl_crypto_key_zap, parse_dsl_crypto_key_zap};
use crate::reader::dmu::{Objects, RecvStagingDataset};
use crate::send_recv::{
    DS_FIELD_RESUME_BYTES, DS_FIELD_RESUME_COMPRESSOK, DS_FIELD_RESUME_EMBEDOK,
    DS_FIELD_RESUME_FROMGUID, DS_FIELD_RESUME_IVSET_GUID, DS_FIELD_RESUME_LARGEBLOCKOK,
    DS_FIELD_RESUME_OBJECT, DS_FIELD_RESUME_OFFSET, DS_FIELD_RESUME_RAWOK, DS_FIELD_RESUME_TOGUID,
    DS_FIELD_RESUME_TONAME, DS_FLAG_INCONSISTENT,
};
use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::zfs::crypto::{
    DSL_DATASET_IVSET_GUID, DSL_DIR_CRYPTO_KEY_OBJ, DslCryptoKeyRecord, ZIO_DATA_IV_LEN,
    ZIO_DATA_MAC_LEN, ZIO_DATA_SALT_LEN, dmu_ot_is_encrypted, extract_raw_dnode_bonus,
    write_raw_dnode_bonus,
};
use ffs_ondisk::zfs::nvlist::{NvList, Value};
use ffs_ondisk::zfs::send_stream::{
    DMU_BACKUP_FEATURE_COMPRESSED, DMU_BACKUP_FEATURE_EMBED_DATA, DMU_BACKUP_FEATURE_LARGE_BLOCKS,
    DMU_BACKUP_FEATURE_RAW, DMU_BACKUP_FEATURE_RESUMING, DMU_OST_ZFS, DMU_OST_ZVOL,
    DMU_REPLAY_RECORD_BYTES, DRR_FLAG_CI_DATA, DRR_OBJECT_SPILL, DRR_RAW_BYTESWAP, DrrBegin,
    DrrFree, DrrFreeObjects, DrrObject, DrrObjectRange, DrrRecord, DrrSpill, DrrType, DrrWrite,
    DrrWriteEmbedded, Fletcher4Stream, ReceiveResumeToken, StreamCryptoKeydata, StreamHeaderType,
    StreamMetaDnode, detect_stream_endian, validate_toname_snapshot,
};
use ffs_ondisk::zfs::{
    BlockPointer, Endian, MAX_BLOCK_BYTES, ProtectedBlockSpec, RegularBlockSpec, decompress,
};
use ffs_ondisk::zfs_dmu::{
    DMU_OT_DNODE, DNODE_BLOCK_BYTES, DNODE_BYTES, DNODE_FLAG_USED_BYTES, Dnode, DnodeSpec,
    ObjectSet, ZilHeader, count_allocated_dnodes, write_dnode_at,
};
use ffs_ondisk::zfs_zap::Entry as RawZapEntry;
use ffs_ondisk::zfs_zap::names::NamePolicy as ZapNamePolicy;
use serde::Serialize;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;

const DMU_OTN_ZAP_METADATA: u8 = 196;
const DEFAULT_CHECKPOINT_BYTES: u64 = 4 * 1024 * 1024;
const MAX_RECV_RECORDS: u64 = 10_000_000;
const MAX_COMPOUND_SUBSTREAMS: usize = 256;

/// Request options for native ZFS stream receive (`ffs-zfs recv`).
#[derive(Debug, Clone)]
pub struct ZfsRecvRequest {
    /// Explicit caller-authorized pool-relative target dataset path (e.g. `["data", "dst"]`).
    /// Never derived from untrusted stream `drr_toname`!
    pub target_dataset: Vec<Vec<u8>>,
    /// Optional explicit snapshot name override; when `None`, uses validated suffix after `@`
    /// from `DRR_BEGIN.drr_toname`.
    pub snapshot_override: Option<Vec<u8>>,
    /// Persist private resumable `%recv` / `DS_FLAG_INCONSISTENT` checkpoints (`-s`).
    pub resumable: bool,
    /// Allow rolling back unsnapshotted live head divergence on incremental receive (`-F`).
    pub force: bool,
    /// Maximum received payload bytes accumulated per atomic TXG checkpoint (default 4 MiB).
    pub checkpoint_bytes: u64,
}

impl ZfsRecvRequest {
    #[must_use]
    pub fn new(target_dataset: Vec<Vec<u8>>) -> Self {
        Self {
            target_dataset,
            snapshot_override: None,
            resumable: false,
            force: false,
            checkpoint_bytes: DEFAULT_CHECKPOINT_BYTES,
        }
    }
}

/// Structured report emitted upon completed `receive_stream`.
#[derive(Debug, Clone, Serialize)]
pub struct ZfsRecvReport {
    pub substreams_received: usize,
    pub compound: bool,
    pub raw: bool,
    pub resumed: bool,
    pub final_snapshot: String,
    pub final_snapshot_guid: u64,
    pub records_applied: u64,
    pub objects_received: u64,
    pub blocks_received: u64,
    pub stream_bytes_read: u64,
    pub checkpoint_txgs: u64,
    pub durable_token: ZfsDurableToken,
}

/// Last known durable action performed by an interrupted receive invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ZfsRecvStage {
    /// Private receive staging was created or advanced; it has not been promoted.
    Checkpoint,
    /// A complete substream and its snapshot were published in the target dataset.
    Promoted,
    /// The incomplete substream's private staging was durably reclaimed.
    /// Earlier completed substreams, if any, remain published.
    Aborted,
}

/// Known durable prefix of this receive invocation, including private checkpoints.
///
/// A later `Uncertain` publication may supersede this token. In that case this is
/// a lower bound on completed work, not authority to select an older pool root.
#[derive(Debug, Clone, Serialize)]
pub struct ZfsRecvProgress {
    pub substreams_received: usize,
    pub last_snapshot: Option<String>,
    pub last_snapshot_guid: Option<u64>,
    /// Successful staging, checkpoint, promotion and abort TXGs in this invocation.
    pub committed_txgs: u64,
    pub last_durable_stage: ZfsRecvStage,
    pub durable_token: ZfsDurableToken,
}

/// Outcome of an entire receive, which can publish several independent native TXGs.
///
/// Unlike `ZfsTxOutcome`, a receive can fail after a known durable prefix without
/// any uncertainty about its final publication. Such a failure is `Interrupted`,
/// never `NotCommitted`, and must not be retried as an untouched operation.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ZfsRecvOutcome {
    /// Every substream and the complete outer framing were accepted.
    Committed {
        value: ZfsRecvReport,
        token: ZfsDurableToken,
    },
    /// This invocation published no native TXG. Prior resumable state is unchanged.
    NotCommitted(FfsError),
    /// Receive failed without a new TXG, and aborting its pre-existing staging
    /// also failed before publication. The prior receive state remains intact.
    CleanupFailed {
        reason: FfsError,
        cleanup_error: FfsError,
    },
    /// Receive failed after the known durable prefix, with no uncertain publication.
    Interrupted {
        reason: FfsError,
        progress: ZfsRecvProgress,
        /// Failure to reclaim non-resumable staging, when cleanup was attempted.
        cleanup_error: Option<FfsError>,
    },
    /// A native publication (possibly abort cleanup) needs fresh-engine recovery.
    Uncertain {
        reason: FfsError,
        target_txg: u64,
        target_slot: usize,
        progress: Option<ZfsRecvProgress>,
        /// Original stream error when the uncertain transaction was abort cleanup.
        receive_error: Option<FfsError>,
    },
}

impl ZfsRecvOutcome {
    #[must_use]
    pub const fn is_committed(&self) -> bool {
        matches!(self, Self::Committed { .. })
    }

    /// Whether this invocation published no new native TXG. A cleanup failure
    /// still requires handling the pre-existing receive state and both errors.
    #[must_use]
    pub const fn is_not_committed(&self) -> bool {
        matches!(self, Self::NotCommitted(_) | Self::CleanupFailed { .. })
    }

    /// Extract successful completion without discarding interruption or recovery
    /// information from the error case.
    pub fn into_result(self) -> std::result::Result<(ZfsRecvReport, ZfsDurableToken), Box<Self>> {
        match self {
            Self::Committed { value, token } => Ok((value, token)),
            outcome => Err(Box::new(outcome)),
        }
    }
}

#[derive(Default)]
struct RecvAttempt {
    progress: Option<ZfsRecvProgress>,
    cleanup_error: Option<FfsError>,
    receive_error: Option<FfsError>,
}

impl RecvAttempt {
    fn record(&mut self, token: ZfsDurableToken, stage: ZfsRecvStage) {
        if let Some(progress) = &mut self.progress {
            progress.committed_txgs += 1;
            progress.last_durable_stage = stage;
            progress.durable_token = token;
        } else {
            self.progress = Some(ZfsRecvProgress {
                substreams_received: 0,
                last_snapshot: None,
                last_snapshot_guid: None,
                committed_txgs: 1,
                last_durable_stage: stage,
                durable_token: token,
            });
        }
    }

    fn promoted(&mut self, token: ZfsDurableToken, name: &[u8], guid: u64) {
        self.record(token, ZfsRecvStage::Promoted);
        if let Some(progress) = &mut self.progress {
            progress.substreams_received += 1;
            progress.last_snapshot = Some(String::from_utf8_lossy(name).into_owned());
            progress.last_snapshot_guid = Some(guid);
        }
    }

    fn finish(self, outcome: ZfsTxOutcome<ZfsRecvReport>) -> ZfsRecvOutcome {
        match outcome {
            ZfsTxOutcome::Committed { value, token } => ZfsRecvOutcome::Committed { value, token },
            ZfsTxOutcome::NotCommitted(reason) => match (self.progress, self.cleanup_error) {
                (Some(progress), cleanup_error) => ZfsRecvOutcome::Interrupted {
                    reason,
                    progress,
                    cleanup_error,
                },
                (None, Some(cleanup_error)) => ZfsRecvOutcome::CleanupFailed {
                    reason,
                    cleanup_error,
                },
                (None, None) => ZfsRecvOutcome::NotCommitted(reason),
            },
            ZfsTxOutcome::Uncertain {
                reason,
                target_txg,
                target_slot,
            } => ZfsRecvOutcome::Uncertain {
                reason,
                target_txg,
                target_slot,
                progress: self.progress,
                receive_error: self.receive_error,
            },
        }
    }
}

/// Persisted state of an interrupted resumable receive (`%recv` or `DS_FLAG_INCONSISTENT`),
/// including the OpenZFS v1 `receive_resume_token` ASCII string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ZfsResumeState {
    pub is_pct_recv_child: bool,
    pub toguid: u64,
    pub fromguid: Option<u64>,
    pub object: u64,
    pub offset: u64,
    pub bytes: u64,
    pub toname: String,
    pub compressok: bool,
    pub embedok: bool,
    pub largeblockok: bool,
    pub rawok: bool,
    pub ivsetguid: Option<u64>,
    pub token: String,
}

// ── Bounded Stream Reader ───────────────────────────────────────────────────

struct StreamReader<'a, R: Read> {
    input: &'a mut R,
    bytes_read: u64,
}

impl<'a, R: Read> StreamReader<'a, R> {
    fn new(input: &'a mut R) -> Self {
        Self {
            input,
            bytes_read: 0,
        }
    }

    fn read_header_or_eof(&mut self, cx: &Cx) -> Result<Option<[u8; DMU_REPLAY_RECORD_BYTES]>> {
        checkpoint(cx)?;
        let mut buf = [0_u8; DMU_REPLAY_RECORD_BYTES];
        let mut filled = 0_usize;
        while filled < buf.len() {
            match self.input.read(&mut buf[filled..]) {
                Ok(0) => {
                    if filled == 0 {
                        return Ok(None);
                    }
                    return Err(FfsError::Format(format!(
                        "truncated DMU replay record header ({filled}/{} bytes)",
                        buf.len()
                    )));
                }
                Ok(n) => {
                    filled += n;
                    self.bytes_read = self.bytes_read.saturating_add(n as u64);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    return Err(FfsError::Format(format!("send stream read error: {e}")));
                }
            }
        }
        Ok(Some(buf))
    }

    fn read_exact_bytes(&mut self, cx: &Cx, len: usize) -> Result<Vec<u8>> {
        checkpoint(cx)?;
        if len == 0 {
            return Ok(Vec::new());
        }
        if len > MAX_BLOCK_BYTES {
            return Err(FfsError::Format(
                "DMU send stream payload exceeds 16 MiB bound".into(),
            ));
        }
        let mut buf = vec![0_u8; len];
        let mut filled = 0_usize;
        while filled < len {
            match self.input.read(&mut buf[filled..]) {
                Ok(0) => {
                    return Err(FfsError::Format(format!(
                        "truncated DMU replay record payload ({filled}/{len} bytes)"
                    )));
                }
                Ok(n) => {
                    filled += n;
                    self.bytes_read = self.bytes_read.saturating_add(n as u64);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    return Err(FfsError::Format(format!("send stream read error: {e}")));
                }
            }
        }
        Ok(buf)
    }

    fn assert_eof(&mut self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        let mut probe = [0_u8; 1];
        loop {
            match self.input.read(&mut probe) {
                Ok(0) => return Ok(()),
                Ok(_) => {
                    return Err(FfsError::Format(
                        "unexpected trailing bytes after final DMU DRR_END".into(),
                    ));
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    return Err(FfsError::Format(format!(
                        "send stream trailing read error: {e}"
                    )));
                }
            }
        }
    }
}

// ── Chunked Staged Operations ───────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ObjectRangeMeta {
    salt: [u8; ZIO_DATA_SALT_LEN],
    iv: [u8; ZIO_DATA_IV_LEN],
    mac: [u8; ZIO_DATA_MAC_LEN],
    flags: u8,
}

#[derive(Debug, Clone)]
enum RecvOp {
    ObjectRange(DrrObjectRange),
    Object {
        rec: DrrObject,
        bonus: Vec<u8>,
    },
    FreeObjects(DrrFreeObjects),
    Write {
        rec: DrrWrite,
        payload: Vec<u8>,
    },
    WriteEmbedded {
        rec: DrrWriteEmbedded,
        payload: Vec<u8>,
    },
    Free(DrrFree),
    Spill {
        rec: DrrSpill,
        payload: Vec<u8>,
    },
}

struct ChunkProgress {
    object: u64,
    offset: u64,
    bytes: u64,
}

#[derive(Debug, Clone)]
struct StagedSubstreamMeta {
    stage_dd_obj: u64,
    stage_head_obj: u64,
    is_pct_recv_child: bool,
    target_dd_obj: u64,
    target_head_obj: Option<u64>,
    prev_snap_obj: u64,
    prev_snap_txg: u64,
    is_raw_encrypted: bool,
    raw_meta_dnode: Option<StreamMetaDnode>,
    crypto_version: u64,
    portable_mac: [u8; 32],
    to_ivset_guid: Option<u64>,
    compression: DatasetCompression,
}

fn admit_received_compression(compression: u8, features: &MosFeatureState) -> Result<()> {
    // Raw, compressed, embedded and spill records all carry native codecs.
    // LZ4 is pool-wide and must already be active; ZSTD requires both enabled
    // per-dataset capabilities before its ownership can be staged atomically.
    if !matches!(compression, 0 | 2 | 3 | 5..=16) {
        return Err(FfsError::Format(format!(
            "invalid compressed receive block selector {compression}"
        )));
    }
    DatasetCompression::from_property(u64::from(compression), features).map(|_| ())
}

/// A stream checksum covers the transmitted bytes, not the validity of the
/// compressed frame. Validate bounded plaintext transforms before enqueueing a
/// record, so neither a checkpoint nor promotion can publish an unreadable BP.
/// Raw encrypted streams deliberately retain their ciphertext without decoding.
fn validate_received_block_payload(
    cx: &Cx,
    logical_size: u64,
    compression: u8,
    payload: &[u8],
    raw_encrypted: bool,
) -> Result<()> {
    if !(512..=MAX_BLOCK_BYTES as u64).contains(&logical_size)
        || !logical_size.is_multiple_of(512)
        || payload.len() < 512
        || !payload.len().is_multiple_of(512)
        || payload.len() as u64 > logical_size
    {
        return Err(FfsError::Format(
            "invalid receive block logical or physical size".into(),
        ));
    }
    let codec = if compression == 0 { 2 } else { compression };
    if codec == 2 {
        if payload.len() as u64 != logical_size {
            return Err(FfsError::Format(
                "uncompressed receive block length mismatch".into(),
            ));
        }
    } else if !raw_encrypted {
        checkpoint(cx)?;
        let logical_bytes =
            usize::try_from(logical_size).map_err(|_| corrupt("receive logical size overflow"))?;
        let decoded = decompress(payload, codec, logical_bytes).map_err(|e| parse_err(&e))?;
        drop(decoded);
        checkpoint(cx)?;
    }
    Ok(())
}

fn validate_received_embedded_payload(
    cx: &Cx,
    rec: &DrrWriteEmbedded,
    payload: &[u8],
) -> Result<()> {
    if !(512..=MAX_BLOCK_BYTES as u64).contains(&rec.length)
        || !rec.length.is_multiple_of(512)
        || rec.offset.checked_add(rec.length).is_none()
        || u64::from(rec.lsize) != rec.length
        || !(1..=112).contains(&rec.psize)
        || rec.psize > rec.lsize
        || !matches!(rec.compression, 2 | 3 | 5..=16)
    {
        return Err(FfsError::Format(
            "invalid DRR_WRITE_EMBEDDED geometry or compression".into(),
        ));
    }
    let packed =
        usize::try_from(rec.psize).map_err(|_| corrupt("embedded physical size overflow"))?;
    if payload.len() != packed.next_multiple_of(8) {
        return Err(FfsError::Format(
            "DRR_WRITE_EMBEDDED payload length mismatch".into(),
        ));
    }
    checkpoint(cx)?;
    let logical =
        usize::try_from(rec.lsize).map_err(|_| corrupt("embedded logical size overflow"))?;
    let decoded =
        decompress(&payload[..packed], rec.compression, logical).map_err(|e| parse_err(&e))?;
    drop(decoded);
    checkpoint(cx)
}

fn validate_received_geometry(offset: u64, logical: u64, block_bytes: usize) -> Result<()> {
    let block_bytes = block_bytes as u64;
    if block_bytes == 0
        || !offset.is_multiple_of(block_bytes)
        || logical != block_bytes
        || offset.checked_add(logical).is_none()
    {
        return Err(FfsError::Format(
            "receive record geometry disagrees with its dnode".into(),
        ));
    }
    Ok(())
}

fn validate_received_plain_order(
    object_type: u8,
    stream_order: Endian,
    pool_order: Endian,
) -> Result<()> {
    if stream_order != pool_order && !dmu_ot_is_byte_array(object_type) {
        return Err(unsupported(
            "cross-endian receive of structured DMU payloads requires byte-swap conversion",
        ));
    }
    Ok(())
}

fn validate_received_crypto_identity(
    incoming: &StreamCryptoKeydata,
    existing: &DslCryptoKeyRecord,
) -> Result<()> {
    // Wrapping material may change independently of the underlying dataset key.
    // Its native key GUID, cipher and encryption format must remain compatible.
    if incoming.guid != existing.guid
        || incoming.suite != existing.suite
        || incoming.version != existing.version
    {
        return Err(FfsError::Format(
            "raw receive crypto identity disagrees with its destination".into(),
        ));
    }
    Ok(())
}

fn validate_received_base_ivset(
    cx: &Cx,
    mos: &mut Objects,
    keydata: &StreamCryptoKeydata,
    base_snapshot: u64,
) -> Result<()> {
    let expected = keydata
        .from_ivset_guid
        .filter(|&guid| guid != 0)
        .ok_or_else(|| {
            FfsError::Format("raw incremental receive requires a nonzero from_ivset_guid".into())
        })?;
    if mos.dataset_ivset_guid(cx, base_snapshot)? != Some(expected) {
        return Err(FfsError::Format(
            "raw incremental from_ivset_guid disagrees with target base snapshot".into(),
        ));
    }
    Ok(())
}

fn admit_received_meta_dnode(meta: &StreamMetaDnode) -> Result<()> {
    // The native envelope admits larger profiles; local dnode-table indexing
    // and the COW writer currently support 16 KiB tables and seven levels.
    if meta.data_bytes != DNODE_BLOCK_BYTES as u64 || !(1..=7).contains(&meta.levels) {
        return Err(unsupported(
            "raw receive requires a 16 KiB meta-dnode with at most seven levels",
        ));
    }
    Ok(())
}

fn validate_received_raw_object(meta: Option<&StreamMetaDnode>, object: u64) -> Result<()> {
    if meta.is_some_and(|meta| object / 32 > meta.max_block) {
        return Err(FfsError::Format(
            "raw receive object exceeds the source meta-dnode maximum block".into(),
        ));
    }
    Ok(())
}

fn validate_received_meta_geometry(meta: &StreamMetaDnode, existing: &Dnode) -> Result<()> {
    // OpenZFS raw receive treats these four properties as immutable once the
    // object set exists. Selectors and maxblkid are supplied by the new stream.
    if meta.levels != existing.levels()
        || meta.data_bytes != existing.data_bytes() as u64
        || meta.indirect_shift != existing.indirect_shift()
        || usize::from(meta.nblkptr) != existing.pointers().len()
    {
        return Err(FfsError::Format(
            "raw receive meta-dnode geometry disagrees with its existing object set".into(),
        ));
    }
    Ok(())
}

fn read_received_objectset(
    cx: &Cx,
    mos: &mut Objects,
    head: &Dnode,
    ceiling: u64,
) -> Result<ObjectSet> {
    let root = head
        .bonus()
        .get(128..256)
        .ok_or_else(|| corrupt("truncated receive dataset root block pointer"))?;
    let bp = BlockPointer::parse(root, head.order()).map_err(|e| parse_err(&e))?;
    let (raw, order, _) = mos.read_dataset_objset_block_raw(cx, &bp, ceiling, None, true)?;
    ObjectSet::parse(&raw, order).map_err(|e| parse_err(&e))
}

fn received_raw_order(flags: u8, stream_order: Endian) -> Endian {
    if flags & DRR_RAW_BYTESWAP == 0 {
        stream_order
    } else {
        match stream_order {
            Endian::Little => Endian::Big,
            Endian::Big => Endian::Little,
        }
    }
}

// ── ZAP Helpers for Resume State ────────────────────────────────────────────

fn zap_u64_entry(name: &[u8], val: u64) -> RawZapEntry {
    RawZapEntry {
        name: name.to_vec(),
        integer_bytes: 8,
        values: vec![val],
        collision: 0,
    }
}

fn zap_text_entry(name: &[u8], text: &[u8]) -> RawZapEntry {
    let mut vals: Vec<u64> = text.iter().map(|&b| u64::from(b)).collect();
    vals.push(0);
    RawZapEntry {
        name: name.to_vec(),
        integer_bytes: 1,
        values: vals,
        collision: 0,
    }
}

fn zap_text_value(entries: &[RawZapEntry], name: &[u8]) -> Option<String> {
    let entry = entries.iter().find(|e| e.name == name)?;
    if entry.integer_bytes != 1 {
        return None;
    }
    let raw: Vec<u8> = entry
        .values
        .iter()
        .filter_map(|&v| u8::try_from(v).ok())
        .collect();
    let trimmed = raw.strip_suffix(&[0]).unwrap_or(&raw);
    String::from_utf8(trimmed.to_vec()).ok()
}

fn is_resume_zap_key(name: &[u8]) -> bool {
    matches!(
        name,
        DS_FIELD_RESUME_FROMGUID
            | DS_FIELD_RESUME_TOGUID
            | DS_FIELD_RESUME_TONAME
            | DS_FIELD_RESUME_OBJECT
            | DS_FIELD_RESUME_OFFSET
            | DS_FIELD_RESUME_BYTES
            | DS_FIELD_RESUME_COMPRESSOK
            | DS_FIELD_RESUME_EMBEDOK
            | DS_FIELD_RESUME_LARGEBLOCKOK
            | DS_FIELD_RESUME_RAWOK
            | DS_FIELD_RESUME_IVSET_GUID
    )
}

// OpenZFS dmu_recv.c::recv_check_large_blocks refuses a downgrade of the
// stream's block geometry when its incremental/resume base already owns it.
fn require_receive_large_blocks(owners: &[&str], begin: &DrrBegin) -> Result<()> {
    if owners.contains(&"org.open-zfs:large_blocks")
        && !begin.features.contains(DMU_BACKUP_FEATURE_LARGE_BLOCKS)
    {
        return Err(unsupported(
            "incremental or resumed receive of large blocks requires stream large-block support",
        ));
    }
    Ok(())
}

fn build_resume_state_from_staging(staging: &RecvStagingDataset) -> Result<ZfsResumeState> {
    let toguid = zap_optional_u64(&staging.head_zap, DS_FIELD_RESUME_TOGUID)?
        .filter(|&v| v != 0)
        .ok_or_else(|| corrupt("staging dataset missing com.delphix:resume_toguid"))?;
    let fromguid =
        zap_optional_u64(&staging.head_zap, DS_FIELD_RESUME_FROMGUID)?.filter(|&v| v != 0);
    let object = zap_optional_u64(&staging.head_zap, DS_FIELD_RESUME_OBJECT)?.unwrap_or(0);
    let offset = zap_optional_u64(&staging.head_zap, DS_FIELD_RESUME_OFFSET)?.unwrap_or(0);
    let bytes = zap_optional_u64(&staging.head_zap, DS_FIELD_RESUME_BYTES)?.unwrap_or(0);
    let toname = zap_text_value(&staging.head_zap, DS_FIELD_RESUME_TONAME)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| corrupt("staging dataset missing com.delphix:resume_toname"))?;
    let compressok =
        zap_optional_u64(&staging.head_zap, DS_FIELD_RESUME_COMPRESSOK)?.is_some_and(|v| v != 0);
    let embedok =
        zap_optional_u64(&staging.head_zap, DS_FIELD_RESUME_EMBEDOK)?.is_some_and(|v| v != 0);
    let largeblockok =
        zap_optional_u64(&staging.head_zap, DS_FIELD_RESUME_LARGEBLOCKOK)?.is_some_and(|v| v != 0);
    let rawok = zap_optional_u64(&staging.head_zap, DS_FIELD_RESUME_RAWOK)?.is_some_and(|v| v != 0);
    let ivsetguid =
        zap_optional_u64(&staging.head_zap, DS_FIELD_RESUME_IVSET_GUID)?.filter(|&v| v != 0);

    let tok = ReceiveResumeToken {
        toguid,
        fromguid,
        object,
        offset,
        bytes,
        toname: toname.clone(),
        compressok,
        embedok,
        largeblockok,
        rawok,
        saved: false,
        ivsetguid,
    };
    let token = tok.encode().map_err(|e| parse_err(&e))?;
    Ok(ZfsResumeState {
        is_pct_recv_child: staging.is_pct_recv_child,
        toguid,
        fromguid,
        object,
        offset,
        bytes,
        toname,
        compressok,
        embedok,
        largeblockok,
        rawok,
        ivsetguid,
        token,
    })
}

struct CompoundMetadata {
    properties: Vec<(String, ZfsPropertySetValue)>,
    snapshots: BTreeMap<Vec<u8>, u64>,
}

fn stream_source_dataset(toname: &[u8]) -> Result<&[u8]> {
    let snapshot = validate_toname_snapshot(toname).map_err(|e| parse_err(&e))?;
    let dataset = &toname[..toname.len() - snapshot.len() - 1];
    if dataset.split(|&b| b == b'/').any(|part| {
        part.is_empty()
            || matches!(part, b"." | b"..")
            || part
                .iter()
                .any(|&b| matches!(b, 0..=31 | 127 | b'@' | b'#' | b'\\'))
    }) {
        return Err(corrupt("invalid compound stream source dataset name"));
    }
    Ok(dataset)
}

fn extract_compound_metadata(pkg_nvl: &NvList, source: &[u8]) -> Result<CompoundMetadata> {
    // One receive request owns one destination. A recursive package must never
    // flatten unrelated source datasets into that destination or borrow the
    // properties of an arbitrary first nvlist entry.
    if pkg_nvl.fields.get("not_recursive") != Some(&Value::Boolean(true)) {
        return Err(unsupported(
            "recursive compound receive requires dataset hierarchy support",
        ));
    }
    let fss = pkg_nvl
        .list("fss")
        .ok_or_else(|| corrupt("compound metadata lacks fss nvlist"))?;
    if fss.fields.len() != 1 {
        return Err(unsupported(
            "compound receive admits exactly one source dataset",
        ));
    }
    let Some(Value::List(ds_entry)) = fss.fields.values().next() else {
        return Err(corrupt("compound source dataset metadata is not an nvlist"));
    };
    if ds_entry.text("name").map(str::as_bytes) != Some(source) {
        return Err(corrupt("compound source dataset disagrees with DRR_BEGIN"));
    }
    let snaps = ds_entry
        .list("snaps")
        .ok_or_else(|| corrupt("compound dataset lacks snapshot identities"))?;
    let mut snapshots = BTreeMap::new();
    for (name, value) in &snaps.fields {
        let Value::Unsigned(guid) = value else {
            return Err(corrupt("compound snapshot GUID is not a native uint64"));
        };
        if *guid == 0 {
            return Err(corrupt("compound snapshot GUID must be nonzero"));
        }
        snapshots.insert(name.as_bytes().to_vec(), *guid);
    }
    let mut out = Vec::new();
    let Some(props) = ds_entry.list("props") else {
        return Ok(CompoundMetadata {
            properties: out,
            snapshots,
        });
    };
    for (k, v) in &props.fields {
        // Security boundary: never let untrusted received properties choose host mountpoints
        // or host key file paths!
        if matches!(
            k.as_str(),
            "mountpoint"
                | "keylocation"
                | "encryption"
                | "keyformat"
                | "pbkdf2salt"
                | "pbkdf2iters"
        ) {
            continue;
        }
        // Only admit well-formed user properties or known native dataset properties.
        let allowed = k.contains(':')
            || matches!(
                k.as_str(),
                "atime"
                    | "readonly"
                    | "recordsize"
                    | "compression"
                    | "checksum"
                    | "quota"
                    | "refquota"
                    | "reservation"
                    | "refreservation"
                    | "snapdev"
                    | "sync"
                    | "logbias"
                    | "volsize"
                    | "volblocksize"
            );
        if !allowed {
            continue;
        }
        match v {
            Value::Unsigned(n) => out.push((k.clone(), ZfsPropertySetValue::Number(*n))),
            Value::String(s) => {
                out.push((k.clone(), ZfsPropertySetValue::Text(s.as_bytes().to_vec())));
            }
            _ => {}
        }
    }
    Ok(CompoundMetadata {
        properties: out,
        snapshots,
    })
}

fn validate_compound_substream(
    source: &[u8],
    metadata: Option<&CompoundMetadata>,
    begin: &DrrBegin,
    previous_guid: u64,
) -> Result<()> {
    if stream_source_dataset(&begin.toname)? != source {
        return Err(corrupt(
            "compound substream belongs to a different source dataset",
        ));
    }
    let snapshot = validate_toname_snapshot(&begin.toname).map_err(|e| parse_err(&e))?;
    if let Some(metadata) = metadata
        && metadata.snapshots.get(&snapshot) != Some(&begin.toguid)
    {
        return Err(corrupt(
            "compound substream snapshot name/GUID disagrees with metadata",
        ));
    }
    if previous_guid != 0 && (begin.fromguid != previous_guid || begin.toguid == previous_guid) {
        return Err(corrupt(
            "compound substreams do not form an incremental snapshot chain",
        ));
    }
    Ok(())
}

fn validate_target_dataset(target: &[Vec<u8>]) -> Result<()> {
    if target.is_empty() {
        return Err(reject_einval(
            "receive target dataset cannot be the pool root",
        ));
    }
    for comp in target {
        validate_dsl_component(comp, false)?;
        if comp.starts_with(b"%") {
            return Err(reject_einval(
                "receive target dataset component cannot start with reserved '%'",
            ));
        }
    }
    Ok(())
}

/// Read-only inspection of an interrupted resumable receive (`%recv` or `DS_FLAG_INCONSISTENT`)
/// on `target_dataset`, returning its persisted OpenZFS v1 `receive_resume_token` if present.
pub fn inspect_receive_resume_state_in_mos(
    cx: &Cx,
    mos: &mut Objects,
    target_dataset: &[Vec<u8>],
) -> Result<Option<ZfsResumeState>> {
    validate_target_dataset(target_dataset)?;
    let Some(staging) = mos.find_recv_staging_dataset(cx, target_dataset)? else {
        return Ok(None);
    };
    Ok(Some(build_resume_state_from_staging(&staging)?))
}

impl ZfsTransactionEngine {
    /// Inspect an interrupted resumable receive (`%recv` or `DS_FLAG_INCONSISTENT`)
    /// on `target_dataset` without performing any writes, returning the OpenZFS v1
    /// `receive_resume_token` if present.
    pub fn inspect_receive_resume_state(
        &self,
        cx: &Cx,
        target_dataset: &[Vec<u8>],
    ) -> Result<Option<ZfsResumeState>> {
        let mut mos = self.open_read_objects(cx)?;
        inspect_receive_resume_state_in_mos(cx, &mut mos, target_dataset)
    }

    /// Atomically abort an incomplete resumable receive (`%recv` or `DS_FLAG_INCONSISTENT`)
    /// on `target_dataset`, reclaiming all staged blocks, MOS objects, and feature refcounts.
    pub fn abort_receive(&mut self, cx: &Cx, target_dataset: &[Vec<u8>]) -> ZfsTxOutcome<u64> {
        if let Err(err) = validate_target_dataset(target_dataset) {
            return ZfsTxOutcome::NotCommitted(err);
        }
        let target_owned = target_dataset.to_vec();
        let order = self.order;
        let empty_bpobj_id = self.empty_bpobj_id;
        self.execute_staged_txg_typed(
            cx,
            "abort_receive",
            move |mos, mos_dirty_dnodes, features, alloc, new_txg, staged_writes| {
                let Some(staging) = mos.find_recv_staging_dataset(cx, &target_owned)? else {
                    return Err(FfsError::NotFound(
                        "no incomplete resumable receive found for target dataset".into(),
                    ));
                };
                let leaf_name: &[u8] = if staging.is_pct_recv_child {
                    b"%recv"
                } else {
                    target_owned.last().expect("nonempty")
                };
                let crypto = resolve_staging_crypto_info(cx, mos, staging.directory_object)?;
                let before_alloc = alloc.total_allocated_bytes();
                stage_destroy_dataset_by_ids(
                    cx,
                    mos,
                    staging.directory_object,
                    staging.head_object,
                    leaf_name,
                    crypto.as_ref(),
                    mos_dirty_dnodes,
                    features,
                    empty_bpobj_id,
                    alloc,
                    order,
                    new_txg,
                    staged_writes,
                )?;
                let reclaimed = before_alloc.saturating_sub(alloc.total_allocated_bytes());
                Ok((reclaimed, reclaimed))
            },
        )
    }

    /// Ingest a native OpenZFS `DMU_BACKUP_STREAM` (single substream or `-p`/`-I` compound
    /// stream, full or incremental, logical/compressed/embedded/large-block or keyless raw
    /// encrypted `-w`, optionally resumable `-s`) into `req.target_dataset`.
    ///
    /// Interrupted receives report every known durable checkpoint or completed
    /// substream separately from an uncertain native publication. Automatic abort
    /// cleanup is itself a native transaction and does not undo an earlier
    /// completed compound substream.
    pub fn receive_stream(
        &mut self,
        cx: &Cx,
        req: &ZfsRecvRequest,
        input: &mut impl Read,
    ) -> ZfsRecvOutcome {
        let attempt = RefCell::new(RecvAttempt::default());
        let outcome = self.receive_stream_inner(cx, req, input, &attempt);
        attempt.into_inner().finish(outcome)
    }

    #[allow(clippy::too_many_lines)]
    fn receive_stream_inner(
        &mut self,
        cx: &Cx,
        req: &ZfsRecvRequest,
        input: &mut impl Read,
        attempt: &RefCell<RecvAttempt>,
    ) -> ZfsTxOutcome<ZfsRecvReport> {
        if self.poisoned_uncertain {
            return ZfsTxOutcome::NotCommitted(unsupported(
                "ZFS writer handle experienced an Uncertain Uberblock outcome; reopen fresh engine",
            ));
        }
        if let Err(err) = checkpoint(cx) {
            return ZfsTxOutcome::NotCommitted(err);
        }
        if let Err(err) = validate_target_dataset(&req.target_dataset) {
            return ZfsTxOutcome::NotCommitted(err);
        }
        let mut reader = StreamReader::new(input);
        let first_hdr = match reader.read_header_or_eof(cx) {
            Ok(Some(h)) => h,
            Ok(None) => {
                return ZfsTxOutcome::NotCommitted(FfsError::Format(
                    "empty DMU send stream".into(),
                ));
            }
            Err(e) => return ZfsTxOutcome::NotCommitted(e),
        };
        let stream_order = match detect_stream_endian(&first_hdr) {
            Ok(o) => o,
            Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
        };
        let (first_rec, _) = match DrrRecord::parse_header(&first_hdr, stream_order) {
            Ok(r) => r,
            Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
        };
        let DrrRecord::Begin(first_begin) = first_rec else {
            return ZfsTxOutcome::NotCommitted(FfsError::Format(
                "DMU send stream must begin with DRR_BEGIN".into(),
            ));
        };

        let mut compound = false;
        let mut compound_props: Vec<(String, ZfsPropertySetValue)> = Vec::new();
        let mut substreams_received = 0_usize;
        let mut total_records = 0_u64;
        let mut total_objects = 0_u64;
        let mut total_blocks = 0_u64;
        let mut total_checkpoints = 0_u64;
        let mut any_raw = false;
        let mut any_resumed = false;
        let mut last_snap_name = String::new();
        let mut last_snap_guid = 0_u64;
        let mut last_token: Option<ZfsDurableToken> = None;

        if first_begin.hdr_type == StreamHeaderType::CompoundStream {
            compound = true;
            if first_begin.features.unsupported_bits() != 0 {
                return ZfsTxOutcome::NotCommitted(unsupported(format!(
                    "compound DMU stream requires unsupported feature bits 0x{:x}",
                    first_begin.features.unsupported_bits()
                )));
            }
            let source_dataset = match stream_source_dataset(&first_begin.toname) {
                Ok(source) => source,
                Err(e) => return ZfsTxOutcome::NotCommitted(e),
            };
            let payload_len =
                match DrrRecord::Begin(first_begin.clone()).expected_payload_len(false) {
                    Ok(n) => n,
                    Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
                };
            let pkg_bytes = match reader.read_exact_bytes(cx, payload_len) {
                Ok(b) => b,
                Err(e) => return ZfsTxOutcome::NotCommitted(e),
            };
            // Native compound packages have their own header END immediately
            // after the nvlist, distinct from the final package terminator.
            // Validate it before trusting properties or allocating staging state.
            let mut header_checksum = Fletcher4Stream::new(stream_order);
            if let Err(e) = header_checksum
                .update(&first_hdr)
                .and_then(|()| header_checksum.update(&pkg_bytes))
            {
                return ZfsTxOutcome::NotCommitted(parse_err(&e));
            }
            let header_end = match reader.read_header_or_eof(cx) {
                Ok(Some(h)) => h,
                Ok(None) => {
                    return ZfsTxOutcome::NotCommitted(FfsError::Format(
                        "truncated compound DMU stream before header DRR_END".into(),
                    ));
                }
                Err(e) => return ZfsTxOutcome::NotCommitted(e),
            };
            let (header_end_record, trailer) =
                match DrrRecord::parse_header(&header_end, stream_order) {
                    Ok(r) => r,
                    Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
                };
            match header_end_record {
                DrrRecord::End(end)
                    if end.checksum == header_checksum.state()
                        && end.toguid == 0
                        && trailer == [0; 4] => {}
                DrrRecord::End(_) => {
                    return ZfsTxOutcome::NotCommitted(FfsError::Format(
                        "compound DMU header DRR_END checksum or framing mismatch".into(),
                    ));
                }
                _ => {
                    return ZfsTxOutcome::NotCommitted(FfsError::Format(
                        "compound DMU nvlist must be followed by its header DRR_END".into(),
                    ));
                }
            }
            let compound_metadata = if pkg_bytes.is_empty() {
                None
            } else {
                let nvl = match NvList::parse_exact(&pkg_bytes) {
                    Ok(nvl) => nvl,
                    Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
                };
                match extract_compound_metadata(&nvl, source_dataset) {
                    Ok(metadata) => Some(metadata),
                    Err(e) => return ZfsTxOutcome::NotCommitted(e),
                }
            };
            if let Some(metadata) = &compound_metadata {
                compound_props.clone_from(&metadata.properties);
            }
            total_records += 2;

            loop {
                let next_hdr = match reader.read_header_or_eof(cx) {
                    Ok(Some(h)) => h,
                    Ok(None) => {
                        return ZfsTxOutcome::NotCommitted(FfsError::Format(
                            "truncated compound DMU stream before outer DRR_END".into(),
                        ));
                    }
                    Err(e) => return ZfsTxOutcome::NotCommitted(e),
                };
                let (next_rec, trailer) = match DrrRecord::parse_header(&next_hdr, stream_order) {
                    Ok(r) => r,
                    Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
                };
                match next_rec {
                    DrrRecord::End(end) => {
                        if end.checksum != [0; 4] || end.toguid != 0 || trailer != [0; 4] {
                            return ZfsTxOutcome::NotCommitted(FfsError::Format(
                                "compound DMU final DRR_END must have zero checksum and GUID"
                                    .into(),
                            ));
                        }
                        total_records += 1;
                        if let Err(e) = reader.assert_eof(cx) {
                            return ZfsTxOutcome::NotCommitted(e);
                        }
                        break;
                    }
                    DrrRecord::Begin(sub_begin) => {
                        if sub_begin.hdr_type != StreamHeaderType::Substream {
                            return ZfsTxOutcome::NotCommitted(FfsError::Format(
                                "nested compound DMU stream is unsupported".into(),
                            ));
                        }
                        if substreams_received >= MAX_COMPOUND_SUBSTREAMS {
                            return ZfsTxOutcome::NotCommitted(unsupported(
                                "compound stream exceeds 256 substream bound",
                            ));
                        }
                        if let Err(e) = validate_compound_substream(
                            source_dataset,
                            compound_metadata.as_ref(),
                            &sub_begin,
                            last_snap_guid,
                        ) {
                            return ZfsTxOutcome::NotCommitted(e);
                        }
                        let sub_props = if substreams_received == 0 {
                            &compound_props[..]
                        } else {
                            &[]
                        };
                        match self.receive_one_substream(
                            cx,
                            req,
                            stream_order,
                            &next_hdr,
                            &sub_begin,
                            sub_props,
                            false,
                            &mut reader,
                            attempt,
                        ) {
                            ZfsTxOutcome::Committed {
                                value: sub_rep,
                                token: tok,
                            } => {
                                substreams_received += 1;
                                total_records += sub_rep.records_applied;
                                total_objects += sub_rep.objects_received;
                                total_blocks += sub_rep.blocks_received;
                                total_checkpoints += sub_rep.checkpoint_txgs;
                                any_raw |= sub_rep.raw;
                                any_resumed |= sub_rep.resumed;
                                last_snap_name = sub_rep.final_snapshot;
                                last_snap_guid = sub_rep.final_snapshot_guid;
                                last_token = Some(tok);
                            }
                            ZfsTxOutcome::NotCommitted(e) => return ZfsTxOutcome::NotCommitted(e),
                            ZfsTxOutcome::Uncertain {
                                reason,
                                target_txg,
                                target_slot,
                            } => {
                                return ZfsTxOutcome::Uncertain {
                                    reason,
                                    target_txg,
                                    target_slot,
                                };
                            }
                        }
                    }
                    _ => {
                        return ZfsTxOutcome::NotCommitted(FfsError::Format(
                            "unexpected record at top level of compound DMU stream".into(),
                        ));
                    }
                }
            }
            if substreams_received == 0 {
                return ZfsTxOutcome::NotCommitted(FfsError::Format(
                    "compound DMU stream contained zero substreams".into(),
                ));
            }
        } else {
            match self.receive_one_substream(
                cx,
                req,
                stream_order,
                &first_hdr,
                &first_begin,
                &[],
                true,
                &mut reader,
                attempt,
            ) {
                ZfsTxOutcome::Committed {
                    value: sub_rep,
                    token: tok,
                } => {
                    substreams_received = 1;
                    total_records = sub_rep.records_applied;
                    total_objects = sub_rep.objects_received;
                    total_blocks = sub_rep.blocks_received;
                    total_checkpoints = sub_rep.checkpoint_txgs;
                    any_raw = sub_rep.raw;
                    any_resumed = sub_rep.resumed;
                    last_snap_name = sub_rep.final_snapshot;
                    last_snap_guid = sub_rep.final_snapshot_guid;
                    last_token = Some(tok);
                }
                ZfsTxOutcome::NotCommitted(e) => return ZfsTxOutcome::NotCommitted(e),
                ZfsTxOutcome::Uncertain {
                    reason,
                    target_txg,
                    target_slot,
                } => {
                    return ZfsTxOutcome::Uncertain {
                        reason,
                        target_txg,
                        target_slot,
                    };
                }
            }
        }

        let Some(durable_token) = last_token else {
            return ZfsTxOutcome::NotCommitted(corrupt("missing durable token after receive"));
        };
        ZfsTxOutcome::Committed {
            value: ZfsRecvReport {
                substreams_received,
                compound,
                raw: any_raw,
                resumed: any_resumed,
                final_snapshot: last_snap_name,
                final_snapshot_guid: last_snap_guid,
                records_applied: total_records,
                objects_received: total_objects,
                blocks_received: total_blocks,
                stream_bytes_read: reader.bytes_read,
                checkpoint_txgs: total_checkpoints,
                durable_token: durable_token.clone(),
            },
            token: durable_token,
        }
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn receive_one_substream<R: Read>(
        &mut self,
        cx: &Cx,
        req: &ZfsRecvRequest,
        stream_order: Endian,
        begin_hdr: &[u8; DMU_REPLAY_RECORD_BYTES],
        begin: &DrrBegin,
        compound_props: &[(String, ZfsPropertySetValue)],
        require_eof_before_commit: bool,
        reader: &mut StreamReader<'_, R>,
        attempt: &RefCell<RecvAttempt>,
    ) -> ZfsTxOutcome<ZfsRecvReport> {
        // 1. Fail-closed admission of DRR_BEGIN header BEFORE allocating any block!
        let bad_feats = begin.features.unsupported_bits();
        if bad_feats != 0 {
            return ZfsTxOutcome::NotCommitted(unsupported(format!(
                "DMU send stream requires unsupported feature bits 0x{bad_feats:x}"
            )));
        }
        if begin.flags & DRR_FLAG_CI_DATA != 0 {
            return ZfsTxOutcome::NotCommitted(unsupported(
                "case-insensitive ZPL send streams are unsupported",
            ));
        }
        if begin.toguid == 0 {
            return ZfsTxOutcome::NotCommitted(FfsError::Format(
                "DRR_BEGIN has zero drr_toguid".into(),
            ));
        }
        if !matches!(begin.objset_type, DMU_OST_ZFS | DMU_OST_ZVOL) {
            return ZfsTxOutcome::NotCommitted(unsupported(format!(
                "unsupported DMU stream objset type {}",
                begin.objset_type
            )));
        }
        for (name, value) in compound_props {
            if name == "compression" {
                let ZfsPropertySetValue::Number(raw) = value else {
                    return ZfsTxOutcome::NotCommitted(FfsError::Format(
                        "received compression property must be a native numeric selector".into(),
                    ));
                };
                if let Err(error) = DatasetCompression::from_property(*raw, &self.mos_features) {
                    return ZfsTxOutcome::NotCommitted(error);
                }
            }
        }
        let snap_name = match &req.snapshot_override {
            Some(name) => {
                if let Err(e) = validate_dsl_component(name, true) {
                    return ZfsTxOutcome::NotCommitted(e);
                }
                name.clone()
            }
            None => match validate_toname_snapshot(&begin.toname) {
                Ok(n) => {
                    if let Err(e) = validate_dsl_component(&n, true) {
                        return ZfsTxOutcome::NotCommitted(e);
                    }
                    n
                }
                Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
            },
        };

        let is_raw = begin.features.contains(DMU_BACKUP_FEATURE_RAW);
        let is_resuming = begin.features.contains(DMU_BACKUP_FEATURE_RESUMING);

        let begin_payload_len = match DrrRecord::Begin(begin.clone()).expected_payload_len(is_raw) {
            Ok(n) => n,
            Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
        };
        let begin_payload = match reader.read_exact_bytes(cx, begin_payload_len) {
            Ok(b) => b,
            Err(e) => return ZfsTxOutcome::NotCommitted(e),
        };

        let mut cksum = Fletcher4Stream::new(stream_order);
        if let Err(e) = cksum.verify_record(begin_hdr, &begin_payload, DrrType::Begin, false) {
            return ZfsTxOutcome::NotCommitted(parse_err(&e));
        }

        let keydata: Option<StreamCryptoKeydata> = if is_raw && !begin_payload.is_empty() {
            match NvList::parse_exact(&begin_payload)
                .and_then(|nvl| StreamCryptoKeydata::from_nvlist(&nvl))
            {
                Ok(kd) => Some(kd),
                Err(e) => return ZfsTxOutcome::NotCommitted(parse_err(&e)),
            }
        } else {
            None
        };

        if is_raw && keydata.is_none() {
            return ZfsTxOutcome::NotCommitted(FfsError::Format(
                "raw encrypted receive requires DRR_BEGIN crypt_keydata".into(),
            ));
        }
        if let Some(kd) = &keydata
            && let Err(error) = admit_received_meta_dnode(&kd.meta_dnode)
        {
            return ZfsTxOutcome::NotCommitted(error);
        }

        if keydata.is_some()
            && (!self
                .mos_features
                .read_features
                .contains_key("com.datto:encryption")
                || !self
                    .mos_features
                    .read_features
                    .contains_key("com.delphix:extensible_dataset"))
        {
            return ZfsTxOutcome::NotCommitted(unsupported(
                "pool lacks com.datto:encryption / com.delphix:extensible_dataset for raw encrypted receive",
            ));
        }

        // 2. Stage begin TXG (or validate existing resumable staging dataset).
        let (stage_meta, mut committed_progress) = if is_resuming {
            match self.validate_resume_staging(cx, &req.target_dataset, begin, keydata.as_ref()) {
                Ok(v) => v,
                Err(e) => return ZfsTxOutcome::NotCommitted(e),
            }
        } else {
            match self.commit_recv_begin_txg(cx, req, begin, keydata.as_ref()) {
                ZfsTxOutcome::Committed { value: meta, token } => {
                    attempt.borrow_mut().record(token, ZfsRecvStage::Checkpoint);
                    (
                        meta,
                        ChunkProgress {
                            object: 0,
                            offset: 0,
                            bytes: reader.bytes_read,
                        },
                    )
                }
                ZfsTxOutcome::NotCommitted(e) => return ZfsTxOutcome::NotCommitted(e),
                ZfsTxOutcome::Uncertain {
                    reason,
                    target_txg,
                    target_slot,
                } => {
                    return ZfsTxOutcome::Uncertain {
                        reason,
                        target_txg,
                        target_slot,
                    };
                }
            }
        };

        let cleanup_on_abort = |engine: &mut Self, err: FfsError| -> ZfsTxOutcome<ZfsRecvReport> {
            if !req.resumable && !engine.poisoned_uncertain {
                match engine.abort_receive(cx, &req.target_dataset) {
                    ZfsTxOutcome::Committed { token, .. } => {
                        attempt.borrow_mut().record(token, ZfsRecvStage::Aborted);
                    }
                    ZfsTxOutcome::NotCommitted(cleanup_error) => {
                        attempt.borrow_mut().cleanup_error = Some(cleanup_error);
                    }
                    ZfsTxOutcome::Uncertain {
                        reason,
                        target_txg,
                        target_slot,
                    } => {
                        attempt.borrow_mut().receive_error = Some(err);
                        return ZfsTxOutcome::Uncertain {
                            reason,
                            target_txg,
                            target_slot,
                        };
                    }
                }
            }
            ZfsTxOutcome::NotCommitted(err)
        };

        // 3. Stream records in strict ascending `(object, offset)` order with bounded TXG checkpoints.
        let mut records_applied = 1_u64;
        let mut objects_received = 0_u64;
        let mut blocks_received = 0_u64;
        let mut checkpoint_txgs = u64::from(!is_resuming);

        let mut pending_ops: Vec<RecvOp> = Vec::new();
        let mut substream_object_ranges: BTreeMap<u64, ObjectRangeMeta> = BTreeMap::new();
        let mut pending_bytes = 0_u64;
        let checkpoint_limit = req.checkpoint_bytes.max(512);

        let mut last_obj = committed_progress.object;
        let mut last_offset = committed_progress.offset;
        let mut seen_objects: BTreeSet<u64> = BTreeSet::new();
        let mut obj_blksz_map: BTreeMap<u64, u64> = BTreeMap::new();
        let mut seen_per_record_cksum = false;
        let mut saw_end = false;

        while !saw_end {
            if records_applied >= MAX_RECV_RECORDS {
                return cleanup_on_abort(
                    self,
                    unsupported("receive stream exceeded record safety limit"),
                );
            }
            let hdr_bytes = match reader.read_header_or_eof(cx) {
                Ok(Some(h)) => h,
                Ok(None) => {
                    return cleanup_on_abort(
                        self,
                        FfsError::Format("truncated DMU substream before DRR_END".into()),
                    );
                }
                Err(e) => return cleanup_on_abort(self, e),
            };
            let (rec, trailer) = match DrrRecord::parse_header(&hdr_bytes, stream_order) {
                Ok(r) => r,
                Err(e) => return cleanup_on_abort(self, parse_err(&e)),
            };
            if trailer != [0; 4] {
                seen_per_record_cksum = true;
            }
            let payload_len = match rec.expected_payload_len(is_raw) {
                Ok(n) => n,
                Err(e) => return cleanup_on_abort(self, parse_err(&e)),
            };
            let payload = match reader.read_exact_bytes(cx, payload_len) {
                Ok(b) => b,
                Err(e) => return cleanup_on_abort(self, e),
            };
            if let Err(e) = cksum.verify_record(
                &hdr_bytes,
                &payload,
                rec.record_type(),
                seen_per_record_cksum,
            ) {
                return cleanup_on_abort(self, parse_err(&e));
            }
            records_applied += 1;

            match rec {
                DrrRecord::Begin(_) => {
                    return cleanup_on_abort(
                        self,
                        FfsError::Format("unexpected nested DRR_BEGIN inside substream".into()),
                    );
                }
                DrrRecord::WriteByref(_) => {
                    return cleanup_on_abort(
                        self,
                        unsupported("DRR_WRITE_BYREF (dedup send stream) is unsupported"),
                    );
                }
                DrrRecord::Redact(_) => {
                    return cleanup_on_abort(
                        self,
                        unsupported("DRR_REDACT (redacted send stream) is unsupported"),
                    );
                }
                DrrRecord::ObjectRange(r) => {
                    if !is_raw {
                        return cleanup_on_abort(
                            self,
                            FfsError::Format(
                                "DRR_OBJECT_RANGE requires a raw encrypted stream".into(),
                            ),
                        );
                    }
                    // This receiver's metadnode uses 16 KiB blocks (32 slots).
                    // Reject incompatible ranges before expanding any state.
                    if r.numslots != 32 || !r.firstobj.is_multiple_of(32) {
                        return cleanup_on_abort(
                            self,
                            unsupported(
                                "DRR_OBJECT_RANGE requires one aligned 32-slot dnode block",
                            ),
                        );
                    }
                    if received_raw_order(r.flags, stream_order) != self.order {
                        return cleanup_on_abort(
                            self,
                            unsupported(
                                "raw receive cannot reconstruct foreign-order dnode tables",
                            ),
                        );
                    }
                    if let Err(error) =
                        validate_received_raw_object(stage_meta.raw_meta_dnode.as_ref(), r.firstobj)
                    {
                        return cleanup_on_abort(self, error);
                    }
                    if r.toguid != 0 && r.toguid != begin.toguid {
                        return cleanup_on_abort(
                            self,
                            corrupt("DRR_OBJECT_RANGE toguid disagrees with DRR_BEGIN"),
                        );
                    }
                    if r.firstobj
                        .checked_add(r.numslots)
                        .is_none_or(|end| end < last_obj)
                    {
                        return cleanup_on_abort(
                            self,
                            FfsError::Format("out-of-order DRR_OBJECT_RANGE".into()),
                        );
                    }
                    let start_bid = r.firstobj / 32;
                    let blocks = r.numslots / 32;
                    for b in 0..blocks {
                        substream_object_ranges.insert(
                            start_bid + b,
                            ObjectRangeMeta {
                                salt: r.salt,
                                iv: r.iv,
                                mac: r.mac,
                                flags: r.flags,
                            },
                        );
                    }
                    pending_ops.push(RecvOp::ObjectRange(r));
                }
                DrrRecord::Object(o) => {
                    if let Err(error) =
                        validate_received_raw_object(stage_meta.raw_meta_dnode.as_ref(), o.object)
                    {
                        return cleanup_on_abort(self, error);
                    }
                    if o.toguid != 0 && o.toguid != begin.toguid {
                        return cleanup_on_abort(
                            self,
                            corrupt("DRR_OBJECT toguid disagrees with DRR_BEGIN"),
                        );
                    }
                    if o.object == 0 {
                        return cleanup_on_abort(
                            self,
                            FfsError::Format("DRR_OBJECT cannot target object 0".into()),
                        );
                    }
                    let Ok(bonus_type) = u8::try_from(o.bonus_type) else {
                        return cleanup_on_abort(self, corrupt("DRR_OBJECT bonus type overflow"));
                    };
                    if u8::try_from(o.object_type).is_err() || o.object_type == 0 {
                        return cleanup_on_abort(self, corrupt("invalid DRR_OBJECT type"));
                    }
                    if o.compress > 16 {
                        return cleanup_on_abort(
                            self,
                            FfsError::Format("invalid DRR_OBJECT compression selector".into()),
                        );
                    }
                    if let Err(error) =
                        DatasetCompression::from_property(u64::from(o.compress), &self.mos_features)
                    {
                        return cleanup_on_abort(self, error);
                    }
                    if !is_raw
                        && o.bonuslen != 0
                        && let Err(error) =
                            validate_received_plain_order(bonus_type, stream_order, self.order)
                    {
                        return cleanup_on_abort(self, error);
                    }
                    // Native dnode overrides are limited to legacy checksums.
                    // Newer algorithms remain valid on individual DRR_WRITE BPs.
                    if o.checksumtype >= 9 {
                        return cleanup_on_abort(
                            self,
                            FfsError::Format(
                                "DRR_OBJECT checksum selector is outside the native legacy range"
                                    .into(),
                            ),
                        );
                    }
                    if o.object < last_obj || !seen_objects.insert(o.object) {
                        return cleanup_on_abort(
                            self,
                            FfsError::Format(format!(
                                "reordered or duplicate DRR_OBJECT {}",
                                o.object
                            )),
                        );
                    }
                    let blksz = u64::from(o.blksz);
                    if blksz < 512
                        || !blksz.is_multiple_of(512)
                        || (o.maxblkid != 0 && !blksz.is_power_of_two())
                        || blksz > MAX_BLOCK_BYTES as u64
                    {
                        return cleanup_on_abort(
                            self,
                            FfsError::Format(format!("invalid DRR_OBJECT blksz {blksz}")),
                        );
                    }
                    if blksz > 131_072
                        && !self
                            .mos_features
                            .read_features
                            .contains_key("org.open-zfs:large_blocks")
                    {
                        return cleanup_on_abort(
                            self,
                            unsupported("pool lacks org.open-zfs:large_blocks for >128KiB object"),
                        );
                    }
                    if o.dn_slots > 1
                        && !self
                            .mos_features
                            .read_features
                            .contains_key("org.zfsonlinux:large_dnode")
                    {
                        return cleanup_on_abort(
                            self,
                            unsupported(
                                "pool lacks org.zfsonlinux:large_dnode for multi-slot dnode",
                            ),
                        );
                    }
                    last_obj = o.object;
                    last_offset = 0;
                    obj_blksz_map.insert(o.object, blksz);
                    objects_received += 1;
                    pending_bytes = pending_bytes.saturating_add(payload.len() as u64 + 512);
                    pending_ops.push(RecvOp::Object {
                        rec: o,
                        bonus: payload,
                    });
                }
                DrrRecord::FreeObjects(f) => {
                    if f.toguid != 0 && f.toguid != begin.toguid {
                        return cleanup_on_abort(
                            self,
                            corrupt("DRR_FREEOBJECTS toguid disagrees with DRR_BEGIN"),
                        );
                    }
                    if f.firstobj == 0
                        || f.numobjs == 0
                        || f.firstobj.checked_add(f.numobjs).is_none()
                    {
                        return cleanup_on_abort(
                            self,
                            FfsError::Format("invalid DRR_FREEOBJECTS range".into()),
                        );
                    }
                    if f.firstobj < last_obj {
                        return cleanup_on_abort(
                            self,
                            FfsError::Format("reordered DRR_FREEOBJECTS".into()),
                        );
                    }
                    last_obj = f.firstobj.saturating_add(f.numobjs - 1);
                    last_offset = 0;
                    pending_bytes = pending_bytes.saturating_add(256);
                    pending_ops.push(RecvOp::FreeObjects(f));
                }
                DrrRecord::Write(w) => {
                    if let Err(error) =
                        validate_received_raw_object(stage_meta.raw_meta_dnode.as_ref(), w.object)
                    {
                        return cleanup_on_abort(self, error);
                    }
                    if w.toguid != 0 && w.toguid != begin.toguid {
                        return cleanup_on_abort(
                            self,
                            corrupt("DRR_WRITE toguid disagrees with DRR_BEGIN"),
                        );
                    }
                    if w.object == 0 || w.object < last_obj {
                        return cleanup_on_abort(
                            self,
                            FfsError::Format("reordered DRR_WRITE object".into()),
                        );
                    }
                    if w.object == last_obj && w.offset < last_offset {
                        return cleanup_on_abort(
                            self,
                            FfsError::Format("reordered DRR_WRITE offset".into()),
                        );
                    }
                    if let Some(&blksz) = obj_blksz_map.get(&w.object)
                        && (!w.offset.is_multiple_of(blksz) || w.logical_size != blksz)
                    {
                        return cleanup_on_abort(
                            self,
                            FfsError::Format(
                                "misaligned or mismatched DRR_WRITE block size".into(),
                            ),
                        );
                    }
                    if let Err(error) =
                        admit_received_compression(w.compressiontype, &self.mos_features)
                    {
                        return cleanup_on_abort(self, error);
                    }
                    let object_type = match u8::try_from(w.object_type) {
                        Ok(kind) if kind != 0 => kind,
                        _ => return cleanup_on_abort(self, corrupt("invalid DRR_WRITE type")),
                    };
                    let Some(end_offset) = w.offset.checked_add(w.logical_size) else {
                        return cleanup_on_abort(self, corrupt("DRR_WRITE offset overflow"));
                    };
                    if !is_raw {
                        if w.flags & DRR_RAW_BYTESWAP != 0 {
                            return cleanup_on_abort(
                                self,
                                corrupt("non-raw DRR_WRITE carries raw byte order"),
                            );
                        }
                        if let Err(error) =
                            validate_received_plain_order(object_type, stream_order, self.order)
                        {
                            return cleanup_on_abort(self, error);
                        }
                    }
                    if let Err(error) = validate_received_block_payload(
                        cx,
                        w.logical_size,
                        w.compressiontype,
                        &payload,
                        is_raw,
                    ) {
                        return cleanup_on_abort(self, error);
                    }
                    last_obj = w.object;
                    last_offset = end_offset;
                    blocks_received += 1;
                    pending_bytes = pending_bytes.saturating_add(payload.len() as u64);
                    pending_ops.push(RecvOp::Write { rec: w, payload });
                }
                DrrRecord::WriteEmbedded(e) => {
                    if is_raw {
                        return cleanup_on_abort(
                            self,
                            FfsError::Format(
                                "DRR_WRITE_EMBEDDED is forbidden in raw encrypted streams".into(),
                            ),
                        );
                    }
                    if let Err(error) =
                        admit_received_compression(e.compression, &self.mos_features)
                    {
                        return cleanup_on_abort(self, error);
                    }
                    if e.toguid != 0 && e.toguid != begin.toguid {
                        return cleanup_on_abort(
                            self,
                            corrupt("DRR_WRITE_EMBEDDED toguid disagrees with DRR_BEGIN"),
                        );
                    }
                    if !self
                        .read_features
                        .iter()
                        .any(|f| f == "com.delphix:embedded_data")
                    {
                        return cleanup_on_abort(
                            self,
                            unsupported("pool lacks com.delphix:embedded_data"),
                        );
                    }
                    if e.object == 0 || e.object < last_obj {
                        return cleanup_on_abort(
                            self,
                            FfsError::Format("reordered DRR_WRITE_EMBEDDED object".into()),
                        );
                    }
                    if e.object == last_obj && e.offset < last_offset {
                        return cleanup_on_abort(
                            self,
                            FfsError::Format("reordered DRR_WRITE_EMBEDDED offset".into()),
                        );
                    }
                    if e.etype != 0 {
                        return cleanup_on_abort(
                            self,
                            unsupported("non-DATA DRR_WRITE_EMBEDDED subtype is unsupported"),
                        );
                    }
                    if let Some(&blksz) = obj_blksz_map.get(&e.object)
                        && (!e.offset.is_multiple_of(blksz) || e.length != blksz)
                    {
                        return cleanup_on_abort(
                            self,
                            FfsError::Format(
                                "misaligned or mismatched DRR_WRITE_EMBEDDED block size".into(),
                            ),
                        );
                    }
                    if let Err(error) = validate_received_embedded_payload(cx, &e, &payload) {
                        return cleanup_on_abort(self, error);
                    }
                    last_obj = e.object;
                    last_offset = e.offset + e.length;
                    blocks_received += 1;
                    pending_bytes = pending_bytes.saturating_add(payload.len() as u64 + 128);
                    pending_ops.push(RecvOp::WriteEmbedded { rec: e, payload });
                }
                DrrRecord::Free(f) => {
                    if let Err(error) =
                        validate_received_raw_object(stage_meta.raw_meta_dnode.as_ref(), f.object)
                    {
                        return cleanup_on_abort(self, error);
                    }
                    if f.toguid != 0 && f.toguid != begin.toguid {
                        return cleanup_on_abort(
                            self,
                            corrupt("DRR_FREE toguid disagrees with DRR_BEGIN"),
                        );
                    }
                    if f.object == 0 || f.object < last_obj {
                        return cleanup_on_abort(
                            self,
                            FfsError::Format("reordered DRR_FREE object".into()),
                        );
                    }
                    last_obj = f.object;
                    if f.length != u64::MAX {
                        last_offset = last_offset.max(f.offset.saturating_add(f.length));
                    }
                    pending_bytes = pending_bytes.saturating_add(128);
                    pending_ops.push(RecvOp::Free(f));
                }
                DrrRecord::Spill(s) => {
                    if let Err(error) =
                        validate_received_raw_object(stage_meta.raw_meta_dnode.as_ref(), s.object)
                    {
                        return cleanup_on_abort(self, error);
                    }
                    if let Err(error) =
                        admit_received_compression(s.compressiontype, &self.mos_features)
                    {
                        return cleanup_on_abort(self, error);
                    }
                    if s.toguid != 0 && s.toguid != begin.toguid {
                        return cleanup_on_abort(
                            self,
                            corrupt("DRR_SPILL toguid disagrees with DRR_BEGIN"),
                        );
                    }
                    if s.object == 0 || s.object < last_obj {
                        return cleanup_on_abort(
                            self,
                            FfsError::Format("reordered DRR_SPILL object".into()),
                        );
                    }
                    // Native non-raw SPILL records always carry logical bytes,
                    // even when the stream permits compressed WRITE records.
                    if !is_raw && (s.compressiontype != 0 || s.flags & DRR_RAW_BYTESWAP != 0) {
                        return cleanup_on_abort(
                            self,
                            FfsError::Format("non-raw DRR_SPILL must contain logical bytes".into()),
                        );
                    }
                    if let Err(error) = validate_received_block_payload(
                        cx,
                        s.length,
                        s.compressiontype,
                        &payload,
                        is_raw,
                    ) {
                        return cleanup_on_abort(self, error);
                    }
                    last_obj = s.object;
                    blocks_received += 1;
                    pending_bytes = pending_bytes.saturating_add(payload.len() as u64);
                    pending_ops.push(RecvOp::Spill { rec: s, payload });
                }
                DrrRecord::End(e) => {
                    if e.toguid != 0 && e.toguid != begin.toguid {
                        return cleanup_on_abort(
                            self,
                            corrupt("DRR_END toguid disagrees with DRR_BEGIN"),
                        );
                    }
                    saw_end = true;
                }
            }

            if (!pending_ops.is_empty() && pending_bytes >= checkpoint_limit)
                || (saw_end && (!pending_ops.is_empty() || is_raw))
            {
                let next_prog = ChunkProgress {
                    object: last_obj,
                    offset: last_offset,
                    bytes: reader.bytes_read,
                };
                match self.commit_recv_chunk_txg(
                    cx,
                    &stage_meta,
                    stream_order,
                    &pending_ops,
                    &substream_object_ranges,
                    &next_prog,
                    saw_end,
                ) {
                    ZfsTxOutcome::Committed { token, .. } => {
                        attempt.borrow_mut().record(token, ZfsRecvStage::Checkpoint);
                        committed_progress = next_prog;
                        pending_ops.clear();
                        pending_bytes = 0;
                        checkpoint_txgs += 1;
                    }
                    ZfsTxOutcome::NotCommitted(err) => return cleanup_on_abort(self, err),
                    ZfsTxOutcome::Uncertain {
                        reason,
                        target_txg,
                        target_slot,
                    } => {
                        return ZfsTxOutcome::Uncertain {
                            reason,
                            target_txg,
                            target_slot,
                        };
                    }
                }
            }
        }

        // Verify EOF before final atomic promotion for standalone substreams so trailing
        // garbage aborts cleanly without committing a promoted dataset or snapshot.
        if require_eof_before_commit && let Err(e) = reader.assert_eof(cx) {
            return cleanup_on_abort(self, e);
        }

        // 4. Atomic final promotion (`stage_recv_end`)!
        let _ = committed_progress;
        match self.commit_recv_end_txg(cx, req, &stage_meta, begin, &snap_name, compound_props) {
            ZfsTxOutcome::Committed {
                value: snap_guid,
                token: tok,
            } => {
                attempt
                    .borrow_mut()
                    .promoted(tok.clone(), &snap_name, snap_guid);
                ZfsTxOutcome::Committed {
                    value: ZfsRecvReport {
                        substreams_received: 1,
                        compound: false,
                        raw: stage_meta.is_raw_encrypted,
                        resumed: is_resuming,
                        final_snapshot: String::from_utf8_lossy(&snap_name).into_owned(),
                        final_snapshot_guid: snap_guid,
                        records_applied,
                        objects_received,
                        blocks_received,
                        stream_bytes_read: reader.bytes_read,
                        checkpoint_txgs: checkpoint_txgs + 1,
                        durable_token: tok.clone(),
                    },
                    token: tok,
                }
            }
            ZfsTxOutcome::NotCommitted(err) => cleanup_on_abort(self, err),
            ZfsTxOutcome::Uncertain {
                reason,
                target_txg,
                target_slot,
            } => ZfsTxOutcome::Uncertain {
                reason,
                target_txg,
                target_slot,
            },
        }
    }

    fn validate_resume_staging(
        &self,
        cx: &Cx,
        target_dataset: &[Vec<u8>],
        begin: &DrrBegin,
        keydata: Option<&StreamCryptoKeydata>,
    ) -> Result<(StagedSubstreamMeta, ChunkProgress)> {
        let mut mos = self.open_read_objects(cx)?;
        let Some(staging) = mos.find_recv_staging_dataset(cx, target_dataset)? else {
            return Err(FfsError::NotFound(
                "resuming receive requires an existing incomplete receive staging dataset".into(),
            ));
        };
        let state = build_resume_state_from_staging(&staging)?;
        if state.toguid != begin.toguid {
            return Err(FfsError::Format(
                "resuming stream toguid disagrees with persisted receive state".into(),
            ));
        }
        if state.fromguid.unwrap_or(0) != begin.fromguid {
            return Err(FfsError::Format(
                "resuming stream fromguid disagrees with persisted receive base".into(),
            ));
        }
        if staging.objectset_kind != u64::from(begin.objset_type) {
            return Err(FfsError::Format(
                "resuming stream objset type disagrees with persisted staging dataset".into(),
            ));
        }
        let (staging_head, staging_ceiling) = mos.object_with_ceiling(cx, staging.head_object)?;
        let staging_entries = dataset_feature_entries(
            cx,
            &mut mos,
            staging.head_object,
            &staging_head,
            &self.mos_features,
        )?;
        let owners = dataset_block_feature_owners(&staging_entries, &self.mos_features)?;
        require_receive_large_blocks(&owners, begin)?;
        let is_raw = begin.features.contains(DMU_BACKUP_FEATURE_RAW);
        if state.rawok != is_raw || is_raw != keydata.is_some() {
            return Err(FfsError::Format(
                "resuming stream raw mode disagrees with persisted receive state".into(),
            ));
        }
        let staging_crypto = resolve_staging_crypto_info(cx, &mut mos, staging.directory_object)?;
        if staging_crypto.is_some() != is_raw {
            return Err(FfsError::Format(
                "resuming stream encryption disagrees with its staging dataset".into(),
            ));
        }
        if let Some(kd) = keydata {
            let crypto = staging_crypto
                .as_ref()
                .ok_or_else(|| corrupt("raw receive staging dataset lacks crypto identity"))?;
            validate_received_crypto_identity(kd, &crypto.record)?;
            let staging_os = read_received_objectset(cx, &mut mos, &staging_head, staging_ceiling)?;
            validate_received_meta_geometry(&kd.meta_dnode, &staging_os.meta)?;
            if state.ivsetguid.unwrap_or(0) != kd.to_ivset_guid {
                return Err(FfsError::Format(
                    "resuming raw stream ivset_guid disagrees with persisted receive state".into(),
                ));
            }
            if begin.fromguid != 0 {
                validate_received_base_ivset(cx, &mut mos, kd, staging.prev_snap_obj)?;
            }
        }
        let (target_dd_obj, target_head_obj) = if staging.is_pct_recv_child {
            let (dd, head, _) = resolve_dataset_ids(cx, &mut mos, target_dataset)?;
            (dd, Some(head))
        } else {
            (staging.directory_object, None)
        };
        let is_raw_encrypted = is_raw;
        let (crypto_version, portable_mac, to_ivset_guid) = if let Some(kd) = keydata {
            (kd.version, kd.portable_mac, Some(kd.to_ivset_guid))
        } else {
            (1, [0_u8; 32], state.ivsetguid)
        };
        // A full receive is hidden from ordinary dataset queries until promotion;
        // its empty property catalog inherits from the visible parent. The
        // private incremental child inherits the existing target's policy.
        let policy_parent = if staging.is_pct_recv_child {
            target_dataset
        } else {
            &target_dataset[..target_dataset.len() - 1]
        };
        let compression = effective_compression_for_new_dataset(
            cx,
            &mut mos,
            policy_parent,
            &[],
            &self.mos_features,
        )?;
        Ok((
            StagedSubstreamMeta {
                stage_dd_obj: staging.directory_object,
                stage_head_obj: staging.head_object,
                is_pct_recv_child: staging.is_pct_recv_child,
                target_dd_obj,
                target_head_obj,
                prev_snap_obj: staging.prev_snap_obj,
                prev_snap_txg: staging.prev_snap_txg,
                is_raw_encrypted,
                raw_meta_dnode: keydata.map(|kd| kd.meta_dnode),
                crypto_version,
                portable_mac,
                to_ivset_guid,
                compression,
            },
            ChunkProgress {
                object: state.object,
                offset: state.offset,
                bytes: state.bytes,
            },
        ))
    }

    #[allow(clippy::too_many_lines)]
    fn commit_recv_begin_txg(
        &mut self,
        cx: &Cx,
        req: &ZfsRecvRequest,
        begin: &DrrBegin,
        keydata: Option<&StreamCryptoKeydata>,
    ) -> ZfsTxOutcome<StagedSubstreamMeta> {
        let target_dataset = req.target_dataset.clone();
        let force = req.force;
        let begin_cloned = begin.clone();
        let kd_cloned = keydata.cloned();
        let order = self.order;
        let empty_bpobj_id = self.empty_bpobj_id;

        self.execute_staged_txg_typed(
            cx,
            "recv_begin",
            move |mos, mos_dirty_dnodes, features, alloc, new_txg, staged_writes| {
                if mos.find_recv_staging_dataset(cx, &target_dataset)?.is_some() {
                    return Err(FfsError::Exists);
                }
                let mos_meta = mos.meta_dnode().clone();
                let mos_ceiling = mos.root_birth_txg();
                let existing_target = resolve_dataset_ids(cx, mos, &target_dataset).ok();

                let mut resume_zap: Vec<RawZapEntry> = vec![
                    zap_u64_entry(DS_FIELD_RESUME_TOGUID, begin_cloned.toguid),
                    zap_text_entry(DS_FIELD_RESUME_TONAME, &begin_cloned.toname),
                    zap_u64_entry(DS_FIELD_RESUME_OBJECT, 0),
                    zap_u64_entry(DS_FIELD_RESUME_OFFSET, 0),
                    zap_u64_entry(DS_FIELD_RESUME_BYTES, 0),
                ];
                if begin_cloned.fromguid != 0 {
                    resume_zap.push(zap_u64_entry(
                        DS_FIELD_RESUME_FROMGUID,
                        begin_cloned.fromguid,
                    ));
                }
                if begin_cloned.features.contains(DMU_BACKUP_FEATURE_COMPRESSED) {
                    resume_zap.push(zap_u64_entry(DS_FIELD_RESUME_COMPRESSOK, 1));
                }
                if begin_cloned.features.contains(DMU_BACKUP_FEATURE_EMBED_DATA) {
                    resume_zap.push(zap_u64_entry(DS_FIELD_RESUME_EMBEDOK, 1));
                }
                if begin_cloned
                    .features
                    .contains(DMU_BACKUP_FEATURE_LARGE_BLOCKS)
                {
                    resume_zap.push(zap_u64_entry(DS_FIELD_RESUME_LARGEBLOCKOK, 1));
                }
                if let Some(ref kd) = kd_cloned {
                    resume_zap.push(zap_u64_entry(DS_FIELD_RESUME_RAWOK, 1));
                    if kd.to_ivset_guid != 0 {
                        resume_zap.push(zap_u64_entry(DS_FIELD_RESUME_IVSET_GUID, kd.to_ivset_guid));
                        resume_zap.push(zap_u64_entry(DSL_DATASET_IVSET_GUID, kd.to_ivset_guid));
                    }
                }

                if begin_cloned.fromguid == 0 {
                    // Full receive into brand-new target dataset.
                    if existing_target.is_some() {
                        return Err(FfsError::Exists);
                    }
                    let parent_path = &target_dataset[..target_dataset.len() - 1];
                    let leaf_name = target_dataset.last().expect("nonempty");
                    let compression = effective_compression_for_new_dataset(
                        cx, mos, parent_path, &[], features,
                    )?;
                    let (parent_dd_obj, _, pool_guid) = resolve_dataset_ids(cx, mos, parent_path)?;
                    let (parent_dd_dn, _) = read_staged_or_committed_dnode(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        parent_dd_obj,
                        order,
                    )?;
                    let parent_cz_obj = order
                        .u64(parent_dd_dn.bonus(), 32)
                        .map_err(|e| parse_err(&e))?;
                    let (p_cz_dn, p_cz_ceil) = mos.object_with_ceiling(cx, parent_cz_obj)?;
                    let mut p_cz_entries = mos.zap_values(cx, parent_cz_obj)?;
                    if p_cz_entries.iter().any(|e| e.name.as_slice() == leaf_name.as_slice()) {
                        return Err(FfsError::Exists);
                    }

                    let pool_origin = lookup_pool_origin_snapshot(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        order,
                    )?;
                    let origin_snap_obj = pool_origin.map_or(0, |(_, _, s)| s);

                    let dd_obj =
                        allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
                    let head_obj =
                        allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
                    let child_zap =
                        allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
                    let props_zap =
                        allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
                    let snapmap_obj =
                        allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
                    let deadlist_obj = allocate_fresh_deadlist(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        features,
                        alloc,
                        empty_bpobj_id,
                        &BTreeSet::new(),
                        &[],
                        order,
                        new_txg,
                        staged_writes,
                    )?;

                    let initial_props: Vec<RawZapEntry> =
                        kd_cloned.as_ref().map_or_else(Vec::new, |kd| {
                            let mut enc_props = vec![
                                zap_u64_entry(b"keyformat", kd.keyformat as u64),
                                zap_u64_entry(b"pbkdf2salt", kd.pbkdf2_salt),
                                zap_u64_entry(b"pbkdf2iters", kd.pbkdf2_iters),
                                zap_text_entry(b"keylocation", b"prompt"),
                            ];
                            enc_props.sort_by(|a, b| a.name.cmp(&b.name));
                            enc_props
                        });

                    for (obj_id, ot, norm, entries) in [
                        (child_zap, DMU_OT_DSL_DIR_CHILD_MAP, 0_u64, &[][..]),
                        (props_zap, DMU_OT_DSL_PROPS, 0_u64, initial_props.as_slice()),
                        (snapmap_obj, DMU_OT_DSL_DS_SNAP_MAP, 2_u64, &[][..]),
                    ] {
                        write_zap_dnode_in_mos(
                            cx,
                            mos,
                            &mos_meta,
                            mos_ceiling,
                            mos_dirty_dnodes,
                            alloc,
                            obj_id,
                            None,
                            ot,
                            0,
                            Vec::new(),
                            entries,
                            norm,
                            false,
                            order,
                            new_txg,
                            staged_writes,
                        )?;
                    }

                    // If raw encrypted, create `dsl_crypto_key` MOS ZAP object verbatim!
                    let mut dd_extra_zap = Vec::new();
                    if let Some(ref kd) = kd_cloned {
                        let ck_obj = allocate_object_id(
                            cx,
                            mos,
                            &mos_meta,
                            mos_ceiling,
                            mos_dirty_dnodes,
                            1,
                        )?;
                        let mut enc_mk = [0_u8; 32];
                        let mk_len = kd.wrapped_master_key.len().min(32);
                        enc_mk[..mk_len].copy_from_slice(&kd.wrapped_master_key[..mk_len]);
                        let ck_rec = DslCryptoKeyRecord {
                            suite: kd.suite,
                            version: kd.version,
                            guid: kd.guid,
                            root_ddobj: dd_obj,
                            refcount: 1,
                            keyformat: kd.keyformat,
                            pbkdf2_salt: kd.pbkdf2_salt,
                            pbkdf2_iters: kd.pbkdf2_iters,
                            iv: kd.iv,
                            mac: kd.mac,
                            encrypted_master_key: enc_mk,
                            encrypted_hmac_key: kd.wrapped_hmac_key,
                        };
                        let ck_entries = encode_dsl_crypto_key_zap(&ck_rec);
                        write_zap_dnode_in_mos(
                            cx,
                            mos,
                            &mos_meta,
                            mos_ceiling,
                            mos_dirty_dnodes,
                            alloc,
                            ck_obj,
                            None,
                            DMU_OTN_ZAP_METADATA,
                            0,
                            Vec::new(),
                            &ck_entries,
                            0,
                            false,
                            order,
                            new_txg,
                            staged_writes,
                        )?;
                        features.increment_read("com.datto:encryption", new_txg)?;
                        dd_extra_zap.push(zap_u64_entry(DSL_DIR_CRYPTO_KEY_OBJ, ck_obj));
                    }

                    // Build initial empty ObjectSet (`kind = 2` ZPL or `3` ZVOL).
                    let raw_meta = kd_cloned.as_ref().map(|kd| kd.meta_dnode);
                    let empty_meta = Dnode::from_spec(DnodeSpec {
                        object_type: DMU_OT_DNODE,
                        bonus_type: 0,
                        checksum_type: raw_meta.map_or(0, |mdn| mdn.checksum),
                        compress_type: raw_meta.map_or(0, |mdn| mdn.compression),
                        flags: DNODE_FLAG_USED_BYTES,
                        order,
                        levels: raw_meta.map_or(1, |mdn| mdn.levels),
                        indirect_shift: raw_meta.map_or(17, |mdn| mdn.indirect_shift),
                        data_bytes: DNODE_BLOCK_BYTES,
                        max_block: raw_meta.map_or(0, |mdn| mdn.max_block),
                        used_bytes: 0,
                        slots: 1,
                        pointers: vec![BlockPointer::hole_pointer(); 3],
                        bonus: Vec::new(),
                        spill: None,
                    })
                    .map_err(|e| parse_err(&e))?;
                    let os_phys_len = if kd_cloned.is_some() { 4096 } else { 2048 };
                    let mut os = ObjectSet::new(
                        u64::from(begin_cloned.objset_type),
                        0,
                        empty_meta,
                        ZilHeader::empty(),
                        os_phys_len,
                    )
                    .map_err(|e| parse_err(&e))?;
                    let os_bp = if let Some(ref kd) = kd_cloned {
                        write_dataset_objset_block_raw_protected(
                            &mut os,
                            alloc,
                            7,
                            order,
                            new_txg,
                            kd.portable_mac,
                            [0_u8; 32],
                            staged_writes,
                        )?
                    } else {
                        write_dataset_objset_block(&mut os, alloc, 7, order, new_txg, compression, None, staged_writes)?
                    };
                    let os_space = SpaceDelta::from_bp(&os_bp)?;

                    // Stage `head_obj` (zapified with `DS_FIELD_RESUME_*` + `DS_FLAG_INCONSISTENT`).
                    features.increment_read("com.delphix:extensible_dataset", new_txg)?;
                    let head_guid = derive_unique_guid(pool_guid, new_txg, head_obj, 1);
                    let head_fsid = derive_fsid_guid(head_guid);
                    let mut head_bonus = vec![0_u8; 320];
                    head_bonus[0..8].copy_from_slice(&order.encode(dd_obj));
                    head_bonus[8..16].copy_from_slice(&order.encode(origin_snap_obj));
                    head_bonus[16..24].copy_from_slice(&order.encode(u64::from(origin_snap_obj != 0)));
                    head_bonus[32..40].copy_from_slice(&order.encode(snapmap_obj));
                    head_bonus[48..56].copy_from_slice(&order.encode(begin_cloned.creation_time));
                    head_bonus[56..64].copy_from_slice(&order.encode(new_txg));
                    head_bonus[64..72].copy_from_slice(&order.encode(deadlist_obj));
                    head_bonus[72..80].copy_from_slice(&order.encode(os_space.dsize));
                    head_bonus[80..88].copy_from_slice(&order.encode(os_space.comp));
                    head_bonus[88..96].copy_from_slice(&order.encode(os_space.uncomp));
                    head_bonus[96..104].copy_from_slice(&order.encode(os_space.dsize));
                    head_bonus[104..112].copy_from_slice(&order.encode(head_fsid));
                    head_bonus[112..120].copy_from_slice(&order.encode(head_guid));
                    head_bonus[120..128]
                        .copy_from_slice(&order.encode(DS_FLAG_INCONSISTENT | DS_FLAG_UNIQUE_ACCURATE));
                    head_bonus[128..256].copy_from_slice(&os_bp.encode(order));
                    write_zap_dnode_in_mos(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        alloc,
                        head_obj,
                        None,
                        DMU_OTN_ZAP_METADATA,
                        DMU_OT_DSL_DATASET,
                        head_bonus,
                        &resume_zap,
                        0,
                        false,
                        order,
                        new_txg,
                        staged_writes,
                    )?;

                    // Stage `dd_obj`.
                    let mut dd_bonus = vec![0_u8; 256];
                    dd_bonus[0..8].copy_from_slice(&order.encode(begin_cloned.creation_time));
                    dd_bonus[8..16].copy_from_slice(&order.encode(head_obj));
                    dd_bonus[16..24].copy_from_slice(&order.encode(parent_dd_obj));
                    dd_bonus[24..32].copy_from_slice(&order.encode(origin_snap_obj));
                    dd_bonus[32..40].copy_from_slice(&order.encode(child_zap));
                    dd_bonus[40..48].copy_from_slice(&order.encode(os_space.dsize));
                    dd_bonus[48..56].copy_from_slice(&order.encode(os_space.comp));
                    dd_bonus[56..64].copy_from_slice(&order.encode(os_space.uncomp));
                    dd_bonus[80..88].copy_from_slice(&order.encode(props_zap));
                    dd_bonus[104..112].copy_from_slice(&order.encode(os_space.dsize)); // DD_USED_HEAD
                    put_new_dsl_dir_in_mos(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        features,
                        alloc,
                        dd_obj,
                        dd_bonus,
                        &dd_extra_zap,
                        order,
                        new_txg,
                        staged_writes,
                    )?;

                    if let Some((origin_dd_obj, _, o_snap)) = pool_origin {
                        link_dataset_to_origin_snapshot(
                            cx,
                            mos,
                            &mos_meta,
                            mos_ceiling,
                            mos_dirty_dnodes,
                            alloc,
                            origin_dd_obj,
                            o_snap,
                            head_obj,
                            order,
                            new_txg,
                            staged_writes,
                        )?;
                    }

                    // Link into `parent_dd.dd_child_dir_zapobj` and propagate space.
                    p_cz_entries.push(zap_u64_entry(leaf_name, dd_obj));
                    write_zap_dnode_in_mos(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        alloc,
                        parent_cz_obj,
                        Some((&p_cz_dn, p_cz_ceil)),
                        p_cz_dn.object_type(),
                        p_cz_dn.bonus_type(),
                        Vec::new(),
                        &p_cz_entries,
                        0,
                        false,
                        order,
                        new_txg,
                        staged_writes,
                    )?;
                    propagate_dsl_dir_space_delta(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        parent_dd_obj,
                        0,
                        0,
                        i128::from(os_space.dsize),
                        0,
                        0,
                        i128::from(os_space.comp),
                        i128::from(os_space.uncomp),
                        order,
                    )?;
                    bump_filesystem_limits_counter_if_present(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        alloc,
                        parent_dd_obj,
                        b"com.joyent:filesystem_count",
                        1,
                        order,
                        new_txg,
                        staged_writes,
                    )?;

                    let meta = StagedSubstreamMeta {
                        stage_dd_obj: dd_obj,
                        stage_head_obj: head_obj,
                        is_pct_recv_child: false,
                        target_dd_obj: dd_obj,
                        target_head_obj: None,
                        prev_snap_obj: origin_snap_obj,
                        prev_snap_txg: u64::from(origin_snap_obj != 0),
                        is_raw_encrypted: kd_cloned.is_some(),
                        raw_meta_dnode: kd_cloned.as_ref().map(|kd| kd.meta_dnode),
                        crypto_version: kd_cloned.as_ref().map_or(1, |k| k.version),
                        portable_mac: kd_cloned.as_ref().map_or([0_u8; 32], |k| k.portable_mac),
                        to_ivset_guid: kd_cloned.as_ref().map(|k| k.to_ivset_guid),
                        compression,
                    };
                    Ok((meta, head_obj))
                } else {
                    // Incremental receive into existing `target_dataset`: stage inside hidden `%recv` child!
                    let Some((target_dd_obj, target_head_obj, pool_guid)) = existing_target else {
                        return Err(FfsError::NotFound(
                            "incremental receive requires an existing target dataset".into(),
                        ));
                    };
                    let compression = effective_compression_for_new_dataset(
                        cx, mos, &target_dataset, &[], features,
                    )?;
                    let (target_head_dn, _) = read_staged_or_committed_dnode(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        target_head_obj,
                        order,
                    )?;
                    let prev_snap_obj = order
                        .u64(target_head_dn.bonus(), 8)
                        .map_err(|e| parse_err(&e))?;
                    let prev_snap_txg = order
                        .u64(target_head_dn.bonus(), 16)
                        .map_err(|e| parse_err(&e))?;
                    let target_unique = order
                        .u64(target_head_dn.bonus(), 96)
                        .map_err(|e| parse_err(&e))?;
                    if prev_snap_obj == 0 {
                        return Err(FfsError::Format(
                            "incremental receive target has no base snapshot".into(),
                        ));
                    }
                    let (prev_snap_dn, prev_snap_ceiling) = read_staged_or_committed_dnode(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        prev_snap_obj,
                        order,
                    )?;
                    let prev_snap_guid = order
                        .u64(prev_snap_dn.bonus(), 112)
                        .map_err(|e| parse_err(&e))?;
                    if prev_snap_guid != begin_cloned.fromguid {
                        return Err(FfsError::Format(format!(
                            "incremental stream fromguid 0x{:x} does not match target base snapshot guid 0x{:x}",
                            begin_cloned.fromguid, prev_snap_guid
                        )));
                    }
                    if target_unique > 0 && !force {
                        return Err(reject_busy(
                            "target dataset has been modified since base snapshot (pass --force to roll back)",
                        ));
                    }
                    dataset_feature_entries(cx, mos, target_head_obj, &target_head_dn, features)?;
                    let previous_entries =
                        dataset_feature_entries(cx, mos, prev_snap_obj, &prev_snap_dn, features)?;
                    let inherited_owners = dataset_block_feature_owners(&previous_entries, features)?;
                    require_receive_large_blocks(&inherited_owners, &begin_cloned)?;
                    // Native receive creates a clone of the base snapshot. Its
                    // shared blocks still require a distinct dataset owner.
                    activate_dataset_block_features(
                        &mut resume_zap,
                        &inherited_owners,
                        features,
                        new_txg,
                    )?;
                    let target_crypto = mos.dataset_crypto_info(cx, &target_dataset)?;
                    if let Some(ref kd) = kd_cloned {
                        let Some(ref tc) = target_crypto else {
                            return Err(FfsError::Format(
                                "raw encrypted incremental cannot target unencrypted dataset".into(),
                            ));
                        };
                        validate_received_crypto_identity(kd, &tc.record)?;
                        validate_received_base_ivset(cx, mos, kd, prev_snap_obj)?;
                        let base_os = read_received_objectset(cx, mos, &prev_snap_dn, prev_snap_ceiling)?;
                        validate_received_meta_geometry(&kd.meta_dnode, &base_os.meta)?;
                    } else if target_crypto.is_some() {
                        return Err(unsupported(
                            "non-raw incremental receive into an encrypted dataset requires re-encryption",
                        ));
                    }

                    let (target_dd_dn, _) = read_staged_or_committed_dnode(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        target_dd_obj,
                        order,
                    )?;
                    let target_cz_obj = order
                        .u64(target_dd_dn.bonus(), 32)
                        .map_err(|e| parse_err(&e))?;
                    let (t_cz_dn, t_cz_ceil) = mos.object_with_ceiling(cx, target_cz_obj)?;
                    let mut t_cz_entries = mos.zap_values(cx, target_cz_obj)?;
                    if t_cz_entries.iter().any(|e| e.name == b"%recv") {
                        return Err(FfsError::Exists);
                    }

                    let recv_dd_obj =
                        allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
                    let recv_head_obj =
                        allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
                    let recv_cz_obj =
                        allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
                    let recv_props_obj =
                        allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
                    let recv_snapmap_obj =
                        allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
                    let recv_deadlist_obj = allocate_fresh_deadlist(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        features,
                        alloc,
                        empty_bpobj_id,
                        &BTreeSet::new(),
                        &[],
                        order,
                        new_txg,
                        staged_writes,
                    )?;
                    for (obj_id, ot, norm) in [
                        (recv_cz_obj, DMU_OT_DSL_DIR_CHILD_MAP, 0_u64),
                        (recv_props_obj, DMU_OT_DSL_PROPS, 0_u64),
                        (recv_snapmap_obj, DMU_OT_DSL_DS_SNAP_MAP, 2_u64),
                    ] {
                        write_zap_dnode_in_mos(
                            cx,
                            mos,
                            &mos_meta,
                            mos_ceiling,
                            mos_dirty_dnodes,
                            alloc,
                            obj_id,
                            None,
                            ot,
                            0,
                            Vec::new(),
                            &[],
                            norm,
                            false,
                            order,
                            new_txg,
                            staged_writes,
                        )?;
                    }

                    let mut dd_extra_zap = Vec::new();
                    if let Some(ref tc) = target_crypto {
                        adjust_dsl_crypto_key_refcount(
                            cx,
                            mos,
                            &mos_meta,
                            mos_ceiling,
                            mos_dirty_dnodes,
                            alloc,
                            tc.crypto_key_obj,
                            1,
                            order,
                            new_txg,
                            staged_writes,
                        )?;
                        dd_extra_zap.push(zap_u64_entry(DSL_DIR_CRYPTO_KEY_OBJ, tc.crypto_key_obj));
                    }

                    features.increment_read("com.delphix:extensible_dataset", new_txg)?;
                    let prev_ref = order
                        .u64(prev_snap_dn.bonus(), 72)
                        .map_err(|e| parse_err(&e))?;
                    let prev_comp = order
                        .u64(prev_snap_dn.bonus(), 80)
                        .map_err(|e| parse_err(&e))?;
                    let prev_uncomp = order
                        .u64(prev_snap_dn.bonus(), 88)
                        .map_err(|e| parse_err(&e))?;
                    let prev_flags = order
                        .u64(prev_snap_dn.bonus(), 120)
                        .map_err(|e| parse_err(&e))?;
                    let recv_guid = derive_unique_guid(pool_guid, new_txg, recv_head_obj, 2);
                    let recv_fsid = derive_fsid_guid(recv_guid);
                    let mut recv_head_bonus = vec![0_u8; 320];
                    recv_head_bonus[0..8].copy_from_slice(&order.encode(recv_dd_obj));
                    recv_head_bonus[8..16].copy_from_slice(&order.encode(prev_snap_obj));
                    recv_head_bonus[16..24].copy_from_slice(&order.encode(prev_snap_txg));
                    recv_head_bonus[32..40].copy_from_slice(&order.encode(recv_snapmap_obj));
                    recv_head_bonus[48..56]
                        .copy_from_slice(&order.encode(begin_cloned.creation_time));
                    recv_head_bonus[56..64].copy_from_slice(&order.encode(new_txg));
                    recv_head_bonus[64..72].copy_from_slice(&order.encode(recv_deadlist_obj));
                    recv_head_bonus[72..80].copy_from_slice(&order.encode(prev_ref));
                    recv_head_bonus[80..88].copy_from_slice(&order.encode(prev_comp));
                    recv_head_bonus[88..96].copy_from_slice(&order.encode(prev_uncomp));
                    recv_head_bonus[96..104].copy_from_slice(&order.encode(0));
                    recv_head_bonus[104..112].copy_from_slice(&order.encode(recv_fsid));
                    recv_head_bonus[112..120].copy_from_slice(&order.encode(recv_guid));
                    recv_head_bonus[120..128].copy_from_slice(&order.encode(
                        (prev_flags & 0x1_0006) | DS_FLAG_INCONSISTENT | DS_FLAG_UNIQUE_ACCURATE,
                    ));
                    recv_head_bonus[128..256].copy_from_slice(&prev_snap_dn.bonus()[128..256]);
                    write_zap_dnode_in_mos(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        alloc,
                        recv_head_obj,
                        None,
                        DMU_OTN_ZAP_METADATA,
                        DMU_OT_DSL_DATASET,
                        recv_head_bonus,
                        &resume_zap,
                        0,
                        false,
                        order,
                        new_txg,
                        staged_writes,
                    )?;

                    let mut recv_dd_bonus = vec![0_u8; 256];
                    recv_dd_bonus[0..8].copy_from_slice(&order.encode(begin_cloned.creation_time));
                    recv_dd_bonus[8..16].copy_from_slice(&order.encode(recv_head_obj));
                    recv_dd_bonus[16..24].copy_from_slice(&order.encode(target_dd_obj));
                    recv_dd_bonus[24..32].copy_from_slice(&order.encode(prev_snap_obj));
                    recv_dd_bonus[32..40].copy_from_slice(&order.encode(recv_cz_obj));
                    recv_dd_bonus[80..88].copy_from_slice(&order.encode(recv_props_obj));
                    put_new_dsl_dir_in_mos(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        features,
                        alloc,
                        recv_dd_obj,
                        recv_dd_bonus,
                        &dd_extra_zap,
                        order,
                        new_txg,
                        staged_writes,
                    )?;
                    link_dataset_to_origin_snapshot(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        alloc,
                        target_dd_obj,
                        prev_snap_obj,
                        recv_head_obj,
                        order,
                        new_txg,
                        staged_writes,
                    )?;

                    t_cz_entries.push(zap_u64_entry(b"%recv", recv_dd_obj));
                    write_zap_dnode_in_mos(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        alloc,
                        target_cz_obj,
                        Some((&t_cz_dn, t_cz_ceil)),
                        t_cz_dn.object_type(),
                        t_cz_dn.bonus_type(),
                        Vec::new(),
                        &t_cz_entries,
                        0,
                        false,
                        order,
                        new_txg,
                        staged_writes,
                    )?;

                    let meta = StagedSubstreamMeta {
                        stage_dd_obj: recv_dd_obj,
                        stage_head_obj: recv_head_obj,
                        is_pct_recv_child: true,
                        target_dd_obj,
                        target_head_obj: Some(target_head_obj),
                        prev_snap_obj,
                        prev_snap_txg,
                        is_raw_encrypted: kd_cloned.is_some(),
                        raw_meta_dnode: kd_cloned.as_ref().map(|kd| kd.meta_dnode),
                        crypto_version: kd_cloned.as_ref().map_or(1, |k| k.version),
                        portable_mac: kd_cloned.as_ref().map_or([0_u8; 32], |k| k.portable_mac),
                        to_ivset_guid: kd_cloned.as_ref().map(|k| k.to_ivset_guid),
                        compression,
                    };
                    Ok((meta, recv_head_obj))
                }
            },
        )
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    fn commit_recv_chunk_txg(
        &mut self,
        cx: &Cx,
        stage: &StagedSubstreamMeta,
        stream_order: Endian,
        ops: &[RecvOp],
        known_object_ranges: &BTreeMap<u64, ObjectRangeMeta>,
        progress: &ChunkProgress,
        final_chunk: bool,
    ) -> ZfsTxOutcome<()> {
        let stage_cloned = stage.clone();
        let ops_owned = ops.to_vec();
        let ranges_seed = known_object_ranges.clone();
        let prog_obj = progress.object;
        let prog_off = progress.offset;
        let prog_bytes = progress.bytes;
        let order = self.order;
        let empty_bpobj_id = self.empty_bpobj_id;

        self.execute_staged_txg_typed(
            cx,
            "recv_chunk",
            move |mos, mos_dirty_dnodes, features, alloc, new_txg, staged_writes| {
                let mos_meta = mos.meta_dnode().clone();
                let mos_ceiling = mos.root_birth_txg();
                let (head_dn, head_ceil) = read_staged_or_committed_dnode(
                    cx,
                    mos,
                    &mos_meta,
                    mos_ceiling,
                    mos_dirty_dnodes,
                    stage_cloned.stage_head_obj,
                    order,
                )?;
                let old_os_bp = BlockPointer::parse(&head_dn.bonus()[128..256], head_dn.order())
                    .map_err(|e| parse_err(&e))?;
                let (os_raw, os_order, _) =
                    mos.read_dataset_objset_block_raw(cx, &old_os_bp, head_ceil, None, true)?;
                let mut os = ObjectSet::parse(&os_raw, os_order).map_err(|e| parse_err(&e))?;
                let old_meta = os.meta.clone();
                let old_meta_ceil = old_os_bp.birth();
                let raw_meta = stage_cloned.raw_meta_dnode;
                if let Some(meta) = raw_meta {
                    validate_received_meta_geometry(&meta, &old_meta)?;
                }

                let stage_crypto =
                    resolve_staging_crypto_info(cx, mos, stage_cloned.stage_dd_obj)?;
                let crypto_ctx = stage_crypto.map(|info| {
                    std::sync::Arc::new(crate::reader::dmu::DatasetCryptoContext {
                        info,
                        raw_scrub_only: stage_cloned.is_raw_encrypted,
                    })
                });
                let mut os_view = mos.open_objectset_view_with_crypto(
                    old_meta.clone(),
                    old_meta_ceil,
                    mos.txg,
                    crypto_ctx,
                );

                let raw_enc_ver = stage_cloned
                    .is_raw_encrypted
                    .then_some(stage_cloned.crypto_version);

                // Track per-object pending mutations in this chunk.
                struct ObjDraft {
                    object_type: u8,
                    bonus_type: u8,
                    checksum_type: u8,
                    compress_type: u8,
                    data_bytes: usize,
                    indirect_shift: u8,
                    nlevels: u8,
                    slots: usize,
                    nblkptr: usize,
                    max_block: u64,
                    bonus: Vec<u8>,
                    raw_bonus: Option<Vec<u8>>,
                    spill: Option<BlockPointer>,
                    existing: Option<Dnode>,
                    leaves: BTreeMap<u64, StagedLeafUpdate>,
                }

                let mut meta_dirty_blocks: BTreeMap<u64, Vec<u8>> = BTreeMap::new();
                let mut object_ranges: BTreeMap<u64, ObjectRangeMeta> = ranges_seed;
                let mut drafts: BTreeMap<u64, ObjDraft> = BTreeMap::new();
                let mut retired_bps: Vec<BlockPointer> = Vec::new();
                let mut born_space = SpaceDelta::default();
                let mut feature_usage = DatasetFeatureUsage::default();
                let mut max_meta_block = old_meta.max_block();

                let load_draft = |obj_id: u64,
                                  drafts: &mut BTreeMap<u64, ObjDraft>,
                                  meta_dirty: &mut BTreeMap<u64, Vec<u8>>,
                                  os_view: &mut Objects|
                 -> Result<()> {
                    if drafts.contains_key(&obj_id) {
                        return Ok(());
                    }
                    let dn = match read_staged_or_committed_dnode(
                        cx,
                        os_view,
                        &old_meta,
                        old_meta_ceil,
                        meta_dirty,
                        obj_id,
                        order,
                    ) {
                        Ok((dn, _)) => dn,
                        Err(FfsError::NotFound(_)) => {
                            return Err(corrupt(format!(
                                "receive stream referenced unknown object {obj_id}"
                            )));
                        }
                        Err(error) => return Err(error),
                    };
                    let preserved_raw_bonus = if stage_cloned.is_raw_encrypted {
                        let meta_bid = obj_id / 32;
                        ensure_dnode_table_block_loaded(
                            cx,
                            os_view,
                            &old_meta,
                            old_meta_ceil,
                            meta_bid,
                            meta_dirty,
                        )?;
                        let blk = meta_dirty
                            .get(&meta_bid)
                            .ok_or_else(|| corrupt("missing raw dnode table block"))?;
                        extract_raw_dnode_bonus(blk, (obj_id % 32) as usize, order)
                            .map_err(|e| parse_err(&e))?
                            .map(|(_, bytes)| bytes)
                    } else {
                        None
                    };
                    drafts.insert(
                        obj_id,
                        ObjDraft {
                            object_type: dn.object_type(),
                            bonus_type: dn.bonus_type(),
                            checksum_type: dn.checksum_type(),
                            compress_type: dn.compress_type(),
                            data_bytes: dn.data_bytes(),
                            indirect_shift: dn.indirect_shift(),
                            nlevels: dn.levels(),
                            slots: dn.slots(),
                            nblkptr: dn.pointers().len(),
                            max_block: dn.max_block(),
                            bonus: dn.bonus().to_vec(),
                            raw_bonus: preserved_raw_bonus,
                            spill: dn.spill().cloned(),
                            existing: Some(dn),
                            leaves: BTreeMap::new(),
                        },
                    );
                    Ok(())
                };

                for op in &ops_owned {
                    checkpoint(cx)?;
                    match op {
                        RecvOp::ObjectRange(r) => {
                            let start_bid = r.firstobj / 32;
                            let blocks = r.numslots / 32;
                            for b in 0..blocks {
                                object_ranges.insert(
                                    start_bid + b,
                                    ObjectRangeMeta {
                                        salt: r.salt,
                                        iv: r.iv,
                                        mac: r.mac,
                                        flags: r.flags,
                                    },
                                );
                            }
                        }
                        RecvOp::Object { rec, bonus } => {
                            let existing = match read_staged_or_committed_dnode(
                                cx,
                                &mut os_view,
                                &old_meta,
                                old_meta_ceil,
                                &meta_dirty_blocks,
                                rec.object,
                                order,
                            ) {
                                Ok((dn, _)) => Some(dn),
                                Err(FfsError::NotFound(_)) => None,
                                Err(error) => return Err(error),
                            };
                            let slots = usize::from(rec.dn_slots.max(1));
                            let ind_shift = if (10..=17).contains(&rec.indblkshift) {
                                rec.indblkshift
                            } else {
                                17
                            };
                            let nblkptr = usize::from(rec.nblkptr.clamp(1, 3));
                            let bonuslen = usize::try_from(rec.bonuslen).unwrap_or(0);
                            let raw_bonuslen = usize::try_from(rec.raw_bonuslen).unwrap_or(0);
                            let plain_bonus = bonus
                                .get(..bonuslen.min(bonus.len()))
                                .unwrap_or(bonus)
                                .to_vec();
                            let raw_bonus = if stage_cloned.is_raw_encrypted && raw_bonuslen > 0 {
                                Some(
                                    bonus
                                        .get(..raw_bonuslen.min(bonus.len()))
                                        .unwrap_or(bonus)
                                        .to_vec(),
                                )
                            } else {
                                None
                            };
                            let spill = if rec.flags & DRR_OBJECT_SPILL != 0 {
                                existing.as_ref().and_then(|d| d.spill().cloned())
                            } else {
                                if let Some(old_spill) = existing.as_ref().and_then(Dnode::spill) {
                                    retired_bps.push(old_spill.clone());
                                }
                                None
                            };
                            let prev_max = existing.as_ref().map_or(0, Dnode::max_block);
                            drafts.insert(
                                rec.object,
                                ObjDraft {
                                    object_type: u8::try_from(rec.object_type)
                                        .map_err(|_| corrupt("DRR_OBJECT type overflow"))?,
                                    bonus_type: u8::try_from(rec.bonus_type)
                                        .map_err(|_| corrupt("DRR_OBJECT bonus_type overflow"))?,
                                    checksum_type: rec.checksumtype,
                                    compress_type: rec.compress,
                                    data_bytes: usize::try_from(rec.blksz)
                                        .map_err(|_| corrupt("DRR_OBJECT blksz overflow"))?,
                                    indirect_shift: ind_shift,
                                    nlevels: rec.nlevels.clamp(1, 7),
                                    slots,
                                    nblkptr,
                                    max_block: prev_max.max(rec.maxblkid),
                                    bonus: plain_bonus,
                                    raw_bonus,
                                    spill,
                                    existing,
                                    leaves: BTreeMap::new(),
                                },
                            );
                        }
                        RecvOp::FreeObjects(f) => {
                            let end = f
                                .firstobj
                                .checked_add(f.numobjs)
                                .ok_or_else(|| corrupt("DRR_FREEOBJECTS overflow"))?;
                            for obj_id in f.firstobj..end {
                                drafts.remove(&obj_id);
                                let (dn, dn_ceil) = match read_staged_or_committed_dnode(
                                    cx,
                                    &mut os_view,
                                    &old_meta,
                                    old_meta_ceil,
                                    &meta_dirty_blocks,
                                    obj_id,
                                    order,
                                ) {
                                    Ok(existing) => existing,
                                    Err(FfsError::NotFound(_)) => continue,
                                    Err(error) => return Err(error),
                                };
                                collect_non_hole_bps_from(
                                    cx,
                                    &mut os_view,
                                    &dn,
                                    dn_ceil,
                                    0,
                                    true,
                                    &mut retired_bps,
                                )?;
                                if let Some(sbp) = dn.spill() {
                                    retired_bps.push(sbp.clone());
                                }
                                remove_dnode_from_table(
                                    cx,
                                    &mut os_view,
                                    &old_meta,
                                    old_meta_ceil,
                                    &mut meta_dirty_blocks,
                                    obj_id,
                                    order,
                                )?;
                            }
                        }
                        RecvOp::Write { rec, payload } => {
                            load_draft(
                                rec.object,
                                &mut drafts,
                                &mut meta_dirty_blocks,
                                &mut os_view,
                            )?;
                            let d = drafts.get_mut(&rec.object).expect("loaded");
                            // Incremental and resumed streams may omit OBJECT;
                            // admission must use the actual preserved dnode too.
                            validate_received_geometry(rec.offset, rec.logical_size, d.data_bytes)?;
                            if rec.object_type != u32::from(d.object_type) {
                                return Err(corrupt("DRR_WRITE type disagrees with its dnode"));
                            }
                            if !stage_cloned.is_raw_encrypted {
                                validate_received_plain_order(d.object_type, stream_order, order)?;
                            }
                            let blksz = d.data_bytes as u64;
                            let bid = rec.offset / blksz;
                            d.max_block = d.max_block.max(bid);
                            let block_order = if rec.flags & DRR_RAW_BYTESWAP != 0 {
                                match stream_order {
                                    Endian::Little => Endian::Big,
                                    Endian::Big => Endian::Little,
                                }
                            } else if stage_cloned.is_raw_encrypted {
                                stream_order
                            } else {
                                order
                            };
                            let eff_cksum = if matches!(rec.checksumtype, 6..=8 | 11) {
                                rec.checksumtype
                            } else {
                                8
                            };
                            let upd = if stage_cloned.is_raw_encrypted {
                                let comp = if rec.compressiontype != 0 {
                                    rec.compressiontype
                                } else {
                                    2
                                };
                                let is_enc = dmu_ot_is_encrypted(d.object_type);
                                let (salt, iv) = if is_enc {
                                    (Some(rec.salt), Some(rec.iv))
                                } else {
                                    if rec.salt != [0; ZIO_DATA_SALT_LEN]
                                        || rec.iv != [0; ZIO_DATA_IV_LEN]
                                    {
                                        return Err(corrupt(
                                            "authenticated non-encrypted raw write carries salt or IV",
                                        ));
                                    }
                                    (None, None)
                                };
                                let dva = alloc.allocate(payload.len())?;
                                let bp = BlockPointer::new_protected(&ProtectedBlockSpec {
                                    dvas: &[dva],
                                    physical: payload,
                                    logical_bytes: usize::try_from(rec.logical_size)
                                        .map_err(|_| corrupt("write logical_size overflow"))?,
                                    compression: comp,
                                    checksum_type: eff_cksum,
                                    object_type: d.object_type,
                                    level: 0,
                                    payload_order: block_order,
                                    birth: new_txg,
                                    fill: 1,
                                    salt,
                                    iv,
                                    mac: rec.mac,
                                })
                                .map_err(|e| parse_err(&e))?;
                                let mut padded = payload.clone();
                                padded.resize(
                                    usize::try_from(dva.allocated_bytes)
                                        .unwrap_or(payload.len())
                                        .max(payload.len()),
                                    0,
                                );
                                staged_writes.push(StagedBlockWrite::from_dva(
                                    WriteBucket::ChildBlocks,
                                    dva,
                                    padded,
                                ));
                                StagedLeafUpdate::Prebuilt(bp)
                            } else if rec.compressiontype != 0 && rec.compressiontype != 2 {
                                let dva = alloc.allocate(payload.len())?;
                                let bp = BlockPointer::new_regular(&RegularBlockSpec {
                                    dvas: &[dva],
                                    physical: payload,
                                    logical_bytes: usize::try_from(rec.logical_size)
                                        .map_err(|_| corrupt("write logical_size overflow"))?,
                                    compression: rec.compressiontype,
                                    checksum_type: eff_cksum,
                                    object_type: d.object_type,
                                    level: 0,
                                    payload_order: block_order,
                                    birth: new_txg,
                                    fill: 1,
                                })
                                .map_err(|e| parse_err(&e))?;
                                let mut padded = payload.clone();
                                padded.resize(
                                    usize::try_from(dva.allocated_bytes)
                                        .unwrap_or(payload.len())
                                        .max(payload.len()),
                                    0,
                                );
                                staged_writes.push(StagedBlockWrite::from_dva(
                                    WriteBucket::ChildBlocks,
                                    dva,
                                    padded,
                                ));
                                StagedLeafUpdate::Prebuilt(bp)
                            } else {
                                StagedLeafUpdate::Plaintext(payload.clone())
                            };
                            d.leaves.insert(bid, upd);
                        }
                        RecvOp::WriteEmbedded { rec, payload } => {
                            load_draft(
                                rec.object,
                                &mut drafts,
                                &mut meta_dirty_blocks,
                                &mut os_view,
                            )?;
                            let d = drafts.get_mut(&rec.object).expect("loaded");
                            validate_received_geometry(rec.offset, rec.length, d.data_bytes)?;
                            validate_received_plain_order(d.object_type, stream_order, order)?;
                            let blksz = d.data_bytes as u64;
                            let bid = rec.offset / blksz;
                            d.max_block = d.max_block.max(bid);
                            let psize = usize::try_from(rec.psize).unwrap_or(0);
                            let lsize = usize::try_from(rec.lsize).unwrap_or(0);
                            let packed = payload
                                .get(..psize)
                                .ok_or_else(|| corrupt("truncated DRR_WRITE_EMBEDDED payload"))?;
                            let bp = BlockPointer::encode_embedded_data(
                                packed,
                                lsize,
                                rec.compression,
                                d.object_type,
                                order,
                                new_txg,
                            )
                            .map_err(|e| parse_err(&e))?;
                            d.leaves.insert(bid, StagedLeafUpdate::Prebuilt(bp));
                        }
                        RecvOp::Free(f) => {
                            load_draft(
                                f.object,
                                &mut drafts,
                                &mut meta_dirty_blocks,
                                &mut os_view,
                            )?;
                            let d = drafts.get_mut(&f.object).expect("loaded");
                            let blksz = d.data_bytes as u64;
                            let start_bid = f.offset / blksz;
                            if f.length == u64::MAX {
                                if start_bid == 0 {
                                    d.max_block = 0;
                                    d.leaves.insert(0, StagedLeafUpdate::Hole);
                                } else {
                                    d.max_block = d.max_block.min(start_bid - 1);
                                }
                            } else if f.length > 0 {
                                let count = f.length.div_ceil(blksz);
                                let end_bid = start_bid.saturating_add(count).min(d.max_block + 1);
                                for bid in start_bid..end_bid {
                                    d.leaves.insert(bid, StagedLeafUpdate::Hole);
                                }
                            }
                        }
                        RecvOp::Spill { rec, payload } => {
                            load_draft(
                                rec.object,
                                &mut drafts,
                                &mut meta_dirty_blocks,
                                &mut os_view,
                            )?;
                            let d = drafts.get_mut(&rec.object).expect("loaded");
                            // OpenZFS leaves drr_type zero: spill blocks inherit
                            // their DMU type (and encryption policy) from the
                            // owning dnode's bonus type, not its data object type.
                            let obj_type = d.bonus_type;
                            if obj_type == 0 || (rec.object_type != 0 && rec.object_type != u32::from(obj_type)) {
                                return Err(corrupt("DRR_SPILL type disagrees with its dnode bonus type"));
                            }
                            if !stage_cloned.is_raw_encrypted {
                                validate_received_plain_order(obj_type, stream_order, order)?;
                            }
                            let block_order = if rec.flags & DRR_RAW_BYTESWAP != 0 {
                                match stream_order {
                                    Endian::Little => Endian::Big,
                                    Endian::Big => Endian::Little,
                                }
                            } else if stage_cloned.is_raw_encrypted {
                                stream_order
                            } else {
                                order
                            };
                            let comp = if rec.compressiontype != 0 {
                                rec.compressiontype
                            } else {
                                2
                            };
                            let dva = alloc.allocate(payload.len())?;
                            let bp = if stage_cloned.is_raw_encrypted {
                                let is_enc = dmu_ot_is_encrypted(obj_type);
                                let (salt, iv) = if is_enc {
                                    (Some(rec.salt), Some(rec.iv))
                                } else {
                                    if rec.salt != [0; ZIO_DATA_SALT_LEN]
                                        || rec.iv != [0; ZIO_DATA_IV_LEN]
                                    {
                                        return Err(corrupt(
                                            "authenticated non-encrypted raw spill carries salt or IV",
                                        ));
                                    }
                                    (None, None)
                                };
                                BlockPointer::new_protected(&ProtectedBlockSpec {
                                    dvas: &[dva],
                                    physical: payload,
                                    logical_bytes: usize::try_from(rec.length)
                                        .map_err(|_| corrupt("DRR_SPILL length overflow"))?,
                                    compression: comp,
                                    checksum_type: 8,
                                    object_type: obj_type,
                                    level: 0,
                                    payload_order: block_order,
                                    birth: new_txg,
                                    fill: 1,
                                    salt,
                                    iv,
                                    mac: rec.mac,
                                })
                                .map_err(|e| parse_err(&e))?
                            } else {
                                BlockPointer::new_regular(&RegularBlockSpec {
                                    dvas: &[dva],
                                    physical: payload,
                                    logical_bytes: usize::try_from(rec.length)
                                        .map_err(|_| corrupt("DRR_SPILL length overflow"))?,
                                    compression: comp,
                                    checksum_type: 8,
                                    object_type: obj_type,
                                    level: 0,
                                    payload_order: block_order,
                                    birth: new_txg,
                                    fill: 1,
                                })
                                .map_err(|e| parse_err(&e))?
                            };
                            let mut padded = payload.clone();
                            padded.resize(
                                usize::try_from(dva.allocated_bytes)
                                    .unwrap_or(payload.len())
                                    .max(payload.len()),
                                0,
                            );
                            staged_writes.push(StagedBlockWrite::from_dva(
                                WriteBucket::ChildBlocks,
                                dva,
                                padded,
                            ));
                            // When a resumable raw encrypted receive checkpoints between
                            // `DRR_OBJECT` (with `DRR_OBJECT_SPILL`) and `DRR_SPILL`, the
                            // on-disk dnode had `has_spill == false`, so `extract_raw_dnode_bonus`
                            // captured the trailing 128 zero bytes reserved for the incoming spill
                            // pointer. Trim that zero-filled spill slot while rejecting any
                            // non-zero ciphertext that would collide with the spill BP.
                            if let Some(ref mut raw_bonus) = d.raw_bonus {
                                let dnode_size = d
                                    .slots
                                    .checked_mul(DNODE_BYTES)
                                    .ok_or_else(|| corrupt("dnode size overflow"))?;
                                let bonus_start = 64 + d.nblkptr * 128;
                                let spill_bonus_cap = dnode_size
                                    .checked_sub(128)
                                    .and_then(|end| end.checked_sub(bonus_start))
                                    .ok_or_else(|| {
                                        corrupt("dnode has insufficient space for spill pointer")
                                    })?;
                                if raw_bonus.len() > spill_bonus_cap {
                                    if raw_bonus[spill_bonus_cap..].iter().any(|&b| b != 0) {
                                        return Err(corrupt(
                                            "raw bonus payload exceeds dnode spill bonus capacity",
                                        ));
                                    }
                                    raw_bonus.truncate(spill_bonus_cap);
                                }
                            }
                            d.spill = Some(bp);
                        }
                    }
                }

                // Flush all modified object dnodes into `meta_dirty_blocks`.
                for (obj_id, draft) in drafts {
                    validate_received_raw_object(raw_meta.as_ref(), obj_id)?;
                    let cow_out = cow_update_dnode_with_staged_leaves(
                        cx,
                        &mut os_view,
                        alloc,
                        DnodeCowSpec {
                            existing: draft.existing.as_ref().map(|d| (d, old_meta_ceil)),
                            object_type: draft.object_type,
                            bonus_type: draft.bonus_type,
                            checksum_type: draft.checksum_type,
                            compress_type: draft.compress_type,
                            user_flags: 0,
                            indirect_shift: draft.indirect_shift,
                            data_bytes: draft.data_bytes,
                            max_block: draft.max_block,
                            slots: draft.slots,
                            nblkptr: draft.nblkptr,
                            bonus: draft.bonus,
                            spill: draft.spill,
                            order,
                            new_txg,
                            leaf_bucket: WriteBucket::ChildBlocks,
                            indirect_bucket: WriteBucket::ChildBlocks,
                        },
                        &draft.leaves,
                        obj_id,
                        stage_cloned.compression,
                        None,
                        raw_enc_ver.map(|v| (v, draft.nlevels)),
                        staged_writes,
                    )?;
                    born_space.add_assign(cow_out.born)?;
                    feature_usage.extend(cow_out.feature_usage);
                    retired_bps.extend(cow_out.retired_bps);

                    // COW preserves an existing object's policy (or inheritance
                    // for a new object). Receive must instead install the native
                    // dn_checksum supplied by DRR_OBJECT, including changes in
                    // an incremental stream, independently of the data BPs.
                    let mut dnode_bytes = cow_out.dnode.encode().map_err(|e| parse_err(&e))?;
                    dnode_bytes[5] = draft.checksum_type;
                    let received_dnode =
                        Dnode::parse(&dnode_bytes, order).map_err(|e| parse_err(&e))?;

                    let meta_bid = obj_id / 32;
                    max_meta_block = max_meta_block.max(meta_bid);
                    ensure_dnode_table_block_loaded(
                        cx,
                        &mut os_view,
                        &old_meta,
                        old_meta_ceil,
                        meta_bid,
                        &mut meta_dirty_blocks,
                    )?;
                    let blk = meta_dirty_blocks
                        .get_mut(&meta_bid)
                        .ok_or_else(|| corrupt("missing loaded dnode table block"))?;
                    let slot = (obj_id % 32) as usize;
                    write_dnode_at(blk, slot, &received_dnode).map_err(|e| parse_err(&e))?;
                    if let Some(ref raw_b) = draft.raw_bonus {
                        write_raw_dnode_bonus(blk, slot, raw_b).map_err(|e| parse_err(&e))?;
                    }
                }

                // Raw metadata selectors and maximum block come from BEGIN,
                // including streams with no OBJECT or WRITE records. Preserve
                // the old upper range until END so later FREEOBJECTS records
                // can still retire objects when the source table shrank.
                let target_meta_max = raw_meta.map_or(max_meta_block, |meta| {
                    if final_chunk {
                        meta.max_block
                    } else {
                        meta.max_block.max(old_meta.max_block())
                    }
                });
                if raw_meta.is_some() && target_meta_max < old_meta.max_block() {
                    // A hostile header cannot discard allocated objects merely
                    // by lowering mdn_maxblkid. Their FREEOBJECTS records must
                    // have retired every child before the table is truncated.
                    for bid in allocated_leaf_blocks_in_range(
                        cx, &mut os_view, &old_meta, old_meta_ceil,
                        target_meta_max + 1, old_meta.max_block(),
                    )? {
                        checkpoint(cx)?;
                        let allocated = if let Some(bytes) = meta_dirty_blocks.get(&bid) {
                            count_allocated_dnodes(bytes, order).map_err(|e| parse_err(&e))?
                        } else if let Some((bytes, block_order, _)) = os_view.object_data_block(
                            cx, &old_meta, old_meta_ceil, bid,
                        )? {
                            count_allocated_dnodes(&bytes, block_order).map_err(|e| parse_err(&e))?
                        } else {
                            0
                        };
                        if allocated != 0 {
                            return Err(FfsError::Format(
                                "raw meta-dnode truncation would discard allocated objects".into(),
                            ));
                        }
                    }
                }
                if !meta_dirty_blocks.is_empty() || raw_meta.is_some() {
                    let mut meta_leaves: BTreeMap<u64, StagedLeafUpdate> = BTreeMap::new();
                    for (bid, blk_bytes) in meta_dirty_blocks {
                        if bid > target_meta_max {
                            // Final truncation retires this old table block in
                            // COW; never allocate an unreachable replacement.
                            continue;
                        }
                        let upd = if stage_cloned.is_raw_encrypted && blk_bytes.iter().all(|&byte| byte == 0) {
                            // A native hole has no ciphertext or range MAC. In
                            // particular, FREEOBJECTS may clear an entire old
                            // table block without a source OBJECT_RANGE record.
                            StagedLeafUpdate::Hole
                        } else if stage_cloned.is_raw_encrypted {
                            let rng = object_ranges.get(&bid).ok_or_else(|| {
                                corrupt(format!(
                                    "raw encrypted receive missing DRR_OBJECT_RANGE for dnode block {bid}"
                                ))
                            })?;
                            let blk_order = received_raw_order(rng.flags, stream_order);
                            if blk_order != order {
                                return Err(unsupported(
                                    "raw receive cannot reconstruct foreign-order dnode tables",
                                ));
                            }
                            let fill = count_allocated_dnodes(&blk_bytes, blk_order)
                                .map_err(|e| parse_err(&e))?;
                            let dva = alloc.allocate(blk_bytes.len())?;
                            let bp = BlockPointer::new_protected(&ProtectedBlockSpec {
                                dvas: &[dva],
                                physical: &blk_bytes,
                                logical_bytes: DNODE_BLOCK_BYTES,
                                compression: 2,
                                checksum_type: 8,
                                object_type: DMU_OT_DNODE,
                                level: 0,
                                payload_order: blk_order,
                                birth: new_txg,
                                fill,
                                salt: Some(rng.salt),
                                iv: Some(rng.iv),
                                mac: rng.mac,
                            })
                            .map_err(|e| parse_err(&e))?;
                            staged_writes.push(StagedBlockWrite::from_dva(
                                WriteBucket::DatasetMetadata,
                                dva,
                                blk_bytes,
                            ));
                            StagedLeafUpdate::Prebuilt(bp)
                        } else {
                            StagedLeafUpdate::Plaintext(blk_bytes)
                        };
                        meta_leaves.insert(bid, upd);
                    }
                    let meta_out = cow_update_dnode_with_staged_leaves(
                        cx,
                        &mut os_view,
                        alloc,
                        DnodeCowSpec {
                            existing: Some((&old_meta, old_meta_ceil)),
                            object_type: DMU_OT_DNODE,
                            bonus_type: 0,
                            checksum_type: raw_meta
                                .map_or_else(|| old_meta.checksum_type(), |meta| meta.checksum),
                            compress_type: raw_meta
                                .map_or_else(|| old_meta.compress_type(), |meta| meta.compression),
                            user_flags: 0,
                            indirect_shift: old_meta.indirect_shift(),
                            data_bytes: DNODE_BLOCK_BYTES,
                            max_block: target_meta_max,
                            slots: 1,
                            nblkptr: 3,
                            bonus: Vec::new(),
                            spill: None,
                            order,
                            new_txg,
                            leaf_bucket: WriteBucket::DatasetMetadata,
                            indirect_bucket: WriteBucket::DatasetMetadata,
                        },
                        &meta_leaves,
                        0,
                        stage_cloned.compression,
                        None,
                        raw_enc_ver.map(|v| {
                            (
                                v,
                                raw_meta.map_or_else(|| old_meta.levels(), |meta| meta.levels),
                            )
                        }),
                        staged_writes,
                    )?;
                    born_space.add_assign(meta_out.born)?;
                    feature_usage.extend(meta_out.feature_usage);
                    retired_bps.extend(meta_out.retired_bps);
                    os.meta = meta_out.dnode;
                }

                // Write updated `DMU_OT_OBJSET` root block.
                retired_bps.push(old_os_bp);
                let new_os_bp = if stage_cloned.is_raw_encrypted {
                    // Native raw receive defers local accounting until mount.
                    // Its MAC is not portable and must never survive a clone.
                    os.flags &= !1;
                    write_dataset_objset_block_raw_protected(
                        &mut os,
                        alloc,
                        7,
                        order,
                        new_txg,
                        stage_cloned.portable_mac,
                        [0_u8; 32],
                        staged_writes,
                    )?
                } else {
                    write_dataset_objset_block(&mut os, alloc, 7, order, new_txg, stage_cloned.compression, None, staged_writes)?
                };
                born_space.add_assign(SpaceDelta::from_bp(&new_os_bp)?)?;
                feature_usage.observe(&new_os_bp);

                // Retire blocks (`birth > prev_snap_txg` freed now; `birth <= prev_snap_txg` to deadlist).
                let mut dead_space = SpaceDelta::default();
                let mut live_freed_space = SpaceDelta::default();
                let mut to_deadlist = Vec::new();
                for rbp in &retired_bps {
                    let delta = SpaceDelta::from_bp(rbp)?;
                    if rbp.birth() > stage_cloned.prev_snap_txg {
                        alloc.free_block_dvas(rbp, new_txg)?;
                        live_freed_space.add_assign(delta)?;
                    } else if !rbp.hole() && !rbp.embedded() {
                        to_deadlist.push(rbp.clone());
                        dead_space.add_assign(delta)?;
                    }
                }
                let deadlist_obj = order
                    .u64(head_dn.bonus(), 64)
                    .map_err(|e| parse_err(&e))?;
                if !to_deadlist.is_empty() {
                    enqueue_into_dataset_deadlist(
                        cx,
                        mos,
                        mos_dirty_dnodes,
                        &mut features.write_features,
                        &mut features.write_dirty,
                        empty_bpobj_id,
                        deadlist_obj,
                        &to_deadlist,
                        alloc,
                        order,
                        new_txg,
                        staged_writes,
                    )?;
                }

                // Compute space accounting deltas and enforce dataset quotas & pool reservations!
                let old_ref = order.u64(head_dn.bonus(), 72).map_err(|e| parse_err(&e))?;
                let old_comp = order.u64(head_dn.bonus(), 80).map_err(|e| parse_err(&e))?;
                let old_uncomp = order.u64(head_dn.bonus(), 88).map_err(|e| parse_err(&e))?;
                let old_unique = order.u64(head_dn.bonus(), 96).map_err(|e| parse_err(&e))?;
                let total_retired_dsize = live_freed_space.dsize.saturating_add(dead_space.dsize);
                let total_retired_comp = live_freed_space.comp.saturating_add(dead_space.comp);
                let total_retired_uncomp =
                    live_freed_space.uncomp.saturating_add(dead_space.uncomp);

                let new_ref = old_ref
                    .saturating_add(born_space.dsize)
                    .saturating_sub(total_retired_dsize);
                let new_comp = old_comp
                    .saturating_add(born_space.comp)
                    .saturating_sub(total_retired_comp);
                let new_uncomp = old_uncomp
                    .saturating_add(born_space.uncomp)
                    .saturating_sub(total_retired_uncomp);
                let new_unique = old_unique
                    .saturating_add(born_space.dsize)
                    .saturating_sub(live_freed_space.dsize);

                let delta_dsize =
                    i128::from(born_space.dsize) - i128::from(live_freed_space.dsize);
                let delta_comp = i128::from(born_space.comp) - i128::from(live_freed_space.comp);
                let delta_uncomp =
                    i128::from(born_space.uncomp) - i128::from(live_freed_space.uncomp);
                if delta_dsize > 0 {
                    let growth = u64::try_from(delta_dsize).unwrap_or(u64::MAX);
                    enforce_dataset_quotas_for_growth(
                        cx,
                        mos,
                        mos_dirty_dnodes,
                        stage_cloned.target_head_obj.unwrap_or(stage_cloned.stage_head_obj),
                        stage_cloned.target_dd_obj,
                        growth,
                        growth,
                        order,
                    )?;
                    enforce_pool_reservations_for_growth(
                        cx,
                        mos,
                        mos_dirty_dnodes,
                        stage_cloned
                            .target_head_obj
                            .unwrap_or(stage_cloned.stage_head_obj),
                        stage_cloned.target_dd_obj,
                        growth,
                        0,
                        alloc.total_free_bytes(),
                        order,
                    )?;
                }

                // Update staging `head_dataset` bonus + persisted `DS_FIELD_RESUME_{OBJECT,OFFSET,BYTES}`!
                let mut new_head_bonus = head_dn.bonus().to_vec();
                new_head_bonus[72..80].copy_from_slice(&order.encode(new_ref));
                new_head_bonus[80..88].copy_from_slice(&order.encode(new_comp));
                new_head_bonus[88..96].copy_from_slice(&order.encode(new_uncomp));
                new_head_bonus[96..104].copy_from_slice(&order.encode(new_unique));
                new_head_bonus[128..256].copy_from_slice(&new_os_bp.encode(order));

                let mut head_entries = dataset_feature_entries(
                    cx,
                    mos,
                    stage_cloned.stage_head_obj,
                    &head_dn,
                    features,
                )?;
                // The checkpoint must own every emitted feature-bearing block
                // even when the stream stops before final promotion.
                activate_dataset_block_features(
                    &mut head_entries,
                    &feature_usage.required_features(),
                    features,
                    new_txg,
                )?;
                for (key, val) in [
                    (DS_FIELD_RESUME_OBJECT, prog_obj),
                    (DS_FIELD_RESUME_OFFSET, prog_off),
                    (DS_FIELD_RESUME_BYTES, prog_bytes),
                ] {
                    head_entries.retain(|e| e.name != key);
                    head_entries.push(zap_u64_entry(key, val));
                }
                write_zap_dnode_in_mos(
                    cx,
                    mos,
                    &mos_meta,
                    mos_ceiling,
                    mos_dirty_dnodes,
                    alloc,
                    stage_cloned.stage_head_obj,
                    Some((&head_dn, head_ceil)),
                    DMU_OTN_ZAP_METADATA,
                    DMU_OT_DSL_DATASET,
                    new_head_bonus,
                    &head_entries,
                    0,
                    false,
                    order,
                    new_txg,
                    staged_writes,
                )?;

                propagate_dsl_dir_space_delta(
                    cx,
                    mos,
                    &mos_meta,
                    mos_ceiling,
                    mos_dirty_dnodes,
                    stage_cloned.stage_dd_obj,
                    delta_dsize,
                    0,
                    0,
                    0,
                    0,
                    delta_comp,
                    delta_uncomp,
                    order,
                )?;

                Ok(((), stage_cloned.stage_head_obj))
            },
        )
    }

    #[allow(clippy::too_many_lines)]
    fn commit_recv_end_txg(
        &mut self,
        cx: &Cx,
        req: &ZfsRecvRequest,
        stage: &StagedSubstreamMeta,
        begin: &DrrBegin,
        snap_name: &[u8],
        compound_props: &[(String, ZfsPropertySetValue)],
    ) -> ZfsTxOutcome<u64> {
        let stage_cloned = stage.clone();
        let begin_cloned = begin.clone();
        let snap_owned = snap_name.to_vec();
        let props_owned = compound_props.to_vec();
        let target_dataset = req.target_dataset.clone();
        let order = self.order;
        let empty_bpobj_id = self.empty_bpobj_id;

        self.execute_staged_txg_typed(
            cx,
            "recv_end",
            move |mos, mos_dirty_dnodes, features, alloc, new_txg, staged_writes| {
                let mos_meta = mos.meta_dnode().clone();
                let mos_ceiling = mos.root_birth_txg();
                let (stage_head_dn, stage_head_ceil) = read_staged_or_committed_dnode(
                    cx,
                    mos,
                    &mos_meta,
                    mos_ceiling,
                    mos_dirty_dnodes,
                    stage_cloned.stage_head_obj,
                    order,
                )?;

                let stage_ref = order
                    .u64(stage_head_dn.bonus(), 72)
                    .map_err(|e| parse_err(&e))?;
                let stage_comp = order
                    .u64(stage_head_dn.bonus(), 80)
                    .map_err(|e| parse_err(&e))?;
                let stage_uncomp = order
                    .u64(stage_head_dn.bonus(), 88)
                    .map_err(|e| parse_err(&e))?;
                let stage_unique = order
                    .u64(stage_head_dn.bonus(), 96)
                    .map_err(|e| parse_err(&e))?;
                let stage_flags = order
                    .u64(stage_head_dn.bonus(), 120)
                    .map_err(|e| parse_err(&e))?;
                let clean_flags = (stage_flags & !DS_FLAG_INCONSISTENT) | DS_FLAG_UNIQUE_ACCURATE;
                let stage_deadlist = order
                    .u64(stage_head_dn.bonus(), 64)
                    .map_err(|e| parse_err(&e))?;
                let mut stage_entries = dataset_feature_entries(
                    cx,
                    mos,
                    stage_cloned.stage_head_obj,
                    &stage_head_dn,
                    features,
                )?;
                if !stage_cloned.is_pct_recv_child {
                    // A newly received filesystem owns explicitly selected ZSTD
                    // before its final snapshot is created, even for an empty
                    // stream. Incremental clone-swap instead replaces the target's
                    // old ownership with the staged block/ancestor ownership.
                    activate_initial_compression_feature(
                        &mut stage_entries,
                        &props_owned,
                        features,
                        new_txg,
                    )?;
                }
                let stage_owners = dataset_block_feature_owners(&stage_entries, features)?;
                let mut snapshot_entries = Vec::new();
                if let Some(ivg) = stage_cloned.to_ivset_guid.filter(|&v| v != 0) {
                    snapshot_entries.push(zap_u64_entry(DSL_DATASET_IVSET_GUID, ivg));
                }
                // Native snapshot creation acquires a separate feature reference
                // even though its ObjectSet is physically shared with the head.
                activate_dataset_block_features(
                    &mut snapshot_entries,
                    &stage_owners,
                    features,
                    new_txg,
                )?;

                if stage_cloned.is_pct_recv_child {
                    // Incremental receive promotion: atomic `dsl_dataset_clone_swap`!
                    let target_head_obj = stage_cloned
                        .target_head_obj
                        .ok_or_else(|| corrupt("missing target head object for %recv swap"))?;
                    let (target_head_dn, target_head_ceil) = read_staged_or_committed_dnode(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        target_head_obj,
                        order,
                    )?;
                    let mut target_head_entries = dataset_feature_entries(
                        cx,
                        mos,
                        target_head_obj,
                        &target_head_dn,
                        features,
                    )?;
                    let target_snapmap_obj = order
                        .u64(target_head_dn.bonus(), 32)
                        .map_err(|e| parse_err(&e))?;
                    let target_old_deadlist = order
                        .u64(target_head_dn.bonus(), 64)
                        .map_err(|e| parse_err(&e))?;
                    let target_old_unique = order
                        .u64(target_head_dn.bonus(), 96)
                        .map_err(|e| parse_err(&e))?;

                    // Refuse duplicate snapshot name before mutating anything!
                    let (sm_dn, sm_ceil) = mos.object_with_ceiling(cx, target_snapmap_obj)?;
                    let mut sm_entries = mos.zap_values_with_names(
                        cx,
                        target_snapmap_obj,
                        ZapNamePolicy::AsciiUppercase,
                    )?;
                    if sm_entries
                        .iter()
                        .any(|e| e.name.eq_ignore_ascii_case(&snap_owned))
                    {
                        return Err(FfsError::Exists);
                    }

                    // 1. Free old `target_head`'s unsnapshotted unique blocks (if `--force` rolled back head).
                    let old_target_bp = BlockPointer::parse(
                        &target_head_dn.bonus()[128..256],
                        target_head_dn.order(),
                    )
                    .map_err(|e| parse_err(&e))?;
                    let target_crypto = mos.dataset_crypto_info(cx, &target_dataset)?;
                    let (old_head_freed_space, _) = walk_objectset_above_txg(
                        cx,
                        mos,
                        &old_target_bp,
                        target_head_ceil,
                        target_crypto.as_ref(),
                        stage_cloned.prev_snap_txg,
                        ObjectSetWalkMode::FreeToAllocator,
                        alloc,
                        new_txg,
                    )?;
                    free_deadlist_containers(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        features,
                        alloc,
                        target_old_deadlist,
                        empty_bpobj_id,
                        order,
                        new_txg,
                    )?;

                    // 2. Create new snapshot `snap_ds_obj` on `target_dd_obj` adopting `%recv`'s
                    //    ObjectSet BP + deadlist + exact `drr_toguid` + `drr_creation_time`.
                    let snap_ds_obj =
                        allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
                    let fresh_deadlist = allocate_fresh_deadlist(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        features,
                        alloc,
                        empty_bpobj_id,
                        &BTreeSet::new(),
                        &[],
                        order,
                        new_txg,
                        staged_writes,
                    )?;

                    let snap_guid = begin_cloned.toguid;
                    let snap_fsid = derive_fsid_guid(snap_guid);
                    let mut snap_bonus = vec![0_u8; 320];
                    snap_bonus[0..8].copy_from_slice(&order.encode(stage_cloned.target_dd_obj));
                    snap_bonus[8..16].copy_from_slice(&order.encode(stage_cloned.prev_snap_obj));
                    snap_bonus[16..24].copy_from_slice(&order.encode(stage_cloned.prev_snap_txg));
                    snap_bonus[24..32].copy_from_slice(&order.encode(target_head_obj));
                    snap_bonus[40..48].copy_from_slice(&order.encode(1));
                    snap_bonus[48..56].copy_from_slice(&order.encode(begin_cloned.creation_time));
                    snap_bonus[56..64].copy_from_slice(&order.encode(new_txg));
                    snap_bonus[64..72].copy_from_slice(&order.encode(stage_deadlist));
                    snap_bonus[72..80].copy_from_slice(&order.encode(stage_ref));
                    snap_bonus[80..88].copy_from_slice(&order.encode(stage_comp));
                    snap_bonus[88..96].copy_from_slice(&order.encode(stage_uncomp));
                    snap_bonus[96..104].copy_from_slice(&order.encode(0));
                    snap_bonus[104..112].copy_from_slice(&order.encode(snap_fsid));
                    snap_bonus[112..120].copy_from_slice(&order.encode(snap_guid));
                    snap_bonus[120..128].copy_from_slice(&order.encode(clean_flags));
                    snap_bonus[128..256].copy_from_slice(&stage_head_dn.bonus()[128..256]);

                    if snapshot_entries.is_empty() {
                        let snap_dn = Dnode::from_spec(DnodeSpec {
                            object_type: DMU_OT_DSL_DATASET,
                            bonus_type: DMU_OT_DSL_DATASET,
                            checksum_type: 0,
                            compress_type: 0,
                            flags: DNODE_FLAG_USED_BYTES,
                            order,
                            levels: 1,
                            indirect_shift: 17,
                            data_bytes: 512,
                            max_block: 0,
                            used_bytes: 0,
                            slots: 1,
                            pointers: vec![BlockPointer::hole_pointer()],
                            bonus: snap_bonus,
                            spill: None,
                        })
                        .map_err(|e| parse_err(&e))?;
                        put_dnode_in_table(
                            cx,
                            mos,
                            &mos_meta,
                            mos_ceiling,
                            mos_dirty_dnodes,
                            snap_ds_obj,
                            &snap_dn,
                        )?;
                    } else {
                        features.increment_read("com.delphix:extensible_dataset", new_txg)?;
                        write_zap_dnode_in_mos(
                            cx,
                            mos,
                            &mos_meta,
                            mos_ceiling,
                            mos_dirty_dnodes,
                            alloc,
                            snap_ds_obj,
                            None,
                            DMU_OTN_ZAP_METADATA,
                            DMU_OT_DSL_DATASET,
                            snap_bonus,
                            &snapshot_entries,
                            0,
                            false,
                            order,
                            new_txg,
                            staged_writes,
                        )?;
                    }

                    // 3. Relink `prev_snap.ds_next_snap_obj = snap_ds_obj`, unlink `%recv` from
                    //    `prev_snap`'s `ds_next_clones_obj` + `target_dd.dd_clones`.
                    let (prev_snap_dn, _) = read_staged_or_committed_dnode(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        stage_cloned.prev_snap_obj,
                        order,
                    )?;
                    let mut prev_bonus = prev_snap_dn.bonus().to_vec();
                    prev_bonus[24..32].copy_from_slice(&order.encode(snap_ds_obj));
                    let prev_children = order.u64(&prev_bonus, 40).map_err(|e| parse_err(&e))?;
                    let prev_nc_obj = order.u64(&prev_bonus, 256).map_err(|e| parse_err(&e))?;
                    let new_prev_children = prev_children.saturating_sub(1).max(1);
                    prev_bonus[40..48].copy_from_slice(&order.encode(new_prev_children));
                    if prev_nc_obj != 0 {
                        let (nc_dn, nc_ceil) = mos.object_with_ceiling(cx, prev_nc_obj)?;
                        let mut nc_entries = mos.zap_values(cx, prev_nc_obj)?;
                        let key = format!("{:x}", stage_cloned.stage_head_obj).into_bytes();
                        nc_entries.retain(|e| e.name != key);
                        if nc_entries.is_empty() {
                            free_mos_object_completely(
                                cx,
                                mos,
                                &mos_meta,
                                mos_ceiling,
                                mos_dirty_dnodes,
                                alloc,
                                prev_nc_obj,
                                order,
                                new_txg,
                            )?;
                            prev_bonus[256..264].copy_from_slice(&order.encode(0));
                        } else {
                            write_zap_dnode_in_mos(
                                cx,
                                mos,
                                &mos_meta,
                                mos_ceiling,
                                mos_dirty_dnodes,
                                alloc,
                                prev_nc_obj,
                                Some((&nc_dn, nc_ceil)),
                                nc_dn.object_type(),
                                nc_dn.bonus_type(),
                                Vec::new(),
                                &nc_entries,
                                0,
                                false,
                                order,
                                new_txg,
                                staged_writes,
                            )?;
                        }
                    }
                    let prev_spill = prev_snap_dn.spill().cloned();
                    let mut updated_prev_dn = prev_snap_dn;
                    updated_prev_dn
                        .set_bonus_and_spill(DMU_OT_DSL_DATASET, prev_bonus, prev_spill)
                        .map_err(|e| parse_err(&e))?;
                    put_dnode_in_table(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        stage_cloned.prev_snap_obj,
                        &updated_prev_dn,
                    )?;

                    // 4. Insert `<snap_name> -> snap_ds_obj` into `target_snapmap_obj` & update `target_head`.
                    sm_entries.push(zap_u64_entry(&snap_owned, snap_ds_obj));
                    write_zap_dnode_in_mos(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        alloc,
                        target_snapmap_obj,
                        Some((&sm_dn, sm_ceil)),
                        sm_dn.object_type(),
                        sm_dn.bonus_type(),
                        Vec::new(),
                        &sm_entries,
                        2,
                        false,
                        order,
                        new_txg,
                        staged_writes,
                    )?;

                    let mut new_target_head_bonus = target_head_dn.bonus().to_vec();
                    new_target_head_bonus[8..16].copy_from_slice(&order.encode(snap_ds_obj));
                    new_target_head_bonus[16..24].copy_from_slice(&order.encode(new_txg));
                    new_target_head_bonus[64..72].copy_from_slice(&order.encode(fresh_deadlist));
                    new_target_head_bonus[72..80].copy_from_slice(&order.encode(stage_ref));
                    new_target_head_bonus[80..88].copy_from_slice(&order.encode(stage_comp));
                    new_target_head_bonus[88..96].copy_from_slice(&order.encode(stage_uncomp));
                    new_target_head_bonus[96..104].copy_from_slice(&order.encode(0));
                    new_target_head_bonus[120..128].copy_from_slice(&order.encode(clean_flags));
                    new_target_head_bonus[128..256]
                        .copy_from_slice(&stage_head_dn.bonus()[128..256]);
                    // OpenZFS clone_swap swaps the feature-owner sets, then
                    // destroys the temporary old head. In particular, --force
                    // must release features used only by the discarded target.
                    let old_target_owners =
                        dataset_block_feature_owners(&target_head_entries, features)?;
                    release_dataset_block_features(&target_head_entries, features)?;
                    target_head_entries.retain(|entry| {
                        !old_target_owners
                            .iter()
                            .any(|feature| entry.name == feature.as_bytes())
                    });
                    activate_dataset_block_features(
                        &mut target_head_entries,
                        &stage_owners,
                        features,
                        new_txg,
                    )?;
                    if target_head_dn.object_type() == DMU_OTN_ZAP_METADATA
                        || !target_head_entries.is_empty()
                    {
                        if target_head_dn.object_type() != DMU_OTN_ZAP_METADATA {
                            features.increment_read("com.delphix:extensible_dataset", new_txg)?;
                        }
                        write_zap_dnode_in_mos(
                            cx,
                            mos,
                            &mos_meta,
                            mos_ceiling,
                            mos_dirty_dnodes,
                            alloc,
                            target_head_obj,
                            Some((&target_head_dn, target_head_ceil)),
                            DMU_OTN_ZAP_METADATA,
                            DMU_OT_DSL_DATASET,
                            new_target_head_bonus,
                            &target_head_entries,
                            0,
                            false,
                            order,
                            new_txg,
                            staged_writes,
                        )?;
                    } else {
                        let target_spill = target_head_dn.spill().cloned();
                        let mut updated_target_head = target_head_dn;
                        updated_target_head
                            .set_bonus_and_spill(
                                DMU_OT_DSL_DATASET,
                                new_target_head_bonus,
                                target_spill,
                            )
                            .map_err(|e| parse_err(&e))?;
                        put_dnode_in_table(
                            cx,
                            mos,
                            &mos_meta,
                            mos_ceiling,
                            mos_dirty_dnodes,
                            target_head_obj,
                            &updated_target_head,
                        )?;
                    }

                    // 5. Tear down temporary `%recv` MOS container objects (WITHOUT freeing the
                    //    ObjectSet blocks or deadlist that `snap_ds_obj`/`target_head` just adopted!).
                    let (recv_dd_dn, _) = read_staged_or_committed_dnode(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        stage_cloned.stage_dd_obj,
                        order,
                    )?;
                    let recv_cz = order
                        .u64(recv_dd_dn.bonus(), 32)
                        .map_err(|e| parse_err(&e))?;
                    let recv_used = order
                        .u64(recv_dd_dn.bonus(), 40)
                        .map_err(|e| parse_err(&e))?;
                    let recv_comp = order
                        .u64(recv_dd_dn.bonus(), 48)
                        .map_err(|e| parse_err(&e))?;
                    let recv_uncomp = order
                        .u64(recv_dd_dn.bonus(), 56)
                        .map_err(|e| parse_err(&e))?;
                    let recv_props = order
                        .u64(recv_dd_dn.bonus(), 80)
                        .map_err(|e| parse_err(&e))?;
                    let recv_snapmap = order
                        .u64(stage_head_dn.bonus(), 32)
                        .map_err(|e| parse_err(&e))?;

                    // Unlink `"%recv"` from `target_dd.dd_child_dir_zapobj` and `target_dd.dd_clones`.
                    let (target_dd_dn, _) = read_staged_or_committed_dnode(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        stage_cloned.target_dd_obj,
                        order,
                    )?;
                    let target_cz = order
                        .u64(target_dd_dn.bonus(), 32)
                        .map_err(|e| parse_err(&e))?;
                    let target_clones = order
                        .u64(target_dd_dn.bonus(), 144)
                        .map_err(|e| parse_err(&e))?;
                    let (t_cz_dn, t_cz_ceil) = mos.object_with_ceiling(cx, target_cz)?;
                    let mut t_cz_entries = mos.zap_values(cx, target_cz)?;
                    t_cz_entries.retain(|e| e.name != b"%recv");
                    write_zap_dnode_in_mos(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        alloc,
                        target_cz,
                        Some((&t_cz_dn, t_cz_ceil)),
                        t_cz_dn.object_type(),
                        t_cz_dn.bonus_type(),
                        Vec::new(),
                        &t_cz_entries,
                        0,
                        false,
                        order,
                        new_txg,
                        staged_writes,
                    )?;
                    if target_clones != 0 {
                        let (cl_dn, cl_ceil) = mos.object_with_ceiling(cx, target_clones)?;
                        let mut cl_entries = mos.zap_values(cx, target_clones)?;
                        let key = format!("{:x}", stage_cloned.stage_head_obj).into_bytes();
                        cl_entries.retain(|e| e.name != key);
                        write_zap_dnode_in_mos(
                            cx,
                            mos,
                            &mos_meta,
                            mos_ceiling,
                            mos_dirty_dnodes,
                            alloc,
                            target_clones,
                            Some((&cl_dn, cl_ceil)),
                            cl_dn.object_type(),
                            cl_dn.bonus_type(),
                            Vec::new(),
                            &cl_entries,
                            0,
                            false,
                            order,
                            new_txg,
                            staged_writes,
                        )?;
                    }

                    // Decrement `extensible_dataset` for `%recv` head (and `%recv` dd if zapified).
                    release_dataset_block_features(&stage_entries, features)?;
                    if stage_head_dn.object_type() == DMU_OTN_ZAP_METADATA {
                        features.decrement_read("com.delphix:extensible_dataset")?;
                    }
                    if recv_dd_dn.object_type() == DMU_OTN_ZAP_METADATA {
                        features.decrement_read("com.delphix:extensible_dataset")?;
                    }
                    if let Some(ref tc) = target_crypto {
                        adjust_dsl_crypto_key_refcount(
                            cx,
                            mos,
                            &mos_meta,
                            mos_ceiling,
                            mos_dirty_dnodes,
                            alloc,
                            tc.crypto_key_obj,
                            -1,
                            order,
                            new_txg,
                            staged_writes,
                        )?;
                    }
                    for mos_id in [
                        recv_snapmap,
                        recv_cz,
                        recv_props,
                        stage_cloned.stage_head_obj,
                        stage_cloned.stage_dd_obj,
                    ] {
                        free_mos_object_completely(
                            cx,
                            mos,
                            &mos_meta,
                            mos_ceiling,
                            mos_dirty_dnodes,
                            alloc,
                            mos_id,
                            order,
                            new_txg,
                        )?;
                    }

                    // Reconcile `target_dd` space counters: `%recv`'s `dd_used` was already counted
                    // in `target_dd`'s `dd_used_child`; move it to `dd_used_snap` and subtract
                    // any force-rolled-back `old_head_freed_space`.
                    let head_drop = i128::from(target_old_unique.max(old_head_freed_space.dsize));
                    propagate_dsl_dir_space_delta(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        stage_cloned.target_dd_obj,
                        -head_drop,
                        i128::from(recv_used),
                        -i128::from(recv_used),
                        0,
                        0,
                        -i128::from(old_head_freed_space.comp),
                        -i128::from(old_head_freed_space.uncomp),
                        order,
                    )?;
                    let _ = (recv_comp, recv_uncomp);

                    if !props_owned.is_empty() {
                        apply_received_props(
                            cx,
                            mos,
                            &mos_meta,
                            mos_ceiling,
                            mos_dirty_dnodes,
                            alloc,
                            stage_cloned.target_dd_obj,
                            &props_owned,
                            order,
                            new_txg,
                            staged_writes,
                        )?;
                    }
                    Ok((snap_guid, snap_ds_obj))
                } else {
                    // Full receive promotion: strip resume ZAP keys, clear `DS_FLAG_INCONSISTENT`,
                    // and create final snapshot preserving exact `drr_toguid` & `drr_creation_time`!
                    let snapmap_obj = order
                        .u64(stage_head_dn.bonus(), 32)
                        .map_err(|e| parse_err(&e))?;
                    let snap_ds_obj =
                        allocate_object_id(cx, mos, &mos_meta, mos_ceiling, mos_dirty_dnodes, 1)?;
                    let fresh_deadlist = allocate_fresh_deadlist(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        features,
                        alloc,
                        empty_bpobj_id,
                        &BTreeSet::new(),
                        &[],
                        order,
                        new_txg,
                        staged_writes,
                    )?;

                    let snap_guid = begin_cloned.toguid;
                    let snap_fsid = derive_fsid_guid(snap_guid);
                    let mut snap_bonus = vec![0_u8; 320];
                    snap_bonus[0..8].copy_from_slice(&order.encode(stage_cloned.stage_dd_obj));
                    snap_bonus[8..16].copy_from_slice(&order.encode(stage_cloned.prev_snap_obj));
                    snap_bonus[16..24].copy_from_slice(&order.encode(stage_cloned.prev_snap_txg));
                    snap_bonus[24..32].copy_from_slice(&order.encode(stage_cloned.stage_head_obj));
                    snap_bonus[40..48].copy_from_slice(&order.encode(1));
                    snap_bonus[48..56].copy_from_slice(&order.encode(begin_cloned.creation_time));
                    snap_bonus[56..64].copy_from_slice(&order.encode(new_txg));
                    snap_bonus[64..72].copy_from_slice(&order.encode(stage_deadlist));
                    snap_bonus[72..80].copy_from_slice(&order.encode(stage_ref));
                    snap_bonus[80..88].copy_from_slice(&order.encode(stage_comp));
                    snap_bonus[88..96].copy_from_slice(&order.encode(stage_uncomp));
                    snap_bonus[96..104].copy_from_slice(&order.encode(0));
                    snap_bonus[104..112].copy_from_slice(&order.encode(snap_fsid));
                    snap_bonus[112..120].copy_from_slice(&order.encode(snap_guid));
                    snap_bonus[120..128].copy_from_slice(&order.encode(clean_flags));
                    snap_bonus[128..256].copy_from_slice(&stage_head_dn.bonus()[128..256]);

                    if snapshot_entries.is_empty() {
                        let snap_dn = Dnode::from_spec(DnodeSpec {
                            object_type: DMU_OT_DSL_DATASET,
                            bonus_type: DMU_OT_DSL_DATASET,
                            checksum_type: 0,
                            compress_type: 0,
                            flags: DNODE_FLAG_USED_BYTES,
                            order,
                            levels: 1,
                            indirect_shift: 17,
                            data_bytes: 512,
                            max_block: 0,
                            used_bytes: 0,
                            slots: 1,
                            pointers: vec![BlockPointer::hole_pointer()],
                            bonus: snap_bonus,
                            spill: None,
                        })
                        .map_err(|e| parse_err(&e))?;
                        put_dnode_in_table(
                            cx,
                            mos,
                            &mos_meta,
                            mos_ceiling,
                            mos_dirty_dnodes,
                            snap_ds_obj,
                            &snap_dn,
                        )?;
                    } else {
                        features.increment_read("com.delphix:extensible_dataset", new_txg)?;
                        write_zap_dnode_in_mos(
                            cx,
                            mos,
                            &mos_meta,
                            mos_ceiling,
                            mos_dirty_dnodes,
                            alloc,
                            snap_ds_obj,
                            None,
                            DMU_OTN_ZAP_METADATA,
                            DMU_OT_DSL_DATASET,
                            snap_bonus,
                            &snapshot_entries,
                            0,
                            false,
                            order,
                            new_txg,
                            staged_writes,
                        )?;
                    }

                    // Relink `origin_snap` next_clones entry if pool origin was linked (`head_obj -> snap_ds_obj`).
                    if stage_cloned.prev_snap_obj != 0 {
                        relink_origin_next_clone(
                            cx,
                            mos,
                            &mos_meta,
                            mos_ceiling,
                            mos_dirty_dnodes,
                            alloc,
                            stage_cloned.prev_snap_obj,
                            stage_cloned.stage_head_obj,
                            snap_ds_obj,
                            order,
                            new_txg,
                            staged_writes,
                        )?;
                    }

                    // Insert `snap_name -> snap_ds_obj` into `snapmap_obj`.
                    let (sm_dn, sm_ceil) = mos.object_with_ceiling(cx, snapmap_obj)?;
                    let mut sm_entries =
                        mos.zap_values_with_names(cx, snapmap_obj, ZapNamePolicy::AsciiUppercase)?;
                    sm_entries.push(zap_u64_entry(&snap_owned, snap_ds_obj));
                    write_zap_dnode_in_mos(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        alloc,
                        snapmap_obj,
                        Some((&sm_dn, sm_ceil)),
                        sm_dn.object_type(),
                        sm_dn.bonus_type(),
                        Vec::new(),
                        &sm_entries,
                        2,
                        false,
                        order,
                        new_txg,
                        staged_writes,
                    )?;

                    // Update `head_obj`: clear `DS_FLAG_INCONSISTENT`, strip `DS_FIELD_RESUME_*`,
                    // point `ds_prev_snap_obj = snap_ds_obj`, reset `ds_unique_bytes = 0`.
                    let mut new_head_bonus = stage_head_dn.bonus().to_vec();
                    new_head_bonus[8..16].copy_from_slice(&order.encode(snap_ds_obj));
                    new_head_bonus[16..24].copy_from_slice(&order.encode(new_txg));
                    new_head_bonus[64..72].copy_from_slice(&order.encode(fresh_deadlist));
                    new_head_bonus[96..104].copy_from_slice(&order.encode(0));
                    new_head_bonus[120..128].copy_from_slice(&order.encode(clean_flags));

                    let mut remaining_head_zap = stage_entries;
                    remaining_head_zap.retain(|e| !is_resume_zap_key(&e.name));
                    if remaining_head_zap.is_empty() {
                        // Un-zapify `head_obj` cleanly and decrement `extensible_dataset`!
                        let mut old_head_bps = Vec::new();
                        collect_non_hole_bps_from(
                            cx,
                            mos,
                            &stage_head_dn,
                            stage_head_ceil,
                            0,
                            true,
                            &mut old_head_bps,
                        )?;
                        for bp in &old_head_bps {
                            alloc.free_block_dvas(bp, new_txg)?;
                        }
                        features.decrement_read("com.delphix:extensible_dataset")?;
                        let clean_head_dn = Dnode::from_spec(DnodeSpec {
                            object_type: DMU_OT_DSL_DATASET,
                            bonus_type: DMU_OT_DSL_DATASET,
                            checksum_type: 0,
                            compress_type: 0,
                            flags: DNODE_FLAG_USED_BYTES,
                            order,
                            levels: 1,
                            indirect_shift: 17,
                            data_bytes: 512,
                            max_block: 0,
                            used_bytes: 0,
                            slots: 1,
                            pointers: vec![BlockPointer::hole_pointer()],
                            bonus: new_head_bonus,
                            spill: None,
                        })
                        .map_err(|e| parse_err(&e))?;
                        put_dnode_in_table(
                            cx,
                            mos,
                            &mos_meta,
                            mos_ceiling,
                            mos_dirty_dnodes,
                            stage_cloned.stage_head_obj,
                            &clean_head_dn,
                        )?;
                    } else {
                        write_zap_dnode_in_mos(
                            cx,
                            mos,
                            &mos_meta,
                            mos_ceiling,
                            mos_dirty_dnodes,
                            alloc,
                            stage_cloned.stage_head_obj,
                            Some((&stage_head_dn, stage_head_ceil)),
                            DMU_OTN_ZAP_METADATA,
                            DMU_OT_DSL_DATASET,
                            new_head_bonus,
                            &remaining_head_zap,
                            0,
                            false,
                            order,
                            new_txg,
                            staged_writes,
                        )?;
                    }

                    // Shift `dd_used_head` -> `dd_used_snap` on full receive snapshot.
                    propagate_dsl_dir_space_delta(
                        cx,
                        mos,
                        &mos_meta,
                        mos_ceiling,
                        mos_dirty_dnodes,
                        stage_cloned.stage_dd_obj,
                        -i128::from(stage_unique),
                        i128::from(stage_unique),
                        0,
                        0,
                        0,
                        0,
                        0,
                        order,
                    )?;

                    if !props_owned.is_empty() {
                        apply_received_props(
                            cx,
                            mos,
                            &mos_meta,
                            mos_ceiling,
                            mos_dirty_dnodes,
                            alloc,
                            stage_cloned.stage_dd_obj,
                            &props_owned,
                            order,
                            new_txg,
                            staged_writes,
                        )?;
                    }
                    Ok((snap_guid, snap_ds_obj))
                }
            },
        )
    }
}

fn resolve_staging_crypto_info(
    cx: &Cx,
    mos: &mut Objects,
    dd_obj: u64,
) -> Result<Option<ZfsDatasetCryptoInfo>> {
    let dd_dn = mos.object(cx, dd_obj)?;
    if dd_dn.object_type() != DMU_OTN_ZAP_METADATA {
        return Ok(None);
    }
    let rows = mos.zap_values(cx, dd_obj)?;
    let Some(ck_obj) = zap_optional_u64(&rows, DSL_DIR_CRYPTO_KEY_OBJ)?.filter(|&id| id != 0)
    else {
        return Ok(None);
    };
    let ck_rows = mos.zap_values(cx, ck_obj)?;
    let record = parse_dsl_crypto_key_zap(&ck_rows)?;
    Ok(Some(ZfsDatasetCryptoInfo {
        encryption_root_ddobj: dd_obj,
        encryption_root_components: Vec::new(),
        crypto_key_obj: ck_obj,
        record,
        keylocation: b"prompt".to_vec(),
    }))
}

#[allow(clippy::too_many_arguments)]
fn relink_origin_next_clone(
    cx: &Cx,
    mos: &mut Objects,
    mos_meta: &Dnode,
    mos_ceiling: u64,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    alloc: &mut PoolSpaceAllocator,
    origin_snap_obj: u64,
    old_child_obj: u64,
    new_child_obj: u64,
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<()> {
    let (o_snap_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        origin_snap_obj,
        order,
    )?;
    let o_nc_obj = order
        .u64(o_snap_dn.bonus(), 256)
        .map_err(|e| parse_err(&e))?;
    if o_nc_obj == 0 {
        return Ok(());
    }
    let (nc_dn, nc_ceil) = mos.object_with_ceiling(cx, o_nc_obj)?;
    let mut nc_entries = mos.zap_values(cx, o_nc_obj)?;
    let old_key = format!("{old_child_obj:x}").into_bytes();
    if nc_entries.iter().any(|e| e.name == old_key) {
        nc_entries.retain(|e| e.name != old_key);
        nc_entries.push(zap_u64_entry(
            format!("{new_child_obj:x}").as_bytes(),
            new_child_obj,
        ));
        write_zap_dnode_in_mos(
            cx,
            mos,
            mos_meta,
            mos_ceiling,
            mos_dirty_dnodes,
            alloc,
            o_nc_obj,
            Some((&nc_dn, nc_ceil)),
            nc_dn.object_type(),
            nc_dn.bonus_type(),
            Vec::new(),
            &nc_entries,
            0,
            false,
            order,
            new_txg,
            staged_writes,
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn apply_received_props(
    cx: &Cx,
    mos: &mut Objects,
    mos_meta: &Dnode,
    mos_ceiling: u64,
    mos_dirty_dnodes: &mut BTreeMap<u64, Vec<u8>>,
    alloc: &mut PoolSpaceAllocator,
    dd_obj: u64,
    props: &[(String, ZfsPropertySetValue)],
    order: Endian,
    new_txg: u64,
    staged_writes: &mut Vec<StagedBlockWrite>,
) -> Result<()> {
    let (dd_dn, _) = read_staged_or_committed_dnode(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        dd_obj,
        order,
    )?;
    let props_obj = order.u64(dd_dn.bonus(), 80).map_err(|e| parse_err(&e))?;
    if props_obj == 0 {
        return Ok(());
    }
    let (p_dn, p_ceil) = read_staged_or_committed_dnode(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        props_obj,
        order,
    )?;
    let mut rows = mos.zap_values(cx, props_obj)?;
    for (name, val) in props {
        let recvd_key = format!("{name}$recvd").into_bytes();
        rows.retain(|e| e.name != recvd_key);
        match val {
            ZfsPropertySetValue::Number(n) => rows.push(zap_u64_entry(&recvd_key, *n)),
            ZfsPropertySetValue::Text(t) => rows.push(zap_text_entry(&recvd_key, t)),
        }
    }
    write_zap_dnode_in_mos(
        cx,
        mos,
        mos_meta,
        mos_ceiling,
        mos_dirty_dnodes,
        alloc,
        props_obj,
        Some((&p_dn, p_ceil)),
        DMU_OT_DSL_PROPS,
        0,
        Vec::new(),
        &rows,
        0,
        false,
        order,
        new_txg,
        staged_writes,
    )?;
    Ok(())
}
