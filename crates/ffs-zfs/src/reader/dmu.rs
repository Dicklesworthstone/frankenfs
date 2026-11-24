//! Read DMU objects under one explicitly selected, verified MOS root.
//! No automatic import/TXG selection, writes, replay, or ZPL file-size guesses.

pub mod allocation;
mod features;
mod holes;
pub mod properties;
pub mod scrub;
mod seek;
mod zap;
pub mod zil;
pub mod zpl;
pub mod zvol;

pub(super) use features::supported_label_feature;

use super::{
    BlockPointer, Cx, Endian, FfsError, Leaf, Pool, Result, RootBlock, VdevConfig, checkpoint,
    corrupt, parse, unsupported,
};
use crate::crypto::{
    ZfsDatasetCryptoInfo, ZfsKeyMaterial, ZfsKeyRing, ZfsKeyStatus, parse_dsl_crypto_key_zap,
};
use ffs_ondisk::zfs::crypto::{
    DSL_DATASET_IVSET_GUID, DSL_DIR_CRYPTO_KEY_OBJ, UnwrappedDslKey, bp_crypt_mac,
    compute_authenticated_block_mac, compute_indirect_block_mac, ct_eq, decrypt_regular_block,
    verify_objset_macs,
};
use ffs_ondisk::zfs::decompress;
use ffs_ondisk::zfs_dmu::{
    DMU_OT_DNODE, DMU_OT_OBJSET, DNODE_BLOCK_BYTES, DNODE_BYTES, Dnode, ObjectSet, ZapEntry,
    dnode_at,
};
use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;

const CACHE_BYTES: usize = 16 * 1024 * 1024;
const CACHE_BLOCKS: usize = 32;
const MAX_READ_BYTES: usize = 16 * 1024 * 1024;
const MAX_OBJECT: u64 = 1_u64 << 48;

#[derive(Clone)]
struct CheckedBlock {
    bytes: Arc<Vec<u8>>,
    order: Endian,
    birth: u64,
}
struct Object {
    node: Dnode,
    /// A dnode cannot reference a block younger than its containing block.
    ceiling: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct DatasetCryptoContext {
    pub(crate) info: ZfsDatasetCryptoInfo,
    pub(crate) raw_scrub_only: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct RecvStagingDataset {
    pub(crate) directory_object: u64,
    pub(crate) head_object: u64,
    pub(crate) is_pct_recv_child: bool,
    pub(crate) prev_snap_obj: u64,
    pub(crate) prev_snap_txg: u64,
    pub(crate) objectset_kind: u64,
    pub(crate) head_zap: Vec<ffs_ondisk::zfs_zap::Entry>,
}

/// Root/configuration ownership never leaves this object. Cache keys include
/// the complete block pointer and caches never cross selected root lifetimes.
pub struct Objects {
    pool: Pool,
    config: VdevConfig,
    pub txg: u64,
    root_birth: u64,
    meta: Dnode,
    cache: VecDeque<(BlockPointer, CheckedBlock)>,
    cached_bytes: usize,
    keyring: ZfsKeyRing,
    crypto: Option<Arc<DatasetCryptoContext>>,
}

impl Leaf {
    pub fn objects(&self, cx: &Cx, label: usize, slot: usize, pool_guid: u64) -> Result<Objects> {
        let root = self.root(cx, label, slot, pool_guid)?;
        Objects::from_root(cx, Pool::from(self.clone()), root)
    }

    pub fn import_objects(&self, cx: &Cx, expected_pool_guid: Option<u64>) -> Result<Objects> {
        let (_, _, root) = self.import_active(cx, expected_pool_guid)?;
        Objects::from_root(cx, Pool::from(self.clone()), root)
    }
}

impl Pool {
    pub fn objects(&self, cx: &Cx, label: usize, slot: usize, pool_guid: u64) -> Result<Objects> {
        if let Some(leaf) = self.standalone_leaf() {
            return leaf.objects(cx, label, slot, pool_guid);
        }
        let root = self.root(cx, label, slot, pool_guid)?;
        Objects::from_root(cx, self.clone(), root)
    }

    pub fn import_objects(&self, cx: &Cx, expected_pool_guid: Option<u64>) -> Result<Objects> {
        if let Some(leaf) = self.standalone_leaf() {
            return leaf.import_objects(cx, expected_pool_guid);
        }
        let (_, _, root) = self.import_active(cx, expected_pool_guid)?;
        Objects::from_root(cx, self.clone(), root)
    }
}

pub(crate) type CheckedDmuBlock = (Arc<Vec<u8>>, Endian, u64);

impl Objects {
    #[must_use]
    pub const fn pool_guid(&self) -> u64 {
        self.config.pool_guid
    }

    /// Return the pool name recorded in the member labels, falling back to `"pool"`.
    pub fn pool_name(&self, cx: &Cx) -> Result<String> {
        if let Some(leaf) = self.pool.leaves().first() {
            for idx in 0..4 {
                if let Ok(lbl) = leaf.label(cx, idx)
                    && let Some(name) = lbl.config.text("name")
                    && !name.is_empty()
                {
                    return Ok(name.to_owned());
                }
            }
        }
        Ok("pool".to_owned())
    }

    #[must_use]
    pub(crate) const fn meta_dnode(&self) -> &Dnode {
        &self.meta
    }

    #[must_use]
    pub(crate) const fn root_birth_txg(&self) -> u64 {
        self.root_birth
    }

    /// Attach a shared keyring to this MOS / object-set view.
    #[must_use]
    pub fn with_keyring(mut self, keyring: ZfsKeyRing) -> Self {
        self.keyring = keyring;
        self
    }

    /// Borrow the keyring attached to this view.
    #[must_use]
    pub const fn keyring(&self) -> &ZfsKeyRing {
        &self.keyring
    }

    #[must_use]
    pub(crate) fn is_raw_scrub_keyless(&self) -> bool {
        self.crypto.as_ref().is_some_and(|ctx| {
            ctx.raw_scrub_only && self.keyring.get(ctx.info.encryption_root_ddobj).is_none()
        })
    }

    /// Discover native `com.datto:encryption` metadata for `components` from this MOS view.
    pub fn dataset_crypto_info(
        &mut self,
        cx: &Cx,
        components: &[Vec<u8>],
    ) -> Result<Option<ZfsDatasetCryptoInfo>> {
        checkpoint(cx)?;
        let all_datasets = self.datasets(cx)?;
        let dataset = all_datasets
            .iter()
            .find(|row| row.components == components)
            .ok_or_else(|| FfsError::NotFound("ZFS dataset".into()))?;
        self.dataset_crypto_info_from_dir(cx, dataset.directory_object, &all_datasets)
    }

    pub(crate) fn dataset_crypto_info_for_dir(
        &mut self,
        cx: &Cx,
        directory_object: u64,
    ) -> Result<Option<ZfsDatasetCryptoInfo>> {
        checkpoint(cx)?;
        let all_datasets = self.datasets(cx)?;
        self.dataset_crypto_info_from_dir(cx, directory_object, &all_datasets)
    }

    fn dataset_crypto_info_from_dir(
        &mut self,
        cx: &Cx,
        directory_object: u64,
        all_datasets: &[Dataset],
    ) -> Result<Option<ZfsDatasetCryptoInfo>> {
        let dir = self.load(cx, directory_object)?;
        if dir.node.object_type() != 196 {
            return Ok(None);
        }
        let dir_entries = self.zap_values(cx, directory_object)?;
        let Some(entry) = dir_entries
            .iter()
            .find(|row| row.name == DSL_DIR_CRYPTO_KEY_OBJ)
        else {
            return Ok(None);
        };
        let crypto_key_obj = entry.scalar().map_err(|error| parse(&error))?;
        if crypto_key_obj == 0 {
            return Ok(None);
        }
        let key_dnode = self.object(cx, crypto_key_obj)?;
        if key_dnode.object_type() != 196 {
            return Err(corrupt("dsl_crypto_key object has non-ZAP DMU type"));
        }
        let key_entries = self.zap_values(cx, crypto_key_obj)?;
        let record = parse_dsl_crypto_key_zap(&key_entries)?;
        let root_ddobj = record.root_ddobj;
        let root_dir = self.load(cx, root_ddobj)?;
        if !matches!(root_dir.node.object_type(), 12 | 196)
            || root_dir.node.bonus_type() != 12
            || root_dir.node.bonus().len() != 256
        {
            return Err(corrupt("DSL_CRYPTO_ROOT_DDOBJ is not a valid dsl_dir"));
        }
        let encryption_root_components = all_datasets
            .iter()
            .find(|row| row.directory_object == root_ddobj)
            .map(|row| row.components.clone())
            .ok_or_else(|| corrupt("DSL_CRYPTO_ROOT_DDOBJ absent from DSL directory hierarchy"))?;
        let root_props_obj = root_dir
            .node
            .order()
            .u64(root_dir.node.bonus(), 80)
            .map_err(|error| parse(&error))?;
        let mut keylocation = b"prompt".to_vec();
        if root_props_obj > 1
            && let Ok(prop_entries) = self.zap_values(cx, root_props_obj)
            && let Some(loc_entry) = prop_entries.iter().find(|row| row.name == b"keylocation")
            && loc_entry.integer_bytes == 1
            && loc_entry.values.last() == Some(&0)
        {
            let mut decoded = Vec::with_capacity(loc_entry.values.len().saturating_sub(1));
            let mut valid = true;
            for &val in &loc_entry.values[..loc_entry.values.len() - 1] {
                match u8::try_from(val) {
                    Ok(byte) if byte != 0 => decoded.push(byte),
                    _ => {
                        valid = false;
                        break;
                    }
                }
            }
            if valid && !decoded.is_empty() {
                keylocation = decoded;
            }
        }
        Ok(Some(ZfsDatasetCryptoInfo {
            encryption_root_ddobj: root_ddobj,
            encryption_root_components,
            crypto_key_obj,
            record,
            keylocation,
        }))
    }

    /// Unwrap and load the dataset encryption key for `components` into this view's keyring.
    pub fn load_key(
        &mut self,
        cx: &Cx,
        components: &[Vec<u8>],
        material: &ZfsKeyMaterial,
    ) -> Result<ZfsDatasetCryptoInfo> {
        let info = self.dataset_crypto_info(cx, components)?.ok_or_else(|| {
            FfsError::Format("cannot load key for an unencrypted ZFS dataset".into())
        })?;
        self.keyring.load_key(&info, material)?;
        Ok(info)
    }

    /// Unload the encryption key for `components`'s encryption root from this view's keyring.
    pub fn unload_key(&mut self, cx: &Cx, components: &[Vec<u8>]) -> Result<bool> {
        let info = self.dataset_crypto_info(cx, components)?.ok_or_else(|| {
            FfsError::Format("cannot unload key for an unencrypted ZFS dataset".into())
        })?;
        let removed = self.keyring.unload_key(info.encryption_root_ddobj)?;
        self.clear_cache();
        Ok(removed)
    }

    pub(super) fn clear_cache(&mut self) {
        self.cache.clear();
        self.cached_bytes = 0;
    }

    /// Report runtime `ZfsKeyStatus` for `components`.
    pub fn key_status(&mut self, cx: &Cx, components: &[Vec<u8>]) -> Result<ZfsKeyStatus> {
        let info = self.dataset_crypto_info(cx, components)?;
        Ok(self
            .keyring
            .key_status(info.as_ref().map(|item| item.encryption_root_ddobj)))
    }

    #[must_use]
    pub(crate) fn open_objectset_view(&self, meta: Dnode, root_birth: u64, txg: u64) -> Self {
        self.open_objectset_view_with_crypto(meta, root_birth, txg, None)
    }

    #[must_use]
    pub(crate) fn open_objectset_view_with_crypto(
        &self,
        meta: Dnode,
        root_birth: u64,
        txg: u64,
        crypto: Option<Arc<DatasetCryptoContext>>,
    ) -> Self {
        Self {
            pool: self.pool.clone(),
            config: self.config.clone(),
            txg,
            root_birth,
            meta,
            cache: VecDeque::new(),
            cached_bytes: 0,
            keyring: self.keyring.clone(),
            crypto,
        }
    }

    pub(crate) fn read_dataset_objset_block_raw(
        &mut self,
        cx: &Cx,
        bp: &BlockPointer,
        ceiling: u64,
        verify_key: Option<&UnwrappedDslKey>,
        allow_protected_keyless: bool,
    ) -> Result<CheckedDmuBlock> {
        let blk =
            self.read_dataset_objset_block(cx, bp, ceiling, verify_key, allow_protected_keyless)?;
        Ok((blk.bytes, blk.order, blk.birth))
    }

    pub(crate) fn checked_raw(
        &mut self,
        cx: &Cx,
        bp: &BlockPointer,
        kind: u8,
        level: u8,
        size: usize,
        ceiling: u64,
    ) -> Result<Option<CheckedDmuBlock>> {
        Ok(self
            .checked(cx, bp, kind, level, size, ceiling)?
            .map(|b| (b.bytes, b.order, b.birth)))
    }

    pub(crate) fn object_with_ceiling(&mut self, cx: &Cx, number: u64) -> Result<(Dnode, u64)> {
        let obj = self.load(cx, number)?;
        Ok((obj.node, obj.ceiling))
    }

    pub(crate) fn object_data_block(
        &mut self,
        cx: &Cx,
        node: &Dnode,
        ceiling: u64,
        block_id: u64,
    ) -> Result<Option<CheckedDmuBlock>> {
        let obj = Object {
            node: node.clone(),
            ceiling,
        };
        Ok(self
            .data_block(cx, &obj, block_id)?
            .map(|b| (b.bytes, b.order, b.birth)))
    }

    pub(super) fn clone_mos(&self) -> Self {
        Self {
            pool: self.pool.clone(),
            config: self.config.clone(),
            txg: self.txg,
            root_birth: self.root_birth,
            meta: self.meta.clone(),
            cache: VecDeque::new(),
            cached_bytes: 0,
            keyring: self.keyring.clone(),
            crypto: self.crypto.clone(),
        }
    }

    #[must_use]
    pub(crate) const fn config(&self) -> &VdevConfig {
        &self.config
    }

    /// Read and physically verify (checksum/protected physical checksum) a block's
    /// on-disk bytes WITHOUT decompressing or decrypting — used by `--compressed`
    /// and keyless `--raw` native sends.
    pub(crate) fn read_verified_physical_block(
        &self,
        cx: &Cx,
        bp: &BlockPointer,
    ) -> Result<Vec<u8>> {
        checkpoint(cx)?;
        Ok(self.pool.read_raw_block(cx, &self.config, bp)?.bytes)
    }

    /// Read and validate an indirect block (`level > 0`), verifying indirect MACs
    /// when inside an encrypted dataset.
    pub(crate) fn read_indirect_block(
        &mut self,
        cx: &Cx,
        bp: &BlockPointer,
        kind: u8,
        level: u8,
        size: usize,
        ceiling: u64,
    ) -> Result<Option<(Vec<u8>, Endian, u64)>> {
        Ok(self
            .checked(cx, bp, kind, level, size, ceiling)?
            .map(|b| ((*b.bytes).clone(), b.order, b.birth)))
    }

    /// Read and verify a logical level-0 block (decrypting if keyed, decompressing
    /// if compressed).
    pub(crate) fn read_logical_block(
        &mut self,
        cx: &Cx,
        bp: &BlockPointer,
        kind: u8,
        size: usize,
        ceiling: u64,
    ) -> Result<Option<(Vec<u8>, Endian, u64)>> {
        Ok(self
            .checked(cx, bp, kind, 0, size, ceiling)?
            .map(|b| ((*b.bytes).clone(), b.order, b.birth)))
    }

    /// Read `com.datto:ivset_guid` from a zapified `dsl_dataset` object (`DMU_OTN_ZAP_METADATA=196`).
    pub(crate) fn dataset_ivset_guid(&mut self, cx: &Cx, ds_obj: u64) -> Result<Option<u64>> {
        let node = self.object(cx, ds_obj)?;
        if node.object_type() != 196 {
            return Ok(None);
        }
        for entry in self.zap_values(cx, ds_obj)? {
            if entry.name == DSL_DATASET_IVSET_GUID {
                return Ok(Some(entry.scalar().map_err(|error| parse(&error))?));
            }
        }
        Ok(None)
    }

    /// Inspect whether a `DS_FLAG_INCONSISTENT` dataset is a genuine private resumable
    /// receive staging dataset (`%recv` child or zapified `com.delphix:resume_toguid`).
    fn is_resumable_recv_staging(
        &mut self,
        cx: &Cx,
        components: &[Vec<u8>],
        head_obj: u64,
        head_node: &Dnode,
    ) -> Result<bool> {
        if components.last().is_some_and(|c| c == b"%recv") {
            return Ok(true);
        }
        if head_node.object_type() != 196 {
            return Ok(false);
        }
        for entry in self.zap_values(cx, head_obj)? {
            if entry.name == b"com.delphix:resume_toguid" {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Locate an active private resumable receive staging dataset for `target_components`:
    /// either `target/%recv` (for an incremental receive into an existing dataset) OR
    /// `target` itself when marked `DS_FLAG_INCONSISTENT` with `com.delphix:resume_toguid`
    /// (for a new full receive).
    pub(crate) fn find_recv_staging_dataset(
        &mut self,
        cx: &Cx,
        target_components: &[Vec<u8>],
    ) -> Result<Option<RecvStagingDataset>> {
        checkpoint(cx)?;
        let pool_dir = self.zap(cx, 1)?;
        let root_dd = pool_dir
            .iter()
            .find(|entry| entry.name == b"root_dataset")
            .ok_or_else(|| corrupt("MOS object directory lacks root_dataset"))?
            .value;

        let mut cur_dd = root_dd;
        for comp in target_components {
            let dir_obj = self.load(cx, cur_dd)?;
            let children_zap = dir_obj
                .node
                .order()
                .u64(dir_obj.node.bonus(), 32)
                .map_err(|e| parse(&e))?;
            if children_zap == 0 {
                return Ok(None);
            }
            let Some(child_entry) = self
                .zap(cx, children_zap)?
                .into_iter()
                .find(|e| e.name.as_slice() == comp.as_slice())
            else {
                return Ok(None);
            };
            cur_dd = child_entry.value;
        }

        // First check for hidden `%recv` child under `cur_dd` (incremental receive staging).
        let target_dir = self.load(cx, cur_dd)?;
        let target_children = target_dir
            .node
            .order()
            .u64(target_dir.node.bonus(), 32)
            .map_err(|e| parse(&e))?;
        let mut candidate = if target_children != 0
            && let Some(recv_child) = self
                .zap(cx, target_children)?
                .into_iter()
                .find(|e| e.name == b"%recv")
        {
            Some((recv_child.value, true))
        } else {
            None
        };

        // Otherwise check whether `cur_dd` itself is an inconsistent full-receive target.
        if candidate.is_none() {
            let head_obj = target_dir
                .node
                .order()
                .u64(target_dir.node.bonus(), 8)
                .map_err(|e| parse(&e))?;
            if head_obj != 0 {
                let ds = self.load(cx, head_obj)?;
                let flags = ds
                    .node
                    .order()
                    .u64(ds.node.bonus(), 120)
                    .map_err(|e| parse(&e))?;
                if flags & 0x1 != 0
                    && self.is_resumable_recv_staging(cx, target_components, head_obj, &ds.node)?
                {
                    candidate = Some((cur_dd, false));
                }
            }
        }

        let Some((stage_dd, is_pct_recv_child)) = candidate else {
            return Ok(None);
        };
        let stage_dir = self.load(cx, stage_dd)?;
        let dir_order = stage_dir.node.order();
        let head_obj = dir_order
            .u64(stage_dir.node.bonus(), 8)
            .map_err(|e| parse(&e))?;
        if head_obj == 0 {
            return Err(corrupt("staging receive DSL directory has no head dataset"));
        }
        let ds = self.load(cx, head_obj)?;
        let ds_order = ds.node.order();
        let prev_snap_obj = ds_order.u64(ds.node.bonus(), 8).map_err(|e| parse(&e))?;
        let prev_snap_txg = ds_order.u64(ds.node.bonus(), 16).map_err(|e| parse(&e))?;
        let root_bp =
            BlockPointer::parse(&ds.node.bonus()[128..256], ds_order).map_err(|e| parse(&e))?;
        let raw_os = self.read_dataset_objset_block(cx, &root_bp, ds.ceiling, None, true)?;
        let os = ObjectSet::parse(&raw_os.bytes, raw_os.order).map_err(|e| parse(&e))?;
        let head_zap = if ds.node.object_type() == 196 {
            self.zap_values(cx, head_obj)?
        } else {
            Vec::new()
        };
        Ok(Some(RecvStagingDataset {
            directory_object: stage_dd,
            head_object: head_obj,
            is_pct_recv_child,
            prev_snap_obj,
            prev_snap_txg,
            objectset_kind: os.kind,
            head_zap,
        }))
    }

    pub(crate) fn from_root(cx: &Cx, pool: Pool, root: RootBlock) -> Result<Self> {
        let objectset = ObjectSet::parse(&root.data, root.uberblock.root.payload_order())
            .map_err(|error| parse(&error))?;
        if objectset.kind != 1 {
            return Err(corrupt("selected object set is not the MOS"));
        }
        let config = root.config;
        let reflow_info = root.uberblock.raidz_reflow_info;
        let pool = pool
            .retain_striped_topology(cx, &config)?
            .retain_advanced_topology(cx, &config, reflow_info)?;
        checkpoint(cx)?;
        let mut view = Self {
            pool,
            config,
            txg: root.uberblock.txg,
            root_birth: root.uberblock.root.birth(),
            meta: objectset.meta,
            cache: VecDeque::new(),
            cached_bytes: 0,
            keyring: ZfsKeyRing::new(),
            crypto: None,
        };
        // Label features only describe what is needed to bootstrap the MOS.
        // Keep this view private until its complete native feature catalogs
        // admit reads. Every explicit/automatic leaf/group open joins here.
        view.admit_features(cx)?;
        // When `com.delphix:device_removal` is active in the labels, eagerly
        // load MOS indirect mapping tables so subsequent dataset/object reads
        // resolve removed-vdev DVAs transparently.
        if view
            .config
            .read_features
            .iter()
            .any(|f| f == "com.delphix:device_removal")
            && let Ok(mos_cfg) = view.load_mos_config_nvlist(cx)
        {
            let indirect_maps = crate::reader::pool::indirect::IndirectVdevMap::load_from_mos(
                cx, &mut view, &mos_cfg,
            )?;
            view.pool.set_indirect_maps(indirect_maps);
        }
        checkpoint(cx)?;
        Ok(view)
    }

    /// Load and parse the MOS `"config"` packed nvlist object (if present).
    pub fn load_mos_config_nvlist(&mut self, cx: &Cx) -> Result<ffs_ondisk::zfs::nvlist::NvList> {
        checkpoint(cx)?;
        let directory = self.zap_values(cx, 1)?;
        let config_row = directory
            .iter()
            .find(|row| row.name == b"config")
            .ok_or_else(|| corrupt("MOS directory missing config entry"))?;
        let config_id = config_row.scalar().map_err(|e| parse(&e))?;
        let obj = self.load(cx, config_id)?;
        if obj.node.object_type() != 3 || obj.node.bonus_type() != 4 || obj.node.bonus().len() != 8
        {
            return Err(corrupt("MOS config is not a packed nvlist with size bonus"));
        }
        let length = obj
            .node
            .order()
            .u64(obj.node.bonus(), 0)
            .map_err(|e| parse(&e))?;
        if !(1..=ffs_ondisk::zfs::LABEL_CONFIG_BYTES as u64).contains(&length) {
            return Err(unsupported("MOS config nvlist length out of bounds"));
        }
        let mut bytes = Vec::with_capacity(length as usize);
        let bsize = obj.node.data_bytes() as u64;
        let blocks = length.div_ceil(bsize);
        for bid in 0..blocks {
            let blk = self
                .data_block(cx, &obj, bid)?
                .ok_or_else(|| corrupt("MOS config contains a hole"))?;
            let need = (length - bytes.len() as u64).min(bsize) as usize;
            bytes.extend_from_slice(&blk.bytes[..need]);
        }
        ffs_ondisk::zfs::nvlist::NvList::parse_exact(&bytes).map_err(|e| parse(&e))
    }

    /// Decode a dataset root `DMU_OT_OBJSET` block pointer from the MOS.
    ///
    /// When `verify_key` is `Some`, the pointer MUST be protected (`BP_IS_PROTECTED`)
    /// and its `os_portable_mac`/`os_local_mac` are authenticated with `verify_key`.
    /// When `verify_key` is `None` and `allow_protected_keyless` is `true` (e.g.,
    /// keyless `datasets`/`snapshots`/`raw_scrub` inspection), protected objset
    /// blocks are physically checksummed and decompressed without needing the key.
    fn read_dataset_objset_block(
        &mut self,
        cx: &Cx,
        bp: &BlockPointer,
        ceiling: u64,
        verify_key: Option<&UnwrappedDslKey>,
        allow_protected_keyless: bool,
    ) -> Result<CheckedBlock> {
        checkpoint(cx)?;
        if bp.hole() {
            return Err(corrupt("dataset object-set root is a hole"));
        }
        if bp.protected() {
            if verify_key.is_none() && !allow_protected_keyless {
                return Err(FfsError::PermissionDenied);
            }
            if bp.embedded()
                || bp.birth() == 0
                || bp.birth() > ceiling
                || bp.birth() > self.txg
                || bp.level() != 0
                || bp.object_type() != DMU_OT_OBJSET
                || !matches!(bp.logical_bytes(), 2048 | 4096)
            {
                return Err(corrupt(
                    "protected dataset object-set block pointer has invalid geometry or birth",
                ));
            }
            let raw = self.pool.read_raw_block(cx, &self.config, bp)?.bytes;
            let logical = decompress(&raw, bp.compression(), bp.logical_bytes())
                .map_err(|error| parse(&error))?;
            if logical.len() != bp.logical_bytes() {
                return Err(corrupt("decoded protected objset has the wrong length"));
            }
            if let Some(key) = verify_key {
                verify_objset_macs(&logical, bp.payload_order(), &key.hmac_key, key.version)
                    .map_err(|error| parse(&error))?;
            }
            checkpoint(cx)?;
            return Ok(CheckedBlock {
                bytes: Arc::new(logical),
                order: bp.payload_order(),
                birth: bp.birth(),
            });
        }
        if verify_key.is_some() {
            return Err(corrupt(
                "encrypted dataset root block pointer lacks BP_IS_PROTECTED",
            ));
        }
        self.checked(cx, bp, DMU_OT_OBJSET, 0, bp.logical_bytes(), ceiling)?
            .ok_or_else(|| corrupt("dataset object-set root is a hole"))
    }
}

impl Objects {
    /// Check the interpretation of an already checksum-protected pointer.
    /// Returns false for a native hole. This does not verify a data payload:
    /// allocation queries inspect leaf pointers without reading file contents.
    pub(crate) fn validate_pointer(
        &self,
        bp: &BlockPointer,
        kind: u8,
        level: u8,
        size: usize,
        ceiling: u64,
    ) -> Result<bool> {
        if bp.embedded() && bp.protected() {
            return Err(corrupt("embedded DMU block cannot be protected"));
        }
        if bp.birth() > ceiling || bp.birth() > self.txg {
            return Err(corrupt(
                "DMU child birth is newer than its parent or selected TXG",
            ));
        }
        if bp.hole() {
            if bp.protected() {
                return Err(corrupt("hole DMU pointer cannot be protected"));
            }
            self.validate_hole(bp, kind, level, size)?;
            return Ok(false);
        }
        if self.crypto.is_some() {
            if !bp.protected() {
                return Err(corrupt(
                    "unprotected non-hole block pointer inside encrypted dataset",
                ));
            }
            if bp.embedded() {
                return Err(corrupt(
                    "embedded block pointer is forbidden inside encrypted dataset",
                ));
            }
        } else if bp.protected() {
            return Err(unsupported(
                "encrypted DMU blocks need their native pipeline",
            ));
        }
        if bp.birth() == 0
            || bp.level() != level
            || bp.object_type() != kind
            || bp.logical_bytes() != size
        {
            return Err(corrupt(
                "DMU block type, level or size disagrees with its dnode",
            ));
        }
        if bp.embedded()
            && (self.config.version != 5000
                || !self
                    .config
                    .read_features
                    .iter()
                    .any(|name| name == "com.delphix:embedded_data"))
        {
            return Err(unsupported(
                "embedded DMU block is not declared by the selected label features",
            ));
        }
        Ok(true)
    }

    /// Validate interpretation BEFORE cache lookup and physical I/O. Neither a
    /// valid checksum nor a cached byte string authorizes the wrong level/type.
    fn checked(
        &mut self,
        cx: &Cx,
        bp: &BlockPointer,
        kind: u8,
        level: u8,
        size: usize,
        ceiling: u64,
    ) -> Result<Option<CheckedBlock>> {
        checkpoint(cx)?;
        if let Some(ctx) = &self.crypto
            && !ctx.raw_scrub_only
            && self.keyring.get(ctx.info.encryption_root_ddobj).is_none()
        {
            // Immediate fail-closed revocation if key was unloaded while view is open.
            self.cache.clear();
            self.cached_bytes = 0;
            return Err(FfsError::PermissionDenied);
        }
        if !self.validate_pointer(bp, kind, level, size, ceiling)? {
            return Ok(None);
        }
        if let Some(index) = self.cache.iter().position(|(key, _)| key == bp) {
            let item = self
                .cache
                .remove(index)
                .ok_or_else(|| corrupt("missing DMU cache entry"))?;
            let block = item.1.clone();
            self.cache.push_back(item);
            checkpoint(cx)?;
            return Ok(Some(block));
        }
        // The pointer came from a checksum-verified dnode/indirect block.
        // Embedded words are payload, not DVAs or an independent checksum.
        let bytes = if bp.embedded() {
            bp.decode_embedded().map_err(|error| parse(&error))?
        } else if bp.protected() {
            let ctx = self
                .crypto
                .as_ref()
                .ok_or_else(|| unsupported("encrypted DMU blocks need their native pipeline"))?
                .clone();
            let raw = self.pool.read_raw_block(cx, &self.config, bp)?.bytes;
            if bp.level() > 0 {
                // Indirect blocks are authenticated keylessly via SHA-512 over child blkptr_auth_bufs.
                let logical = decompress(&raw, bp.compression(), bp.logical_bytes())
                    .map_err(|error| parse(&error))?;
                let expected = compute_indirect_block_mac(
                    &logical,
                    bp.payload_order(),
                    ctx.info.record.version,
                )
                .map_err(|error| parse(&error))?;
                if !ct_eq(&expected, &bp_crypt_mac(bp)) {
                    return Err(corrupt("protected indirect block MAC mismatch"));
                }
                logical
            } else if bp.is_encrypted() {
                if let Some(key) = self.keyring.get(ctx.info.encryption_root_ddobj) {
                    decrypt_regular_block(&key, bp, &raw).map_err(|error| parse(&error))?
                } else if ctx.raw_scrub_only && bp.object_type() == DMU_OT_DNODE {
                    // OpenZFS leaves dnode cores, child BPs, and spill BPs plaintext so locked
                    // pools can scrub indirect MACs and physical checksums keylessly.
                    if bp.compression() != 2 || raw.len() != DNODE_BLOCK_BYTES {
                        return Err(corrupt(
                            "encrypted DMU_OT_DNODE block must be uncompressed 16 KiB",
                        ));
                    }
                    raw
                } else {
                    return Err(FfsError::PermissionDenied);
                }
            } else if bp.object_type() == DMU_OT_OBJSET {
                let logical = decompress(&raw, bp.compression(), bp.logical_bytes())
                    .map_err(|error| parse(&error))?;
                if let Some(key) = self.keyring.get(ctx.info.encryption_root_ddobj) {
                    verify_objset_macs(&logical, bp.payload_order(), &key.hmac_key, key.version)
                        .map_err(|error| parse(&error))?;
                } else if !ctx.raw_scrub_only {
                    return Err(FfsError::PermissionDenied);
                }
                logical
            } else {
                // Authenticated-only level-0 block (e.g. userused/groupused/projectused).
                if let Some(key) = self.keyring.get(ctx.info.encryption_root_ddobj) {
                    let expected = compute_authenticated_block_mac(&key.hmac_key, &raw);
                    if !ct_eq(&expected, &bp_crypt_mac(bp)) {
                        return Err(corrupt("authenticated DMU block MAC mismatch"));
                    }
                } else if !ctx.raw_scrub_only {
                    return Err(FfsError::PermissionDenied);
                }
                decompress(&raw, bp.compression(), bp.logical_bytes())
                    .map_err(|error| parse(&error))?
            }
        } else {
            self.pool.read_block(cx, &self.config, bp)?.bytes
        };
        if bytes.len() != size {
            return Err(corrupt("decoded DMU block has the wrong length"));
        }
        checkpoint(cx)?;
        let block = CheckedBlock {
            bytes: Arc::new(bytes),
            order: bp.payload_order(),
            birth: bp.birth(),
        };
        while self.cached_bytes + size > CACHE_BYTES || self.cache.len() >= CACHE_BLOCKS {
            let Some((_, old)) = self.cache.pop_front() else {
                break;
            };
            self.cached_bytes -= old.bytes.len();
        }
        if size <= CACHE_BYTES {
            self.cached_bytes += size;
            self.cache.push_back((bp.clone(), block.clone()));
        }
        checkpoint(cx)?;
        Ok(Some(block))
    }

    pub(super) fn read_zil_block(
        &self,
        cx: &Cx,
        bp: &BlockPointer,
    ) -> Result<Option<(Vec<u8>, Endian)>> {
        checkpoint(cx)?;
        if bp.hole() {
            return Ok(None);
        }
        let block = self.pool.read_block(cx, &self.config, bp)?;
        Ok(Some((block.bytes, bp.payload_order())))
    }

    fn data_block(&mut self, cx: &Cx, object: &Object, id: u64) -> Result<Option<CheckedBlock>> {
        let route = object.node.route(id).map_err(|error| parse(&error))?;
        let mut bp = object.node.pointers()[route[0]].clone();
        let mut ceiling = object.ceiling;
        for (depth, _) in route.iter().enumerate() {
            let level = object.node.levels() - 1 - depth as u8;
            let size = if level == 0 {
                object.node.data_bytes()
            } else {
                object.node.indirect_bytes()
            };
            let Some(block) =
                self.checked(cx, &bp, object.node.object_type(), level, size, ceiling)?
            else {
                return Ok(None); // Sparse subtree: do not issue reads for invented children.
            };
            if level == 0 {
                return Ok(Some(block));
            }
            let at = route[depth + 1] * 128;
            bp = BlockPointer::parse(&block.bytes[at..at + 128], block.order)
                .map_err(|error| parse(&error))?;
            ceiling = block.birth;
        }
        Err(corrupt("DMU traversal did not reach a data block"))
    }

    fn load(&mut self, cx: &Cx, number: u64) -> Result<Object> {
        checkpoint(cx)?;
        if number >= MAX_OBJECT {
            return Err(corrupt("DMU object ID exceeds native 48-bit range"));
        }
        let meta = Object {
            node: self.meta.clone(),
            ceiling: self.root_birth,
        };
        if number == 0 {
            return Ok(meta);
        }
        let block_id = number / (DNODE_BLOCK_BYTES / DNODE_BYTES) as u64;
        if block_id > self.meta.max_block() {
            return Err(FfsError::NotFound(format!("ZFS object {number}")));
        }
        let block = self.data_block(cx, &meta, block_id)?.ok_or_else(|| {
            FfsError::NotFound(format!("ZFS object {number} lies in a sparse dnode block"))
        })?;
        let slot = (number % (DNODE_BLOCK_BYTES / DNODE_BYTES) as u64) as usize;
        let node = dnode_at(&block.bytes, slot, block.order)
            .map_err(|error| parse(&error))?
            .ok_or_else(|| FfsError::NotFound(format!("ZFS object {number} is unallocated")))?;
        checkpoint(cx)?;
        Ok(Object {
            node,
            ceiling: block.birth,
        })
    }

    pub fn object(&mut self, cx: &Cx, number: u64) -> Result<Dnode> {
        self.load(cx, number).map(|object| object.node)
    }

    /// Explicit raw DMU range, not a ZPL file read: dn_maxblkid is allocation
    /// geometry, not EOF. Requests outside it are errors, never inferred EOF.
    pub fn read(&mut self, cx: &Cx, number: u64, start: u64, size: usize) -> Result<Vec<u8>> {
        checkpoint(cx)?;
        if size > MAX_READ_BYTES {
            return Err(unsupported("DMU range exceeds 16 MiB read budget"));
        }
        let object = self.load(cx, number)?;
        let end = start
            .checked_add(size as u64)
            .ok_or_else(|| corrupt("DMU read range overflow"))?;
        let block_bytes = object.node.data_bytes() as u64;
        if size != 0 && (end - 1) / block_bytes > object.node.max_block() {
            return Err(corrupt("raw DMU range exceeds allocated object geometry"));
        }
        let mut result = Vec::new();
        result
            .try_reserve_exact(size)
            .map_err(|error| FfsError::Io(std::io::Error::other(error)))?;
        result.resize(size, 0);
        let mut done = 0;
        while done < size {
            checkpoint(cx)?;
            let logical = start + done as u64;
            let id = logical / block_bytes;
            let within = (logical % block_bytes) as usize;
            let count = (size - done).min(object.node.data_bytes() - within);
            if let Some(block) = self.data_block(cx, &object, id)? {
                result[done..done + count].copy_from_slice(&block.bytes[within..within + count]);
            }
            done += count;
        }
        checkpoint(cx)?;
        Ok(result)
    }

    pub fn zap(&mut self, cx: &Cx, number: u64) -> Result<Vec<ZapEntry>> {
        let mut result = Vec::new();
        for entry in self.zap_values(cx, number)? {
            checkpoint(cx)?;
            let value = entry.scalar().map_err(|error| parse(&error))?;
            result.push(ZapEntry {
                name: entry.name,
                value,
                collision: entry.collision,
            });
        }
        checkpoint(cx)?;
        Ok(result)
    }

    /// Inventory head datasets through MOS object 1 -> DSL directory hierarchy.
    /// This does not import/mount them or claim snapshot/clone/feature coverage.
    pub fn datasets(&mut self, cx: &Cx) -> Result<Vec<Dataset>> {
        let directory = self.load(cx, 1)?;
        if directory.node.object_type() != 1 {
            return Err(corrupt("MOS object 1 is not the pool directory"));
        }
        // The MOS directory is heterogeneous: checksum salt and TXG history
        // arrays coexist with object references. Validate the complete typed
        // map, then apply the reference contract only to root_dataset.
        let root = self
            .zap_values(cx, 1)?
            .into_iter()
            .find(|entry| entry.name == b"root_dataset")
            .ok_or_else(|| corrupt("MOS pool directory has no root_dataset"))?
            .scalar()
            .map_err(|error| parse(&error))?;
        let mut pending = vec![(root, 0_u64, Vec::<Vec<u8>>::new())];
        let mut seen = BTreeSet::new();
        let mut dataset_ids = BTreeSet::new();
        let mut result = Vec::new();
        let mut total_name_bytes = 0_usize;
        while let Some((number, parent, components)) = pending.pop() {
            checkpoint(cx)?;
            if number == 0 || !seen.insert(number) {
                return Err(corrupt("cyclic or aliased DSL directory"));
            }
            if seen.len() > 4096 || components.len() > 64 {
                return Err(unsupported("DSL inventory exceeds directory/depth budget"));
            }
            let dir = self.load(cx, number)?;
            let n = &dir.node;
            if n.bonus_type() != 12
                || n.bonus().len() != 256
                || n.spill().is_some()
                || !matches!(n.object_type(), 12 | 196)
            {
                return Err(unsupported("unsupported DSL directory dnode/bonus layout"));
            }
            let order = n.order();
            let head = order.u64(n.bonus(), 8).map_err(|error| parse(&error))?;
            let native_parent = order.u64(n.bonus(), 16).map_err(|error| parse(&error))?;
            let children = order.u64(n.bonus(), 32).map_err(|error| parse(&error))?;
            if native_parent != parent {
                return Err(corrupt("DSL directory parent identity disagrees"));
            }
            if head != 0 {
                if !dataset_ids.insert(head) {
                    return Err(corrupt("DSL directories alias a head dataset"));
                }
                let dataset = self.load(cx, head)?;
                let n = &dataset.node;
                if n.bonus_type() != 16
                    || n.bonus().len() != 320
                    || n.spill().is_some()
                    || !matches!(n.object_type(), 16 | 196)
                {
                    return Err(unsupported("unsupported DSL dataset dnode/bonus layout"));
                }
                let order = n.order();
                if order.u64(n.bonus(), 0).map_err(|error| parse(&error))? != number
                    || order.u64(n.bonus(), 24).map_err(|error| parse(&error))? != 0
                {
                    return Err(corrupt(
                        "DSL head dataset has a foreign directory or snapshot identity",
                    ));
                }
                let flags = order.u64(n.bonus(), 120).map_err(|error| parse(&error))?;
                if flags & !0x1_0007 != 0 {
                    return Err(unsupported(
                        "inconsistent, deferred or unknown dataset state",
                    ));
                }
                if flags & 0x1 != 0 {
                    if self.is_resumable_recv_staging(cx, &components, head, n)? {
                        // Hide incomplete resumable receive staging datasets (`%recv` or
                        // `com.delphix:resume_toguid`) from live namespace reads so zero
                        // partial state leaks while sibling datasets remain readable.
                        continue;
                    }
                    return Err(unsupported(
                        "inconsistent, deferred or unknown dataset state",
                    ));
                }
                let guid = order.u64(n.bonus(), 112).map_err(|error| parse(&error))?;
                let creation_txg = order.u64(n.bonus(), 56).map_err(|error| parse(&error))?;
                if guid == 0 || creation_txg == 0 || creation_txg > self.txg {
                    return Err(corrupt("invalid dataset GUID or creation transaction"));
                }
                let root_bytes = &n.bonus()[128..256];
                let bp = BlockPointer::parse(root_bytes, order).map_err(|error| parse(&error))?;
                let objectset_kind = if root_bytes.iter().all(|&byte| byte == 0) {
                    // OpenZFS creates $ORIGIN without ever initializing an
                    // object set. Preserve the head in inventory, without
                    // inventing a filesystem type or readable empty root.
                    if n.bonus()[72..104].iter().any(|&byte| byte != 0) {
                        return Err(corrupt(
                            "uninitialized dataset has referenced or unique data",
                        ));
                    }
                    None
                } else {
                    if !matches!(bp.logical_bytes(), 1024 | 2048 | 4096) {
                        return Err(corrupt("dataset object-set size exceeds native profile"));
                    }
                    let raw =
                        self.read_dataset_objset_block(cx, &bp, dataset.ceiling, None, true)?;
                    let objectset =
                        ObjectSet::parse(&raw.bytes, raw.order).map_err(|error| parse(&error))?;
                    if !matches!(objectset.kind, 2 | 3) {
                        return Err(unsupported("head is not a filesystem or volume object set"));
                    }
                    Some(objectset.kind)
                };
                result.push(Dataset {
                    components: components.clone(),
                    directory_object: number,
                    head_object: head,
                    guid,
                    creation_txg,
                    flags,
                    objectset_kind,
                    root_birth: bp.birth(),
                });
            }
            if children != 0 {
                let child = self.load(cx, children)?;
                if !matches!(child.node.object_type(), 13 | 196) {
                    return Err(corrupt("DSL child map has the wrong object type"));
                }
                let entries = self.zap(cx, children)?;
                if entries.len() + pending.len() + seen.len() > 4096 {
                    return Err(unsupported("DSL inventory exceeds directory budget"));
                }
                for entry in entries.into_iter().rev() {
                    if entry.name.is_empty()
                        || entry.name == b"."
                        || entry.name == b".."
                        || entry
                            .name
                            .iter()
                            .any(|&b| matches!(b, b'/' | b'@' | b'#' | 0))
                    {
                        return Err(corrupt("invalid DSL child-name component"));
                    }
                    let mut path = components.clone();
                    path.push(entry.name);
                    total_name_bytes += path.iter().map(Vec::len).sum::<usize>();
                    if total_name_bytes > 1024 * 1024 {
                        return Err(unsupported("DSL name budget exceeded"));
                    }
                    pending.push((entry.value, number, path));
                }
            }
        }
        checkpoint(cx)?;
        Ok(result)
    }
}

#[derive(Debug)]
pub struct Dataset {
    pub components: Vec<Vec<u8>>,
    pub directory_object: u64,
    pub head_object: u64,
    pub guid: u64,
    pub creation_txg: u64,
    pub flags: u64,
    /// None means an uninitialized native head with an entirely zero root
    /// pointer and no referenced/unique data. It has no readable object set.
    pub objectset_kind: Option<u64>,
    pub root_birth: u64,
}

companion_bin_tests! {
    #[cfg(test)]
    mod embedded_tests;
    #[cfg(test)]
    mod tests;
}
