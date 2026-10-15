//! Read DMU objects under one explicitly selected, verified MOS root.
//! No automatic import/TXG selection, writes, replay, or ZPL file-size guesses.

mod features;
mod holes;
pub mod scrub;
mod seek;
mod zap;
pub mod zil;
pub mod zpl;

pub(super) use features::supported_label_feature;

use super::{
    BlockPointer, Cx, Endian, FfsError, Leaf, Pool, Result, RootBlock, VdevConfig, checkpoint,
    corrupt, parse, unsupported,
};
use ffs_ondisk::zfs_dmu::{DNODE_BLOCK_BYTES, DNODE_BYTES, Dnode, ObjectSet, ZapEntry, dnode_at};
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

impl Objects {
    #[must_use]
    pub const fn pool_guid(&self) -> u64 {
        self.config.pool_guid
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
        }
    }

    fn from_root(cx: &Cx, pool: Pool, root: RootBlock) -> Result<Self> {
        let objectset = ObjectSet::parse(&root.data, root.uberblock.root.payload_order())
            .map_err(|error| parse(&error))?;
        if objectset.kind != 1 {
            return Err(corrupt("selected object set is not the MOS"));
        }
        let config = root.config;
        checkpoint(cx)?;
        let mut view = Self {
            pool,
            config,
            txg: root.uberblock.txg,
            root_birth: root.uberblock.root.birth(),
            meta: objectset.meta,
            cache: VecDeque::new(),
            cached_bytes: 0,
        };
        // Label features only describe what is needed to bootstrap the MOS.
        // Keep this view private until its complete native feature catalogs
        // admit reads. Every explicit/automatic leaf/group open joins here.
        view.admit_features(cx)?;
        checkpoint(cx)?;
        Ok(view)
    }
}

impl Objects {
    /// Check the interpretation of an already checksum-protected pointer.
    /// Returns false for a native hole. This does not verify a data payload:
    /// allocation queries inspect leaf pointers without reading file contents.
    fn validate_pointer(
        &self,
        bp: &BlockPointer,
        kind: u8,
        level: u8,
        size: usize,
        ceiling: u64,
    ) -> Result<bool> {
        if bp.protected() {
            return Err(unsupported(
                "encrypted DMU blocks need their native pipeline",
            ));
        }
        if bp.birth() > ceiling || bp.birth() > self.txg {
            return Err(corrupt(
                "DMU child birth is newer than its parent or selected TXG",
            ));
        }
        if bp.hole() {
            self.validate_hole(bp, kind, level, size)?;
            return Ok(false);
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
        let root = self
            .zap(cx, 1)?
            .into_iter()
            .find(|entry| entry.name == b"root_dataset")
            .ok_or_else(|| corrupt("MOS pool directory has no root_dataset"))?
            .value;
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
                if flags & !0x1_0006 != 0 {
                    return Err(unsupported(
                        "inconsistent, deferred or unknown dataset state",
                    ));
                }
                let guid = order.u64(n.bonus(), 112).map_err(|error| parse(&error))?;
                let creation_txg = order.u64(n.bonus(), 56).map_err(|error| parse(&error))?;
                if guid == 0 || creation_txg == 0 || creation_txg > self.txg {
                    return Err(corrupt("invalid dataset GUID or creation transaction"));
                }
                let bp = BlockPointer::parse(&n.bonus()[128..256], order)
                    .map_err(|error| parse(&error))?;
                if !matches!(bp.logical_bytes(), 1024 | 2048 | 4096) {
                    return Err(corrupt("dataset object-set size exceeds native profile"));
                }
                let raw = self
                    .checked(cx, &bp, 11, 0, bp.logical_bytes(), dataset.ceiling)?
                    .ok_or_else(|| corrupt("head dataset has no object-set root"))?;
                let objectset =
                    ObjectSet::parse(&raw.bytes, raw.order).map_err(|error| parse(&error))?;
                if !matches!(objectset.kind, 2 | 3) {
                    return Err(unsupported("head is not a filesystem or volume object set"));
                }
                result.push(Dataset {
                    components: components.clone(),
                    directory_object: number,
                    head_object: head,
                    guid,
                    creation_txg,
                    flags,
                    objectset_kind: objectset.kind,
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
    pub objectset_kind: u64,
    pub root_birth: u64,
}

companion_bin_tests! {
    #[cfg(test)]
    mod embedded_tests;
    #[cfg(test)]
    mod tests;
}
