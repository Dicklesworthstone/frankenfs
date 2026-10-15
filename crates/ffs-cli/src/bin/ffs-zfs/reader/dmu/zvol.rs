//! Immutable native volume datasets, not ZPL files or host block devices.
//!
//! OpenZFS zfs-2.3.0 zvol.h/zvol.c: object 1 (DMU_OT_ZVOL) contains
//! logical sectors; object 2 (DMU_OT_ZVOL_PROP) stores a uint64 `size`.
//! Volblocksize comes from object 1's dnode. Neither dn_maxblkid nor used
//! allocation determines capacity. Pending ZIL intent is not replayed.

use super::{
    BlockPointer, Cx, FfsError, MAX_READ_BYTES, Object, ObjectSet, Objects, Result,
    VecDeque, checkpoint, corrupt, parse, unsupported,
};
use ffs_block::ByteDevice;
use ffs_types::ByteOffset;
use serde::Serialize;
use std::io::IoSliceMut;

const VOLUME_OBJECT: u64 = 1;
const PROPERTY_OBJECT: u64 = 2;
const VOLUME_TYPE: u8 = 23;
const PROPERTY_TYPE: u8 = 24;
const OBJECTSET_TYPE: u64 = 3;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VolumeInfo {
    pub pool_guid: u64,
    pub dataset_guid: u64,
    pub pool_txg: u64,
    pub view_txg: u64,
    pub root_birth: u64,
    pub size_bytes: u64,
    pub block_bytes: usize,
    pub dnode_used_bytes: u64,
    pub snapshot: bool,
}

/// Owns a pinned native object-set root and its underlying immutable pool.
/// Sequential reads reuse this view's cache. The ByteDevice implementation
/// uses request-local caches, so concurrent callers need no blocking mutex and
/// cannot accidentally share an interpretation or historical birth ceiling.
pub struct Zvol {
    objects: Objects,
    data: Object,
    info: VolumeInfo,
}

impl Objects {
    /// Select a native volume head or exact named snapshot through the same
    /// verified DSL inventory/lineage used by ZPL. No arbitrary root pointers,
    /// host paths, dataset-name guessing or fallback to live-head data.
    pub fn zvol(
        &mut self,
        cx: &Cx,
        components: &[Vec<u8>],
        snapshot: Option<&[u8]>,
    ) -> Result<Zvol> {
        checkpoint(cx)?;
        let (root, guid, flags, view_txg, ceiling, kind) = if let Some(name) = snapshot {
            let selected = self.named_snapshot_root(cx, components, name)?;
            (
                selected.root,
                selected.info.guid,
                selected.info.flags,
                selected.info.creation_txg,
                selected.info.creation_txg,
                selected.info.objectset_kind,
            )
        } else {
            let selected = self
                .datasets(cx)?
                .into_iter()
                .find(|row| row.components == components)
                .ok_or_else(|| FfsError::NotFound("ZFS volume dataset".into()))?;
            let object = self.load(cx, selected.head_object)?;
            let root = BlockPointer::parse(&object.node.bonus()[128..256], object.node.order())
                .map_err(|error| parse(&error))?;
            if root.birth() != selected.root_birth {
                return Err(corrupt("selected volume root identity changed"));
            }
            (
                root, selected.guid, selected.flags, self.txg, object.ceiling,
                selected.objectset_kind,
            )
        };
        if kind != OBJECTSET_TYPE || flags & 0x1_0000 != 0 {
            return Err(unsupported("zvol reads require a native volume object set"));
        }
        let block = self
            .checked(cx, &root, 11, 0, root.logical_bytes(), ceiling)?
            .ok_or_else(|| corrupt("volume object-set root is a hole"))?;
        let os = ObjectSet::parse(&block.bytes, block.order).map_err(|error| parse(&error))?;
        if os.kind != OBJECTSET_TYPE {
            return Err(corrupt("selected volume object-set type changed"));
        }
        let info = VolumeInfo {
            pool_guid: self.pool_guid(),
            dataset_guid: guid,
            pool_txg: self.txg,
            view_txg,
            root_birth: root.birth(),
            size_bytes: 0,
            block_bytes: 0,
            dnode_used_bytes: 0,
            snapshot: snapshot.is_some(),
        };
        let view = Self {
            pool: self.pool.clone(),
            config: self.config.clone(),
            txg: view_txg,
            root_birth: root.birth(),
            meta: os.meta,
            cache: VecDeque::new(),
            cached_bytes: 0,
        };
        Zvol::open(cx, view, info)
    }
}

impl Zvol {
    fn open(cx: &Cx, mut objects: Objects, mut info: VolumeInfo) -> Result<Self> {
        let data = objects.load(cx, VOLUME_OBJECT)?;
        let props = objects.load(cx, PROPERTY_OBJECT)?;
        for (object, kind) in [(&data, VOLUME_TYPE), (&props, PROPERTY_TYPE)] {
            if object.node.object_type() != kind
                || object.node.bonus_type() != 0
                || !object.node.bonus().is_empty()
                || object.node.spill().is_some()
            {
                return Err(corrupt("invalid native zvol data or property dnode"));
            }
        }
        let rows = objects.zap_values(cx, PROPERTY_OBJECT)?;
        let size = rows.iter().find(|entry| entry.name == b"size")
            .ok_or_else(|| corrupt("native zvol size property is absent"))?;
        if size.integer_bytes != 8 || size.values.len() != 1 {
            return Err(corrupt("native zvol size is not one uint64"));
        }
        let block_bytes = data.node.data_bytes();
        let size_bytes = size.values[0];
        if !(512..=MAX_READ_BYTES).contains(&block_bytes)
            || !block_bytes.is_power_of_two()
            || size_bytes == 0
            || !size_bytes.is_multiple_of(block_bytes as u64)
        {
            return Err(corrupt("native zvol capacity or block geometry is invalid"));
        }
        info.size_bytes = size_bytes;
        info.block_bytes = block_bytes;
        info.dnode_used_bytes = data.node.used_bytes();
        checkpoint(cx)?;
        Ok(Self { objects, data, info })
    }

    #[must_use]
    pub const fn info(&self) -> &VolumeInfo {
        &self.info
    }

    /// Exact, bounded byte range. Arbitrary byte alignment is intentional at
    /// the ByteDevice seam; callers exposing sectors impose their own alignment.
    /// A range crossing capacity is an error, not a short successful read.
    pub fn read(&mut self, cx: &Cx, start: u64, size: usize) -> Result<Vec<u8>> {
        read_range(cx, &mut self.objects, &self.data, self.info.size_bytes, start, size)
    }

    /// Allocation queries reuse the shared native pointer validator and skip
    /// hole subtrees. They do not verify the contents of allocated data blocks.
    pub fn seek_data_hole(&mut self, cx: &Cx, start: u64, want_data: bool) -> Result<u64> {
        self.objects.seek_data_hole(cx, &self.data, self.info.size_bytes, start, want_data)
    }
}

fn check_range(capacity: u64, start: u64, size: usize) -> Result<()> {
    if size > MAX_READ_BYTES {
        return Err(unsupported("zvol request exceeds 16 MiB read budget"));
    }
    if start.checked_add(size as u64).is_none_or(|end| end > capacity) {
        return Err(FfsError::Io(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof, "zvol range exceeds native capacity",
        )));
    }
    Ok(())
}

fn read_range(
    cx: &Cx,
    objects: &mut Objects,
    data: &Object,
    capacity: u64,
    start: u64,
    size: usize,
) -> Result<Vec<u8>> {
    checkpoint(cx)?;
    check_range(capacity, start, size)?;
    let mut result = Vec::new();
    result.try_reserve_exact(size)
        .map_err(|error| FfsError::Io(std::io::Error::other(error)))?;
    result.resize(size, 0);
    let block_bytes = data.node.data_bytes() as u64;
    let mut done = 0;
    while done < size {
        checkpoint(cx)?;
        let logical = start + done as u64;
        let id = logical / block_bytes;
        // No on-disk pointers exist beyond dn_maxblkid. The remaining admitted
        // volume range is sparse, even if its size exceeds tree capacity.
        if id > data.node.max_block() {
            break;
        }
        let within = (logical % block_bytes) as usize;
        let count = (size - done).min(data.node.data_bytes() - within);
        if let Some(block) = objects.data_block(cx, data, id)? {
            result[done..done + count].copy_from_slice(&block.bytes[within..within + count]);
        }
        done += count;
    }
    checkpoint(cx)?;
    Ok(result)
}

impl ByteDevice for Zvol {
    fn len_bytes(&self) -> u64 {
        self.info.size_bytes
    }

    fn supports_vectored_reads(&self) -> bool {
        true
    }

    fn preserves_read_exact_at_destination_on_error(&self) -> bool {
        true
    }

    fn preserves_read_vectored_destinations_on_error(&self) -> bool {
        true
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        check_range(self.info.size_bytes, offset.0, out.len())?;
        let mut view = self.objects.clone_mos(); // Same pinned object set, fresh cache.
        let bytes = read_range(cx, &mut view, &self.data, self.info.size_bytes, offset.0, out.len())?;
        checkpoint(cx)?;
        out.copy_from_slice(&bytes);
        // No fallible operation after publication to the caller's buffer.
        Ok(())
    }

    fn read_vectored_exact_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        out: &mut [IoSliceMut<'_>],
    ) -> Result<()> {
        checkpoint(cx)?;
        let size = out.iter().try_fold(0_usize, |total, part| {
            total.checked_add(part.len()).filter(|sum| *sum <= MAX_READ_BYTES)
                .ok_or_else(|| unsupported("zvol vectored request exceeds 16 MiB"))
        })?;
        check_range(self.info.size_bytes, offset.0, size)?;
        let mut view = self.objects.clone_mos();
        let bytes = read_range(cx, &mut view, &self.data, self.info.size_bytes, offset.0, size)?;
        checkpoint(cx)?;
        let mut done = 0;
        for part in out {
            let count = part.len();
            part.copy_from_slice(&bytes[done..done + count]);
            done += count;
        }
        Ok(())
    }

    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _bytes: &[u8]) -> Result<()> {
        Err(FfsError::ReadOnly)
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        // Immutable view: no backing flush, import bookkeeping or ZIL replay.
        checkpoint(cx)
    }
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
