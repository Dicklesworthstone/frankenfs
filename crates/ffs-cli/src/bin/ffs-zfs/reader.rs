//! Offline ZFS label discovery and explicit single-leaf MOS-root extraction.
//! No pool import, TXG selection, log replay, device writes or host path following.

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result};
use ffs_ondisk::zfs::nvlist::{NvList, Value};
use ffs_ondisk::zfs::{
    BlockPointer, DATA_OFFSET, Endian, LABEL_BYTES, LABEL_CONFIG_BYTES, LABEL_CONFIG_OFFSET,
    UBERBLOCK_RING_BYTES, UBERBLOCK_RING_OFFSET, Uberblock, label_offsets, uberblock_bytes,
    verify_label_checksum,
};
use ffs_types::ByteOffset;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;

fn checkpoint(cx: &Cx) -> Result<()> {
    cx.checkpoint().map_err(|_| FfsError::Cancelled)
}
fn corrupt(detail: impl Into<String>) -> FfsError {
    FfsError::Corruption {
        block: 0,
        detail: detail.into(),
    }
}
fn unsupported(detail: impl Into<String>) -> FfsError {
    FfsError::UnsupportedFeature(detail.into())
}
fn parse(error: &ffs_types::ParseError) -> FfsError {
    corrupt(error.to_string())
}
fn integer(list: &NvList, name: &str) -> Result<u64> {
    list.unsigned(name)
        .ok_or_else(|| corrupt(format!("missing or mistyped ZFS config integer {name}")))
}

struct ReadOnlyImage {
    file: File,
    length: u64,
}
impl ByteDevice for ReadOnlyImage {
    fn len_bytes(&self) -> u64 {
        self.length
    }
    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, bytes: &mut [u8]) -> Result<()> {
        checkpoint(cx)?;
        self.file.read_exact_at(bytes, offset.0)?;
        checkpoint(cx)
    }
    fn write_all_at(&self, _cx: &Cx, _offset: ByteOffset, _bytes: &[u8]) -> Result<()> {
        Err(FfsError::ReadOnly)
    }
    fn sync(&self, cx: &Cx) -> Result<()> {
        checkpoint(cx)
    }
}

pub struct Leaf {
    device: Box<dyn ByteDevice>,
    base: u64,
    length: u64,
}

#[derive(Debug)]
pub struct Label {
    pub offset: u64,
    pub order: Endian,
    pub config: NvList,
    pub slot_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SingleLeaf {
    pool_guid: u64,
    leaf_guid: u64,
    version: u64,
    txg: u64,
    ashift: u8,
    id: u32,
    allocated_bytes: u64,
    read_features: Vec<String>,
}

impl Label {
    /// Deliberately narrower than discovery. No multi-leaf or feature-registry
    /// claim follows from being able to print a checksum-valid configuration.
    fn single_leaf(&self, pool_guid: u64) -> Result<SingleLeaf> {
        let config = &self.config;
        let version = integer(config, "version")?;
        if !(1..=28).contains(&version) && version != 5000 {
            return Err(unsupported("unsupported ZFS pool version"));
        }
        if integer(config, "pool_guid")? != pool_guid || pool_guid == 0 {
            return Err(corrupt("label belongs to another pool GUID"));
        }
        if integer(config, "state")? != 1 {
            return Err(unsupported(
                "root extraction requires an exported pool image",
            ));
        }
        if integer(config, "vdev_children")? != 1 {
            return Err(unsupported(
                "root extraction currently requires exactly one top-level leaf",
            ));
        }
        if config.fields.contains_key("hole_array") {
            return Err(unsupported(
                "a removed top-level vdev is outside the single-leaf profile",
            ));
        }
        let mut read_features = Vec::new();
        if version == 5000 {
            let features = config
                .list("features_for_read")
                .ok_or_else(|| corrupt("missing ZFS read-feature catalog"))?;
            for (name, value) in &features.fields {
                if name != "org.illumos:lz4_compress" || !matches!(value, Value::Boolean(true)) {
                    return Err(unsupported(format!(
                        "unsupported ZFS label read feature {name}"
                    )));
                }
                read_features.push(name.clone());
            }
        }
        let tree = config
            .list("vdev_tree")
            .ok_or_else(|| corrupt("missing vdev tree"))?;
        if !matches!(tree.text("type"), Some("file" | "disk"))
            || tree.fields.contains_key("children")
        {
            return Err(unsupported(
                "mirror, RAIDZ, indirect and other compound vdevs require native mapping",
            ));
        }
        for name in [
            "is_log",
            "is_spare",
            "not_present",
            "offline",
            "faulted",
            "removed",
            "removing",
            "degraded",
            "is_hole",
            "resilver_txg",
            "rebuild_txg",
        ] {
            if let Some(value) = tree.fields.get(name)
                && !matches!(value, Value::Unsigned(0))
            {
                return Err(unsupported(format!(
                    "ZFS leaf state {name} is not admitted"
                )));
            }
        }
        if tree.fields.contains_key("allocation_bias")
            || tree.fields.contains_key("indirect_object")
        {
            return Err(unsupported(
                "special allocation and indirect vdev mappings are not admitted",
            ));
        }
        let leaf_guid = integer(config, "guid")?;
        if leaf_guid == 0
            || integer(config, "top_guid")? != leaf_guid
            || integer(tree, "guid")? != leaf_guid
        {
            return Err(corrupt("top-level and physical leaf GUIDs disagree"));
        }
        let id = u32::try_from(integer(tree, "id")?).map_err(|_| corrupt("vdev ID overflow"))?;
        if id != 0 {
            return Err(unsupported(
                "single-leaf profile requires top-level vdev zero",
            ));
        }
        let ashift =
            u8::try_from(integer(tree, "ashift")?).map_err(|_| corrupt("ashift overflow"))?;
        uberblock_bytes(ashift).map_err(|error| parse(&error))?;
        let txg = integer(config, "txg")?;
        if txg == 0 {
            return Err(corrupt("uninitialized label transaction group"));
        }
        Ok(SingleLeaf {
            pool_guid,
            leaf_guid,
            version,
            txg,
            ashift,
            id,
            allocated_bytes: integer(tree, "asize")?,
            read_features,
        })
    }
}

pub struct RootBlock {
    pub uberblock: Uberblock,
    pub data: Vec<u8>,
    pub physical_offset: u64,
    pub copy_index: usize,
}

impl Leaf {
    pub fn open(cx: &Cx, path: &Path, base: u64, length: Option<u64>) -> Result<Self> {
        checkpoint(cx)?;
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(unsupported(
                "ZFS reader requires an immutable offline regular image",
            ));
        }
        file.try_lock_shared()
            .map_err(|error| FfsError::Io(std::io::Error::other(error)))?;
        let size = metadata.len();
        Self::from_device(
            cx,
            Box::new(ReadOnlyImage { file, length: size }),
            base,
            length.unwrap_or_else(|| size.saturating_sub(base)),
        )
    }
    pub fn from_device(
        cx: &Cx,
        device: Box<dyn ByteDevice>,
        base: u64,
        length: u64,
    ) -> Result<Self> {
        checkpoint(cx)?;
        if base
            .checked_add(length)
            .is_none_or(|end| end > device.len_bytes())
        {
            return Err(FfsError::InvalidGeometry(
                "ZFS view exceeds backing image".into(),
            ));
        }
        label_offsets(length).map_err(|error| parse(&error))?;
        Ok(Self {
            device,
            base,
            length,
        })
    }
    fn read(&self, cx: &Cx, offset: u64, size: usize) -> Result<Vec<u8>> {
        checkpoint(cx)?;
        if offset
            .checked_add(size as u64)
            .is_none_or(|end| end > self.length)
        {
            return Err(corrupt("ZFS read exceeds selected leaf"));
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|error| FfsError::Io(std::io::Error::other(error)))?;
        bytes.resize(size, 0);
        self.device
            .read_exact_at(cx, ByteOffset(self.base + offset), &mut bytes)?;
        checkpoint(cx)?;
        Ok(bytes)
    }
    pub fn label(&self, cx: &Cx, index: usize) -> Result<Label> {
        let offsets = label_offsets(self.length).map_err(|error| parse(&error))?;
        let offset = *offsets
            .get(index)
            .ok_or_else(|| corrupt("label index must be 0 through 3"))?;
        let config_offset = offset + LABEL_CONFIG_OFFSET;
        let raw = self.read(cx, config_offset, LABEL_CONFIG_BYTES)?;
        let order = verify_label_checksum(&raw, config_offset).map_err(|error| parse(&error))?;
        let config = NvList::parse(&raw[..raw.len() - 40]).map_err(|error| parse(&error))?;
        let tree = config
            .list("vdev_tree")
            .ok_or_else(|| unsupported("label has no normal data-vdev tree"))?;
        let ashift =
            u8::try_from(integer(tree, "ashift")?).map_err(|_| corrupt("ashift overflow"))?;
        let slot_bytes = uberblock_bytes(ashift).map_err(|error| parse(&error))?;
        checkpoint(cx)?;
        Ok(Label {
            offset,
            order,
            config,
            slot_bytes,
        })
    }
    pub fn uberblock(&self, cx: &Cx, label: &Label, slot: usize) -> Result<Uberblock> {
        if slot >= UBERBLOCK_RING_BYTES / label.slot_bytes {
            return Err(corrupt("uberblock slot exceeds ring"));
        }
        let offset = label.offset + UBERBLOCK_RING_OFFSET + (slot * label.slot_bytes) as u64;
        let raw = self.read(cx, offset, label.slot_bytes)?;
        let ub = Uberblock::parse(&raw, offset).map_err(|error| parse(&error))?;
        checkpoint(cx)?;
        Ok(ub)
    }
    /// The caller explicitly names a candidate. Never import the maximum TXG,
    /// rewind silently, trust a foreign leaf, or repair a bad redundant copy.
    pub fn root(
        &self,
        cx: &Cx,
        label_index: usize,
        slot: usize,
        pool_guid: u64,
    ) -> Result<RootBlock> {
        let label = self.label(cx, label_index)?;
        let selected = label.single_leaf(pool_guid)?;
        // Strict initial profile: all four configurations must be readable and
        // agree on the addressing/identity fields. Discovery remains available
        // on damaged images; extraction does not silently decide their history.
        for index in 0..4 {
            let other = self.label(cx, index)?.single_leaf(pool_guid)?;
            if other != selected {
                return Err(corrupt("ZFS label identities or configurations disagree"));
            }
        }
        let ub = self.uberblock(cx, &label, slot)?;
        if ub.version != selected.version || ub.txg < selected.txg {
            return Err(corrupt(
                "selected uberblock predates or disagrees with label configuration",
            ));
        }
        // Native vdev_guid_sum includes the root (pool GUID) and every child.
        // With one physical leaf there are exactly these two wrapping terms.
        if ub.guid_sum != selected.pool_guid.wrapping_add(selected.leaf_guid) {
            return Err(corrupt(
                "selected uberblock belongs to another vdev configuration",
            ));
        }
        let (data, physical_offset, copy_index) = self.read_block(cx, &selected, &ub.root)?;
        if data.len() < 1024
            || ub
                .root
                .payload_order()
                .u64(&data, 704)
                .map_err(|error| parse(&error))?
                != 1
        {
            return Err(corrupt("selected root is not a META object set"));
        }
        checkpoint(cx)?;
        Ok(RootBlock {
            uberblock: ub,
            data,
            physical_offset,
            copy_index,
        })
    }
    fn read_block(
        &self,
        cx: &Cx,
        config: &SingleLeaf,
        bp: &BlockPointer,
    ) -> Result<(Vec<u8>, u64, usize)> {
        let dvas = bp.regular_dvas().map_err(|error| parse(&error))?;
        let sector = 1_u64 << config.ashift;
        let aligned_end = self.length / LABEL_BYTES * LABEL_BYTES - 2 * LABEL_BYTES;
        if config.allocated_bytes == 0
            || !config.allocated_bytes.is_multiple_of(sector)
            || config.allocated_bytes > aligned_end - DATA_OFFSET
        {
            return Err(corrupt(
                "configured ZFS allocation region exceeds the selected leaf",
            ));
        }
        // Validate every declared copy before attempting any data I/O.
        for dva in &dvas {
            if dva.vdev != config.id || dva.gang {
                return Err(unsupported(
                    "foreign-vdev or gang DVA needs a different native mapping",
                ));
            }
            if !dva.offset.is_multiple_of(sector)
                || dva.allocated_bytes != (bp.physical_bytes() as u64).div_ceil(sector) * sector
                || dva
                    .offset
                    .checked_add(dva.allocated_bytes)
                    .is_none_or(|end| end > config.allocated_bytes)
            {
                return Err(corrupt("unaligned or out-of-range single-leaf DVA"));
            }
        }
        let mut failures = Vec::new();
        for (index, dva) in dvas.iter().enumerate() {
            checkpoint(cx)?;
            let offset = DATA_OFFSET + dva.offset;
            let result = self
                .read(cx, offset, bp.physical_bytes())
                .and_then(|bytes| bp.decode(&bytes).map_err(|error| parse(&error)));
            match result {
                Ok(data) => {
                    checkpoint(cx)?;
                    return Ok((data, offset, index));
                }
                Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                Err(error) => failures.push(format!("DVA {index}: {error}")),
            }
        }
        Err(corrupt(format!(
            "all ZFS block copies failed: {}",
            failures.join("; ")
        )))
    }
}

#[cfg(test)]
mod tests;
