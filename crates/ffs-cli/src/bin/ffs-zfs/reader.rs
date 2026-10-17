//! Offline ZFS label discovery and leaf/mirror/RAIDZ MOS-root extraction.
//! Supports explicit or automatic read-only root selection, without log replay,
//! device writes, live pool ownership or host path following.

pub mod dmu;
mod pool;

pub use pool::Pool;

use asupersync::Cx;
use dmu::supported_label_feature as supported_read_feature;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result};
use ffs_ondisk::zfs::nvlist::{NvList, Value};
use ffs_ondisk::zfs::{
    BlockPointer, DATA_OFFSET, Dva, Endian, LABEL_BYTES, LABEL_CONFIG_BYTES, LABEL_CONFIG_OFFSET,
    UBERBLOCK_RING_BYTES, UBERBLOCK_RING_OFFSET, Uberblock, label_offsets, uberblock_bytes,
    verify_label_checksum,
};
use ffs_types::ByteOffset;
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::Arc;

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

#[derive(Clone)]
pub struct Leaf {
    device: Arc<dyn ByteDevice>,
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

/// Addressing and read features of the single admitted top-level data vdev.
#[derive(Debug, Clone, PartialEq, Eq)]
struct VdevConfig {
    pool_guid: u64,
    top_guid: u64,
    version: u64,
    txg: u64,
    ashift: u8,
    id: u32,
    allocated_bytes: u64,
    read_features: Vec<String>,
    /// Native child-ID order, bound to supplied images after group admission.
    /// Absent for standalone leaves and ordinary mirrors.
    raidz_members: Option<RaidzGroup>,
}

/// Parity and child order are bound together by complete label agreement.
/// When `parity == 0`, `members` describes top-level vdevs in a striped pool.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RaidzGroup {
    parity: usize,
    members: Vec<RaidzMember>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RaidzMember {
    supplied_index: usize,
    guid: u64,
    ashift: u8,
    allocated_bytes: u64,
}

impl VdevConfig {
    pub(self) fn total_data_bytes(&self) -> u64 {
        if let Some(group) = &self.raidz_members {
            if group.parity == 0 {
                return group
                    .members
                    .iter()
                    .fold(0_u64, |sum, m| sum.saturating_add(m.allocated_bytes));
            }
            let width = group.members.len() as u64;
            let data_cols = width.saturating_sub(group.parity as u64);
            if let Some(column_bytes) = self.allocated_bytes.checked_div(width) {
                return column_bytes.saturating_mul(data_cols);
            }
        }
        self.allocated_bytes
    }
}

fn admit_vdev_state(tree: &NvList) -> Result<()> {
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
        "resilver_defer",
        "unspare",
    ] {
        if let Some(value) = tree.fields.get(name)
            && !matches!(value, Value::Unsigned(0))
        {
            return Err(unsupported(format!(
                "ZFS vdev state {name} is not admitted"
            )));
        }
    }
    if [
        "allocation_bias",
        "indirect_object",
        "indirect_births",
        "prev_indirect_vdev",
        "raidz_expanding",
        "raidz_expand_txgs",
    ]
    .iter()
    .any(|name| tree.fields.contains_key(*name))
    {
        return Err(unsupported(
            "special allocation, indirect and expanded RAIDZ mappings are not admitted",
        ));
    }
    Ok(())
}

impl Label {
    fn vdev_config_with_mode(
        &self,
        pool_guid: u64,
        allow_active_state: bool,
        allow_striped_top_vdevs: bool,
    ) -> Result<VdevConfig> {
        let config = &self.config;
        let version = integer(config, "version")?;
        if !(1..=28).contains(&version) && version != 5000 {
            return Err(unsupported("unsupported ZFS pool version"));
        }
        if integer(config, "pool_guid")? != pool_guid || pool_guid == 0 {
            return Err(corrupt("label belongs to another pool GUID"));
        }
        let state = integer(config, "state")?;
        if allow_active_state {
            if !matches!(state, 0 | 1) {
                return Err(unsupported(
                    "pool import requires an active or exported pool image",
                ));
            }
        } else if state != 1 {
            return Err(unsupported(
                "root extraction requires an exported pool image",
            ));
        }
        let vdev_children = integer(config, "vdev_children")?;
        if allow_striped_top_vdevs {
            if !(1..=8).contains(&vdev_children) {
                return Err(unsupported(
                    "striped pool profile requires one through eight top-level data vdevs",
                ));
            }
        } else if vdev_children != 1 {
            return Err(unsupported(
                "root extraction requires exactly one top-level data vdev",
            ));
        }
        if config.fields.contains_key("hole_array") {
            return Err(unsupported(
                "a removed top-level vdev is outside the read profile",
            ));
        }
        let mut read_features = Vec::new();
        if version == 5000 {
            let features = config
                .list("features_for_read")
                .ok_or_else(|| corrupt("missing ZFS read-feature catalog"))?;
            for (name, value) in &features.fields {
                if !supported_read_feature(name, value) {
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
        admit_vdev_state(tree)?;
        let top_guid = integer(config, "top_guid")?;
        if top_guid == 0 || top_guid == pool_guid || integer(tree, "guid")? != top_guid {
            return Err(corrupt("top-level vdev GUIDs disagree"));
        }
        let id = u32::try_from(integer(tree, "id")?).map_err(|_| corrupt("vdev ID overflow"))?;
        if allow_striped_top_vdevs {
            if u64::from(id) >= vdev_children {
                return Err(corrupt("top-level vdev ID exceeds vdev_children"));
            }
        } else if id != 0 {
            return Err(unsupported(
                "read profile requires the single top-level vdev to have ID zero",
            ));
        }
        let ashift =
            u8::try_from(integer(tree, "ashift")?).map_err(|_| corrupt("ashift overflow"))?;
        uberblock_bytes(ashift).map_err(|error| parse(&error))?;
        let txg = integer(config, "txg")?;
        if txg == 0 {
            return Err(corrupt("uninitialized label transaction group"));
        }
        Ok(VdevConfig {
            pool_guid,
            top_guid,
            version,
            txg,
            ashift,
            id,
            allocated_bytes: integer(tree, "asize")?,
            read_features,
            raidz_members: None,
        })
    }

    /// A standalone image must describe a standalone physical data vdev.
    /// A mirror member needs the explicitly supplied complete member set.
    fn single_leaf(&self, pool_guid: u64) -> Result<VdevConfig> {
        self.single_leaf_with_mode(pool_guid, false)
    }

    fn single_leaf_with_mode(
        &self,
        pool_guid: u64,
        allow_active_state: bool,
    ) -> Result<VdevConfig> {
        let config = self.vdev_config_with_mode(pool_guid, allow_active_state, false)?;
        let tree = self
            .config
            .list("vdev_tree")
            .ok_or_else(|| corrupt("missing vdev tree"))?;
        if !matches!(tree.text("type"), Some("file" | "disk"))
            || tree.fields.contains_key("children")
        {
            return Err(unsupported(
                "compound vdev requires its explicitly supplied native topology",
            ));
        }
        if integer(&self.config, "guid")? != config.top_guid {
            return Err(corrupt("top-level and physical leaf GUIDs disagree"));
        }
        Ok(config)
    }

    pub(self) fn striped_leaf_config(
        &self,
        pool_guid: u64,
        expected_children: usize,
        allow_active_state: bool,
    ) -> Result<VdevConfig> {
        let config = self.vdev_config_with_mode(pool_guid, allow_active_state, true)?;
        if integer(&self.config, "vdev_children")? != expected_children as u64 {
            return Err(corrupt(
                "striped pool member disagrees on vdev_children count",
            ));
        }
        let tree = self
            .config
            .list("vdev_tree")
            .ok_or_else(|| corrupt("missing vdev tree"))?;
        if !matches!(tree.text("type"), Some("file" | "disk"))
            || tree.fields.contains_key("children")
        {
            return Err(unsupported(
                "striped top-level vdev profile requires standalone file or disk leaves",
            ));
        }
        if integer(&self.config, "guid")? != config.top_guid {
            return Err(corrupt("top-level and physical leaf GUIDs disagree"));
        }
        Ok(config)
    }
}

/// A native column extent in the selected RAIDZ DVA. Skip-only columns
/// have zero read bytes; parity may be mapped without needing physical I/O.
#[derive(Debug)]
pub struct RaidzColumnInfo {
    pub child_id: usize,
    pub member_guid: u64,
    pub physical_offset: u64,
    pub bytes: usize,
    pub parity: bool,
}

#[derive(Debug)]
pub struct RaidzReadInfo {
    pub dva_offset: u64,
    pub allocated_bytes: u64,
    pub columns: Vec<RaidzColumnInfo>,
    pub parity_read: bool,
    /// Native child IDs whose data was reconstructed, never argument indices.
    /// Excluded parity is not reported as repaired or reconstructed storage.
    pub reconstructed_children: Vec<usize>,
}

struct BlockRead {
    bytes: Vec<u8>,
    physical_offset: u64,
    copy_index: usize,
    member_index: usize,
    raidz: Option<RaidzReadInfo>,
}

pub struct RootBlock {
    pub uberblock: Uberblock,
    pub data: Vec<u8>,
    /// A replica address, or the first data-column address when raidz is set.
    /// For a gang root this identifies its header, not contiguous root bytes.
    pub physical_offset: u64,
    pub copy_index: usize,
    /// A replica identity, or the first data-column identity when raidz is set.
    pub member_guid: u64,
    pub raidz: Option<RaidzReadInfo>,
    config: VdevConfig,
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
            device: Arc::from(device),
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
        if ub.guid_sum != selected.pool_guid.wrapping_add(selected.top_guid) {
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
            member_guid: selected.top_guid,
            raidz: None,
            config: selected,
        })
    }

    /// Select the highest readable TXG using the same redundant-label policy
    /// as multi-member pools. Explicit root extraction remains strict.
    pub fn import_active(
        &self,
        cx: &Cx,
        expected_pool_guid: Option<u64>,
    ) -> Result<(usize, usize, RootBlock)> {
        Pool::from(self.clone()).import_active(cx, expected_pool_guid)
    }

    fn read_block(
        &self,
        cx: &Cx,
        config: &VdevConfig,
        bp: &BlockPointer,
    ) -> Result<(Vec<u8>, u64, usize)> {
        if bp.gang() {
            let block = Pool::from(self.clone()).read_gang_block(cx, config, bp)?;
            return Ok((block.bytes, block.physical_offset, block.copy_index));
        }
        let dvas = self.block_dvas(config, bp)?;
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

    pub(self) fn validate_dva_for_vdev(
        &self,
        ashift: u8,
        allocated_bytes: u64,
        expected_vdev_id: u32,
        bp: &BlockPointer,
        dva: &Dva,
    ) -> Result<()> {
        let sector = 1_u64 << ashift;
        let aligned_end = self.length / LABEL_BYTES * LABEL_BYTES - 2 * LABEL_BYTES;
        if allocated_bytes == 0
            || !allocated_bytes.is_multiple_of(sector)
            || allocated_bytes > aligned_end - DATA_OFFSET
        {
            return Err(corrupt(
                "configured ZFS allocation region exceeds the selected leaf",
            ));
        }
        if dva.vdev != expected_vdev_id || dva.gang {
            return Err(unsupported(
                "foreign-vdev or gang DVA needs a different native mapping",
            ));
        }
        if !dva.offset.is_multiple_of(sector)
            || dva.allocated_bytes != (bp.physical_bytes() as u64).div_ceil(sector) * sector
            || dva
                .offset
                .checked_add(dva.allocated_bytes)
                .is_none_or(|end| end > allocated_bytes)
        {
            return Err(corrupt("unaligned or out-of-range data-vdev DVA"));
        }
        Ok(())
    }

    /// Validate the whole DVA set against one physical member before data I/O.
    fn block_dvas(&self, config: &VdevConfig, bp: &BlockPointer) -> Result<Vec<Dva>> {
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
            self.validate_dva_for_vdev(config.ashift, config.allocated_bytes, config.id, bp, dva)?;
        }
        Ok(dvas)
    }
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
