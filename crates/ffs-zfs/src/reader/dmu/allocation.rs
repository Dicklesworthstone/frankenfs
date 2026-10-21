//! Reconstruct committed metaslab allocation from the selected MOS.
//!
//! This is a read-only allocation-log check, not namespace leak detection or
//! allocator admission. Active log space maps and pool checkpoints require
//! additional state and are explicitly refused, never silently omitted.

use super::super::{NvList, Value, VdevConfig, admit_vdev_state, integer};
use super::{
    CheckedBlock, Cx, FfsError, Object, Objects, Result, checkpoint, corrupt, parse, unsupported,
};
use ffs_ondisk::zfs::LABEL_CONFIG_BYTES;
use ffs_ondisk::zfs_dmu::space_map::{AllocationMap, Header, Record, Records};
use ffs_ondisk::zfs_zap::Entry;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy)]
pub struct AllocationLimits {
    pub metaslabs: u64,
    pub records: u64,
    /// Conservative decoded metadata work, including repeated cached traversal.
    pub metadata_bytes: u64,
    pub ranges_per_metaslab: usize,
}

impl Default for AllocationLimits {
    fn default() -> Self {
        Self {
            metaslabs: 65_536,
            records: 16_777_216,
            metadata_bytes: 512 * 1024 * 1024,
            ranges_per_metaslab: 65_536,
        }
    }
}

#[derive(Debug)]
pub struct MetaslabAllocation {
    pub id: u64,
    pub object: u64,
    pub start: u64,
    pub size: u64,
    pub allocated_bytes: u64,
    pub free_bytes: u64,
    pub allocated_ranges: usize,
    pub free_ranges: u64,
    pub largest_free_range: u64,
    pub stream_bytes: u64,
}

#[derive(Debug)]
pub struct VdevAllocation {
    pub id: u32,
    pub guid: u64,
    pub ashift: u8,
    pub metaslab_shift: u8,
    pub metaslab_array: u64,
    pub asize: u64,
    pub mapped_bytes: u64,
    pub allocated_bytes: u64,
    pub free_bytes: u64,
    /// Space below asize but outside the complete native metaslab count.
    pub unmapped_tail_bytes: u64,
    pub metaslabs: Vec<MetaslabAllocation>,
}

#[derive(Debug)]
pub struct PoolAllocation {
    pub pool_guid: u64,
    pub txg: u64,
    /// Top-level DVA/asize bytes; includes RAIDZ parity and allocation padding.
    pub mapped_bytes: u64,
    pub allocated_bytes: u64,
    pub free_bytes: u64,
    pub records_examined: u64,
    pub charged_metadata_bytes: u64,
    pub vdevs: Vec<VdevAllocation>,
}

struct Budget {
    bytes: u64,
    records: u64,
}

#[derive(Clone, Copy)]
struct MetaslabRegion {
    start: u64,
    size: u64,
    shift: u8,
}

impl Budget {
    fn charge(&mut self, bytes: u64) -> Result<()> {
        self.bytes = self
            .bytes
            .checked_sub(bytes)
            .ok_or_else(|| unsupported("allocation inspection exceeds metadata-work budget"))?;
        Ok(())
    }

    fn load(&mut self, view: &mut Objects, cx: &Cx, number: u64) -> Result<Object> {
        self.charge(tree_work(&view.meta))?;
        view.load(cx, number)
    }

    fn block(
        &mut self,
        view: &mut Objects,
        cx: &Cx,
        object: &Object,
        id: u64,
    ) -> Result<Option<CheckedBlock>> {
        checkpoint(cx)?;
        self.charge(tree_work(&object.node))?;
        view.data_block(cx, object, id)
    }

    fn zap(&mut self, view: &mut Objects, cx: &Cx, id: u64, kind: u8) -> Result<Vec<Entry>> {
        let object = self.load(view, cx, id)?;
        if id == 0 || object.node.object_type() != kind || object.node.spill().is_some() {
            return Err(corrupt("allocation metadata has the wrong ZAP identity"));
        }
        let blocks = object
            .node
            .max_block()
            .checked_add(1)
            .ok_or_else(|| corrupt("allocation ZAP geometry overflow"))?;
        let size = blocks
            .checked_mul(object.node.data_bytes() as u64)
            .ok_or_else(|| corrupt("allocation ZAP byte size overflow"))?;
        if size > 1024 * 1024 {
            return Err(unsupported("allocation metadata ZAP exceeds one MiB"));
        }
        // The ZAP reader reloads its dnode and can check copied pointer-table
        // blocks as well as its primary routes. Charge that work before entry.
        self.charge(tree_work(&view.meta))?;
        self.charge(
            blocks
                .checked_mul(2 * tree_work(&object.node))
                .ok_or_else(|| corrupt("allocation ZAP work overflow"))?,
        )?;
        view.zap_values(cx, id)
    }
}

fn tree_work(node: &ffs_ondisk::zfs_dmu::Dnode) -> u64 {
    node.data_bytes() as u64 + u64::from(node.levels() - 1) * node.indirect_bytes() as u64
}

fn scalar(entry: &Entry) -> Result<u64> {
    if entry.integer_bytes != 8 || entry.values.len() != 1 {
        return Err(corrupt("allocation metadata requires one native uint64"));
    }
    Ok(entry.values[0])
}

fn required(rows: &[Entry], name: &[u8]) -> Result<u64> {
    scalar(
        rows.iter()
            .find(|row| row.name == name)
            .ok_or_else(|| corrupt("required allocation metadata entry is absent"))?,
    )
}

fn sum(left: u64, right: u64) -> Result<u64> {
    left.checked_add(right)
        .ok_or_else(|| corrupt("pool allocation accounting overflow"))
}

struct Top {
    id: u32,
    guid: u64,
    ashift: u8,
    shift: u8,
    array: u64,
    asize: u64,
    objects: Vec<u64>,
}

impl Objects {
    /// Complete per-pool result or error. Work uses a private root-local cache;
    /// it never promotes incomplete results into mount free-space accounting.
    pub fn allocation(&self, cx: &Cx, limits: AllocationLimits) -> Result<PoolAllocation> {
        checkpoint(cx)?;
        if !(1..=65_536).contains(&limits.metaslabs)
            || limits.records == 0
            || limits.metadata_bytes == 0
            || !(1..=1_048_576).contains(&limits.ranges_per_metaslab)
        {
            return Err(unsupported("invalid allocation inspection limits"));
        }
        let mut view = self.clone_mos();
        let mut budget = Budget {
            bytes: limits.metadata_bytes,
            records: limits.records,
        };
        let directory = budget.zap(&mut view, cx, 1, 1)?;
        let v2 = if view.config.version == 5000 {
            let id = required(&directory, b"features_for_write")?;
            let features = budget.zap(&mut view, cx, id, 196)?;
            let mut v2 = false;
            for feature in features {
                checkpoint(cx)?;
                let active = scalar(&feature)? != 0;
                if active
                    && matches!(
                        feature.name.as_slice(),
                        b"com.delphix:log_spacemap" | b"com.delphix:zpool_checkpoint"
                    )
                {
                    return Err(unsupported(
                        "current allocation needs unflushed log-space-map or pool-checkpoint accounting",
                    ));
                }
                v2 |= active && feature.name == b"com.delphix:spacemap_v2";
            }
            v2
        } else {
            false
        };
        let config_id = required(&directory, b"config")?;
        let object = budget.load(&mut view, cx, config_id)?;
        if object.node.object_type() != 3
            || object.node.bonus_type() != 4
            || object.node.bonus().len() != 8
            || object.node.spill().is_some()
        {
            return Err(corrupt(
                "MOS config is not a packed nvlist with a size bonus",
            ));
        }
        let length = object
            .node
            .order()
            .u64(object.node.bonus(), 0)
            .map_err(|error| parse(&error))?;
        if !(1..=LABEL_CONFIG_BYTES as u64).contains(&length) {
            return Err(unsupported(
                "MOS allocation config exceeds the native nvlist reader budget or is empty",
            ));
        }
        let mut bytes = Vec::with_capacity(length as usize);
        let block_bytes = object.node.data_bytes() as u64;
        let blocks = length.div_ceil(block_bytes);
        if blocks - 1 > object.node.max_block() {
            return Err(corrupt("MOS config size exceeds its dnode geometry"));
        }
        for id in 0..blocks {
            let block = budget
                .block(&mut view, cx, &object, id)?
                .ok_or_else(|| corrupt("MOS config contains a sparse block"))?;
            let count = (length - bytes.len() as u64).min(block_bytes) as usize;
            bytes.extend_from_slice(&block.bytes[..count]);
        }
        let config = NvList::parse_exact(&bytes).map_err(|error| parse(&error))?;
        if view.config.raidz_members.is_none() && view.pool.leaves().len() > 1 {
            // Mirrors retain GUID ownership in their labels rather than a
            // native child mapping in VdevConfig. Include their bounded reread.
            budget.charge(view.pool.leaves().len() as u64 * 4 * LABEL_CONFIG_BYTES as u64)?;
        }
        let mut tops = view.allocation_topology(cx, &config)?;
        let mut count = 0;
        let mut identities = BTreeSet::from([1, config_id]);
        // Resolve the complete metaslab/object namespace before reading any
        // space-map stream. Zero IDs are native never-initialized metaslabs.
        for top in &mut tops {
            let number = top.asize >> top.shift;
            count = sum(count, number)?;
            if number == 0 || count > limits.metaslabs {
                return Err(unsupported("allocation inspection exceeds metaslab budget"));
            }
            if top.array == 0 || !identities.insert(top.array) {
                return Err(corrupt("metaslab-array object is absent or aliased"));
            }
            let array = budget.load(&mut view, cx, top.array)?;
            if array.node.object_type() != 2
                || array.node.bonus_type() != 0
                || !array.node.bonus().is_empty()
                || array.node.spill().is_some()
            {
                return Err(corrupt("metaslab array has the wrong native layout"));
            }
            top.objects = Vec::with_capacity(number as usize);
            let per_block = array.node.data_bytes() as u64 / 8;
            for block_id in 0..number.div_ceil(per_block) {
                checkpoint(cx)?;
                let block = if block_id <= array.node.max_block() {
                    budget.block(&mut view, cx, &array, block_id)?
                } else {
                    None
                };
                let remaining = number - top.objects.len() as u64;
                for slot in 0..remaining.min(per_block) {
                    checkpoint(cx)?;
                    let id = match &block {
                        Some(block) => block
                            .order
                            .u64(&block.bytes, slot as usize * 8)
                            .map_err(|error| parse(&error))?,
                        None => 0,
                    };
                    if id != 0 && (id >= super::MAX_OBJECT || !identities.insert(id)) {
                        return Err(corrupt(
                            "space-map object aliases another metaslab or metadata object",
                        ));
                    }
                    top.objects.push(id);
                }
            }
        }
        let mut report = PoolAllocation {
            pool_guid: view.config.pool_guid,
            txg: view.txg,
            mapped_bytes: 0,
            allocated_bytes: 0,
            free_bytes: 0,
            records_examined: 0,
            charged_metadata_bytes: 0,
            vdevs: Vec::new(),
        };
        for top in tops {
            let size = 1_u64 << top.shift;
            let mapped_bytes = size * top.objects.len() as u64; // bounded by asize
            let mut vdev = VdevAllocation {
                id: top.id,
                guid: top.guid,
                ashift: top.ashift,
                metaslab_shift: top.shift,
                metaslab_array: top.array,
                asize: top.asize,
                mapped_bytes,
                allocated_bytes: 0,
                free_bytes: 0,
                unmapped_tail_bytes: top.asize - mapped_bytes,
                metaslabs: Vec::new(),
            };
            for (id, object) in top.objects.into_iter().enumerate() {
                checkpoint(cx)?;
                let start = id as u64 * size;
                let (map, stream_bytes) = view.load_allocation_map(
                    cx,
                    object,
                    MetaslabRegion {
                        start,
                        size,
                        shift: top.ashift,
                    },
                    v2,
                    limits.ranges_per_metaslab,
                    &mut budget,
                )?;
                let mut cursor = start;
                let mut free_ranges = 0;
                let mut largest = 0;
                for range in map.ranges() {
                    checkpoint(cx)?;
                    if range.start > cursor {
                        free_ranges += 1;
                        largest = largest.max(range.start - cursor);
                    }
                    cursor = range.end;
                }
                if cursor < start + size {
                    free_ranges += 1;
                    largest = largest.max(start + size - cursor);
                }
                let allocated = map.allocated_bytes();
                vdev.allocated_bytes = sum(vdev.allocated_bytes, allocated)?;
                vdev.free_bytes = sum(vdev.free_bytes, size - allocated)?;
                vdev.metaslabs.push(MetaslabAllocation {
                    id: id as u64,
                    object,
                    start,
                    size,
                    allocated_bytes: allocated,
                    free_bytes: size - allocated,
                    allocated_ranges: map.range_count(),
                    free_ranges,
                    largest_free_range: largest,
                    stream_bytes,
                });
            }
            report.mapped_bytes = sum(report.mapped_bytes, vdev.mapped_bytes)?;
            report.allocated_bytes = sum(report.allocated_bytes, vdev.allocated_bytes)?;
            report.free_bytes = sum(report.free_bytes, vdev.free_bytes)?;
            report.vdevs.push(vdev);
        }
        report.records_examined = limits.records - budget.records;
        report.charged_metadata_bytes = limits.metadata_bytes - budget.bytes;
        checkpoint(cx)?;
        Ok(report)
    }

    fn load_allocation_map(
        &mut self,
        cx: &Cx,
        number: u64,
        region: MetaslabRegion,
        v2: bool,
        max_ranges: usize,
        budget: &mut Budget,
    ) -> Result<(AllocationMap, u64)> {
        let MetaslabRegion { start, size, shift } = region;
        let mut map =
            AllocationMap::new(start, size, shift, max_ranges).map_err(|error| parse(&error))?;
        if number == 0 {
            return Ok((map, 0));
        }
        let object = budget.load(self, cx, number)?;
        if object.node.object_type() != 8
            || object.node.bonus_type() != 7
            || object.node.spill().is_some()
        {
            return Err(corrupt(
                "metaslab reference is not a native space-map object",
            ));
        }
        let header = Header::parse(object.node.bonus(), object.node.order())
            .map_err(|error| parse(&error))?;
        let expected = u64::try_from(header.allocated)
            .map_err(|_| corrupt("metaslab space map has negative allocated bytes"))?;
        if expected > size || !expected.is_multiple_of(1_u64 << shift) {
            return Err(corrupt(
                "metaslab space-map allocation counter exceeds its region",
            ));
        }
        let bytes = object.node.data_bytes() as u64;
        let blocks = header.length.div_ceil(bytes);
        if blocks != 0 && blocks - 1 > object.node.max_block() {
            return Err(corrupt(
                "space-map stream exceeds its native dnode geometry",
            ));
        }
        for id in 0..blocks {
            let block = budget
                .block(self, cx, &object, id)?
                .ok_or_else(|| corrupt("space-map stream contains a hole"))?;
            let used = (header.length - id * bytes).min(bytes) as usize;
            for record in Records::new(&block.bytes[..used], block.order, v2)
                .map_err(|error| parse(&error))?
            {
                checkpoint(cx)?;
                budget.records = budget
                    .records
                    .checked_sub(1)
                    .ok_or_else(|| unsupported("allocation inspection exceeds record budget"))?;
                if let Record::Extent(entry) = record.map_err(|error| parse(&error))? {
                    if entry.vdev.is_some_and(|id| id != 0) {
                        return Err(corrupt(
                            "metaslab space map contains a log-map vdev identity",
                        ));
                    }
                    let range = entry
                        .byte_range(start, size, shift)
                        .map_err(|error| parse(&error))?;
                    map.apply(entry.kind, range)
                        .map_err(|error| parse(&error))?;
                }
            }
        }
        if map.allocated_bytes() != expected {
            return Err(corrupt(
                "reconstructed allocation disagrees with native space-map counter",
            ));
        }
        checkpoint(cx)?;
        Ok((map, header.length))
    }

    fn allocation_topology(&self, cx: &Cx, config: &NvList) -> Result<Vec<Top>> {
        if config.fields.contains_key("hole_array") {
            return Err(unsupported(
                "removed top-level vdevs need separate allocation accounting",
            ));
        }
        if integer(config, "pool_guid")? != self.config.pool_guid
            || integer(config, "version")? != self.config.version
            || integer(config, "txg")? > self.txg
            || integer(config, "txg")? < self.config.txg
        {
            return Err(corrupt(
                "MOS allocation config disagrees with the selected pool view",
            ));
        }
        let root = config
            .list("vdev_tree")
            .ok_or_else(|| corrupt("MOS config has no vdev tree"))?;
        admit_vdev_state(root)?;
        if root.text("type") != Some("root")
            || integer(root, "guid")? != self.config.pool_guid
            || integer(root, "id")? != 0
        {
            return Err(corrupt("MOS allocation config has a foreign root vdev"));
        }
        let Some(Value::Lists(children)) = root.fields.get("children") else {
            return Err(corrupt("MOS allocation tree has no top-level children"));
        };
        let striped = self
            .config
            .raidz_members
            .as_ref()
            .filter(|group| group.parity == 0);
        let count = striped.map_or(1, |group| group.members.len());
        if children.len() != count {
            return Err(unsupported(
                "MOS allocation tree differs from the admitted topology",
            ));
        }
        let mut tops = Vec::with_capacity(count);
        for (index, child) in children.iter().enumerate() {
            checkpoint(cx)?;
            admit_vdev_state(child)?;
            if child
                .fields
                .get("nonallocating")
                .is_some_and(|value| !matches!(value, Value::Unsigned(0)))
            {
                return Err(unsupported(
                    "nonallocating vdev state needs separate accounting",
                ));
            }
            let (guid, ashift, asize) = striped.map_or(
                (
                    self.config.top_guid,
                    self.config.ashift,
                    self.config.allocated_bytes,
                ),
                |group| {
                    let member = &group.members[index];
                    (member.guid, member.ashift, member.allocated_bytes)
                },
            );
            if integer(child, "id")? != index as u64
                || integer(child, "guid")? != guid
                || integer(child, "ashift")? != u64::from(ashift)
                || integer(child, "asize")? != asize
            {
                return Err(corrupt(
                    "MOS metaslab geometry differs from admitted label geometry",
                ));
            }
            if striped.is_some() || self.pool.leaves().len() == 1 {
                physical_leaf(child)?;
            } else {
                let Some(Value::Lists(leaves)) = child.fields.get("children") else {
                    return Err(corrupt("MOS redundant allocation tree has no leaves"));
                };
                if leaves.len() != self.pool.leaves().len() {
                    return Err(corrupt("MOS allocation tree has a different member count"));
                }
                let mut guids = BTreeSet::from([self.config.pool_guid, guid]);
                for (id, leaf) in leaves.iter().enumerate() {
                    physical_leaf(leaf)?;
                    let member = integer(leaf, "guid")?;
                    if integer(leaf, "id")? != id as u64 || member == 0 || !guids.insert(member) {
                        return Err(corrupt("MOS allocation leaf IDs or GUIDs are not unique"));
                    }
                }
                if let Some(group) = &self.config.raidz_members {
                    if child.text("type") != Some("raidz")
                        || integer(child, "nparity")? != group.parity as u64
                        || leaves
                            .iter()
                            .zip(&group.members)
                            .any(|(leaf, member)| leaf.unsigned("guid") != Some(member.guid))
                    {
                        return Err(corrupt(
                            "MOS RAIDZ allocation layout disagrees with selected mapping",
                        ));
                    }
                } else {
                    if child.text("type") != Some("mirror") {
                        return Err(corrupt("MOS allocation tree is not the selected mirror"));
                    }
                    let expected: BTreeSet<_> = leaves
                        .iter()
                        .filter_map(|leaf| leaf.unsigned("guid"))
                        .collect();
                    self.check_allocation_mirror_members(cx, &expected)?;
                }
            }
            let shift = u8::try_from(integer(child, "metaslab_shift")?)
                .map_err(|_| corrupt("metaslab shift overflow"))?;
            if !(ashift..=63).contains(&shift)
                || asize == 0
                || !asize.is_multiple_of(1_u64 << ashift)
            {
                return Err(corrupt("invalid metaslab extent geometry"));
            }
            tops.push(Top {
                id: index as u32,
                guid,
                ashift,
                shift,
                asize,
                array: integer(child, "metaslab_array")?,
                objects: Vec::new(),
            });
        }
        Ok(tops)
    }

    fn check_allocation_mirror_members(&self, cx: &Cx, expected: &BTreeSet<u64>) -> Result<()> {
        let mut supplied = BTreeSet::new();
        for leaf in self.pool.leaves() {
            let mut matched = None;
            for index in 0..4 {
                checkpoint(cx)?;
                let label = match leaf.label(cx, index) {
                    Ok(label) => label,
                    Err(FfsError::Cancelled) => return Err(FfsError::Cancelled),
                    Err(_) => continue,
                };
                let candidate: VdevConfig =
                    match label.vdev_config_with_mode(self.config.pool_guid, true, false) {
                        Ok(candidate) => candidate,
                        Err(_) => continue,
                    };
                if candidate == self.config {
                    matched = label
                        .config
                        .unsigned("guid")
                        .filter(|guid| expected.contains(guid));
                    if matched.is_some() {
                        break;
                    }
                }
            }
            if !matched.is_some_and(|guid| supplied.insert(guid)) {
                return Err(corrupt(
                    "MOS allocation mirror does not match supplied member labels",
                ));
            }
        }
        if &supplied != expected {
            return Err(corrupt("incomplete allocation mirror identity set"));
        }
        Ok(())
    }
}

fn physical_leaf(tree: &NvList) -> Result<()> {
    if !matches!(tree.text("type"), Some("file" | "disk")) || tree.fields.contains_key("children") {
        return Err(unsupported(
            "allocation inspection needs the admitted ordinary vdev topology",
        ));
    }
    admit_vdev_state(tree)
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
