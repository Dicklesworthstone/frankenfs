//! Read-only proof and survivor plan for removing an empty trailing vdev.

use std::collections::BTreeSet;

use super::super::ZfsStorageIdentity;
use super::*;
use crate::reader::dmu::Objects;
use crate::reader::pool::vdev::{PoolTopology, TopVdevKind, VdevHealth};
use ffs_ondisk::zfs_dmu::{
    OBJSET_GROUPUSED_OFFSET, OBJSET_PROJECTUSED_OFFSET, OBJSET_USERUSED_OFFSET, dnode_at,
};

pub(super) struct EmptyRemovalPlan {
    pub(super) mos: Objects,
    pub(super) config: NvList,
    pub(super) pool: crate::Pool,
    pub(super) identity: ZfsStorageIdentity,
    pub(super) label_offsets: Vec<[u64; 4]>,
    pub(super) labels: Vec<Vec<u8>>,
    pub(super) retired_objects: Vec<u64>,
    pub(super) next_txg: u64,
}

impl EmptyRemovalPlan {
    #[allow(clippy::too_many_lines)]
    pub(super) fn build(
        cx: &Cx,
        engine: &ZfsTransactionEngine,
        source: u32,
        target: u32,
        extents: &[(u64, u64)],
    ) -> Result<Self> {
        checkpoint(cx)?;
        if engine.requires_recovery() {
            return Err(unsupported(
                "vdev removal requires recovery of the uncertain writer",
            ));
        }
        if source == target || target != engine.allocator.vdev_id {
            return Err(unsupported(
                "vdev removal must retain the current allocating vdev",
            ));
        }
        if engine.current_uberblock.checkpoint_txg != 0
            || !engine.allocator.checkpoint_deferred_frees.is_empty()
            || [
                &engine.mos_features.read_features,
                &engine.mos_features.write_features,
            ]
            .iter()
            .any(|features| {
                features
                    .get("com.delphix:zpool_checkpoint")
                    .copied()
                    .unwrap_or(0)
                    != 0
            })
        {
            return Err(unsupported(
                "vdev removal requires a fully discarded pool checkpoint",
            ));
        }
        if engine.current_uberblock.raidz_reflow_info != 0 {
            return Err(unsupported(
                "vdev removal requires a completed RAIDZ expansion",
            ));
        }
        if [
            &engine.mos_features.read_features,
            &engine.mos_features.write_features,
        ]
        .iter()
        .any(|features| {
            features
                .get("com.delphix:log_spacemap")
                .copied()
                .unwrap_or(0)
                != 0
        }) {
            return Err(unsupported(
                "empty-vdev removal requires fully consolidated native space maps",
            ));
        }
        if !extents.is_empty() {
            return Err(unsupported(
                "allocated-vdev evacuation requires survivor bootstrap and indirect-free accounting; caller extents are not allocation authority",
            ));
        }
        let next_txg = engine
            .committed_txg
            .checked_add(1)
            .ok_or_else(|| corrupt("ZFS TXG counter overflow"))?;
        let mut mos = engine.open_read_objects(cx)?;
        let mut config = mos.load_mos_config_nvlist(cx)?;
        let topology =
            PoolTopology::from_mos_config(&config, &engine.storage_identity.member_guids)?;
        if topology.pool_guid != engine.storage_identity.pool_guid
            || topology.guid_sum != engine.storage_identity.guid_sum
        {
            return Err(corrupt(
                "vdev removal MOS identity disagrees with the admitted writer",
            ));
        }
        if !topology.spares.is_empty() || !topology.l2cache.is_empty() {
            return Err(unsupported(
                "empty-vdev removal requires a pool without auxiliary devices",
            ));
        }
        let tops = match config
            .list("vdev_tree")
            .and_then(|root| root.fields.get("children"))
        {
            Some(Value::Lists(tops)) => tops,
            _ => return Err(corrupt("vdev removal requires native top-level children")),
        };
        let source_index =
            usize::try_from(source).map_err(|_| corrupt("source vdev ID overflow"))?;
        if tops.len() < 2 || source_index.checked_add(1) != Some(tops.len()) {
            return Err(unsupported(
                "only an empty trailing top-level vdev can be removed without indirect mappings",
            ));
        }
        if topology.top_vdev(target).is_none() {
            return Err(corrupt("removal target vdev is absent"));
        }
        let mut assigned = BTreeSet::new();
        for (tree, top) in tops.iter().zip(&topology.top_vdevs) {
            if !matches!(top.kind, TopVdevKind::Leaf | TopVdevKind::Mirror)
                || top.alloc_class != AllocClass::Normal
                || !top.is_complete()
                || !top.health.is_healthy()
                || top.ashift != engine.allocator.ashift
                || !(9..=16).contains(&top.ashift)
            {
                return Err(unsupported(
                    "empty-vdev removal requires complete healthy normal leaf or mirror vdevs with matching sectors",
                ));
            }
            if let Some(children) = tree.fields.get("children") {
                let Value::Lists(children) = children else {
                    return Err(corrupt("removal vdev children are not an array"));
                };
                if children.iter().any(|child| {
                    !matches!(child.text("type"), Some("file" | "disk"))
                        || child.fields.contains_key("children")
                        || !VdevHealth::from_vdev_tree(child).is_healthy()
                }) {
                    return Err(unsupported(
                        "empty-vdev removal requires direct healthy physical children",
                    ));
                }
            }
            let shift = tree
                .unsigned("metaslab_shift")
                .ok_or_else(|| corrupt("removal vdev has no metaslab shift"))?;
            if shift < u64::from(top.ashift) || shift > 62 || top.asize == 0 {
                return Err(corrupt("invalid removal metaslab geometry"));
            }
            for member in top.supplied_indices.iter().flatten() {
                if !assigned.insert(*member) {
                    return Err(corrupt("removal physical member belongs to multiple vdevs"));
                }
                let leaf = engine
                    .pool
                    .leaves()
                    .get(*member)
                    .ok_or_else(|| corrupt("removal member route is absent"))?;
                let end = label_offsets(leaf.length_bytes()).map_err(|e| parse_err(&e))?[2];
                if end
                    .checked_sub(DATA_OFFSET)
                    .is_none_or(|capacity| top.asize > capacity)
                {
                    return Err(corrupt("removal vdev exceeds its physical member"));
                }
            }
        }
        if assigned.len() != engine.pool.leaves().len() {
            return Err(unsupported(
                "empty-vdev removal cannot retain unassigned physical devices",
            ));
        }

        // This reader returns a complete replay or an error; its work budgets
        // never turn a partial allocation inventory into an empty source.
        let allocation = mos.allocation(
            cx,
            crate::reader::dmu::allocation::AllocationLimits {
                metadata_bytes: 64 * 1024 * 1024,
                ..crate::reader::dmu::allocation::AllocationLimits::default()
            },
        )?;
        if allocation.pool_guid != topology.pool_guid
            || allocation.txg != engine.committed_txg
            || allocation.vdevs.len() != topology.top_vdevs.len()
        {
            return Err(corrupt(
                "removal allocation inventory does not cover the selected native topology",
            ));
        }
        let mut owned_objects = BTreeSet::new();
        let mut retired_objects = Vec::new();
        for vdev in &allocation.vdevs {
            let top = topology
                .top_vdev(vdev.id)
                .ok_or_else(|| corrupt("removal allocation inventory names a foreign vdev"))?;
            if vdev.guid != top.guid || vdev.ashift != top.ashift || vdev.asize != top.asize {
                return Err(corrupt(
                    "removal allocation geometry disagrees with its native vdev",
                ));
            }
            if vdev.id == source && vdev.allocated_bytes != 0 {
                return Err(unsupported(
                    "source vdev still owns allocated space; native indirect evacuation is not yet admitted",
                ));
            }
            for object in std::iter::once(vdev.metaslab_array).chain(
                vdev.metaslabs
                    .iter()
                    .map(|ms| ms.object)
                    .filter(|object| *object != 0),
            ) {
                if object == 0 || !owned_objects.insert(object) {
                    return Err(corrupt(
                        "vdev metaslab metadata aliases another allocation domain",
                    ));
                }
                if vdev.id == source {
                    retired_objects.push(object);
                }
            }
        }
        RemovalReferences::new(source).verify_pool(
            cx,
            &mut mos,
            &engine.current_uberblock.root,
            &engine.mos_os,
        )?;

        let removed: BTreeSet<_> = topology
            .top_vdev(source)
            .ok_or_else(|| corrupt("source vdev is absent"))?
            .supplied_indices
            .iter()
            .flatten()
            .copied()
            .collect();
        let survivors: Vec<_> = (0..engine.pool.leaves().len())
            .filter(|index| !removed.contains(index))
            .collect();
        if survivors.is_empty()
            || engine.storage_identity.member_guids.len() != engine.pool.leaves().len()
            || engine.storage_identity.member_dev_inos.len() != engine.pool.leaves().len()
        {
            return Err(corrupt(
                "removal would lose the admitted physical device set",
            ));
        }
        let old_count = u64::try_from(tops.len()).map_err(|_| corrupt("vdev count overflow"))?;
        let new_count = old_count - 1;
        let mut labels = Vec::with_capacity(survivors.len());
        let mut offsets = Vec::with_capacity(survivors.len());
        for (index, leaf) in engine.pool.leaves().iter().enumerate() {
            let label = leaf.label(cx, 0)?;
            if label.config.unsigned("pool_guid") != Some(engine.storage_identity.pool_guid)
                || label.config.unsigned("guid")
                    != engine.storage_identity.member_guids.get(index).copied()
                || label.config.unsigned("vdev_children") != Some(old_count)
            {
                return Err(corrupt(
                    "removal member identity changed after writer admission",
                ));
            }
            if removed.contains(&index) {
                continue;
            }
            let mut updated = label.config;
            updated
                .fields
                .insert("txg".into(), Value::Unsigned(next_txg));
            updated
                .fields
                .insert("vdev_children".into(), Value::Unsigned(new_count));
            let packed = updated.encode_xdr().map_err(|e| parse_err(&e))?;
            if packed.len() > LABEL_CONFIG_BYTES - 40 {
                return Err(unsupported(
                    "removal label configuration exceeds native label capacity",
                ));
            }
            labels.push(packed);
            offsets.push(label_offsets(leaf.length_bytes()).map_err(|e| parse_err(&e))?);
        }
        let pool = crate::Pool::from_wide_leaves(
            survivors
                .iter()
                .map(|index| engine.pool.leaves()[*index].clone())
                .collect(),
        )?;
        let mut identity = engine.storage_identity.clone();
        identity.member_guids = survivors
            .iter()
            .map(|index| engine.storage_identity.member_guids[*index])
            .collect();
        identity.member_dev_inos = survivors
            .iter()
            .map(|index| engine.storage_identity.member_dev_inos[*index])
            .collect();
        identity.guid_sum =
            PoolTopology::compute_guid_sum(identity.pool_guid, &topology.top_vdevs[..source_index]);
        let first_top = topology
            .top_vdevs
            .iter()
            .find(|top| top.children_guids.contains(&identity.member_guids[0]))
            .ok_or_else(|| corrupt("surviving member has no top-level identity"))?;
        identity.top_guid = first_top.guid;
        identity.ashift = first_top.ashift;
        identity.asize = first_top.asize;
        identity.label_txg = next_txg;
        identity.topology = if new_count > 1 {
            ZfsTopologyKind::MultiVdev {
                top_levels: source_index,
            }
        } else if identity.member_guids.len() == 1 {
            ZfsTopologyKind::SingleLeaf
        } else {
            ZfsTopologyKind::Mirror {
                width: identity.member_guids.len(),
            }
        };
        let Some(Value::List(root)) = config.fields.get_mut("vdev_tree") else {
            return Err(corrupt("removal MOS root disappeared"));
        };
        let Some(Value::Lists(children)) = root.fields.get_mut("children") else {
            return Err(corrupt("removal MOS children disappeared"));
        };
        children.pop();
        config
            .fields
            .insert("vdev_children".into(), Value::Unsigned(new_count));
        config
            .fields
            .insert("txg".into(), Value::Unsigned(next_txg));
        Ok(Self {
            mos,
            config,
            pool,
            identity,
            label_offsets: offsets,
            labels,
            retired_objects,
            next_txg,
        })
    }
}

/// Strictly inspect every allocated MOS dnode, including snapshot dataset
/// bonuses and deferred BP objects. Best-effort scrub enumeration is not proof
/// that an apparently empty device is unreferenced.
struct RemovalReferences {
    source: u32,
    metadata_left: usize,
    pointers_left: usize,
}

impl RemovalReferences {
    fn new(source: u32) -> Self {
        Self {
            source,
            metadata_left: 64 * 1024 * 1024,
            pointers_left: 1_048_576,
        }
    }

    fn charge(&mut self, bytes: usize) -> Result<()> {
        self.metadata_left = self.metadata_left.checked_sub(bytes).ok_or_else(|| {
            unsupported("empty-vdev reference verification exceeds 64 MiB of metadata")
        })?;
        Ok(())
    }

    fn pointer(&mut self, bp: &BlockPointer) -> Result<()> {
        self.pointers_left = self.pointers_left.checked_sub(1).ok_or_else(|| {
            unsupported("empty-vdev reference verification exceeds its pointer budget")
        })?;
        if bp.hole() || bp.embedded() {
            return Ok(());
        }
        if bp.protected() {
            return Err(unsupported(
                "empty-vdev removal requires unencrypted ownership metadata",
            ));
        }
        for dva in bp.data_dvas().map_err(|e| parse_err(&e))? {
            if dva.vdev == self.source {
                return Err(corrupt(
                    "empty source space maps disagree with a retained block reference",
                ));
            }
            if dva.gang {
                return Err(unsupported(
                    "empty-vdev removal requires direct non-gang block references",
                ));
            }
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn tree(
        &mut self,
        cx: &Cx,
        view: &mut Objects,
        node: &Dnode,
        bp: &BlockPointer,
        level: u8,
        ceiling: u64,
    ) -> Result<()> {
        checkpoint(cx)?;
        let bytes = if level == 0 {
            node.data_bytes()
        } else {
            node.indirect_bytes()
        };
        if !view.validate_pointer(bp, node.object_type(), level, bytes, ceiling)? {
            return Ok(());
        }
        self.pointer(bp)?;
        if level == 0 || bp.embedded() {
            return Ok(());
        }
        self.charge(bytes)?;
        let Some((raw, order, birth)) =
            view.checked_raw(cx, bp, node.object_type(), level, bytes, ceiling)?
        else {
            return Err(corrupt(
                "allocated ownership pointer unexpectedly became a hole",
            ));
        };
        for encoded in raw.as_chunks::<128>().0 {
            let child = BlockPointer::parse(encoded, order).map_err(|e| parse_err(&e))?;
            self.tree(cx, view, node, &child, level - 1, birth)?;
        }
        Ok(())
    }

    fn node(&mut self, cx: &Cx, view: &mut Objects, node: &Dnode, ceiling: u64) -> Result<()> {
        let level = node
            .levels()
            .checked_sub(1)
            .ok_or_else(|| corrupt("zero-level ownership dnode"))?;
        for bp in node.pointers() {
            self.tree(cx, view, node, bp, level, ceiling)?;
        }
        if let Some(spill) = node.spill() {
            self.pointer(spill)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn objectset(
        &mut self,
        cx: &Cx,
        view: &mut Objects,
        os: &ObjectSet,
        order: Endian,
        ceiling: u64,
        mos: bool,
    ) -> Result<Vec<(BlockPointer, u64)>> {
        if !os.zil_header.log.hole() {
            return Err(unsupported(
                "empty-vdev removal requires object sets without retained ZIL blocks",
            ));
        }
        self.node(cx, view, &os.meta, ceiling)?;
        for offset in [
            OBJSET_USERUSED_OFFSET,
            OBJSET_GROUPUSED_OFFSET,
            OBJSET_PROJECTUSED_OFFSET,
        ] {
            if let Some(node) = os
                .embedded_dnode(offset, order)
                .map_err(|e| parse_err(&e))?
            {
                self.node(cx, view, &node, ceiling)?;
            }
        }
        if os.meta.max_block() > 4096 {
            return Err(unsupported(
                "empty-vdev removal dnode table exceeds verification bounds",
            ));
        }
        let mut datasets = Vec::new();
        for block in 0..=os.meta.max_block() {
            checkpoint(cx)?;
            self.charge(DNODE_BLOCK_BYTES)?;
            let Some((raw, block_order, birth)) =
                view.object_data_block(cx, &os.meta, ceiling, block)?
            else {
                continue;
            };
            let mut slot = 0;
            while slot < DNODE_BLOCK_BYTES / DNODE_BYTES {
                let Some(node) = dnode_at(&raw, slot, block_order).map_err(|e| parse_err(&e))?
                else {
                    slot += 1;
                    continue;
                };
                slot += node.slots();
                self.node(cx, view, &node, birth)?;
                if mos && node.bonus_type() == DMU_OT_DSL_DATASET {
                    if node.bonus().len() < 256 {
                        return Err(corrupt("truncated dataset ownership bonus"));
                    }
                    let bp = BlockPointer::parse(&node.bonus()[128..256], node.order())
                        .map_err(|e| parse_err(&e))?;
                    self.pointer(&bp)?;
                    if !bp.hole() {
                        datasets.push((bp, birth));
                    }
                }
                if mos && node.object_type() == DMU_OT_BPOBJ {
                    if node.bonus_type() != DMU_OT_BPOBJ_HDR || node.bonus().len() < 16 {
                        return Err(corrupt("invalid deferred BP object during removal"));
                    }
                    let count = node
                        .order()
                        .u64(node.bonus(), 0)
                        .map_err(|e| parse_err(&e))?;
                    let len = count
                        .checked_mul(128)
                        .and_then(|bytes| usize::try_from(bytes).ok())
                        .ok_or_else(|| corrupt("deferred BP object length overflow"))?;
                    self.charge(len)?;
                    let bytes =
                        super::super::dmu_cow::read_dnode_prefix(cx, view, &node, birth, len)?;
                    for encoded in bytes.as_chunks::<128>().0 {
                        self.pointer(
                            &BlockPointer::parse(encoded, node.order())
                                .map_err(|e| parse_err(&e))?,
                        )?;
                    }
                }
            }
        }
        Ok(datasets)
    }

    fn verify_pool(
        mut self,
        cx: &Cx,
        mos: &mut Objects,
        root: &BlockPointer,
        os: &ObjectSet,
    ) -> Result<()> {
        self.pointer(root)?;
        let directory = mos.zap_values(cx, 1)?;
        if zap_optional_u64(&directory, b"bptree_obj")?.is_some_and(|object| object != 0) {
            return Err(unsupported(
                "empty-vdev removal requires completed asynchronous dataset destruction",
            ));
        }
        if zap_optional_u64(&directory, b"log_spacemaps")?.is_some_and(|object| object != 0) {
            return Err(unsupported(
                "empty-vdev removal requires fully consolidated native space maps",
            ));
        }
        let datasets = self.objectset(cx, mos, os, root.payload_order(), root.birth(), true)?;
        for (bp, ceiling) in datasets {
            self.charge(bp.logical_bytes())?;
            let (raw, order, birth) =
                mos.read_dataset_objset_block_raw(cx, &bp, ceiling, None, false)?;
            let dataset = ObjectSet::parse(&raw, order).map_err(|e| parse_err(&e))?;
            if !matches!(dataset.kind, 2 | 3) {
                return Err(unsupported(
                    "empty-vdev removal encountered an unsupported dataset object set",
                ));
            }
            let mut view = mos.open_objectset_view(dataset.meta.clone(), birth, mos.txg);
            let _ = self.objectset(cx, &mut view, &dataset, order, birth, false)?;
        }
        Ok(())
    }
}

companion_bin_tests! {
#[cfg(test)]
mod tests {
    use super::*;
    use ffs_types::ByteOffset;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    };

    #[derive(Clone)]
    struct MemoryDevice {
        bytes: Arc<Mutex<Vec<u8>>>,
        writes: Arc<AtomicUsize>,
    }

    impl MemoryDevice {
        fn new() -> Self {
            Self {
                bytes: Arc::new(Mutex::new(vec![0; 12 * 1024 * 1024])),
                writes: Arc::new(AtomicUsize::new(0)),
            }
        }
    }

    impl ByteDevice for MemoryDevice {
        fn len_bytes(&self) -> u64 {
            u64::try_from(self.bytes.lock().unwrap().len()).unwrap()
        }

        fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
            checkpoint(cx)?;
            let start = usize::try_from(offset.0).map_err(|_| corrupt("test offset overflow"))?;
            let end = start.checked_add(out.len()).ok_or_else(|| corrupt("test read overflow"))?;
            let bytes = self.bytes.lock().unwrap();
            let source = bytes.get(start..end).ok_or_else(|| corrupt("test read past device"))?;
            out.copy_from_slice(source);
            Ok(())
        }

        fn write_all_at(&self, cx: &Cx, offset: ByteOffset, input: &[u8]) -> Result<()> {
            checkpoint(cx)?;
            let start = usize::try_from(offset.0).map_err(|_| corrupt("test offset overflow"))?;
            let end = start.checked_add(input.len()).ok_or_else(|| corrupt("test write overflow"))?;
            let mut bytes = self.bytes.lock().unwrap();
            let target = bytes.get_mut(start..end).ok_or_else(|| corrupt("test write past device"))?;
            target.copy_from_slice(input);
            self.writes.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }

        fn sync(&self, cx: &Cx) -> Result<()> {
            checkpoint(cx)
        }
    }

    fn fixture(guid: u64) -> (Cx, ZfsTransactionEngine, Vec<MemoryDevice>) {
        let cx = Cx::for_testing();
        let devices = vec![MemoryDevice::new(), MemoryDevice::new()];
        let boxes = || devices.iter().cloned()
            .map(|device| Box::new(device) as Box<dyn ByteDevice>).collect();
        let mut spec = ZfsPoolCreateSpec::single_leaf("removal_ownership", guid);
        spec.vdevs.push(ZfsCreateVdevSpec {
            kind: ZfsCreateVdevKind::Leaf,
            alloc_class: AllocClass::Normal,
        });
        let created = create_pool_on_devices(&cx, boxes(), &spec).unwrap();
        let engine = ZfsTransactionEngine::from_devices(
            &cx,
            boxes(),
            super::super::super::ZfsWriteOptions {
                offline_image: true,
                allow_write: true,
                pool_guid: guid,
                label: 0,
                slot: created.initial_slot,
                reconcile_torn_uberblocks: false,
            },
        ).unwrap();
        (cx, engine, devices)
    }

    fn assert_refusal(
        cx: &Cx,
        engine: &mut ZfsTransactionEngine,
        devices: &[MemoryDevice],
        expected: Option<&str>,
    ) {
        let before: Vec<_> = devices.iter().map(|device| device.bytes.lock().unwrap().clone()).collect();
        let writes: Vec<_> = devices.iter().map(|device| device.writes.load(Ordering::Relaxed)).collect();
        let error = match engine.remove_vdev(cx, 1, 0, &[]) {
            ZfsTxOutcome::NotCommitted(error) => error,
            outcome => panic!("unsafe removal outcome: {outcome:?}"),
        };
        if let Some(expected) = expected {
            assert!(error.to_string().contains(expected), "{error}");
        }
        for ((device, before), writes) in devices.iter().zip(before).zip(writes) {
            assert_eq!(*device.bytes.lock().unwrap(), before);
            assert_eq!(device.writes.load(Ordering::Relaxed), writes);
        }
    }

    #[test]
    fn empty_removal_rejects_aliased_nonempty_source_maps_despite_an_empty_request() {
        let (cx, mut engine, devices) = fixture(0x5245_4D4F_5645_5100);
        let order = engine.order;
        engine.execute_staged_txg_typed(
            &cx,
            "removal_source_map_fixture",
            |mos, dirty, _features, alloc, txg, staged| {
                let mut config = mos.load_mos_config_nvlist(&cx)?;
                let Some(Value::List(root)) = config.fields.get_mut("vdev_tree") else {
                    return Err(corrupt("fixture root absent"));
                };
                let Some(Value::Lists(tops)) = root.fields.get_mut("children") else {
                    return Err(corrupt("fixture children absent"));
                };
                // This deliberately inconsistent native config exposes the
                // primary's nonempty committed map as the source's map. The
                // removal must replay it and refuse before trusting [].
                let array = tops[0].unsigned("metaslab_array").unwrap();
                tops[1].fields.insert("metaslab_array".into(), Value::Unsigned(array));
                write_mos_config_nvlist(
                    &cx, mos, dirty, alloc, order, txg, &config, staged,
                )?;
                Ok(((), 0))
            },
        ).into_result().unwrap();
        assert_refusal(&cx, &mut engine, &devices, None);
    }

    #[test]
    fn empty_removal_checks_snapshot_only_source_references_before_writes() {
        let (cx, mut engine, devices) = fixture(0x5245_4D4F_5645_5200);
        let timestamp = ffs_ondisk::zfs_zpl::Timestamp {
            seconds: 1_735_014_100,
            nanos: 0,
        };
        let (snapshot, _) = engine.create_snapshot(&cx, &[], b"retained", timestamp)
            .into_result().unwrap();
        engine.execute_staged_txg_typed(
            &cx,
            "removal_snapshot_reference_fixture",
            |mos, dirty, _features, _alloc, _txg, _staged| {
                let (mut node, _) = mos.object_with_ceiling(&cx, snapshot)?;
                let order = node.order();
                let mut bonus = node.bonus().to_vec();
                let bp = BlockPointer::parse(&bonus[128..256], order).map_err(|e| parse_err(&e))?;
                let mut encoded = bp.encode(order);
                // Native DVA word 0 stores the top-level ID in its high 32 bits.
                // Keep the physical checksum unchanged while making this
                // snapshot's root disagree with the source's empty space maps.
                let word = order.u64(&encoded, 0).map_err(|e| parse_err(&e))?;
                encoded[..8].copy_from_slice(&order.encode((word & 0xffff_ffff) | (1_u64 << 32)));
                bonus[128..256].copy_from_slice(&encoded);
                let bonus_type = node.bonus_type();
                let spill = node.spill().cloned();
                node.set_bonus_and_spill(bonus_type, bonus, spill).map_err(|e| parse_err(&e))?;
                let meta = mos.meta_dnode().clone();
                let ceiling = mos.root_birth_txg();
                put_dnode_in_table(&cx, mos, &meta, ceiling, dirty, snapshot, &node)?;
                Ok(((), snapshot))
            },
        ).into_result().unwrap();
        assert_refusal(&cx, &mut engine, &devices, Some("retained block reference"));
    }
}
}
