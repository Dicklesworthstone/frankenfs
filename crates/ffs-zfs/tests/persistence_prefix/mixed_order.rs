//! Foreign byte orders remain readable but copied metadata must not be relabeled.

use super::*;

const TIME: Timestamp = Timestamp {
    seconds: 1_731_234_567,
    nanos: 73,
};

fn native_block(image: &[u8], pointer: &BlockPointer) -> Vec<u8> {
    let dva = pointer.regular_dvas().unwrap()[0];
    let start = usize::try_from(DATA_OFFSET + dva.offset).unwrap();
    ffs_ondisk::zfs::decompress(
        &image[start..start + pointer.physical_bytes()],
        pointer.compression(),
        pointer.logical_bytes(),
    )
    .unwrap()
}

fn native_objectset(cx: &Cx, engine: &ZfsTransactionEngine, image: &[u8]) -> ObjectSet {
    let mut mos = engine.open_read_objects(cx).unwrap();
    let dataset = mos
        .datasets(cx)
        .unwrap()
        .into_iter()
        .find(|row| row.components == [b"data".to_vec()])
        .unwrap();
    let head = mos.object(cx, dataset.head_object).unwrap();
    let pointer = BlockPointer::parse(&head.bonus()[128..256], head.order()).unwrap();
    ObjectSet::parse(&native_block(image, &pointer), pointer.payload_order()).unwrap()
}

pub fn build_zvol_objectset(
    arena: &mut RawArena,
    birth: u64,
    objectset_order: Endian,
    contents_order: Endian,
) -> (BlockPointer, u64, Vec<u8>) {
    let mut table = vec![0; DNODE_BLOCK_BYTES];
    for (object, kind, payload) in [
        (1, 23, vec![0x6a; 512]),
        (2, 24, mzap(&[(b"size", 4096)], 0x777, contents_order)),
    ] {
        let pointer = arena.alloc_block(&payload, kind, 0, birth, contents_order);
        let node = make_dnode(
            kind,
            payload.len(),
            vec![pointer],
            0,
            Vec::new(),
            None,
            0,
            contents_order,
        );
        write_dnode_at(&mut table, object, &node).unwrap();
    }
    let pointer = arena.alloc_block(&table, DMU_OT_DNODE, 0, birth, contents_order);
    let meta = make_dnode(
        DMU_OT_DNODE,
        DNODE_BLOCK_BYTES,
        vec![pointer],
        0,
        Vec::new(),
        None,
        0,
        objectset_order,
    );
    let objectset = ObjectSet::new(3, 0, meta, ZilHeader::empty(), 1024).unwrap();
    let bytes = objectset.encode(objectset_order).unwrap();
    let root = arena.alloc_block(&bytes, DMU_OT_OBJSET, 0, birth, objectset_order);
    let referenced = objectset.meta.used_bytes() + bp_allocated_bytes(&root);
    (root, referenced, Vec::new())
}

#[test]
fn mixed_order_dnode_leaf_preserves_untouched_sa_neighbors() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    for leaf_order in [Endian::Little, Endian::Big] {
        let (mut engine, devices) = file_range_fixture(
            &cx,
            &PoolFixtureSpec {
                extra_zpl_leaf_order: Some(leaf_order),
                deadlist_mode: DeadlistMode::NativeDeadlist,
                ..PoolFixtureSpec::default()
            },
        );
        let image = devices[0].durable_snapshot();
        let objectset = native_objectset(&cx, &engine, &image);
        assert_eq!(objectset.meta.order(), Endian::Little);
        let pointer = &objectset.meta.pointers()[1];
        assert_eq!(pointer.payload_order(), leaf_order);
        let table = native_block(&image, pointer);
        assert_eq!(
            ffs_ondisk::zfs_dmu::count_allocated_dnodes(&table, leaf_order).unwrap(),
            2
        );
        let original = ffs_ondisk::zfs_dmu::dnode_at(&table, 1, leaf_order)
            .unwrap()
            .unwrap();
        assert_eq!(original.bonus().len(), 256);
        if leaf_order == Endian::Big {
            // The old COW structural counter accepts this entire block in the
            // wrong order. It silently sees a one-byte SA bonus in the untouched
            // neighbor; a checksum-valid replacement would make it unreadable.
            assert_eq!(
                ffs_ondisk::zfs_dmu::count_allocated_dnodes(&table, Endian::Little).unwrap(),
                2
            );
            let wrong = ffs_ondisk::zfs_dmu::dnode_at(&table, 1, Endian::Little)
                .unwrap()
                .unwrap();
            assert_eq!(wrong.bonus().len(), 1);
        }
        let mut head = file_range_head(&cx, &engine);
        assert_eq!(head.resolve(&cx, b"/foreign.bin").unwrap(), 32);
        assert_eq!(head.resolve(&cx, b"/neighbor.bin").unwrap(), 33);
        assert_eq!(head.read(&cx, 32, 0, 512).unwrap(), vec![0x71; 512]);
        assert_eq!(head.read(&cx, 33, 0, 512).unwrap(), vec![0x72; 512]);
        let neighbor = head.stat(&cx, 33).unwrap();
        let attrs = ffs_zfs::ZfsPosixSetAttr {
            mtime: Some(TIME),
            ..ffs_zfs::ZfsPosixSetAttr::default()
        };
        let operation = |writer: &mut ZfsTransactionEngine| {
            writer.set_posix_attributes(&cx, &dataset, 32, &attrs, TIME, ZfsDataChecksum::Fletcher4)
        };
        if leaf_order == Endian::Big {
            assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, operation);
            assert_eq!(devices[0].durable_snapshot(), image);
        } else {
            operation(&mut engine).into_result().unwrap();
            assert_eq!(
                file_range_head(&cx, &engine).stat(&cx, 32).unwrap().0.times[1],
                TIME
            );
        }
        let slot = engine.committed_slot();
        drop(engine);
        let fresh: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let reopened =
            open_engine_on_devices(&cx, &fresh, default_write_opts(POOL_GUID, slot)).unwrap();
        let mut head = file_range_head(&cx, &reopened);
        assert_eq!(head.stat(&cx, 33).unwrap(), neighbor);
        assert_eq!(head.read(&cx, 32, 0, 512).unwrap(), vec![0x71; 512]);
        assert_eq!(head.read(&cx, 33, 0, 512).unwrap(), vec![0x72; 512]);
        assert_pool_scrub_and_allocation_clean(&cx, &fresh, POOL_GUID, None);
    }
}

#[test]
fn mixed_order_zpl_objectset_without_limits_refuses_before_backing_writes() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    for user_accounting in [false, true] {
        let (mut engine, devices) = file_range_fixture(
            &cx,
            &PoolFixtureSpec {
                zpl_order: Some(Endian::Big),
                zpl_contents_order: Some(Endian::Little),
                user_accounting,
                deadlist_mode: DeadlistMode::NativeDeadlist,
                ..PoolFixtureSpec::default()
            },
        );
        let image = devices[0].durable_snapshot();
        let objectset = native_objectset(&cx, &engine, &image);
        assert_eq!(objectset.meta.order(), Endian::Big);
        assert_eq!(objectset.meta.pointers()[0].payload_order(), Endian::Little);
        let mut head = file_range_head(&cx, &engine);
        assert_eq!(head.read(&cx, 4, 0, 8192).unwrap(), b"SNAPDATA".repeat(512));
        assert_eq!(head.read(&cx, 5, 0, 4096).unwrap(), vec![0x5a; 4096]);
        let attrs = ffs_zfs::ZfsPosixSetAttr {
            mtime: Some(TIME),
            ..ffs_zfs::ZfsPosixSetAttr::default()
        };
        assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
            writer.set_posix_attributes(&cx, &dataset, 5, &attrs, TIME, ZfsDataChecksum::Fletcher4)
        });
        assert_eq!(devices[0].durable_snapshot(), image);
        assert_eq!(
            file_range_head(&cx, &engine).read(&cx, 5, 0, 4096).unwrap(),
            vec![0x5a; 4096]
        );
    }
}

#[test]
fn mixed_order_zvol_objectsets_and_leaves_preserve_reads_and_refuse_resize() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    for (objectset_order, contents_order) in [
        (Endian::Little, Endian::Little),
        (Endian::Big, Endian::Little),
        (Endian::Little, Endian::Big),
    ] {
        let (mut engine, devices) = file_range_fixture(
            &cx,
            &PoolFixtureSpec {
                zvol_orders: Some((objectset_order, contents_order)),
                deadlist_mode: DeadlistMode::NativeDeadlist,
                ..PoolFixtureSpec::default()
            },
        );
        let before = devices[0].durable_snapshot();
        let info = engine.zvol_info(&cx, &dataset, None).unwrap();
        assert_eq!((info.volsize, info.volblocksize), (4096, 512));
        let mut bytes = vec![0; 512];
        engine
            .zvol_read_at(&cx, &dataset, None, 0, &mut bytes)
            .unwrap();
        assert_eq!(bytes, vec![0x6a; 512]);
        if objectset_order == Endian::Little && contents_order == Endian::Little {
            engine
                .zvol_resize(&cx, &dataset, 8192)
                .into_result()
                .unwrap();
            assert_eq!(engine.zvol_info(&cx, &dataset, None).unwrap().volsize, 8192);
        } else {
            assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
                writer.zvol_resize(&cx, &dataset, 8192)
            });
            assert_eq!(devices[0].durable_snapshot(), before);
            assert_eq!(engine.zvol_info(&cx, &dataset, None).unwrap(), info);
        }
        engine
            .zvol_read_at(&cx, &dataset, None, 0, &mut bytes)
            .unwrap();
        assert_eq!(bytes, vec![0x6a; 512]);
    }
}
