//! Context-sized legacy and native hole-birth pointers.
//!
//! OpenZFS zfs-2.3.0 dnode_sync.c/free_blocks and zio.c write a zero pointer
//! with only LSIZE, TYPE, LEVEL and logical birth retained. dbuf.c supplies
//! zeroes from dnode geometry, without physical reads. The recorded LSIZE of
//! a data hole is historical, not permission to allocate that many zeroes.

use super::{BlockPointer, Endian, Objects, Result, corrupt, parse, unsupported};
use ffs_ondisk::zfs::MAX_BLOCK_BYTES;

impl Objects {
    pub(super) fn validate_hole(
        &self,
        bp: &BlockPointer,
        kind: u8,
        level: u8,
        size: usize,
    ) -> Result<()> {
        if !bp.hole() || !(512..=MAX_BLOCK_BYTES).contains(&size)
            || !size.is_multiple_of(512) || level > 31
        {
            return Err(corrupt("invalid DMU hole or context geometry"));
        }
        let mut raw = [0_u8; 128];
        let zero = BlockPointer::parse(&raw, Endian::Little).map_err(|error| parse(&error))?;
        if bp == &zero {
            return Ok(()); // Legacy holes carry no size/type/birth information.
        }
        if self.config.version != 5000 || !self.config.read_features.iter()
            .any(|name| name == "com.delphix:hole_birth")
        {
            return Err(unsupported("nonzero DMU hole requires native hole_birth admission"));
        }
        if bp.birth() == 0 || bp.object_type() != kind || bp.level() != level
            || (level != 0 && bp.logical_bytes() != size)
        {
            return Err(corrupt("native hole birth, type or indirect geometry disagrees"));
        }
        // Compare complete numeric pointers to check every reserved/DVA word
        // without exposing their private representation. Data-hole LSIZE is
        // retained metadata; current dnode geometry supplies the logical span.
        let property = (bp.logical_bytes() as u64 / 512 - 1)
            | (u64::from(kind) << 48) | (u64::from(level) << 56);
        raw[48..56].copy_from_slice(&property.to_le_bytes());
        raw[80..88].copy_from_slice(&bp.birth().to_le_bytes());
        let canonical = BlockPointer::parse(&raw, Endian::Little)
            .map_err(|error| parse(&error))?;
        if bp != &canonical {
            return Err(corrupt("hole retains noncanonical allocation, transform or checksum fields"));
        }
        Ok(())
    }
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::reader::{ByteOffset, Cx, DATA_OFFSET, FfsError, Leaf, VdevConfig};
        use crate::reader::dmu::{Object, Dnode};
        use ffs_block::ByteDevice;
        use std::collections::VecDeque;

        struct NoIo;
        impl ByteDevice for NoIo {
            fn len_bytes(&self) -> u64 { 8 * 1024 * 1024 }
            fn read_exact_at(&self, _: &Cx, _: ByteOffset, _: &mut [u8]) -> Result<()> {
                panic!("hole handling issued a physical read")
            }
            fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> Result<()> {
                panic!("hole handling wrote backing storage")
            }
            fn sync(&self, _: &Cx) -> Result<()> { panic!("hole handling flushed storage") }
        }

        fn hole(size: usize, kind: u8, level: u8, birth: u64, order: Endian) -> [u8; 128] {
            let mut raw = [0; 128];
            let property = (size as u64 / 512 - 1)
                | (u64::from(kind) << 48) | (u64::from(level) << 56);
            raw[48..56].copy_from_slice(&order.encode(property));
            raw[80..88].copy_from_slice(&order.encode(birth));
            raw
        }

        // Construct a private DMU view to exercise actual read/seek methods.
        // Public label/MOS admission is tested separately in features::tests.
        fn view(raw: &[u8], order: Endian, size: usize, levels: u8) -> (Objects, Object) {
            let mut node = vec![0; 512];
            node[0] = 19;
            node[1] = 12;
            node[2] = levels;
            node[3] = 1;
            let sectors = (size / 512) as u16;
            node[8..10].copy_from_slice(&match order {
                Endian::Little => sectors.to_le_bytes(),
                Endian::Big => sectors.to_be_bytes(),
            });
            let last = if levels == 1 { 0 } else { 1_u64 << (5 * (levels - 1) - 1) };
            node[16..24].copy_from_slice(&order.encode(last));
            node[64..192].copy_from_slice(raw);
            let node = Dnode::parse(&node, order).unwrap();
            let object = Object { node: node.clone(), ceiling: 80 };
            let leaf = Leaf::from_device(&Cx::for_testing(), Box::new(NoIo), 0, 8 * 1024 * 1024).unwrap();
            let view = Objects {
                pool: leaf.into(),
                config: VdevConfig {
                    pool_guid: 1, top_guid: 2, version: 5000, txg: 100,
                    ashift: 9, id: 0, allocated_bytes: DATA_OFFSET - 512 * 1024,
                    read_features: vec!["com.delphix:hole_birth".into()], raidz_members: None,
                },
                txg: 100, root_birth: 90, meta: node, cache: VecDeque::new(), cached_bytes: 0,
            };
            (view, object)
        }

        #[test]
        fn legacy_holes_remain_context_sized_without_feature_admission() {
            for levels in [1, 2, 12] {
                let (mut view, object) = view(&[0; 128], Endian::Little, 4096, levels);
                view.config.version = 28;
                view.config.read_features.clear();
                assert!(view.data_block(&Cx::for_testing(), &object, 0).unwrap().is_none());
                assert_eq!(view.seek_data_hole(&Cx::for_testing(), &object, 4096, 37, false).unwrap(), 37);
                assert!(view.seek_data_hole(&Cx::for_testing(), &object, 4096, 37, true).is_err());
                assert!(view.cache.is_empty());
            }
        }

        #[test]
        fn born_holes_skip_whole_subtrees_in_reads_and_allocation_seeks() {
            let cx = Cx::for_testing();
            for order in [Endian::Little, Endian::Big] {
                for levels in [1, 2, 12] {
                    let level = levels - 1;
                    let raw = hole(if level == 0 { 512 } else { 4096 }, 19, level, 70, order);
                    let (mut view, object) = view(&raw, order, 4096, levels);
                    assert!(view.data_block(&cx, &object, object.node.max_block()).unwrap().is_none());
                    let eof = if levels == 1 { 4096 } else { (1_u64 << 40) + 7 };
                    assert_eq!(view.seek_data_hole(&cx, &object, eof, 73, false).unwrap(), 73);
                    let error = view.seek_data_hole(&cx, &object, eof, 73, true).unwrap_err();
                    assert!(matches!(error, FfsError::Io(error) if error.raw_os_error() == Some(libc::ENXIO)));
                    assert!(view.cache.is_empty());
                    assert_eq!(view.cached_bytes, 0);
                }
            }
        }

        #[test]
        fn born_holes_require_the_feature_and_valid_parent_and_view_births() {
            let cx = Cx::for_testing();
            let raw = hole(512, 19, 0, 70, Endian::Little);
            let (mut selected, mut object) = view(&raw, Endian::Little, 512, 1);
            selected.config.read_features.clear();
            assert!(matches!(selected.data_block(&cx, &object, 0), Err(FfsError::UnsupportedFeature(_))));
            selected.config.read_features.push("com.delphix:hole_birth".into());
            selected.config.version = 28;
            assert!(selected.data_block(&cx, &object, 0).is_err());
            selected.config.version = 5000;
            object.ceiling = 69;
            assert!(selected.data_block(&cx, &object, 0).is_err());
            object.ceiling = 80;
            selected.txg = 69;
            assert!(selected.seek_data_hole(&cx, &object, 512, 0, false).is_err());
            selected.txg = 70;
            assert!(selected.data_block(&cx, &object, 0).unwrap().is_none());
        }

        #[test]
        fn every_noncanonical_hole_word_is_rejected_without_io() {
            for order in [Endian::Little, Endian::Big] {
                let good = hole(512, 19, 0, 70, order);
                let (selected, _) = view(&good, order, 512, 1);
                for word in 0..16 {
                    if matches!(word, 6 | 10) { continue; }
                    for bit in 0..64 {
                        let mut raw = good;
                        raw[word * 8..word * 8 + 8].copy_from_slice(&order.encode(1_u64 << bit));
                        let bp = BlockPointer::parse(&raw, order).unwrap();
                        assert!(selected.validate_hole(&bp, 19, 0, 512).is_err(), "word {word} bit {bit}");
                    }
                }
                for bit in (16..48).chain(61..64) {
                    let mut raw = good;
                    let property = order.u64(&raw, 48).unwrap() | (1_u64 << bit);
                    raw[48..56].copy_from_slice(&order.encode(property));
                    if let Ok(bp) = BlockPointer::parse(&raw, order) {
                        assert!(selected.validate_hole(&bp, 19, 0, 512).is_err(), "property bit {bit}");
                    }
                }
                for (kind, level, size, birth) in [(20, 0, 512, 70), (19, 1, 512, 70), (19, 0, 512, 0)] {
                    let bp = BlockPointer::parse(&hole(size, kind, level, birth, order), order).unwrap();
                    assert!(selected.validate_hole(&bp, 19, 0, 512).is_err());
                }
                let bp = BlockPointer::parse(&hole(8192, 19, 1, 70, order), order).unwrap();
                assert!(selected.validate_hole(&bp, 19, 1, 4096).is_err());
            }
        }

        #[test]
        fn erased_data_addresses_do_not_turn_a_transformed_pointer_into_zeroes() {
            let mut raw = hole(512, 19, 0, 70, Endian::Little);
            let property = Endian::Little.u64(&raw, 48).unwrap() | (2 << 32) | (7 << 40);
            raw[48..56].copy_from_slice(&property.to_le_bytes());
            let (mut selected, object) = view(&raw, Endian::Little, 512, 1);
            assert!(selected.data_block(&Cx::for_testing(), &object, 0).is_err());
            assert!(selected.seek_data_hole(&Cx::for_testing(), &object, 512, 0, false).is_err());
            assert!(selected.cache.is_empty());
        }
    }
}
