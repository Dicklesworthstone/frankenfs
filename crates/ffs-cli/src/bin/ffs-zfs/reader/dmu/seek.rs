//! Bounded allocation queries within one immutable DMU object-set view.
//!
//! Native holes are absent block pointers, not zero-filled or compressed data.
//! Only indirect blocks are read; leaf payload checksums/transforms remain the
//! responsibility of the ordinary read path. Tree ranges use u128 block IDs so
//! legal high-level geometry cannot wrap before it is clipped to ZPL_SIZE.

use super::{
    BlockPointer, Cx, Dnode, FfsError, Object, Objects, Result, checkpoint, corrupt, parse,
    unsupported,
};

const MAX_SEEK_POINTERS: usize = 1_048_576;
const MAX_SEEK_METADATA_BYTES: usize = 64 * 1024 * 1024;

struct Budget {
    pointers: usize,
    metadata_bytes: usize,
}

impl Budget {
    fn pointer(&mut self) -> Result<()> {
        self.pointers = self
            .pointers
            .checked_sub(1)
            .ok_or_else(|| unsupported("ZPL seek exceeds its DMU pointer-work budget"))?;
        Ok(())
    }

    fn metadata(&mut self, bytes: usize) -> Result<()> {
        self.metadata_bytes = self
            .metadata_bytes
            .checked_sub(bytes)
            .ok_or_else(|| unsupported("ZPL seek exceeds its 64 MiB metadata-work budget"))?;
        Ok(())
    }
}

struct Search {
    first: u128,
    end: u128,
    want_data: bool,
    budget: Budget,
}

struct Subtree {
    pointer: BlockPointer,
    first: u128,
    blocks: u128,
    level: u8,
    ceiling: u64,
}

fn no_data() -> FfsError {
    FfsError::Io(std::io::Error::from_raw_os_error(libc::ENXIO))
}

impl Objects {
    /// Seek at native logical-block granularity, with an implicit hole at EOF.
    /// The caller supplies a checked ZPL object and its native logical EOF.
    /// Cache hits count as metadata work too; a warm cache cannot bypass limits.
    pub(super) fn seek_data_hole(
        &mut self,
        cx: &Cx,
        object: &Object,
        file_size: u64,
        start: u64,
        want_data: bool,
    ) -> Result<u64> {
        checkpoint(cx)?;
        if start >= file_size {
            return Err(no_data());
        }
        let block_bytes = object.node.data_bytes() as u128;
        let mut search = Search {
            first: u128::from(start) / block_bytes,
            end: u128::from(file_size)
                .div_ceil(block_bytes)
                .min(u128::from(object.node.max_block()) + 1),
            want_data,
            budget: Budget {
                pointers: MAX_SEEK_POINTERS,
                metadata_bytes: MAX_SEEK_METADATA_BYTES,
            },
        };
        let level = object.node.levels() - 1;
        let blocks = (object.node.indirect_bytes() as u128 / 128)
            .checked_pow(u32::from(level))
            .ok_or_else(|| corrupt("DMU seek tree geometry overflow"))?;
        for (index, pointer) in object.node.pointers().iter().enumerate() {
            let subtree = Subtree {
                pointer: pointer.clone(),
                first: index as u128 * blocks,
                blocks,
                level,
                ceiling: object.ceiling,
            };
            if let Some(block) = self.seek_subtree(cx, &object.node, subtree, &mut search)? {
                // A returned block lies strictly below EOF, so this product
                // fits u64 even when the unvisited tree's capacity would not.
                let offset = u64::try_from(block * block_bytes)
                    .map_err(|_| corrupt("DMU seek result overflow"))?;
                checkpoint(cx)?;
                return Ok(offset.max(start));
            }
        }
        checkpoint(cx)?;
        if want_data {
            return Err(no_data());
        }
        // dn_maxblkid is not EOF. The logical tail beyond allocated geometry is
        // sparse even if all physically represented pointers contain data.
        let tail = (search.end * block_bytes).min(u128::from(file_size));
        let tail = u64::try_from(tail).map_err(|_| corrupt("DMU seek tail overflow"))?;
        Ok(tail.max(start))
    }

    fn seek_subtree(
        &mut self,
        cx: &Cx,
        node: &Dnode,
        subtree: Subtree,
        search: &mut Search,
    ) -> Result<Option<u128>> {
        checkpoint(cx)?;
        let end = subtree
            .first
            .checked_add(subtree.blocks)
            .ok_or_else(|| corrupt("DMU seek subtree overflow"))?;
        if subtree.first >= search.end || end <= search.first || search.first >= search.end {
            return Ok(None);
        }
        search.budget.pointer()?;
        let size = if subtree.level == 0 {
            node.data_bytes()
        } else {
            node.indirect_bytes()
        };
        let allocated = self.validate_pointer(
            &subtree.pointer,
            node.object_type(),
            subtree.level,
            size,
            subtree.ceiling,
        )?;
        if !allocated || subtree.level == 0 {
            // A hole at any level describes the whole logical subtree. A
            // non-hole leaf describes data, including embedded/gang/compressed
            // payloads. Neither case calls the physical data reader.
            checkpoint(cx)?;
            return Ok((allocated == search.want_data).then_some(subtree.first.max(search.first)));
        }
        // Charge before I/O/cache access. The parsed Dnode limits recursion to
        // twelve levels, with at most one retained indirect block per level.
        search.budget.metadata(size)?;
        let block = self
            .checked(
                cx,
                &subtree.pointer,
                node.object_type(),
                subtree.level,
                size,
                subtree.ceiling,
            )?
            .ok_or_else(|| corrupt("allocated DMU seek pointer became a hole"))?;
        let children = size / 128;
        let child_blocks = subtree.blocks / children as u128;
        if child_blocks == 0 {
            return Err(corrupt("DMU seek child has no logical range"));
        }
        let first = (search.first.saturating_sub(subtree.first) / child_blocks)
            .min(children as u128) as usize;
        let last = (search.end.min(end) - subtree.first)
            .div_ceil(child_blocks)
            .min(children as u128) as usize;
        for index in first..last {
            checkpoint(cx)?;
            let at = index * 128;
            let pointer = BlockPointer::parse(&block.bytes[at..at + 128], block.order)
                .map_err(|error| parse(&error))?;
            let child = Subtree {
                pointer,
                first: subtree.first + index as u128 * child_blocks,
                blocks: child_blocks,
                level: subtree.level - 1,
                ceiling: block.birth,
            };
            if let Some(found) = self.seek_subtree(cx, node, child, search)? {
                return Ok(Some(found));
            }
        }
        checkpoint(cx)?;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::super::super::{ByteOffset, DATA_OFFSET, LABEL_BYTES, Leaf, VdevConfig};
    use super::*;
    use ffs_block::ByteDevice;
    use ffs_ondisk::zfs::{Endian, checksum};
    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    const BASE: u64 = 1024;
    const LENGTH: u64 = 16 * 1024 * 1024;
    const INDIRECT: u64 = DATA_OFFSET + 0x10000;
    const LOWER: u64 = DATA_OFFSET + 0x12000;
    const DATA: u64 = DATA_OFFSET + 0x16000;
    type Reads = Arc<Mutex<Vec<(u64, usize)>>>;

    // Constructed traversal fixtures: bypass label/MOS admission on purpose.
    // Missing payload storage makes accidental file-data I/O fail, not pass.
    struct Memory {
        blocks: BTreeMap<u64, Vec<u8>>,
        reads: Reads,
        cancelled_at: Option<u64>,
    }

    impl ByteDevice for Memory {
        fn len_bytes(&self) -> u64 {
            BASE + LENGTH
        }

        fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, out: &mut [u8]) -> Result<()> {
            checkpoint(cx)?;
            self.reads.lock().unwrap().push((offset.0, out.len()));
            if self.cancelled_at == Some(offset.0) {
                return Err(FfsError::Cancelled);
            }
            let bytes = self
                .blocks
                .get(&offset.0)
                .filter(|bytes| bytes.len() == out.len())
                .ok_or_else(|| corrupt("seek attempted an unregistered payload read"))?;
            out.copy_from_slice(bytes);
            Ok(())
        }

        fn write_all_at(&self, _: &Cx, _: ByteOffset, _: &[u8]) -> Result<()> {
            panic!("sparse seek wrote to the backing image")
        }

        fn sync(&self, _: &Cx) -> Result<()> {
            panic!("sparse seek flushed the backing image")
        }
    }

    fn pointer(
        bytes: &[u8],
        at: u64,
        kind: u8,
        level: u8,
        birth: u64,
        containing: Endian,
        payload: Endian,
    ) -> Vec<u8> {
        let sectors = bytes.len() as u64 / 512;
        let mut words = [0_u64; 16];
        words[0] = sectors;
        words[1] = (at - DATA_OFFSET) / 512;
        words[6] = (sectors - 1)
            | ((sectors - 1) << 16)
            | (2 << 32)
            | (7 << 40)
            | (u64::from(kind) << 48)
            | (u64::from(level) << 56)
            | (u64::from(payload == Endian::Little) << 63);
        words[10] = birth;
        words[12..].copy_from_slice(&checksum(bytes, 7, payload).unwrap());
        words
            .into_iter()
            .flat_map(|word| containing.encode(word))
            .collect()
    }

    fn node(
        data_bytes: usize,
        levels: u8,
        shift: u8,
        maximum: u64,
        pointers: &[Vec<u8>],
        order: Endian,
    ) -> Dnode {
        let mut raw = vec![0; 512];
        raw[0] = 19;
        raw[1] = shift;
        raw[2] = levels;
        raw[3] = pointers.len() as u8;
        raw[7] = 1;
        let sectors = (data_bytes / 512) as u16;
        raw[8..10].copy_from_slice(&match order {
            Endian::Little => sectors.to_le_bytes(),
            Endian::Big => sectors.to_be_bytes(),
        });
        raw[16..24].copy_from_slice(&order.encode(maximum));
        for (index, pointer) in pointers.iter().enumerate() {
            raw[64 + index * 128..192 + index * 128].copy_from_slice(pointer);
        }
        Dnode::parse(&raw, order).unwrap()
    }

    fn view(blocks: BTreeMap<u64, Vec<u8>>, cancelled_at: Option<u64>) -> (Objects, Reads) {
        let reads = Arc::default();
        let leaf = Leaf::from_device(
            &Cx::for_testing(),
            Box::new(Memory {
                blocks,
                reads: Arc::clone(&reads),
                cancelled_at,
            }),
            BASE,
            LENGTH,
        )
        .unwrap();
        (
            Objects {
                pool: leaf.into(),
                config: VdevConfig {
                    pool_guid: 123,
                    top_guid: 999,
                    version: 5000,
                    txg: 42,
                    ashift: 9,
                    id: 0,
                    allocated_bytes: LENGTH - DATA_OFFSET - 2 * LABEL_BYTES,
                    read_features: Vec::new(),
                    raidz_members: None,
                },
                txg: 43,
                root_birth: 42,
                // Not consulted by seek_data_hole, whose object is already
                // loaded. No object/MOS-read success is inferred from this.
                meta: node(512, 1, 0, 0, &[vec![0; 128]], Endian::Little),
                cache: std::collections::VecDeque::new(),
                cached_bytes: 0,
            },
            reads,
        )
    }

    fn assert_no_data(result: Result<u64>) {
        assert!(matches!(
            result,
            Err(FfsError::Io(error)) if error.raw_os_error() == Some(libc::ENXIO)
        ));
    }

    #[test]
    fn sparse_seek_matches_every_direct_layout_without_reading_payloads() {
        let cx = Cx::for_testing();
        for order in [Endian::Little, Endian::Big] {
            for mask in 0_u8..8 {
                let pointers: Vec<_> = (0..3)
                    .map(|index| {
                        if mask & (1 << index) != 0 {
                            pointer(&[0; 512], DATA, 19, 0, 20, order, order)
                        } else {
                            vec![0; 128]
                        }
                    })
                    .collect();
                let object = Object {
                    node: node(512, 1, 0, 2, &pointers, order),
                    ceiling: 30,
                };
                let (mut objects, reads) = view(BTreeMap::new(), None);
                for eof in [0_u64, 1, 511, 512, 513, 1027, 1536, 4099] {
                    for start in [
                        0, 1, 510, 511, 512, 513, 1023, 1024, 1026, 1536, 4098, eof, u64::MAX,
                    ] {
                        for want_data in [false, true] {
                            // Independent bytewise oracle, including allocated
                            // zero-filled blocks, a partial last block and the
                            // unrepresented sparse tail after dn_maxblkid.
                            let expected = (start..eof).find(|offset| {
                                let block = offset / 512;
                                let data = block < 3 && mask & (1 << block) != 0;
                                data == want_data
                            });
                            let actual =
                                objects.seek_data_hole(&cx, &object, eof, start, want_data);
                            if start >= eof || expected.is_none() && want_data {
                                assert_no_data(actual);
                            } else {
                                assert_eq!(actual.unwrap(), expected.unwrap_or(eof));
                            }
                        }
                    }
                }
                assert!(reads.lock().unwrap().is_empty());
            }
        }
    }

    #[test]
    fn sparse_seek_descends_mixed_endian_metadata_and_skips_indirect_holes() {
        let cx = Cx::for_testing();
        for order in [Endian::Little, Endian::Big] {
            let other = if order == Endian::Little {
                Endian::Big
            } else {
                Endian::Little
            };
            let mut lower = vec![0; 4096];
            lower[5 * 128..6 * 128]
                .copy_from_slice(&pointer(&[0; 512], DATA, 19, 0, 20, order, other));
            let mut upper = vec![0; 4096];
            upper[128..256].copy_from_slice(&pointer(&lower, LOWER, 19, 1, 25, other, order));
            let root = pointer(&upper, INDIRECT, 19, 2, 30, order, other);
            let object = Object {
                node: node(512, 3, 12, 63, &[root], order),
                ceiling: 35,
            };
            let (mut objects, reads) = view(
                BTreeMap::from([(BASE + INDIRECT, upper), (BASE + LOWER, lower)]),
                None,
            );
            assert_eq!(
                objects.seek_data_hole(&cx, &object, 32768, 1, true).unwrap(),
                37 * 512
            );
            assert_eq!(
                objects
                    .seek_data_hole(&cx, &object, 32768, 37 * 512 + 3, false)
                    .unwrap(),
                38 * 512
            );
            assert_eq!(
                objects.seek_data_hole(&cx, &object, 32768, 1, false).unwrap(),
                1
            );
            assert_no_data(objects.seek_data_hole(&cx, &object, 32768, 38 * 512, true));
            assert_eq!(
                *reads.lock().unwrap(),
                [(BASE + INDIRECT, 4096), (BASE + LOWER, 4096)]
            );
        }
    }

    #[test]
    fn sparse_seek_clips_huge_tree_capacity_before_converting_to_byte_offsets() {
        let cx = Cx::for_testing();
        let object = Object {
            // 1024^11 logical blocks exceed a u64 byte address space by far.
            node: node(
                16 * 1024 * 1024,
                12,
                17,
                u64::MAX,
                &[vec![0; 128]],
                Endian::Big,
            ),
            ceiling: 30,
        };
        let (mut objects, reads) = view(BTreeMap::new(), None);
        for start in [0, 1 << 40, u64::MAX - 1] {
            assert_eq!(
                objects
                    .seek_data_hole(&cx, &object, u64::MAX, start, false)
                    .unwrap(),
                start
            );
            assert_no_data(objects.seek_data_hole(&cx, &object, u64::MAX, start, true));
        }
        assert_no_data(objects.seek_data_hole(&cx, &object, u64::MAX, u64::MAX, false));
        assert!(reads.lock().unwrap().is_empty());
    }

    #[test]
    fn sparse_seek_handles_non_power_of_two_single_record_and_sparse_tail() {
        let cx = Cx::for_testing();
        let order = Endian::Little;
        let object = Object {
            node: node(
                1536,
                1,
                0,
                0,
                &[pointer(&[0; 1536], DATA, 19, 0, 20, order, order)],
                order,
            ),
            ceiling: 30,
        };
        let (mut objects, reads) = view(BTreeMap::new(), None);
        assert_eq!(
            objects.seek_data_hole(&cx, &object, 1535, 1534, false).unwrap(),
            1535
        );
        assert_eq!(
            objects.seek_data_hole(&cx, &object, 1535, 1534, true).unwrap(),
            1534
        );
        assert_eq!(
            objects.seek_data_hole(&cx, &object, 1 << 40, 1, false).unwrap(),
            1536
        );
        assert_eq!(
            objects
                .seek_data_hole(&cx, &object, 1 << 40, 1537, false)
                .unwrap(),
            1537
        );
        assert_no_data(objects.seek_data_hole(&cx, &object, 1 << 40, 1536, true));
        assert!(reads.lock().unwrap().is_empty());
    }

    #[test]
    fn sparse_seek_keeps_leaf_type_level_size_and_historical_birth_checks() {
        let cx = Cx::for_testing();
        let order = Endian::Little;
        for (kind, level, bytes, birth) in [
            (18, 0, 512, 20),
            (19, 1, 512, 20),
            (19, 0, 1024, 20),
            (19, 0, 512, 31),
        ] {
            let object = Object {
                node: node(
                    512,
                    1,
                    0,
                    0,
                    &[pointer(&vec![0; bytes], DATA, kind, level, birth, order, order)],
                    order,
                ),
                ceiling: 30,
            };
            let (mut objects, reads) = view(BTreeMap::new(), None);
            for want_data in [false, true] {
                assert!(matches!(
                    objects.seek_data_hole(&cx, &object, 512, 0, want_data),
                    Err(FfsError::Corruption { .. })
                ));
            }
            assert!(reads.lock().unwrap().is_empty());
        }
        let mut hole = vec![0; 128];
        hole[80..88].copy_from_slice(&order.encode(31));
        let object = Object {
            node: node(512, 1, 0, 0, &[hole], order),
            ceiling: 30,
        };
        let (mut objects, _) = view(BTreeMap::new(), None);
        assert!(matches!(
            objects.seek_data_hole(&cx, &object, 512, 0, false),
            Err(FfsError::Corruption { .. })
        ));
    }

    #[test]
    fn sparse_seek_embedded_data_requires_features_but_not_payload_io() {
        let cx = Cx::for_testing();
        for order in [Endian::Little, Endian::Big] {
            let mut words = [0_u64; 16];
            words[0] = u64::from_le_bytes([0, 0, 0, 12, 0x1f, b'E', 1, 0]);
            words[1] = u64::from_le_bytes([255, 232, 0x50, b'E', b'E', b'E', b'E', b'E']);
            words[6] = 511 | (15 << 25) | (15 << 32) | (1 << 39) | (19 << 48);
            words[10] = 20;
            let pointer = words
                .into_iter()
                .flat_map(|word| order.encode(word))
                .collect();
            let object = Object {
                node: node(512, 1, 0, 0, &[pointer], order),
                ceiling: 30,
            };
            let (mut objects, reads) = view(BTreeMap::new(), None);
            assert!(matches!(
                objects.seek_data_hole(&cx, &object, 511, 0, true),
                Err(FfsError::UnsupportedFeature(_))
            ));
            objects
                .config
                .read_features
                .push("com.delphix:embedded_data".into());
            assert_eq!(objects.seek_data_hole(&cx, &object, 511, 7, true).unwrap(), 7);
            assert_eq!(
                objects.seek_data_hole(&cx, &object, 511, 7, false).unwrap(),
                511
            );
            objects.config.read_features.clear();
            assert!(matches!(
                objects.seek_data_hole(&cx, &object, 511, 7, true),
                Err(FfsError::UnsupportedFeature(_))
            ));
            assert!(reads.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn sparse_seek_preserves_indirect_checksum_and_cancellation_failures() {
        let cx = Cx::for_testing();
        let order = Endian::Little;
        let clean = vec![0; 4096];
        let root = pointer(&clean, INDIRECT, 19, 1, 25, order, order);
        let object = Object {
            node: node(512, 2, 12, 31, &[root], order),
            ceiling: 30,
        };
        for want_data in [false, true] {
            let mut damaged = clean.clone();
            damaged[4000] ^= 1;
            let (mut objects, reads) = view(BTreeMap::from([(BASE + INDIRECT, damaged)]), None);
            assert!(
                objects
                    .seek_data_hole(&cx, &object, 16384, 0, want_data)
                    .is_err()
            );
            assert!(objects.cache.is_empty());
            assert_eq!(*reads.lock().unwrap(), [(BASE + INDIRECT, 4096)]);
            let (mut objects, reads) = view(BTreeMap::new(), Some(BASE + INDIRECT));
            assert!(matches!(
                objects.seek_data_hole(&cx, &object, 16384, 0, want_data),
                Err(FfsError::Cancelled)
            ));
            assert!(objects.cache.is_empty());
            assert_eq!(*reads.lock().unwrap(), [(BASE + INDIRECT, 4096)]);
        }
    }

    #[test]
    fn sparse_seek_rechecks_parent_births_after_metadata_is_cached() {
        let cx = Cx::for_testing();
        for order in [Endian::Little, Endian::Big] {
            let mut indirect = vec![0; 4096];
            indirect[..128]
                .copy_from_slice(&pointer(&[0; 512], DATA, 19, 0, 26, order, order));
            let root = pointer(&indirect, INDIRECT, 19, 1, 25, order, order);
            let mut object = Object {
                node: node(512, 2, 12, 31, &[root], order),
                ceiling: 30,
            };
            let (mut objects, reads) =
                view(BTreeMap::from([(BASE + INDIRECT, indirect)]), None);
            for want_data in [true, false] {
                // This child fits the selected TXG and dnode ceiling, but is
                // newer than its checksum-valid containing indirect block.
                assert!(matches!(
                    objects.seek_data_hole(&cx, &object, 16384, 0, want_data),
                    Err(FfsError::Corruption { .. })
                ));
            }
            assert_eq!(objects.cache.len(), 1);
            // The exact same cached root is also rejected under an older
            // parent ceiling, before a hole can be reported from its contents.
            object.ceiling = 24;
            assert!(matches!(
                objects.seek_data_hole(&cx, &object, 16384, 512, false),
                Err(FfsError::Corruption { .. })
            ));
            assert_eq!(*reads.lock().unwrap(), [(BASE + INDIRECT, 4096)]);
        }
    }

    #[test]
    fn sparse_seek_work_limits_apply_before_reads_and_to_cached_metadata() {
        let cx = Cx::for_testing();
        let order = Endian::Little;
        let bytes = vec![0; 4096];
        let root = pointer(&bytes, INDIRECT, 19, 1, 25, order, order);
        let node = node(512, 2, 12, 31, &[root], order);
        let (mut objects, reads) = view(BTreeMap::from([(BASE + INDIRECT, bytes)]), None);
        let subtree = || Subtree {
            pointer: node.pointers()[0].clone(),
            first: 0,
            blocks: 32,
            level: 1,
            ceiling: 30,
        };
        let search = |pointers, metadata_bytes| Search {
            first: 0,
            end: 32,
            want_data: true,
            budget: Budget {
                pointers,
                metadata_bytes,
            },
        };
        assert!(matches!(
            objects.seek_subtree(&cx, &node, subtree(), &mut search(33, 4095)),
            Err(FfsError::UnsupportedFeature(_))
        ));
        assert!(reads.lock().unwrap().is_empty());
        let mut exact = search(33, 4096);
        assert_eq!(
            objects.seek_subtree(&cx, &node, subtree(), &mut exact).unwrap(),
            None
        );
        assert_eq!((exact.budget.pointers, exact.budget.metadata_bytes), (0, 0));
        assert_eq!(*reads.lock().unwrap(), [(BASE + INDIRECT, 4096)]);
        assert!(matches!(
            objects.seek_subtree(&cx, &node, subtree(), &mut search(33, 4095)),
            Err(FfsError::UnsupportedFeature(_))
        ));
        assert!(matches!(
            objects.seek_subtree(&cx, &node, subtree(), &mut search(32, 4096)),
            Err(FfsError::UnsupportedFeature(_))
        ));
        assert_eq!(*reads.lock().unwrap(), [(BASE + INDIRECT, 4096)]);
    }
}
