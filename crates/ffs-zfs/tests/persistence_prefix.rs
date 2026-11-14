#![forbid(unsafe_code)]
//! Native ZFS v5000 TXG lifecycle, metaslab space-map convergence, ZPL v4/v5 + snapshot
//! deadlist COW, persistence-prefix fault-cut / write-reordering / torn-Uberblock /
//! mirror-split-flush / post-commit-cancel schedules, upfront `ENOSPC`, negative
//! admission controls, and OpenZFS `zdb` leak/checksum oracle verification.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::{FfsError, Result};
use ffs_ondisk::zfs::{
    BlockPointer, DATA_OFFSET, Dva, Endian, LABEL_BYTES, LABEL_CONFIG_BYTES, LABEL_CONFIG_OFFSET,
    MMP_MAGIC, RegularBlockSpec, UBERBLOCK_RING_BYTES, UBERBLOCK_RING_OFFSET, Uberblock,
    label_offsets, stamp_label_checksum,
};
use ffs_ondisk::zfs_dmu::space_map::{
    AllocationMap, Header as SpaceMapHeader, MapType, Record as SpaceMapRecord,
    extent_records_for_range,
};
use ffs_ondisk::zfs_dmu::{
    DMU_OT_DNODE, DMU_OT_OBJECT_DIRECTORY, DMU_OT_OBJSET, DNODE_BLOCK_BYTES, DNODE_BYTES,
    DNODE_FLAG_SPILL_BLKPTR, DNODE_FLAG_USED_BYTES, DNODE_FLAG_USEROBJUSED_ACCOUNTED,
    DNODE_FLAG_USERUSED_ACCOUNTED, Dnode, DnodeSpec, OBJSET_GROUPUSED_OFFSET,
    OBJSET_USERUSED_OFFSET, ObjectSet, ZapEntry, ZilHeader, encode_microzap, write_dnode_at,
};
use ffs_ondisk::zfs_zap::{Entry as RawZapEntry, encode_fatzap_with_flags};
use ffs_ondisk::zfs_zpl::{Kind, Metadata, SaRegistry, Timestamp, encode_directory_reference};
use ffs_types::ByteOffset;
use ffs_zfs::reader::dmu::allocation::AllocationLimits;
use ffs_zfs::reader::dmu::scrub::ScrubLimits;
use ffs_zfs::{
    Leaf, Pool, ZfsDataChecksum, ZfsPersistenceStage, ZfsTopologyKind, ZfsTransactionEngine,
    ZfsTxOutcome, ZfsWriteOptions,
};

const POOL_GUID: u64 = 0x5A46_535F_5445_5354;
const TOP_SINGLE_GUID: u64 = 0x1111_2222_3333_4444;
const TOP_MIRROR_GUID: u64 = 0x7777_8888_9999_AAAA;
const CHILD_GUIDS: [u64; 2] = [0x1001_0000_0000_0001, 0x1002_0000_0000_0002];
const INITIAL_TXG: u64 = 20;
const SNAP_TXG: u64 = 15;
const SLAB_SHIFT: u64 = 22; // 4 MiB metaslabs

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeadlistMode {
    None,
    Bpobj,
    NativeDeadlist,
}

#[derive(Debug, Clone)]
struct PoolFixtureSpec {
    pool_name: String,
    member_path_override: Option<String>,
    image_bytes: u64,
    ashift: u8,
    mirror_width: usize,
    zpl_version: u64,
    with_sa_spill: bool,
    user_accounting: bool,
    deadlist_mode: DeadlistMode,
    preallocate_nearly_full: bool,
    pool_state: u64,
    multihost_label: bool,
    active_mmp_uberblock: bool,
    dirty_zil: bool,
    zpl_flags: BTreeMap<u64, u64>,
    root_properties: Vec<(&'static [u8], u64)>,
    data_properties: Vec<(&'static [u8], u64)>,
}

impl Default for PoolFixtureSpec {
    fn default() -> Self {
        Self {
            pool_name: "ffstestpool".to_owned(),
            member_path_override: None,
            image_bytes: 16 * 1024 * 1024,
            ashift: 9,
            mirror_width: 1,
            zpl_version: 5,
            with_sa_spill: false,
            user_accounting: false,
            deadlist_mode: DeadlistMode::None,
            preallocate_nearly_full: false,
            pool_state: 1,
            multihost_label: false,
            active_mmp_uberblock: false,
            dirty_zil: false,
            zpl_flags: BTreeMap::new(),
            root_properties: Vec::new(),
            data_properties: Vec::new(),
        }
    }
}

struct BuiltPool {
    members: Vec<Vec<u8>>,
    pool_guid: u64,
    initial_slot: usize,
    snap_hello_expected: Vec<u8>,
}

// ---------------------------------------------------------------------------
// XDR nvlist packing helpers for pool labels & MOS object 5 (`config`)
// ---------------------------------------------------------------------------

fn xdr_string(value: &str) -> Vec<u8> {
    let mut bytes = u32::try_from(value.len()).unwrap().to_be_bytes().to_vec();
    bytes.extend_from_slice(value.as_bytes());
    bytes.resize(bytes.len().next_multiple_of(4), 0);
    bytes
}

fn nv_pair(name: &str, kind: u32, count: u32, data: &[u8], dec_val_bytes: usize) -> Vec<u8> {
    let mut bytes = vec![0_u8; 8];
    bytes.extend_from_slice(&xdr_string(name));
    bytes.extend_from_slice(&kind.to_be_bytes());
    bytes.extend_from_slice(&count.to_be_bytes());
    bytes.extend_from_slice(data);
    let len = u32::try_from(bytes.len()).unwrap();
    let dec_sz = u32::try_from(
        (16 + name.len() + 1).next_multiple_of(8) + dec_val_bytes.next_multiple_of(8),
    )
    .unwrap();
    bytes[0..4].copy_from_slice(&len.to_be_bytes());
    bytes[4..8].copy_from_slice(&dec_sz.to_be_bytes());
    bytes
}

fn nv_u64(name: &str, value: u64) -> Vec<u8> {
    nv_pair(name, 8, 1, &value.to_be_bytes(), 8)
}

fn nv_str(name: &str, value: &str) -> Vec<u8> {
    nv_pair(name, 9, 1, &xdr_string(value), value.len() + 1)
}

fn nv_bool(name: &str) -> Vec<u8> {
    nv_pair(name, 1, 0, &[], 0)
}

fn nv_list_body(pairs: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![0, 0, 0, 0, 0, 0, 0, 1]; // nvl_version=0, nvl_nvflag=NV_UNIQUE_NAME(1)
    for p in pairs {
        bytes.extend_from_slice(p);
    }
    bytes.extend_from_slice(&[0_u8; 8]);
    bytes
}

fn nv_embedded(name: &str, pairs: &[Vec<u8>]) -> Vec<u8> {
    nv_pair(name, 19, 1, &nv_list_body(pairs), 24)
}

fn nv_list_array(name: &str, items: &[Vec<Vec<u8>>]) -> Vec<u8> {
    let mut payload = Vec::new();
    for item in items {
        payload.extend_from_slice(&nv_list_body(item));
    }
    nv_pair(
        name,
        20,
        u32::try_from(items.len()).unwrap(),
        &payload,
        items.len() * 32,
    )
}

fn pack_xdr_nvlist(pairs: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![1, 1, 0, 0]; // NV_ENCODE_XDR (1), big-endian XDR stream (1)
    out.extend_from_slice(&nv_list_body(pairs));
    out
}

// ---------------------------------------------------------------------------
// Clean ZFS v5000 pool builder
// ---------------------------------------------------------------------------

struct RawArena {
    sector: u64,
    cursor: u64,
    limit: u64,
    blocks: BTreeMap<u64, Vec<u8>>,
    alloc_map: AllocationMap,
}

impl RawArena {
    fn new(asize: u64, ashift: u8) -> Self {
        let sector = 1_u64 << ashift;
        Self {
            sector,
            cursor: sector * 8, // start cleanly past vdev offset 0
            limit: asize,
            blocks: BTreeMap::new(),
            alloc_map: AllocationMap::new(0, asize, ashift, 262_144).expect("alloc map"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn alloc_raw_compressed(
        &mut self,
        logical: &[u8],
        physical_payload: &[u8],
        object_type: u8,
        level: u8,
        compress_type: u8,
        checksum_type: u8,
        birth: u64,
        order: Endian,
    ) -> BlockPointer {
        let lsize = logical.len();
        let psize = physical_payload.len().next_multiple_of(512);
        let mut padded_psize = physical_payload.to_vec();
        padded_psize.resize(psize, 0);
        let asize = (psize as u64).next_multiple_of(self.sector);
        let dva_off = self.cursor;
        assert!(
            dva_off + asize <= self.limit,
            "arena exhausted building fixture"
        );
        self.cursor += asize;
        self.alloc_map
            .apply(MapType::Allocate, dva_off..(dva_off + asize))
            .expect("apply arena alloc");
        let mut disk_bytes = padded_psize.clone();
        disk_bytes.resize(usize::try_from(asize).unwrap(), 0);
        self.blocks.insert(dva_off, disk_bytes);

        let fill = if object_type == DMU_OT_DNODE {
            logical
                .as_chunks::<DNODE_BYTES>()
                .0
                .iter()
                .filter(|slot| slot[0] != 0)
                .count() as u64
        } else if object_type == DMU_OT_OBJSET {
            ObjectSet::parse(logical, order)
                .expect("parse objset for fill")
                .meta_fill()
        } else {
            1
        };
        BlockPointer::new_regular(&RegularBlockSpec {
            dvas: &[Dva {
                vdev: 0,
                offset: dva_off,
                allocated_bytes: asize,
                gang: false,
            }],
            logical_bytes: lsize,
            physical: &padded_psize,
            compression: compress_type,
            checksum_type,
            object_type,
            level,
            payload_order: order,
            birth,
            fill,
        })
        .expect("encode regular block pointer")
    }

    fn alloc_block(
        &mut self,
        payload: &[u8],
        object_type: u8,
        level: u8,
        birth: u64,
        order: Endian,
    ) -> BlockPointer {
        let min_blk = usize::try_from(self.sector).unwrap().max(512);
        let lsize = payload.len().max(min_blk).next_multiple_of(512);
        let mut buf = payload.to_vec();
        buf.resize(lsize, 0);
        self.alloc_raw_compressed(&buf, &buf, object_type, level, 2, 7, birth, order)
    }
}

fn bp_allocated_bytes(bp: &BlockPointer) -> u64 {
    bp.regular_dvas()
        .map_or(0, |dvas| dvas.iter().map(|d| d.allocated_bytes).sum())
}

fn mzap(pairs: &[(&[u8], u64)], salt: u64, order: Endian) -> Vec<u8> {
    let entries: Vec<ZapEntry> = pairs
        .iter()
        .map(|&(name, value)| ZapEntry {
            name: name.to_vec(),
            value,
            collision: 0,
        })
        .collect();
    encode_microzap(&entries, 4096, salt, order).expect("encode microzap")
}

fn encode_space_map_records(
    records: &[SpaceMapRecord],
    block_bytes: usize,
    order: Endian,
    allow_v2: bool,
) -> (Vec<Vec<u8>>, u64) {
    let mut blocks: Vec<Vec<u8>> = Vec::new();
    let mut cur = Vec::with_capacity(block_bytes);
    let pad = SpaceMapRecord::padding_word()
        .encode(order, allow_v2)
        .expect("padding word");
    for rec in records {
        let encoded = rec.encode(order, allow_v2).expect("encode sm record");
        if cur.len() + encoded.len() > block_bytes {
            while cur.len() < block_bytes {
                cur.extend_from_slice(&pad);
            }
            blocks.push(std::mem::replace(&mut cur, Vec::with_capacity(block_bytes)));
        }
        cur.extend_from_slice(&encoded);
    }
    let stream_len = (blocks.len() * block_bytes + cur.len()) as u64;
    if !cur.is_empty() {
        cur.resize(block_bytes, 0);
        blocks.push(cur);
    }
    (blocks, stream_len)
}

#[allow(clippy::too_many_arguments)]
fn make_dnode(
    object_type: u8,
    data_bytes: usize,
    pointers: Vec<BlockPointer>,
    bonus_type: u8,
    bonus: Vec<u8>,
    spill: Option<BlockPointer>,
    user_flags: u8,
    order: Endian,
) -> Dnode {
    let used_bytes: u64 = pointers
        .iter()
        .filter(|bp| !bp.hole())
        .map(bp_allocated_bytes)
        .sum::<u64>()
        + spill.as_ref().map_or(0, bp_allocated_bytes);
    let mut flags = DNODE_FLAG_USED_BYTES | user_flags;
    if spill.is_some() {
        flags |= DNODE_FLAG_SPILL_BLKPTR;
    }
    let max_block = if pointers.is_empty() || pointers.iter().all(BlockPointer::hole) {
        0
    } else {
        (pointers.len() as u64) - 1
    };
    let nblkptr = if bonus_type == 44 || spill.is_some() {
        1
    } else {
        ((DNODE_BYTES - 64 - bonus.len()) / 128).clamp(1, 3)
    };
    assert!(
        pointers.len() <= nblkptr,
        "too many inline pointers ({}) for nblkptr ({nblkptr})",
        pointers.len()
    );
    let mut ptrs = pointers;
    ptrs.resize(nblkptr, BlockPointer::hole_pointer());
    Dnode::from_spec(DnodeSpec {
        object_type,
        bonus_type,
        checksum_type: 0,
        compress_type: 0,
        flags,
        order,
        levels: 1,
        indirect_shift: 17,
        data_bytes,
        max_block,
        used_bytes,
        slots: 1,
        pointers: ptrs,
        bonus,
        spill,
    })
    .expect("encode dnode")
}

fn build_sa_registry_objects(
    arena: &mut RawArena,
    birth: u64,
    order: Endian,
) -> (SaRegistry, Dnode, Dnode, Dnode) {
    // Attribute IDs matching OpenZFS `SaRegistry::LEGACY` (0..16) + custom attr 18:
    // 0: ATIME(16,0), 1: MTIME(16,0), 2: CTIME(16,0), 3: CRTIME(16,0), 4: GEN(8,0),
    // 5: MODE(8,0), 6: SIZE(8,0), 7: PARENT(8,0), 8: LINKS(8,0), 10: RDEV(8,0),
    // 11: FLAGS(8,0), 12: UID(8,0), 13: GID(8,0), 18: ZPL_SCANSTAMP(32,2)
    let reg_entries = vec![
        RawZapEntry {
            name: b"ZPL_ATIME".to_vec(),
            integer_bytes: 8,
            values: vec![16_u64 << 24],
            collision: 0,
        },
        RawZapEntry {
            name: b"ZPL_MTIME".to_vec(),
            integer_bytes: 8,
            values: vec![(16_u64 << 24) | 1],
            collision: 0,
        },
        RawZapEntry {
            name: b"ZPL_CTIME".to_vec(),
            integer_bytes: 8,
            values: vec![(16_u64 << 24) | 2],
            collision: 0,
        },
        RawZapEntry {
            name: b"ZPL_CRTIME".to_vec(),
            integer_bytes: 8,
            values: vec![(16_u64 << 24) | 3],
            collision: 0,
        },
        RawZapEntry {
            name: b"ZPL_GEN".to_vec(),
            integer_bytes: 8,
            values: vec![(8_u64 << 24) | 4],
            collision: 0,
        },
        RawZapEntry {
            name: b"ZPL_MODE".to_vec(),
            integer_bytes: 8,
            values: vec![(8_u64 << 24) | 5],
            collision: 0,
        },
        RawZapEntry {
            name: b"ZPL_SIZE".to_vec(),
            integer_bytes: 8,
            values: vec![(8_u64 << 24) | 6],
            collision: 0,
        },
        RawZapEntry {
            name: b"ZPL_PARENT".to_vec(),
            integer_bytes: 8,
            values: vec![(8_u64 << 24) | 7],
            collision: 0,
        },
        RawZapEntry {
            name: b"ZPL_LINKS".to_vec(),
            integer_bytes: 8,
            values: vec![(8_u64 << 24) | 8],
            collision: 0,
        },
        RawZapEntry {
            name: b"ZPL_RDEV".to_vec(),
            integer_bytes: 8,
            values: vec![(8_u64 << 24) | 0x0a],
            collision: 0,
        },
        RawZapEntry {
            name: b"ZPL_FLAGS".to_vec(),
            integer_bytes: 8,
            values: vec![(8_u64 << 24) | 0x0b],
            collision: 0,
        },
        RawZapEntry {
            name: b"ZPL_UID".to_vec(),
            integer_bytes: 8,
            values: vec![(8_u64 << 24) | 0x0c],
            collision: 0,
        },
        RawZapEntry {
            name: b"ZPL_GID".to_vec(),
            integer_bytes: 8,
            values: vec![(8_u64 << 24) | 0x0d],
            collision: 0,
        },
        RawZapEntry {
            name: b"ZPL_SCANSTAMP".to_vec(),
            integer_bytes: 8,
            values: vec![(0x20_u64 << 24) | (2_u64 << 16) | 0x12],
            collision: 0,
        },
    ];
    // Layout 2: standard file/dir layout; Layout 3: spill layout `[18]`
    let lay_entries = vec![
        RawZapEntry {
            name: b"2".to_vec(),
            integer_bytes: 2,
            values: vec![5, 6, 4, 12, 13, 7, 11, 0, 1, 2, 3, 8],
            collision: 0,
        },
        RawZapEntry {
            name: b"3".to_vec(),
            integer_bytes: 2,
            values: vec![18],
            collision: 0,
        },
    ];
    let registry = SaRegistry::from_zaps(&reg_entries, &lay_entries).expect("valid SaRegistry");

    let sa_master_raw = mzap(&[(b"REGISTRY", 9), (b"LAYOUTS", 10)], 0x1234, order);
    let sa_master_bp = arena.alloc_block(&sa_master_raw, 45, 0, birth, order);
    let sa_master_dn = make_dnode(
        45,
        sa_master_bp.logical_bytes(),
        vec![sa_master_bp],
        0,
        Vec::new(),
        None,
        0,
        order,
    );

    let reg_blocks =
        encode_fatzap_with_flags(&reg_entries, 4096, 0x2345, false, order).expect("reg fat");
    let reg_ptrs: Vec<_> = reg_blocks
        .iter()
        .map(|b| arena.alloc_block(b, 46, 0, birth, order))
        .collect();
    let reg_dn = make_dnode(46, 4096, reg_ptrs, 0, Vec::new(), None, 0, order);

    let lay_blocks =
        encode_fatzap_with_flags(&lay_entries, 4096, 0x3456, false, order).expect("lay fat");
    let lay_ptrs: Vec<_> = lay_blocks
        .iter()
        .map(|b| arena.alloc_block(b, 47, 0, birth, order))
        .collect();
    let lay_dn = make_dnode(47, 4096, lay_ptrs, 0, Vec::new(), None, 0, order);

    (registry, sa_master_dn, reg_dn, lay_dn)
}

fn encode_zpl_bonus_for_fixture(
    meta: &Metadata,
    zpl_version: u64,
    sa_reg: Option<&SaRegistry>,
    with_spill: bool,
    arena: &mut RawArena,
    birth: u64,
    order: Endian,
) -> (u8, Vec<u8>, Option<BlockPointer>) {
    if zpl_version == 4 {
        (
            17,
            meta.encode_legacy(None, order).expect("legacy znode"),
            None,
        )
    } else {
        let reg = sa_reg.expect("v5 requires SA registry");
        // Build a valid template SA buffer for layout 2 (8B header + 128B fixed payload = 136B).
        let mut tmpl = vec![0_u8; 136];
        let hdr_info: u16 = (1_u16 << 10) | 2_u16;
        match order {
            Endian::Little => {
                tmpl[0..4].copy_from_slice(&[0x5a, 0x50, 0x2f, 0x00]);
                tmpl[4..6].copy_from_slice(&hdr_info.to_le_bytes());
            }
            Endian::Big => {
                tmpl[0..4].copy_from_slice(&[0x00, 0x2f, 0x50, 0x5a]);
                tmpl[4..6].copy_from_slice(&hdr_info.to_be_bytes());
            }
        }
        let bonus = reg
            .encode_new_from_template(&tmpl, meta)
            .expect("encode SA metadata");
        let spill = if with_spill {
            // Valid SA header `[magic(4), (header_bytes=8 => 1<<10 | layout=3), 32B attr 18]`
            let mut sraw = vec![0_u8; 512];
            let hdr_word: u16 = (1_u16 << 10) | 3_u16;
            match order {
                Endian::Little => {
                    sraw[0..4].copy_from_slice(&[0x5a, 0x50, 0x2f, 0x00]);
                    sraw[4..6].copy_from_slice(&hdr_word.to_le_bytes());
                }
                Endian::Big => {
                    sraw[0..4].copy_from_slice(&[0x00, 0x2f, 0x50, 0x5a]);
                    sraw[4..6].copy_from_slice(&hdr_word.to_be_bytes());
                }
            }
            sraw[8..40].fill(0xAB);
            Some(arena.alloc_block(&sraw, 44, 0, birth, order))
        } else {
            None
        };
        (44, bonus, spill)
    }
}

#[allow(clippy::too_many_lines)]
fn build_zpl_objectset(
    arena: &mut RawArena,
    spec: &PoolFixtureSpec,
    populate_snapshot_files: bool,
    birth: u64,
    order: Endian,
) -> (BlockPointer, u64, Vec<u8>) {
    let mut table = vec![0_u8; DNODE_BLOCK_BYTES];
    let acct_flags = if spec.user_accounting {
        DNODE_FLAG_USERUSED_ACCOUNTED | DNODE_FLAG_USEROBJUSED_ACCOUNTED
    } else {
        0
    };

    let (sa_reg, sa_objs) = if spec.zpl_version == 5 {
        let (r, m_dn, r_dn, l_dn) = build_sa_registry_objects(arena, birth, order);
        (Some(r), Some((m_dn, r_dn, l_dn)))
    } else {
        (None, None)
    };

    let mut master_pairs: Vec<(&[u8], u64)> = vec![
        (b"VERSION", spec.zpl_version),
        (b"ROOT", 2),
        (b"DELETE_QUEUE", 3),
    ];
    if spec.zpl_version == 5 {
        master_pairs.push((b"SA_ATTRS", 8));
    }
    let master_raw = mzap(&master_pairs, 0x55, order);
    let master_bp = arena.alloc_block(&master_raw, 21, 0, birth, order);
    let master_dn = make_dnode(
        21,
        master_bp.logical_bytes(),
        vec![master_bp],
        0,
        Vec::new(),
        None,
        0,
        order,
    );
    write_dnode_at(&mut table, 1, &master_dn).expect("write master dn");

    let delq_raw = mzap(&[], 0x66, order);
    let delq_bp = arena.alloc_block(&delq_raw, 22, 0, birth, order);
    let delq_dn = make_dnode(
        22,
        delq_bp.logical_bytes(),
        vec![delq_bp],
        0,
        Vec::new(),
        None,
        0,
        order,
    );
    write_dnode_at(&mut table, 3, &delq_dn).expect("write delq dn");

    if let Some((m_dn, r_dn, l_dn)) = sa_objs {
        write_dnode_at(&mut table, 8, &m_dn).expect("sa 8");
        write_dnode_at(&mut table, 9, &r_dn).expect("sa 9");
        write_dnode_at(&mut table, 10, &l_dn).expect("sa 10");
    }

    let ts = Timestamp {
        seconds: 1_700_000_000,
        nanos: 0,
    };
    let mut root_entries: Vec<(&[u8], u64)> = Vec::new();
    let mut snap_hello_bytes = Vec::new();
    let mut subdir_count = 0_u64;

    if populate_snapshot_files {
        // Object 4: `hello.txt` stored with genuine LZJB compression (code 3)
        let mut genuine_lzjb = Vec::new();
        snap_hello_bytes = b"SNAPDATA".repeat(512); // 4096 bytes of `"SNAPDATA"`
        // Group 1: item 0..7 are 8 literal bytes `"SNAPDATA"` (`map = 0x00`)
        genuine_lzjb.push(0x00);
        genuine_lzjb.extend_from_slice(b"SNAPDATA");
        let mut produced = 8_usize;
        while produced < snap_hello_bytes.len() {
            let mut map = 0_u8;
            let mut group_bytes = Vec::new();
            for bit in 0..8 {
                if produced == snap_hello_bytes.len() {
                    break;
                }
                let rem = snap_hello_bytes.len() - produced;
                if rem >= 8 {
                    // Copy match of length `take` (8..=16, multiple of 8 so alignment stays mod 8!) from offset 8!
                    let take = if rem >= 16 { 16 } else { 8 };
                    map |= 1_u8 << bit;
                    let mlen = u8::try_from(take - 3).unwrap();
                    let off = 8_u16;
                    group_bytes.push((mlen << 2) | u8::try_from(off >> 8).unwrap());
                    group_bytes.push(u8::try_from(off & 0xff).unwrap());
                    produced += take;
                } else {
                    group_bytes.push(snap_hello_bytes[produced]);
                    produced += 1;
                }
            }
            genuine_lzjb.push(map);
            genuine_lzjb.extend_from_slice(&group_bytes);
        }
        assert!(genuine_lzjb.len() <= 1024);
        assert_eq!(
            ffs_ondisk::zfs::decompress(&genuine_lzjb, 3, snap_hello_bytes.len()).unwrap(),
            snap_hello_bytes
        );

        let hello_bp = arena.alloc_raw_compressed(
            &snap_hello_bytes,
            &genuine_lzjb,
            19,
            0,
            3, // LZJB!
            7,
            birth,
            order,
        );
        let hello_meta = Metadata {
            kind: Kind::Regular,
            mode: (Kind::Regular.to_tag() << 12) | 0o644,
            size: snap_hello_bytes.len() as u64,
            links: 1,
            parent: 2,
            uid: 1000,
            gid: 1000,
            flags: 0x408 | spec.zpl_flags.get(&4).copied().unwrap_or(0),
            generation: birth,
            times: [ts; 4],
            inline_symlink: None,
        };
        let (bt, bbytes, spill) = encode_zpl_bonus_for_fixture(
            &hello_meta,
            spec.zpl_version,
            sa_reg.as_ref(),
            spec.with_sa_spill,
            arena,
            birth,
            order,
        );
        let hello_dn = make_dnode(
            19,
            snap_hello_bytes.len(),
            vec![hello_bp],
            bt,
            bbytes,
            spill,
            acct_flags,
            order,
        );
        write_dnode_at(&mut table, 4, &hello_dn).expect("write hello dn");
        root_entries.push((
            b"hello.txt",
            encode_directory_reference(4, Kind::Regular).unwrap(),
        ));

        // Object 5: `keep.bin` (4096B uncompressed)
        let keep_data = vec![0x5A_u8; 4096];
        let keep_bp = arena.alloc_block(&keep_data, 19, 0, birth, order);
        let keep_meta = Metadata {
            size: 4096,
            flags: 0x408 | spec.zpl_flags.get(&5).copied().unwrap_or(0),
            ..hello_meta
        };
        let (kbt, kbbytes, kspill) = encode_zpl_bonus_for_fixture(
            &keep_meta,
            spec.zpl_version,
            sa_reg.as_ref(),
            false,
            arena,
            birth,
            order,
        );
        let keep_dn = make_dnode(
            19,
            4096,
            vec![keep_bp],
            kbt,
            kbbytes,
            kspill,
            acct_flags,
            order,
        );
        write_dnode_at(&mut table, 5, &keep_dn).expect("write keep dn");
        root_entries.push((
            b"keep.bin",
            encode_directory_reference(5, Kind::Regular).unwrap(),
        ));

        // Object 6: `sub` empty directory
        let sub_raw = mzap(&[], 0x77, order);
        let sub_bp = arena.alloc_block(&sub_raw, 20, 0, birth, order);
        let sub_meta = Metadata {
            kind: Kind::Directory,
            mode: (Kind::Directory.to_tag() << 12) | 0o755,
            size: 2,
            links: 2,
            parent: 2,
            uid: 0,
            gid: 0,
            flags: 0x408 | spec.zpl_flags.get(&6).copied().unwrap_or(0),
            generation: birth,
            times: [ts; 4],
            inline_symlink: None,
        };
        let (sbt, sbbytes, _) = encode_zpl_bonus_for_fixture(
            &sub_meta,
            spec.zpl_version,
            sa_reg.as_ref(),
            false,
            arena,
            birth,
            order,
        );
        let sub_dn = make_dnode(
            20,
            sub_bp.logical_bytes(),
            vec![sub_bp],
            sbt,
            sbbytes,
            None,
            acct_flags,
            order,
        );
        write_dnode_at(&mut table, 6, &sub_dn).expect("write sub dn");
        root_entries.push((
            b"sub",
            encode_directory_reference(6, Kind::Directory).unwrap(),
        ));
        subdir_count += 1;
    } else if spec.with_sa_spill {
        // Seed a file `spilled.txt` (Object 4) with a valid SA spill block so COW updates preserve it!
        let sp_data = b"initial-spilled-content".to_vec();
        let mut padded = sp_data.clone();
        padded.resize((1_usize << spec.ashift).max(512), 0);
        let sp_bp = arena.alloc_block(&padded, 19, 0, birth, order);
        let sp_meta = Metadata {
            kind: Kind::Regular,
            mode: (Kind::Regular.to_tag() << 12) | 0o644,
            size: sp_data.len() as u64,
            links: 1,
            parent: 2,
            uid: 1000,
            gid: 1000,
            flags: 0x408 | spec.zpl_flags.get(&4).copied().unwrap_or(0),
            generation: birth,
            times: [ts; 4],
            inline_symlink: None,
        };
        let (bt, bbytes, spill) = encode_zpl_bonus_for_fixture(
            &sp_meta,
            spec.zpl_version,
            sa_reg.as_ref(),
            true,
            arena,
            birth,
            order,
        );
        let sp_dn = make_dnode(
            19,
            padded.len(),
            vec![sp_bp],
            bt,
            bbytes,
            spill,
            acct_flags,
            order,
        );
        write_dnode_at(&mut table, 4, &sp_dn).expect("write sp dn");
        root_entries.push((
            b"spilled.txt",
            encode_directory_reference(4, Kind::Regular).unwrap(),
        ));
    }

    let root_raw = mzap(&root_entries, 0x88, order);
    let root_bp = arena.alloc_block(&root_raw, 20, 0, birth, order);
    let root_meta = Metadata {
        kind: Kind::Directory,
        mode: (Kind::Directory.to_tag() << 12) | 0o755,
        size: 2 + (root_entries.len() as u64),
        links: 2 + subdir_count,
        parent: 2,
        uid: 0,
        gid: 0,
        flags: 0x408 | spec.zpl_flags.get(&2).copied().unwrap_or(0),
        generation: birth,
        times: [ts; 4],
        inline_symlink: None,
    };
    let (rbt, rbbytes, _) = encode_zpl_bonus_for_fixture(
        &root_meta,
        spec.zpl_version,
        sa_reg.as_ref(),
        false,
        arena,
        birth,
        order,
    );
    let root_dn = make_dnode(
        20,
        root_bp.logical_bytes(),
        vec![root_bp],
        rbt,
        rbbytes,
        None,
        acct_flags,
        order,
    );
    write_dnode_at(&mut table, 2, &root_dn).expect("write root dn");

    let table_bp = arena.alloc_block(&table, DMU_OT_DNODE, 0, birth, order);
    let meta_dn = make_dnode(
        DMU_OT_DNODE,
        DNODE_BLOCK_BYTES,
        vec![table_bp],
        0,
        Vec::new(),
        None,
        0,
        order,
    );

    let zil_header = if spec.dirty_zil {
        // Non-zero claim_txg triggers `ZilHeader::has_work() == true`!
        let dummy_log_bp = arena.alloc_block(&vec![0_u8; 4096], 9, 0, birth, order);
        ZilHeader {
            claim_txg: birth,
            replay_seq: 1,
            log: dummy_log_bp,
            claim_blk_seq: 1,
            flags: 0,
            claim_lr_seq: 1,
        }
    } else {
        ZilHeader::empty()
    };

    let os_bytes = if spec.user_accounting {
        4096
    } else {
        1024_usize.max(1_usize << spec.ashift)
    };
    let os_flags = if spec.user_accounting { 0x03 } else { 0 };
    let mut os_obj = ObjectSet::new(2, os_flags, meta_dn, zil_header, os_bytes).expect("zpl os");
    if spec.user_accounting {
        let u_raw = mzap(&[], 0x99, order);
        let u_bp = arena.alloc_block(&u_raw, 39, 0, birth, order);
        let u_dn = make_dnode(
            39,
            u_bp.logical_bytes(),
            vec![u_bp],
            0,
            Vec::new(),
            None,
            0,
            order,
        );
        os_obj
            .set_embedded_dnode(OBJSET_USERUSED_OFFSET, Some(&u_dn))
            .expect("userused dnode");

        let g_raw = mzap(&[], 0xAA, order);
        let g_bp = arena.alloc_block(&g_raw, 39, 0, birth, order);
        let g_dn = make_dnode(
            39,
            g_bp.logical_bytes(),
            vec![g_bp],
            0,
            Vec::new(),
            None,
            0,
            order,
        );
        os_obj
            .set_embedded_dnode(OBJSET_GROUPUSED_OFFSET, Some(&g_dn))
            .expect("groupused dnode");
    }
    let encoded_os = os_obj.encode(order).expect("encode zpl os");
    let os_bp = arena.alloc_block(&encoded_os, DMU_OT_OBJSET, 0, birth, order);
    let referenced = os_obj.meta.used_bytes() + bp_allocated_bytes(&os_bp);
    (os_bp, referenced, snap_hello_bytes)
}

fn encode_dsl_dir_bonus(
    head_obj: u64,
    parent_dir_obj: u64,
    origin_obj: u64,
    child_dir_zapobj: u64,
    props_zapobj: u64,
    used_bytes: u64,
    order: Endian,
) -> Vec<u8> {
    let mut raw = vec![0_u8; 256];
    for (at, val) in [
        (0, 1_700_000_000_u64),
        (8, head_obj),
        (16, parent_dir_obj),
        (24, origin_obj),
        (32, child_dir_zapobj),
        (40, used_bytes),
        (48, used_bytes),
        (56, used_bytes),
        (80, props_zapobj),
    ] {
        raw[at..at + 8].copy_from_slice(&order.encode(val));
    }
    raw
}

#[allow(clippy::too_many_arguments)]
fn encode_dsl_dataset_bonus(
    dir_obj: u64,
    prev_snap_obj: u64,
    prev_snap_txg: u64,
    next_snap_obj: u64,
    snapnames_zapobj: u64,
    num_children: u64,
    creation_txg: u64,
    deadlist_obj: u64,
    referenced_bytes: u64,
    guid: u64,
    next_clones_obj: u64,
    os_bp: &BlockPointer,
    order: Endian,
) -> Vec<u8> {
    let mut raw = vec![0_u8; 320];
    for (at, val) in [
        (0, dir_obj),
        (8, prev_snap_obj),
        (16, prev_snap_txg),
        (24, next_snap_obj),
        (32, snapnames_zapobj),
        (40, num_children),
        (48, 1_700_000_000 + creation_txg),
        (56, creation_txg),
        (64, deadlist_obj),
        (72, referenced_bytes),
        (80, referenced_bytes),
        (88, referenced_bytes),
        (96, referenced_bytes),
        (104, guid ^ 0x55AA),
        (112, guid),
        (120, 0),
        (256, next_clones_obj),
    ] {
        raw[at..at + 8].copy_from_slice(&order.encode(val));
    }
    raw[128..256].copy_from_slice(&os_bp.encode(order));
    raw
}

#[allow(clippy::too_many_lines)]
fn build_clean_zfs_pool(spec: &PoolFixtureSpec) -> BuiltPool {
    let order = Endian::Little;
    let asize = (spec.image_bytes - DATA_OFFSET - 2 * LABEL_BYTES) & !((1_u64 << SLAB_SHIFT) - 1);
    assert!(
        asize >= (1 << SLAB_SHIFT),
        "pool image too small for metaslabs"
    );
    let num_slabs = usize::try_from(asize >> SLAB_SHIFT).unwrap();
    let mut arena = RawArena::new(asize, spec.ashift);

    // 1. Build root ZPL dataset + child `"data"` ZPL dataset (with optional `@before` snapshot).
    let (root_os_bp, root_ref_bytes, _) =
        build_zpl_objectset(&mut arena, spec, false, INITIAL_TXG - 1, order);

    let data_birth = if spec.deadlist_mode == DeadlistMode::None {
        INITIAL_TXG - 1
    } else {
        SNAP_TXG
    };
    let (data_os_bp, data_ref_bytes, snap_hello_expected) = build_zpl_objectset(
        &mut arena,
        spec,
        spec.deadlist_mode != DeadlistMode::None,
        data_birth,
        order,
    );

    // 2. Build MOS dnode table blocks (`sm_base_id = 40`, up to 3 inline 16 KiB blocks = 96 objects).
    let sm_base_id = 40_usize;
    let slots_per_dnode_blk = DNODE_BLOCK_BYTES / DNODE_BYTES;
    let mos_table_blocks = (sm_base_id + num_slabs).div_ceil(slots_per_dnode_blk);
    assert!(
        mos_table_blocks <= 3,
        "MOS fixture dnode table blocks exceeded ({mos_table_blocks})"
    );
    let mut mos_tables = vec![vec![0_u8; DNODE_BLOCK_BYTES]; mos_table_blocks];
    let set_mos = |tables: &mut [Vec<u8>], id: usize, dn: &Dnode| {
        write_dnode_at(
            &mut tables[id / slots_per_dnode_blk],
            id % slots_per_dnode_blk,
            dn,
        )
        .unwrap();
    };

    // Object 4: root snapnames (empty)
    let r_snaps_raw = mzap(&[], 0x101, order);
    let r_snaps_bp = arena.alloc_block(&r_snaps_raw, 14, 0, INITIAL_TXG, order);
    set_mos(
        &mut mos_tables,
        4,
        &make_dnode(
            14,
            r_snaps_bp.logical_bytes(),
            vec![r_snaps_bp],
            0,
            Vec::new(),
            None,
            0,
            order,
        ),
    );

    // Object 15: root child_dir_zap `{"$FREE": 14, "$MOS": 9, "$ORIGIN": 24, "data": 17}`
    let child_zap_raw = mzap(
        &[
            (b"$FREE", 14),
            (b"$MOS", 9),
            (b"$ORIGIN", 24),
            (b"data", 17),
        ],
        0x102,
        order,
    );
    let child_zap_bp = arena.alloc_block(&child_zap_raw, 13, 0, INITIAL_TXG, order);
    set_mos(
        &mut mos_tables,
        15,
        &make_dnode(
            13,
            child_zap_bp.logical_bytes(),
            vec![child_zap_bp],
            0,
            Vec::new(),
            None,
            0,
            order,
        ),
    );

    // DSL props ZAPs (`16`, `20`, `30`, `31`, `32`) & empty child_dir_zaps (`19`, `33`, `34`, `35`)
    for (id, kind, salt) in [
        (16_usize, 15_u8, 0x103_u64),
        (19, 13, 0x104),
        (20, 15, 0x105),
        (30, 15, 0x110),
        (31, 15, 0x111),
        (32, 15, 0x112),
        (33, 13, 0x113),
        (34, 13, 0x114),
        (35, 13, 0x115),
    ] {
        let properties = match id {
            16 => spec.root_properties.as_slice(),
            20 => spec.data_properties.as_slice(),
            _ => &[],
        };
        let raw = mzap(properties, salt, order);
        let bp = arena.alloc_block(&raw, kind, 0, INITIAL_TXG, order);
        set_mos(
            &mut mos_tables,
            id,
            &make_dnode(
                kind,
                bp.logical_bytes(),
                vec![bp],
                0,
                Vec::new(),
                None,
                0,
                order,
            ),
        );
    }

    // Empty `DMU_OT_BPOBJ = 5` objects (`bonus_type = DMU_OT_BPOBJ_HDR = 6`):
    // 7 (`sync_bplist`), 8 (`free_bpobj`), 13 (`empty_bpobj`),
    // 36 (`$ORIGIN` head deadlist), 37 (`root` head deadlist), plus 38 (`data` head deadlist in `None` mode)
    for bpobj_id in [7_usize, 8, 13, 36, 37] {
        set_mos(
            &mut mos_tables,
            bpobj_id,
            &make_dnode(5, 4096, Vec::new(), 6, vec![0_u8; 48], None, 0, order),
        );
    }
    if spec.deadlist_mode == DeadlistMode::None {
        set_mos(
            &mut mos_tables,
            38,
            &make_dnode(5, 4096, Vec::new(), 6, vec![0_u8; 48], None, 0, order),
        );
    }

    // Special MOS DSL directories: Object 9 (`$MOS`), Object 14 (`$FREE`), Object 24 (`$ORIGIN`)
    for (special_dir_id, child_id, props_id) in [(9_usize, 33_u64, 30_u64), (14, 34, 31)] {
        let special_bonus = encode_dsl_dir_bonus(0, 2, 0, child_id, props_id, 0, order);
        set_mos(
            &mut mos_tables,
            special_dir_id,
            &make_dnode(12, 512, Vec::new(), 12, special_bonus, None, 0, order),
        );
    }
    let origin_dir_bonus = encode_dsl_dir_bonus(25, 2, 0, 35, 32, 0, order);
    set_mos(
        &mut mos_tables,
        24,
        &make_dnode(12, 512, Vec::new(), 12, origin_dir_bonus, None, 0, order),
    );
    let origin_snaps_raw = mzap(&[(b"$ORIGIN", 26)], 0x10C, order);
    let origin_snaps_bp = arena.alloc_block(&origin_snaps_raw, 14, 0, INITIAL_TXG, order);
    set_mos(
        &mut mos_tables,
        27,
        &make_dnode(
            14,
            origin_snaps_bp.logical_bytes(),
            vec![origin_snaps_bp],
            0,
            Vec::new(),
            None,
            0,
            order,
        ),
    );
    let origin_hole_bp = BlockPointer::hole_pointer();
    let origin_head_bonus = encode_dsl_dataset_bonus(
        24,
        26,
        1,
        0,
        27,
        0,
        1,
        36,
        0,
        0xABCD_0025,
        0,
        &origin_hole_bp,
        order,
    );
    set_mos(
        &mut mos_tables,
        25,
        &make_dnode(16, 512, Vec::new(), 16, origin_head_bonus, None, 0, order),
    );
    let (data_origin_clone_hex, data_origin_clone_id): (&[u8], u64) =
        if spec.deadlist_mode == DeadlistMode::None {
            (b"12", 18)
        } else {
            (b"15", 21)
        };
    let origin_clones_raw = mzap(
        &[(b"3", 3), (data_origin_clone_hex, data_origin_clone_id)],
        0x10D,
        order,
    );
    let origin_clones_bp = arena.alloc_block(&origin_clones_raw, 37, 0, INITIAL_TXG, order);
    set_mos(
        &mut mos_tables,
        28,
        &make_dnode(
            37,
            origin_clones_bp.logical_bytes(),
            vec![origin_clones_bp],
            0,
            Vec::new(),
            None,
            0,
            order,
        ),
    );
    let origin_snap_bonus = encode_dsl_dataset_bonus(
        24,
        0,
        0,
        25,
        0,
        3,
        1,
        13,
        0,
        0xABCD_0026,
        28,
        &origin_hole_bp,
        order,
    );
    set_mos(
        &mut mos_tables,
        26,
        &make_dnode(16, 512, Vec::new(), 16, origin_snap_bonus, None, 0, order),
    );

    // Optional snapshot `@before` (Object 21), snapnames `{"before": 21}` (Object 22), and deadlist (Object 23 or 38).
    let (prev_snap_obj, prev_snap_txg, snapnames_entries, deadlist_obj) = match spec.deadlist_mode {
        DeadlistMode::None => (26_u64, 1_u64, Vec::new(), 38_u64),
        DeadlistMode::Bpobj => {
            let snap_bonus = encode_dsl_dataset_bonus(
                17,
                26,
                1,
                18,
                0,
                1,
                SNAP_TXG,
                13,
                data_ref_bytes,
                0xABCD_0021,
                0,
                &data_os_bp,
                order,
            );
            set_mos(
                &mut mos_tables,
                21,
                &make_dnode(16, 512, Vec::new(), 16, snap_bonus, None, 0, order),
            );
            // Deadlist object 23 (`DMU_OT_BPOBJ = 5`, bonus `DMU_OT_BPOBJ_HDR = 6` 48B)
            set_mos(
                &mut mos_tables,
                23,
                &make_dnode(5, 4096, Vec::new(), 6, vec![0_u8; 48], None, 0, order),
            );
            (21, SNAP_TXG, vec![(b"before".as_slice(), 21_u64)], 23)
        }
        DeadlistMode::NativeDeadlist => {
            let snap_bonus = encode_dsl_dataset_bonus(
                17,
                26,
                1,
                18,
                0,
                1,
                SNAP_TXG,
                13,
                data_ref_bytes,
                0xABCD_0021,
                0,
                &data_os_bp,
                order,
            );
            set_mos(
                &mut mos_tables,
                21,
                &make_dnode(16, 512, Vec::new(), 16, snap_bonus, None, 0, order),
            );
            // Object 23: `DMU_OT_DEADLIST = 50`, bonus `DMU_OT_DEADLIST_HDR = 51` (320B `dsl_deadlist_phys_t`
            // `[dl_used=0, dl_comp=0, dl_uncomp=0, pad...]`), whose own ZAP data block maps `"1" -> 13` (`empty_bpobj`)!
            let mintxg_raw = mzap(&[(b"1", 13)], 0x106, order);
            let mintxg_bp = arena.alloc_block(&mintxg_raw, 50, 0, INITIAL_TXG, order);
            set_mos(
                &mut mos_tables,
                23,
                &make_dnode(
                    50,
                    mintxg_bp.logical_bytes(),
                    vec![mintxg_bp],
                    51,
                    vec![0_u8; 320],
                    None,
                    0,
                    order,
                ),
            );
            (21, SNAP_TXG, vec![(b"before".as_slice(), 21_u64)], 23)
        }
    };

    // Object 22: `data` snapnames ZAP
    let d_snaps_raw = mzap(&snapnames_entries, 0x107, order);
    let d_snaps_bp = arena.alloc_block(&d_snaps_raw, 14, 0, INITIAL_TXG, order);
    set_mos(
        &mut mos_tables,
        22,
        &make_dnode(
            14,
            d_snaps_bp.logical_bytes(),
            vec![d_snaps_bp],
            0,
            Vec::new(),
            None,
            0,
            order,
        ),
    );

    // Object 3: root head `DSL_DATASET`
    let root_ds_bonus = encode_dsl_dataset_bonus(
        2,
        26,
        1,
        0,
        4,
        0,
        10,
        37,
        root_ref_bytes,
        0xABCD_0003,
        0,
        &root_os_bp,
        order,
    );
    set_mos(
        &mut mos_tables,
        3,
        &make_dnode(16, 512, Vec::new(), 16, root_ds_bonus, None, 0, order),
    );

    // Object 18: `data` head `DSL_DATASET`
    let data_ds_bonus = encode_dsl_dataset_bonus(
        17,
        prev_snap_obj,
        prev_snap_txg,
        0,
        22,
        0,
        12,
        deadlist_obj,
        data_ref_bytes,
        0xABCD_0018,
        0,
        &data_os_bp,
        order,
    );
    set_mos(
        &mut mos_tables,
        18,
        &make_dnode(16, 512, Vec::new(), 16, data_ds_bonus, None, 0, order),
    );

    // Object 17: `data` `DSL_DIR` & Object 2: root `DSL_DIR`
    let data_dir_bonus = encode_dsl_dir_bonus(18, 2, 26, 19, 20, data_ref_bytes, order);
    set_mos(
        &mut mos_tables,
        17,
        &make_dnode(12, 512, Vec::new(), 12, data_dir_bonus, None, 0, order),
    );
    let root_dir_bonus =
        encode_dsl_dir_bonus(3, 0, 26, 15, 16, root_ref_bytes + data_ref_bytes, order);
    set_mos(
        &mut mos_tables,
        2,
        &make_dnode(12, 512, Vec::new(), 12, root_dir_bonus, None, 0, order),
    );

    // Objects 10, 11, 12: MOS feature catalogs
    let rf_raw = mzap(
        &[
            (b"org.illumos:lz4_compress", 1),
            (b"com.delphix:hole_birth", 1),
            (b"com.delphix:extensible_dataset", 0),
        ],
        0x108,
        order,
    );
    let rf_bp = arena.alloc_block(&rf_raw, 196, 0, INITIAL_TXG, order);
    set_mos(
        &mut mos_tables,
        10,
        &make_dnode(
            196,
            rf_bp.logical_bytes(),
            vec![rf_bp],
            0,
            Vec::new(),
            None,
            0,
            order,
        ),
    );

    let empty_bpobj_refcount = match spec.deadlist_mode {
        DeadlistMode::None => 1,
        DeadlistMode::Bpobj => 2,
        DeadlistMode::NativeDeadlist => 3,
    };
    let initial_allocated_spacemaps = if spec.preallocate_nearly_full {
        num_slabs as u64
    } else {
        1
    };
    let wf_raw = mzap(
        &[
            (b"com.delphix:async_destroy", 0),
            (b"com.delphix:empty_bpobj", empty_bpobj_refcount),
            (b"com.delphix:enabled_txg", 1),
            (
                b"com.delphix:spacemap_histogram",
                initial_allocated_spacemaps,
            ),
            (b"com.delphix:spacemap_v2", 1),
        ],
        0x109,
        order,
    );
    let wf_bp = arena.alloc_block(&wf_raw, 196, 0, INITIAL_TXG, order);
    set_mos(
        &mut mos_tables,
        11,
        &make_dnode(
            196,
            wf_bp.logical_bytes(),
            vec![wf_bp],
            0,
            Vec::new(),
            None,
            0,
            order,
        ),
    );

    let fd_raw = mzap(&[], 0x10A, order);
    let fd_bp = arena.alloc_block(&fd_raw, 196, 0, INITIAL_TXG, order);
    set_mos(
        &mut mos_tables,
        12,
        &make_dnode(
            196,
            fd_bp.logical_bytes(),
            vec![fd_bp],
            0,
            Vec::new(),
            None,
            0,
            order,
        ),
    );

    // Object 5: MOS `config` packed nvlist
    let top_guid = if spec.mirror_width == 1 {
        TOP_SINGLE_GUID
    } else {
        TOP_MIRROR_GUID
    };
    let single_path = spec
        .member_path_override
        .as_deref()
        .unwrap_or("/dev/ffs-member-0");
    let top_vdev_pairs = if spec.mirror_width == 1 {
        vec![
            nv_str("type", "file"),
            nv_u64("id", 0),
            nv_u64("guid", top_guid),
            nv_str("path", single_path),
            nv_u64("metaslab_array", 6),
            nv_u64("metaslab_shift", SLAB_SHIFT),
            nv_u64("ashift", u64::from(spec.ashift)),
            nv_u64("asize", asize),
            nv_u64("is_log", 0),
        ]
    } else {
        let children: Vec<Vec<Vec<u8>>> = (0..spec.mirror_width)
            .map(|idx| {
                vec![
                    nv_str("type", "file"),
                    nv_u64("id", idx as u64),
                    nv_u64("guid", CHILD_GUIDS[idx]),
                    nv_str("path", &format!("/dev/ffs-member-{idx}")),
                ]
            })
            .collect();
        vec![
            nv_str("type", "mirror"),
            nv_u64("id", 0),
            nv_u64("guid", top_guid),
            nv_u64("metaslab_array", 6),
            nv_u64("metaslab_shift", SLAB_SHIFT),
            nv_u64("ashift", u64::from(spec.ashift)),
            nv_u64("asize", asize),
            nv_u64("is_log", 0),
            nv_list_array("children", &children),
        ]
    };
    let mos_cfg_packed = pack_xdr_nvlist(&[
        nv_u64("version", 5000),
        nv_str("name", &spec.pool_name),
        nv_u64("state", spec.pool_state),
        nv_u64("txg", INITIAL_TXG),
        nv_u64("pool_guid", POOL_GUID),
        nv_u64("hostid", 1),
        nv_str("hostname", "frankenfs"),
        nv_u64("vdev_children", 1),
        nv_embedded(
            "vdev_tree",
            &[
                nv_str("type", "root"),
                nv_u64("id", 0),
                nv_u64("guid", POOL_GUID),
                nv_list_array("children", std::slice::from_ref(&top_vdev_pairs)),
            ],
        ),
        nv_embedded("features_for_read", &[nv_bool("com.delphix:hole_birth")]),
    ]);
    let cfg_len = mos_cfg_packed.len() as u64;
    let mut cfg_padded = mos_cfg_packed;
    cfg_padded.resize(cfg_padded.len().max(4096).next_multiple_of(4096), 0);
    let cfg_bp = arena.alloc_block(&cfg_padded, 3, 0, INITIAL_TXG, order);
    set_mos(
        &mut mos_tables,
        5,
        &make_dnode(
            3,
            cfg_padded.len(),
            vec![cfg_bp],
            4,
            order.encode(cfg_len).to_vec(),
            None,
            0,
            order,
        ),
    );

    // Object 29: `feature_enabled_txg` ZAP
    let fet_raw = mzap(
        &[
            (b"com.delphix:enabled_txg", 1),
            (b"com.delphix:hole_birth", 1),
        ],
        0x10E,
        order,
    );
    let fet_bp = arena.alloc_block(&fet_raw, 196, 0, INITIAL_TXG, order);
    set_mos(
        &mut mos_tables,
        29,
        &make_dnode(
            196,
            fet_bp.logical_bytes(),
            vec![fet_bp],
            0,
            Vec::new(),
            None,
            0,
            order,
        ),
    );

    // Object 1: MOS `DMU_OT_OBJECT_DIRECTORY`
    let obj_dir_raw = mzap(
        &[
            (b"root_dataset", 2),
            (b"config", 5),
            (b"sync_bplist", 7),
            (b"free_bpobj", 8),
            (b"features_for_read", 10),
            (b"features_for_write", 11),
            (b"feature_descriptions", 12),
            (b"empty_bpobj", 13),
            (b"feature_enabled_txg", 29),
        ],
        0x10B,
        order,
    );
    let obj_dir_bp =
        arena.alloc_block(&obj_dir_raw, DMU_OT_OBJECT_DIRECTORY, 0, INITIAL_TXG, order);
    set_mos(
        &mut mos_tables,
        1,
        &make_dnode(
            DMU_OT_OBJECT_DIRECTORY,
            obj_dir_bp.logical_bytes(),
            vec![obj_dir_bp],
            0,
            Vec::new(),
            None,
            0,
            order,
        ),
    );

    // Object 6: Metaslab array (`DMU_OT_OBJECT_ARRAY = 2`); untouched metaslabs start at `0`
    // (mirroring `zpool create`), while populated metaslabs map to `40 + s`.
    let mut ms_arr = vec![0_u8; (num_slabs * 8).max(4096).next_multiple_of(512)];
    for s in 0..num_slabs {
        if s == 0 || spec.preallocate_nearly_full {
            let at = s * 8;
            ms_arr[at..at + 8].copy_from_slice(&order.encode((sm_base_id + s) as u64));
        }
    }
    let ms_arr_bp = arena.alloc_block(&ms_arr, 2, 0, INITIAL_TXG, order);
    set_mos(
        &mut mos_tables,
        6,
        &make_dnode(
            2,
            ms_arr.len(),
            vec![ms_arr_bp],
            0,
            Vec::new(),
            None,
            0,
            order,
        ),
    );

    // Pre-reserve exact deterministic offsets for:
    // - space-map blocks (`4096` bytes each) for slabs that will contain allocated ranges
    // - MOS dnode table blocks (`16384` bytes each)
    // - MOS `ObjectSet` root (`1024` bytes rounded up to sector)
    // - optional `preallocate_nearly_full` filler range
    let sector = 1_u64 << spec.ashift;
    let sm_block_bytes = 4096_u64;
    let mos_table_bytes = DNODE_BLOCK_BYTES as u64;
    let mos_root_lsize = 1024_usize.max(usize::try_from(sector).unwrap());
    let mos_root_alloc_bytes = (mos_root_lsize as u64).next_multiple_of(sector);

    let mut sm_offs = Vec::with_capacity(num_slabs);
    for s in 0..num_slabs {
        if s == 0 || spec.preallocate_nearly_full {
            let off = arena.cursor;
            arena.cursor += sm_block_bytes;
            arena
                .alloc_map
                .apply(MapType::Allocate, off..(off + sm_block_bytes))
                .unwrap();
            sm_offs.push(Some(off));
        } else {
            sm_offs.push(None);
        }
    }

    let mut mos_table_offs = Vec::with_capacity(mos_table_blocks);
    for _ in 0..mos_table_blocks {
        let off = arena.cursor;
        arena.cursor += mos_table_bytes;
        arena
            .alloc_map
            .apply(MapType::Allocate, off..(off + mos_table_bytes))
            .unwrap();
        mos_table_offs.push(off);
    }

    let mos_root_off = arena.cursor;
    arena.cursor += mos_root_alloc_bytes;
    arena
        .alloc_map
        .apply(
            MapType::Allocate,
            mos_root_off..(mos_root_off + mos_root_alloc_bytes),
        )
        .unwrap();

    if spec.preallocate_nearly_full {
        // Leave only 4 KiB free in the entire pool so aCOW TXG deterministically hits `NoSpace`!
        let leave_free = 4096_u64;
        let fill_start = arena.cursor;
        let fill_end = asize - leave_free;
        if fill_end > fill_start {
            arena
                .alloc_map
                .apply(MapType::Allocate, fill_start..fill_end)
                .unwrap();
            arena.cursor = fill_end;
        }
    }

    // Encode per-metaslab space maps for allocated metaslabs (`maybe_sm_off.is_some()`);
    // untouched metaslabs remain `0` in `metaslab_array` so lazy initialization is exercised!
    let slab_size = 1_u64 << SLAB_SHIFT;
    for (s, maybe_sm_off) in sm_offs.iter().copied().enumerate() {
        let Some(sm_off) = maybe_sm_off else {
            continue;
        };
        let s_start = (s as u64) * slab_size;
        let s_end = s_start + slab_size;
        let mut slab_map = AllocationMap::new(s_start, slab_size, spec.ashift, 262_144).unwrap();
        let mut records = Vec::new();
        for r in arena.alloc_map.ranges() {
            let ov_start = r.start.max(s_start);
            let ov_end = r.end.min(s_end);
            if ov_start < ov_end {
                slab_map.apply(MapType::Allocate, ov_start..ov_end).unwrap();
                records.extend(
                    extent_records_for_range(
                        MapType::Allocate,
                        ov_start..ov_end,
                        s_start,
                        slab_size,
                        spec.ashift,
                    )
                    .unwrap(),
                );
            }
        }
        let hist = slab_map.free_histogram(spec.ashift).unwrap();
        let sm_dn = if records.is_empty() {
            let hdr = SpaceMapHeader {
                length: 0,
                allocated: 0,
                histogram: Some(hist),
            };
            make_dnode(
                8,
                4096,
                Vec::new(),
                7,
                hdr.encode(320, 0, order).unwrap(),
                None,
                0,
                order,
            )
        } else {
            let (blocks, stream_len) = encode_space_map_records(&records, 4096, order, true);
            assert_eq!(blocks.len(), 1);
            arena.blocks.insert(sm_off, blocks[0].clone());
            let sm_bp = BlockPointer::new_regular(&RegularBlockSpec {
                dvas: &[Dva {
                    vdev: 0,
                    offset: sm_off,
                    allocated_bytes: sm_block_bytes,
                    gang: false,
                }],
                logical_bytes: 4096,
                physical: &blocks[0],
                compression: 2,
                checksum_type: 7,
                object_type: 8,
                level: 0,
                payload_order: order,
                birth: INITIAL_TXG,
                fill: 1,
            })
            .unwrap();
            let hdr = SpaceMapHeader {
                length: stream_len,
                allocated: i64::try_from(slab_map.allocated_bytes()).unwrap(),
                histogram: Some(hist),
            };
            make_dnode(
                8,
                4096,
                vec![sm_bp],
                7,
                hdr.encode(320, 0, order).unwrap(),
                None,
                0,
                order,
            )
        };
        let sm_id = sm_base_id + s;
        write_dnode_at(
            &mut mos_tables[sm_id / slots_per_dnode_blk],
            sm_id % slots_per_dnode_blk,
            &sm_dn,
        )
        .unwrap();
    }

    // Write MOS dnode table blocks at `mos_table_offs`
    let mut mos_table_bps = Vec::with_capacity(mos_table_blocks);
    for (tbl_blk, tbl_off) in mos_tables.into_iter().zip(mos_table_offs) {
        let fill = tbl_blk
            .as_chunks::<DNODE_BYTES>()
            .0
            .iter()
            .filter(|slot| slot[0] != 0)
            .count() as u64;
        let bp = BlockPointer::new_regular(&RegularBlockSpec {
            dvas: &[Dva {
                vdev: 0,
                offset: tbl_off,
                allocated_bytes: mos_table_bytes,
                gang: false,
            }],
            logical_bytes: DNODE_BLOCK_BYTES,
            physical: &tbl_blk,
            compression: 2,
            checksum_type: 7,
            object_type: DMU_OT_DNODE,
            level: 0,
            payload_order: order,
            birth: INITIAL_TXG,
            fill,
        })
        .unwrap();
        arena.blocks.insert(tbl_off, tbl_blk);
        mos_table_bps.push(bp);
    }
    let mos_meta_dn = make_dnode(
        DMU_OT_DNODE,
        DNODE_BLOCK_BYTES,
        mos_table_bps,
        0,
        Vec::new(),
        None,
        0,
        order,
    );
    let mos_os = ObjectSet::new(1, 0, mos_meta_dn, ZilHeader::empty(), mos_root_lsize).unwrap();
    let mos_os_bytes = mos_os.encode(order).unwrap();
    let mut mos_os_disk = mos_os_bytes.clone();
    mos_os_disk.resize(usize::try_from(mos_root_alloc_bytes).unwrap(), 0);
    arena.blocks.insert(mos_root_off, mos_os_disk);
    let mos_root_bp = BlockPointer::new_regular(&RegularBlockSpec {
        dvas: &[Dva {
            vdev: 0,
            offset: mos_root_off,
            allocated_bytes: mos_root_alloc_bytes,
            gang: false,
        }],
        logical_bytes: mos_root_lsize,
        physical: &mos_os_bytes,
        compression: 2,
        checksum_type: 7,
        object_type: DMU_OT_OBJSET,
        level: 0,
        payload_order: order,
        birth: INITIAL_TXG,
        fill: mos_os.meta_fill(),
    })
    .unwrap();

    // 3. Stamp all 4 labels + Uberblock slot on every member image!
    let slot_bytes = (1_usize << spec.ashift).clamp(1024, 8192);
    let slots_per_label = UBERBLOCK_RING_BYTES / slot_bytes;
    let initial_slot = (INITIAL_TXG as usize) % slots_per_label;
    let guid_sum = if spec.mirror_width == 1 {
        POOL_GUID.wrapping_add(top_guid)
    } else {
        (0..spec.mirror_width).fold(POOL_GUID.wrapping_add(top_guid), |acc, i| {
            acc.wrapping_add(CHILD_GUIDS[i])
        })
    };
    let ub = Uberblock {
        order,
        version: 5000,
        txg: INITIAL_TXG,
        guid_sum,
        timestamp: 1_700_000_000,
        root: mos_root_bp,
    };
    let l_offsets = label_offsets(spec.image_bytes).unwrap();
    let mut members = Vec::with_capacity(spec.mirror_width);

    for &child_guid in CHILD_GUIDS.iter().take(spec.mirror_width) {
        let mut img = vec![0_u8; usize::try_from(spec.image_bytes).unwrap()];
        for (&dva_off, blk) in &arena.blocks {
            let start = usize::try_from(DATA_OFFSET + dva_off).unwrap();
            img[start..start + blk.len()].copy_from_slice(blk);
        }
        let member_guid = if spec.mirror_width == 1 {
            top_guid
        } else {
            child_guid
        };
        let mut lbl_pairs = vec![
            nv_u64("version", 5000),
            nv_str("name", &spec.pool_name),
            nv_u64("state", spec.pool_state),
            nv_u64("txg", INITIAL_TXG),
            nv_u64("pool_guid", POOL_GUID),
            nv_u64("hostid", 1),
            nv_str("hostname", "frankenfs"),
            nv_u64("top_guid", top_guid),
            nv_u64("guid", member_guid),
            nv_u64("vdev_children", 1),
            nv_embedded("vdev_tree", &top_vdev_pairs),
            nv_embedded("features_for_read", &[nv_bool("com.delphix:hole_birth")]),
        ];
        if spec.multihost_label {
            lbl_pairs.push(nv_u64("multihost", 1));
        }
        let lbl_packed = pack_xdr_nvlist(&lbl_pairs);

        for &lbl_base in &l_offsets {
            let cfg_vdev_off = lbl_base + LABEL_CONFIG_OFFSET;
            let mut cfg_blk = vec![0_u8; LABEL_CONFIG_BYTES];
            cfg_blk[..lbl_packed.len()].copy_from_slice(&lbl_packed);
            stamp_label_checksum(&mut cfg_blk, cfg_vdev_off, order).unwrap();
            let c_start = usize::try_from(cfg_vdev_off).unwrap();
            img[c_start..c_start + LABEL_CONFIG_BYTES].copy_from_slice(&cfg_blk);

            let ub_vdev_off =
                lbl_base + UBERBLOCK_RING_OFFSET + ((initial_slot * slot_bytes) as u64);
            let mut ub_blk = ub.encode(slot_bytes, ub_vdev_off).unwrap();
            if spec.active_mmp_uberblock {
                // Stamp active MMP (`mmp_magic = MMP_MAGIC`, `mmp_delay = 100_000`) and re-checksum!
                ub_blk[176..184].copy_from_slice(&order.encode(MMP_MAGIC));
                ub_blk[184..192].copy_from_slice(&order.encode(100_000));
                ub_blk[192..200].copy_from_slice(&order.encode(1));
                stamp_label_checksum(&mut ub_blk, ub_vdev_off, order).unwrap();
            }
            let u_start = usize::try_from(ub_vdev_off).unwrap();
            img[u_start..u_start + slot_bytes].copy_from_slice(&ub_blk);
        }
        members.push(img);
    }

    BuiltPool {
        members,
        pool_guid: POOL_GUID,
        initial_slot,
        snap_hello_expected,
    }
}

// ---------------------------------------------------------------------------
// Separately faultable `ByteDevice` modeling volatile write cache vs durable media
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct PendingWrite {
    offset: u64,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
enum DeviceFault {
    None,
    FailWriteOnCall {
        call_index: usize,
    },
    TornWriteOnCall {
        call_index: usize,
        keep_prefix_bytes: usize,
    },
    FailSyncOnCall {
        sync_index: usize,
    },
}

#[derive(Debug)]
struct MemberMediaState {
    durable: Vec<u8>,
    volatile: Vec<PendingWrite>,
    write_calls: usize,
    sync_calls: usize,
    fault: DeviceFault,
}

impl MemberMediaState {
    fn new(initial: Vec<u8>) -> Self {
        Self {
            durable: initial,
            volatile: Vec::new(),
            write_calls: 0,
            sync_calls: 0,
            fault: DeviceFault::None,
        }
    }

    fn read_overlay(&self, offset: usize, len: usize) -> Vec<u8> {
        let mut out = self.durable[offset..offset + len].to_vec();
        for pw in &self.volatile {
            let pw_start = usize::try_from(pw.offset).unwrap();
            let pw_end = pw_start + pw.bytes.len();
            let ov_start = pw_start.max(offset);
            let ov_end = pw_end.min(offset + len);
            if ov_start < ov_end {
                out[(ov_start - offset)..(ov_end - offset)]
                    .copy_from_slice(&pw.bytes[(ov_start - pw_start)..(ov_end - pw_start)]);
            }
        }
        out
    }

    /// Simulate power loss dropping all unsynced volatile writes.
    fn crash_drop_unsynced(&mut self) {
        self.volatile.clear();
    }

    /// Simulate power loss where the drive controller reordered unsynced writes in reverse
    /// and persisted only the odd-indexed writes before power died.
    fn crash_reorder_and_drop_half_unsynced(&mut self) {
        let pending = std::mem::take(&mut self.volatile);
        for (idx, pw) in pending.into_iter().rev().enumerate() {
            if idx % 2 == 0 {
                let start = usize::try_from(pw.offset).unwrap();
                self.durable[start..start + pw.bytes.len()].copy_from_slice(&pw.bytes);
            }
        }
    }

    /// Simulate power loss flushing all currently buffered volatile writes to media
    /// (for cuts right after a partial Uberblock wave write before `sync` completes).
    fn crash_flush_volatile(&mut self) {
        for pw in self.volatile.drain(..) {
            let start = usize::try_from(pw.offset).unwrap();
            self.durable[start..start + pw.bytes.len()].copy_from_slice(&pw.bytes);
        }
    }
}

#[derive(Clone)]
struct FaultableMemberDevice {
    state: Arc<Mutex<MemberMediaState>>,
}

impl FaultableMemberDevice {
    fn new(initial: Vec<u8>) -> Self {
        Self {
            state: Arc::new(Mutex::new(MemberMediaState::new(initial))),
        }
    }

    fn set_fault(&self, fault: DeviceFault) {
        self.state.lock().unwrap().fault = fault;
    }

    fn durable_snapshot(&self) -> Vec<u8> {
        self.state.lock().unwrap().durable.clone()
    }

    fn fresh_from_durable(&self) -> Self {
        Self::new(self.durable_snapshot())
    }

    fn write_calls(&self) -> usize {
        self.state.lock().unwrap().write_calls
    }
}

impl ByteDevice for FaultableMemberDevice {
    fn len_bytes(&self) -> u64 {
        self.state.lock().unwrap().durable.len() as u64
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let st = self.state.lock().unwrap();
        let start = usize::try_from(offset.0).unwrap();
        if start + buf.len() > st.durable.len() {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "read past end of FaultableMemberDevice".into(),
            });
        }
        let data = st.read_overlay(start, buf.len());
        buf.copy_from_slice(&data);
        Ok(())
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let mut st = self.state.lock().unwrap();
        let call = st.write_calls;
        st.write_calls += 1;
        let start = usize::try_from(offset.0).unwrap();
        if start + buf.len() > st.durable.len() {
            return Err(FfsError::Corruption {
                block: 0,
                detail: "write past end of FaultableMemberDevice".into(),
            });
        }
        match st.fault {
            DeviceFault::FailWriteOnCall { call_index } if call == call_index => {
                return Err(FfsError::Io(std::io::Error::other(
                    "injected write_all_at EIO",
                )));
            }
            DeviceFault::TornWriteOnCall {
                call_index,
                keep_prefix_bytes,
            } if call == call_index => {
                let keep = keep_prefix_bytes.min(buf.len());
                if keep > 0 {
                    st.volatile.push(PendingWrite {
                        offset: offset.0,
                        bytes: buf[..keep].to_vec(),
                    });
                }
                return Err(FfsError::Io(std::io::Error::other(
                    "injected torn sector write EIO",
                )));
            }
            _ => {}
        }
        st.volatile.push(PendingWrite {
            offset: offset.0,
            bytes: buf.to_vec(),
        });
        Ok(())
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let mut st = self.state.lock().unwrap();
        let idx = st.sync_calls;
        st.sync_calls += 1;
        if let DeviceFault::FailSyncOnCall { sync_index } = st.fault
            && idx == sync_index
        {
            return Err(FfsError::Io(std::io::Error::other(
                "injected device cache sync barrier failure",
            )));
        }
        for pw in std::mem::take(&mut st.volatile) {
            let start = usize::try_from(pw.offset).unwrap();
            st.durable[start..start + pw.bytes.len()].copy_from_slice(&pw.bytes);
        }
        Ok(())
    }
}

fn default_write_opts(pool_guid: u64, slot: usize) -> ZfsWriteOptions {
    ZfsWriteOptions {
        offline_image: true,
        allow_write: true,
        pool_guid,
        label: 0,
        slot,
        reconcile_torn_uberblocks: false,
    }
}

fn open_engine_on_devices(
    cx: &Cx,
    devs: &[FaultableMemberDevice],
    opts: ZfsWriteOptions,
) -> Result<ZfsTransactionEngine> {
    let boxed: Vec<Box<dyn ByteDevice>> = devs
        .iter()
        .cloned()
        .map(|d| Box::new(d) as Box<dyn ByteDevice>)
        .collect();
    ZfsTransactionEngine::from_devices(cx, boxed, opts)
}

fn assert_pool_scrub_and_allocation_clean(
    cx: &Cx,
    devs: &[FaultableMemberDevice],
    pool_guid: u64,
    slot: Option<usize>,
) -> u64 {
    let leaves: Vec<Leaf> = devs
        .iter()
        .map(|d| {
            let snap = d.fresh_from_durable();
            let len = snap.len_bytes();
            Leaf::from_device(cx, Box::new(snap), 0, len).expect("open fresh leaf")
        })
        .collect();
    let pool = Pool::from_leaves(leaves).expect("open pool");
    let mut mos = slot.map_or_else(
        || {
            pool.import_objects(cx, Some(pool_guid))
                .expect("import_objects active MOS")
        },
        |s| pool.objects(cx, 0, s, pool_guid).expect("open pinned MOS"),
    );
    let mos_scrub = mos
        .scrub(
            cx,
            ScrubLimits {
                copy_bytes: Some(1 << 29),
                ..ScrubLimits::default()
            },
        )
        .expect("MOS scrub");
    assert!(
        mos_scrub.is_clean(),
        "MOS scrub found issues: {:?}",
        mos_scrub.issues
    );
    let alloc = mos
        .allocation(cx, AllocationLimits::default())
        .expect("MOS allocation");
    assert_eq!(
        alloc.allocated_bytes + alloc.free_bytes,
        alloc.mapped_bytes,
        "allocation accounting mismatch"
    );
    for ds_comp in [Vec::<Vec<u8>>::new(), vec![b"data".to_vec()]] {
        let zpl = mos.zpl(cx, &ds_comp).expect("open dataset ZPL");
        let z_scrub = zpl
            .scrub(
                cx,
                ScrubLimits {
                    copy_bytes: Some(1 << 29),
                    ..ScrubLimits::default()
                },
            )
            .expect("ZPL scrub");
        assert!(
            z_scrub.is_clean(),
            "ZPL scrub failed on {:?}: {:?}",
            ds_comp,
            z_scrub.issues
        );
    }
    mos.txg
}

fn assert_native_write_refused(
    engine: &mut ZfsTransactionEngine,
    devices: &[FaultableMemberDevice],
    errno: i32,
    operation: impl FnOnce(&mut ZfsTransactionEngine) -> ZfsTxOutcome<u64>,
) {
    let txg = engine.committed_txg();
    let events = engine.persistence_events().len();
    let io_before: Vec<_> = devices
        .iter()
        .map(|device| {
            let media = device.state.lock().unwrap();
            (media.write_calls, media.sync_calls)
        })
        .collect();
    match operation(engine) {
        ZfsTxOutcome::NotCommitted(error) => assert_eq!(error.to_errno(), errno, "{error}"),
        outcome => panic!("expected admission refusal, got {outcome:?}"),
    }
    assert_eq!(engine.committed_txg(), txg);
    assert_eq!(engine.persistence_events().len(), events);
    let io_after: Vec<_> = devices
        .iter()
        .map(|device| {
            let media = device.state.lock().unwrap();
            (media.write_calls, media.sync_calls)
        })
        .collect();
    assert_eq!(io_after, io_before, "admission failure performed backing I/O");
}

fn assert_readonly_mutations_refused(
    cx: &Cx,
    engine: &mut ZfsTransactionEngine,
    devices: &[FaultableMemberDevice],
    dataset: &[Vec<u8>],
    timestamp: Timestamp,
) {
    assert_native_write_refused(engine, devices, libc::EROFS, |writer| {
        writer.create_file(
            cx,
            dataset,
            2,
            b"new-file",
            0o644,
            1000,
            1000,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
    });
    assert_native_write_refused(engine, devices, libc::EROFS, |writer| {
        writer.mkdir(cx, dataset, 2, b"new-dir", 0o755, 1000, 1000, timestamp)
    });
    assert_native_write_refused(engine, devices, libc::EROFS, |writer| {
        writer.write_file_data(
            cx,
            dataset,
            4,
            0,
            b"overwrite",
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
    });
    assert_native_write_refused(engine, devices, libc::EROFS, |writer| {
        writer.truncate_file(cx, dataset, 4, 0, timestamp, ZfsDataChecksum::Fletcher4)
    });
    assert_native_write_refused(engine, devices, libc::EROFS, |writer| {
        writer.link_entry(cx, dataset, 4, 2, b"alias", timestamp)
    });
    assert_native_write_refused(engine, devices, libc::EROFS, |writer| {
        writer.rename_entry(
            cx,
            dataset,
            2,
            b"hello.txt",
            6,
            b"moved",
            Some(4),
            timestamp,
        )
    });
    assert_native_write_refused(engine, devices, libc::EROFS, |writer| {
        writer.unlink_entry(cx, dataset, 2, b"keep.bin", false, timestamp)
    });
    assert_native_write_refused(engine, devices, libc::EROFS, |writer| {
        writer.unlink_entry(cx, dataset, 2, b"sub", true, timestamp)
    });
}

#[test]
#[allow(clippy::too_many_lines)]
fn native_write_admission_resolves_readonly_inheritance_and_received_values() {
    const READONLY: &[u8] = b"readonly";
    const RECEIVED: &[u8] = b"readonly$recvd";
    const INHERIT: &[u8] = b"readonly$inherit";
    let cases = [
        ("default", vec![], vec![], true),
        ("inherited", vec![(READONLY, 1)], vec![], false),
        ("local-on", vec![(READONLY, 0)], vec![(READONLY, 1)], false),
        ("local-off", vec![(READONLY, 1)], vec![(READONLY, 0)], true),
        ("received-off", vec![(READONLY, 1)], vec![(RECEIVED, 0)], true),
        (
            "inherit-suppresses-received-off",
            vec![(READONLY, 1)],
            vec![(RECEIVED, 0), (INHERIT, 1)],
            false,
        ),
        ("received-on", vec![(READONLY, 0)], vec![(RECEIVED, 1)], false),
        (
            "inherit-suppresses-received-on",
            vec![(READONLY, 0)],
            vec![(RECEIVED, 1), (INHERIT, 1)],
            true,
        ),
        (
            "local-precedes-inherit",
            vec![(READONLY, 1)],
            vec![(READONLY, 0), (RECEIVED, 1), (INHERIT, 1)],
            true,
        ),
        ("inherited-received", vec![(RECEIVED, 1)], vec![], false),
    ];
    let cx = Cx::for_testing();
    let timestamp = Timestamp {
        seconds: 1_715_000_300,
        nanos: 31,
    };
    let dataset = vec![b"data".to_vec()];
    for (zpl_version, with_sa_spill) in [(4, false), (5, true)] {
        for (case, root_properties, data_properties, writable) in &cases {
            let built = build_clean_zfs_pool(&PoolFixtureSpec {
                zpl_version,
                with_sa_spill,
                deadlist_mode: DeadlistMode::NativeDeadlist,
                root_properties: root_properties.clone(),
                data_properties: data_properties.clone(),
                ..PoolFixtureSpec::default()
            });
            let devices: Vec<_> = built
                .members
                .into_iter()
                .map(FaultableMemberDevice::new)
                .collect();
            let mut engine = open_engine_on_devices(
                &cx,
                &devices,
                default_write_opts(built.pool_guid, built.initial_slot),
            )
            .unwrap();
            if *writable {
                engine
                    .mkdir(&cx, &dataset, 2, b"admitted", 0o755, 1000, 1000, timestamp)
                    .into_result()
                    .unwrap_or_else(|error| panic!("{case}: {error}"));
                if *case == "local-off" {
                    assert_native_write_refused(&mut engine, &devices, libc::EROFS, |writer| {
                        writer.mkdir(&cx, &[], 2, b"still-readonly", 0o755, 0, 0, timestamp)
                    });
                }
            } else {
                assert_readonly_mutations_refused(
                    &cx,
                    &mut engine,
                    &devices,
                    &dataset,
                    timestamp,
                );
            }
            // A fresh native reader sees exactly the expected published state,
            // not a mutation left only in an in-memory view.
            let durable: Vec<_> = devices
                .iter()
                .map(FaultableMemberDevice::fresh_from_durable)
                .collect();
            let fresh = open_engine_on_devices(
                &cx,
                &durable,
                default_write_opts(built.pool_guid, engine.committed_slot()),
            )
            .unwrap();
            let mut mos = fresh.open_read_objects(&cx).unwrap();
            let mut zpl = mos.zpl(&cx, &dataset).unwrap();
            let admitted = zpl.resolve(&cx, b"/admitted");
            if *writable {
                admitted.unwrap_or_else(|error| panic!("{case}: {error}"));
            } else {
                assert!(matches!(admitted, Err(FfsError::NotFound(_))), "{case}");
            }
            let hello = zpl.resolve(&cx, b"/hello.txt").unwrap();
            assert_eq!(
                zpl.read(&cx, hello, 0, 8192).unwrap(),
                built.snap_hello_expected,
                "{case}"
            );
            assert_eq!(zpl.stat(&cx, hello).unwrap().0.links, 1, "{case}");
            assert!(zpl.resolve(&cx, b"/keep.bin").is_ok(), "{case}");
            assert!(zpl.resolve(&cx, b"/sub").is_ok(), "{case}");
        }
    }
}

#[test]
fn native_write_admission_rejects_invalid_readonly_before_backing_writes() {
    let cx = Cx::for_testing();
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        root_properties: vec![(b"readonly", 2)],
        ..PoolFixtureSpec::default()
    });
    let devices: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut engine = open_engine_on_devices(
        &cx,
        &devices,
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    let timestamp = Timestamp {
        seconds: 1_715_000_300,
        nanos: 0,
    };
    assert_native_write_refused(&mut engine, &devices, libc::EIO, |writer| {
        writer.mkdir(&cx, &[], 2, b"invalid", 0o755, 1000, 1000, timestamp)
    });
}

#[test]
#[allow(clippy::too_many_lines)]
fn native_write_admission_protects_files_and_rename_replacement_targets() {
    let cx = Cx::for_testing();
    let timestamp = Timestamp {
        seconds: 1_715_000_320,
        nanos: 0,
    };
    let dataset = vec![b"data".to_vec()];
    // Independent native bit positions: immutable, append-only, nounlink.
    for flag in [1_u64 << 36, 1_u64 << 38, 1_u64 << 37] {
        for (zpl_version, with_sa_spill) in [(4, false), (5, true)] {
            let built = build_clean_zfs_pool(&PoolFixtureSpec {
                zpl_version,
                with_sa_spill,
                deadlist_mode: DeadlistMode::NativeDeadlist,
                zpl_flags: BTreeMap::from([(4, flag)]),
                ..PoolFixtureSpec::default()
            });
            let devices: Vec<_> = built
                .members
                .into_iter()
                .map(FaultableMemberDevice::new)
                .collect();
            let mut engine = open_engine_on_devices(
                &cx,
                &devices,
                default_write_opts(built.pool_guid, built.initial_slot),
            )
            .unwrap();
            assert_native_write_refused(&mut engine, &devices, libc::EPERM, |writer| {
                writer.unlink_entry(&cx, &dataset, 2, b"hello.txt", false, timestamp)
            });
            assert_native_write_refused(&mut engine, &devices, libc::EPERM, |writer| {
                writer.rename_entry(
                    &cx,
                    &dataset,
                    2,
                    b"hello.txt",
                    6,
                    b"moved",
                    Some(4),
                    timestamp,
                )
            });
            // Protection applies to the overwritten object too, even when
            // the source, destination directory and source directory are writable.
            assert_native_write_refused(&mut engine, &devices, libc::EPERM, |writer| {
                writer.rename_entry(
                    &cx,
                    &dataset,
                    2,
                    b"keep.bin",
                    2,
                    b"hello.txt",
                    Some(5),
                    timestamp,
                )
            });
            if flag != 1 << 37 {
                assert_native_write_refused(&mut engine, &devices, libc::EPERM, |writer| {
                    writer.write_file_data(
                        &cx,
                        &dataset,
                        4,
                        0,
                        b"overwrite",
                        timestamp,
                        ZfsDataChecksum::Fletcher4,
                    )
                });
                for size in [0, 4096, 8192] {
                    assert_native_write_refused(&mut engine, &devices, libc::EPERM, |writer| {
                        writer.truncate_file(
                            &cx,
                            &dataset,
                            4,
                            size,
                            timestamp,
                            ZfsDataChecksum::Fletcher4,
                        )
                    });
                }
                assert_native_write_refused(&mut engine, &devices, libc::EPERM, |writer| {
                    writer.link_entry(&cx, &dataset, 4, 6, b"alias", timestamp)
                });
            }
            if flag == 1 << 36 {
                assert_native_write_refused(&mut engine, &devices, libc::EPERM, |writer| {
                    writer.write_file_data(
                        &cx,
                        &dataset,
                        4,
                        4096,
                        b"append",
                        timestamp,
                        ZfsDataChecksum::Fletcher4,
                    )
                });
            }
            let mut expected = built.snap_hello_expected;
            // NOUNLINK protects namespace removal, not authorized data writes
            // or additional hard links.
            if flag == 1 << 37 {
                engine
                    .link_entry(&cx, &dataset, 4, 6, b"alias", timestamp)
                    .into_result()
                    .unwrap();
                engine
                    .write_file_data(
                        &cx,
                        &dataset,
                        4,
                        0,
                        b"allowed",
                        timestamp,
                        ZfsDataChecksum::Fletcher4,
                    )
                    .into_result()
                    .unwrap();
                expected[..7].copy_from_slice(b"allowed");
            }
            let mut mos = engine.open_read_objects(&cx).unwrap();
            let mut zpl = mos.zpl(&cx, &dataset).unwrap();
            assert_eq!(zpl.resolve(&cx, b"/hello.txt").unwrap(), 4);
            assert_eq!(zpl.resolve(&cx, b"/keep.bin").unwrap(), 5);
            assert!(matches!(
                zpl.resolve(&cx, b"/sub/moved"),
                Err(FfsError::NotFound(_))
            ));
            assert_eq!(zpl.read(&cx, 4, 0, 8192).unwrap(), expected);
            assert_eq!(zpl.stat(&cx, 4).unwrap().0.flags, 0x408 | flag);
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn native_write_admission_protects_directory_namespace_and_project_inheritance() {
    let cx = Cx::for_testing();
    let timestamp = Timestamp {
        seconds: 1_715_000_340,
        nanos: 0,
    };
    let dataset = vec![b"data".to_vec()];
    // Test the destination directory independently of the source directory.
    for (flag, errno) in [
        (1_u64 << 36, libc::EPERM),
        (1_u64 << 46, libc::EOPNOTSUPP),
    ] {
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            deadlist_mode: DeadlistMode::NativeDeadlist,
            zpl_flags: BTreeMap::from([(6, flag)]),
            ..PoolFixtureSpec::default()
        });
        let devices: Vec<_> = built
            .members
            .into_iter()
            .map(FaultableMemberDevice::new)
            .collect();
        let mut engine = open_engine_on_devices(
            &cx,
            &devices,
            default_write_opts(built.pool_guid, built.initial_slot),
        )
        .unwrap();
        assert_native_write_refused(&mut engine, &devices, errno, |writer| {
            writer.create_file(
                &cx,
                &dataset,
                6,
                b"new-file",
                0o644,
                1000,
                1000,
                timestamp,
                ZfsDataChecksum::Fletcher4,
            )
        });
        assert_native_write_refused(&mut engine, &devices, errno, |writer| {
            writer.mkdir(&cx, &dataset, 6, b"new-dir", 0o755, 1000, 1000, timestamp)
        });
        assert_native_write_refused(&mut engine, &devices, errno, |writer| {
            writer.link_entry(&cx, &dataset, 4, 6, b"alias", timestamp)
        });
        assert_native_write_refused(&mut engine, &devices, errno, |writer| {
            writer.rename_entry(
                &cx,
                &dataset,
                2,
                b"hello.txt",
                6,
                b"moved",
                Some(4),
                timestamp,
            )
        });
        if flag == 1 << 36 {
            assert_native_write_refused(&mut engine, &devices, libc::EPERM, |writer| {
                writer.unlink_entry(&cx, &dataset, 2, b"sub", true, timestamp)
            });
            assert_native_write_refused(&mut engine, &devices, libc::EPERM, |writer| {
                writer.rename_entry(
                    &cx,
                    &dataset,
                    2,
                    b"sub",
                    2,
                    b"renamed-dir",
                    Some(6),
                    timestamp,
                )
            });
        } else {
            // Refusing unimplemented project inheritance does not prohibit
            // removing an existing empty directory with the native flag.
            engine
                .unlink_entry(&cx, &dataset, 2, b"sub", true, timestamp)
                .into_result()
                .unwrap();
        }
    }

    // An immutable parent also protects already existing names, even though
    // the child objects themselves are not immutable.
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        deadlist_mode: DeadlistMode::NativeDeadlist,
        zpl_flags: BTreeMap::from([(2, 1 << 36)]),
        ..PoolFixtureSpec::default()
    });
    let devices: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut engine = open_engine_on_devices(
        &cx,
        &devices,
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    assert_native_write_refused(&mut engine, &devices, libc::EPERM, |writer| {
        writer.unlink_entry(&cx, &dataset, 2, b"hello.txt", false, timestamp)
    });
    assert_native_write_refused(&mut engine, &devices, libc::EPERM, |writer| {
        writer.unlink_entry(&cx, &dataset, 2, b"sub", true, timestamp)
    });
    assert_native_write_refused(&mut engine, &devices, libc::EPERM, |writer| {
        writer.rename_entry(
            &cx,
            &dataset,
            2,
            b"hello.txt",
            6,
            b"moved",
            Some(4),
            timestamp,
        )
    });
    // The parent namespace flag does not make an unflagged child's contents
    // immutable: a direct write to its existing object remains valid.
    engine
        .write_file_data(
            &cx,
            &dataset,
            4,
            0,
            b"allowed",
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let mut mos = engine.open_read_objects(&cx).unwrap();
    let mut zpl = mos.zpl(&cx, &dataset).unwrap();
    assert_eq!(zpl.read(&cx, 4, 0, 7).unwrap(), b"allowed");
    assert_eq!(zpl.stat(&cx, 2).unwrap().0.flags, 0x408 | (1 << 36));
}

#[test]
#[allow(clippy::too_many_lines)]
fn native_write_admission_preserves_append_and_dos_readonly_semantics() {
    let cx = Cx::for_testing();
    let timestamp = Timestamp {
        seconds: 1_715_000_360,
        nanos: 0,
    };
    let dataset = vec![b"data".to_vec()];
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        ashift: 12,
        mirror_width: 2,
        with_sa_spill: true,
        deadlist_mode: DeadlistMode::NativeDeadlist,
        zpl_flags: BTreeMap::from([(4, 1 << 38), (5, 1 << 32), (6, 1 << 38)]),
        ..PoolFixtureSpec::default()
    });
    let devices: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut engine = open_engine_on_devices(
        &cx,
        &devices,
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    assert_native_write_refused(&mut engine, &devices, libc::EPERM, |writer| {
        writer.write_file_data(
            &cx,
            &dataset,
            4,
            4095,
            b"crosses existing EOF",
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
    });
    for (offset, data) in [(4096, b"tail".as_slice()), (4112, b"end".as_slice())] {
        engine
            .write_file_data(
                &cx,
                &dataset,
                4,
                offset,
                data,
                timestamp,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .expect("append-only positioned append");
    }
    // DOS readonly does not revoke an already authorized low-level data-write
    // capability, but native setattr(size) remains prohibited.
    engine
        .write_file_data(
            &cx,
            &dataset,
            5,
            0,
            b"allowed",
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("authorized DOS-readonly data write");
    assert_native_write_refused(&mut engine, &devices, libc::EPERM, |writer| {
        writer.truncate_file(
            &cx,
            &dataset,
            5,
            0,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
    });

    let (new_file, _) = engine
        .create_file(
            &cx,
            &dataset,
            6,
            b"new-file",
            0o644,
            1000,
            1000,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("append-only directory accepts a new file");
    engine
        .mkdir(&cx, &dataset, 6, b"new-dir", 0o755, 1000, 1000, timestamp)
        .into_result()
        .expect("append-only directory accepts a new directory");
    engine
        .link_entry(&cx, &dataset, 5, 6, b"alias", timestamp)
        .into_result()
        .expect("append-only directory accepts a new link");
    engine
        .rename_entry(
            &cx,
            &dataset,
            2,
            b"keep.bin",
            6,
            b"moved",
            Some(5),
            timestamp,
        )
        .into_result()
        .expect("append-only directory accepts an incoming rename");

    let (replacement, _) = engine
        .create_file(
            &cx,
            &dataset,
            2,
            b"replacement",
            0o644,
            1000,
            1000,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    assert_native_write_refused(&mut engine, &devices, libc::EPERM, |writer| {
        writer.unlink_entry(&cx, &dataset, 6, b"moved", false, timestamp)
    });
    assert_native_write_refused(&mut engine, &devices, libc::EPERM, |writer| {
        writer.rename_entry(
            &cx,
            &dataset,
            6,
            b"moved",
            2,
            b"moved-out",
            Some(5),
            timestamp,
        )
    });
    assert_native_write_refused(&mut engine, &devices, libc::EPERM, |writer| {
        writer.rename_entry(
            &cx,
            &dataset,
            2,
            b"replacement",
            6,
            b"new-file",
            Some(replacement),
            timestamp,
        )
    });
    assert_native_write_refused(&mut engine, &devices, libc::EPERM, |writer| {
        writer.unlink_entry(&cx, &dataset, 6, b"new-dir", true, timestamp)
    });

    let durable: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::fresh_from_durable)
        .collect();
    let fresh = open_engine_on_devices(
        &cx,
        &durable,
        default_write_opts(built.pool_guid, engine.committed_slot()),
    )
    .unwrap();
    let mut mos = fresh.open_read_objects(&cx).unwrap();
    let mut zpl = mos.zpl(&cx, &dataset).unwrap();
    let mut expected = built.snap_hello_expected.clone();
    expected.extend_from_slice(b"tail");
    expected.resize(4112, 0);
    expected.extend_from_slice(b"end");
    assert_eq!(zpl.read(&cx, 4, 0, 8192).unwrap(), expected);
    assert_eq!(zpl.stat(&cx, 4).unwrap().0.flags, 0x408 | (1 << 38));
    assert_eq!(zpl.resolve(&cx, b"/sub/moved").unwrap(), 5);
    assert_eq!(zpl.resolve(&cx, b"/sub/alias").unwrap(), 5);
    assert_eq!(zpl.read(&cx, 5, 0, 7).unwrap(), b"allowed");
    assert_eq!(zpl.stat(&cx, 5).unwrap().0.flags, 0x408 | (1 << 32));
    assert_eq!(zpl.stat(&cx, 5).unwrap().0.links, 2);
    assert_eq!(zpl.resolve(&cx, b"/sub/new-file").unwrap(), new_file);
    assert_eq!(zpl.resolve(&cx, b"/replacement").unwrap(), replacement);
    assert!(zpl.resolve(&cx, b"/sub/new-dir").is_ok());
    assert!(matches!(
        zpl.resolve(&cx, b"/moved-out"),
        Err(FfsError::NotFound(_))
    ));
    let mut snapshot = zpl.open_snapshot(&cx, b"before").unwrap();
    assert_eq!(
        snapshot.read(&cx, 4, 0, 8192).unwrap(),
        built.snap_hello_expected
    );
    assert_eq!(snapshot.read(&cx, 5, 0, 7).unwrap(), vec![0x5A; 7]);
    assert_pool_scrub_and_allocation_clean(
        &cx,
        &durable,
        built.pool_guid,
        Some(fresh.committed_slot()),
    );
}

// ---------------------------------------------------------------------------
// 1. Happy-path ZPL v4 & v5 + ashift 9 & 12 + single & 2-way mirror lifecycle
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)]
fn end_to_end_zpl_v4_and_v5_lifecycle_single_and_mirror_ashift_9_and_12() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_715_000_000,
        nanos: 123_456_789,
    };

    for (zpl_version, ashift, mirror_width, user_accounting, with_sa_spill) in [
        (4_u64, 9_u8, 1_usize, false, false),
        (5_u64, 9_u8, 1_usize, true, true),
        (5_u64, 12_u8, 2_usize, true, false),
    ] {
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            image_bytes: 24 * 1024 * 1024,
            ashift,
            mirror_width,
            zpl_version,
            with_sa_spill,
            user_accounting,
            ..PoolFixtureSpec::default()
        });
        let devs: Vec<_> = built
            .members
            .into_iter()
            .map(FaultableMemberDevice::new)
            .collect();
        let mut engine = open_engine_on_devices(
            &cx,
            &devs,
            default_write_opts(built.pool_guid, built.initial_slot),
        )
        .expect("admit clean pool");
        assert_eq!(engine.committed_txg(), INITIAL_TXG);
        assert_eq!(
            engine.admission_report().topology,
            if mirror_width == 1 {
                ZfsTopologyKind::SingleLeaf
            } else {
                ZfsTopologyKind::Mirror {
                    width: mirror_width,
                }
            }
        );

        let ds = [b"data".to_vec()];
        // If `with_sa_spill` seeded `/spilled.txt` on root dataset, overwrite it and ensure spill survives!
        if with_sa_spill {
            let mut mos = engine.open_read_objects(&cx).unwrap();
            let mut rzpl = mos.zpl(&cx, &[]).unwrap();
            let sp_obj = rzpl.resolve(&cx, b"/spilled.txt").unwrap();
            let (new_sz, tok) = engine
                .write_file_data(
                    &cx,
                    &[],
                    sp_obj,
                    0,
                    b"updated-spilled-payload-bytes!",
                    ts,
                    ZfsDataChecksum::Sha256,
                )
                .into_result()
                .expect("write spilled.txt");
            engine.verify_token(&tok).unwrap();
            assert_eq!(new_sz, 30);
            let mut mos2 = engine.open_read_objects(&cx).unwrap();
            let mut rzpl2 = mos2.zpl(&cx, &[]).unwrap();
            assert_eq!(
                rzpl2.read(&cx, sp_obj, 0, 64).unwrap(),
                b"updated-spilled-payload-bytes!"
            );
        }

        // Create directory `/work` and nested `/work/archive`
        let (work_dir, tok1) = engine
            .mkdir(&cx, &ds, 2, b"work", 0o755, 1000, 1000, ts)
            .into_result()
            .expect("mkdir work");
        engine.verify_token(&tok1).unwrap();
        let (arch_dir, _) = engine
            .mkdir(&cx, &ds, work_dir, b"archive", 0o750, 1000, 1000, ts)
            .into_result()
            .expect("mkdir archive");

        // Create multi-block indirect file (`300 KiB` > `128 KiB` recordsize -> level >= 2!) with SHA-256
        let (big_obj, _) = engine
            .create_file(
                &cx,
                &ds,
                work_dir,
                b"big.bin",
                0o640,
                1000,
                1000,
                ts,
                ZfsDataChecksum::Sha256,
            )
            .into_result()
            .expect("create big.bin");
        let big_payload: Vec<u8> = (0..310_000_usize)
            .map(|i| u8::try_from((i * 37 + 11) % 251).unwrap())
            .collect();
        let (written_sz, _) = engine
            .write_file_data(
                &cx,
                &ds,
                big_obj,
                0,
                &big_payload,
                ts,
                ZfsDataChecksum::Sha256,
            )
            .into_result()
            .expect("write 310 KiB");
        assert_eq!(written_sz, big_payload.len() as u64);

        // Partial overwrite across recordsize boundary (`130_000..133_000`) with Fletcher4
        let patch = vec![0xEE_u8; 3000];
        let mut expected_big = big_payload;
        expected_big[130_000..133_000].copy_from_slice(&patch);
        let _ = engine
            .write_file_data(
                &cx,
                &ds,
                big_obj,
                130_000,
                &patch,
                ts,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .expect("patch cross-block");

        // Partial-block truncate down to `140_123` bytes, then sparse extend to `400_000` bytes!
        let _ = engine
            .truncate_file(&cx, &ds, big_obj, 140_123, ts, ZfsDataChecksum::Fletcher4)
            .into_result()
            .expect("truncate shrink");
        expected_big.truncate(140_123);
        let _ = engine
            .truncate_file(&cx, &ds, big_obj, 400_000, ts, ZfsDataChecksum::Fletcher4)
            .into_result()
            .expect("truncate sparse extend");
        expected_big.resize(400_000, 0);

        // Promote `/work` from Micro-ZAP to Fat-ZAP (create 75 long-named files > 50 bytes, which cannot fit in Micro-ZAP!)
        let mut fat_objs = Vec::new();
        if zpl_version == 5 && mirror_width == 1 {
            for idx in 0..75_usize {
                let long_name = format!(
                    "fatzap_promoted_entry_{idx:03}_with_name_exceeding_microzap_50_byte_limit.dat"
                );
                let (fobj, _) = engine
                    .create_file(
                        &cx,
                        &ds,
                        work_dir,
                        long_name.as_bytes(),
                        0o644,
                        1000,
                        1000,
                        ts,
                        ZfsDataChecksum::Fletcher4,
                    )
                    .into_result()
                    .expect("create fatzap entry");
                fat_objs.push((long_name, fobj));
            }
        }

        // Cross-directory rename `/work/big.bin` -> `/work/archive/moved.bin` (with expected_source_object)
        // First create a victim file at `/work/archive/moved.bin` to test POSIX atomic overwrite!
        let (victim_obj, _) = engine
            .create_file(
                &cx,
                &ds,
                arch_dir,
                b"moved.bin",
                0o600,
                1000,
                1000,
                ts,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        let _ = engine
            .write_file_data(
                &cx,
                &ds,
                victim_obj,
                0,
                b"old-victim-bytes",
                ts,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        let (moved_id, _) = engine
            .rename_entry(
                &cx,
                &ds,
                work_dir,
                b"big.bin",
                arch_dir,
                b"moved.bin",
                Some(big_obj),
                ts,
            )
            .into_result()
            .expect("cross-dir rename");
        assert_eq!(moved_id, big_obj);

        // Directory cycle rejection: renaming `/work` into `/work/archive/subwork` must fail!
        let cycle_res = engine.rename_entry(&cx, &ds, 2, b"work", arch_dir, b"subwork", None, ts);
        assert!(matches!(cycle_res, ZfsTxOutcome::NotCommitted(_)));

        // Non-empty rmdir on `/work/archive` must fail with `NotEmpty`!
        let rmdir_nonempty = engine.unlink_entry(&cx, &ds, work_dir, b"archive", true, ts);
        assert!(matches!(
            rmdir_nonempty,
            ZfsTxOutcome::NotCommitted(FfsError::NotEmpty)
        ));

        // Unlink `/work/archive/moved.bin`? Wait — first read & verify `/work/archive/moved.bin` via fresh Pool!
        let final_slot = engine.committed_slot();
        let final_txg =
            assert_pool_scrub_and_allocation_clean(&cx, &devs, built.pool_guid, Some(final_slot));
        assert_eq!(final_txg, engine.committed_txg());

        {
            let mut mos = engine.open_read_objects(&cx).unwrap();
            let mut zpl = mos.zpl(&cx, &ds).unwrap();
            let resolved = zpl.resolve(&cx, b"/work/archive/moved.bin").unwrap();
            assert_eq!(resolved, big_obj);
            let read_back = zpl.read(&cx, resolved, 0, 500_000).unwrap();
            assert_eq!(read_back, expected_big);
            for (fname, fobj) in &fat_objs {
                let p = format!("/work/{fname}");
                assert_eq!(zpl.resolve(&cx, p.as_bytes()).unwrap(), *fobj);
            }
        }

        // Now unlink `/work/archive/moved.bin` and `rmdir` empty `/work/archive`, and re-verify zero space leaks!
        let _ = engine
            .unlink_entry(&cx, &ds, arch_dir, b"moved.bin", false, ts)
            .into_result()
            .expect("unlink moved.bin");
        let _ = engine
            .unlink_entry(&cx, &ds, work_dir, b"archive", true, ts)
            .into_result()
            .expect("rmdir empty archive");
        assert_pool_scrub_and_allocation_clean(
            &cx,
            &devs,
            built.pool_guid,
            Some(engine.committed_slot()),
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Partition slice `open_files_at` canary preservation
// ---------------------------------------------------------------------------

#[test]
fn partition_slice_open_files_at_preserves_prefix_and_suffix_canaries() {
    let cx = Cx::for_testing();
    let built = build_clean_zfs_pool(&PoolFixtureSpec::default());
    let part_offset = 1_048_576_u64;
    let part_len = built.members[0].len() as u64;
    let suffix_len = 65_536_usize;

    let dir = tempfile::tempdir().unwrap();
    let disk_path = dir.path().join("partitioned_zfs.img");
    let mut disk = vec![0x50_u8; usize::try_from(part_offset).unwrap()]; // 'P' canary
    disk.extend_from_slice(&built.members[0]);
    disk.extend(std::iter::repeat_n(0x51_u8, suffix_len)); // 'Q' canary
    std::fs::write(&disk_path, &disk).unwrap();

    let ts = Timestamp {
        seconds: 1_715_000_100,
        nanos: 0,
    };
    let mut engine = ZfsTransactionEngine::open_files_at(
        &cx,
        &[disk_path.as_path()],
        part_offset,
        Some(part_len),
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .expect("open_files_at");
    let (fobj, tok) = engine
        .create_file(
            &cx,
            &[b"data".to_vec()],
            2,
            b"slice.txt",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    engine.verify_token(&tok).unwrap();
    let _ = engine
        .write_file_data(
            &cx,
            &[b"data".to_vec()],
            fobj,
            0,
            b"inside-partition-slice",
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let slot = engine.committed_slot();
    drop(engine);

    let after = std::fs::read(&disk_path).unwrap();
    assert!(
        after[..usize::try_from(part_offset).unwrap()]
            .iter()
            .all(|&b| b == 0x50),
        "partition prefix canary mutated!"
    );
    let end = usize::try_from(part_offset + part_len).unwrap();
    assert!(
        after[end..].iter().all(|&b| b == 0x51),
        "partition suffix canary mutated!"
    );

    let leaf = Leaf::open(&cx, &disk_path, part_offset, Some(part_len)).unwrap();
    let pool = Pool::from_leaves(vec![leaf]).unwrap();
    let mut mos = pool.objects(&cx, 0, slot, built.pool_guid).unwrap();
    assert!(mos.scrub(&cx, ScrubLimits::default()).unwrap().is_clean());
    let mut zpl = mos.zpl(&cx, &[b"data".to_vec()]).unwrap();
    let resolved = zpl.resolve(&cx, b"/slice.txt").unwrap();
    assert_eq!(
        zpl.read(&cx, resolved, 0, 64).unwrap(),
        b"inside-partition-slice"
    );
}

// ---------------------------------------------------------------------------
// 3. Snapshotted dataset COW + Deadlist (`DMU_OT_BPOBJ` & `DMU_OT_DEADLIST`)
// ---------------------------------------------------------------------------

#[test]
fn snapshotted_dataset_cow_preserves_historical_lzjb_snapshot_with_bpobj_and_deadlist() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_715_000_200,
        nanos: 0,
    };

    for mode in [DeadlistMode::Bpobj, DeadlistMode::NativeDeadlist] {
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            deadlist_mode: mode,
            ..PoolFixtureSpec::default()
        });
        let devs = vec![FaultableMemberDevice::new(built.members[0].clone())];
        let mut engine = open_engine_on_devices(
            &cx,
            &devs,
            default_write_opts(built.pool_guid, built.initial_slot),
        )
        .unwrap();
        let ds = [b"data".to_vec()];
        let (hello_obj, _keep_obj) = {
            let mut mos = engine.open_read_objects(&cx).unwrap();
            let mut zpl = mos.zpl(&cx, &ds).unwrap();
            (
                zpl.resolve(&cx, b"/hello.txt").unwrap(),
                zpl.resolve(&cx, b"/keep.bin").unwrap(),
            )
        };

        // Overwrite `hello.txt` (whose `birth == SNAP_TXG == 15` is referenced by `@before`!),
        // truncate `keep.bin` to 100 bytes, and unlink `keep.bin`!
        // Every retired block with `birth <= 15` MUST go into the dataset deadlist, NOT freed in the metaslab!
        let _ = engine
            .write_file_data(
                &cx,
                &ds,
                hello_obj,
                0,
                b"live-head-overwrite-after-snapshot",
                ts,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .expect("overwrite snapshotted lzjb file");
        let _ = engine
            .truncate_file(&cx, &ds, hello_obj, 34, ts, ZfsDataChecksum::Fletcher4)
            .into_result()
            .expect("truncate snapshotted file");
        let _ = engine
            .unlink_entry(&cx, &ds, 2, b"keep.bin", false, ts)
            .into_result()
            .expect("unlink snapshotted keep.bin");

        let slot = engine.committed_slot();
        assert_pool_scrub_and_allocation_clean(&cx, &devs, built.pool_guid, Some(slot));

        // Verify live head AND immutable `@before` snapshot via fresh Pool!
        let snap_dev = devs[0].fresh_from_durable();
        let leaf = Leaf::from_device(&cx, Box::new(snap_dev), 0, spec_len(&devs[0])).unwrap();
        let pool = Pool::from_leaves(vec![leaf]).unwrap();
        let mut mos = pool.objects(&cx, 0, slot, built.pool_guid).unwrap();

        let mut live_zpl = mos.zpl(&cx, &ds).unwrap();
        assert_eq!(
            live_zpl.read(&cx, hello_obj, 0, 128).unwrap(),
            b"live-head-overwrite-after-snapshot"
        );
        assert!(matches!(
            live_zpl.resolve(&cx, b"/keep.bin"),
            Err(FfsError::NotFound(_))
        ));

        let mut snap_zpl = live_zpl
            .open_snapshot(&cx, b"before")
            .expect("open @before");
        assert!(
            snap_zpl
                .scrub(&cx, ScrubLimits::default())
                .unwrap()
                .is_clean()
        );
        let snap_hello = snap_zpl.resolve(&cx, b"/hello.txt").unwrap();
        assert_eq!(
            snap_zpl.read(&cx, snap_hello, 0, 8192).unwrap(),
            built.snap_hello_expected
        );
        let snap_keep = snap_zpl.resolve(&cx, b"/keep.bin").unwrap();
        assert_eq!(
            snap_zpl.read(&cx, snap_keep, 0, 8192).unwrap(),
            vec![0x5A; 4096]
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn hard_links_preserve_identity_and_data_through_reopen_rename_and_last_unlink() {
    let cx = Cx::for_testing();
    let created = Timestamp {
        seconds: 1_715_000_250,
        nanos: 17,
    };
    let linked = Timestamp {
        seconds: created.seconds + 10,
        nanos: 23,
    };
    let alias = b"a_hard_link_name_long_enough_to_require_native_fatzap_promotion.bin";
    for (zpl_version, ashift, mirror_width, with_sa_spill) in
        [(4, 9, 1, false), (5, 9, 1, true), (5, 12, 2, false)]
    {
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            zpl_version,
            ashift,
            mirror_width,
            with_sa_spill,
            user_accounting: zpl_version == 5,
            ..PoolFixtureSpec::default()
        });
        let mut devs: Vec<_> = built
            .members
            .into_iter()
            .map(FaultableMemberDevice::new)
            .collect();
        let mut engine = open_engine_on_devices(
            &cx,
            &devs,
            default_write_opts(built.pool_guid, built.initial_slot),
        )
        .unwrap();
        let ds = if with_sa_spill {
            vec![]
        } else {
            vec![b"data".to_vec()]
        };
        let source_name: &[u8] = if with_sa_spill {
            b"spilled.txt"
        } else {
            b"source.bin"
        };
        let source_path = [b"/".as_slice(), source_name].concat();
        let source = if with_sa_spill {
            let mut mos = engine.open_read_objects(&cx).unwrap();
            mos.zpl(&cx, &ds)
                .unwrap()
                .resolve(&cx, &source_path)
                .unwrap()
        } else {
            engine
                .create_file(
                    &cx,
                    &ds,
                    2,
                    source_name,
                    0o640,
                    1000,
                    1001,
                    created,
                    ZfsDataChecksum::Sha256,
                )
                .into_result()
                .unwrap()
                .0
        };
        let destination = engine
            .mkdir(&cx, &ds, 2, b"links", 0o750, 1000, 1001, created)
            .into_result()
            .unwrap()
            .0;
        let mut payload: Vec<_> = (0..140_000_usize)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect();
        engine
            .write_file_data(
                &cx,
                &ds,
                source,
                0,
                &payload,
                created,
                ZfsDataChecksum::Sha256,
            )
            .into_result()
            .unwrap();
        let (before, parent_before) = {
            let mut mos = engine.open_read_objects(&cx).unwrap();
            let mut zpl = mos.zpl(&cx, &ds).unwrap();
            (
                zpl.stat(&cx, source).unwrap().0,
                zpl.stat(&cx, destination).unwrap().0,
            )
        };
        let (linked_object, token) = engine
            .link_entry(&cx, &ds, source, destination, alias, linked)
            .into_result()
            .expect("commit hard link");
        assert_eq!(linked_object, source);
        engine.verify_token(&token).unwrap();

        // Reopen from durable bytes, discarding every writer and reader cache.
        let slot = engine.committed_slot();
        devs = devs
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        engine =
            open_engine_on_devices(&cx, &devs, default_write_opts(built.pool_guid, slot)).unwrap();
        let alias_path = [b"/links/".as_slice(), alias].concat();
        {
            let mut mos = engine.open_read_objects(&cx).unwrap();
            let mut zpl = mos.zpl(&cx, &ds).unwrap();
            assert_eq!(zpl.resolve(&cx, &source_path).unwrap(), source);
            assert_eq!(zpl.resolve(&cx, &alias_path).unwrap(), source);
            let after = zpl.stat(&cx, source).unwrap().0;
            let mut expected = before.clone();
            expected.links += 1;
            expected.parent = destination;
            expected.times[2] = linked;
            assert_eq!(after, expected, "only native link metadata should change");
            let parent_after = zpl.stat(&cx, destination).unwrap().0;
            assert_eq!(parent_after.size, parent_before.size + 1);
            assert_eq!(parent_after.links, parent_before.links);
            assert_eq!(parent_after.times[1], linked);
            assert_eq!(zpl.read(&cx, source, 0, payload.len()).unwrap(), payload);
        }

        // Every rejected operation must leave both the TXG and backing media untouched.
        let writes_before: Vec<_> = devs
            .iter()
            .map(FaultableMemberDevice::write_calls)
            .collect();
        let txg_before = engine.committed_txg();
        assert!(matches!(
            engine.link_entry(&cx, &ds, destination, 2, b"directory-link", linked),
            ZfsTxOutcome::NotCommitted(FfsError::RequestRejected {
                errno: libc::EPERM,
                ..
            })
        ));
        assert!(matches!(
            engine.link_entry(&cx, &ds, source, source, b"not-a-directory", linked),
            ZfsTxOutcome::NotCommitted(FfsError::NotDirectory)
        ));
        assert!(matches!(
            engine.link_entry(&cx, &ds, source, destination, alias, linked),
            ZfsTxOutcome::NotCommitted(FfsError::Exists)
        ));
        assert!(matches!(
            engine.link_entry(&cx, &ds, source, destination, b"../invalid", linked),
            ZfsTxOutcome::NotCommitted(FfsError::Format(_))
        ));
        assert!(matches!(
            engine.link_entry(&cx, &ds, 0, destination, b"missing", linked),
            ZfsTxOutcome::NotCommitted(FfsError::NotFound(_))
        ));
        assert_eq!(engine.committed_txg(), txg_before);
        assert_eq!(
            devs.iter()
                .map(FaultableMemberDevice::write_calls)
                .collect::<Vec<_>>(),
            writes_before
        );

        // Renaming between two names for the same object is a namespace no-op.
        engine
            .rename_entry(
                &cx,
                &ds,
                2,
                source_name,
                destination,
                alias,
                Some(source),
                linked,
            )
            .into_result()
            .unwrap();
        engine
            .write_file_data(
                &cx,
                &ds,
                linked_object,
                130_000,
                b"shared data",
                linked,
                ZfsDataChecksum::Sha256,
            )
            .into_result()
            .unwrap();
        payload[130_000..130_011].copy_from_slice(b"shared data");
        engine
            .unlink_entry(&cx, &ds, 2, source_name, false, linked)
            .into_result()
            .unwrap();
        {
            let mut mos = engine.open_read_objects(&cx).unwrap();
            let mut zpl = mos.zpl(&cx, &ds).unwrap();
            assert!(matches!(
                zpl.resolve(&cx, &source_path),
                Err(FfsError::NotFound(_))
            ));
            assert_eq!(zpl.resolve(&cx, &alias_path).unwrap(), source);
            assert_eq!(zpl.stat(&cx, source).unwrap().0.links, 1);
            assert_eq!(zpl.read(&cx, source, 0, payload.len()).unwrap(), payload);
        }
        engine
            .unlink_entry(&cx, &ds, destination, alias, false, linked)
            .into_result()
            .unwrap();
        {
            let mut mos = engine.open_read_objects(&cx).unwrap();
            let mut zpl = mos.zpl(&cx, &ds).unwrap();
            assert!(matches!(
                zpl.resolve(&cx, &alias_path),
                Err(FfsError::NotFound(_))
            ));
            assert!(
                zpl.stat(&cx, source).is_err(),
                "last unlink must reclaim the live object"
            );
        }
        assert_pool_scrub_and_allocation_clean(
            &cx,
            &devs,
            built.pool_guid,
            Some(engine.committed_slot()),
        );
    }
}

#[test]
fn hard_links_and_last_unlink_preserve_native_snapshots_and_deadlists() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_715_000_275,
        nanos: 0,
    };
    let ds = [b"data".to_vec()];
    for mode in [DeadlistMode::Bpobj, DeadlistMode::NativeDeadlist] {
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            deadlist_mode: mode,
            ..PoolFixtureSpec::default()
        });
        let devs: Vec<_> = built
            .members
            .into_iter()
            .map(FaultableMemberDevice::new)
            .collect();
        let mut engine = open_engine_on_devices(
            &cx,
            &devs,
            default_write_opts(built.pool_guid, built.initial_slot),
        )
        .unwrap();
        let source = {
            let mut mos = engine.open_read_objects(&cx).unwrap();
            mos.zpl(&cx, &ds)
                .unwrap()
                .resolve(&cx, b"/hello.txt")
                .unwrap()
        };
        engine
            .link_entry(&cx, &ds, source, 2, b"alias.txt", ts)
            .into_result()
            .unwrap();
        for name in [b"hello.txt".as_slice(), b"alias.txt"] {
            engine
                .unlink_entry(&cx, &ds, 2, name, false, ts)
                .into_result()
                .unwrap();
        }
        let fresh: Vec<_> = devs
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let reopened = open_engine_on_devices(
            &cx,
            &fresh,
            default_write_opts(built.pool_guid, engine.committed_slot()),
        )
        .unwrap();
        let mut mos = reopened.open_read_objects(&cx).unwrap();
        let mut head = mos.zpl(&cx, &ds).unwrap();
        assert!(matches!(
            head.resolve(&cx, b"/hello.txt"),
            Err(FfsError::NotFound(_))
        ));
        assert!(matches!(
            head.resolve(&cx, b"/alias.txt"),
            Err(FfsError::NotFound(_))
        ));
        let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
        assert_eq!(snapshot.resolve(&cx, b"/hello.txt").unwrap(), source);
        assert_eq!(snapshot.stat(&cx, source).unwrap().0.links, 1);
        assert_eq!(
            snapshot.read(&cx, source, 0, 8192).unwrap(),
            built.snap_hello_expected
        );
        assert!(matches!(
            snapshot.resolve(&cx, b"/alias.txt"),
            Err(FfsError::NotFound(_))
        ));
        assert!(
            snapshot
                .scrub(&cx, ScrubLimits::default())
                .unwrap()
                .is_clean()
        );
        assert_pool_scrub_and_allocation_clean(
            &cx,
            &fresh,
            built.pool_guid,
            Some(reopened.committed_slot()),
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn hard_link_persistence_cuts_never_split_directory_entry_from_link_count() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_715_000_290,
        nanos: 0,
    };
    let ds = [b"data".to_vec()];
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        mirror_width: 2,
        deadlist_mode: DeadlistMode::NativeDeadlist,
        ..PoolFixtureSpec::default()
    });
    let probe_devs: Vec<_> = built
        .members
        .iter()
        .cloned()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut probe = open_engine_on_devices(
        &cx,
        &probe_devs,
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    let source = {
        let mut mos = probe.open_read_objects(&cx).unwrap();
        mos.zpl(&cx, &ds)
            .unwrap()
            .resolve(&cx, b"/hello.txt")
            .unwrap()
    };
    probe
        .link_entry(&cx, &ds, source, 2, b"alias.txt", ts)
        .into_result()
        .unwrap();
    let events = probe.persistence_events().to_vec();
    let first_uberblock_seq = events
        .iter()
        .find(|event| matches!(event.stage, ZfsPersistenceStage::UberblockWrite { .. }))
        .unwrap()
        .seq;
    let durable_seq = events
        .iter()
        .find(|event| event.stage == ZfsPersistenceStage::BeforeAcknowledge)
        .unwrap()
        .seq;

    for cut in events {
        for reorder in [false, true] {
            let devs: Vec<_> = built
                .members
                .iter()
                .cloned()
                .map(FaultableMemberDevice::new)
                .collect();
            let mut engine = open_engine_on_devices(
                &cx,
                &devs,
                default_write_opts(built.pool_guid, built.initial_slot),
            )
            .unwrap();
            let seq = cut.seq;
            engine.with_fault_hook(move |event| {
                if event.seq == seq {
                    Err(FfsError::Cancelled)
                } else {
                    Ok(())
                }
            });
            let outcome = engine.link_entry(&cx, &ds, source, 2, b"alias.txt", ts);
            if seq < first_uberblock_seq {
                assert!(
                    matches!(outcome, ZfsTxOutcome::NotCommitted(_)),
                    "cut {:?}",
                    cut.stage
                );
            } else if seq < durable_seq {
                assert!(
                    matches!(outcome, ZfsTxOutcome::Uncertain { .. }),
                    "cut {:?}",
                    cut.stage
                );
            } else {
                assert!(outcome.is_committed(), "known durable cut {:?}", cut.stage);
            }
            for device in &devs {
                let mut state = device.state.lock().unwrap();
                if reorder {
                    state.crash_reorder_and_drop_half_unsynced();
                } else {
                    state.crash_drop_unsynced();
                }
            }
            let leaves = devs
                .iter()
                .map(|device| {
                    let fresh = device.fresh_from_durable();
                    let len = fresh.len_bytes();
                    Leaf::from_device(&cx, Box::new(fresh), 0, len).unwrap()
                })
                .collect();
            let pool = Pool::from_leaves(leaves).unwrap();
            let mut mos = pool.import_objects(&cx, Some(built.pool_guid)).unwrap();
            assert!([INITIAL_TXG, INITIAL_TXG + 1].contains(&mos.txg));
            let recovered_new = mos.txg == INITIAL_TXG + 1;
            if seq < first_uberblock_seq {
                assert!(!recovered_new);
            }
            if seq >= durable_seq {
                assert!(recovered_new);
            }
            let mut head = mos.zpl(&cx, &ds).unwrap();
            assert_eq!(head.resolve(&cx, b"/hello.txt").unwrap(), source);
            match head.resolve(&cx, b"/alias.txt") {
                Ok(object) => {
                    assert!(recovered_new);
                    assert_eq!(object, source);
                    assert_eq!(head.stat(&cx, source).unwrap().0.links, 2);
                }
                Err(FfsError::NotFound(_)) => {
                    assert!(!recovered_new);
                    assert_eq!(head.stat(&cx, source).unwrap().0.links, 1);
                }
                other => panic!("unexpected alias recovery at {:?}: {other:?}", cut.stage),
            }
            assert_eq!(
                head.read(&cx, source, 0, 8192).unwrap(),
                built.snap_hello_expected
            );
            let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
            assert_eq!(snapshot.stat(&cx, source).unwrap().0.links, 1);
            assert!(matches!(
                snapshot.resolve(&cx, b"/alias.txt"),
                Err(FfsError::NotFound(_))
            ));
            assert_pool_scrub_and_allocation_clean(&cx, &devs, built.pool_guid, None);
        }
    }
}

fn spec_len(dev: &FaultableMemberDevice) -> u64 {
    dev.len_bytes()
}

// ---------------------------------------------------------------------------
// 4. Persistence-prefix fault-cut, reorder, torn-Uberblock, mirror-split & cancel
// ---------------------------------------------------------------------------

#[test]
#[allow(clippy::too_many_lines)]
fn persistence_prefix_fault_cuts_reorder_torn_mirror_split_flush_fail_and_cancel() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_715_000_300,
        nanos: 0,
    };
    let base_built = build_clean_zfs_pool(&PoolFixtureSpec::default());
    let ds = [b"data".to_vec()];

    // First run one baseline TXG to record the exact persistence event stages!
    let probe_dev = FaultableMemberDevice::new(base_built.members[0].clone());
    let mut probe_eng = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&probe_dev),
        default_write_opts(base_built.pool_guid, base_built.initial_slot),
    )
    .unwrap();
    let _ = probe_eng
        .create_file(
            &cx,
            &ds,
            2,
            b"probe.txt",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let recorded_events = probe_eng.persistence_events().to_vec();
    assert!(
        recorded_events.len() >= 10,
        "expected full child->dataset->spacemap->mos_root->uberblock waves->before_ack sequence"
    );

    // Verify strict child-before-parent partial order in `recorded_events`!
    let first_ub_pos = recorded_events
        .iter()
        .position(|e| matches!(e.stage, ZfsPersistenceStage::UberblockWrite { .. }))
        .expect("must have UberblockWrite");
    let mos_root_barrier_pos = recorded_events
        .iter()
        .position(|e| matches!(e.stage, ZfsPersistenceStage::MosRootBarrier { .. }))
        .expect("must have MosRootBarrier");
    assert!(
        mos_root_barrier_pos < first_ub_pos,
        "MosRootBarrier MUST precede first UberblockWrite!"
    );

    // A0. Direct `ByteDevice::write_all_at` EIO on child/metadata block returns `NotCommitted`.
    {
        let dev = FaultableMemberDevice::new(base_built.members[0].clone());
        dev.set_fault(DeviceFault::FailWriteOnCall { call_index: 1 });
        let mut eng = open_engine_on_devices(
            &cx,
            std::slice::from_ref(&dev),
            default_write_opts(base_built.pool_guid, base_built.initial_slot),
        )
        .unwrap();
        let out = eng.create_file(
            &cx,
            &ds,
            2,
            b"write_eio.txt",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        );
        assert!(matches!(out, ZfsTxOutcome::NotCommitted(FfsError::Io(_))));
        dev.state.lock().unwrap().crash_drop_unsynced();
        assert_eq!(
            assert_pool_scrub_and_allocation_clean(
                &cx,
                std::slice::from_ref(&dev),
                base_built.pool_guid,
                Some(base_built.initial_slot),
            ),
            INITIAL_TXG
        );
    }

    // A. Cut at EVERY event strictly before `first_ub_pos` (including reordered/dropped volatile cache):
    // Every cut MUST return `ZfsTxOutcome::NotCommitted`, leave `INITIAL_TXG` 100% intact on fresh engine,
    // and allow a subsequent TXG to commit with zero leaks!
    for cut_ev in recorded_events.iter().take(first_ub_pos) {
        let target_seq = cut_ev.seq;
        for reorder_mode in [false, true] {
            let dev = FaultableMemberDevice::new(base_built.members[0].clone());
            let mut eng = open_engine_on_devices(
                &cx,
                std::slice::from_ref(&dev),
                default_write_opts(base_built.pool_guid, base_built.initial_slot),
            )
            .unwrap();
            eng.with_fault_hook(move |ev| {
                if ev.seq == target_seq {
                    Err(FfsError::Io(std::io::Error::other(
                        "pre-uberblock fault cut",
                    )))
                } else {
                    Ok(())
                }
            });
            let out = eng.create_file(
                &cx,
                &ds,
                2,
                b"cut.txt",
                0o644,
                0,
                0,
                ts,
                ZfsDataChecksum::Fletcher4,
            );
            assert!(
                matches!(out, ZfsTxOutcome::NotCommitted(_)),
                "pre-Uberblock cut at seq={target_seq} ({:?}) must be NotCommitted",
                cut_ev.stage
            );
            if reorder_mode {
                dev.state
                    .lock()
                    .unwrap()
                    .crash_reorder_and_drop_half_unsynced();
            } else {
                dev.state.lock().unwrap().crash_drop_unsynced();
            }

            let recovered_txg = assert_pool_scrub_and_allocation_clean(
                &cx,
                std::slice::from_ref(&dev),
                base_built.pool_guid,
                Some(base_built.initial_slot),
            );
            assert_eq!(recovered_txg, INITIAL_TXG);

            // Reopen fresh engine on the crashed durable bytes and commit a real TXG cleanly!
            let fresh_dev = dev.fresh_from_durable();
            let mut fresh_eng = open_engine_on_devices(
                &cx,
                std::slice::from_ref(&fresh_dev),
                default_write_opts(base_built.pool_guid, base_built.initial_slot),
            )
            .unwrap();
            let (created_id, _) = fresh_eng
                .create_file(
                    &cx,
                    &ds,
                    2,
                    b"after_crash.txt",
                    0o644,
                    0,
                    0,
                    ts,
                    ZfsDataChecksum::Fletcher4,
                )
                .into_result()
                .expect("commit after pre-Uberblock crash");
            assert!(created_id > 2);
            assert_pool_scrub_and_allocation_clean(
                &cx,
                std::slice::from_ref(&fresh_dev),
                base_built.pool_guid,
                Some(fresh_eng.committed_slot()),
            );
        }
    }

    // B. Torn 64-byte write on the VERY FIRST `UberblockWrite` (`L0` slot `(INITIAL_TXG+1)%slots`):
    // `L0` slot has corrupt checksum for `TXG 21`, `L0..L3` still have intact `TXG 20` in `initial_slot`!
    {
        let dev = FaultableMemberDevice::new(base_built.members[0].clone());
        // Count how many `write_all_at` calls occur before the first `UberblockWrite`:
        let ub_write_call_idx = recorded_events[..first_ub_pos]
            .iter()
            .filter(|e| {
                matches!(
                    e.stage,
                    ZfsPersistenceStage::ChildBlocksWrite { .. }
                        | ZfsPersistenceStage::DatasetMetadataWrite { .. }
                        | ZfsPersistenceStage::MosSpaceMapWrite { .. }
                        | ZfsPersistenceStage::MosRootWrite { .. }
                )
            })
            .count();
        dev.set_fault(DeviceFault::TornWriteOnCall {
            call_index: ub_write_call_idx,
            keep_prefix_bytes: 64,
        });
        let mut eng = open_engine_on_devices(
            &cx,
            std::slice::from_ref(&dev),
            default_write_opts(base_built.pool_guid, base_built.initial_slot),
        )
        .unwrap();
        let out = eng.create_file(
            &cx,
            &ds,
            2,
            b"torn_ub.txt",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        );
        assert!(
            matches!(out, ZfsTxOutcome::Uncertain { target_txg: 21, .. }),
            "torn L0 Uberblock write must report Uncertain"
        );
        // Handle must now be poisoned until reopened!
        assert!(matches!(
            eng.mkdir(&cx, &ds, 2, b"poisoned", 0o755, 0, 0, ts),
            ZfsTxOutcome::NotCommitted(_)
        ));
        dev.state.lock().unwrap().crash_flush_volatile();

        // `Pool::import_objects` cleanly ignores the checksum-invalid torn slot 21 and selects `INITIAL_TXG = 20`!
        let active_txg = assert_pool_scrub_and_allocation_clean(
            &cx,
            std::slice::from_ref(&dev),
            base_built.pool_guid,
            None,
        );
        assert_eq!(active_txg, INITIAL_TXG);

        // Fresh writer reopening pinned to `initial_slot` (`TXG 20`) succeeds and overwrites slot 21 cleanly!
        let fresh_dev = dev.fresh_from_durable();
        let mut fresh_eng = open_engine_on_devices(
            &cx,
            std::slice::from_ref(&fresh_dev),
            default_write_opts(base_built.pool_guid, base_built.initial_slot),
        )
        .unwrap();
        let (_, tok) = fresh_eng
            .create_file(
                &cx,
                &ds,
                2,
                b"healed_slot21.txt",
                0o644,
                0,
                0,
                ts,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .expect("overwrite torn slot 21");
        fresh_eng.verify_token(&tok).unwrap();
        assert_eq!(fresh_eng.committed_txg(), INITIAL_TXG + 1);
    }

    // C. Wave-1 (`L0..L1`) synced durably at `TXG 21`, crash cut BEFORE Wave-2 (`L2..L3`):
    {
        let dev = FaultableMemberDevice::new(base_built.members[0].clone());
        let mut eng = open_engine_on_devices(
            &cx,
            std::slice::from_ref(&dev),
            default_write_opts(base_built.pool_guid, base_built.initial_slot),
        )
        .unwrap();
        eng.with_fault_hook(|ev| {
            if matches!(
                ev.stage,
                ZfsPersistenceStage::UberblockWrite { label: 2, .. }
            ) {
                Err(FfsError::Io(std::io::Error::other(
                    "crash after Wave 1 (L0..L1 synced) before L2",
                )))
            } else {
                Ok(())
            }
        });
        let out = eng.create_file(
            &cx,
            &ds,
            2,
            b"wave1_committed.txt",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        );
        let ZfsTxOutcome::Uncertain {
            target_txg,
            target_slot,
            ..
        } = out
        else {
            panic!("expected Uncertain on Wave-2 cut");
        };
        assert_eq!(target_txg, INITIAL_TXG + 1);
        dev.state.lock().unwrap().crash_drop_unsynced();

        // `Pool::import_objects` recovers `TXG 21` cleanly!
        let active_txg = assert_pool_scrub_and_allocation_clean(
            &cx,
            std::slice::from_ref(&dev),
            base_built.pool_guid,
            None,
        );
        assert_eq!(active_txg, INITIAL_TXG + 1);

        // Default writer WITHOUT `reconcile_torn_uberblocks` MUST refuse both stale `initial_slot` AND split `target_slot`!
        let fresh_dev = dev.fresh_from_durable();
        assert!(
            open_engine_on_devices(
                &cx,
                std::slice::from_ref(&fresh_dev),
                default_write_opts(base_built.pool_guid, base_built.initial_slot),
            )
            .is_err(),
            "stale slot 20 must be refused when L0..L1 already have TXG 21"
        );
        assert!(
            open_engine_on_devices(
                &cx,
                std::slice::from_ref(&fresh_dev),
                default_write_opts(base_built.pool_guid, target_slot),
            )
            .is_err(),
            "split L0..L1 vs L2..L3 ring must be refused without reconcile_torn_uberblocks"
        );

        // Explicit `reconcile_torn_uberblocks: true` scrubs MOS, heals L2..L3, and commits `TXG 22`!
        let mut healed_eng = open_engine_on_devices(
            &cx,
            std::slice::from_ref(&fresh_dev),
            ZfsWriteOptions {
                reconcile_torn_uberblocks: true,
                ..default_write_opts(base_built.pool_guid, target_slot)
            },
        )
        .expect("reconcile split L0..L1 Uberblocks");
        assert_eq!(healed_eng.committed_txg(), INITIAL_TXG + 1);
        let _ = healed_eng
            .mkdir(&cx, &ds, 2, b"post_heal_dir", 0o755, 0, 0, ts)
            .into_result()
            .expect("commit TXG 22 after heal");
        assert_pool_scrub_and_allocation_clean(
            &cx,
            std::slice::from_ref(&fresh_dev),
            base_built.pool_guid,
            Some(healed_eng.committed_slot()),
        );
    }

    // D. 2-way mirror independent-device split-flush (member 0 syncs Wave-1 `TXG 21`, member 1 fails `UberblockBarrier`):
    {
        let m_built = build_clean_zfs_pool(&PoolFixtureSpec {
            mirror_width: 2,
            ..PoolFixtureSpec::default()
        });
        let m_devs: Vec<_> = m_built
            .members
            .into_iter()
            .map(FaultableMemberDevice::new)
            .collect();
        let pre_ub_barriers = recorded_events[..first_ub_pos]
            .iter()
            .filter(|e| {
                matches!(
                    e.stage,
                    ZfsPersistenceStage::ChildBlocksBarrier { .. }
                        | ZfsPersistenceStage::DatasetMetadataBarrier { .. }
                        | ZfsPersistenceStage::MosSpaceMapBarrier { .. }
                        | ZfsPersistenceStage::MosRootBarrier { .. }
                )
            })
            .count();
        m_devs[1].set_fault(DeviceFault::FailSyncOnCall {
            sync_index: pre_ub_barriers,
        });
        let mut m_eng = open_engine_on_devices(
            &cx,
            &m_devs,
            default_write_opts(m_built.pool_guid, m_built.initial_slot),
        )
        .unwrap();
        let out = m_eng.create_file(
            &cx,
            &ds,
            2,
            b"mirror_split.txt",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        );
        let ZfsTxOutcome::Uncertain {
            target_txg,
            target_slot,
            ..
        } = out
        else {
            panic!("mirror Uberblock sync failure must return Uncertain");
        };
        assert_eq!(target_txg, INITIAL_TXG + 1);
        for d in &m_devs {
            d.state.lock().unwrap().crash_drop_unsynced();
            d.set_fault(DeviceFault::None);
        }

        // `Pool::import_objects` recovers `TXG 21` across the 2-way mirror (both members already synced Child..MosRoot)!
        let active_txg =
            assert_pool_scrub_and_allocation_clean(&cx, &m_devs, m_built.pool_guid, None);
        assert_eq!(active_txg, INITIAL_TXG + 1);

        let fresh_m: Vec<_> = m_devs
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        // Default writer refuses disagreed mirror members; `reconcile_torn_uberblocks: true` heals all 8 labels!
        assert!(
            open_engine_on_devices(
                &cx,
                &fresh_m,
                default_write_opts(m_built.pool_guid, target_slot),
            )
            .is_err()
        );
        let mut healed_m = open_engine_on_devices(
            &cx,
            &fresh_m,
            ZfsWriteOptions {
                reconcile_torn_uberblocks: true,
                ..default_write_opts(m_built.pool_guid, target_slot)
            },
        )
        .expect("reconcile split mirror Uberblocks");
        let _ = healed_m
            .mkdir(&cx, &ds, 2, b"mirror_healed", 0o755, 0, 0, ts)
            .into_result()
            .unwrap();
        assert_pool_scrub_and_allocation_clean(
            &cx,
            &fresh_m,
            m_built.pool_guid,
            Some(healed_m.committed_slot()),
        );
    }

    // E. Post-commit pre-reply cancellation preserves the known committed result.
    // The idempotency guard still refuses a duplicate rename after a fresh reopen,
    // including when another file has reused the original source name.
    {
        let dev = FaultableMemberDevice::new(base_built.members[0].clone());
        let mut eng = open_engine_on_devices(
            &cx,
            std::slice::from_ref(&dev),
            default_write_opts(base_built.pool_guid, base_built.initial_slot),
        )
        .unwrap();
        let (orig_obj, _) = eng
            .create_file(
                &cx,
                &ds,
                2,
                b"src.txt",
                0o644,
                0,
                0,
                ts,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        let _ = eng
            .write_file_data(
                &cx,
                &ds,
                orig_obj,
                0,
                b"precious-original-payload",
                ts,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();

        eng.with_fault_hook(|ev| {
            if matches!(ev.stage, ZfsPersistenceStage::BeforeAcknowledge) {
                Err(FfsError::Cancelled)
            } else {
                Ok(())
            }
        });
        let out = eng.rename_entry(&cx, &ds, 2, b"src.txt", 2, b"dst.txt", Some(orig_obj), ts);
        let ZfsTxOutcome::Committed { value, token } = out else {
            panic!("post-durability cancellation must preserve the committed rename");
        };
        assert_eq!(value, orig_obj);
        eng.verify_token(&token).unwrap();
        let target_slot = token.published_slot();
        assert_eq!(eng.committed_slot(), target_slot);
        assert_eq!(eng.committed_txg(), token.committed_txg());

        // Reopen fresh engine at `target_slot`: `dst.txt` is already committed!
        let fresh_dev = dev.fresh_from_durable();
        let mut fresh_eng = open_engine_on_devices(
            &cx,
            std::slice::from_ref(&fresh_dev),
            default_write_opts(base_built.pool_guid, target_slot),
        )
        .unwrap();

        // Retry 1 (before `src.txt` is recreated): fails with `NotFound`, preserving `dst.txt`!
        assert!(matches!(
            fresh_eng.rename_entry(&cx, &ds, 2, b"src.txt", 2, b"dst.txt", Some(orig_obj), ts),
            ZfsTxOutcome::NotCommitted(FfsError::NotFound(_))
        ));

        // Now create a brand-new `src.txt` (`impostor_obj != orig_obj`) and retry the old rename
        // with `Some(orig_obj)`: MUST fail with `MvccConflict` instead of clobbering `dst.txt`!
        let (impostor_obj, _) = fresh_eng
            .create_file(
                &cx,
                &ds,
                2,
                b"src.txt",
                0o644,
                0,
                0,
                ts,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        assert_ne!(impostor_obj, orig_obj);
        assert!(matches!(
            fresh_eng.rename_entry(&cx, &ds, 2, b"src.txt", 2, b"dst.txt", Some(orig_obj), ts),
            ZfsTxOutcome::NotCommitted(FfsError::MvccConflict { .. })
        ));

        let mut mos = fresh_eng.open_read_objects(&cx).unwrap();
        let mut zpl = mos.zpl(&cx, &ds).unwrap();
        let dst_resolved = zpl.resolve(&cx, b"/dst.txt").unwrap();
        assert_eq!(dst_resolved, orig_obj);
        assert_eq!(
            zpl.read(&cx, dst_resolved, 0, 64).unwrap(),
            b"precious-original-payload"
        );
    }
}

#[test]
fn cancellation_after_final_barrier_preserves_token_and_live_writer_state() {
    let ts = Timestamp {
        seconds: 1_715_000_400,
        nanos: 0,
    };
    let ds = [b"data".to_vec()];
    for mirror_width in [1, 2] {
        for cancel_context in [false, true] {
            let cx = Cx::for_testing();
            let built = build_clean_zfs_pool(&PoolFixtureSpec {
                mirror_width,
                ..PoolFixtureSpec::default()
            });
            let devs: Vec<_> = built
                .members
                .into_iter()
                .map(FaultableMemberDevice::new)
                .collect();
            let mut engine = open_engine_on_devices(
                &cx,
                &devs,
                default_write_opts(built.pool_guid, built.initial_slot),
            )
            .unwrap();
            let cancelled = cx.clone();
            engine.with_fault_hook(move |event| {
                if event.stage == ZfsPersistenceStage::BeforeAcknowledge {
                    if cancel_context {
                        cancelled.cancel_with(
                            asupersync::types::CancelKind::User,
                            Some("after final ZFS publication barrier"),
                        );
                    } else {
                        return Err(FfsError::Cancelled);
                    }
                }
                Ok(())
            });
            let (created, token) = engine
                .create_file(
                    &cx,
                    &ds,
                    2,
                    b"durable.txt",
                    0o600,
                    0,
                    0,
                    ts,
                    ZfsDataChecksum::Fletcher4,
                )
                .into_result()
                .expect("all publication barriers succeeded before cancellation");
            assert_eq!(token.committed_txg(), INITIAL_TXG + 1);
            assert_eq!(engine.committed_txg(), token.committed_txg());
            assert_eq!(engine.committed_slot(), token.published_slot());
            engine.verify_token(&token).unwrap();

            // A new request can use the same owner. Its allocator and root must
            // already reflect the committed operation, with no forced reopen.
            engine.clear_fault_hook();
            let next_cx = Cx::for_testing();
            let (size, next_token) = engine
                .write_file_data(
                    &next_cx,
                    &ds,
                    created,
                    0,
                    b"survives cancellation and power loss",
                    ts,
                    ZfsDataChecksum::Fletcher4,
                )
                .into_result()
                .expect("post-cancellation writer retains its committed allocator");
            assert_eq!(size, 36);
            assert_eq!(next_token.committed_txg(), INITIAL_TXG + 2);
            engine.verify_token(&token).unwrap();
            engine.verify_token(&next_token).unwrap();

            let durable: Vec<_> = devs
                .iter()
                .map(FaultableMemberDevice::fresh_from_durable)
                .collect();
            let fresh = open_engine_on_devices(
                &next_cx,
                &durable,
                default_write_opts(built.pool_guid, next_token.published_slot()),
            )
            .unwrap();
            let mut mos = fresh.open_read_objects(&next_cx).unwrap();
            let mut zpl = mos.zpl(&next_cx, &ds).unwrap();
            assert_eq!(zpl.resolve(&next_cx, b"/durable.txt").unwrap(), created);
            assert_eq!(
                zpl.read(&next_cx, created, 0, 64).unwrap(),
                b"survives cancellation and power loss"
            );
            assert_pool_scrub_and_allocation_clean(
                &next_cx,
                &durable,
                built.pool_guid,
                Some(next_token.published_slot()),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 5. Upfront `ENOSPC` & Negative Admission Controls (0 backing writes!)
// ---------------------------------------------------------------------------

#[test]
fn enospc_and_negative_admission_controls_fail_before_writing_disk() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_715_000_400,
        nanos: 0,
    };

    // 1. Nearly-full single-metaslab pool (`DATA_OFFSET + 2 MiB + 2 * LABEL_BYTES` = `6.5 MiB`):
    // Only 4 KiB free -> 64 KiB write fails with `FfsError::NoSpace` and `0` device writes!
    let full_built = build_clean_zfs_pool(&PoolFixtureSpec {
        image_bytes: DATA_OFFSET + (1 << SLAB_SHIFT) + 2 * LABEL_BYTES,
        preallocate_nearly_full: true,
        ..PoolFixtureSpec::default()
    });
    let full_dev = FaultableMemberDevice::new(full_built.members[0].clone());
    let mut full_eng = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&full_dev),
        default_write_opts(full_built.pool_guid, full_built.initial_slot),
    )
    .expect("open nearly-full pool");
    assert_eq!(full_dev.write_calls(), 0);
    let enospc_out = full_eng.create_file(
        &cx,
        &[b"data".to_vec()],
        2,
        b"too_full_for_cow_tree.txt",
        0o644,
        0,
        0,
        ts,
        ZfsDataChecksum::Fletcher4,
    );
    assert!(
        matches!(enospc_out, ZfsTxOutcome::NotCommitted(FfsError::NoSpace)),
        "expected upfront NoSpace, got {enospc_out:?}"
    );
    assert_eq!(
        full_dev.write_calls(),
        0,
        "ENOSPC must fail strictly before issuing any backing device write"
    );
    assert_pool_scrub_and_allocation_clean(
        &cx,
        std::slice::from_ref(&full_dev),
        full_built.pool_guid,
        Some(full_built.initial_slot),
    );

    // 2. Active pool (`state == 0`), multihost label, active Uberblock MMP, and dirty ZIL all fail closed with 0 writes!
    for bad_spec in [
        PoolFixtureSpec {
            pool_state: 0, // POOL_STATE_ACTIVE
            ..PoolFixtureSpec::default()
        },
        PoolFixtureSpec {
            multihost_label: true,
            ..PoolFixtureSpec::default()
        },
        PoolFixtureSpec {
            active_mmp_uberblock: true,
            ..PoolFixtureSpec::default()
        },
        PoolFixtureSpec {
            dirty_zil: true,
            ..PoolFixtureSpec::default()
        },
    ] {
        let bad_built = build_clean_zfs_pool(&bad_spec);
        let bad_dev = FaultableMemberDevice::new(bad_built.members[0].clone());
        let res = open_engine_on_devices(
            &cx,
            std::slice::from_ref(&bad_dev),
            default_write_opts(bad_built.pool_guid, bad_built.initial_slot),
        );
        assert!(res.is_err(), "expected writer admission refusal");
        assert_eq!(bad_dev.write_calls(), 0);
    }

    // 3. Missing `offline_image` / `allow_write` & foreign `ZfsDurableToken` fail with `PermissionDenied`!
    let clean_a = build_clean_zfs_pool(&PoolFixtureSpec::default());
    let dev_a = FaultableMemberDevice::new(clean_a.members[0].clone());
    assert!(matches!(
        open_engine_on_devices(
            &cx,
            std::slice::from_ref(&dev_a),
            ZfsWriteOptions {
                allow_write: false,
                ..default_write_opts(clean_a.pool_guid, clean_a.initial_slot)
            },
        ),
        Err(FfsError::PermissionDenied)
    ));
    assert!(matches!(
        open_engine_on_devices(
            &cx,
            std::slice::from_ref(&dev_a),
            ZfsWriteOptions {
                offline_image: false,
                ..default_write_opts(clean_a.pool_guid, clean_a.initial_slot)
            },
        ),
        Err(FfsError::PermissionDenied)
    ));

    let mut eng_a = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&dev_a),
        default_write_opts(clean_a.pool_guid, clean_a.initial_slot),
    )
    .unwrap();
    let (_, tok_a) = eng_a
        .mkdir(&cx, &[b"data".to_vec()], 2, b"tok_a", 0o755, 0, 0, ts)
        .into_result()
        .unwrap();

    let clean_b = build_clean_zfs_pool(&PoolFixtureSpec {
        mirror_width: 2,
        ..PoolFixtureSpec::default()
    });
    let devs_b: Vec<_> = clean_b
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let eng_b = open_engine_on_devices(
        &cx,
        &devs_b,
        default_write_opts(clean_b.pool_guid, clean_b.initial_slot),
    )
    .unwrap();
    assert!(matches!(
        eng_b.verify_token(&tok_a),
        Err(FfsError::PermissionDenied)
    ));
}

// ---------------------------------------------------------------------------
// 6. Native OpenZFS `zdb` leak & block-checksum oracle verification
// ---------------------------------------------------------------------------

fn discover_zdb() -> Option<(PathBuf, Option<String>)> {
    if let Ok(explicit) = std::env::var("FFS_ZDB_BIN")
        && !explicit.is_empty()
    {
        let p = PathBuf::from(explicit);
        if p.is_file() {
            return Some((p, std::env::var("FFS_ZDB_LD_LIBRARY_PATH").ok()));
        }
    }
    if let Some(path_os) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_os) {
            let candidate = dir.join("zdb");
            if candidate.is_file() {
                return Some((candidate, None));
            }
        }
    }
    for candidate in ["/usr/sbin/zdb", "/sbin/zdb"] {
        let p = Path::new(candidate);
        if p.is_file() {
            return Some((p.to_path_buf(), None));
        }
    }
    None
}

fn require_oracles_enabled() -> bool {
    std::env::var("FFS_REQUIRE_ORACLES")
        .is_ok_and(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
}

fn run_zdb_check(zdb: &Path, ld_path: Option<&str>, dir: &Path, pool_name: &str, img0: &Path) {
    let mut lu_cmd = Command::new(zdb);
    lu_cmd.arg("-lu").arg(img0);
    if let Some(ld) = ld_path {
        lu_cmd.env("LD_LIBRARY_PATH", ld);
    }
    let lu_out = lu_cmd.output().expect("spawn zdb -lu");
    assert!(
        lu_out.status.success(),
        "zdb -lu failed: stdout={}\nstderr={}",
        String::from_utf8_lossy(&lu_out.stdout),
        String::from_utf8_lossy(&lu_out.stderr)
    );

    let mut bccm = Command::new(zdb);
    bccm.args(["-e", "-V", "-p"])
        .arg(dir)
        .args(["-bccm", pool_name]);
    if let Some(ld) = ld_path {
        bccm.env("LD_LIBRARY_PATH", ld);
    }
    let out = bccm.output().expect("spawn zdb -e -V -p -bccm");
    let mut combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if !out.status.success() {
        let mut dbg = Command::new(zdb);
        dbg.args(["-AAA", "-G", "-e", "-V", "-p"])
            .arg(dir)
            .args(["-bccm", pool_name]);
        if let Some(ld) = ld_path {
            dbg.env("LD_LIBRARY_PATH", ld);
        }
        if let Ok(dbg_out) = dbg.output() {
            combined.push_str("\n--- zdb -AAA -G debug log ---\n");
            combined.push_str(&String::from_utf8_lossy(&dbg_out.stdout));
            combined.push_str(&String::from_utf8_lossy(&dbg_out.stderr));
        }
    }
    assert!(
        out.status.success()
            && combined.contains("No leaks (block sum matches space maps exactly)"),
        "OpenZFS zdb -bccm rejected pool `{pool_name}` (status={:?}):\n{combined}",
        out.status.code()
    );
}

#[test]
fn native_openzfs_zdb_oracle_verifies_committed_pool_and_space_maps() {
    let Some((zdb, ld_path)) = discover_zdb() else {
        assert!(
            !require_oracles_enabled(),
            "FFS_REQUIRE_ORACLES=1 set, but `zdb` binary was not found in PATH or FFS_ZDB_BIN"
        );
        eprintln!(
            "SKIP|suite=ffs-zfs::persistence_prefix|test=native_openzfs_zdb_oracle_verifies_committed_pool_and_space_maps|reason=missing_zdb"
        );
        return;
    };

    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_715_000_500,
        nanos: 0,
    };
    let dir = tempfile::tempdir().unwrap();
    let img_path = dir.path().join("zdb_pool.img");
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        pool_name: "ffszdbpool".to_owned(),
        member_path_override: Some(img_path.to_string_lossy().into_owned()),
        image_bytes: 64 * 1024 * 1024,
        deadlist_mode: DeadlistMode::NativeDeadlist,
        user_accounting: true,
        ..PoolFixtureSpec::default()
    });
    std::fs::write(&img_path, &built.members[0]).unwrap();

    let mut eng = ZfsTransactionEngine::open_files(
        &cx,
        &[img_path.as_path()],
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    let ds = [b"data".to_vec()];
    let (sub_dir, _) = eng
        .mkdir(&cx, &ds, 2, b"zdb_dir", 0o755, 1000, 1000, ts)
        .into_result()
        .unwrap();
    let (fobj, _) = eng
        .create_file(
            &cx,
            &ds,
            sub_dir,
            b"verified.bin",
            0o644,
            1000,
            1000,
            ts,
            ZfsDataChecksum::Sha256,
        )
        .into_result()
        .unwrap();
    // Exceed 4 MiB slab 0 so `PoolSpaceAllocator` spills into untouched metaslab 1 (`ms_arr[1] == 0`),
    // lazily allocating a new `DMU_OT_SPACE_MAP` object + updating `metaslab_array` + `spacemap_histogram`!
    let payload = vec![0x42_u8; 4_200_000];
    let _ = eng
        .write_file_data(&cx, &ds, fobj, 0, &payload, ts, ZfsDataChecksum::Sha256)
        .into_result()
        .unwrap();
    // Also overwrite snapshotted `hello.txt` so OpenZFS `zdb -bccm` validates our `DMU_OT_DEADLIST` + `async_destroy`!
    let hello_obj = {
        let mut mos = eng.open_read_objects(&cx).unwrap();
        let mut zpl = mos.zpl(&cx, &ds).unwrap();
        zpl.resolve(&cx, b"/hello.txt").unwrap()
    };
    let _ = eng
        .write_file_data(
            &cx,
            &ds,
            hello_obj,
            0,
            b"zdb-verified-deadlist-cow!",
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    drop(eng);

    run_zdb_check(
        &zdb,
        ld_path.as_deref(),
        dir.path(),
        "ffszdbpool",
        &img_path,
    );
}
