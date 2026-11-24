#![forbid(unsafe_code)]
//! Native ZFS v5000 TXG lifecycle, metaslab space-map convergence, ZPL v4/v5 + snapshot
//! deadlist COW, persistence-prefix fault-cut / write-reordering / torn-Uberblock /
//! mirror-split-flush / post-commit-cancel schedules, upfront `ENOSPC`, negative
//! admission controls, and OpenZFS `zdb` leak/checksum oracle verification.

#[path = "persistence_prefix/creation_project.rs"]
mod creation_project;
#[path = "persistence_prefix/encryption.rs"]
mod encryption;
#[path = "persistence_prefix/growth.rs"]
mod growth;
#[path = "persistence_prefix/mixed_order.rs"]
mod mixed_order;
#[path = "persistence_prefix/permissions.rs"]
mod permissions;
#[path = "persistence_prefix/projects.rs"]
mod projects;
#[path = "persistence_prefix/quota_profile.rs"]
mod quota_profile;
#[path = "persistence_prefix/send_recv.rs"]
mod send_recv;
#[path = "persistence_prefix/writable_fs.rs"]
mod writable_fs;
#[path = "persistence_prefix/zvol.rs"]
mod zvol;

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
    OBJSET_PROJECTUSED_OFFSET, OBJSET_USERUSED_OFFSET, ObjectSet, ZapEntry, ZilHeader,
    encode_microzap, write_dnode_at,
};
use ffs_ondisk::zfs_zap::{Entry as RawZapEntry, encode_fatzap_with_flags};
use ffs_ondisk::zfs_zpl::{Kind, Metadata, SaRegistry, Timestamp, encode_directory_reference};
use ffs_types::ByteOffset;
use ffs_zfs::reader::dmu::allocation::AllocationLimits;
use ffs_zfs::reader::dmu::scrub::ScrubLimits;
use ffs_zfs::{
    Leaf, Pool, ZfsDataChecksum, ZfsObjectIdentity, ZfsPersistenceStage, ZfsTopologyKind,
    ZfsTransactionEngine, ZfsTxOutcome, ZfsUnlinkedObject, ZfsWriteOptions,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuxiliaryOwnership {
    XattrDirectory,
    CapabilityXattr,
    EmbeddedAcl,
    ExternalAcl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XattrOwnershipFault {
    DirectoryRootAlias,
    ValueRootAlias,
    DirectoryParent,
    DirectoryPublic,
    DirectoryLinks,
    DirectorySize,
    DirectoryNested,
    ValueParent,
    ValuePublic,
    ValueLinks,
    ValueAlias,
    DuplicateValue,
    DotName,
    ValueNested,
    ValueExternalAcl,
    OversizedValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SaSpillFixture {
    None,
    Opaque,
    Mtime,
    Project(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZilTailFixture {
    None,
    UnwrittenTail,
    UnclaimedVerifiedRecord,
}

#[derive(Debug, Clone)]
struct PoolFixtureSpec {
    pool_name: String,
    member_path_override: Option<String>,
    image_bytes: u64,
    ashift: u8,
    mirror_width: usize,
    zpl_version: u64,
    zpl_order: Option<Endian>,
    zpl_contents_order: Option<Endian>,
    extra_zpl_leaf_order: Option<Endian>,
    zvol_orders: Option<(Endian, Endian)>,
    with_sa_spill: bool,
    with_sa_spill_timestamps: bool,
    user_accounting: bool,
    project_accounting: bool,
    sa_project_id: Option<u64>,
    malformed_project_id: bool,
    directory_projects: BTreeMap<u64, u64>,
    owner_quota_objects: Vec<(&'static [u8], u64)>,
    owner_quota_entries: BTreeMap<u64, Vec<(&'static [u8], u64)>>,
    owner_usage_overrides: Vec<(usize, &'static [u8], Option<u64>)>,
    deadlist_mode: DeadlistMode,
    preallocate_nearly_full: bool,
    pool_state: u64,
    multihost_label: bool,
    active_mmp_uberblock: bool,
    dirty_zil: bool,
    zil_tail: ZilTailFixture,
    additional_read_features: Vec<(&'static [u8], u64)>,
    additional_write_features: Vec<(&'static [u8], u64)>,
    zpl_flags: BTreeMap<u64, u64>,
    hello_size: Option<u64>,
    hello_mode: u16,
    hello_compress_type: u8,
    lz4_feature: Option<u64>,
    hello_sa_xattrs: BTreeMap<String, Vec<u8>>,
    hello_sa_xattrs_in_spill: bool,
    root_ids: (u64, u64),
    hello_ownership: Option<ffs_ondisk::zfs_zpl::ReclamationOwnership>,
    root_properties: Vec<(&'static [u8], u64)>,
    data_properties: Vec<(&'static [u8], u64)>,
    data_head_features: Vec<(&'static [u8], u64)>,
    data_objectset_checksum: Option<u8>,
    auxiliary_ownership: Option<(u64, AuxiliaryOwnership)>,
    auxiliary_xattr_fault: Option<XattrOwnershipFault>,
    auxiliary_xattr_owner_ids: Option<(u64, u64)>,
    auxiliary_capability_with_retained_value: bool,
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
            zpl_order: None,
            zpl_contents_order: None,
            extra_zpl_leaf_order: None,
            zvol_orders: None,
            with_sa_spill: false,
            with_sa_spill_timestamps: false,
            user_accounting: false,
            project_accounting: false,
            sa_project_id: None,
            malformed_project_id: false,
            directory_projects: BTreeMap::new(),
            owner_quota_objects: Vec::new(),
            owner_quota_entries: BTreeMap::new(),
            owner_usage_overrides: Vec::new(),
            deadlist_mode: DeadlistMode::None,
            preallocate_nearly_full: false,
            pool_state: 1,
            multihost_label: false,
            active_mmp_uberblock: false,
            dirty_zil: false,
            zil_tail: ZilTailFixture::None,
            additional_read_features: Vec::new(),
            additional_write_features: Vec::new(),
            zpl_flags: BTreeMap::new(),
            hello_size: None,
            hello_mode: 0o644,
            hello_compress_type: 0,
            lz4_feature: Some(1),
            hello_sa_xattrs: BTreeMap::new(),
            hello_sa_xattrs_in_spill: false,
            root_ids: (0, 0),
            hello_ownership: None,
            root_properties: Vec::new(),
            data_properties: Vec::new(),
            data_head_features: Vec::new(),
            data_objectset_checksum: None,
            auxiliary_ownership: None,
            auxiliary_xattr_fault: None,
            auxiliary_xattr_owner_ids: None,
            auxiliary_capability_with_retained_value: false,
        }
    }
}

impl PoolFixtureSpec {
    fn spill_profile(&self) -> SaSpillFixture {
        self.sa_project_id.map_or(
            if self.with_sa_spill_timestamps {
                SaSpillFixture::Mtime
            } else if self.with_sa_spill {
                SaSpillFixture::Opaque
            } else {
                SaSpillFixture::None
            },
            SaSpillFixture::Project,
        )
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

// Independent XDR byte-array encoding, rather than the production SA writer,
// so capability-removal tests start from externally representable attributes.
fn fixture_sa_xattrs(values: &BTreeMap<String, Vec<u8>>) -> Vec<u8> {
    let pairs: Vec<_> = values
        .iter()
        .map(|(name, value)| {
            let mut padded = value.clone();
            padded.resize(padded.len().next_multiple_of(4), 0);
            nv_pair(
                name,
                10,
                u32::try_from(value.len()).unwrap(),
                &padded,
                value.len(),
            )
        })
        .collect();
    pack_xdr_nvlist(&pairs)
}

fn fixture_sa_xattr_header(layout: u16, length: usize, order: Endian) -> Vec<u8> {
    let mut header = vec![0_u8; 8];
    let layout = (1_u16 << 10) | layout;
    let length = u16::try_from(length).unwrap();
    match order {
        Endian::Little => {
            header[..4].copy_from_slice(&[0x5a, 0x50, 0x2f, 0]);
            header[4..6].copy_from_slice(&layout.to_le_bytes());
            header[6..8].copy_from_slice(&length.to_le_bytes());
        }
        Endian::Big => {
            header[..4].copy_from_slice(&[0, 0x2f, 0x50, 0x5a]);
            header[4..6].copy_from_slice(&layout.to_be_bytes());
            header[6..8].copy_from_slice(&length.to_be_bytes());
        }
    }
    header
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
    malformed_project_id: bool,
    with_reclamation_ownership: bool,
    with_sa_xattrs: bool,
) -> (SaRegistry, Dnode, Dnode, Dnode) {
    // Attribute IDs matching OpenZFS `SaRegistry::LEGACY` (0..16) + custom attr 18:
    // 0: ATIME(16,0), 1: MTIME(16,0), 2: CTIME(16,0), 3: CRTIME(16,0), 4: GEN(8,0),
    // 5: MODE(8,0), 6: SIZE(8,0), 7: PARENT(8,0), 8: LINKS(8,0), 10: RDEV(8,0),
    // 11: FLAGS(8,0), 12: UID(8,0), 13: GID(8,0), 18: ZPL_SCANSTAMP(32,2)
    let mut reg_entries = vec![
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
        RawZapEntry {
            name: b"ZPL_PROJID".to_vec(),
            integer_bytes: 8,
            values: vec![((if malformed_project_id { 0x10_u64 } else { 0x08 }) << 24) | 0x13],
            collision: 0,
        },
    ];
    // Layout 2: standard file/dir layout; Layout 3: spill layout `[18]`
    let mut lay_entries = vec![
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
        RawZapEntry {
            name: b"4".to_vec(),
            integer_bytes: 2,
            values: vec![9],
            collision: 0,
        },
        RawZapEntry {
            name: b"5".to_vec(),
            integer_bytes: 2,
            values: vec![15],
            collision: 0,
        },
        RawZapEntry {
            name: b"6".to_vec(),
            integer_bytes: 2,
            values: vec![5, 6, 4, 12, 13, 7, 11, 0, 2, 3, 8],
            collision: 0,
        },
        RawZapEntry {
            name: b"7".to_vec(),
            integer_bytes: 2,
            values: vec![1, 18],
            collision: 0,
        },
        RawZapEntry {
            name: b"8".to_vec(),
            integer_bytes: 2,
            values: vec![1, 18, 19],
            collision: 0,
        },
    ];
    if with_reclamation_ownership {
        for (name, id, length, swap) in [
            (b"ZPL_XATTR".as_slice(), 9_u64, 8_u64, 0_u64),
            (b"ZPL_ZNODE_ACL".as_slice(), 15, 88, 3),
        ] {
            reg_entries.push(RawZapEntry {
                name: name.to_vec(),
                integer_bytes: 8,
                values: vec![(length << 24) | (swap << 16) | id],
                collision: 0,
            });
        }
        lay_entries.push(RawZapEntry {
            name: b"9".to_vec(),
            integer_bytes: 2,
            values: vec![9, 15, 19],
            collision: 0,
        });
    }
    if with_sa_xattrs {
        reg_entries.push(RawZapEntry {
            name: b"ZPL_DXATTR".to_vec(),
            integer_bytes: 8,
            values: vec![(3_u64 << 16) | 20],
            collision: 0,
        });
        for (layout, values) in [
            (
                b"10".as_slice(),
                vec![5, 6, 4, 12, 13, 7, 11, 0, 1, 2, 3, 8, 20],
            ),
            (b"11", vec![20]),
            (b"12", vec![9, 20]),
        ] {
            lay_entries.push(RawZapEntry {
                name: layout.to_vec(),
                integer_bytes: 2,
                values,
                collision: 0,
            });
        }
    }
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
    spill_profile: SaSpillFixture,
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
        let mut bonus = reg
            .encode_new_from_template(&tmpl, meta)
            .expect("encode SA metadata");
        let spill = if spill_profile == SaSpillFixture::None {
            None
        } else {
            // Valid SA header `[magic(4), (header_bytes=8 => 1<<10 | layout=3), 32B attr 18]`
            let with_mtime = matches!(
                spill_profile,
                SaSpillFixture::Mtime | SaSpillFixture::Project(_)
            );
            let mut sraw = vec![
                0_u8;
                if matches!(spill_profile, SaSpillFixture::Project(_)) {
                    8192
                } else {
                    512
                }
            ];
            let layout = match spill_profile {
                SaSpillFixture::Project(_) => 8,
                SaSpillFixture::Mtime => 7,
                _ => 3,
            };
            let hdr_word: u16 = (1_u16 << 10) | layout;
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
            if with_mtime {
                sraw[8..24].copy_from_slice(&bonus[80..96]);
                sraw[24..56].fill(0xAB);
                let mut split_bonus = bonus[..80].to_vec();
                split_bonus.extend_from_slice(&bonus[96..]);
                let split_header = (1_u16 << 10) | 6;
                split_bonus[4..6].copy_from_slice(&match order {
                    Endian::Little => split_header.to_le_bytes(),
                    Endian::Big => split_header.to_be_bytes(),
                });
                bonus = split_bonus;
            } else {
                sraw[8..40].fill(0xAB);
            }
            if let SaSpillFixture::Project(project_id) = spill_profile {
                sraw[56..64].copy_from_slice(&order.encode(project_id));
                // Real LZJB: literal header/attributes followed by a zero run.
                // Pad this valid foreign compressed record so native metadata
                // recompression has a nonzero physical accounting delta at both
                // 512-byte and 4-KiB allocation sectors. Decoding stops at lsize;
                // the trailing physical padding is not logical attribute data.
                let mut compressed = Vec::new();
                for literals in sraw[..72].as_chunks::<8>().0 {
                    compressed.push(0);
                    compressed.extend_from_slice(literals);
                }
                assert!(sraw[72..].iter().all(|byte| *byte == 0));
                let mut produced = 72;
                while produced < sraw.len() {
                    let mut map = 0_u8;
                    let mut group = Vec::new();
                    for bit in 0..8 {
                        let remaining = sraw.len() - produced;
                        if remaining == 0 {
                            break;
                        }
                        if remaining >= 3 {
                            let take = remaining.min(66);
                            map |= 1 << bit;
                            group.extend_from_slice(&[u8::try_from(take - 3).unwrap() << 2, 1]);
                            produced += take;
                        } else {
                            group.push(0);
                            produced += 1;
                        }
                    }
                    compressed.push(map);
                    compressed.extend_from_slice(&group);
                }
                assert!(compressed.len() < 512);
                compressed.resize(4608, 0);
                assert_eq!(
                    ffs_ondisk::zfs::decompress(&compressed, 3, sraw.len()).unwrap(),
                    sraw
                );
                Some(arena.alloc_raw_compressed(&sraw, &compressed, 44, 0, 3, 7, birth, order))
            } else {
                Some(arena.alloc_block(&sraw, 44, 0, birth, order))
            }
        };
        (44, bonus, spill)
    }
}

#[allow(clippy::too_many_lines)]
fn build_zpl_objectset(
    arena: &mut RawArena,
    spec: &PoolFixtureSpec,
    head_object: u64,
    populate_snapshot_files: bool,
    birth: u64,
    order: Endian,
) -> (BlockPointer, u64, Vec<u8>) {
    if head_object == 18
        && let Some((objectset_order, contents_order)) = spec.zvol_orders
    {
        return mixed_order::build_zvol_objectset(arena, birth, objectset_order, contents_order);
    }
    let objectset_order = spec.zpl_order.unwrap_or(order);
    let order = spec.zpl_contents_order.unwrap_or(objectset_order);
    let mut table = vec![0_u8; DNODE_BLOCK_BYTES];
    let acct_flags = if spec.user_accounting || spec.project_accounting {
        DNODE_FLAG_USERUSED_ACCOUNTED | DNODE_FLAG_USEROBJUSED_ACCOUNTED
    } else {
        0
    };

    let (sa_reg, sa_objs) = if spec.zpl_version == 5 {
        let (r, m_dn, r_dn, l_dn) = build_sa_registry_objects(
            arena,
            birth,
            order,
            spec.malformed_project_id,
            spec.hello_ownership.is_some(),
            !spec.hello_sa_xattrs.is_empty(),
        );
        (Some(r), Some((m_dn, r_dn, l_dn)))
    } else {
        (None, None)
    };

    let mut master_pairs: Vec<(&[u8], u64)> = vec![
        (b"VERSION", spec.zpl_version),
        (
            b"ROOT",
            match spec.auxiliary_xattr_fault {
                Some(XattrOwnershipFault::DirectoryRootAlias) if populate_snapshot_files => 13,
                Some(XattrOwnershipFault::ValueRootAlias) if populate_snapshot_files => 14,
                _ => 2,
            },
        ),
        (b"DELETE_QUEUE", 3),
    ];
    if spec.zpl_version == 5 {
        master_pairs.push((b"SA_ATTRS", 8));
    }
    for &(key, object) in &spec.owner_quota_objects {
        master_pairs.push((key, object));
        if object == 0 {
            continue;
        }
        // OpenZFS DMU_OT_USERGROUP_QUOTA is 40. Real limit ZAPs distinguish
        // unsupported quota admission from a corrupt dangling master pointer.
        let slot = usize::try_from(object).unwrap();
        assert!(slot >= 11 && spec.auxiliary_ownership.is_none());
        assert!(
            ffs_ondisk::zfs_dmu::dnode_at(&table, slot, order)
                .unwrap()
                .is_none()
        );
        let default_quota_entries = [(b"0".as_slice(), 1), (b"2a", 1), (b"3e8", 1)];
        let quota_entries = spec
            .owner_quota_entries
            .get(&object)
            .map_or(default_quota_entries.as_slice(), Vec::as_slice);
        let quota_raw = mzap(quota_entries, 0x5151, order);
        let quota_bp = arena.alloc_block(&quota_raw, 40, 0, birth, order);
        let quota_dn = make_dnode(
            40,
            quota_bp.logical_bytes(),
            vec![quota_bp],
            0,
            Vec::new(),
            None,
            0,
            order,
        );
        write_dnode_at(&mut table, slot, &quota_dn).expect("write owner quota dn");
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
            mode: (Kind::Regular.to_tag() << 12) | u64::from(spec.hello_mode),
            size: spec.hello_size.unwrap_or(snap_hello_bytes.len() as u64),
            links: 1,
            parent: 2,
            uid: 1000,
            gid: 1000,
            flags: 0x408
                | spec.zpl_flags.get(&4).copied().unwrap_or(0)
                | if spec.sa_project_id.is_some() {
                    0x0000_8000_0000_0000
                } else {
                    0
                },
            generation: birth,
            times: [ts; 4],
            inline_symlink: None,
        };
        let (bt, mut bbytes, mut spill) = encode_zpl_bonus_for_fixture(
            &hello_meta,
            spec.zpl_version,
            sa_reg.as_ref(),
            if spec.hello_ownership.is_some() {
                SaSpillFixture::None
            } else {
                spec.spill_profile()
            },
            arena,
            birth,
            order,
        );
        if let Some(ownership) = spec.hello_ownership {
            if spec.zpl_version == 4 {
                assert_eq!(ownership.project_id, 0, "legacy znodes have no project ID");
                bbytes[104..112].copy_from_slice(&order.encode(ownership.xattr_directory));
                bbytes[176..184].copy_from_slice(&order.encode(ownership.external_acl_object));
            } else {
                // Independent native layout 9: XATTR(8), ZNODE_ACL(88), PROJID(8).
                // Keep ownership in a real SA spill, outside the core bonus.
                let mut raw = vec![0_u8; 512];
                let header = (1_u16 << 10) | 9;
                match order {
                    Endian::Little => {
                        raw[..4].copy_from_slice(&[0x5a, 0x50, 0x2f, 0]);
                        raw[4..6].copy_from_slice(&header.to_le_bytes());
                    }
                    Endian::Big => {
                        raw[..4].copy_from_slice(&[0, 0x2f, 0x50, 0x5a]);
                        raw[4..6].copy_from_slice(&header.to_be_bytes());
                    }
                }
                for (offset, value) in [
                    (8, ownership.xattr_directory),
                    (16, ownership.external_acl_object),
                    (104, ownership.project_id),
                ] {
                    raw[offset..offset + 8].copy_from_slice(&order.encode(value));
                }
                spill = Some(arena.alloc_block(&raw, 44, 0, birth, order));
            }
        }
        if !spec.hello_sa_xattrs.is_empty()
            && !spec
                .auxiliary_ownership
                .is_some_and(|(object, _)| object == 4)
        {
            assert_eq!(spec.zpl_version, 5);
            assert!(spill.is_none());
            let packed = fixture_sa_xattrs(&spec.hello_sa_xattrs);
            if spec.hello_sa_xattrs_in_spill {
                let mut raw = fixture_sa_xattr_header(11, packed.len(), order);
                raw.extend_from_slice(&packed);
                raw.resize(
                    raw.len()
                        .next_power_of_two()
                        .max(1_usize << spec.ashift)
                        .max(512),
                    0,
                );
                spill = Some(arena.alloc_block(&raw, 44, 0, birth, order));
            } else {
                bbytes[..8].copy_from_slice(&fixture_sa_xattr_header(10, packed.len(), order));
                bbytes.extend_from_slice(&packed);
            }
        }
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
        // Native dn_compress is byte 6; model an imported per-object override
        // independently of the dataset's inherited compression property.
        table[4 * DNODE_BYTES + 6] = spec.hello_compress_type;
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
            SaSpillFixture::None,
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
            flags: 0x408
                | spec.zpl_flags.get(&6).copied().unwrap_or(0)
                | if spec.directory_projects.contains_key(&6) {
                    0x0000_8000_0000_0000
                } else {
                    0
                },
            generation: birth,
            times: [ts; 4],
            inline_symlink: None,
        };
        let (sub_bonus_type, sub_bonus_bytes, sub_spill) = encode_zpl_bonus_for_fixture(
            &sub_meta,
            spec.zpl_version,
            sa_reg.as_ref(),
            spec.directory_projects
                .get(&6)
                .copied()
                .map_or(SaSpillFixture::None, SaSpillFixture::Project),
            arena,
            birth,
            order,
        );
        let sub_dn = make_dnode(
            20,
            sub_bp.logical_bytes(),
            vec![sub_bp],
            sub_bonus_type,
            sub_bonus_bytes,
            sub_spill,
            acct_flags,
            order,
        );
        write_dnode_at(&mut table, 6, &sub_dn).expect("write sub dn");
        root_entries.push((
            b"sub",
            encode_directory_reference(6, Kind::Directory).unwrap(),
        ));
        subdir_count += 1;
    } else if spec.with_sa_spill || spec.with_sa_spill_timestamps || spec.sa_project_id.is_some() {
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
            flags: 0x408
                | spec.zpl_flags.get(&4).copied().unwrap_or(0)
                | if spec.sa_project_id.is_some() {
                    0x0000_8000_0000_0000
                } else {
                    0
                },
            generation: birth,
            times: [ts; 4],
            inline_symlink: None,
        };
        let (bt, bbytes, spill) = encode_zpl_bonus_for_fixture(
            &sp_meta,
            spec.zpl_version,
            sa_reg.as_ref(),
            spec.spill_profile(),
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

    if populate_snapshot_files && let Some((owner, auxiliary)) = spec.auxiliary_ownership {
        // Native ownership edges live in the bonus/SA, independently of the
        // owner's data block pointers. Seed real allocated private objects so
        // final-link tests can distinguish preservation from a leaked object.
        let owner_index = usize::try_from(owner).unwrap();
        let owner_node = Dnode::parse(
            &table[owner_index * DNODE_BYTES..(owner_index + 1) * DNODE_BYTES],
            order,
        )
        .unwrap();
        assert!(owner_node.spill().is_none());
        let metadata = if spec.zpl_version == 4 {
            Metadata::legacy(owner_node.bonus(), order).unwrap()
        } else {
            sa_reg
                .as_ref()
                .unwrap()
                .decode(owner_node.bonus(), None)
                .unwrap()
                .metadata()
                .unwrap()
        };
        let (attribute, layout, payload) = match auxiliary {
            AuxiliaryOwnership::XattrDirectory | AuxiliaryOwnership::CapabilityXattr => {
                let fault = spec.auxiliary_xattr_fault;
                let value = b"private value survives namespace changes";
                let mut padded = value.to_vec();
                padded.resize((1_usize << spec.ashift).max(512), 0);
                let value_bp = arena.alloc_block(&padded, 19, 0, birth, order);
                let mut value_meta = Metadata {
                    mode: (Kind::Regular.to_tag() << 12) | 0o600,
                    kind: Kind::Regular,
                    size: value.len() as u64,
                    parent: 13,
                    links: 1,
                    flags: 1,
                    inline_symlink: None,
                    ..metadata
                };
                if let Some((uid, gid)) = spec.auxiliary_xattr_owner_ids {
                    value_meta.uid = uid;
                    value_meta.gid = gid;
                }
                match fault {
                    Some(XattrOwnershipFault::ValueParent) => value_meta.parent = owner,
                    Some(XattrOwnershipFault::ValuePublic) => value_meta.flags = 0,
                    Some(XattrOwnershipFault::ValueLinks) => value_meta.links = 2,
                    Some(XattrOwnershipFault::OversizedValue) => value_meta.size = 65_537,
                    _ => {}
                }
                let mut value_bonus = value_meta.encode_legacy(None, order).unwrap();
                if fault == Some(XattrOwnershipFault::ValueNested) {
                    value_bonus[104..112].copy_from_slice(&order.encode(13));
                }
                if fault == Some(XattrOwnershipFault::ValueExternalAcl) {
                    value_bonus[176..184].copy_from_slice(&order.encode(13));
                }
                let value_node = make_dnode(
                    19,
                    padded.len(),
                    vec![value_bp],
                    17,
                    value_bonus,
                    None,
                    acct_flags,
                    order,
                );
                write_dnode_at(&mut table, 14, &value_node).unwrap();
                let name: &[u8] = if fault == Some(XattrOwnershipFault::DotName) {
                    b"."
                } else if auxiliary == AuxiliaryOwnership::CapabilityXattr {
                    b"security.capability"
                } else {
                    b"user.retained"
                };
                let value_object = if fault == Some(XattrOwnershipFault::ValueAlias) {
                    owner
                } else {
                    14
                };
                let value_reference =
                    encode_directory_reference(value_object, Kind::Regular).unwrap();
                let mut pairs = vec![(name, value_reference)];
                if fault == Some(XattrOwnershipFault::DuplicateValue) {
                    pairs.push((b"user.aliased", value_reference));
                }
                if spec.auxiliary_capability_with_retained_value {
                    assert_eq!(auxiliary, AuxiliaryOwnership::CapabilityXattr);
                    let retained_bp = arena.alloc_block(&padded, 19, 0, birth, order);
                    let retained = make_dnode(
                        19,
                        padded.len(),
                        vec![retained_bp],
                        17,
                        value_meta.encode_legacy(None, order).unwrap(),
                        None,
                        acct_flags,
                        order,
                    );
                    write_dnode_at(&mut table, 15, &retained).unwrap();
                    pairs.push((
                        b"user.retained",
                        encode_directory_reference(15, Kind::Regular).unwrap(),
                    ));
                }
                let entries = mzap(&pairs, 0xA113, order);
                let directory_bp = arena.alloc_block(&entries, 20, 0, birth, order);
                let mut directory_meta = Metadata {
                    mode: (Kind::Directory.to_tag() << 12) | 0o700,
                    kind: Kind::Directory,
                    size: pairs.len() as u64 + 2,
                    parent: owner,
                    links: 2,
                    flags: 1,
                    inline_symlink: None,
                    ..metadata
                };
                match fault {
                    Some(XattrOwnershipFault::DirectoryParent) => {
                        directory_meta.parent = owner + 1;
                    }
                    Some(XattrOwnershipFault::DirectoryPublic) => directory_meta.flags = 0,
                    Some(XattrOwnershipFault::DirectoryLinks) => directory_meta.links = 3,
                    Some(XattrOwnershipFault::DirectorySize) => directory_meta.size += 1,
                    _ => {}
                }
                let mut directory_bonus = directory_meta.encode_legacy(None, order).unwrap();
                if fault == Some(XattrOwnershipFault::DirectoryNested) {
                    directory_bonus[104..112].copy_from_slice(&order.encode(14));
                }
                let directory_node = make_dnode(
                    20,
                    entries.len(),
                    vec![directory_bp],
                    17,
                    directory_bonus,
                    None,
                    acct_flags,
                    order,
                );
                write_dnode_at(&mut table, 13, &directory_node).unwrap();
                (104, 4, order.encode(13).to_vec())
            }
            AuxiliaryOwnership::EmbeddedAcl => {
                let mut acl = vec![0_u8; 88];
                acl[8..12].copy_from_slice(&24_u32.to_le_bytes());
                acl[12..14].copy_from_slice(&1_u16.to_le_bytes());
                acl[14..16].copy_from_slice(&3_u16.to_le_bytes());
                for (index, (flags, rights)) in [
                    (0x1000_u16, 1_u32),
                    (0x2040_u16, 3_u32),
                    (0x4000_u16, 7_u32),
                ]
                .into_iter()
                .enumerate()
                {
                    let start = 16 + index * 8;
                    acl[start + 2..start + 4].copy_from_slice(&flags.to_le_bytes());
                    acl[start + 4..start + 8].copy_from_slice(&rights.to_le_bytes());
                }
                (176, 5, acl)
            }
            AuxiliaryOwnership::ExternalAcl => {
                // OpenZFS zfs-2.3.0 zfs_acl_phys_t: external object, byte
                // length, version, ACE count, then 72 inline bytes. Twelve
                // compact FUID ACEs exceed that inline capacity.
                let mut acl_data = vec![0_u8; (1_usize << spec.ashift).max(512)];
                for ace in acl_data[..96].as_chunks_mut::<8>().0 {
                    ace[2..4].copy_from_slice(&0x1000_u16.to_le_bytes());
                    ace[4..8].copy_from_slice(&1_u32.to_le_bytes());
                }
                let acl_bp = arena.alloc_block(&acl_data, 33, 0, birth, order);
                let acl_node = make_dnode(
                    33,
                    acl_data.len(),
                    vec![acl_bp],
                    0,
                    Vec::new(),
                    None,
                    0,
                    order,
                );
                write_dnode_at(&mut table, 13, &acl_node).unwrap();
                let mut acl = vec![0_u8; 88];
                acl[..8].copy_from_slice(&order.encode(13));
                acl[8..12].copy_from_slice(&96_u32.to_le_bytes());
                acl[12..14].copy_from_slice(&1_u16.to_le_bytes());
                acl[14..16].copy_from_slice(&12_u16.to_le_bytes());
                (176, 5, acl)
            }
        };
        let mut bonus = owner_node.bonus().to_vec();
        let spill = if owner == 4 && !spec.hello_sa_xattrs.is_empty() {
            assert_eq!(spec.zpl_version, 5);
            assert!(matches!(
                auxiliary,
                AuxiliaryOwnership::XattrDirectory | AuxiliaryOwnership::CapabilityXattr
            ));
            let packed = fixture_sa_xattrs(&spec.hello_sa_xattrs);
            let mut raw = fixture_sa_xattr_header(12, packed.len(), order);
            raw.extend_from_slice(&payload);
            raw.extend_from_slice(&packed);
            raw.resize(
                raw.len()
                    .next_power_of_two()
                    .max(1_usize << spec.ashift)
                    .max(512),
                0,
            );
            Some(arena.alloc_block(&raw, 44, 0, birth, order))
        } else if spec.zpl_version == 4 {
            bonus[attribute..attribute + payload.len()].copy_from_slice(&payload);
            None
        } else {
            let mut raw = vec![0_u8; (1_usize << spec.ashift).max(512)];
            raw[..4].copy_from_slice(&[0x5a, 0x50, 0x2f, 0]);
            raw[4..6].copy_from_slice(&((1_u16 << 10) | layout).to_le_bytes());
            raw[8..8 + payload.len()].copy_from_slice(&payload);
            Some(arena.alloc_block(&raw, 44, 0, birth, order))
        };
        let owner_node = make_dnode(
            owner_node.object_type(),
            owner_node.data_bytes(),
            owner_node.pointers().to_vec(),
            owner_node.bonus_type(),
            bonus,
            spill,
            acct_flags,
            order,
        );
        write_dnode_at(&mut table, owner_index, &owner_node).unwrap();
    }

    let extra_table = spec
        .extra_zpl_leaf_order
        .filter(|_| populate_snapshot_files)
        .map(|leaf_order| {
            assert_eq!(spec.zpl_version, 5);
            assert!(!spec.user_accounting && !spec.project_accounting);
            let mut extra = vec![0_u8; DNODE_BLOCK_BYTES];
            for (slot, name, fill) in [
                (0, b"foreign.bin".as_slice(), 0x71),
                (1, b"neighbor.bin", 0x72),
            ] {
                let data = vec![fill; 512];
                let pointer = arena.alloc_block(&data, 19, 0, birth, leaf_order);
                let meta = Metadata {
                    kind: Kind::Regular,
                    mode: (Kind::Regular.to_tag() << 12) | 0o644,
                    size: 512,
                    links: 1,
                    parent: 2,
                    uid: 1000,
                    gid: 1000,
                    flags: 0x408,
                    generation: birth,
                    times: [ts; 4],
                    inline_symlink: None,
                };
                let (bonus_type, mut bonus, spill) = encode_zpl_bonus_for_fixture(
                    &meta,
                    5,
                    sa_reg.as_ref(),
                    SaSpillFixture::None,
                    arena,
                    birth,
                    leaf_order,
                );
                assert!(bonus.len() <= 256 && spill.is_none());
                bonus.resize(256, 0);
                let node = make_dnode(
                    19,
                    512,
                    vec![pointer],
                    bonus_type,
                    bonus,
                    None,
                    0,
                    leaf_order,
                );
                write_dnode_at(&mut extra, slot, &node).unwrap();
                root_entries.push((
                    name,
                    encode_directory_reference(32 + slot as u64, Kind::Regular).unwrap(),
                ));
            }
            (extra, leaf_order)
        });

    let root_raw = mzap(&root_entries, 0x88, order);
    let root_bp = arena.alloc_block(&root_raw, 20, 0, birth, order);
    let root_meta = Metadata {
        kind: Kind::Directory,
        mode: (Kind::Directory.to_tag() << 12) | 0o755,
        size: 2 + (root_entries.len() as u64),
        links: 2 + subdir_count,
        parent: 2,
        uid: spec.root_ids.0,
        gid: spec.root_ids.1,
        flags: 0x408
            | spec.zpl_flags.get(&2).copied().unwrap_or(0)
            | if spec.directory_projects.contains_key(&2) {
                0x0000_8000_0000_0000
            } else {
                0
            },
        generation: birth,
        times: [ts; 4],
        inline_symlink: None,
    };
    let (rbt, rbbytes, rspill) = encode_zpl_bonus_for_fixture(
        &root_meta,
        spec.zpl_version,
        sa_reg.as_ref(),
        spec.directory_projects
            .get(&2)
            .copied()
            .map_or(SaSpillFixture::None, SaSpillFixture::Project),
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
        rspill,
        acct_flags,
        order,
    );
    write_dnode_at(&mut table, 2, &root_dn).expect("write root dn");

    let mut table_pointers = vec![arena.alloc_block(&table, DMU_OT_DNODE, 0, birth, order)];
    if let Some((extra, leaf_order)) = extra_table {
        table_pointers.push(arena.alloc_block(&extra, DMU_OT_DNODE, 0, birth, leaf_order));
    }
    let meta_dn = make_dnode(
        DMU_OT_DNODE,
        DNODE_BLOCK_BYTES,
        table_pointers,
        0,
        Vec::new(),
        None,
        0,
        objectset_order,
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
    } else if head_object == 18 && spec.zil_tail != ZilTailFixture::None {
        let chain_identity = [0x1111_u64, 0x2222_u64, head_object, 1_u64];
        let mut zil_block = vec![0_u8; 4096];
        if spec.zil_tail == ZilTailFixture::UnclaimedVerifiedRecord {
            // Valid ZILOG2 chain header (184B at offset 0) + one 32B record at offset 184.
            // Next block pointer (`zil_block[8..136]`) is a hole whose checksum words carry seq=2.
            let next_identity = [0x1111_u64, 0x2222_u64, head_object, 2_u64];
            for (idx, val) in next_identity.into_iter().enumerate() {
                zil_block[8 + 96 + idx * 8..8 + 104 + idx * 8].copy_from_slice(&order.encode(val));
            }
            zil_block[136..144].copy_from_slice(&order.encode(216_u64)); // zc_nused = 184 + 32
            zil_block[144..152].copy_from_slice(&order.encode(0x0210_da7a_b10c_7a11_u64)); // ECK_MAGIC
            for (idx, val) in chain_identity.into_iter().enumerate() {
                zil_block[152 + idx * 8..160 + idx * 8].copy_from_slice(&order.encode(val));
            }
            // Minimal valid 32B `lr_t`: kind=1, length=32, txg=birth+1 (pending!), seq=1.
            zil_block[184..192].copy_from_slice(&order.encode(1_u64));
            zil_block[192..200].copy_from_slice(&order.encode(32_u64));
            zil_block[200..208].copy_from_slice(&order.encode(birth + 1));
            zil_block[208..216].copy_from_slice(&order.encode(1_u64));
            let cksum = ffs_ondisk::zfs::checksum(&zil_block, 7, order).expect("zilog2 fletcher4");
            for (idx, val) in cksum.into_iter().enumerate() {
                zil_block[152 + idx * 8..160 + idx * 8].copy_from_slice(&order.encode(val));
            }
        }
        let allocated_bp = arena.alloc_block(&zil_block, 9, 0, birth, order);
        let dva = allocated_bp.regular_dvas().expect("regular zil dva")[0];
        let mut raw_bp = [0_u8; 128];
        raw_bp[0..8].copy_from_slice(&order.encode(dva.allocated_bytes / 512));
        raw_bp[8..16].copy_from_slice(&order.encode(dva.offset / 512));
        let prop = 0x07_u64
            | (0x07_u64 << 16)
            | (0x02_u64 << 32)
            | (0x09_u64 << 40)
            | (0x09_u64 << 48)
            | (u64::from(order == Endian::Little) << 63);
        raw_bp[48..56].copy_from_slice(&order.encode(prop));
        raw_bp[80..88].copy_from_slice(&order.encode(birth));
        for (idx, val) in chain_identity.into_iter().enumerate() {
            raw_bp[96 + idx * 8..104 + idx * 8].copy_from_slice(&order.encode(val));
        }
        let zil_bp = BlockPointer::parse(&raw_bp, order).expect("parse zilog2 bp");
        ZilHeader {
            claim_txg: 0,
            replay_seq: 0,
            log: zil_bp,
            claim_blk_seq: 0,
            flags: 0,
            claim_lr_seq: 0,
        }
    } else {
        ZilHeader::empty()
    };

    let os_bytes = if spec.user_accounting || spec.project_accounting {
        4096
    } else {
        1024_usize.max(1_usize << spec.ashift)
    };
    let os_flags = if spec.project_accounting {
        0x07
    } else if spec.user_accounting {
        0x03
    } else {
        0
    };
    let mut os_obj = ObjectSet::new(2, os_flags, meta_dn, zil_header, os_bytes).expect("zpl os");
    if spec.user_accounting || spec.project_accounting {
        let mut counters: NativeAccountingCounters = std::array::from_fn(|_| BTreeMap::new());
        for (object, raw) in table.as_chunks::<DNODE_BYTES>().0.iter().enumerate() {
            if !matches!(raw[0], 19 | 20) {
                continue;
            }
            let node = Dnode::parse(raw, order).unwrap();
            let (metadata, project) = if node.bonus_type() == 17 {
                (Metadata::legacy(node.bonus(), order).unwrap(), 0)
            } else {
                let spill = node.spill().map(|pointer| {
                    let dva = pointer.regular_dvas().unwrap()[0];
                    ffs_ondisk::zfs::decompress(
                        &arena.blocks[&dva.offset][..pointer.physical_bytes()],
                        pointer.compression(),
                        pointer.logical_bytes(),
                    )
                    .unwrap()
                });
                let attributes = sa_reg
                    .as_ref()
                    .unwrap()
                    .decode(node.bonus(), spill.as_deref())
                    .unwrap();
                // A deliberately malformed scalar still has a known intended
                // owner in the refusal fixture; no mutation may consume it.
                let project = if object == 4 && spec.malformed_project_id {
                    spec.sa_project_id.unwrap_or(0)
                } else {
                    attributes.project_id().unwrap()
                };
                (attributes.metadata().unwrap(), project)
            };
            for (map, owner) in counters
                .iter_mut()
                .zip([metadata.uid, metadata.gid, project])
            {
                // OpenZFS charges the 512-byte native dnode in addition to
                // dn_used for every accounted object, including empty files.
                *map.entry(format!("{owner:x}").into_bytes()).or_default() +=
                    node.used_bytes() + 512;
                *map.entry(format!("obj-{owner:x}").into_bytes())
                    .or_default() += 1;
            }
        }
        for &(dimension, key, value) in &spec.owner_usage_overrides {
            if let Some(value) = value {
                counters[dimension].insert(key.to_vec(), value);
            } else {
                counters[dimension].remove(key);
            }
        }
        for (index, (offset, salt)) in [
            (OBJSET_USERUSED_OFFSET, 0x99),
            (OBJSET_GROUPUSED_OFFSET, 0xAA),
            (OBJSET_PROJECTUSED_OFFSET, 0xBB),
        ]
        .into_iter()
        .enumerate()
        {
            if index == 2 && !spec.project_accounting {
                continue;
            }
            let entries: Vec<_> = counters[index]
                .iter()
                .map(|(key, value)| (key.as_slice(), *value))
                .collect();
            let raw = mzap(&entries, salt, order);
            let pointer = arena.alloc_block(&raw, 39, 0, birth, order);
            let node = make_dnode(
                39,
                pointer.logical_bytes(),
                vec![pointer],
                0,
                Vec::new(),
                None,
                0,
                objectset_order,
            );
            os_obj
                .set_embedded_dnode(offset, Some(&node))
                .expect("accounting dnode");
        }
    }
    let mut encoded_os = os_obj.encode(objectset_order).expect("encode zpl os");
    let os_bp = if head_object == 18
        && let Some(checksum) = spec.data_objectset_checksum
    {
        let min_block = usize::try_from(arena.sector).unwrap().max(512);
        encoded_os.resize(encoded_os.len().max(min_block).next_multiple_of(512), 0);
        arena.alloc_raw_compressed(
            &encoded_os,
            &encoded_os,
            DMU_OT_OBJSET,
            0,
            2,
            checksum,
            birth,
            objectset_order,
        )
    } else {
        arena.alloc_block(&encoded_os, DMU_OT_OBJSET, 0, birth, objectset_order)
    };
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
        build_zpl_objectset(&mut arena, spec, 3, false, INITIAL_TXG - 1, order);

    let data_birth = if spec.deadlist_mode == DeadlistMode::None {
        INITIAL_TXG - 1
    } else {
        SNAP_TXG
    };
    let (data_os_bp, data_ref_bytes, snap_hello_expected) = build_zpl_objectset(
        &mut arena,
        spec,
        18,
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
    let data_head = if spec.data_head_features.is_empty() {
        make_dnode(16, 512, Vec::new(), 16, data_ds_bonus, None, 0, order)
    } else {
        let raw = mzap(&spec.data_head_features, 0x112, order);
        let pointer = arena.alloc_block(&raw, 196, 0, INITIAL_TXG, order);
        make_dnode(
            196,
            pointer.logical_bytes(),
            vec![pointer],
            16,
            data_ds_bonus,
            None,
            0,
            order,
        )
    };
    set_mos(&mut mos_tables, 18, &data_head);

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
    let mut rf_entries: Vec<(&[u8], u64)> = vec![
        (b"com.delphix:hole_birth", 1),
        (
            b"com.delphix:extensible_dataset",
            u64::from(!spec.data_head_features.is_empty()),
        ),
    ];
    if let Some(count) = spec.lz4_feature {
        rf_entries.push((b"org.illumos:lz4_compress", count));
    }
    for &(name, count) in &spec.additional_read_features {
        rf_entries.push((name, count));
    }
    let rf_raw = mzap(&rf_entries, 0x108, order);
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
    let mut write_features: Vec<(&[u8], u64)> = vec![
        (b"com.delphix:async_destroy", 0),
        (b"com.delphix:empty_bpobj", empty_bpobj_refcount),
        (b"com.delphix:enabled_txg", 1),
        (
            b"com.delphix:spacemap_histogram",
            initial_allocated_spacemaps,
        ),
        (b"com.delphix:spacemap_v2", 1),
    ];
    write_features.extend_from_slice(&spec.additional_write_features);
    let wf_raw = mzap(&write_features, 0x109, order);
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
    protection_depth: usize,
    protection_completed: usize,
    protection_aborted: usize,
    unprotected_io: usize,
    refuse_protection: bool,
}

impl MemberMediaState {
    fn new(initial: Vec<u8>) -> Self {
        Self {
            durable: initial,
            volatile: Vec::new(),
            write_calls: 0,
            sync_calls: 0,
            fault: DeviceFault::None,
            protection_depth: 0,
            protection_completed: 0,
            protection_aborted: 0,
            unprotected_io: 0,
            refuse_protection: false,
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
        if st.protection_depth == 0 {
            st.unprotected_io += 1;
        }
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
        if st.protection_depth == 0 {
            st.unprotected_io += 1;
        }
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

    fn begin_durability_commit(&self, cx: &Cx) -> Result<()> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let mut state = self.state.lock().unwrap();
        if state.refuse_protection {
            return Err(FfsError::ReadOnly);
        }
        state.protection_depth += 1;
        Ok(())
    }

    fn complete_durability_commit(&self) {
        let mut state = self.state.lock().unwrap();
        state.protection_depth -= 1;
        state.protection_completed += 1;
    }

    fn abort_durability_commit(&self) {
        let mut state = self.state.lock().unwrap();
        state.protection_depth -= 1;
        state.protection_aborted += 1;
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
    assert_eq!(
        io_after, io_before,
        "admission failure performed backing I/O"
    );
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
        (
            "received-off",
            vec![(READONLY, 1)],
            vec![(RECEIVED, 0)],
            true,
        ),
        (
            "inherit-suppresses-received-off",
            vec![(READONLY, 1)],
            vec![(RECEIVED, 0), (INHERIT, 1)],
            false,
        ),
        (
            "received-on",
            vec![(READONLY, 0)],
            vec![(RECEIVED, 1)],
            false,
        ),
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
                assert_readonly_mutations_refused(&cx, &mut engine, &devices, &dataset, timestamp);
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
    for (flag, errno) in [(1_u64 << 36, libc::EPERM), (1_u64 << 46, libc::EOPNOTSUPP)] {
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
        writer.truncate_file(&cx, &dataset, 5, 0, timestamp, ZfsDataChecksum::Fletcher4)
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

type NativeAccountingCounters = [BTreeMap<Vec<u8>, u64>; 3];

fn native_accounting_snapshot(
    cx: &Cx,
    engine: &ZfsTransactionEngine,
    device: &FaultableMemberDevice,
) -> (Option<Dnode>, NativeAccountingCounters) {
    let mut mos = engine.open_read_objects(cx).unwrap();
    let head = mos.object(cx, 18).unwrap();
    let root = BlockPointer::parse(&head.bonus()[128..256], head.order()).unwrap();
    let image = device.durable_snapshot();
    let read = |pointer: &BlockPointer| {
        let dva = pointer.regular_dvas().unwrap()[0];
        let start = usize::try_from(DATA_OFFSET + dva.offset).unwrap();
        ffs_ondisk::zfs::decompress(
            &image[start..start + pointer.physical_bytes()],
            pointer.compression(),
            pointer.logical_bytes(),
        )
        .unwrap()
    };
    let objectset = ObjectSet::parse(&read(&root), root.payload_order()).unwrap();
    assert_eq!(objectset.meta.levels(), 1);
    let table_pointer = &objectset.meta.pointers()[0];
    let node =
        ffs_ondisk::zfs_dmu::dnode_at(&read(table_pointer), 4, table_pointer.payload_order())
            .unwrap();
    let counters = std::array::from_fn(|index| {
        let offset = [
            OBJSET_USERUSED_OFFSET,
            OBJSET_GROUPUSED_OFFSET,
            OBJSET_PROJECTUSED_OFFSET,
        ][index];
        let node = objectset
            .embedded_dnode(offset, root.payload_order())
            .unwrap()
            .unwrap();
        assert_eq!(node.levels(), 1);
        let pointer = &node.pointers()[0];
        ffs_ondisk::zfs_dmu::microzap(&read(pointer), pointer.payload_order())
            .unwrap()
            .into_iter()
            .map(|entry| (entry.name, entry.value))
            .collect()
    });
    (node, counters)
}

#[test]
#[allow(clippy::too_many_lines)]
fn project_owner_receives_spill_recompression_truncate_and_final_unlink_accounting() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_715_000_500,
        nanos: 123,
    };
    for (ashift, mirror_width) in [(9, 1), (12, 2)] {
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            ashift,
            mirror_width,
            image_bytes: 24 * 1024 * 1024,
            deadlist_mode: DeadlistMode::NativeDeadlist,
            project_accounting: true,
            sa_project_id: Some(42),
            additional_write_features: vec![(b"org.zfsonlinux:project_quota", 1)],
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
        let (original_node, original_counters) =
            native_accounting_snapshot(&cx, &engine, &devices[0]);
        let original_node = original_node.unwrap();
        let old_spill = original_node.spill().unwrap();
        assert_eq!(
            (old_spill.compression(), old_spill.logical_bytes()),
            (3, 8192)
        );
        let expected_spill_bytes = 1_u64 << ashift;
        let expected_reclaim = bp_allocated_bytes(old_spill) - expected_spill_bytes;
        assert!(
            expected_reclaim > 0,
            "fixture must exercise a physical accounting delta"
        );

        engine
            .set_attributes(
                &cx,
                &dataset,
                4,
                &ffs_zfs::ZfsSetAttr {
                    mtime: Some(timestamp),
                    ..ffs_zfs::ZfsSetAttr::default()
                },
                timestamp,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        let (updated_node, updated_counters) =
            native_accounting_snapshot(&cx, &engine, &devices[0]);
        let updated_node = updated_node.unwrap();
        let new_spill = updated_node.spill().unwrap();
        assert_eq!(new_spill.compression(), 15);
        assert_eq!(new_spill.logical_bytes(), 8192);
        assert_eq!(bp_allocated_bytes(new_spill), expected_spill_bytes);
        assert_eq!(
            updated_node.pointers(),
            original_node.pointers(),
            "timestamps must retain the exact data tree"
        );
        assert_eq!(
            updated_node.used_bytes(),
            original_node.used_bytes() - expected_reclaim
        );
        for (index, owner) in [b"3e8".as_slice(), b"3e8".as_slice(), b"2a".as_slice()]
            .into_iter()
            .enumerate()
        {
            assert_eq!(
                updated_counters[index][owner],
                original_counters[index][owner] - expected_reclaim
            );
            let mut expected = original_counters[index].clone();
            *expected.get_mut(owner).unwrap() -= expected_reclaim;
            assert_eq!(
                updated_counters[index], expected,
                "only the native accounting owner's bytes may change"
            );
        }
        assert_eq!(
            updated_counters[2][b"0".as_slice()],
            original_counters[2][b"0".as_slice()]
        );

        engine
            .truncate_file(&cx, &dataset, 4, 0, timestamp, ZfsDataChecksum::Fletcher4)
            .into_result()
            .unwrap();
        let (truncated_node, truncated_counters) =
            native_accounting_snapshot(&cx, &engine, &devices[0]);
        let truncated_node = truncated_node.unwrap();
        assert_eq!(truncated_node.used_bytes(), expected_spill_bytes);
        assert_eq!(
            truncated_counters[2][b"2a".as_slice()],
            expected_spill_bytes + 512
        );
        assert_eq!(truncated_counters[2][b"obj-2a".as_slice()], 1);
        assert_eq!(
            truncated_counters[2][b"0".as_slice()],
            original_counters[2][b"0".as_slice()]
        );

        let (_, token) = engine
            .unlink_entry(&cx, &dataset, 2, b"hello.txt", false, timestamp)
            .into_result()
            .unwrap();
        let (removed, final_counters) = native_accounting_snapshot(&cx, &engine, &devices[0]);
        assert!(removed.is_none());
        assert!(!final_counters[2].contains_key(b"2a".as_slice()));
        assert!(!final_counters[2].contains_key(b"obj-2a".as_slice()));
        assert_eq!(
            final_counters[2][b"0".as_slice()],
            original_counters[2][b"0".as_slice()]
        );
        drop(engine);
        for device in &devices {
            device.state.lock().unwrap().crash_drop_unsynced();
        }
        assert_pool_scrub_and_allocation_clean(
            &cx,
            &devices,
            built.pool_guid,
            Some(token.published_slot()),
        );
        let fresh: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let reopened = open_engine_on_devices(
            &cx,
            &fresh,
            default_write_opts(built.pool_guid, token.published_slot()),
        )
        .unwrap();
        let (_, persisted_counters) = native_accounting_snapshot(&cx, &reopened, &fresh[0]);
        assert_eq!(persisted_counters, final_counters);
        let mut mos = reopened.open_read_objects(&cx).unwrap();
        let mut zpl = mos.zpl(&cx, &dataset).unwrap();
        let mut snapshot = zpl.open_snapshot(&cx, b"before").unwrap();
        let historical = snapshot.resolve(&cx, b"/hello.txt").unwrap();
        assert_eq!(
            snapshot
                .read(&cx, historical, 0, built.snap_hello_expected.len())
                .unwrap(),
            built.snap_hello_expected
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn project_owner_survives_unlink_replacement_restart_and_orphan_reclamation() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_715_000_600,
        nanos: 321,
    };
    for (ashift, mirror_width, replace) in
        [(9, 1, false), (9, 1, true), (12, 2, false), (12, 2, true)]
    {
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            ashift,
            mirror_width,
            image_bytes: 24 * 1024 * 1024,
            deadlist_mode: DeadlistMode::NativeDeadlist,
            project_accounting: true,
            sa_project_id: Some(42),
            additional_write_features: vec![(b"org.zfsonlinux:project_quota", 1)],
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
        let (original_node, original_counters) =
            native_accounting_snapshot(&cx, &engine, &devices[0]);
        let original_node = original_node.unwrap();
        let old_spill = original_node.spill().unwrap();
        assert_eq!(
            (old_spill.compression(), old_spill.logical_bytes()),
            (3, 8192)
        );
        let expected_spill_bytes = 1_u64 << ashift;
        assert!(bp_allocated_bytes(old_spill) > expected_spill_bytes);
        let identity = {
            let mut mos = engine.open_read_objects(&cx).unwrap();
            let mut zpl = mos.zpl(&cx, &dataset).unwrap();
            ZfsUnlinkedObject {
                object: 4,
                generation: zpl.stat(&cx, 4).unwrap().0.generation,
            }
        };
        let outcome = if replace {
            engine.rename_retaining_open_target(
                &cx,
                &dataset,
                2,
                b"keep.bin",
                2,
                b"hello.txt",
                Some(5),
                identity,
                timestamp,
            )
        } else {
            engine.unlink_open_file(&cx, &dataset, 2, b"hello.txt", identity, timestamp)
        };
        let (_, retained_token) = outcome.into_result().unwrap();
        assert_eq!(engine.pending_unlinks(&cx, &dataset).unwrap(), [identity]);
        let (retained_node, retained_counters) =
            native_accounting_snapshot(&cx, &engine, &devices[0]);
        // Unlink/replacement updates only `links` and `ctime` (both in `bonus`), so
        // `encode_updated_zpl_bonus` preserves the existing compressed spill block
        // intact (`used_bytes` unchanged) until `truncate_file` below updates `mtime`
        // inside the spill block and credits recompression to project `42` (`"2a"`).
        assert_eq!(
            retained_node.unwrap().used_bytes(),
            original_node.used_bytes()
        );
        assert_eq!(
            retained_counters, original_counters,
            "retention without spill-attribute edits must preserve existing compressed spill and owner charges"
        );
        drop(engine);
        for device in &devices {
            device.state.lock().unwrap().crash_drop_unsynced();
        }
        let fresh: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let mut reopened = open_engine_on_devices(
            &cx,
            &fresh,
            default_write_opts(built.pool_guid, retained_token.published_slot()),
        )
        .unwrap();
        assert_eq!(reopened.pending_unlinks(&cx, &dataset).unwrap(), [identity]);
        let (_, persisted_counters) = native_accounting_snapshot(&cx, &reopened, &fresh[0]);
        assert_eq!(persisted_counters, retained_counters);
        {
            let mut mos = reopened.open_read_objects(&cx).unwrap();
            let mut zpl = mos.zpl(&cx, &dataset).unwrap();
            assert_eq!(zpl.stat(&cx, 4).unwrap().0.links, 0);
            assert_eq!(
                zpl.read(&cx, 4, 0, built.snap_hello_expected.len())
                    .unwrap(),
                built.snap_hello_expected
            );
            if replace {
                assert_eq!(zpl.resolve(&cx, b"/hello.txt").unwrap(), 5);
                assert!(matches!(
                    zpl.resolve(&cx, b"/keep.bin"),
                    Err(FfsError::NotFound(_))
                ));
            } else {
                assert!(matches!(
                    zpl.resolve(&cx, b"/hello.txt"),
                    Err(FfsError::NotFound(_))
                ));
                assert_eq!(zpl.resolve(&cx, b"/keep.bin").unwrap(), 5);
            }
        }

        reopened
            .truncate_file(&cx, &dataset, 4, 0, timestamp, ZfsDataChecksum::Fletcher4)
            .into_result()
            .unwrap();
        let (truncated_node, truncated_counters) =
            native_accounting_snapshot(&cx, &reopened, &fresh[0]);
        let truncated_node = truncated_node.unwrap();
        assert_eq!(truncated_node.spill().unwrap().compression(), 15);
        assert_eq!(truncated_node.used_bytes(), expected_spill_bytes);
        assert_eq!(
            truncated_counters[2][b"2a".as_slice()],
            expected_spill_bytes + 512
        );
        assert_eq!(truncated_counters[2][b"obj-2a".as_slice()], 1);
        assert_eq!(
            truncated_counters[2][b"0".as_slice()],
            original_counters[2][b"0".as_slice()]
        );
        assert_eq!(reopened.pending_unlinks(&cx, &dataset).unwrap(), [identity]);

        let (_, reaped_token) = reopened
            .reap_unlinked_file(&cx, &dataset, identity)
            .into_result()
            .unwrap();
        assert_eq!(
            reopened.pending_unlinks(&cx, &dataset).unwrap(),
            [] as [ZfsUnlinkedObject; 0]
        );
        let (removed, final_counters) = native_accounting_snapshot(&cx, &reopened, &fresh[0]);
        assert!(removed.is_none());
        for (index, (owner, object_key)) in [
            (b"3e8".as_slice(), b"obj-3e8".as_slice()),
            (b"3e8".as_slice(), b"obj-3e8".as_slice()),
            (b"2a".as_slice(), b"obj-2a".as_slice()),
        ]
        .into_iter()
        .enumerate()
        {
            let mut expected = truncated_counters[index].clone();
            for (key, decrement) in [(owner, truncated_node.used_bytes() + 512), (object_key, 1)] {
                let remaining = expected[key].checked_sub(decrement).unwrap();
                if remaining == 0 {
                    expected.remove(key);
                } else {
                    *expected.get_mut(key).unwrap() = remaining;
                }
            }
            assert_eq!(
                final_counters[index], expected,
                "reaping must debit the actual owner exactly once"
            );
        }
        assert!(!final_counters[2].contains_key(b"2a".as_slice()));
        assert!(!final_counters[2].contains_key(b"obj-2a".as_slice()));
        drop(reopened);
        for device in &fresh {
            device.state.lock().unwrap().crash_drop_unsynced();
        }
        let durable: Vec<_> = fresh
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let final_engine = open_engine_on_devices(
            &cx,
            &durable,
            default_write_opts(built.pool_guid, reaped_token.published_slot()),
        )
        .unwrap();
        let (removed, persisted_counters) =
            native_accounting_snapshot(&cx, &final_engine, &durable[0]);
        assert!(removed.is_none());
        assert_eq!(persisted_counters, final_counters);
        assert_eq!(
            final_engine.pending_unlinks(&cx, &dataset).unwrap(),
            [] as [ZfsUnlinkedObject; 0]
        );
        let mut mos = final_engine.open_read_objects(&cx).unwrap();
        let mut zpl = mos.zpl(&cx, &dataset).unwrap();
        let mut snapshot = zpl.open_snapshot(&cx, b"before").unwrap();
        assert_eq!(
            snapshot
                .read(&cx, 4, 0, built.snap_hello_expected.len())
                .unwrap(),
            built.snap_hello_expected
        );
        assert_pool_scrub_and_allocation_clean(
            &cx,
            &durable,
            built.pool_guid,
            Some(reaped_token.published_slot()),
        );
    }
}

#[test]
fn malformed_project_owner_refuses_compound_setattr_before_any_backing_write() {
    let cx = Cx::for_testing();
    for spec in [
        PoolFixtureSpec {
            project_accounting: true,
            sa_project_id: Some(42),
            malformed_project_id: true,
            deadlist_mode: DeadlistMode::NativeDeadlist,
            additional_write_features: vec![(b"org.zfsonlinux:project_quota", 1)],
            ..PoolFixtureSpec::default()
        },
        PoolFixtureSpec {
            zpl_version: 4,
            project_accounting: true,
            zpl_flags: BTreeMap::from([(4, 0x0000_8000_0000_0000)]),
            deadlist_mode: DeadlistMode::NativeDeadlist,
            additional_write_features: vec![(b"org.zfsonlinux:project_quota", 1)],
            ..PoolFixtureSpec::default()
        },
    ] {
        let built = build_clean_zfs_pool(&spec);
        let devices: Vec<_> = built
            .members
            .into_iter()
            .map(FaultableMemberDevice::new)
            .collect();
        let before: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::durable_snapshot)
            .collect();
        let mut engine = open_engine_on_devices(
            &cx,
            &devices,
            default_write_opts(built.pool_guid, built.initial_slot),
        )
        .unwrap();
        let timestamp = Timestamp {
            seconds: 1_715_000_500,
            nanos: 123,
        };
        assert_native_write_refused(&mut engine, &devices, libc::EIO, |engine| {
            engine.set_attributes(
                &cx,
                &[b"data".to_vec()],
                4,
                &ffs_zfs::ZfsSetAttr {
                    size: Some(0),
                    mtime: Some(timestamp),
                    ..ffs_zfs::ZfsSetAttr::default()
                },
                timestamp,
                ZfsDataChecksum::Fletcher4,
            )
        });
        for (device, expected) in devices.iter().zip(before) {
            assert_eq!(device.durable_snapshot(), expected);
            assert!(device.state.lock().unwrap().volatile.is_empty());
        }
    }
}

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

fn native_zpl_file_dnode(
    cx: &Cx,
    engine: &ZfsTransactionEngine,
    device: &FaultableMemberDevice,
    dataset: &[Vec<u8>],
    object: u64,
) -> Dnode {
    let mut mos = engine.open_read_objects(cx).unwrap();
    let dataset = mos
        .datasets(cx)
        .unwrap()
        .into_iter()
        .find(|row| row.components == dataset)
        .unwrap();
    let head = mos.object(cx, dataset.head_object).unwrap();
    let root = BlockPointer::parse(&head.bonus()[128..256], head.order()).unwrap();
    let image = device.durable_snapshot();
    let read = |pointer: &BlockPointer| {
        let dva = pointer.regular_dvas().unwrap()[0];
        let start = usize::try_from(DATA_OFFSET + dva.offset).unwrap();
        ffs_ondisk::zfs::decompress(
            &image[start..start + pointer.physical_bytes()],
            pointer.compression(),
            pointer.logical_bytes(),
        )
        .unwrap()
    };
    let objectset = ObjectSet::parse(&read(&root), root.payload_order()).unwrap();
    assert_eq!(objectset.meta.levels(), 1);
    let slot = usize::try_from(object).unwrap();
    let slots_per_block = DNODE_BLOCK_BYTES / DNODE_BYTES;
    let table_pointer = &objectset.meta.pointers()[slot / slots_per_block];
    ffs_ondisk::zfs_dmu::dnode_at(
        &read(table_pointer),
        slot % slots_per_block,
        table_pointer.payload_order(),
    )
    .unwrap()
    .unwrap()
}

fn native_plain_leaf_pointers(device: &FaultableMemberDevice, node: &Dnode) -> Vec<BlockPointer> {
    let image = device.durable_snapshot();
    let mut pending: Vec<_> = node.pointers().iter().rev().cloned().collect();
    let mut leaves = Vec::new();
    while let Some(pointer) = pending.pop() {
        if pointer.hole() {
            continue;
        }
        if pointer.level() == 0 {
            leaves.push(pointer);
            continue;
        }
        let dva = pointer.regular_dvas().unwrap()[0];
        let start = usize::try_from(DATA_OFFSET + dva.offset).unwrap();
        let raw = ffs_ondisk::zfs::decompress(
            &image[start..start + pointer.physical_bytes()],
            pointer.compression(),
            pointer.logical_bytes(),
        )
        .unwrap();
        pending.extend(raw.chunks_exact(128).rev().map(|bytes| {
            let child = BlockPointer::parse(bytes, pointer.payload_order()).unwrap();
            assert!(child.hole() || child.level() + 1 == pointer.level());
            child
        }));
    }
    leaves
}

#[test]
#[allow(clippy::too_many_lines)]
fn native_plain_compression_resolves_properties_and_preserves_object_overrides() {
    const COMP: &[u8] = b"compression";
    const RECEIVED: &[u8] = b"compression$recvd";
    const INHERIT: &[u8] = b"compression$inherit";
    let cases = [
        ("default-off", vec![], vec![], 0, 2, Some(1)),
        ("inherited-lz4", vec![(COMP, 15)], vec![], 0, 15, Some(1)),
        ("received-gzip", vec![], vec![(RECEIVED, 6)], 0, 6, Some(1)),
        (
            "explicit-inherit",
            vec![(COMP, 14)],
            vec![(RECEIVED, 15), (INHERIT, 1)],
            0,
            14,
            Some(1),
        ),
        (
            "local-gzip",
            vec![(COMP, 15)],
            vec![(COMP, 13)],
            0,
            13,
            Some(1),
        ),
        ("on-lz4", vec![], vec![(COMP, 1)], 0, 15, Some(1)),
        ("on-lzjb", vec![], vec![(COMP, 1)], 0, 3, None),
        ("explicit-lzjb", vec![], vec![(COMP, 3)], 0, 3, Some(1)),
        ("object-off", vec![], vec![(COMP, 15)], 2, 2, Some(1)),
        ("object-gzip", vec![], vec![(COMP, 15)], 5, 5, Some(1)),
        ("object-on", vec![], vec![(COMP, 2)], 1, 15, Some(1)),
        ("object-lz4", vec![], vec![(COMP, 2)], 15, 15, Some(1)),
        ("object-empty", vec![], vec![(COMP, 15)], 4, 2, Some(1)),
        (
            "object-zstd-no-level",
            vec![],
            vec![(COMP, 2)],
            16,
            2,
            Some(1),
        ),
        (
            "object-zstd-default-level",
            vec![],
            vec![(COMP, 6)],
            16,
            16,
            Some(1),
        ),
    ];
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_715_000_807,
        nanos: 0,
    };
    let mut compressible = vec![0; 4096];
    for index in (0..compressible.len()).step_by(256) {
        compressible[index] = 0xA7;
    }
    // A deterministic high-entropy block exercises the physical-size fallback,
    // independently of the encoder's choice of compression algorithm.
    let mut state = 0xA26D_7C91_u32;
    let incompressible: Vec<_> = (0..4096)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state.to_le_bytes()[0]
        })
        .collect();
    for zpl_version in [4, 5] {
        for (case, root_properties, data_properties, selector, expected, lz4_feature) in &cases {
            let mut data_properties = data_properties.clone();
            data_properties.push((b"recordsize", 4096));
            let built = build_clean_zfs_pool(&PoolFixtureSpec {
                zpl_version,
                deadlist_mode: DeadlistMode::NativeDeadlist,
                root_properties: root_properties.clone(),
                data_properties,
                hello_compress_type: *selector,
                lz4_feature: *lz4_feature,
                additional_read_features: if *selector == 16 {
                    vec![(b"org.freebsd:zstd_compress", 0)]
                } else {
                    Vec::new()
                },
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
            engine
                .write_file_data(
                    &cx,
                    &dataset,
                    4,
                    0,
                    &compressible,
                    timestamp,
                    ZfsDataChecksum::Inherit,
                )
                .into_result()
                .unwrap_or_else(|error| panic!("{case}: {error}"));
            let node = native_zpl_file_dnode(&cx, &engine, &devices[0], &dataset, 4);
            assert_eq!(node.compress_type(), *selector, "{case}");
            let leaves = native_plain_leaf_pointers(&devices[0], &node);
            assert_eq!(leaves.len(), 1, "{case}");
            assert_eq!(leaves[0].compression(), *expected, "{case}");
            assert_eq!(leaves[0].logical_bytes(), 4096, "{case}");
            if *expected == 2 {
                assert_eq!(leaves[0].physical_bytes(), 4096, "{case}");
            } else {
                assert!(leaves[0].physical_bytes() < 4096, "{case}");
            }
            let mut mos = engine.open_read_objects(&cx).unwrap();
            assert_eq!(
                mos.zpl(&cx, &dataset)
                    .unwrap()
                    .read(&cx, 4, 0, 4096)
                    .unwrap(),
                compressible,
                "{case}"
            );
            let head = mos.object(&cx, 18).unwrap();
            let root = BlockPointer::parse(&head.bonus()[128..256], head.order()).unwrap();
            let expected_metadata = if *lz4_feature == Some(1) { 15 } else { 3 };
            assert_eq!(
                root.compression(),
                expected_metadata,
                "ObjectSet metadata {case}"
            );
            let image = devices[0].durable_snapshot();
            let root_offset =
                usize::try_from(DATA_OFFSET + root.regular_dvas().unwrap()[0].offset).unwrap();
            let raw = ffs_ondisk::zfs::decompress(
                &image[root_offset..root_offset + root.physical_bytes()],
                root.compression(),
                root.logical_bytes(),
            )
            .unwrap();
            let objectset = ObjectSet::parse(&raw, root.payload_order()).unwrap();
            for pointer in objectset
                .meta
                .pointers()
                .iter()
                .filter(|pointer| !pointer.hole())
            {
                assert_eq!(
                    pointer.compression(),
                    expected_metadata,
                    "DNODE metadata {case}"
                );
            }

            // Time-only COW and namespace edits must not reset imported policy.
            engine
                .set_attributes(
                    &cx,
                    &dataset,
                    4,
                    &ffs_zfs::ZfsSetAttr {
                        atime: Some(timestamp),
                        ..ffs_zfs::ZfsSetAttr::default()
                    },
                    timestamp,
                    ZfsDataChecksum::Inherit,
                )
                .into_result()
                .unwrap();
            engine
                .rename_entry(
                    &cx,
                    &dataset,
                    2,
                    b"hello.txt",
                    2,
                    b"renamed",
                    Some(4),
                    timestamp,
                )
                .into_result()
                .unwrap();
            let metadata_node = native_zpl_file_dnode(&cx, &engine, &devices[0], &dataset, 4);
            assert_eq!(metadata_node.compress_type(), *selector, "{case}");
            assert_eq!(metadata_node.pointers(), node.pointers(), "{case}");

            engine
                .write_file_data(
                    &cx,
                    &dataset,
                    4,
                    0,
                    &incompressible,
                    timestamp,
                    ZfsDataChecksum::Inherit,
                )
                .into_result()
                .unwrap();
            let slot = engine.committed_slot();
            drop(engine);
            let durable: Vec<_> = devices
                .iter()
                .map(FaultableMemberDevice::fresh_from_durable)
                .collect();
            let reopened =
                open_engine_on_devices(&cx, &durable, default_write_opts(built.pool_guid, slot))
                    .unwrap();
            let node = native_zpl_file_dnode(&cx, &reopened, &durable[0], &dataset, 4);
            assert_eq!(node.compress_type(), *selector, "{case}");
            let leaves = native_plain_leaf_pointers(&durable[0], &node);
            assert_eq!(leaves.len(), 1, "{case}");
            assert_eq!(leaves[0].compression(), 2, "incompressible {case}");
            assert_eq!(leaves[0].physical_bytes(), 4096, "incompressible {case}");
            let mut mos = reopened.open_read_objects(&cx).unwrap();
            let mut view = mos.zpl(&cx, &dataset).unwrap();
            assert_eq!(view.resolve(&cx, b"/renamed").unwrap(), 4);
            assert_eq!(
                view.read(&cx, 4, 0, 4096).unwrap(),
                incompressible,
                "{case}"
            );
            assert_eq!(
                mos.zpl_snapshot(&cx, &dataset, b"before")
                    .unwrap()
                    .read(&cx, 4, 0, 4096)
                    .unwrap(),
                built.snap_hello_expected,
                "snapshot {case}"
            );
            assert_pool_scrub_and_allocation_clean(&cx, &durable, built.pool_guid, Some(slot));
        }
    }
}

#[test]
fn native_compression_refuses_unavailable_or_invalid_policy_before_writes() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_715_000_808,
        nanos: 0,
    };
    for (property, selector, lz4_feature) in [
        (15, 0, None),
        (15, 0, Some(0)),
        (2, 15, None),
        (16, 0, Some(1)),
        (2, 255, Some(1)),
    ] {
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            deadlist_mode: DeadlistMode::NativeDeadlist,
            data_properties: vec![(b"compression", property)],
            hello_compress_type: selector,
            lz4_feature,
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
        assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
            writer.write_file_data(
                &cx,
                &dataset,
                4,
                0,
                &[0xA9; 4096],
                timestamp,
                ZfsDataChecksum::Inherit,
            )
        });
    }
}

#[test]
fn native_zero_records_become_holes_except_with_explicit_compression_off() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_715_000_812,
        nanos: 0,
    };
    for (property, selector, expect_hole) in [(2, 0, false), (15, 0, true), (2, 4, true)] {
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            deadlist_mode: DeadlistMode::NativeDeadlist,
            data_properties: vec![(b"recordsize", 4096), (b"compression", property)],
            hello_compress_type: selector,
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
        engine
            .write_file_data(
                &cx,
                &dataset,
                4,
                0,
                &[0; 4096],
                timestamp,
                ZfsDataChecksum::Inherit,
            )
            .into_result()
            .unwrap();
        let node = native_zpl_file_dnode(&cx, &engine, &devices[0], &dataset, 4);
        assert_eq!(node.compress_type(), selector);
        assert_eq!(
            native_plain_leaf_pointers(&devices[0], &node).is_empty(),
            expect_hole
        );
        assert_eq!(node.used_bytes(), if expect_hole { 0 } else { 4096 });
        let slot = engine.committed_slot();
        drop(engine);
        let durable: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let mut reopened =
            open_engine_on_devices(&cx, &durable, default_write_opts(built.pool_guid, slot))
                .unwrap();
        let mut mos = reopened.open_read_objects(&cx).unwrap();
        assert_eq!(
            mos.zpl(&cx, &dataset)
                .unwrap()
                .read(&cx, 4, 0, 4096)
                .unwrap(),
            vec![0; 4096]
        );
        assert_eq!(
            mos.zpl_snapshot(&cx, &dataset, b"before")
                .unwrap()
                .read(&cx, 4, 0, 4096)
                .unwrap(),
            built.snap_hello_expected
        );
        reopened
            .write_file_data(
                &cx,
                &dataset,
                4,
                17,
                b"initialized",
                timestamp,
                ZfsDataChecksum::Inherit,
            )
            .into_result()
            .unwrap();
        let mut expected = vec![0; 4096];
        expected[17..28].copy_from_slice(b"initialized");
        let mut mos = reopened.open_read_objects(&cx).unwrap();
        assert_eq!(
            mos.zpl(&cx, &dataset)
                .unwrap()
                .read(&cx, 4, 0, 4096)
                .unwrap(),
            expected
        );
        assert_pool_scrub_and_allocation_clean(
            &cx,
            &durable,
            built.pool_guid,
            Some(reopened.committed_slot()),
        );
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn native_zstd_property_ownership_and_compressed_data_survive_shared_lifecycle() {
    use ffs_zfs::ZfsPropertySetValue;

    const ZSTD: &[u8] = b"org.freebsd:zstd_compress";
    let cx = Cx::for_testing();
    let parent = [b"data".to_vec()];
    let dataset = vec![b"data".to_vec(), b"compressed".to_vec()];
    let clone = vec![b"data".to_vec(), b"clone".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_715_000_809,
        nanos: 0,
    };
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        additional_read_features: vec![(ZSTD, 0)],
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
    engine
        .create_dataset(&cx, &parent, b"compressed", &[], timestamp)
        .into_result()
        .unwrap();
    assert_native_dataset_feature(&cx, &engine, &dataset, ZSTD, false, 0);
    engine
        .set_property(
            &cx,
            &dataset,
            "compression",
            ZfsPropertySetValue::Number(16 | (6 << 7)),
        )
        .into_result()
        .unwrap();
    // Native dsl_dataset_set_compression_sync activates this feature at an
    // explicit property assignment, including an empty dataset with no BP16.
    assert_native_dataset_feature(&cx, &engine, &dataset, ZSTD, true, 1);
    engine
        .set_property(
            &cx,
            &dataset,
            "compression",
            ZfsPropertySetValue::Number(16 | (6 << 7)),
        )
        .into_result()
        .unwrap();
    assert_native_dataset_feature(&cx, &engine, &dataset, ZSTD, true, 1);
    let (file, _) = engine
        .create_file(
            &cx,
            &dataset,
            2,
            b"payload",
            0o600,
            1000,
            1000,
            timestamp,
            ZfsDataChecksum::Inherit,
        )
        .into_result()
        .unwrap();
    let payload = vec![0xD3; 8192];
    engine
        .write_file_data(
            &cx,
            &dataset,
            file,
            0,
            &payload,
            timestamp,
            ZfsDataChecksum::Inherit,
        )
        .into_result()
        .unwrap();
    let node = native_zpl_file_dnode(&cx, &engine, &devices[0], &dataset, file);
    assert_eq!(
        node.compress_type(),
        0,
        "new files must retain native inheritance"
    );
    for pointer in native_plain_leaf_pointers(&devices[0], &node) {
        assert_eq!(pointer.compression(), 16);
        assert!(pointer.physical_bytes() < pointer.logical_bytes());
        let media = devices[0].durable_snapshot();
        let offset =
            usize::try_from(DATA_OFFSET + pointer.regular_dvas().unwrap()[0].offset).unwrap();
        assert_eq!(
            media[offset + 7],
            6,
            "persist the requested native ZSTD level"
        );
    }
    let (snapshot, _) = engine
        .create_snapshot(&cx, &dataset, b"compressed", timestamp)
        .into_result()
        .unwrap();
    assert_native_dataset_feature(&cx, &engine, &dataset, ZSTD, true, 2);
    let (clone_head, _) = engine
        .create_clone(
            &cx,
            &dataset,
            b"compressed",
            &parent,
            b"clone",
            &[],
            timestamp,
        )
        .into_result()
        .unwrap();
    assert_native_dataset_feature(&cx, &engine, &clone, ZSTD, true, 3);
    engine
        .set_property(&cx, &dataset, "compression", ZfsPropertySetValue::Number(2))
        .into_result()
        .unwrap();
    engine
        .write_file_data(
            &cx,
            &dataset,
            file,
            0,
            &[0xE4; 8192],
            timestamp,
            ZfsDataChecksum::Inherit,
        )
        .into_result()
        .unwrap();
    assert_native_dataset_feature(&cx, &engine, &dataset, ZSTD, true, 3);
    let node = native_zpl_file_dnode(&cx, &engine, &devices[0], &dataset, file);
    assert!(
        native_plain_leaf_pointers(&devices[0], &node)
            .iter()
            .all(|pointer| pointer.compression() == 2)
    );
    let slot = engine.committed_slot();
    drop(engine);
    let durable: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::fresh_from_durable)
        .collect();
    let mut reopened =
        open_engine_on_devices(&cx, &durable, default_write_opts(built.pool_guid, slot)).unwrap();
    let mut mos = reopened.open_read_objects(&cx).unwrap();
    for object in [snapshot, clone_head] {
        assert_eq!(
            mos.zap(&cx, object)
                .unwrap()
                .iter()
                .find(|entry| entry.name == ZSTD)
                .unwrap()
                .value,
            0
        );
    }
    assert_eq!(
        mos.zpl_snapshot(&cx, &dataset, b"compressed")
            .unwrap()
            .read(&cx, file, 0, payload.len())
            .unwrap(),
        payload
    );
    assert_eq!(
        mos.zpl(&cx, &clone)
            .unwrap()
            .read(&cx, file, 0, payload.len())
            .unwrap(),
        payload
    );
    reopened.destroy_dataset(&cx, &clone).into_result().unwrap();
    assert_native_dataset_feature(&cx, &reopened, &dataset, ZSTD, true, 2);
    reopened
        .destroy_snapshot(&cx, &dataset, b"compressed", false)
        .into_result()
        .unwrap();
    assert_native_dataset_feature(&cx, &reopened, &dataset, ZSTD, true, 1);
    reopened
        .destroy_dataset(&cx, &dataset)
        .into_result()
        .unwrap();
    assert_native_dataset_feature(&cx, &reopened, &parent, ZSTD, false, 0);
    assert_pool_scrub_and_allocation_clean(
        &cx,
        &durable,
        built.pool_guid,
        Some(reopened.committed_slot()),
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn inherited_zstd_first_data_crash_cuts_publish_compression_and_owner_together() {
    use ffs_zfs::ZfsPropertySetValue;
    use std::sync::atomic::{AtomicBool, Ordering};

    const ZSTD: &[u8] = b"org.freebsd:zstd_compress";
    let cx = Cx::for_testing();
    let parent = [b"data".to_vec()];
    let dataset = vec![b"data".to_vec(), b"inherited".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_715_000_810,
        nanos: 0,
    };
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        data_properties: vec![(b"recordsize", 4096)],
        additional_read_features: vec![(ZSTD, 0)],
        ..PoolFixtureSpec::default()
    });
    let devices: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut setup = open_engine_on_devices(
        &cx,
        &devices,
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    setup
        .set_property(&cx, &parent, "compression", ZfsPropertySetValue::Number(16))
        .into_result()
        .unwrap();
    setup
        .create_dataset(&cx, &parent, b"inherited", &[], timestamp)
        .into_result()
        .unwrap();
    let (file, _) = setup
        .create_file(
            &cx,
            &dataset,
            2,
            b"payload",
            0o600,
            1000,
            1000,
            timestamp,
            ZfsDataChecksum::Inherit,
        )
        .into_result()
        .unwrap();
    setup
        .create_snapshot(&cx, &dataset, b"empty", timestamp)
        .into_result()
        .unwrap();
    // Inheritance and default-ON metadata do not themselves create a ZSTD owner.
    assert_native_dataset_feature(&cx, &setup, &dataset, ZSTD, false, 1);
    let base_txg = setup.committed_txg();
    let base_slot = setup.committed_slot();
    drop(setup);
    let payload = vec![0xBD; 5 * 4096];
    for stage in 0..6_u8 {
        let cut_devices: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let mut engine = open_engine_on_devices(
            &cx,
            &cut_devices,
            default_write_opts(built.pool_guid, base_slot),
        )
        .unwrap();
        let tripped = Arc::new(AtomicBool::new(false));
        let hook_tripped = Arc::clone(&tripped);
        engine.with_fault_hook(move |event| {
            let cut = matches!(
                (stage, event.stage),
                (0, ZfsPersistenceStage::ChildBlocksWrite { .. })
                    | (1, ZfsPersistenceStage::DatasetMetadataBarrier { .. })
                    | (2, ZfsPersistenceStage::MosSpaceMapBarrier { .. })
                    | (3, ZfsPersistenceStage::MosRootBarrier { .. })
                    | (4, ZfsPersistenceStage::UberblockWrite { label: 2, .. })
                    | (5, ZfsPersistenceStage::BeforeAcknowledge)
            );
            if cut {
                hook_tripped.store(true, Ordering::SeqCst);
                Err(FfsError::Cancelled)
            } else {
                Ok(())
            }
        });
        let outcome = engine.write_file_data(
            &cx,
            &dataset,
            file,
            0,
            &payload,
            timestamp,
            ZfsDataChecksum::Inherit,
        );
        assert!(tripped.load(Ordering::SeqCst), "missed ZSTD cut {stage}");
        let published = stage >= 4;
        let slot = match outcome {
            ZfsTxOutcome::NotCommitted(FfsError::Cancelled) if !published => base_slot,
            ZfsTxOutcome::Uncertain { target_slot, .. } if stage == 4 => {
                assert!(engine.requires_recovery());
                target_slot
            }
            ZfsTxOutcome::Committed { token, .. } if stage == 5 => token.published_slot(),
            other => panic!("unexpected ZSTD cut {stage}: {other:?}"),
        };
        drop(engine);
        let durable: Vec<_> = cut_devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let mut options = default_write_opts(built.pool_guid, slot);
        options.reconcile_torn_uberblocks = stage == 4;
        let mut recovered = open_engine_on_devices(&cx, &durable, options).unwrap();
        assert_eq!(recovered.committed_txg(), base_txg + u64::from(published));
        assert_native_dataset_feature(
            &cx,
            &recovered,
            &dataset,
            ZSTD,
            published,
            1 + u64::from(published),
        );
        let mut mos = recovered.open_read_objects(&cx).unwrap();
        assert_eq!(
            mos.zpl(&cx, &dataset)
                .unwrap()
                .read(&cx, file, 0, payload.len())
                .unwrap(),
            if published { payload.as_slice() } else { &[] }
        );
        assert!(
            mos.zpl_snapshot(&cx, &dataset, b"empty")
                .unwrap()
                .read(&cx, file, 0, payload.len())
                .unwrap()
                .is_empty()
        );
        assert_pool_scrub_and_allocation_clean(&cx, &durable, built.pool_guid, Some(slot));
        recovered
            .write_file_data(
                &cx,
                &dataset,
                file,
                0,
                &payload,
                timestamp,
                ZfsDataChecksum::Inherit,
            )
            .into_result()
            .unwrap();
        assert_native_dataset_feature(&cx, &recovered, &dataset, ZSTD, true, 2);
        let node = native_zpl_file_dnode(&cx, &recovered, &durable[0], &dataset, file);
        let leaves = native_plain_leaf_pointers(&durable[0], &node);
        assert_eq!(leaves.len(), 5);
        assert!(leaves.iter().all(|pointer| pointer.compression() == 16));
    }
}

#[test]
fn native_plain_zvol_compression_survives_partial_discard_and_reopen() {
    use ffs_zfs::{ZfsPropertySetValue, ZfsZvolCreateOptions};

    const ZSTD: &[u8] = b"org.freebsd:zstd_compress";
    let cx = Cx::for_testing();
    let parent = [b"data".to_vec()];
    let dataset = vec![b"data".to_vec(), b"compressed-volume".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_715_000_811,
        nanos: 0,
    };
    for compression in [15, 16 | (7 << 7)] {
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            additional_read_features: vec![(ZSTD, 0)],
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
        engine
            .zvol_create(
                &cx,
                &parent,
                b"compressed-volume",
                &ZfsZvolCreateOptions {
                    volsize: 64 * 1024,
                    volblocksize: 4096,
                    sparse: true,
                    initial_props: vec![(
                        "compression".to_owned(),
                        ZfsPropertySetValue::Number(compression),
                    )],
                    timestamp,
                },
            )
            .into_result()
            .unwrap();
        let original = vec![0xC5; 4 * 4096];
        engine
            .zvol_write_at(&cx, &dataset, 0, &original, ZfsDataChecksum::Fletcher4)
            .into_result()
            .unwrap();
        let node = native_zpl_file_dnode(&cx, &engine, &devices[0], &dataset, 1);
        assert_eq!(node.compress_type(), 0);
        let leaves = native_plain_leaf_pointers(&devices[0], &node);
        assert_eq!(leaves.len(), 4);
        assert!(leaves.iter().all(
            |pointer| u64::from(pointer.compression()) == compression & 127
                && pointer.physical_bytes() < pointer.logical_bytes()
        ));
        engine
            .create_snapshot(&cx, &dataset, b"original", timestamp)
            .into_result()
            .unwrap();
        engine
            .zvol_discard(&cx, &dataset, 512, 512, ZfsDataChecksum::Fletcher4)
            .into_result()
            .unwrap();
        engine
            .zvol_discard(&cx, &dataset, 4096, 4096, ZfsDataChecksum::Fletcher4)
            .into_result()
            .unwrap();
        let mut expected = original.clone();
        expected[512..1024].fill(0);
        expected[4096..8192].fill(0);
        let slot = engine.committed_slot();
        drop(engine);
        let durable: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let mut reopened =
            open_engine_on_devices(&cx, &durable, default_write_opts(built.pool_guid, slot))
                .unwrap();
        let mut mos = reopened.open_read_objects(&cx).unwrap();
        assert_eq!(
            mos.zvol(&cx, &dataset, None)
                .unwrap()
                .read(&cx, 0, original.len())
                .unwrap(),
            expected
        );
        assert_eq!(
            mos.zvol(&cx, &dataset, Some(b"original"))
                .unwrap()
                .read(&cx, 0, original.len())
                .unwrap(),
            original
        );
        let node = native_zpl_file_dnode(&cx, &reopened, &durable[0], &dataset, 1);
        let leaves = native_plain_leaf_pointers(&durable[0], &node);
        assert_eq!(leaves.len(), 3);
        assert!(
            leaves
                .iter()
                .all(|pointer| u64::from(pointer.compression()) == compression & 127)
        );
        assert_native_dataset_feature(
            &cx,
            &reopened,
            &dataset,
            ZSTD,
            compression & 127 == 16,
            if compression & 127 == 16 { 2 } else { 0 },
        );
        reopened
            .destroy_snapshot(&cx, &dataset, b"original", false)
            .into_result()
            .unwrap();
        reopened.zvol_destroy(&cx, &dataset).into_result().unwrap();
        assert_native_dataset_feature(&cx, &reopened, &parent, ZSTD, false, 0);
        assert_pool_scrub_and_allocation_clean(
            &cx,
            &durable,
            built.pool_guid,
            Some(reopened.committed_slot()),
        );
    }
}

#[test]
fn native_writes_resolve_effective_recordsize_before_choosing_file_geometry() {
    const RECORDSIZE: &[u8] = b"recordsize";
    const RECEIVED: &[u8] = b"recordsize$recvd";
    const INHERIT: &[u8] = b"recordsize$inherit";
    let cases = [
        ("default", vec![], vec![], 131_072_usize),
        ("inherited", vec![(RECORDSIZE, 4096)], vec![], 4096),
        (
            "local-override",
            vec![(RECORDSIZE, 512)],
            vec![(RECORDSIZE, 8192)],
            8192,
        ),
        (
            "received",
            vec![(RECORDSIZE, 4096)],
            vec![(RECEIVED, 8192)],
            8192,
        ),
        (
            "inherit-suppresses-received",
            vec![(RECORDSIZE, 4096)],
            vec![(RECEIVED, 8192), (INHERIT, 1)],
            4096,
        ),
        (
            "local-precedes-inherit",
            vec![(RECORDSIZE, 8192)],
            vec![(RECORDSIZE, 2048), (RECEIVED, 512), (INHERIT, 1)],
            2048,
        ),
        ("inherited-received", vec![(RECEIVED, 1024)], vec![], 1024),
    ];
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_715_000_198,
        nanos: 19,
    };
    for zpl_version in [4, 5] {
        for (case, root_properties, data_properties, recordsize) in &cases {
            let built = build_clean_zfs_pool(&PoolFixtureSpec {
                zpl_version,
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
            let (object, _) = engine
                .create_file(
                    &cx,
                    &dataset,
                    2,
                    b"geometry.bin",
                    0o644,
                    1000,
                    1000,
                    timestamp,
                    ZfsDataChecksum::Fletcher4,
                )
                .into_result()
                .unwrap_or_else(|error| panic!("{case}: {error}"));
            let payload: Vec<_> = (0..recordsize * 2 + 17)
                .map(|index| u8::try_from(index % 251).unwrap())
                .collect();
            let (_, token) = engine
                .write_file_data(
                    &cx,
                    &dataset,
                    object,
                    0,
                    &payload,
                    timestamp,
                    ZfsDataChecksum::Fletcher4,
                )
                .into_result()
                .unwrap_or_else(|error| panic!("{case}: {error}"));
            engine.verify_token(&token).unwrap();
            let slot = engine.committed_slot();
            drop(engine);

            let durable: Vec<_> = devices
                .iter()
                .map(FaultableMemberDevice::fresh_from_durable)
                .collect();
            let reopened =
                open_engine_on_devices(&cx, &durable, default_write_opts(built.pool_guid, slot))
                    .unwrap();
            let node = native_zpl_file_dnode(&cx, &reopened, &durable[0], &dataset, object);
            assert_eq!(node.data_bytes(), *recordsize, "{case}");
            let mut mos = reopened.open_read_objects(&cx).unwrap();
            let mut zpl = mos.zpl(&cx, &dataset).unwrap();
            assert_eq!(
                zpl.resolve(&cx, b"/geometry.bin").unwrap(),
                object,
                "{case}"
            );
            assert_eq!(
                zpl.read(&cx, object, 0, payload.len() + 1).unwrap(),
                payload,
                "{case}"
            );
            let mut snapshot = mos.zpl_snapshot(&cx, &dataset, b"before").unwrap();
            assert!(matches!(
                snapshot.resolve(&cx, b"/geometry.bin"),
                Err(FfsError::NotFound(_))
            ));
            assert_pool_scrub_and_allocation_clean(&cx, &durable, built.pool_guid, Some(slot));
        }
    }
}

#[test]
fn native_writes_reject_invalid_effective_recordsize_without_backing_writes() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_715_000_198,
        nanos: 0,
    };
    for invalid in [0, 511, 513, 1_048_577, u64::MAX] {
        for (root_properties, data_properties) in [
            (vec![(b"recordsize".as_slice(), invalid)], vec![]),
            (vec![], vec![(b"recordsize".as_slice(), invalid)]),
            (vec![], vec![(b"recordsize$recvd".as_slice(), invalid)]),
        ] {
            let built = build_clean_zfs_pool(&PoolFixtureSpec {
                root_properties,
                data_properties,
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
            assert_native_write_refused(&mut engine, &devices, libc::EIO, |writer| {
                writer.write_file_data(
                    &cx,
                    &dataset,
                    4,
                    0,
                    b"must not be published",
                    timestamp,
                    ZfsDataChecksum::Fletcher4,
                )
            });
        }
    }
}

#[test]
fn native_zpl_writes_resolve_dataset_checksum_sources() {
    const SHA512: &[u8] = b"org.illumos:sha512";
    const CHECKSUM: &[u8] = b"checksum";
    const RECEIVED: &[u8] = b"checksum$recvd";
    const INHERIT: &[u8] = b"checksum$inherit";
    let cases = [
        ("default", vec![], vec![], 7_u8),
        ("on", vec![(CHECKSUM, 1)], vec![], 7),
        ("inherited-sha256", vec![(CHECKSUM, 8)], vec![], 8),
        ("local-sha256", vec![(CHECKSUM, 7)], vec![(CHECKSUM, 8)], 8),
        (
            "local-fletcher4",
            vec![(CHECKSUM, 8)],
            vec![(CHECKSUM, 7)],
            7,
        ),
        (
            "received-sha256",
            vec![(CHECKSUM, 7)],
            vec![(RECEIVED, 8)],
            8,
        ),
        (
            "inherit-suppresses-received",
            vec![(CHECKSUM, 8)],
            vec![(RECEIVED, 7), (INHERIT, 1)],
            8,
        ),
        (
            "local-precedes-inherit",
            vec![(CHECKSUM, 8)],
            vec![(CHECKSUM, 7), (RECEIVED, 8), (INHERIT, 1)],
            7,
        ),
        ("inherited-received", vec![(RECEIVED, 8)], vec![], 8),
        ("fletcher2", vec![(CHECKSUM, 6)], vec![], 6),
        ("owned-inherited-sha512", vec![(CHECKSUM, 11)], vec![], 11),
        (
            "owned-local-sha512",
            vec![(CHECKSUM, 7)],
            vec![(CHECKSUM, 11)],
            11,
        ),
    ];
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let time = Timestamp {
        seconds: 1_715_000_800,
        nanos: 0,
    };
    for (case, root_properties, data_properties, expected_checksum) in cases {
        let owns_sha512 = expected_checksum == 11;
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            root_properties,
            data_properties,
            data_head_features: if owns_sha512 {
                vec![(SHA512, 0)]
            } else {
                Vec::new()
            },
            additional_read_features: if owns_sha512 {
                vec![(SHA512, 1)]
            } else {
                Vec::new()
            },
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
        let (object, _) = engine
            .create_file(
                &cx,
                &dataset,
                2,
                b"checksummed",
                0o644,
                1000,
                1000,
                time,
                ZfsDataChecksum::Inherit,
            )
            .into_result()
            .unwrap();
        let check = |engine: &ZfsTransactionEngine| {
            let node = native_zpl_file_dnode(&cx, engine, &devices[0], &dataset, object);
            assert_eq!(
                node.checksum_type(),
                0,
                "{case}: inherited policy was pinned"
            );
            assert_eq!(node.levels(), 1, "{case}");
            assert!(!node.pointers()[0].hole(), "{case}");
            assert_eq!(
                node.pointers()[0].checksum_type(),
                expected_checksum,
                "{case}: durable data block used the wrong checksum"
            );
        };
        let payload = vec![0x5B; 8192];
        engine
            .write_file_data(
                &cx,
                &dataset,
                object,
                0,
                &payload,
                time,
                ZfsDataChecksum::Inherit,
            )
            .into_result()
            .unwrap();
        check(&engine);
        engine
            .truncate_file(&cx, &dataset, object, 3333, time, ZfsDataChecksum::Inherit)
            .into_result()
            .unwrap();
        check(&engine);
        engine
            .edit_file_range(
                &cx,
                &dataset,
                object,
                13,
                71,
                ffs_zfs::ZfsFileRangeOperation::PunchHole,
                time,
                ZfsDataChecksum::Inherit,
            )
            .into_result()
            .unwrap();
        check(&engine);
        let slot = engine.committed_slot();
        drop(engine);
        let durable: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let reopened =
            open_engine_on_devices(&cx, &durable, default_write_opts(built.pool_guid, slot))
                .unwrap();
        let mut view = reopened
            .open_read_objects(&cx)
            .unwrap()
            .zpl(&cx, &dataset)
            .unwrap();
        let mut expected = vec![0x5B; 3333];
        expected[13..84].fill(0);
        assert_eq!(view.read(&cx, object, 0, 8192).unwrap(), expected, "{case}");
        let node = native_zpl_file_dnode(&cx, &reopened, &durable[0], &dataset, object);
        assert_eq!(
            node.pointers()[0].checksum_type(),
            expected_checksum,
            "{case}"
        );
        if owns_sha512 {
            let mut mos = reopened.open_read_objects(&cx).unwrap();
            assert_eq!(mos.object(&cx, 18).unwrap().object_type(), 196, "{case}");
            let ownership = mos.zap(&cx, 18).unwrap();
            assert_eq!(
                ownership
                    .iter()
                    .find(|entry| entry.name == SHA512)
                    .map(|entry| entry.value),
                Some(0),
                "{case}: native dataset ownership must survive rewrites"
            );
            let features = mos.zap(&cx, 10).unwrap();
            for feature in [SHA512, b"com.delphix:extensible_dataset".as_slice()] {
                assert_eq!(
                    features
                        .iter()
                        .find(|entry| entry.name == feature)
                        .map(|entry| entry.value),
                    Some(1),
                    "{case}: continuing owned SHA512 must preserve feature refcounts"
                );
            }
        }
        assert_pool_scrub_and_allocation_clean(&cx, &durable, built.pool_guid, Some(slot));
    }
}

#[test]
fn native_checksum_changes_preserve_explicit_sha256_objects() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let time = Timestamp {
        seconds: 1_715_000_801,
        nanos: 0,
    };
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        root_properties: vec![(b"checksum", 8)],
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
    let (inherited, _) = engine
        .create_file(
            &cx,
            &dataset,
            2,
            b"inherited",
            0o644,
            1000,
            1000,
            time,
            ZfsDataChecksum::Inherit,
        )
        .into_result()
        .unwrap();
    let (pinned, _) = engine
        .create_file(
            &cx,
            &dataset,
            2,
            b"pinned",
            0o644,
            1000,
            1000,
            time,
            ZfsDataChecksum::Sha256,
        )
        .into_result()
        .unwrap();
    let payload = vec![0x5A; 8192];
    for object in [inherited, pinned] {
        engine
            .write_file_data(
                &cx,
                &dataset,
                object,
                0,
                &payload,
                time,
                ZfsDataChecksum::Inherit,
            )
            .into_result()
            .unwrap();
        let node = native_zpl_file_dnode(&cx, &engine, &devices[0], &dataset, object);
        assert_eq!(node.pointers()[0].checksum_type(), 8);
    }
    engine
        .set_property(
            &cx,
            &dataset,
            "checksum",
            ffs_zfs::ZfsPropertySetValue::Number(7),
        )
        .into_result()
        .unwrap();
    for (object, expected_checksum, expected_override) in [(inherited, 7, 0), (pinned, 8, 8)] {
        engine
            .write_file_data(
                &cx,
                &dataset,
                object,
                7,
                b"next",
                time,
                ZfsDataChecksum::Inherit,
            )
            .into_result()
            .unwrap();
        let node = native_zpl_file_dnode(&cx, &engine, &devices[0], &dataset, object);
        assert_eq!(node.pointers()[0].checksum_type(), expected_checksum);
        assert_eq!(node.checksum_type(), expected_override);
        engine
            .truncate_file(
                &cx,
                &dataset,
                object,
                3073,
                time,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        let node = native_zpl_file_dnode(&cx, &engine, &devices[0], &dataset, object);
        assert_eq!(node.pointers()[0].checksum_type(), expected_checksum);
        engine
            .edit_file_range(
                &cx,
                &dataset,
                object,
                20,
                11,
                ffs_zfs::ZfsFileRangeOperation::PunchHole,
                time,
                ZfsDataChecksum::Inherit,
            )
            .into_result()
            .unwrap();
        let node = native_zpl_file_dnode(&cx, &engine, &devices[0], &dataset, object);
        assert_eq!(node.pointers()[0].checksum_type(), expected_checksum);
    }
    // An explicit Fletcher4 request remains explicit. A subsequent inherited
    // request sees the current dataset property because dn_checksum stayed zero.
    engine
        .set_property(
            &cx,
            &dataset,
            "checksum",
            ffs_zfs::ZfsPropertySetValue::Number(8),
        )
        .into_result()
        .unwrap();
    for (selection, expected_checksum) in [
        (ZfsDataChecksum::Fletcher4, 7),
        (ZfsDataChecksum::Inherit, 8),
    ] {
        engine
            .write_file_data(&cx, &dataset, inherited, 0, b"tail", time, selection)
            .into_result()
            .unwrap();
        let node = native_zpl_file_dnode(&cx, &engine, &devices[0], &dataset, inherited);
        assert_eq!(node.pointers()[0].checksum_type(), expected_checksum);
        assert_eq!(node.checksum_type(), 0);
    }
    let slot = engine.committed_slot();
    drop(engine);
    let durable: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::fresh_from_durable)
        .collect();
    let reopened =
        open_engine_on_devices(&cx, &durable, default_write_opts(built.pool_guid, slot)).unwrap();
    let mut view = reopened
        .open_read_objects(&cx)
        .unwrap()
        .zpl(&cx, &dataset)
        .unwrap();
    for object in [inherited, pinned] {
        let mut expected = vec![0x5A; 3073];
        expected[7..11].copy_from_slice(b"next");
        expected[20..31].fill(0);
        if object == inherited {
            expected[..4].copy_from_slice(b"tail");
        }
        assert_eq!(view.read(&cx, object, 0, 8192).unwrap(), expected);
        let node = native_zpl_file_dnode(&cx, &reopened, &durable[0], &dataset, object);
        assert_eq!(node.pointers()[0].checksum_type(), 8);
    }
    assert_pool_scrub_and_allocation_clean(&cx, &durable, built.pool_guid, Some(slot));
}

#[test]
fn native_zpl_checksum_policy_refuses_unadmitted_algorithms_before_writes() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let time = Timestamp {
        seconds: 1_715_000_802,
        nanos: 0,
    };
    for value in [0, 2, 9, 11, u64::MAX] {
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            root_properties: vec![(b"checksum", value)],
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
        assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
            writer.create_file(
                &cx,
                &dataset,
                2,
                b"refused",
                0o644,
                1000,
                1000,
                time,
                ZfsDataChecksum::Inherit,
            )
        });
        assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
            writer.write_file_data(
                &cx,
                &dataset,
                4,
                0,
                b"must not publish",
                time,
                ZfsDataChecksum::Inherit,
            )
        });
        let mut view = engine
            .open_read_objects(&cx)
            .unwrap()
            .zpl(&cx, &dataset)
            .unwrap();
        assert_eq!(
            view.read(&cx, 4, 0, 8192).unwrap(),
            built.snap_hello_expected
        );
        assert!(matches!(
            view.resolve(&cx, b"/refused"),
            Err(FfsError::NotFound(_))
        ));
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn native_sha512_writes_refuse_invalid_existing_ownership_or_disabled_features() {
    const SHA512: &[u8] = b"org.illumos:sha512";
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_715_000_803,
        nanos: 0,
    };
    let cases = [
        ("disabled-feature", None, None, None, 11),
        ("inactive-feature", Some(0), Some(0), None, 11),
        ("missing-feature", Some(0), None, None, 11),
        ("malformed-owner", Some(1), Some(1), None, 11),
        ("old-root-missing-owner", None, Some(1), Some(11), 7),
        ("old-root-inactive-feature", Some(0), Some(0), Some(11), 7),
    ];
    for (case, owner, feature, old_root_checksum, checksum) in cases {
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            deadlist_mode: DeadlistMode::NativeDeadlist,
            data_properties: vec![(b"checksum", checksum)],
            data_head_features: owner.into_iter().map(|value| (SHA512, value)).collect(),
            additional_read_features: feature.into_iter().map(|value| (SHA512, value)).collect(),
            data_objectset_checksum: old_root_checksum,
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
        for requested in [ZfsDataChecksum::Inherit, ZfsDataChecksum::Fletcher4] {
            assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
                writer.write_file_data(
                    &cx,
                    &dataset,
                    4,
                    0,
                    b"must not publish",
                    timestamp,
                    requested,
                )
            });
        }
        // A metadata-only update also rewrites the old object-set root. Its
        // SHA512 ownership must be admitted even with a Fletcher4 data request.
        assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
            writer.set_attributes(
                &cx,
                &dataset,
                4,
                &ffs_zfs::ZfsSetAttr {
                    mtime: Some(timestamp),
                    ..ffs_zfs::ZfsSetAttr::default()
                },
                timestamp,
                ZfsDataChecksum::Fletcher4,
            )
        });
        let mut view = engine
            .open_read_objects(&cx)
            .unwrap()
            .zpl(&cx, &dataset)
            .unwrap();
        assert_eq!(
            view.read(&cx, 4, 0, 8192).unwrap(),
            built.snap_hello_expected,
            "{case}"
        );
    }
}

fn assert_native_dataset_feature(
    cx: &Cx,
    engine: &ZfsTransactionEngine,
    dataset: &[Vec<u8>],
    feature: &[u8],
    owned: bool,
    count: u64,
) {
    let mut mos = engine.open_read_objects(cx).unwrap();
    let row = mos
        .datasets(cx)
        .unwrap()
        .into_iter()
        .find(|row| row.components == dataset)
        .unwrap();
    let head = mos.object(cx, row.head_object).unwrap();
    let marker = if head.object_type() == 196 {
        mos.zap(cx, row.head_object)
            .unwrap()
            .into_iter()
            .find(|entry| entry.name == feature)
            .map(|entry| entry.value)
    } else {
        None
    };
    assert_eq!(marker, owned.then_some(0));
    let feature_object = mos
        .zap(cx, 1)
        .unwrap()
        .into_iter()
        .find(|entry| entry.name == b"features_for_read")
        .unwrap()
        .value;
    assert_eq!(
        mos.zap(cx, feature_object)
            .unwrap()
            .into_iter()
            .find(|entry| entry.name == feature)
            .map(|entry| entry.value),
        Some(count)
    );
}

#[test]
fn native_large_records_and_sha512_activate_on_first_block_and_survive_property_changes() {
    const LARGE_BLOCKS: &[u8] = b"org.open-zfs:large_blocks";
    const SHA512: &[u8] = b"org.illumos:sha512";
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_715_000_804,
        nanos: 0,
    };
    for (zpl_version, recordsize, checksum, mirror_width) in
        [(4, 262_144_usize, 7, 1), (5, 1_048_576, 11, 2)]
    {
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            zpl_version,
            mirror_width,
            deadlist_mode: DeadlistMode::NativeDeadlist,
            root_properties: vec![(b"recordsize", recordsize as u64), (b"checksum", checksum)],
            additional_read_features: vec![(LARGE_BLOCKS, 0), (SHA512, 0)],
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
        let object = engine
            .create_file(
                &cx,
                &dataset,
                2,
                b"large-records",
                0o644,
                1000,
                1000,
                timestamp,
                ZfsDataChecksum::Inherit,
            )
            .into_result()
            .unwrap()
            .0;
        for feature in [LARGE_BLOCKS, SHA512] {
            assert_native_dataset_feature(&cx, &engine, &dataset, feature, false, 0);
        }
        let mut payload: Vec<_> = (0..recordsize * 2 + 17)
            .map(|index| u8::try_from(index % 251).unwrap())
            .collect();
        let (_, token) = engine
            .write_file_data(
                &cx,
                &dataset,
                object,
                0,
                &payload,
                timestamp,
                ZfsDataChecksum::Inherit,
            )
            .into_result()
            .unwrap();
        engine.verify_token(&token).unwrap();
        assert_native_dataset_feature(&cx, &engine, &dataset, LARGE_BLOCKS, true, 1);
        assert_native_dataset_feature(
            &cx,
            &engine,
            &dataset,
            SHA512,
            checksum == 11,
            u64::from(checksum == 11),
        );
        let node = native_zpl_file_dnode(&cx, &engine, &devices[0], &dataset, object);
        assert_eq!(node.data_bytes(), recordsize);
        assert_eq!(node.levels(), 2);
        assert_eq!(node.checksum_type(), 0);
        let indirect = &node.pointers()[0];
        assert_eq!(u64::from(indirect.checksum_type()), checksum);
        let image = devices[0].durable_snapshot();
        let dva = indirect.regular_dvas().unwrap()[0];
        let offset = usize::try_from(DATA_OFFSET + dva.offset).unwrap();
        for index in 0..3 {
            let pointer = BlockPointer::parse(
                &image[offset + index * 128..offset + (index + 1) * 128],
                indirect.payload_order(),
            )
            .unwrap();
            assert!(!pointer.hole());
            assert_eq!(pointer.logical_bytes(), recordsize);
            assert_eq!(u64::from(pointer.checksum_type()), checksum);
        }

        // Lowering a property cannot release ownership of blocks that remain
        // in this head, snapshots, or later clones.
        for (name, value) in [("recordsize", 4096), ("checksum", 7)] {
            engine
                .set_property(
                    &cx,
                    &dataset,
                    name,
                    ffs_zfs::ZfsPropertySetValue::Number(value),
                )
                .into_result()
                .unwrap();
        }
        engine
            .write_file_data(
                &cx,
                &dataset,
                object,
                31,
                b"after-property-change",
                timestamp,
                ZfsDataChecksum::Inherit,
            )
            .into_result()
            .unwrap();
        payload[31..52].copy_from_slice(b"after-property-change");
        let slot = engine.committed_slot();
        drop(engine);
        let durable: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let reopened =
            open_engine_on_devices(&cx, &durable, default_write_opts(built.pool_guid, slot))
                .unwrap();
        assert_native_dataset_feature(&cx, &reopened, &dataset, LARGE_BLOCKS, true, 1);
        assert_native_dataset_feature(
            &cx,
            &reopened,
            &dataset,
            SHA512,
            checksum == 11,
            u64::from(checksum == 11),
        );
        let node = native_zpl_file_dnode(&cx, &reopened, &durable[0], &dataset, object);
        assert_eq!(node.data_bytes(), recordsize);
        let mut mos = reopened.open_read_objects(&cx).unwrap();
        assert_eq!(
            mos.zpl(&cx, &dataset)
                .unwrap()
                .read(&cx, object, 0, payload.len() + 1)
                .unwrap(),
            payload
        );
        assert!(matches!(
            mos.zpl_snapshot(&cx, &dataset, b"before")
                .unwrap()
                .resolve(&cx, b"/large-records"),
            Err(FfsError::NotFound(_))
        ));
        assert_pool_scrub_and_allocation_clean(&cx, &durable, built.pool_guid, Some(slot));
    }
}

#[test]
fn native_large_record_first_use_refuses_disabled_feature_without_writes() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_715_000_805,
        nanos: 0,
    };
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        deadlist_mode: DeadlistMode::NativeDeadlist,
        data_properties: vec![(b"recordsize", 262_144)],
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
    let payload = vec![0xAD; 262_144];
    assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
        writer.write_file_data(
            &cx,
            &dataset,
            4,
            0,
            &payload,
            timestamp,
            ZfsDataChecksum::Inherit,
        )
    });
}

#[test]
fn native_block_feature_first_use_crash_cuts_publish_data_and_ownership_together() {
    use std::sync::atomic::{AtomicBool, Ordering};

    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_715_000_806,
        nanos: 0,
    };
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        deadlist_mode: DeadlistMode::NativeDeadlist,
        data_properties: vec![(b"recordsize", 262_144), (b"checksum", 11)],
        additional_read_features: vec![
            (b"org.open-zfs:large_blocks", 0),
            (b"org.illumos:sha512", 0),
        ],
        ..PoolFixtureSpec::default()
    });
    let payload = vec![0xBC; 262_161];
    for stage in 0..6_u8 {
        let devices: Vec<_> = built
            .members
            .iter()
            .cloned()
            .map(FaultableMemberDevice::new)
            .collect();
        let mut engine = open_engine_on_devices(
            &cx,
            &devices,
            default_write_opts(built.pool_guid, built.initial_slot),
        )
        .unwrap();
        let tripped = Arc::new(AtomicBool::new(false));
        let hook_tripped = Arc::clone(&tripped);
        engine.with_fault_hook(move |event| {
            let cut = matches!(
                (stage, event.stage),
                (0, ZfsPersistenceStage::ChildBlocksWrite { .. })
                    | (1, ZfsPersistenceStage::DatasetMetadataBarrier { .. })
                    | (2, ZfsPersistenceStage::MosSpaceMapBarrier { .. })
                    | (3, ZfsPersistenceStage::MosRootBarrier { .. })
                    | (4, ZfsPersistenceStage::UberblockWrite { label: 2, .. })
                    | (5, ZfsPersistenceStage::BeforeAcknowledge)
            );
            if cut {
                hook_tripped.store(true, Ordering::SeqCst);
                Err(FfsError::Cancelled)
            } else {
                Ok(())
            }
        });
        let outcome = engine.write_file_data(
            &cx,
            &dataset,
            4,
            0,
            &payload,
            timestamp,
            ZfsDataChecksum::Inherit,
        );
        assert!(tripped.load(Ordering::SeqCst), "missed feature cut {stage}");
        let published = stage >= 4;
        let slot = match outcome {
            ZfsTxOutcome::NotCommitted(FfsError::Cancelled) if !published => built.initial_slot,
            ZfsTxOutcome::Uncertain { target_slot, .. } if stage == 4 => {
                assert!(engine.requires_recovery());
                target_slot
            }
            ZfsTxOutcome::Committed { token, .. } if stage == 5 => token.published_slot(),
            other => panic!("unexpected feature activation outcome at {stage}: {other:?}"),
        };
        drop(engine);
        let durable: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let mut options = default_write_opts(built.pool_guid, slot);
        options.reconcile_torn_uberblocks = stage == 4;
        let mut recovered = open_engine_on_devices(&cx, &durable, options).unwrap();
        assert_eq!(
            recovered.committed_txg(),
            INITIAL_TXG + u64::from(published)
        );
        assert_eq!(
            dsl_block_feature_counts(&cx, &recovered),
            [u64::from(published); 3]
        );
        for feature in [
            b"org.open-zfs:large_blocks".as_slice(),
            b"org.illumos:sha512".as_slice(),
        ] {
            assert_native_dataset_feature(
                &cx,
                &recovered,
                &dataset,
                feature,
                published,
                u64::from(published),
            );
        }
        let mut mos = recovered.open_read_objects(&cx).unwrap();
        assert_eq!(
            mos.zpl(&cx, &dataset)
                .unwrap()
                .read(&cx, 4, 0, payload.len() + 1)
                .unwrap(),
            if published {
                payload.as_slice()
            } else {
                built.snap_hello_expected.as_slice()
            }
        );
        assert_eq!(
            mos.zpl_snapshot(&cx, &dataset, b"before")
                .unwrap()
                .read(&cx, 4, 0, 8192)
                .unwrap(),
            built.snap_hello_expected
        );
        assert_pool_scrub_and_allocation_clean(&cx, &durable, built.pool_guid, Some(slot));

        // Retrying either recovered state must acquire exactly one owner.
        recovered
            .write_file_data(
                &cx,
                &dataset,
                4,
                0,
                &payload,
                timestamp,
                ZfsDataChecksum::Inherit,
            )
            .into_result()
            .unwrap();
        for feature in [
            b"org.open-zfs:large_blocks".as_slice(),
            b"org.illumos:sha512".as_slice(),
        ] {
            assert_native_dataset_feature(&cx, &recovered, &dataset, feature, true, 1);
        }
        assert_eq!(dsl_block_feature_counts(&cx, &recovered), [1; 3]);
    }
}

#[test]
fn native_zvol_refuses_unresolved_checksum_inheritance_before_publication() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        zvol_orders: Some((Endian::Little, Endian::Little)),
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
    engine.zvol_info(&cx, &dataset, None).unwrap();
    let txg = engine.committed_txg();
    let events = engine.persistence_events().len();
    let io_before: Vec<_> = devices
        .iter()
        .map(|device| {
            let media = device.state.lock().unwrap();
            (media.write_calls, media.sync_calls)
        })
        .collect();
    let payload = [0x5A; 512];
    let outcomes = [
        engine.zvol_write_at(&cx, &dataset, 0, &payload, ZfsDataChecksum::Inherit),
        engine.zvol_discard(&cx, &dataset, 0, 512, ZfsDataChecksum::Inherit),
        engine.zvol_batch_apply(&cx, &dataset, &BTreeMap::new(), ZfsDataChecksum::Inherit),
    ];
    for outcome in outcomes {
        match outcome {
            ZfsTxOutcome::NotCommitted(FfsError::UnsupportedFeature(detail)) => {
                assert_eq!(
                    detail,
                    "checksum inheritance is only supported for native ZPL writes"
                );
            }
            other => panic!("expected checksum admission refusal, got {other:?}"),
        }
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
    assert_eq!(io_after, io_before);
    // Explicit volume checksums still publish and survive a fresh native open.
    engine
        .zvol_write_at(&cx, &dataset, 0, &payload, ZfsDataChecksum::Sha256)
        .into_result()
        .unwrap();
    let slot = engine.committed_slot();
    drop(engine);
    let durable: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::fresh_from_durable)
        .collect();
    let reopened =
        open_engine_on_devices(&cx, &durable, default_write_opts(built.pool_guid, slot)).unwrap();
    let mut actual = [0; 512];
    reopened
        .zvol_read_at(&cx, &dataset, None, 0, &mut actual)
        .unwrap();
    assert_eq!(actual, payload);
}

#[test]
fn writes_preserve_existing_blocks_after_recordsize_reduction() {
    let cx = Cx::for_testing();
    let timestamp = Timestamp {
        seconds: 1_715_000_199,
        nanos: 0,
    };
    let dataset = [b"data".to_vec()];
    let patch = b"replacement bytes across the former record boundary";

    for (zpl_version, mirror_width, ashift) in [(4, 1, 9), (5, 2, 12)] {
        for offset in [13_usize, 3070, 4083, 8205] {
            // A native property reduction leaves existing files' block geometry
            // intact. The compressed 4 KiB file predates this 512-byte setting.
            let built = build_clean_zfs_pool(&PoolFixtureSpec {
                zpl_version,
                mirror_width,
                ashift,
                deadlist_mode: DeadlistMode::NativeDeadlist,
                data_properties: vec![(b"recordsize", 512)],
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
            let source = engine
                .open_read_objects(&cx)
                .unwrap()
                .zpl(&cx, &dataset)
                .unwrap()
                .resolve(&cx, b"/hello.txt")
                .unwrap();
            let mut expected = built.snap_hello_expected.clone();
            expected.resize(expected.len().max(offset + patch.len()), 0);
            expected[offset..offset + patch.len()].copy_from_slice(patch);

            let (size, token) = engine
                .write_file_data(
                    &cx,
                    &dataset,
                    source,
                    offset as u64,
                    patch,
                    timestamp,
                    ZfsDataChecksum::Sha256,
                )
                .into_result()
                .unwrap();
            assert_eq!(size, expected.len() as u64);
            engine.verify_token(&token).unwrap();
            let slot = engine.committed_slot();
            drop(engine);

            // Reopen from durable bytes, rather than trusting the writer's view.
            let durable: Vec<_> = devs
                .iter()
                .map(FaultableMemberDevice::fresh_from_durable)
                .collect();
            let reopened =
                open_engine_on_devices(&cx, &durable, default_write_opts(built.pool_guid, slot))
                    .unwrap();
            let mut mos = reopened.open_read_objects(&cx).unwrap();
            let mut head = mos.zpl(&cx, &dataset).unwrap();
            assert_eq!(head.resolve(&cx, b"/hello.txt").unwrap(), source);
            assert_eq!(
                head.read(&cx, source, 0, expected.len() + 1).unwrap(),
                expected,
                "recordsize reduction must preserve unrelated bytes at offset {offset}"
            );
            let mut snapshot = mos.zpl_snapshot(&cx, &dataset, b"before").unwrap();
            assert_eq!(
                snapshot
                    .read(&cx, source, 0, built.snap_hello_expected.len() + 1)
                    .unwrap(),
                built.snap_hello_expected,
                "COW must preserve the snapshotted original block"
            );
            assert_pool_scrub_and_allocation_clean(&cx, &durable, built.pool_guid, Some(slot));
        }
    }
}

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
fn final_reclamation_releases_private_xattrs_and_refuses_external_acls() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_715_000_210,
        nanos: 29,
    };
    for (zpl_version, mirror_width, ashift) in [(4, 1, 9), (5, 2, 12)] {
        for auxiliary in [
            AuxiliaryOwnership::XattrDirectory,
            AuxiliaryOwnership::ExternalAcl,
        ] {
            for owner in [4, 6] {
                let built = build_clean_zfs_pool(&PoolFixtureSpec {
                    zpl_version,
                    mirror_width,
                    ashift,
                    deadlist_mode: DeadlistMode::NativeDeadlist,
                    auxiliary_ownership: Some((owner, auxiliary)),
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
                let directory = owner == 6;
                let name: &[u8] = if directory { b"sub" } else { b"hello.txt" };
                let replacement = if directory {
                    engine
                        .mkdir(&cx, &dataset, 2, b"replacement", 0o755, 0, 0, timestamp)
                        .into_result()
                        .unwrap()
                        .0
                } else {
                    engine
                        .create_file(
                            &cx,
                            &dataset,
                            2,
                            b"replacement",
                            0o600,
                            0,
                            0,
                            timestamp,
                            ZfsDataChecksum::Fletcher4,
                        )
                        .into_result()
                        .unwrap()
                        .0
                };
                let before: Vec<_> = devices
                    .iter()
                    .map(FaultableMemberDevice::durable_snapshot)
                    .collect();
                if auxiliary == AuxiliaryOwnership::ExternalAcl {
                    assert_native_write_refused(
                        &mut engine,
                        &devices,
                        libc::EOPNOTSUPP,
                        |writer| writer.unlink_entry(&cx, &dataset, 2, name, directory, timestamp),
                    );
                    assert_native_write_refused(
                        &mut engine,
                        &devices,
                        libc::EOPNOTSUPP,
                        |writer| {
                            writer.rename_entry(
                                &cx,
                                &dataset,
                                2,
                                b"replacement",
                                2,
                                name,
                                Some(replacement),
                                timestamp,
                            )
                        },
                    );
                }
                for (device, bytes) in devices.iter().zip(&before) {
                    let media = device.state.lock().unwrap();
                    assert_eq!(&media.durable, bytes);
                    assert!(media.volatile.is_empty());
                }

                if directory {
                    engine
                        .unlink_entry(&cx, &dataset, 2, b"replacement", true, timestamp)
                        .into_result()
                        .unwrap();
                } else {
                    // Removing one of several links retains the owner and its
                    // auxiliary tree. Both unlink and replacement must remain
                    // usable rather than refusing every attributed file.
                    engine
                        .link_entry(&cx, &dataset, owner, 2, b"alias", timestamp)
                        .into_result()
                        .unwrap();
                    engine
                        .unlink_entry(&cx, &dataset, 2, b"alias", false, timestamp)
                        .into_result()
                        .unwrap();
                    engine
                        .link_entry(&cx, &dataset, owner, 2, b"alias", timestamp)
                        .into_result()
                        .unwrap();
                    engine
                        .rename_entry(
                            &cx,
                            &dataset,
                            2,
                            b"replacement",
                            2,
                            b"alias",
                            Some(replacement),
                            timestamp,
                        )
                        .into_result()
                        .unwrap();
                    engine
                        .unlink_entry(&cx, &dataset, 2, b"alias", false, timestamp)
                        .into_result()
                        .unwrap();
                }

                // Moving the attributed owner itself never reclaims it.
                engine
                    .rename_entry(
                        &cx,
                        &dataset,
                        2,
                        name,
                        2,
                        b"preserved",
                        Some(owner),
                        timestamp,
                    )
                    .into_result()
                    .unwrap();
                let slot = engine.committed_slot();
                let fresh: Vec<_> = devices
                    .iter()
                    .map(FaultableMemberDevice::fresh_from_durable)
                    .collect();
                let mut reopened =
                    open_engine_on_devices(&cx, &fresh, default_write_opts(built.pool_guid, slot))
                        .unwrap();
                let mut mos = reopened.open_read_objects(&cx).unwrap();
                let mut zpl = mos.zpl(&cx, &dataset).unwrap();
                assert_eq!(zpl.resolve(&cx, b"/preserved").unwrap(), owner);
                assert_eq!(
                    zpl.stat(&cx, owner).unwrap().0.links,
                    if directory { 2 } else { 1 }
                );
                if auxiliary == AuxiliaryOwnership::XattrDirectory {
                    assert_eq!(
                        zpl.getxattr(&cx, owner, "user.retained").unwrap(),
                        Some(b"private value survives namespace changes".to_vec())
                    );
                }
                if !directory {
                    assert_eq!(
                        zpl.read(&cx, owner, 0, built.snap_hello_expected.len())
                            .unwrap(),
                        built.snap_hello_expected
                    );
                }
                if auxiliary == AuxiliaryOwnership::XattrDirectory {
                    reopened
                        .unlink_entry(&cx, &dataset, 2, b"preserved", directory, timestamp)
                        .into_result()
                        .unwrap();
                    let mut head = reopened
                        .open_read_objects(&cx)
                        .unwrap()
                        .zpl(&cx, &dataset)
                        .unwrap();
                    for object in [owner, 13, 14] {
                        assert!(matches!(head.stat(&cx, object), Err(FfsError::NotFound(_))));
                    }
                    let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
                    assert_eq!(
                        snapshot.getxattr(&cx, owner, "user.retained").unwrap(),
                        Some(b"private value survives namespace changes".to_vec())
                    );
                } else {
                    assert_native_write_refused(
                        &mut reopened,
                        &fresh,
                        libc::EOPNOTSUPP,
                        |writer| {
                            writer.unlink_entry(
                                &cx,
                                &dataset,
                                2,
                                b"preserved",
                                directory,
                                timestamp,
                            )
                        },
                    );
                }
                assert_pool_scrub_and_allocation_clean(
                    &cx,
                    &fresh,
                    built.pool_guid,
                    Some(reopened.committed_slot()),
                );
            }
        }
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
fn rename_exchange_preserves_objects_parents_snapshots_and_spilled_metadata() {
    let cx = Cx::for_testing();
    let ds = [b"data".to_vec()];
    let ts = Timestamp {
        seconds: 1_715_000_280,
        nanos: 37,
    };
    for (zpl_version, ashift, mirror_width, spill, deadlist_mode) in [
        (4, 9, 1, false, DeadlistMode::Bpobj),
        (5, 12, 2, false, DeadlistMode::NativeDeadlist),
        (5, 9, 1, true, DeadlistMode::NativeDeadlist),
    ] {
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            zpl_version,
            ashift,
            mirror_width,
            with_sa_spill: spill,
            user_accounting: zpl_version == 5,
            deadlist_mode,
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
        let nested = engine
            .mkdir(&cx, &ds, 6, b"nested", 0o750, 1000, 1001, ts)
            .into_result()
            .unwrap()
            .0;
        engine
            .link_entry(&cx, &ds, 4, nested, b"kept", ts)
            .into_result()
            .unwrap();
        let (source, target, root_before, parent_before, file_before) = {
            let mut mos = engine.open_read_objects(&cx).unwrap();
            let mut head = mos.zpl(&cx, &ds).unwrap();
            let file = head.stat(&cx, 4).unwrap().0;
            let directory = head.stat(&cx, nested).unwrap().0;
            (
                ZfsObjectIdentity {
                    object: 4,
                    generation: file.generation,
                },
                ZfsObjectIdentity {
                    object: nested,
                    generation: directory.generation,
                },
                head.stat(&cx, 2).unwrap().0,
                head.stat(&cx, 6).unwrap().0,
                file,
            )
        };
        let txg_before = engine.committed_txg();
        engine
            .exchange_entries(&cx, &ds, 2, b"hello.txt", 6, b"nested", source, target, ts)
            .into_result()
            .unwrap();
        assert_eq!(engine.committed_txg(), txg_before + 1);
        // The old guards refuse an accidental retry instead of swapping back.
        assert_native_write_refused(&mut engine, &devices, libc::ESTALE, |writer| {
            writer.exchange_entries(&cx, &ds, 2, b"hello.txt", 6, b"nested", source, target, ts)
        });
        let fresh: Vec<_> = devices
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
        assert_eq!(head.resolve(&cx, b"/hello.txt").unwrap(), nested);
        assert_eq!(head.resolve(&cx, b"/hello.txt/kept").unwrap(), 4);
        assert_eq!(head.resolve(&cx, b"/sub/nested").unwrap(), 4);
        let file = head.stat(&cx, 4).unwrap().0;
        let directory = head.stat(&cx, nested).unwrap().0;
        let root = head.stat(&cx, 2).unwrap().0;
        let parent = head.stat(&cx, 6).unwrap().0;
        assert_eq!((file.parent, directory.parent), (6, 2));
        assert_eq!(
            (file.links, file.generation, file.size),
            (file_before.links, file_before.generation, file_before.size)
        );
        assert_eq!(
            (file.times[0], file.times[1], file.times[3]),
            (
                file_before.times[0],
                file_before.times[1],
                file_before.times[3]
            )
        );
        assert_eq!((file.times[2], directory.times[2]), (ts, ts));
        assert_eq!(
            (root.size, parent.size),
            (root_before.size, parent_before.size)
        );
        assert_eq!(
            (root.links, parent.links),
            (root_before.links + 1, parent_before.links - 1)
        );
        assert_eq!(
            head.read(&cx, 4, 0, 8192).unwrap(),
            built.snap_hello_expected
        );
        let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
        assert_eq!(snapshot.resolve(&cx, b"/hello.txt").unwrap(), 4);
        assert_eq!(snapshot.stat(&cx, 4).unwrap().0.links, 1);
        assert!(matches!(
            snapshot.resolve(&cx, b"/sub/nested"),
            Err(FfsError::NotFound(_))
        ));
        assert_eq!(
            snapshot.read(&cx, 4, 0, 8192).unwrap(),
            built.snap_hello_expected
        );
        assert_pool_scrub_and_allocation_clean(&cx, &fresh, built.pool_guid, None);
    }
}

#[test]
fn rename_exchange_rejects_stale_missing_and_cyclic_entries_before_writes() {
    let cx = Cx::for_testing();
    let ds = [b"data".to_vec()];
    let ts = Timestamp {
        seconds: 1_715_000_285,
        nanos: 0,
    };
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        deadlist_mode: DeadlistMode::NativeDeadlist,
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
    let child = engine
        .create_file(
            &cx,
            &ds,
            6,
            b"child",
            0o600,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap()
        .0;
    let (file, other, directory, nested) = {
        let mut mos = engine.open_read_objects(&cx).unwrap();
        let mut head = mos.zpl(&cx, &ds).unwrap();
        let mut identity = |object| ZfsObjectIdentity {
            object,
            generation: head.stat(&cx, object).unwrap().0.generation,
        };
        (identity(4), identity(5), identity(6), identity(child))
    };
    for (source, target) in [
        (
            ZfsObjectIdentity {
                generation: file.generation + 1,
                ..file
            },
            other,
        ),
        (
            file,
            ZfsObjectIdentity {
                generation: other.generation + 1,
                ..other
            },
        ),
        (other, file),
    ] {
        assert_native_write_refused(&mut engine, &devices, libc::ESTALE, |writer| {
            writer.exchange_entries(
                &cx,
                &ds,
                2,
                b"hello.txt",
                2,
                b"keep.bin",
                source,
                target,
                ts,
            )
        });
    }
    assert_native_write_refused(&mut engine, &devices, libc::ENOENT, |writer| {
        writer.exchange_entries(&cx, &ds, 2, b"hello.txt", 2, b"missing", file, other, ts)
    });
    // Each orientation exercises a different proposed directory parent edge.
    assert_native_write_refused(&mut engine, &devices, libc::EINVAL, |writer| {
        writer.exchange_entries(&cx, &ds, 2, b"sub", 6, b"child", directory, nested, ts)
    });
    assert_native_write_refused(&mut engine, &devices, libc::EINVAL, |writer| {
        writer.exchange_entries(&cx, &ds, 6, b"child", 2, b"sub", nested, directory, ts)
    });
    assert_native_write_refused(&mut engine, &devices, libc::EINVAL, |writer| {
        writer.exchange_entries(
            &cx,
            &ds,
            2,
            b"../hello.txt",
            2,
            b"keep.bin",
            file,
            other,
            ts,
        )
    });
}

#[test]
fn rename_exchange_respects_native_flags_on_both_objects_and_parents() {
    let cx = Cx::for_testing();
    let ds = [b"data".to_vec()];
    let ts = Timestamp {
        seconds: 1_715_000_286,
        nanos: 0,
    };
    for (object, flag) in [
        (4, 0x0000_0010_0000_0000), // immutable source
        (5, 0x0000_0040_0000_0000), // append-only target
        (5, 0x0000_0020_0000_0000), // nounlink target
        (2, 0x0000_0040_0000_0000), // append-only parent
    ] {
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            zpl_flags: BTreeMap::from([(object, flag)]),
            deadlist_mode: DeadlistMode::NativeDeadlist,
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
        let (source, target) = {
            let mut mos = engine.open_read_objects(&cx).unwrap();
            let mut head = mos.zpl(&cx, &ds).unwrap();
            (
                ZfsObjectIdentity {
                    object: 4,
                    generation: head.stat(&cx, 4).unwrap().0.generation,
                },
                ZfsObjectIdentity {
                    object: 5,
                    generation: head.stat(&cx, 5).unwrap().0.generation,
                },
            )
        };
        assert_native_write_refused(&mut engine, &devices, libc::EPERM, |writer| {
            writer.exchange_entries(
                &cx,
                &ds,
                2,
                b"hello.txt",
                2,
                b"keep.bin",
                source,
                target,
                ts,
            )
        });
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn rename_exchange_persistence_cuts_never_publish_half_a_swap() {
    let cx = Cx::for_testing();
    let ds = [b"data".to_vec()];
    let ts = Timestamp {
        seconds: 1_715_000_287,
        nanos: 0,
    };
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        mirror_width: 2,
        deadlist_mode: DeadlistMode::NativeDeadlist,
        ..PoolFixtureSpec::default()
    });
    let seed_devices: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut seed = open_engine_on_devices(
        &cx,
        &seed_devices,
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    let nested = seed
        .mkdir(&cx, &ds, 6, b"nested", 0o755, 0, 0, ts)
        .into_result()
        .unwrap()
        .0;
    seed.link_entry(&cx, &ds, 4, nested, b"kept", ts)
        .into_result()
        .unwrap();
    let (source, target, old_root_links, old_parent_links, old_file_parent) = {
        let mut mos = seed.open_read_objects(&cx).unwrap();
        let mut head = mos.zpl(&cx, &ds).unwrap();
        (
            ZfsObjectIdentity {
                object: 4,
                generation: head.stat(&cx, 4).unwrap().0.generation,
            },
            ZfsObjectIdentity {
                object: nested,
                generation: head.stat(&cx, nested).unwrap().0.generation,
            },
            head.stat(&cx, 2).unwrap().0.links,
            head.stat(&cx, 6).unwrap().0.links,
            head.stat(&cx, 4).unwrap().0.parent,
        )
    };
    let initial_slot = seed.committed_slot();
    let initial_txg = seed.committed_txg();
    let initial: Vec<_> = seed_devices
        .iter()
        .map(FaultableMemberDevice::durable_snapshot)
        .collect();
    drop(seed);
    let operation = |engine: &mut ZfsTransactionEngine| {
        engine.exchange_entries(&cx, &ds, 2, b"hello.txt", 6, b"nested", source, target, ts)
    };
    let probe_devices: Vec<_> = initial
        .iter()
        .cloned()
        .map(FaultableMemberDevice::new)
        .collect();
    let mut probe = open_engine_on_devices(
        &cx,
        &probe_devices,
        default_write_opts(built.pool_guid, initial_slot),
    )
    .unwrap();
    operation(&mut probe).into_result().unwrap();
    let events = probe.persistence_events().to_vec();
    let first_publish = events
        .iter()
        .find(|event| matches!(event.stage, ZfsPersistenceStage::UberblockWrite { .. }))
        .unwrap()
        .seq;
    let acknowledged = events
        .iter()
        .find(|event| event.stage == ZfsPersistenceStage::BeforeAcknowledge)
        .unwrap()
        .seq;
    assert!(
        events.len() >= 7,
        "must execute every native publication stage"
    );
    for cut in events {
        for reorder in [false, true] {
            let devices: Vec<_> = initial
                .iter()
                .cloned()
                .map(FaultableMemberDevice::new)
                .collect();
            let mut engine = open_engine_on_devices(
                &cx,
                &devices,
                default_write_opts(built.pool_guid, initial_slot),
            )
            .unwrap();
            let sequence = cut.seq;
            engine.with_fault_hook(move |event| {
                if event.seq == sequence {
                    Err(FfsError::Cancelled)
                } else {
                    Ok(())
                }
            });
            let outcome = operation(&mut engine);
            if sequence <= first_publish {
                assert!(
                    matches!(outcome, ZfsTxOutcome::NotCommitted(_)),
                    "{:?}",
                    cut.stage
                );
            } else if sequence < acknowledged {
                assert!(
                    matches!(outcome, ZfsTxOutcome::Uncertain { .. }),
                    "{:?}",
                    cut.stage
                );
            } else {
                assert!(outcome.is_committed(), "{:?}", cut.stage);
            }
            for device in &devices {
                let mut media = device.state.lock().unwrap();
                if reorder {
                    media.crash_reorder_and_drop_half_unsynced();
                } else {
                    media.crash_drop_unsynced();
                }
            }
            // Rebuild the reader from only durable media, never the old cache.
            let leaves = devices
                .iter()
                .map(|device| {
                    let fresh = device.fresh_from_durable();
                    let len = fresh.len_bytes();
                    Leaf::from_device(&cx, Box::new(fresh), 0, len).unwrap()
                })
                .collect();
            let pool = Pool::from_leaves(leaves).unwrap();
            let mut mos = pool.import_objects(&cx, Some(built.pool_guid)).unwrap();
            assert!([initial_txg, initial_txg + 1].contains(&mos.txg));
            let swapped = mos.txg == initial_txg + 1;
            if sequence <= first_publish {
                assert!(!swapped);
            }
            if sequence >= acknowledged {
                assert!(swapped);
            }
            let mut head = mos.zpl(&cx, &ds).unwrap();
            let root_entry = head.resolve(&cx, b"/hello.txt").unwrap();
            let nested_entry = head.resolve(&cx, b"/sub/nested").unwrap();
            assert_eq!(
                (root_entry, nested_entry),
                if swapped {
                    (target.object, source.object)
                } else {
                    (source.object, target.object)
                }
            );
            assert_eq!(
                head.stat(&cx, source.object).unwrap().0.parent,
                if swapped { 6 } else { old_file_parent }
            );
            assert_eq!(
                head.stat(&cx, target.object).unwrap().0.parent,
                if swapped { 2 } else { 6 }
            );
            assert_eq!(
                head.stat(&cx, 2).unwrap().0.links,
                old_root_links + u64::from(swapped)
            );
            assert_eq!(
                head.stat(&cx, 6).unwrap().0.links,
                old_parent_links - u64::from(swapped)
            );
            assert_eq!(head.stat(&cx, source.object).unwrap().0.links, 2);
            assert_eq!(
                head.read(&cx, source.object, 0, 8192).unwrap(),
                built.snap_hello_expected
            );
            let child: &[u8] = if swapped {
                b"/hello.txt/kept"
            } else {
                b"/sub/nested/kept"
            };
            assert_eq!(head.resolve(&cx, child).unwrap(), source.object);
            let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
            assert_eq!(snapshot.resolve(&cx, b"/hello.txt").unwrap(), source.object);
            assert_eq!(
                snapshot.read(&cx, source.object, 0, 8192).unwrap(),
                built.snap_hello_expected
            );
            assert_pool_scrub_and_allocation_clean(&cx, &devices, built.pool_guid, None);
        }
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
            // Fault hooks run before their device operation: the first
            // UberblockWrite cut has not attempted publication yet.
            if seq <= first_uberblock_seq {
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
            if seq <= first_uberblock_seq {
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

#[test]
fn native_unlinked_reclamation_rejects_stale_or_unowned_objects_without_writes() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let ts = Timestamp {
        seconds: 1_715_000_300,
        nanos: 17,
    };
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        deadlist_mode: DeadlistMode::NativeDeadlist,
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
        default_write_opts(POOL_GUID, built.initial_slot),
    )
    .unwrap();
    let mut head = engine
        .open_read_objects(&cx)
        .unwrap()
        .zpl(&cx, &dataset)
        .unwrap();
    let object = head.resolve(&cx, b"/hello.txt").unwrap();
    let identity = ZfsUnlinkedObject {
        object,
        generation: head.stat(&cx, object).unwrap().0.generation,
    };
    let stale = ZfsUnlinkedObject {
        generation: identity.generation + 1,
        ..identity
    };
    assert_native_write_refused(&mut engine, &devices, libc::ENOENT, |writer| {
        writer.reap_unlinked_file(&cx, &dataset, identity)
    });
    assert_native_write_refused(&mut engine, &devices, libc::ESTALE, |writer| {
        writer.unlink_open_file(&cx, &dataset, 2, b"hello.txt", stale, ts)
    });
    engine
        .unlink_open_file(&cx, &dataset, 2, b"hello.txt", identity, ts)
        .into_result()
        .unwrap();
    assert_eq!(
        engine.pending_unlinks(&cx, &dataset).unwrap(),
        vec![identity]
    );
    assert_native_write_refused(&mut engine, &devices, libc::ESTALE, |writer| {
        writer.reap_unlinked_file(&cx, &dataset, stale)
    });
    engine
        .reap_unlinked_file(&cx, &dataset, identity)
        .into_result()
        .unwrap();
    assert_eq!(
        engine.pending_unlinks(&cx, &dataset).unwrap(),
        [] as [ZfsUnlinkedObject; 0]
    );
    let (reused, _) = engine
        .create_file(
            &cx,
            &dataset,
            2,
            b"reused",
            0o600,
            1000,
            1000,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    assert_eq!(
        reused, object,
        "fixture must exercise native object slot reuse"
    );
    assert_native_write_refused(&mut engine, &devices, libc::ENOENT, |writer| {
        writer.reap_unlinked_file(&cx, &dataset, identity)
    });
    let mut head = engine
        .open_read_objects(&cx)
        .unwrap()
        .zpl(&cx, &dataset)
        .unwrap();
    assert_ne!(
        head.stat(&cx, reused).unwrap().0.generation,
        identity.generation
    );
    assert_eq!(head.resolve(&cx, b"/reused").unwrap(), reused);
    assert_pool_scrub_and_allocation_clean(&cx, &devices, POOL_GUID, None);
}

#[test]
fn native_unlink_and_reap_persistence_cuts_preserve_queue_namespace_and_snapshots() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let ts = Timestamp {
        seconds: 1_715_000_301,
        nanos: 19,
    };
    for reaping in [false, true] {
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            mirror_width: 2,
            deadlist_mode: DeadlistMode::NativeDeadlist,
            user_accounting: true,
            ..PoolFixtureSpec::default()
        });
        let seed_devices: Vec<_> = built
            .members
            .iter()
            .cloned()
            .map(FaultableMemberDevice::new)
            .collect();
        let mut seed = open_engine_on_devices(
            &cx,
            &seed_devices,
            default_write_opts(POOL_GUID, built.initial_slot),
        )
        .unwrap();
        let mut seed_head = seed
            .open_read_objects(&cx)
            .unwrap()
            .zpl(&cx, &dataset)
            .unwrap();
        let object = seed_head.resolve(&cx, b"/hello.txt").unwrap();
        let identity = ZfsUnlinkedObject {
            object,
            generation: seed_head.stat(&cx, object).unwrap().0.generation,
        };
        if reaping {
            seed.unlink_open_file(&cx, &dataset, 2, b"hello.txt", identity, ts)
                .into_result()
                .unwrap();
        }
        let initial_slot = seed.committed_slot();
        let initial_txg = seed.committed_txg();
        let initial: Vec<_> = seed_devices
            .iter()
            .map(FaultableMemberDevice::durable_snapshot)
            .collect();
        drop(seed);
        let operation = |engine: &mut ZfsTransactionEngine| {
            if reaping {
                engine.reap_unlinked_file(&cx, &dataset, identity)
            } else {
                engine.unlink_open_file(&cx, &dataset, 2, b"hello.txt", identity, ts)
            }
        };
        let probe_devices: Vec<_> = initial
            .iter()
            .cloned()
            .map(FaultableMemberDevice::new)
            .collect();
        let mut probe = open_engine_on_devices(
            &cx,
            &probe_devices,
            default_write_opts(POOL_GUID, initial_slot),
        )
        .unwrap();
        let (_, token) = operation(&mut probe).into_result().unwrap();
        let events = probe.persistence_events().to_vec();
        let first_publish = events
            .iter()
            .find(|event| matches!(event.stage, ZfsPersistenceStage::UberblockWrite { .. }))
            .unwrap()
            .seq;
        let acknowledged = events
            .iter()
            .find(|event| event.stage == ZfsPersistenceStage::BeforeAcknowledge)
            .unwrap()
            .seq;
        for cut in events {
            for reorder in [false, true] {
                let devices: Vec<_> = initial
                    .iter()
                    .cloned()
                    .map(FaultableMemberDevice::new)
                    .collect();
                let mut engine = open_engine_on_devices(
                    &cx,
                    &devices,
                    default_write_opts(POOL_GUID, initial_slot),
                )
                .unwrap();
                let sequence = cut.seq;
                engine.with_fault_hook(move |event| {
                    if event.seq == sequence {
                        Err(FfsError::Cancelled)
                    } else {
                        Ok(())
                    }
                });
                let outcome = operation(&mut engine);
                if sequence <= first_publish {
                    assert!(
                        matches!(outcome, ZfsTxOutcome::NotCommitted(_)),
                        "{reaping} {:?}",
                        cut.stage
                    );
                } else if sequence < acknowledged {
                    assert!(
                        matches!(outcome, ZfsTxOutcome::Uncertain { .. }),
                        "{reaping} {:?}",
                        cut.stage
                    );
                } else {
                    assert!(outcome.is_committed(), "{reaping} {:?}", cut.stage);
                }
                drop(engine);
                for device in &devices {
                    let mut media = device.state.lock().unwrap();
                    if reorder {
                        media.crash_reorder_and_drop_half_unsynced();
                    } else {
                        media.crash_drop_unsynced();
                    }
                }
                let leaves = devices
                    .iter()
                    .map(|device| {
                        let fresh = device.fresh_from_durable();
                        let len = fresh.len_bytes();
                        Leaf::from_device(&cx, Box::new(fresh), 0, len).unwrap()
                    })
                    .collect();
                let mut mos = Pool::from_leaves(leaves)
                    .unwrap()
                    .import_objects(&cx, Some(POOL_GUID))
                    .unwrap();
                assert!([initial_txg, initial_txg + 1].contains(&mos.txg));
                let published = mos.txg == initial_txg + 1;
                if sequence <= first_publish {
                    assert!(!published);
                }
                if sequence >= acknowledged {
                    assert!(published);
                }
                let mut head = mos.zpl(&cx, &dataset).unwrap();
                let removed = reaping || published;
                assert_eq!(
                    matches!(head.resolve(&cx, b"/hello.txt"), Err(FfsError::NotFound(_))),
                    removed
                );
                if reaping && published {
                    assert!(head.stat(&cx, object).is_err());
                } else {
                    assert_eq!(head.stat(&cx, object).unwrap().0.links, u64::from(!removed));
                    assert_eq!(
                        head.read(&cx, object, 0, 8192).unwrap(),
                        built.snap_hello_expected
                    );
                }
                let mut snapshot = head.open_snapshot(&cx, b"before").unwrap();
                assert_eq!(
                    snapshot.read(&cx, object, 0, 8192).unwrap(),
                    built.snap_hello_expected
                );
                assert_eq!(snapshot.stat(&cx, object).unwrap().0.links, 1);
                assert_pool_scrub_and_allocation_clean(&cx, &devices, POOL_GUID, None);

                // Explicit native-ring reconciliation preserves the root selected
                // above; it does not replay or change the dataset's queue.
                let slot = if published {
                    token.published_slot()
                } else {
                    initial_slot
                };
                let mut options = default_write_opts(POOL_GUID, slot);
                options.reconcile_torn_uberblocks = true;
                let recovered = open_engine_on_devices(&cx, &devices, options).unwrap();
                let queue = recovered.pending_unlinks(&cx, &dataset).unwrap();
                assert_eq!(
                    queue,
                    if reaping == published {
                        Vec::new()
                    } else {
                        vec![identity]
                    }
                );
            }
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

    // A. Cut at EVERY event through the first prewrite Uberblock hook (including
    // reordered/dropped volatile cache). The hook runs before the write itself.
    // Every cut MUST return `ZfsTxOutcome::NotCommitted`, leave `INITIAL_TXG` 100% intact on fresh engine,
    // and allow a subsequent TXG to commit with zero leaks!
    for cut_ev in recorded_events.iter().take(first_ub_pos + 1) {
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
    let mut head = eng.open_read_objects(&cx).unwrap().zpl(&cx, &ds).unwrap();
    let retained = ZfsUnlinkedObject {
        object: fobj,
        generation: head.stat(&cx, fobj).unwrap().0.generation,
    };
    drop(head);
    let (_, retained_token) = eng
        .unlink_open_file(&cx, &ds, sub_dir, b"verified.bin", retained, ts)
        .into_result()
        .unwrap();
    drop(eng);

    // The native checker must accept both a live unlinked-set member and the
    // fully reclaimed state; self-round-trip is not the allocation oracle.
    run_zdb_check(
        &zdb,
        ld_path.as_deref(),
        dir.path(),
        "ffszdbpool",
        &img_path,
    );
    let mut eng = ZfsTransactionEngine::open_files(
        &cx,
        &[img_path.as_path()],
        default_write_opts(built.pool_guid, retained_token.published_slot()),
    )
    .unwrap();
    assert_eq!(eng.pending_unlinks(&cx, &ds).unwrap(), vec![retained]);
    eng.reap_unlinked_file(&cx, &ds, retained)
        .into_result()
        .unwrap();
    assert_eq!(
        eng.pending_unlinks(&cx, &ds).unwrap(),
        [] as [ZfsUnlinkedObject; 0]
    );
    drop(eng);
    run_zdb_check(
        &zdb,
        ld_path.as_deref(),
        dir.path(),
        "ffszdbpool",
        &img_path,
    );
}

#[test]
fn reconciliation_refuses_unadmitted_writers_without_rewriting_any_member() {
    let cx = Cx::for_testing();
    for (mirror_width, ashift) in [(1, 9), (1, 12), (2, 9), (2, 12)] {
        for dirty_zil in [false, true] {
            for torn in [false, true] {
                let spec = PoolFixtureSpec {
                    mirror_width,
                    ashift,
                    dirty_zil,
                    additional_write_features: if dirty_zil {
                        Vec::new()
                    } else {
                        vec![(b"org.openzfs:device_rebuild", 1)]
                    },
                    ..PoolFixtureSpec::default()
                };
                let mut built = build_clean_zfs_pool(&spec);
                if torn {
                    let offsets = label_offsets(spec.image_bytes).unwrap();
                    let slot_bytes = 1_usize << spec.ashift.max(10);
                    for member in &mut built.members {
                        for label in [2, 3] {
                            let offset = offsets[label]
                                + UBERBLOCK_RING_OFFSET
                                + (built.initial_slot * slot_bytes) as u64;
                            let start = usize::try_from(offset).unwrap();
                            member[start..start + slot_bytes].fill(0);
                        }
                    }
                }
                let devices: Vec<_> = built
                    .members
                    .into_iter()
                    .map(FaultableMemberDevice::new)
                    .collect();
                let before: Vec<_> = devices
                    .iter()
                    .map(FaultableMemberDevice::durable_snapshot)
                    .collect();
                let result = open_engine_on_devices(
                    &cx,
                    &devices,
                    ZfsWriteOptions {
                        reconcile_torn_uberblocks: true,
                        ..default_write_opts(built.pool_guid, built.initial_slot)
                    },
                );
                match result {
                    Err(FfsError::UnsupportedFeature(reason)) => {
                        let expected = if dirty_zil {
                            "pending ZIL"
                        } else {
                            "active ZFS write feature org.openzfs:device_rebuild"
                        };
                        assert!(reason.contains(expected), "{reason}");
                    }
                    Err(error) => panic!("unexpected admission error: {error}"),
                    Ok(_) => panic!("unadmitted writer was accepted"),
                }
                for (device, original) in devices.iter().zip(&before) {
                    let media = device.state.lock().unwrap();
                    assert_eq!(
                        (media.write_calls, media.sync_calls),
                        (0, 0),
                        "rejected writer touched media: mirror={mirror_width}, ashift={ashift}, dirty_zil={dirty_zil}, torn={torn}"
                    );
                    assert!(media.volatile.is_empty());
                    assert_eq!(media.durable.as_slice(), original.as_slice());
                }
            }
        }
    }
}

#[test]
fn direct_zfs_publication_defers_every_mirror_member_until_final_barrier() {
    let cx = Cx::for_testing();
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        mirror_width: 2,
        ..PoolFixtureSpec::default()
    });
    let members: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let options = ZfsWriteOptions {
        reconcile_torn_uberblocks: true,
        ..default_write_opts(built.pool_guid, built.initial_slot)
    };
    let mut engine = open_engine_on_devices(&cx, &members, options).unwrap();
    let protection =
        |s: &MemberMediaState| (s.protection_depth, s.protection_completed, s.unprotected_io);
    for member in &members {
        let state = member.state.lock().unwrap();
        assert_eq!((state.write_calls, state.sync_calls), (4, 2));
        assert_eq!(protection(&state), (0, 1, 0));
    }
    let create = |engine: &mut ZfsTransactionEngine, name: &[u8]| {
        engine.create_file(
            &cx,
            &[b"data".to_vec()],
            2,
            name,
            0o644,
            0,
            0,
            Timestamp {
                seconds: 1_715_000_500,
                nanos: 0,
            },
            ZfsDataChecksum::Fletcher4,
        )
    };

    // Failure to admit the second member unwinds the first before any source write.
    members[1].state.lock().unwrap().refuse_protection = true;
    assert!(matches!(
        create(&mut engine, b"refused"),
        ZfsTxOutcome::NotCommitted(FfsError::ReadOnly)
    ));
    for (i, member) in members.iter().enumerate() {
        let state = member.state.lock().unwrap();
        assert_eq!((state.write_calls, state.sync_calls), (4, 2));
        assert_eq!(
            (state.protection_depth, state.protection_aborted),
            (0, usize::from(i == 0))
        );
    }
    members[1].state.lock().unwrap().refuse_protection = false;

    engine.begin_durability_commit(&cx).unwrap();
    let (_, token) = create(&mut engine, b"protected").into_result().unwrap();
    engine.verify_token(&token).unwrap();
    for member in &members {
        let state = member.state.lock().unwrap();
        assert!(state.sync_calls > 4);
        assert_eq!(protection(&state), (1, 2, 0));
    }
    engine.complete_durability_commit();
    engine.sync_devices(&cx).unwrap();
    for member in &members {
        let state = member.state.lock().unwrap();
        assert_eq!(protection(&state), (0, 3, 1));
    }

    // A second-wave fault makes the native outcome uncertain. Neither member
    // may report completion or run an unprotected barrier over that epoch.
    engine.with_fault_hook(|event| {
        if matches!(
            event.stage,
            ZfsPersistenceStage::UberblockBarrier { wave: 2, .. }
        ) {
            return Err(FfsError::Io(std::io::Error::other("cut final publication")));
        }
        Ok(())
    });
    assert!(matches!(
        create(&mut engine, b"cut"),
        ZfsTxOutcome::Uncertain { .. }
    ));
    for (i, member) in members.iter().enumerate() {
        let state = member.state.lock().unwrap();
        assert_eq!(protection(&state), (0, 3, 1));
        assert_eq!(state.protection_aborted, 1 + usize::from(i == 0));
    }
}

#[test]
fn native_writer_sync_reports_member_errors_without_minting_a_commit() {
    let cx = Cx::for_testing();
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        mirror_width: 2,
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
    assert!(!engine.requires_recovery());
    assert_eq!(engine.free_bytes(), engine.admission_report().free_bytes);
    let timestamp = Timestamp {
        seconds: 1_715_000_500,
        nanos: 0,
    };
    let (_, token) = engine
        .create_file(
            &cx,
            &[b"data".to_vec()],
            2,
            b"synced.txt",
            0o644,
            0,
            0,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let free_bytes = engine.free_bytes();
    let allocated_bytes = engine.allocated_bytes();
    assert_eq!(
        free_bytes + allocated_bytes,
        engine.storage_identity().asize
    );
    let before: Vec<_> = devices
        .iter()
        .map(|device| {
            let state = device.state.lock().unwrap();
            (state.write_calls, state.sync_calls)
        })
        .collect();
    devices[1].set_fault(DeviceFault::FailSyncOnCall {
        sync_index: before[1].1,
    });
    assert!(matches!(engine.sync_devices(&cx), Err(FfsError::Io(_))));
    assert!(!engine.requires_recovery());
    assert_eq!(engine.committed_txg(), token.committed_txg());
    assert_eq!(engine.committed_slot(), token.published_slot());
    engine.verify_token(&token).unwrap();
    assert_eq!(engine.free_bytes(), free_bytes);
    assert_eq!(engine.allocated_bytes(), allocated_bytes);
    for (device, &(writes, syncs)) in devices.iter().zip(&before) {
        let state = device.state.lock().unwrap();
        assert_eq!(state.write_calls, writes);
        assert_eq!(state.sync_calls, syncs + 1);
    }
    devices[1].set_fault(DeviceFault::None);
    engine.sync_devices(&cx).unwrap();

    engine.with_fault_hook(|event| {
        if matches!(
            event.stage,
            ZfsPersistenceStage::UberblockWrite { label: 1, .. }
        ) {
            Err(FfsError::Io(std::io::Error::other(
                "cut during root publication",
            )))
        } else {
            Ok(())
        }
    });
    assert!(matches!(
        engine.mkdir(
            &cx,
            &[b"data".to_vec()],
            2,
            b"uncertain",
            0o755,
            0,
            0,
            timestamp
        ),
        ZfsTxOutcome::Uncertain { .. }
    ));
    assert!(engine.requires_recovery());
    let syncs: Vec<_> = devices
        .iter()
        .map(|device| device.state.lock().unwrap().sync_calls)
        .collect();
    assert!(matches!(
        engine.sync_devices(&cx),
        Err(FfsError::UnsupportedFeature(_))
    ));
    for (device, syncs) in devices.iter().zip(syncs) {
        assert_eq!(device.state.lock().unwrap().sync_calls, syncs);
    }
}

#[test]
fn zeroed_replica_uberblock_slot_reports_split_uberblock_disagreement_without_writes() {
    let cx = Cx::for_testing();
    let spec = PoolFixtureSpec::default();
    let mut built = build_clean_zfs_pool(&spec);
    let offsets = label_offsets(spec.image_bytes).unwrap();
    let slot_bytes = 1_usize << spec.ashift.max(10);
    let l3_slot_start = usize::try_from(
        offsets[3] + UBERBLOCK_RING_OFFSET + (built.initial_slot * slot_bytes) as u64,
    )
    .unwrap();
    built.members[0][l3_slot_start..l3_slot_start + 16].fill(0);

    let device = FaultableMemberDevice::new(built.members.remove(0));
    let before = device.durable_snapshot();
    let Err(err) = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&device),
        default_write_opts(built.pool_guid, built.initial_slot),
    ) else {
        panic!("split Uberblock without reconciliation must be refused");
    };
    match err {
        FfsError::Corruption { detail, .. } => {
            assert!(
                detail.contains("Uberblock slots disagree"),
                "expected split-Uberblock diagnostic, got: {detail}"
            );
        }
        other => panic!("expected FfsError::Corruption for split Uberblock, got: {other}"),
    }
    let media = device.state.lock().unwrap();
    assert_eq!((media.write_calls, media.sync_calls), (0, 0));
    assert_eq!(media.volatile.len(), 0);
    assert_eq!(media.durable.as_slice(), before.as_slice());
}

#[test]
fn exported_unclaimed_unwritten_zil_tail_admits_and_commits_cleanly() {
    let cx = Cx::for_testing();
    let mut built = build_clean_zfs_pool(&PoolFixtureSpec {
        zil_tail: ZilTailFixture::UnwrittenTail,
        ..PoolFixtureSpec::default()
    });
    let device = FaultableMemberDevice::new(built.members.remove(0));
    let mut engine = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&device),
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .expect("exported pool with unclaimed unwritten ZIL tail block should admit cleanly");
    assert!(engine.admission_report().admitted_clean_write);
    let timestamp = Timestamp {
        seconds: 1_715_001_000,
        nanos: 0,
    };
    let (file_obj, token) = engine
        .create_file(
            &cx,
            &[b"data".to_vec()],
            2,
            b"after_fsync_export.bin",
            0o640,
            0,
            0,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("create_file over dataset with unwritten ZIL tail should commit");
    let (_, token2) = engine
        .write_file_data(
            &cx,
            &[b"data".to_vec()],
            file_obj,
            0,
            b"preserved-zil-tail-dva",
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("write_file_data should commit");
    assert_eq!(
        engine.free_bytes() + engine.allocated_bytes(),
        engine.storage_identity().asize
    );

    // Reopen at the newly published slot and verify both MOS scrub/allocation and ZIL tail preservation.
    let reopened = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&device),
        default_write_opts(built.pool_guid, token2.published_slot()),
    )
    .expect("reopening after TXG commit should admit and verify space maps");
    reopened.verify_token(&token).unwrap_err();
    assert_eq!(reopened.committed_txg(), token2.committed_txg());
    let snap = device.fresh_from_durable();
    let len = snap.len_bytes();
    let leaf = Leaf::from_device(&cx, Box::new(snap), 0, len).expect("open fresh leaf");
    let pool = Pool::from_leaves(vec![leaf]).expect("open pool");
    let mut mos = pool
        .objects(&cx, 0, token2.published_slot(), built.pool_guid)
        .expect("open MOS");
    assert!(
        mos.scrub(&cx, ScrubLimits::default())
            .expect("MOS scrub")
            .is_clean()
    );
    let _ = mos
        .allocation(&cx, AllocationLimits::default())
        .expect("MOS space-map allocation check");
    let log = mos
        .intent_log(&cx, &[b"data".to_vec()])
        .expect("inspect preserved ZIL tail");
    assert_eq!(log.header.claim_txg, 0);
    assert_eq!(log.verified_blocks, 0);
    assert_eq!(log.records.len(), 0);
    assert_eq!(
        log.termination,
        ffs_zfs::reader::dmu::zil::Termination::UnverifiedTail
    );
}

#[test]
fn unclaimed_verified_zil_log_block_is_refused_without_writes() {
    let cx = Cx::for_testing();
    let mut built = build_clean_zfs_pool(&PoolFixtureSpec {
        zil_tail: ZilTailFixture::UnclaimedVerifiedRecord,
        ..PoolFixtureSpec::default()
    });
    let device = FaultableMemberDevice::new(built.members.remove(0));
    let before = device.durable_snapshot();
    let Err(err) = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&device),
        default_write_opts(built.pool_guid, built.initial_slot),
    ) else {
        panic!("unclaimed ZIL chain with verified uncommitted record must be refused");
    };
    match err {
        FfsError::UnsupportedFeature(detail) => {
            assert!(
                detail.contains("clean-only ZFS writer refuses pending ZIL on datasets: data"),
                "unexpected pending-ZIL refusal detail: {detail}"
            );
        }
        other => panic!("expected UnsupportedFeature for pending ZIL, got: {other}"),
    }
    let media = device.state.lock().unwrap();
    assert_eq!((media.write_calls, media.sync_calls), (0, 0));
    assert_eq!(media.volatile.len(), 0);
    assert_eq!(media.durable.as_slice(), before.as_slice());
}

#[test]
#[allow(clippy::too_many_lines)]
fn dsl_dataset_snapshot_clone_hold_bookmark_defer_destroy_and_reclamation() {
    let cx = Cx::for_testing();
    let mut built = build_clean_zfs_pool(&PoolFixtureSpec {
        image_bytes: 32 * 1024 * 1024,
        ashift: 9,
        zpl_version: 5,
        user_accounting: true,
        deadlist_mode: DeadlistMode::NativeDeadlist,
        additional_write_features: vec![(b"com.delphix:bookmarks", 0)],
        ..PoolFixtureSpec::default()
    });
    let initial_label_bytes = built.members[0][..usize::try_from(LABEL_BYTES).unwrap()].to_vec();
    let device = FaultableMemberDevice::new(built.members.remove(0));
    let mut engine = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&device),
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .expect("admit clean pool");
    let ts = Timestamp {
        seconds: 1_720_000_000,
        nanos: 0,
    };

    // 1. Create child dataset `data/workspace` with initial user + numeric properties.
    let data_ds = vec![b"data".to_vec()];
    let child_ds = vec![b"data".to_vec(), b"workspace".to_vec()];
    let (ws_head_obj, _) = engine
        .create_dataset(
            &cx,
            &data_ds,
            b"workspace",
            &[
                (
                    "org:team".to_owned(),
                    ffs_zfs::ZfsPropertySetValue::Text(b"storage".to_vec()),
                ),
                ("atime".to_owned(), ffs_zfs::ZfsPropertySetValue::Number(0)),
            ],
            ts,
        )
        .into_result()
        .expect("create_dataset data/workspace");

    // Verify OpenZFS `$ORIGIN@$ORIGIN` (`dp_origin_snap` = Object 26) linkage & dedicated `DMU_OT_DEADLIST` (50)!
    {
        let mut mos = engine.open_read_objects(&cx).unwrap();
        let ws_head_dn = mos.object(&cx, ws_head_obj).unwrap();
        let ws_dir_obj = ws_head_dn.order().u64(ws_head_dn.bonus(), 0).unwrap();
        let ws_prev_snap = ws_head_dn.order().u64(ws_head_dn.bonus(), 8).unwrap();
        let ws_prev_txg = ws_head_dn.order().u64(ws_head_dn.bonus(), 16).unwrap();
        let ws_deadlist_obj = ws_head_dn.order().u64(ws_head_dn.bonus(), 64).unwrap();
        assert_eq!(
            ws_prev_snap, 26,
            "new dataset must link ds_prev_snap_obj to $ORIGIN@$ORIGIN"
        );
        assert_eq!(
            ws_prev_txg, 1,
            "new dataset must inherit $ORIGIN@$ORIGIN ds_creation_txg"
        );
        assert_ne!(
            ws_deadlist_obj, 13,
            "writable head dataset must never alias shared empty_bpobj"
        );
        assert_eq!(mos.object(&cx, ws_deadlist_obj).unwrap().object_type(), 50);

        let ws_dir_dn = mos.object(&cx, ws_dir_obj).unwrap();
        assert_eq!(
            ws_dir_dn.order().u64(ws_dir_dn.bonus(), 24).unwrap(),
            26,
            "new dsl_dir must link dd_origin_obj to $ORIGIN@$ORIGIN"
        );
        let origin_snap_dn = mos.object(&cx, 26).unwrap();
        assert_eq!(
            origin_snap_dn
                .order()
                .u64(origin_snap_dn.bonus(), 40)
                .unwrap(),
            4,
            "$ORIGIN@$ORIGIN ds_num_children must increment for new dataset"
        );
        let origin_dd_dn = mos.object(&cx, 24).unwrap();
        let origin_dd_clones = origin_dd_dn.order().u64(origin_dd_dn.bonus(), 144).unwrap();
        assert_ne!(origin_dd_clones, 0);
        assert_eq!(mos.object(&cx, origin_dd_clones).unwrap().object_type(), 52);
    }

    // Populate a file in `data/workspace` (root dir of newly created dataset is Object 3).
    let (note_obj, _) = engine
        .create_file(
            &cx,
            &child_ds,
            3,
            b"note.txt",
            0o644,
            1000,
            1000,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("create note.txt in child dataset");
    engine
        .write_file_data(
            &cx,
            &child_ds,
            note_obj,
            0,
            b"origin-v1-payload",
            ts,
            ZfsDataChecksum::Sha256,
        )
        .into_result()
        .expect("write note.txt");

    // 2. Create snapshot `@base`, place hold `"keep"`, and create `@base` -> `#anchor` -> `#chained` bookmarks.
    engine
        .create_snapshot(&cx, &child_ds, b"base", ts)
        .into_result()
        .expect("create_snapshot @base");
    engine
        .hold_snapshot(&cx, &child_ds, b"base", b"keep", ts)
        .into_result()
        .expect("hold_snapshot @base keep");
    let holds = engine
        .list_holds(&cx, &child_ds, b"base")
        .expect("list_holds");
    assert_eq!(holds.len(), 1);
    assert_eq!(holds[0].tag, "keep");

    engine
        .create_bookmark(&cx, &child_ds, b"anchor", b"base", false)
        .into_result()
        .expect("create_bookmark #anchor from @base");
    engine
        .create_bookmark(&cx, &child_ds, b"chained", b"anchor", true)
        .into_result()
        .expect("create_bookmark #chained from #anchor");
    let listed_bookmarks = engine
        .list_bookmarks(&cx, &child_ds)
        .expect("list_bookmarks");
    assert_eq!(listed_bookmarks.len(), 2);
    assert_eq!(
        listed_bookmarks[0].creation_txg,
        listed_bookmarks[1].creation_txg
    );

    // Verify `com.delphix:extensible_dataset` incremented in MOS `features_for_read` (obj 10),
    // while vdev label `features_for_read` config nvlist stayed untouched!
    {
        let mut mos = engine.open_read_objects(&cx).unwrap();
        let rf = mos.zap(&cx, 10).unwrap();
        let ext_ds = rf
            .iter()
            .find(|e| e.name == b"com.delphix:extensible_dataset")
            .unwrap();
        assert!(ext_ds.value >= 1);
        let wf = mos.zap(&cx, 11).unwrap();
        let bm_feat = wf
            .iter()
            .find(|e| e.name == b"com.delphix:bookmarks")
            .unwrap();
        assert_eq!(
            bm_feat.value, 1,
            "com.delphix:bookmarks refcount tracks per-dataset ds_bookmarks_obj ZAP"
        );
        let cur_snap = device.durable_snapshot();
        let cfg_off = usize::try_from(LABEL_CONFIG_OFFSET).unwrap();
        let cfg_slice_old = &initial_label_bytes[cfg_off..cfg_off + LABEL_CONFIG_BYTES];
        let cfg_slice_new = &cur_snap[cfg_off..cfg_off + LABEL_CONFIG_BYTES];
        assert_eq!(cfg_slice_old, cfg_slice_new);
    }

    // 3. Create writable clone `data/fork` from `data/workspace@base` and diverge both heads!
    let clone_ds = vec![b"data".to_vec(), b"fork".to_vec()];
    engine
        .create_clone(&cx, &child_ds, b"base", &data_ds, b"fork", &[], ts)
        .into_result()
        .expect("create_clone data/fork");
    engine
        .write_file_data(
            &cx,
            &child_ds,
            note_obj,
            0,
            b"origin-v2-mutated",
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("overwrite origin note.txt");
    engine
        .write_file_data(
            &cx,
            &clone_ds,
            note_obj,
            0,
            b"cloned-v2-diverged!",
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("overwrite clone note.txt");

    // Verify all 3 views (`@base`, `data/workspace`, `data/fork`) read distinct exact bytes.
    {
        let mut mos = engine.open_read_objects(&cx).unwrap();
        let mut snap_view = mos.zpl_snapshot(&cx, &child_ds, b"base").unwrap();
        assert_eq!(
            snap_view.read(&cx, note_obj, 0, 64).unwrap(),
            b"origin-v1-payload"
        );
        let mut orig_view = mos.zpl(&cx, &child_ds).unwrap();
        assert_eq!(
            orig_view.read(&cx, note_obj, 0, 64).unwrap(),
            b"origin-v2-mutated"
        );
        let mut clone_view = mos.zpl(&cx, &clone_ds).unwrap();
        assert_eq!(
            clone_view.read(&cx, note_obj, 0, 64).unwrap(),
            b"cloned-v2-diverged!"
        );
    }

    // 4. Rename snapshot `@base` -> `@milestone`, rename clone `data/fork` -> `moved_fork` (cross-parent!),
    //    and reject dataset rename cycle (`data` -> `data/sub`).
    engine
        .rename_snapshot(&cx, &child_ds, b"base", b"milestone")
        .into_result()
        .expect("rename_snapshot");
    let moved_clone_ds = vec![b"moved_fork".to_vec()];
    engine
        .rename_dataset(&cx, &clone_ds, &moved_clone_ds)
        .into_result()
        .expect("cross-parent rename_dataset");
    assert_native_write_refused(
        &mut engine,
        std::slice::from_ref(&device),
        libc::EINVAL,
        |writer| writer.rename_dataset(&cx, &data_ds, &[b"data".to_vec(), b"cycle".to_vec()]),
    );

    // 5. Non-deferred destroy of held/cloned `@milestone` refuses with EBUSY;
    //    deferred destroy sets DS_FLAG_DEFER_DESTROY, survives hold release while clone lives,
    //    and auto-destroys when `moved_fork` clone is destroyed!
    assert_native_write_refused(
        &mut engine,
        std::slice::from_ref(&device),
        libc::EBUSY,
        |writer| writer.destroy_snapshot(&cx, &child_ds, b"milestone", false),
    );
    engine
        .destroy_snapshot(&cx, &child_ds, b"milestone", true)
        .into_result()
        .expect("defer destroy @milestone");
    engine
        .release_snapshot(&cx, &child_ds, b"milestone", b"keep")
        .into_result()
        .expect("release hold keep");
    {
        let mut mos = engine.open_read_objects(&cx).unwrap();
        let snaps = mos.snapshots(&cx, &child_ds).unwrap();
        assert_eq!(snaps.len(), 1, "clone still pins deferred origin snapshot");
    }

    // Destroying `moved_fork` removes the last clone reference and auto-destroys `@milestone`!
    engine
        .destroy_dataset(&cx, &moved_clone_ds)
        .into_result()
        .expect("destroy clone moved_fork + auto-destroy deferred origin snap");
    {
        let mut mos = engine.open_read_objects(&cx).unwrap();
        let snaps = mos.snapshots(&cx, &child_ds).unwrap();
        assert!(
            snaps.is_empty(),
            "deferred origin snapshot must auto-destroy"
        );
        let bms = ffs_zfs::list_bookmarks_in_mos(&cx, &mut mos, &child_ds).unwrap();
        assert_eq!(bms.len(), 2, "bookmarks must survive snapshot destruction");
    }

    engine
        .destroy_bookmark(&cx, &child_ds, b"chained")
        .into_result()
        .expect("destroy_bookmark #chained");
    assert_eq!(engine.list_bookmarks(&cx, &child_ds).unwrap().len(), 1);

    // Finally destroy `data/workspace` itself and verify full MOS scrub + exact space-map accounting!
    engine
        .destroy_bookmark(&cx, &child_ds, b"anchor")
        .into_result()
        .expect("destroy_bookmark #anchor");
    engine
        .destroy_dataset(&cx, &child_ds)
        .into_result()
        .expect("destroy_dataset data/workspace");

    assert_eq!(
        engine.free_bytes() + engine.allocated_bytes(),
        engine.storage_identity().asize
    );
    let mos = engine.open_read_objects(&cx).unwrap();
    assert!(mos.scrub(&cx, ScrubLimits::default()).unwrap().is_clean());
    let _ = mos
        .allocation(&cx, AllocationLimits::default())
        .expect("clean allocation audit after full DSL lifecycle");
}

fn dsl_block_feature_counts(cx: &Cx, engine: &ZfsTransactionEngine) -> [u64; 3] {
    let mut mos = engine.open_read_objects(cx).unwrap();
    let rows = mos.zap(cx, 10).unwrap();
    [
        b"org.open-zfs:large_blocks".as_slice(),
        b"org.illumos:sha512".as_slice(),
        b"com.delphix:extensible_dataset".as_slice(),
    ]
    .map(|feature| rows.iter().find(|row| row.name == feature).unwrap().value)
}

#[test]
#[allow(clippy::too_many_lines)]
fn dsl_block_feature_ownership_survives_properties_snapshots_clones_and_deferred_destroy() {
    let cx = Cx::for_testing();
    let built = build_clean_zfs_pool(&PoolFixtureSpec {
        image_bytes: 32 * 1024 * 1024,
        data_properties: vec![(b"recordsize", 262_144), (b"checksum", 11)],
        data_head_features: vec![
            (b"org.open-zfs:large_blocks", 0),
            (b"org.illumos:sha512", 0),
        ],
        additional_read_features: vec![
            (b"org.open-zfs:large_blocks", 1),
            (b"org.illumos:sha512", 1),
        ],
        additional_write_features: vec![(b"com.delphix:bookmarks", 0)],
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
    let dataset = vec![b"data".to_vec()];
    let clone = vec![b"data".to_vec(), b"feature-clone".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_720_000_100,
        nanos: 0,
    };
    let (file, _) = engine
        .create_file(
            &cx,
            &dataset,
            2,
            b"feature-data",
            0o644,
            1000,
            1000,
            timestamp,
            ZfsDataChecksum::Inherit,
        )
        .into_result()
        .unwrap();
    let original = vec![0x6D; 300 * 1024];
    engine
        .write_file_data(
            &cx,
            &dataset,
            file,
            0,
            &original,
            timestamp,
            ZfsDataChecksum::Inherit,
        )
        .into_result()
        .unwrap();
    assert_eq!(dsl_block_feature_counts(&cx, &engine), [1, 1, 1]);
    let (snapshot, _) = engine
        .create_snapshot(&cx, &dataset, b"origin", timestamp)
        .into_result()
        .unwrap();
    assert_eq!(dsl_block_feature_counts(&cx, &engine), [2, 2, 2]);
    engine
        .create_bookmark(&cx, &dataset, b"anchor", b"origin", false)
        .into_result()
        .unwrap();
    engine
        .write_file_data(
            &cx,
            &dataset,
            file,
            31,
            b"head-divergent",
            timestamp,
            ZfsDataChecksum::Inherit,
        )
        .into_result()
        .unwrap();
    assert_eq!(engine.list_bookmarks(&cx, &dataset).unwrap().len(), 1);
    assert_eq!(dsl_block_feature_counts(&cx, &engine), [2, 2, 2]);

    // Properties select future blocks. They do not release either owner's
    // existing feature, even after every current head block is later retired.
    for (name, value) in [("recordsize", 512), ("checksum", 7)] {
        engine
            .set_property(
                &cx,
                &dataset,
                name,
                ffs_zfs::ZfsPropertySetValue::Number(value),
            )
            .into_result()
            .unwrap();
        assert_eq!(dsl_block_feature_counts(&cx, &engine), [2, 2, 2]);
    }
    engine
        .inherit_property(&cx, &dataset, "recordsize")
        .into_result()
        .unwrap();
    assert_eq!(dsl_block_feature_counts(&cx, &engine), [2, 2, 2]);
    let (clone_head, _) = engine
        .create_clone(
            &cx,
            &dataset,
            b"origin",
            &dataset,
            b"feature-clone",
            &[],
            timestamp,
        )
        .into_result()
        .unwrap();
    assert_eq!(dsl_block_feature_counts(&cx, &engine), [3, 3, 3]);
    engine
        .write_file_data(
            &cx,
            &clone,
            file,
            17,
            b"clone-divergent",
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    assert_eq!(dsl_block_feature_counts(&cx, &engine), [3, 3, 3]);

    let slot = engine.committed_slot();
    drop(engine);
    let durable: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::fresh_from_durable)
        .collect();
    let mut engine =
        open_engine_on_devices(&cx, &durable, default_write_opts(built.pool_guid, slot)).unwrap();
    assert_eq!(dsl_block_feature_counts(&cx, &engine), [3, 3, 3]);
    let mut mos = engine.open_read_objects(&cx).unwrap();
    for object in [18, snapshot, clone_head] {
        assert_eq!(mos.object(&cx, object).unwrap().object_type(), 196);
        let rows = mos.zap(&cx, object).unwrap();
        for feature in [
            b"org.open-zfs:large_blocks".as_slice(),
            b"org.illumos:sha512".as_slice(),
        ] {
            assert_eq!(
                rows.iter().find(|row| row.name == feature).unwrap().value,
                0
            );
        }
    }
    let mut head_bytes = original.clone();
    head_bytes[31..31 + b"head-divergent".len()].copy_from_slice(b"head-divergent");
    let mut clone_bytes = original.clone();
    clone_bytes[17..17 + b"clone-divergent".len()].copy_from_slice(b"clone-divergent");
    assert_eq!(
        mos.zpl(&cx, &dataset)
            .unwrap()
            .read(&cx, file, 0, original.len())
            .unwrap(),
        head_bytes
    );
    assert_eq!(
        mos.zpl(&cx, &clone)
            .unwrap()
            .read(&cx, file, 0, original.len())
            .unwrap(),
        clone_bytes
    );
    assert_eq!(
        mos.zpl_snapshot(&cx, &dataset, b"origin")
            .unwrap()
            .read(&cx, file, 0, original.len())
            .unwrap(),
        original
    );
    drop(mos);

    engine
        .hold_snapshot(&cx, &dataset, b"origin", b"keep", timestamp)
        .into_result()
        .unwrap();
    engine
        .destroy_snapshot(&cx, &dataset, b"origin", true)
        .into_result()
        .unwrap();
    assert_eq!(dsl_block_feature_counts(&cx, &engine), [3, 3, 3]);
    engine.destroy_dataset(&cx, &clone).into_result().unwrap();
    assert_eq!(dsl_block_feature_counts(&cx, &engine), [2, 2, 2]);
    assert_eq!(
        engine
            .open_read_objects(&cx)
            .unwrap()
            .snapshots(&cx, &dataset)
            .unwrap()
            .len(),
        1
    );
    engine
        .release_snapshot(&cx, &dataset, b"origin", b"keep")
        .into_result()
        .unwrap();
    assert_eq!(dsl_block_feature_counts(&cx, &engine), [1, 1, 1]);
    assert!(
        engine
            .open_read_objects(&cx)
            .unwrap()
            .snapshots(&cx, &dataset)
            .unwrap()
            .is_empty()
    );
    assert_eq!(engine.list_bookmarks(&cx, &dataset).unwrap().len(), 1);
    engine
        .destroy_bookmark(&cx, &dataset, b"anchor")
        .into_result()
        .unwrap();
    engine.destroy_dataset(&cx, &dataset).into_result().unwrap();
    assert_eq!(dsl_block_feature_counts(&cx, &engine), [0, 0, 0]);
    let slot = engine.committed_slot();
    drop(engine);
    let final_devices: Vec<_> = durable
        .iter()
        .map(FaultableMemberDevice::fresh_from_durable)
        .collect();
    let reopened = open_engine_on_devices(
        &cx,
        &final_devices,
        default_write_opts(built.pool_guid, slot),
    )
    .unwrap();
    assert_eq!(dsl_block_feature_counts(&cx, &reopened), [0, 0, 0]);
    let mut mos = reopened.open_read_objects(&cx).unwrap();
    assert!(
        !mos.datasets(&cx)
            .unwrap()
            .iter()
            .any(|row| row.components == dataset)
    );
    assert!(mos.scrub(&cx, ScrubLimits::default()).unwrap().is_clean());
    mos.allocation(&cx, AllocationLimits::default()).unwrap();
}

#[test]
#[allow(clippy::too_many_lines)]
fn dsl_block_feature_properties_do_not_create_or_steal_dataset_ownership() {
    let cx = Cx::for_testing();
    let timestamp = Timestamp {
        seconds: 1_720_000_101,
        nanos: 0,
    };
    for other_owner in [false, true] {
        let expected = u64::from(other_owner);
        let built = build_clean_zfs_pool(&PoolFixtureSpec {
            data_head_features: if other_owner {
                vec![
                    (b"org.open-zfs:large_blocks", 0),
                    (b"org.illumos:sha512", 0),
                ]
            } else {
                Vec::new()
            },
            additional_read_features: vec![
                (b"org.open-zfs:large_blocks", expected),
                (b"org.illumos:sha512", expected),
            ],
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
        let parent = vec![b"data".to_vec()];
        let dataset = vec![b"data".to_vec(), b"configured-only".to_vec()];
        let (head, _) = engine
            .create_dataset(
                &cx,
                &parent,
                b"configured-only",
                &[
                    (
                        "recordsize".into(),
                        ffs_zfs::ZfsPropertySetValue::Number(262_144),
                    ),
                    ("checksum".into(), ffs_zfs::ZfsPropertySetValue::Number(11)),
                ],
                timestamp,
            )
            .into_result()
            .unwrap();
        assert_eq!(dsl_block_feature_counts(&cx, &engine), [expected; 3]);
        assert_eq!(
            engine
                .open_read_objects(&cx)
                .unwrap()
                .object(&cx, head)
                .unwrap()
                .object_type(),
            16
        );
        for value in [512, 1_048_576] {
            engine
                .set_property(
                    &cx,
                    &dataset,
                    "recordsize",
                    ffs_zfs::ZfsPropertySetValue::Number(value),
                )
                .into_result()
                .unwrap();
            assert_eq!(dsl_block_feature_counts(&cx, &engine), [expected; 3]);
        }
        engine
            .inherit_property(&cx, &dataset, "recordsize")
            .into_result()
            .unwrap();
        assert_eq!(dsl_block_feature_counts(&cx, &engine), [expected; 3]);
        engine
            .set_property(
                &cx,
                &dataset,
                "recordsize",
                ffs_zfs::ZfsPropertySetValue::Number(262_144),
            )
            .into_result()
            .unwrap();
        engine
            .create_snapshot(&cx, &dataset, b"empty", timestamp)
            .into_result()
            .unwrap();
        assert_eq!(dsl_block_feature_counts(&cx, &engine), [expected; 3]);
        engine
            .destroy_snapshot(&cx, &dataset, b"empty", false)
            .into_result()
            .unwrap();
        engine.destroy_dataset(&cx, &dataset).into_result().unwrap();
        assert_eq!(dsl_block_feature_counts(&cx, &engine), [expected; 3]);
        assert_pool_scrub_and_allocation_clean(
            &cx,
            &devices,
            built.pool_guid,
            Some(engine.committed_slot()),
        );
    }
}

#[test]
fn dsl_block_feature_properties_require_enabled_pool_features_without_writes() {
    let cx = Cx::for_testing();
    let built = build_clean_zfs_pool(&PoolFixtureSpec::default());
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
    let dataset = [b"data".to_vec()];
    for (property, value) in [("recordsize", 262_144), ("checksum", 11)] {
        assert_native_write_refused(&mut engine, &devices, libc::EOPNOTSUPP, |writer| {
            writer.set_property(
                &cx,
                &dataset,
                property,
                ffs_zfs::ZfsPropertySetValue::Number(value),
            )
        });
    }
}

#[test]
fn dsl_block_feature_lifecycle_refuses_malformed_or_inactive_ownership_without_writes() {
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_720_000_102,
        nanos: 0,
    };
    for feature in [
        b"org.open-zfs:large_blocks".as_slice(),
        b"org.illumos:sha512".as_slice(),
    ] {
        for (marker, count) in [(1, Some(1)), (0, Some(0)), (0, None)] {
            let built = build_clean_zfs_pool(&PoolFixtureSpec {
                data_head_features: vec![(feature, marker)],
                additional_read_features: count.into_iter().map(|value| (feature, value)).collect(),
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
            assert_native_write_refused(&mut engine, &devices, libc::EIO, |writer| {
                writer.create_snapshot(&cx, &dataset, b"refused", timestamp)
            });
            assert_native_write_refused(&mut engine, &devices, libc::EIO, |writer| {
                writer.destroy_dataset(&cx, &dataset)
            });
            let mut mos = engine.open_read_objects(&cx).unwrap();
            assert!(mos.snapshots(&cx, &dataset).unwrap().is_empty());
            assert!(
                mos.datasets(&cx)
                    .unwrap()
                    .iter()
                    .any(|row| row.components == dataset)
            );
        }
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn dsl_quota_refquota_reservation_and_inherit_enforcement() {
    let cx = Cx::for_testing();
    let mut built = build_clean_zfs_pool(&PoolFixtureSpec {
        image_bytes: 16 * 1024 * 1024,
        ashift: 9,
        zpl_version: 5,
        deadlist_mode: DeadlistMode::NativeDeadlist,
        ..PoolFixtureSpec::default()
    });
    let device = FaultableMemberDevice::new(built.members.remove(0));
    let mut engine = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&device),
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .expect("admit pool");
    let ts = Timestamp {
        seconds: 1_720_100_000,
        nanos: 0,
    };
    let data_ds = vec![b"data".to_vec()];

    // Read current referenced bytes on `data` so we set a tight `refquota` (`+ 32 KiB`).
    let base_ref = {
        let mut mos = engine.open_read_objects(&cx).unwrap();
        let row = mos
            .datasets(&cx)
            .unwrap()
            .into_iter()
            .find(|d| d.components == data_ds)
            .unwrap();
        let dn = mos.object(&cx, row.head_object).unwrap();
        dn.order().u64(dn.bonus(), 72).unwrap()
    };
    engine
        .set_property(
            &cx,
            &data_ds,
            "refquota",
            ffs_zfs::ZfsPropertySetValue::Number(base_ref + 32 * 1024),
        )
        .into_result()
        .expect("set refquota");

    let (f_obj, _) = engine
        .create_file(
            &cx,
            &data_ds,
            2,
            b"quota_probe.bin",
            0o644,
            0,
            0,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("create within refquota");

    // Exceeding `refquota` must fail closed with `EDQUOT` and zero writes!
    let big_buf = vec![0xAB_u8; 96 * 1024];
    assert_native_write_refused(
        &mut engine,
        std::slice::from_ref(&device),
        libc::EDQUOT,
        |writer| {
            writer.write_file_data(
                &cx,
                &data_ds,
                f_obj,
                0,
                &big_buf,
                ts,
                ZfsDataChecksum::Fletcher4,
            )
        },
    );

    // Inheriting `refquota` lifts the limit so the exact same 96 KiB write commits cleanly!
    engine
        .inherit_property(&cx, &data_ds, "refquota")
        .into_result()
        .expect("inherit refquota");
    engine
        .write_file_data(
            &cx,
            &data_ds,
            f_obj,
            0,
            &big_buf,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("write succeeds after inheriting refquota");

    // Reservation exceeding pool free space refuses with ENOSPC (`NoSpace`).
    let impossible_resv = engine.free_bytes() + 4 * 1024 * 1024;
    assert_native_write_refused(
        &mut engine,
        std::slice::from_ref(&device),
        libc::ENOSPC,
        |writer| {
            writer.set_property(
                &cx,
                &data_ds,
                "reservation",
                ffs_zfs::ZfsPropertySetValue::Number(impossible_resv),
            )
        },
    );

    // Reserving nearly all pool free space on root dataset starves unreserved `data` writes with ENOSPC!
    let free_now = engine.free_bytes();
    let root_unique = {
        let mut mos = engine.open_read_objects(&cx).unwrap();
        let row = mos
            .datasets(&cx)
            .unwrap()
            .into_iter()
            .find(|d| d.components.is_empty())
            .unwrap();
        let dn = mos.object(&cx, row.head_object).unwrap();
        dn.order().u64(dn.bonus(), 96).unwrap()
    };
    let tight_resv = root_unique + free_now.saturating_sub(512 * 1024);
    engine
        .set_property(
            &cx,
            &[],
            "refreservation",
            ffs_zfs::ZfsPropertySetValue::Number(tight_resv),
        )
        .into_result()
        .expect("set root refreservation");
    let huge_buf = vec![0xCD_u8; 768 * 1024];
    assert_native_write_refused(
        &mut engine,
        std::slice::from_ref(&device),
        libc::ENOSPC,
        |writer| {
            writer.write_file_data(
                &cx,
                &data_ds,
                f_obj,
                0,
                &huge_buf,
                ts,
                ZfsDataChecksum::Fletcher4,
            )
        },
    );
    engine
        .inherit_property(&cx, &[], "refreservation")
        .into_result()
        .expect("clear root refreservation");

    let mos = engine.open_read_objects(&cx).unwrap();
    assert!(mos.scrub(&cx, ScrubLimits::default()).unwrap().is_clean());
    let _ = mos.allocation(&cx, AllocationLimits::default()).unwrap();
}

#[test]
#[allow(clippy::too_many_lines)]
fn zpl_posix_setattr_sa_inline_and_spill_xattrs_and_mounted_zfsfs_snapshot_invalidation() {
    use ffs_core::{FsOps, RequestScope, SetAttrRequest, XattrSetMode};
    use ffs_types::InodeNumber;
    use std::ffi::OsStr;

    let cx = Cx::for_testing();
    let mut built = build_clean_zfs_pool(&PoolFixtureSpec {
        image_bytes: 32 * 1024 * 1024,
        ashift: 9,
        zpl_version: 5,
        user_accounting: true,
        deadlist_mode: DeadlistMode::NativeDeadlist,
        ..PoolFixtureSpec::default()
    });
    let device = FaultableMemberDevice::new(built.members.remove(0));
    let mut engine = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&device),
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .expect("admit pool");
    let ts = Timestamp {
        seconds: 1_720_200_000,
        nanos: 0,
    };
    let data_ds = vec![b"data".to_vec()];

    // 1. Direct engine POSIX setattr (setuid + chown clears set-ID bits & transfers user/group quota) + SA inline & spill xattrs!
    let (target_obj, _) = engine
        .create_file(
            &cx,
            &data_ds,
            2,
            b"xattr_target.bin",
            0o4755,
            1000,
            1000,
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("create setuid file");
    engine
        .write_file_data(
            &cx,
            &data_ds,
            target_obj,
            0,
            b"quota-charged-data",
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("write data");
    // Wait: note `0o4755` setuid on direct engine `write_file_data` is allowed unless `ZfsFs` `admit_data_mutation` blocks it;
    // now chown `(1000, 1000) -> (2000, 2000)` must clear `0o4000` -> `0o0755`!
    engine
        .set_posix_attributes(
            &cx,
            &data_ds,
            target_obj,
            &ffs_zfs::ZfsPosixSetAttr {
                uid: Some(2000),
                gid: Some(2000),
                ..ffs_zfs::ZfsPosixSetAttr::default()
            },
            ts,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("chown transfers quota and clears setuid");
    {
        let mut mos = engine.open_read_objects(&cx).unwrap();
        let mut zpl = mos.zpl(&cx, &data_ds).unwrap();
        let (meta, _) = zpl.stat(&cx, target_obj).unwrap();
        assert_eq!((meta.uid, meta.gid), (2000, 2000));
        assert_eq!(meta.mode & 0o7777, 0o755, "chown must clear S_ISUID");
    }

    // Small inline SA xattr (`<= 320B` -> no spill block!) + Create/Replace modes.
    engine
        .set_xattr(
            &cx,
            &data_ds,
            target_obj,
            "user.inline",
            b"compact-val",
            ffs_zfs::ZfsXattrSetMode::Create,
            ts,
        )
        .into_result()
        .expect("set inline xattr");
    assert_native_write_refused(
        &mut engine,
        std::slice::from_ref(&device),
        libc::EEXIST,
        |writer| {
            writer.set_xattr(
                &cx,
                &data_ds,
                target_obj,
                "user.inline",
                b"dup",
                ffs_zfs::ZfsXattrSetMode::Create,
                ts,
            )
        },
    );
    assert_native_write_refused(
        &mut engine,
        std::slice::from_ref(&device),
        libc::ENODATA,
        |writer| {
            writer.set_xattr(
                &cx,
                &data_ds,
                target_obj,
                "user.absent",
                b"v",
                ffs_zfs::ZfsXattrSetMode::Replace,
                ts,
            )
        },
    );

    // Large 3,000-byte xattr spills cleanly to `DMU_OT_SA = 44`!
    let large_xattr = vec![b'X'; 3000];
    engine
        .set_xattr(
            &cx,
            &data_ds,
            target_obj,
            "user.spilled",
            &large_xattr,
            ffs_zfs::ZfsXattrSetMode::Create,
            ts,
        )
        .into_result()
        .expect("set spilled SA xattr");
    {
        let mut mos = engine.open_read_objects(&cx).unwrap();
        let mut zpl = mos.zpl(&cx, &data_ds).unwrap();
        let mut names = zpl.listxattr(&cx, target_obj).unwrap();
        names.sort();
        assert_eq!(names, vec!["user.inline", "user.spilled"]);
        assert_eq!(
            zpl.getxattr(&cx, target_obj, "user.inline")
                .unwrap()
                .as_deref(),
            Some(b"compact-val".as_slice())
        );
        assert_eq!(
            zpl.getxattr(&cx, target_obj, "user.spilled")
                .unwrap()
                .as_deref(),
            Some(large_xattr.as_slice())
        );
    }
    engine
        .remove_xattr(&cx, &data_ds, target_obj, "user.spilled", ts)
        .into_result()
        .expect("remove spilled SA xattr");

    // 2. Mount via `ZfsFs::with_writer_options` (`allow_mode_and_owner_setattr: true`) and exercise
    //    FUSE wire `S_IFREG | 0o600` setattr, FsOps xattr CRUD, and live `.zfs/snapshot` invalidation!
    let fs = ffs_zfs::ZfsFs::with_writer_options(
        &cx,
        engine,
        data_ds,
        ffs_zfs::ZfsMountWriteOptions {
            allow_mode_and_owner_setattr: true,
        },
    )
    .expect("mount writable ZfsFs");
    let mut scope = RequestScope::empty();
    let attr = fs
        .lookup(
            &cx,
            &mut scope,
            InodeNumber(1),
            OsStr::new("xattr_target.bin"),
        )
        .expect("lookup xattr_target.bin");
    let updated = fs
        .setattr(
            &cx,
            &mut scope,
            attr.ino,
            &SetAttrRequest {
                mode: Some(0o100_600), // Linux FUSE wire `S_IFREG | 0o600`
                uid: Some(3000),
                gid: Some(3000),
                ..SetAttrRequest::default()
            },
        )
        .expect("FUSE wire S_IFREG | 0o600 setattr");
    assert_eq!(updated.perm, 0o600);
    assert_eq!((updated.uid, updated.gid), (3000, 3000));

    fs.setxattr(
        &cx,
        &mut scope,
        attr.ino,
        "user.fsops",
        b"mounted-xattr",
        XattrSetMode::Create,
    )
    .expect("FsOps::setxattr");
    assert_eq!(
        fs.getxattr(&cx, attr.ino, "user.fsops").unwrap().as_deref(),
        Some(b"mounted-xattr".as_slice())
    );
    fs.removexattr(&cx, &mut scope, attr.ino, "user.fsops")
        .expect("FsOps::removexattr");
    assert_eq!(fs.getxattr(&cx, attr.ino, "user.fsops").unwrap(), None);

    // Live `.zfs/snapshot` create -> lookup -> rename -> destroy -> recreate with monotonic non-colliding `snap_idx`!
    let ctl = fs
        .lookup(&cx, &mut scope, InodeNumber(1), OsStr::new(".zfs"))
        .unwrap();
    let snapdir = fs
        .lookup(&cx, &mut scope, ctl.ino, OsStr::new("snapshot"))
        .unwrap();
    fs.create_snapshot(&cx, b"live_s1")
        .expect("ZfsFs::create_snapshot");
    let first_snap_root = fs
        .lookup(&cx, &mut scope, snapdir.ino, OsStr::new("live_s1"))
        .expect("lookup newly created .zfs/snapshot/live_s1");
    fs.rename_snapshot(&cx, b"live_s1", b"live_s2")
        .expect("ZfsFs::rename_snapshot");
    assert!(matches!(
        fs.lookup(&cx, &mut scope, snapdir.ino, OsStr::new("live_s1")),
        Err(FfsError::NotFound(_))
    ));
    let renamed_snap_root = fs
        .lookup(&cx, &mut scope, snapdir.ino, OsStr::new("live_s2"))
        .expect("lookup renamed .zfs/snapshot/live_s2");
    assert_eq!(
        first_snap_root.ino, renamed_snap_root.ino,
        "GUID-bound snapshot keeps stable synthetic inode across rename"
    );
    fs.destroy_snapshot(&cx, b"live_s2", false)
        .expect("ZfsFs::destroy_snapshot");
    assert!(matches!(
        fs.lookup(&cx, &mut scope, snapdir.ino, OsStr::new("live_s2")),
        Err(FfsError::NotFound(_))
    ));
    assert!(matches!(
        fs.getattr(&cx, &mut scope, renamed_snap_root.ino),
        Err(FfsError::NotFound(_))
    ));

    fs.create_snapshot(&cx, b"live_s2")
        .expect("recreate snapshot with same name");
    let recreated_snap_root = fs
        .lookup(&cx, &mut scope, snapdir.ino, OsStr::new("live_s2"))
        .expect("lookup recreated snapshot");
    assert_ne!(
        recreated_snap_root.ino, renamed_snap_root.ino,
        "monotonic snap_idx must never alias a destroyed snapshot's inode"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn dsl_and_xattr_persistence_prefix_cuts_preserve_scrub_and_allocation() {
    let cx = Cx::for_testing();
    let ts = Timestamp {
        seconds: 1_720_300_000,
        nanos: 0,
    };
    let data_ds = vec![b"data".to_vec()];

    for stage_kind in 0..4_u8 {
        let mut built = build_clean_zfs_pool(&PoolFixtureSpec {
            image_bytes: 32 * 1024 * 1024,
            ashift: 9,
            mirror_width: 2,
            zpl_version: 5,
            deadlist_mode: DeadlistMode::NativeDeadlist,
            ..PoolFixtureSpec::default()
        });
        let devices: Vec<_> = built
            .members
            .drain(..)
            .map(FaultableMemberDevice::new)
            .collect();
        let mut engine = open_engine_on_devices(
            &cx,
            &devices,
            default_write_opts(built.pool_guid, built.initial_slot),
        )
        .expect("admit mirror pool");

        let (_, _) = engine
            .create_snapshot(&cx, &data_ds, b"cut_base", ts)
            .into_result()
            .expect("seed @cut_base");
        let pre_slot = engine.committed_slot();
        let pre_txg = engine.committed_txg();

        engine.with_fault_hook(move |event| {
            let cut = matches!(
                (stage_kind, event.stage),
                (0, ZfsPersistenceStage::MosSpaceMapWrite { .. })
                    | (1, ZfsPersistenceStage::ChildBlocksWrite { .. })
                    | (2, ZfsPersistenceStage::MosRootBarrier { .. })
                    | (3, ZfsPersistenceStage::UberblockWrite { label: 1, .. })
            );
            if cut {
                Err(FfsError::Io(std::io::Error::other(
                    "injected DSL/xattr cut",
                )))
            } else {
                Ok(())
            }
        });

        let outcome = if stage_kind % 2 == 0 {
            engine.create_clone(&cx, &data_ds, b"cut_base", &data_ds, b"cut_clone", &[], ts)
        } else {
            let spill_val = vec![b'Z'; 2500];
            engine.set_xattr(
                &cx,
                &data_ds,
                4,
                "user.cut_spill",
                &spill_val,
                ffs_zfs::ZfsXattrSetMode::Create,
                ts,
            )
        };

        if stage_kind < 3 {
            assert!(matches!(outcome, ZfsTxOutcome::NotCommitted(_)));
            let verify_eng = open_engine_on_devices(
                &cx,
                &devices,
                default_write_opts(built.pool_guid, pre_slot),
            )
            .expect("pre-Uberblock cut must reopen cleanly at pre_slot");
            assert_eq!(verify_eng.committed_txg(), pre_txg);
            let mos = verify_eng.open_read_objects(&cx).unwrap();
            assert!(mos.scrub(&cx, ScrubLimits::default()).unwrap().is_clean());
            let _ = mos.allocation(&cx, AllocationLimits::default()).unwrap();
        } else {
            let ZfsTxOutcome::Uncertain { target_slot, .. } = outcome else {
                panic!("partial Uberblock ring write must report Uncertain");
            };
            let reconciled = open_engine_on_devices(
                &cx,
                &devices,
                ZfsWriteOptions {
                    offline_image: true,
                    allow_write: true,
                    pool_guid: built.pool_guid,
                    label: 0,
                    slot: target_slot,
                    reconcile_torn_uberblocks: true,
                },
            )
            .expect("explicit Uberblock ring reconciliation must recover cleanly");
            assert_eq!(reconciled.committed_txg(), pre_txg + 1);
            let mos = reconciled.open_read_objects(&cx).unwrap();
            assert!(mos.scrub(&cx, ScrubLimits::default()).unwrap().is_clean());
            let _ = mos.allocation(&cx, AllocationLimits::default()).unwrap();
        }
    }
}

#[test]
fn cloned_dataset_from_snapshot_with_unwritten_zil_tail_admits_reopen_and_resets_clone_zil() {
    let cx = Cx::for_testing();
    let mut built = build_clean_zfs_pool(&PoolFixtureSpec {
        zil_tail: ZilTailFixture::UnwrittenTail,
        ..PoolFixtureSpec::default()
    });
    let device = FaultableMemberDevice::new(built.members.remove(0));
    let ts = Timestamp {
        seconds: 1_725_000_000,
        nanos: 0,
    };
    let data_ds = vec![b"data".to_vec()];
    let clone_ds = vec![b"data".to_vec(), b"cloned_view".to_vec()];

    let clone_slot = {
        let mut engine = open_engine_on_devices(
            &cx,
            std::slice::from_ref(&device),
            default_write_opts(built.pool_guid, built.initial_slot),
        )
        .expect("admit pool with unwritten ZIL tail");
        engine
            .create_snapshot(&cx, &data_ds, b"snap1", ts)
            .into_result()
            .expect("create_snapshot data@snap1");
        let (_, tok) = engine
            .create_clone(&cx, &data_ds, b"snap1", &data_ds, b"cloned_view", &[], ts)
            .into_result()
            .expect("create_clone data/cloned_view");
        tok.published_slot()
    };

    // Reopen a fresh engine while `data/cloned_view` still shares `data@snap1`'s ObjectSet
    // (`ds_bp.birth() <= prev_snap_txg`, carrying `data`'s unclaimed `zh_log` block).
    let after_write_slot = {
        let mut reopened = open_engine_on_devices(
            &cx,
            std::slice::from_ref(&device),
            default_write_opts(built.pool_guid, clone_slot),
        )
        .expect("fresh writer reopen must admit clone sharing origin snapshot ZIL tail");
        {
            let mut mos = reopened.open_read_objects(&cx).expect("open MOS");
            let pre_clone_log = mos
                .intent_log(&cx, &clone_ds)
                .expect("intent_log on unmodified clone");
            assert_eq!(
                pre_clone_log.termination,
                ffs_zfs::reader::dmu::zil::Termination::Empty
            );
        }
        let (clone_file, _) = reopened
            .create_file(
                &cx,
                &clone_ds,
                2,
                b"clone_only.txt",
                0o644,
                0,
                0,
                ts,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .expect("tx-create on data/cloned_view");
        let (_, tok_w) = reopened
            .write_file_data(
                &cx,
                &clone_ds,
                clone_file,
                0,
                b"clone-diverged-bytes\n",
                ts,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .expect("tx-write on data/cloned_view");
        let (_, tok_o) = reopened
            .create_file(
                &cx,
                &data_ds,
                2,
                b"origin_after_clone.txt",
                0o644,
                0,
                0,
                ts,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .expect("tx-create on origin data after clone");
        assert!(tok_o.committed_txg() > tok_w.committed_txg());
        tok_o.published_slot()
    };

    // Reopen a third engine and verify scrub, space-map accounting, and ZIL ownership separation!
    let final_eng = open_engine_on_devices(
        &cx,
        std::slice::from_ref(&device),
        default_write_opts(built.pool_guid, after_write_slot),
    )
    .expect("third writer reopen after clone COW");
    let mut mos = final_eng.open_read_objects(&cx).expect("open final MOS");
    assert!(mos.scrub(&cx, ScrubLimits::default()).unwrap().is_clean());
    let _ = mos
        .allocation(&cx, AllocationLimits::default())
        .expect("space-map accounting must remain exact (no stolen or leaked zh_log)");
    let origin_log = mos
        .intent_log(&cx, &data_ds)
        .expect("origin intent_log preserved");
    assert_eq!(
        origin_log.termination,
        ffs_zfs::reader::dmu::zil::Termination::UnverifiedTail
    );
    let clone_log = mos
        .intent_log(&cx, &clone_ds)
        .expect("COW'd clone intent_log reset to empty");
    assert_eq!(
        clone_log.termination,
        ffs_zfs::reader::dmu::zil::Termination::Empty
    );
}

fn file_range_fixture(
    cx: &Cx,
    spec: &PoolFixtureSpec,
) -> (ZfsTransactionEngine, Vec<FaultableMemberDevice>) {
    let built = build_clean_zfs_pool(spec);
    let devices: Vec<_> = built
        .members
        .into_iter()
        .map(FaultableMemberDevice::new)
        .collect();
    let engine = open_engine_on_devices(
        cx,
        &devices,
        default_write_opts(built.pool_guid, built.initial_slot),
    )
    .unwrap();
    (engine, devices)
}

fn file_range_head(cx: &Cx, engine: &ZfsTransactionEngine) -> ffs_zfs::Zpl {
    engine
        .open_read_objects(cx)
        .unwrap()
        .zpl(cx, &[b"data".to_vec()])
        .unwrap()
}

#[test]
#[allow(clippy::too_many_lines)]
fn setid_native_data_policy_preserves_legacy_noops_and_nonexecutable_sgid() {
    use ffs_zfs::{ZfsFileRangeOperation::PunchHole, ZfsPosixSetAttr};

    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_730_100_000,
        nanos: 19,
    };
    for zpl_version in [4, 5] {
        let (mut engine, devices) = file_range_fixture(
            &cx,
            &PoolFixtureSpec {
                zpl_version,
                deadlist_mode: DeadlistMode::NativeDeadlist,
                user_accounting: true,
                ..PoolFixtureSpec::default()
            },
        );
        for (mode, expected_mode) in [(0o6755, 0o755), (0o6644, 0o2644)] {
            let (file, _) = engine
                .create_file(
                    &cx,
                    &dataset,
                    2,
                    format!("setid-{mode:o}").as_bytes(),
                    mode,
                    1000,
                    1000,
                    timestamp,
                    ZfsDataChecksum::Fletcher4,
                )
                .into_result()
                .unwrap();
            let mut expected = b"original-data".to_vec();
            engine
                .write_file_data(
                    &cx,
                    &dataset,
                    file,
                    0,
                    &expected,
                    timestamp,
                    ZfsDataChecksum::Fletcher4,
                )
                .into_result()
                .unwrap();
            assert_eq!(
                file_range_head(&cx, &engine)
                    .stat(&cx, file)
                    .unwrap()
                    .0
                    .mode
                    & 0o7777,
                u64::from(mode),
                "the existing native writer preserves explicitly assigned permissions"
            );
            engine
                .write_file_data_clearing_setid(
                    &cx,
                    &dataset,
                    file,
                    0,
                    b"",
                    timestamp,
                    ZfsDataChecksum::Fletcher4,
                )
                .into_result()
                .unwrap();
            engine
                .edit_file_range_clearing_setid(
                    &cx,
                    &dataset,
                    file,
                    100,
                    10,
                    PunchHole,
                    timestamp,
                    ZfsDataChecksum::Fletcher4,
                )
                .into_result()
                .unwrap();
            let mut head = file_range_head(&cx, &engine);
            assert_eq!(
                head.stat(&cx, file).unwrap().0.mode & 0o7777,
                u64::from(mode)
            );
            assert_eq!(head.read(&cx, file, 0, 100).unwrap(), expected);

            let previous_txg = engine.committed_txg();
            let (_, token) = engine
                .write_file_data_clearing_setid(
                    &cx,
                    &dataset,
                    file,
                    0,
                    b"next",
                    timestamp,
                    ZfsDataChecksum::Fletcher4,
                )
                .into_result()
                .unwrap();
            assert_eq!(token.committed_txg(), previous_txg + 1);
            expected[..4].copy_from_slice(b"next");
            let mut head = file_range_head(&cx, &engine);
            assert_eq!(head.stat(&cx, file).unwrap().0.mode & 0o7777, expected_mode);
            assert_eq!(head.read(&cx, file, 0, 100).unwrap(), expected);

            engine
                .set_posix_attributes(
                    &cx,
                    &dataset,
                    file,
                    &ZfsPosixSetAttr {
                        mode: Some(mode),
                        ..ZfsPosixSetAttr::default()
                    },
                    timestamp,
                    ZfsDataChecksum::Fletcher4,
                )
                .into_result()
                .unwrap();
            engine
                .edit_file_range(
                    &cx,
                    &dataset,
                    file,
                    1,
                    1,
                    PunchHole,
                    timestamp,
                    ZfsDataChecksum::Fletcher4,
                )
                .into_result()
                .unwrap();
            expected[1] = 0;
            assert_eq!(
                file_range_head(&cx, &engine)
                    .stat(&cx, file)
                    .unwrap()
                    .0
                    .mode
                    & 0o7777,
                u64::from(mode),
                "the existing native range writer preserves permissions"
            );
            let previous_txg = engine.committed_txg();
            let (_, token) = engine
                .edit_file_range_clearing_setid(
                    &cx,
                    &dataset,
                    file,
                    3,
                    2,
                    PunchHole,
                    timestamp,
                    ZfsDataChecksum::Fletcher4,
                )
                .into_result()
                .unwrap();
            assert_eq!(token.committed_txg(), previous_txg + 1);
            expected[3..5].fill(0);
            let mut head = file_range_head(&cx, &engine);
            assert_eq!(head.stat(&cx, file).unwrap().0.mode & 0o7777, expected_mode);
            assert_eq!(head.read(&cx, file, 0, 100).unwrap(), expected);

            let previous_txg = engine.committed_txg();
            let (_, token) = engine
                .set_posix_attributes(
                    &cx,
                    &dataset,
                    file,
                    &ZfsPosixSetAttr {
                        size: Some(5),
                        mode: Some(mode),
                        clear_suid_sgid: true,
                        ..ZfsPosixSetAttr::default()
                    },
                    timestamp,
                    ZfsDataChecksum::Fletcher4,
                )
                .into_result()
                .unwrap();
            assert_eq!(token.committed_txg(), previous_txg + 1);
            expected.truncate(5);
            let mut head = file_range_head(&cx, &engine);
            assert_eq!(head.stat(&cx, file).unwrap().0.mode & 0o7777, expected_mode);
            assert_eq!(head.read(&cx, file, 0, 100).unwrap(), expected);
        }
        assert_pool_scrub_and_allocation_clean(&cx, &devices, POOL_GUID, None);
    }
}

#[test]
fn file_range_edits_preserve_edges_snapshots_links_and_exact_allocation() {
    use ffs_zfs::ZfsFileRangeOperation::{PunchHole, ZeroRange};

    const BLOCK: usize = 4096;
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_730_000_000,
        nanos: 987_654_321,
    };
    let payload: Vec<_> = (0..9 * BLOCK + 37)
        .map(|index| u8::try_from(index % 251 + 1).unwrap())
        .collect();
    for (zpl_version, mirror_width, ashift, deadlist_mode) in [
        (4, 1, 9, DeadlistMode::Bpobj),
        (5, 2, 12, DeadlistMode::NativeDeadlist),
    ] {
        let (mut engine, devices) = file_range_fixture(
            &cx,
            &PoolFixtureSpec {
                zpl_version,
                mirror_width,
                ashift,
                deadlist_mode,
                with_sa_spill_timestamps: zpl_version == 5,
                user_accounting: true,
                data_properties: vec![(b"recordsize", BLOCK as u64)],
                image_bytes: 24 * 1024 * 1024,
                ..PoolFixtureSpec::default()
            },
        );
        engine
            .write_file_data(
                &cx,
                &dataset,
                4,
                0,
                &payload,
                timestamp,
                ZfsDataChecksum::Sha256,
            )
            .into_result()
            .unwrap();
        engine
            .link_entry(&cx, &dataset, 4, 6, b"range-alias", timestamp)
            .into_result()
            .unwrap();
        engine
            .create_snapshot(&cx, &dataset, b"range-base", timestamp)
            .into_result()
            .unwrap();
        let (before, used_before) = file_range_head(&cx, &engine).stat(&cx, 4).unwrap();
        let edited_time = Timestamp {
            seconds: timestamp.seconds + 10,
            nanos: 123,
        };
        let (_, token) = engine
            .edit_file_range(
                &cx,
                &dataset,
                4,
                101,
                (4 * BLOCK + 202) as u64,
                PunchHole,
                edited_time,
                ZfsDataChecksum::Sha256,
            )
            .into_result()
            .unwrap();
        assert!(token.matches_engine(&engine));
        let mut expected = payload.clone();
        expected[101..4 * BLOCK + 303].fill(0);
        let mut head = file_range_head(&cx, &engine);
        assert_eq!(head.read(&cx, 4, 0, expected.len()).unwrap(), expected);
        assert_eq!(head.resolve(&cx, b"/sub/range-alias").unwrap(), 4);
        let (after, used_after) = head.stat(&cx, 4).unwrap();
        assert_eq!(used_after, used_before - 3 * BLOCK as u64);
        assert_eq!((after.times[1], after.times[2]), (edited_time, edited_time));
        assert_eq!(after.times[0], before.times[0]);
        assert_eq!(after.times[3], before.times[3]);
        assert_eq!(
            (
                after.size,
                after.links,
                after.generation,
                after.mode,
                after.uid,
                after.gid
            ),
            (
                before.size,
                before.links,
                before.generation,
                before.mode,
                before.uid,
                before.gid
            )
        );
        assert_eq!(
            head.seek(&cx, 4, BLOCK as u64, ffs_core::SeekWhence::Data)
                .unwrap(),
            4 * BLOCK as u64
        );
        assert_eq!(
            head.seek(&cx, 4, 0, ffs_core::SeekWhence::Hole).unwrap(),
            BLOCK as u64
        );

        let tail = expected.len() - 19;
        let (size, _) = engine
            .edit_file_range(
                &cx,
                &dataset,
                4,
                tail as u64,
                2 * BLOCK as u64,
                ZeroRange { keep_size: true },
                edited_time,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        assert_eq!(size, expected.len() as u64);
        expected[tail..].fill(0);
        let extend_at = expected.len() + 17;
        let (size, _) = engine
            .edit_file_range(
                &cx,
                &dataset,
                4,
                extend_at as u64,
                (BLOCK + 23) as u64,
                ZeroRange { keep_size: false },
                edited_time,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        expected.resize(extend_at + BLOCK + 23, 0);
        assert_eq!(size, expected.len() as u64);
        assert_eq!(
            file_range_head(&cx, &engine)
                .read(&cx, 4, 0, expected.len())
                .unwrap(),
            expected
        );

        let stable = file_range_head(&cx, &engine).stat(&cx, 4).unwrap();
        engine
            .edit_file_range(
                &cx,
                &dataset,
                4,
                size + 100,
                512,
                PunchHole,
                timestamp,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        let unchanged = file_range_head(&cx, &engine).stat(&cx, 4).unwrap();
        assert_eq!(unchanged.0.times, stable.0.times);
        assert_eq!((unchanged.0.size, unchanged.1), (stable.0.size, stable.1));

        engine
            .edit_file_range(
                &cx,
                &dataset,
                4,
                0,
                size,
                PunchHole,
                edited_time,
                ZfsDataChecksum::Fletcher4,
            )
            .into_result()
            .unwrap();
        let slot = engine.committed_slot();
        drop(engine);
        let fresh: Vec<_> = devices
            .iter()
            .map(FaultableMemberDevice::fresh_from_durable)
            .collect();
        let reopened =
            open_engine_on_devices(&cx, &fresh, default_write_opts(POOL_GUID, slot)).unwrap();
        let mut head = file_range_head(&cx, &reopened);
        assert_eq!(head.stat(&cx, 4).unwrap().0.size, size);
        assert_eq!(
            head.read(&cx, 4, 0, expected.len()).unwrap(),
            vec![0; expected.len()]
        );
        assert_eq!(
            head.seek(&cx, 4, 0, ffs_core::SeekWhence::Data)
                .unwrap_err()
                .to_errno(),
            libc::ENXIO
        );
        let mut snapshot = head.open_snapshot(&cx, b"range-base").unwrap();
        assert_eq!(snapshot.read(&cx, 4, 0, payload.len()).unwrap(), payload);
        assert_eq!(snapshot.stat(&cx, 4).unwrap().0.size, payload.len() as u64);
        assert_pool_scrub_and_allocation_clean(&cx, &fresh, POOL_GUID, Some(slot));
    }
}

#[test]
fn file_range_large_sparse_edits_skip_holes_and_extend_without_allocation() {
    use ffs_zfs::ZfsFileRangeOperation::{PunchHole, ZeroRange};

    const FAR: u64 = 1_u64 << 42;
    const NEW_EOF: u64 = (1_u64 << 50) + 4096;
    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_730_000_001,
        nanos: 0,
    };
    let (mut engine, devices) = file_range_fixture(
        &cx,
        &PoolFixtureSpec {
            zpl_version: 4,
            data_properties: vec![(b"recordsize", 4096)],
            ..PoolFixtureSpec::default()
        },
    );
    let (file, _) = engine
        .create_file(
            &cx,
            &dataset,
            2,
            b"sparse-range",
            0o644,
            1000,
            1000,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .expect("create the sparse file in the initially empty dataset");
    let prefix = vec![0x45; 4096];
    engine
        .write_file_data(
            &cx,
            &dataset,
            file,
            0,
            &prefix,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    engine
        .write_file_data(
            &cx,
            &dataset,
            file,
            FAR,
            b"TAIL",
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let used = file_range_head(&cx, &engine).stat(&cx, file).unwrap().1;
    engine
        .edit_file_range(
            &cx,
            &dataset,
            file,
            4096,
            FAR - 4096,
            PunchHole,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let mut head = file_range_head(&cx, &engine);
    assert_eq!(head.read(&cx, file, 0, 4096).unwrap(), prefix);
    assert_eq!(head.read(&cx, file, FAR, 4).unwrap(), b"TAIL");
    assert_eq!(head.stat(&cx, file).unwrap().1, used);
    engine
        .edit_file_range(
            &cx,
            &dataset,
            file,
            1024,
            FAR + 3 - 1024,
            PunchHole,
            timestamp,
            ZfsDataChecksum::Sha256,
        )
        .into_result()
        .unwrap();
    let mut head = file_range_head(&cx, &engine);
    assert_eq!(head.read(&cx, file, 0, 1024).unwrap(), vec![0x45; 1024]);
    assert_eq!(head.read(&cx, file, 1024, 4096).unwrap(), vec![0; 4096]);
    assert_eq!(head.read(&cx, file, FAR, 4).unwrap(), b"\0\0\0L");
    assert_eq!(
        head.seek(&cx, file, 4096, ffs_core::SeekWhence::Data)
            .unwrap(),
        FAR
    );
    let used = head.stat(&cx, file).unwrap().1;
    let (size, _) = engine
        .edit_file_range(
            &cx,
            &dataset,
            file,
            NEW_EOF - 4096,
            4096,
            ZeroRange { keep_size: false },
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let mut head = file_range_head(&cx, &engine);
    assert_eq!(size, NEW_EOF);
    assert_eq!(head.stat(&cx, file).unwrap().1, used);
    assert_eq!(
        head.read(&cx, file, NEW_EOF - 4096, 4096).unwrap(),
        vec![0; 4096]
    );
    engine
        .edit_file_range(
            &cx,
            &dataset,
            file,
            0,
            NEW_EOF,
            PunchHole,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let mut head = file_range_head(&cx, &engine);
    assert_eq!(head.stat(&cx, file).unwrap().1, 0);
    assert_eq!(head.stat(&cx, file).unwrap().0.size, NEW_EOF);
    assert_eq!(
        head.seek(&cx, file, 0, ffs_core::SeekWhence::Hole).unwrap(),
        0
    );
    assert_eq!(
        head.seek(&cx, file, 0, ffs_core::SeekWhence::Data)
            .unwrap_err()
            .to_errno(),
        libc::ENXIO
    );

    let slot = engine.committed_slot();
    let txg = engine.committed_txg();
    drop(head);
    drop(engine);
    let fresh: Vec<_> = devices
        .iter()
        .map(FaultableMemberDevice::fresh_from_durable)
        .collect();
    let reopened =
        open_engine_on_devices(&cx, &fresh, default_write_opts(POOL_GUID, slot)).unwrap();
    assert_eq!(reopened.committed_txg(), txg);
    let mut head = file_range_head(&cx, &reopened);
    assert_eq!(head.resolve(&cx, b"/sparse-range").unwrap(), file);
    assert_eq!(head.stat(&cx, file).unwrap().0.size, NEW_EOF);
    assert_eq!(head.stat(&cx, file).unwrap().1, 0);
    for offset in [0, FAR, NEW_EOF - 4096] {
        assert_eq!(head.read(&cx, file, offset, 4096).unwrap(), vec![0; 4096]);
    }
    assert_eq!(
        head.seek(&cx, file, 0, ffs_core::SeekWhence::Data)
            .unwrap_err()
            .to_errno(),
        libc::ENXIO
    );
    assert_pool_scrub_and_allocation_clean(&cx, &fresh, POOL_GUID, Some(slot));
}

#[test]
fn file_range_reclaims_project_quota_bytes_without_changing_object_counts() {
    use ffs_zfs::ZfsFileRangeOperation::PunchHole;

    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_730_000_002,
        nanos: 0,
    };
    let (mut engine, devices) = file_range_fixture(
        &cx,
        &PoolFixtureSpec {
            project_accounting: true,
            sa_project_id: Some(42),
            additional_write_features: vec![(b"org.zfsonlinux:project_quota", 1)],
            data_properties: vec![(b"recordsize", 4096)],
            deadlist_mode: DeadlistMode::NativeDeadlist,
            ..PoolFixtureSpec::default()
        },
    );
    engine
        .write_file_data(
            &cx,
            &dataset,
            4,
            0,
            &vec![0x61; 6 * 4096],
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let (before_node, before) = native_accounting_snapshot(&cx, &engine, &devices[0]);
    engine
        .edit_file_range(
            &cx,
            &dataset,
            4,
            4096,
            2 * 4096,
            PunchHole,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    let (after_node, after) = native_accounting_snapshot(&cx, &engine, &devices[0]);
    assert_eq!(
        after_node.unwrap().used_bytes(),
        before_node.unwrap().used_bytes() - 8192
    );
    for (index, owner) in [b"3e8".as_slice(), b"3e8".as_slice(), b"2a".as_slice()]
        .into_iter()
        .enumerate()
    {
        let mut expected = before[index].clone();
        *expected.get_mut(owner).unwrap() -= 8192;
        assert_eq!(
            after[index], expected,
            "only the file owner's physical-byte charge may change"
        );
    }
    assert_pool_scrub_and_allocation_clean(&cx, &devices, POOL_GUID, None);
}

#[test]
fn file_range_invalid_bounds_times_and_native_flags_refuse_before_writes() {
    use ffs_zfs::ZfsFileRangeOperation::{PunchHole, ZeroRange};

    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_730_000_003,
        nanos: 0,
    };
    let (mut engine, devices) = file_range_fixture(&cx, &PoolFixtureSpec::default());
    for operation in [PunchHole, ZeroRange { keep_size: false }] {
        assert_native_write_refused(&mut engine, &devices, libc::ENOENT, |writer| {
            writer.edit_file_range(
                &cx,
                &dataset,
                4,
                0,
                1,
                operation,
                timestamp,
                ZfsDataChecksum::Fletcher4,
            )
        });
    }
    let (file, _) = engine
        .create_file(
            &cx,
            &dataset,
            2,
            b"range-admission",
            0o644,
            1000,
            1000,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
        .into_result()
        .unwrap();
    for (offset, length) in [
        (0, 0),
        (u64::MAX, 1),
        (i64::MAX as u64, 1),
        (1, i64::MAX as u64),
    ] {
        assert_native_write_refused(&mut engine, &devices, libc::EINVAL, |writer| {
            writer.edit_file_range(
                &cx,
                &dataset,
                file,
                offset,
                length,
                PunchHole,
                timestamp,
                ZfsDataChecksum::Fletcher4,
            )
        });
    }
    assert_native_write_refused(&mut engine, &devices, libc::EINVAL, |writer| {
        writer.edit_file_range(
            &cx,
            &dataset,
            file,
            0,
            1,
            PunchHole,
            Timestamp {
                nanos: 1_000_000_000,
                ..timestamp
            },
            ZfsDataChecksum::Fletcher4,
        )
    });
    assert_native_write_refused(&mut engine, &devices, libc::EISDIR, |writer| {
        writer.edit_file_range(
            &cx,
            &dataset,
            2,
            0,
            1,
            PunchHole,
            timestamp,
            ZfsDataChecksum::Fletcher4,
        )
    });
    for flag in [1_u64 << 32, 1_u64 << 36, 1_u64 << 38] {
        let (mut protected, devices) = file_range_fixture(
            &cx,
            &PoolFixtureSpec {
                deadlist_mode: DeadlistMode::Bpobj,
                zpl_flags: BTreeMap::from([(4, 0x408 | flag)]),
                ..PoolFixtureSpec::default()
            },
        );
        let mut head = file_range_head(&cx, &protected);
        let protected_file = head.resolve(&cx, b"/hello.txt").unwrap();
        let (metadata, _) = head.stat(&cx, protected_file).unwrap();
        assert_eq!(metadata.kind, Kind::Regular);
        assert_ne!(metadata.flags & flag, 0);
        for operation in [PunchHole, ZeroRange { keep_size: false }] {
            assert_native_write_refused(&mut protected, &devices, libc::EPERM, |writer| {
                writer.edit_file_range(
                    &cx,
                    &dataset,
                    protected_file,
                    0,
                    17,
                    operation,
                    timestamp,
                    ZfsDataChecksum::Fletcher4,
                )
            });
        }
    }
}

#[test]
fn file_range_persistence_cuts_keep_exact_old_or_new_bytes_and_snapshot_ownership() {
    use ffs_zfs::ZfsFileRangeOperation::{PunchHole, ZeroRange};
    use std::sync::atomic::{AtomicBool, Ordering};

    let cx = Cx::for_testing();
    let dataset = [b"data".to_vec()];
    let timestamp = Timestamp {
        seconds: 1_730_000_004,
        nanos: 0,
    };
    let edited_time = Timestamp {
        seconds: timestamp.seconds + 1,
        nanos: 17,
    };
    let payload = vec![0x5A; 5 * 4096 + 17];
    let (mut seed, seed_devices) = file_range_fixture(
        &cx,
        &PoolFixtureSpec {
            data_properties: vec![(b"recordsize", 4096)],
            deadlist_mode: DeadlistMode::NativeDeadlist,
            user_accounting: true,
            ..PoolFixtureSpec::default()
        },
    );
    seed.write_file_data(
        &cx,
        &dataset,
        4,
        0,
        &payload,
        timestamp,
        ZfsDataChecksum::Fletcher4,
    )
    .into_result()
    .unwrap();
    seed.set_posix_attributes(
        &cx,
        &dataset,
        4,
        &ffs_zfs::ZfsPosixSetAttr {
            mode: Some(0o6755),
            ..ffs_zfs::ZfsPosixSetAttr::default()
        },
        timestamp,
        ZfsDataChecksum::Fletcher4,
    )
    .into_result()
    .unwrap();
    seed.create_snapshot(&cx, &dataset, b"range-cut", timestamp)
        .into_result()
        .unwrap();
    let pre_slot = seed.committed_slot();
    let pre_txg = seed.committed_txg();
    let old_used = file_range_head(&cx, &seed).stat(&cx, 4).unwrap().1;
    let initial: Vec<_> = seed_devices
        .iter()
        .map(FaultableMemberDevice::durable_snapshot)
        .collect();
    drop(seed);
    drop(seed_devices);

    for operation in [PunchHole, ZeroRange { keep_size: false }] {
        let length = if operation == PunchHole {
            3 * 4096 + 400
        } else {
            payload.len() + 4096
        };
        let mut expected = payload.clone();
        if operation != PunchHole {
            expected.resize(101 + length, 0);
        }
        expected[101..101 + length].fill(0);
        let released = if operation == PunchHole {
            2 * 4096
        } else {
            5 * 4096
        };
        for stage in 0..7_u8 {
            let devices: Vec<_> = initial
                .iter()
                .cloned()
                .map(FaultableMemberDevice::new)
                .collect();
            let mut engine =
                open_engine_on_devices(&cx, &devices, default_write_opts(POOL_GUID, pre_slot))
                    .unwrap();
            let tripped = Arc::new(AtomicBool::new(false));
            let hook_tripped = Arc::clone(&tripped);
            engine.with_fault_hook(move |event| {
                let cut = matches!(
                    (stage, event.stage),
                    (0, ZfsPersistenceStage::ChildBlocksWrite { .. })
                        | (1, ZfsPersistenceStage::DatasetMetadataBarrier { .. })
                        | (2, ZfsPersistenceStage::MosSpaceMapBarrier { .. })
                        | (3, ZfsPersistenceStage::MosRootBarrier { .. })
                        | (4, ZfsPersistenceStage::UberblockBarrier { wave: 1, .. })
                        | (5, ZfsPersistenceStage::UberblockWrite { label: 2, .. })
                        | (6, ZfsPersistenceStage::BeforeAcknowledge)
                );
                if cut {
                    hook_tripped.store(true, Ordering::SeqCst);
                    Err(FfsError::Cancelled)
                } else {
                    Ok(())
                }
            });
            let outcome = engine.edit_file_range_clearing_setid(
                &cx,
                &dataset,
                4,
                101,
                length as u64,
                operation,
                edited_time,
                ZfsDataChecksum::Sha256,
            );
            assert!(
                tripped.load(Ordering::SeqCst),
                "range operation missed stage {stage}"
            );
            let published = stage >= 5;
            let target_slot = match outcome {
                ZfsTxOutcome::NotCommitted(FfsError::Cancelled) if stage < 4 => None,
                ZfsTxOutcome::Uncertain {
                    target_txg,
                    target_slot,
                    ..
                } if (4..=5).contains(&stage) => {
                    assert_eq!(target_txg, pre_txg + 1);
                    assert!(engine.requires_recovery());
                    Some(target_slot)
                }
                ZfsTxOutcome::Committed { value, token } if stage == 6 => {
                    assert_eq!(value, expected.len() as u64);
                    assert_eq!(token.committed_txg(), pre_txg + 1);
                    Some(token.published_slot())
                }
                other => panic!("unexpected range outcome at stage {stage}: {other:?}"),
            };
            drop(engine);
            let crashed: Vec<_> = devices
                .iter()
                .map(FaultableMemberDevice::fresh_from_durable)
                .collect();
            if stage == 4 {
                let mut absent = default_write_opts(POOL_GUID, target_slot.unwrap());
                absent.reconcile_torn_uberblocks = true;
                assert!(
                    open_engine_on_devices(&cx, &crashed, absent).is_err(),
                    "first-wave pre-barrier target is not durable"
                );
            }
            let slot = if published {
                target_slot.unwrap()
            } else {
                pre_slot
            };
            let mut options = default_write_opts(POOL_GUID, slot);
            options.reconcile_torn_uberblocks = (4..=5).contains(&stage);
            let recovered = open_engine_on_devices(&cx, &crashed, options).unwrap();
            assert_eq!(recovered.committed_txg(), pre_txg + u64::from(published));
            let mut head = file_range_head(&cx, &recovered);
            let bytes = if published { &expected } else { &payload };
            assert_eq!(head.read(&cx, 4, 0, bytes.len() + 1).unwrap(), *bytes);
            let (metadata, used) = head.stat(&cx, 4).unwrap();
            assert_eq!(metadata.size, bytes.len() as u64);
            assert_eq!(
                metadata.mode & 0o7777,
                if published { 0o755 } else { 0o6755 }
            );
            assert_eq!(
                metadata.times[1],
                if published { edited_time } else { timestamp }
            );
            assert_eq!(used, old_used - if published { released } else { 0 });
            let mut snapshot = head.open_snapshot(&cx, b"range-cut").unwrap();
            assert_eq!(snapshot.read(&cx, 4, 0, payload.len()).unwrap(), payload);
            assert_eq!(snapshot.stat(&cx, 4).unwrap().1, old_used);
            assert_eq!(snapshot.stat(&cx, 4).unwrap().0.mode & 0o7777, 0o6755);
            assert_pool_scrub_and_allocation_clean(&cx, &crashed, POOL_GUID, Some(slot));
        }
    }
}
