#![forbid(unsafe_code)]

use asupersync::Cx;
use criterion::{Criterion, criterion_group};
use ffs_btrfs::{BtrfsDirItem, BtrfsInodeItem, BtrfsInodeRef};
use ffs_core::{Ext4JournalReplayMode, OpenFs, OpenOptions, RequestScope};
use ffs_harness::load_sparse_fixture;
use ffs_ondisk::{
    BtrfsHeader, BtrfsRaidProfile, BtrfsSuperblock, EXT_INIT_MAX_LEN, Ext4DirEntry, Ext4Extent,
    Ext4GroupDesc, Ext4Inode, chunk_type_flags, dx_hash, ext4_casefold_key, ext4_chksum,
    lookup_in_dir_block, parse_dev_item, parse_dir_block, parse_dx_root, parse_extent_tree,
    parse_internal_items, parse_leaf_items, parse_sys_chunk_array, parse_xattr_block,
    verify_btrfs_superblock_checksum, verify_btrfs_tree_block_checksum,
};
use ffs_types::{BlockNumber, InodeNumber};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::fmt::Write as _;
use std::fs::File;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::NamedTempFile;

const BTRFS_BENCH_BLOCK_SIZE: usize = 4096;
const BTRFS_HEADER_SIZE: usize = 101;
const BTRFS_KEY_PTR_SIZE: usize = 33;

fn self_identity() -> String {
    let Ok(path) = std::env::current_exe() else {
        return "unavailable".to_owned();
    };
    let Ok(bytes) = std::fs::read(&path) else {
        return "unavailable".to_owned();
    };
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(encoded, "{byte:02x}");
    }
    format!("{} ({} bytes) {}", encoded, bytes.len(), path.display())
}

fn fixture_path(name: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("conformance/fixtures")
        .join(name)
}

fn golden_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .join("conformance/golden")
        .join(name)
}

const RUNTIME_HTREE_FILE_CONTENT: &[u8] = b"hello from FrankenFS runtime htree bench\n";
const RUNTIME_HTREE_FILE_COUNT: usize = 256;
const RUNTIME_HTREE_HASH_SEED: &str = "11111111-2222-3333-4444-555555555555";

fn trace_ext4_tools() -> bool {
    std::env::var_os("FFS_TRACE_EXT4_TOOLS").is_some()
}

fn run_debugfs_w(image: &Path, cmd: &str) {
    if trace_ext4_tools() {
        eprintln!("debugfs params: -w -R {cmd:?} {}", image.display());
    }
    let status = Command::new("debugfs")
        .args(["-w", "-R", cmd])
        .arg(image)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run debugfs");
    assert!(status.success(), "debugfs -w -R {cmd:?} failed");
}

fn run_e2fsck_dir_index(image: &Path) {
    if trace_ext4_tools() {
        eprintln!("e2fsck params: -fyD {}", image.display());
    }
    let status = Command::new("e2fsck")
        .args(["-fyD"])
        .arg(image)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run e2fsck");

    let code = status.code().unwrap_or(-1);
    assert!(
        matches!(code, 0 | 1),
        "e2fsck -fyD failed with exit code {code}"
    );
}

fn create_runtime_htree_image(image: &Path) {
    let file = File::create(image).expect("create runtime htree image file");
    file.set_len(64 * 1024 * 1024)
        .expect("set runtime htree image length");
    drop(file);

    if trace_ext4_tools() {
        eprintln!(
            "mkfs.ext4 params: -L ffs-runtime-dx -b 4096 -q -O dir_index {}",
            image.display()
        );
    }
    let status = Command::new("mkfs.ext4")
        .args([
            "-L",
            "ffs-runtime-dx",
            "-b",
            "4096",
            "-q",
            "-O",
            "dir_index",
        ])
        .arg(image)
        .stderr(std::process::Stdio::null())
        .status()
        .expect("run mkfs.ext4");
    assert!(status.success(), "mkfs.ext4 -O dir_index failed");

    run_debugfs_w(
        image,
        &format!("set_super_value hash_seed {RUNTIME_HTREE_HASH_SEED}"),
    );
    run_debugfs_w(image, "mkdir /htree");

    let content = NamedTempFile::new().expect("create runtime htree content file");
    std::fs::write(content.path(), RUNTIME_HTREE_FILE_CONTENT)
        .expect("write runtime htree content file");
    for idx in 0..RUNTIME_HTREE_FILE_COUNT {
        run_debugfs_w(
            image,
            &format!(
                "write {} /htree/file_{idx:03}.txt",
                content.path().display()
            ),
        );
    }
    run_debugfs_w(
        image,
        &format!("write {} /readme-dx.txt", content.path().display()),
    );

    run_e2fsck_dir_index(image);
}

fn runtime_htree_image_path() -> (PathBuf, Option<NamedTempFile>) {
    let local_golden = golden_path("ext4_dir_index_reference.ext4");
    if local_golden.exists() {
        return (local_golden, None);
    }

    let image = NamedTempFile::new().expect("create generated runtime htree image");
    create_runtime_htree_image(image.path());
    (image.path().to_path_buf(), Some(image))
}

fn open_runtime_htree_fixture() -> (OpenFs, Cx, Ext4Inode, Option<NamedTempFile>) {
    let (path, image_guard) = runtime_htree_image_path();
    let cx = Cx::for_testing();
    let opts = OpenOptions {
        ext4_journal_replay_mode: Ext4JournalReplayMode::Skip,
        ..OpenOptions::default()
    };
    let fs = OpenFs::open_with_options(&cx, &path, &opts).expect("open runtime htree image");
    let htree = fs
        .lookup(&cx, InodeNumber(2), OsStr::new("htree"))
        .expect("lookup /htree");
    let htree_inode = fs.read_inode(&cx, htree.ino).expect("read /htree inode");
    assert!(
        htree_inode.has_htree_index(),
        "/htree must be backed by a real ext4 htree index"
    );
    (fs, cx, htree_inode, image_guard)
}

fn linear_runtime_htree_lookup(
    fs: &OpenFs,
    cx: &Cx,
    scope: &RequestScope,
    dir_inode: &Ext4Inode,
    name: &[u8],
) -> Option<Ext4DirEntry> {
    let block_size = u64::from(fs.block_size());
    let num_blocks = dir_inode.size.div_ceil(block_size);

    for logical_block in 0..num_blocks {
        let logical_block =
            u32::try_from(logical_block).expect("runtime htree logical block fits u32");
        let Some((physical_block, unwritten)) = fs
            .resolve_extent(cx, scope, dir_inode, logical_block)
            .expect("resolve runtime htree directory block")
        else {
            continue;
        };
        if unwritten {
            continue;
        }
        let block = fs
            .read_block_with_scope(cx, scope, BlockNumber(physical_block))
            .expect("read runtime htree directory block");
        if let Some(entry) =
            lookup_in_dir_block(&block, fs.block_size(), name).expect("scan directory block")
        {
            return Some(entry);
        }
    }

    None
}

fn btrfs_internal_node_block() -> Vec<u8> {
    let mut block = vec![0_u8; BTRFS_BENCH_BLOCK_SIZE];
    block
        .get_mut(0x60..0x64)
        .expect("btrfs nritems field")
        .copy_from_slice(&2_u32.to_le_bytes());
    *block.get_mut(0x64).expect("btrfs level field") = 1;
    write_btrfs_key_ptr(&mut block, 0, (256, 132, 0), 0x4000, 10);
    write_btrfs_key_ptr(&mut block, 1, (512, 132, 100), 0x8000, 10);
    block
}

fn write_btrfs_key_ptr(
    block: &mut [u8],
    index: usize,
    key: (u64, u8, u64),
    blockptr: u64,
    generation: u64,
) {
    let (objectid, item_type, offset) = key;
    let base = BTRFS_HEADER_SIZE + index * BTRFS_KEY_PTR_SIZE;
    block
        .get_mut(base..base + 8)
        .expect("btrfs key objectid field")
        .copy_from_slice(&objectid.to_le_bytes());
    *block.get_mut(base + 8).expect("btrfs key item_type field") = item_type;
    block
        .get_mut(base + 9..base + 17)
        .expect("btrfs key offset field")
        .copy_from_slice(&offset.to_le_bytes());
    block
        .get_mut(base + 17..base + 25)
        .expect("btrfs key_ptr blockptr field")
        .copy_from_slice(&blockptr.to_le_bytes());
    block
        .get_mut(base + 25..base + 33)
        .expect("btrfs key_ptr generation field")
        .copy_from_slice(&generation.to_le_bytes());
}

fn bench_ext4_inode_parse(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("ext4_inode_regular_file.json"))
        .expect("load inode fixture");

    c.bench_function("ext4_inode_parse", |b| {
        b.iter(|| Ext4Inode::parse_from_bytes(black_box(&data)).expect("inode parse"));
    });
}

fn bench_ext4_group_desc_32(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("ext4_group_desc_32byte.json"))
        .expect("load gd32 fixture");

    c.bench_function("ext4_group_desc_32byte", |b| {
        b.iter(|| Ext4GroupDesc::parse_from_bytes(black_box(&data), 32).expect("gd32 parse"));
    });
}

fn bench_ext4_group_desc_64(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("ext4_group_desc_64byte.json"))
        .expect("load gd64 fixture");

    c.bench_function("ext4_group_desc_64byte", |b| {
        b.iter(|| Ext4GroupDesc::parse_from_bytes(black_box(&data), 64).expect("gd64 parse"));
    });
}

// bd-fjeb0 — encode-side benches for Ext4GroupDesc::write_to_bytes.
// Pair the existing parse benches above so the perf gate tracks both
// sides of the encode/decode bijection (the bd-ov7zr proptest suite +
// bd-38xrn fuzz target pin correctness; these benches pin latency).

fn bench_ext4_group_desc_write_32(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("ext4_group_desc_32byte.json"))
        .expect("load gd32 fixture");
    let gd = Ext4GroupDesc::parse_from_bytes(&data, 32).expect("gd32 parse for write bench");
    let mut buf = [0_u8; 32];

    c.bench_function("ext4_group_desc_32byte_write", |b| {
        b.iter(|| {
            gd.write_to_bytes(black_box(&mut buf), 32)
                .expect("gd32 write");
        });
    });
}

fn bench_ext4_group_desc_write_64(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("ext4_group_desc_64byte.json"))
        .expect("load gd64 fixture");
    let gd = Ext4GroupDesc::parse_from_bytes(&data, 64).expect("gd64 parse for write bench");
    let mut buf = [0_u8; 64];

    c.bench_function("ext4_group_desc_64byte_write", |b| {
        b.iter(|| {
            gd.write_to_bytes(black_box(&mut buf), 64)
                .expect("gd64 write");
        });
    });
}

fn bench_ext4_dir_block_parse(c: &mut Criterion) {
    let data =
        load_sparse_fixture(&fixture_path("ext4_dir_block.json")).expect("load dir block fixture");

    c.bench_function("ext4_dir_block_parse", |b| {
        b.iter(|| {
            let entries = parse_dir_block(black_box(&data), 4096).expect("dir block parse");
            black_box(entries);
        });
    });
}

fn bench_ext4_extent_tree_parse(c: &mut Criterion) {
    // The inode fixture contains a 60-byte extent tree in the i_block region.
    let inode_data = load_sparse_fixture(&fixture_path("ext4_inode_regular_file.json"))
        .expect("load inode fixture");
    let inode = Ext4Inode::parse_from_bytes(&inode_data).expect("inode parse");

    c.bench_function("ext4_extent_tree_parse", |b| {
        b.iter(|| {
            let _ = black_box(parse_extent_tree(black_box(&inode.extent_bytes)));
        });
    });
}

fn bench_btrfs_sys_chunk_parse(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("btrfs_superblock_with_chunks.json"))
        .expect("load btrfs chunks fixture");
    let sb = ffs_ondisk::BtrfsSuperblock::parse_superblock_region(&data)
        .expect("parse btrfs superblock");

    c.bench_function("btrfs_sys_chunk_parse", |b| {
        b.iter(|| {
            let entries =
                parse_sys_chunk_array(black_box(&sb.sys_chunk_array)).expect("chunk parse");
            black_box(entries);
        });
    });
}

// bd-6eyj5 — bench coverage for four hot ext4/btrfs metadata parsers
// that previously had no perf gate. Each is on the mounted-image
// metadata read path; a regression here would silently slow throughput
// without tripping the existing perf gate.

fn bench_ext4_xattr_block_parse(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("ext4_xattr_block.json"))
        .expect("load ext4_xattr_block fixture");

    c.bench_function("ext4_xattr_block_parse", |b| {
        b.iter(|| {
            let xattrs = parse_xattr_block(black_box(&data)).expect("xattr block parse");
            black_box(xattrs);
        });
    });
}

fn bench_ext4_dx_root_parse(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("ext4_htree_dx_root.json"))
        .expect("load ext4_htree_dx_root fixture");

    c.bench_function("ext4_dx_root_parse", |b| {
        b.iter(|| {
            let root = parse_dx_root(black_box(&data)).expect("dx root parse");
            black_box(root);
        });
    });
}

fn bench_btrfs_dev_item_parse(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("btrfs_devitem.json"))
        .expect("load btrfs_devitem fixture");

    c.bench_function("btrfs_dev_item_parse", |b| {
        b.iter(|| {
            let item = parse_dev_item(black_box(&data)).expect("dev item parse");
            black_box(item);
        });
    });
}

// bd-js1k5 — bench coverage for btrfs parsers on the mounted-image
// hot path that bd-6eyj5 left un-benched. The existing
// `bench_btrfs_sys_chunk_parse` pre-parses the superblock during
// setup and benches only sys_chunk_array decoding; these benches
// expose the parsers themselves to the perf gate.

fn bench_btrfs_superblock_parse_region(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("btrfs_superblock_sparse.json"))
        .expect("load btrfs_superblock_sparse fixture");

    c.bench_function("btrfs_superblock_parse_region", |b| {
        b.iter(|| {
            let sb = BtrfsSuperblock::parse_superblock_region(black_box(&data))
                .expect("btrfs superblock parse");
            black_box(sb);
        });
    });
}

fn bench_btrfs_leaf_items_parse(c: &mut Criterion) {
    let data = load_sparse_fixture(&fixture_path("btrfs_fstree_leaf.json"))
        .expect("load btrfs_fstree_leaf fixture");

    c.bench_function("btrfs_leaf_items_parse", |b| {
        b.iter(|| {
            let (header, items) = parse_leaf_items(black_box(&data)).expect("leaf items parse");
            black_box((header, items));
        });
    });
}

fn bench_btrfs_internal_items_parse(c: &mut Criterion) {
    let data = btrfs_internal_node_block();

    c.bench_function("btrfs_internal_items_parse", |b| {
        b.iter(|| {
            let (header, ptrs) =
                parse_internal_items(black_box(&data)).expect("internal items parse");
            black_box((header, ptrs));
        });
    });
}

fn bench_btrfs_header_parse_from_block(c: &mut Criterion) {
    // Header-only access path; transitively covered by the leaf/internal
    // parsers but also called standalone elsewhere in the codebase.
    let data = load_sparse_fixture(&fixture_path("btrfs_fstree_leaf.json"))
        .expect("load btrfs_fstree_leaf fixture for header bench");

    c.bench_function("btrfs_header_parse_from_block", |b| {
        b.iter(|| {
            let header = BtrfsHeader::parse_from_block(black_box(&data)).expect("header parse");
            black_box(header);
        });
    });
}

fn bench_ext4_extent_tree_index_parse(c: &mut Criterion) {
    // The leaf path is exercised by `bench_ext4_extent_tree_parse` via the
    // inode fixture's i_block region; this bench covers the internal-node
    // (index) decoding path, which uses Ext4ExtentIndex layout instead of
    // Ext4Extent layout.
    let data = load_sparse_fixture(&fixture_path("ext4_extent_tree_index.json"))
        .expect("load ext4_extent_tree_index fixture");

    c.bench_function("ext4_extent_tree_index_parse", |b| {
        b.iter(|| {
            let _ = black_box(parse_extent_tree(black_box(&data)));
        });
    });
}

// bd-7pfh0 — bench coverage for ext4 dx_hash directory hash function
// across all 5 supported hash versions plus the unknown-version
// fallback. dx_hash is on every htree directory lookup; a regression
// in any variant (swapped LEGACY multiplier, mis-aligned MD4 chunk
// loop, slower TEA Feistel rounds) would silently degrade lookup
// throughput without tripping any existing perf gate. Pairs with
// bd-590tc (proptest MRs) and the existing dx_hash unit tests for
// correctness; this pins the latency floor.

fn bench_ext4_dx_hash(c: &mut Criterion) {
    // Hash-version constants per fs/ext4/ext4.h (private in ondisk):
    //   0 = LEGACY (signed), 1 = HALF_MD4, 2 = TEA (signed),
    //   3 = LEGACY_UNSIGNED, 4 = HALF_MD4_UNSIGNED, 5 = TEA_UNSIGNED.
    const HASH_VERSIONS: [(u8, &str); 6] = [
        (0, "legacy_signed"),
        (1, "half_md4_signed"),
        (2, "tea_signed"),
        (3, "legacy_unsigned"),
        (4, "half_md4_unsigned"),
        (5, "tea_unsigned"),
    ];

    // Representative directory-name workload: 32 names of varying
    // lengths covering short ("a"), typical ("README.md"), nested
    // ("path/to/some/deeply/nested/file.txt"), max-length-ish, and
    // unicode-heavy patterns (as raw bytes — dx_hash takes &[u8]).
    const ASCII_UPPERCASE: &[u8; 26] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let names: Vec<Vec<u8>> = (0_usize..32)
        .map(|i| {
            let mut name = format!("entry_{i:04}_").into_bytes();
            // Pad to varying lengths to exercise both single-chunk
            // and multi-chunk paths in HALF_MD4 (32-byte chunks) and
            // TEA (16-byte chunks).
            let pad_len = 4 + (i % 64);
            name.extend(std::iter::repeat_n(
                ASCII_UPPERCASE[i % ASCII_UPPERCASE.len()],
                pad_len,
            ));
            name
        })
        .collect();

    let seed: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

    for (version, label) in HASH_VERSIONS {
        c.bench_function(&format!("ext4_dx_hash_{label}"), |b| {
            b.iter(|| {
                for name in &names {
                    let (major, minor) =
                        dx_hash(black_box(version), black_box(name), black_box(&seed));
                    black_box((major, minor));
                }
            });
        });
    }
}

// bd-rx88y — Criterion benches for `ext4_casefold_key` across the
// three distinct code paths in `casefold_name` (UTF-8 ASCII fast
// path, UTF-8 with multi-codepoint sharp-s expansion, invalid-UTF-8
// ASCII fallback). The function is on the hot path for every
// directory lookup on a casefold-enabled ext4 filesystem
// (lookup_in_dir_block_casefold calls it once per target plus once
// per scanned entry). Without these benches a regression in any
// branch — e.g., introducing per-char allocation, switching from
// chars() to grapheme iteration — would silently slow every
// casefold dir lookup with no signal until end users notice.
//
// Pairs with bd-6rsow proptest (32 cases of equivalence-relation
// laws), bd-c7nid fuzz target (>1M iterations / session), and
// bd-7pfh0 (dx_hash benches across 6 hash versions) — the same
// hot-path-correctness/performance pattern, applied to the casefold
// fold instead of the dx_hash function.

fn bench_ext4_casefold_key_ascii(c: &mut Criterion) {
    // Pure ASCII filename — the fast path: UTF-8 valid, every char
    // is single-codepoint and lowercases in place.
    let names: Vec<&[u8]> = vec![
        b"README.md",
        b"src",
        b"main.rs",
        b"Cargo.toml",
        b"DOCUMENTATION_AND_NOTES.txt",
        b"a",
        b"some_quite_long_filename_with_many_characters_to_exercise.dat",
    ];
    c.bench_function("ext4_casefold_key_ascii", |b| {
        b.iter(|| {
            for name in &names {
                black_box(ext4_casefold_key(black_box(name)));
            }
        });
    });
}

fn bench_ext4_casefold_key_mixed_utf8(c: &mut Criterion) {
    // UTF-8 with embedded sharp-s — exercises the multi-codepoint
    // expansion branch. ß (U+00DF) and ẞ (U+1E9E) both expand to
    // "ss" via the explicit match in casefold_name.
    let names: Vec<&[u8]> = vec![
        "Straße.txt".as_bytes(),
        "GROẞBUCHSTABEN.md".as_bytes(),
        "café_passé.csv".as_bytes(),
        "MüllerStraße_Düsseldorf.log".as_bytes(),
        "naïve_façade_ßtest.dat".as_bytes(),
    ];
    c.bench_function("ext4_casefold_key_mixed_utf8", |b| {
        b.iter(|| {
            for name in &names {
                black_box(ext4_casefold_key(black_box(name)));
            }
        });
    });
}

fn bench_ext4_casefold_key_long_utf8(c: &mut Criterion) {
    // Long all-non-ASCII UTF-8 input — exercises the multi-byte
    // chars() iteration path with no ASCII fast steps. Tests that
    // long Unicode lookups don't regress with grapheme/normalization
    // overhead.
    let names: Vec<Vec<u8>> = vec![
        "ΑΒΓΔΕΖΗΘΙΚΛΜΝΞΟΠΡΣΤΥΦΧΨΩ".repeat(4).into_bytes(),
        "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ".repeat(2).into_bytes(),
        "你好世界这是一个长的中文文件名".repeat(3).into_bytes(),
        "אבגדהוזחטיכלמנסעפצקרשת".repeat(4).into_bytes(),
    ];
    c.bench_function("ext4_casefold_key_long_utf8", |b| {
        b.iter(|| {
            for name in &names {
                black_box(ext4_casefold_key(black_box(name.as_slice())));
            }
        });
    });
}

fn bench_ext4_casefold_key_invalid_utf8(c: &mut Criterion) {
    // Invalid UTF-8 — exercises the ASCII-fallback branch. Bytes
    // > 0x7F break UTF-8 validity, forcing the byte-by-byte ASCII
    // case fold path.
    let names: Vec<Vec<u8>> = vec![
        b"FILE\xff\xfe\xfd.bin".to_vec(),
        b"\x80\x81\x82SomeAsciiTail.dat".to_vec(),
        b"prefix\xc3middle\xc3suffix".to_vec(), // truncated UTF-8 lead
        b"\xff".repeat(64),
    ];
    c.bench_function("ext4_casefold_key_invalid_utf8", |b| {
        b.iter(|| {
            for name in &names {
                black_box(ext4_casefold_key(black_box(name.as_slice())));
            }
        });
    });
}

fn bench_btrfs_raid_profile_single(c: &mut Criterion) {
    // Single is the no-RAID-bit fallback path for single-device filesystems.
    let inputs = [
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA,
        chunk_type_flags::BTRFS_BLOCK_GROUP_METADATA,
        chunk_type_flags::BTRFS_BLOCK_GROUP_SYSTEM,
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_METADATA,
    ];
    c.bench_function("btrfs_raid_profile_single", |b| {
        b.iter(|| {
            for input in &inputs {
                black_box(BtrfsRaidProfile::from_chunk_type(black_box(*input)));
            }
        });
    });
}

fn bench_btrfs_raid_profile_raid0(c: &mut Criterion) {
    // Raid0 is the first matching cascade arm.
    let inputs = [
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0,
        chunk_type_flags::BTRFS_BLOCK_GROUP_METADATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0,
        chunk_type_flags::BTRFS_BLOCK_GROUP_SYSTEM | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0,
    ];
    c.bench_function("btrfs_raid_profile_raid0", |b| {
        b.iter(|| {
            for input in &inputs {
                black_box(BtrfsRaidProfile::from_chunk_type(black_box(*input)));
            }
        });
    });
}

fn bench_btrfs_raid_profile_dup(c: &mut Criterion) {
    // Dup is the final matching cascade arm before the Single fallback.
    let inputs = [
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_DUP,
        chunk_type_flags::BTRFS_BLOCK_GROUP_METADATA | chunk_type_flags::BTRFS_BLOCK_GROUP_DUP,
    ];
    c.bench_function("btrfs_raid_profile_dup", |b| {
        b.iter(|| {
            for input in &inputs {
                black_box(BtrfsRaidProfile::from_chunk_type(black_box(*input)));
            }
        });
    });
}

fn bench_btrfs_raid_profile_mixed(c: &mut Criterion) {
    // Mixed workload covering all 9 profile outcomes.
    let inputs = [
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA, // Single
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID0,
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1,
        chunk_type_flags::BTRFS_BLOCK_GROUP_METADATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1C3,
        chunk_type_flags::BTRFS_BLOCK_GROUP_METADATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID1C4,
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID10,
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID5,
        chunk_type_flags::BTRFS_BLOCK_GROUP_DATA | chunk_type_flags::BTRFS_BLOCK_GROUP_RAID6,
        chunk_type_flags::BTRFS_BLOCK_GROUP_METADATA | chunk_type_flags::BTRFS_BLOCK_GROUP_DUP,
    ];
    c.bench_function("btrfs_raid_profile_mixed", |b| {
        b.iter(|| {
            for input in &inputs {
                black_box(BtrfsRaidProfile::from_chunk_type(black_box(*input)));
            }
        });
    });
}

// bd-ibj7e — Criterion benches for the ext4 *_extra timestamp bit-pack
// helpers. extra_nsec / extra_epoch decode the [nsec:30][epoch:2] u32
// layout once per timestamp read on every inode access on ext4 v6+
// filesystems. atime_full / mtime_full / ctime_full / crtime_full are
// the composite (i64, u32) decoders used by stat() and friends.
//
// Pairs with bd-834zk (proptest MR for the bit-pack algebra), bd-fqzsz
// (libfuzzer >1M iter), and bd-rx88y / bd-obp9f (casefold + raid_profile
// trios) — same hot-path correctness/perf trio applied to the timestamp
// bit-pack. A regression that introduced per-call allocation, switched
// from bit-shifts to a slower byte-extracting path, or added unnecessary
// bounds checks would silently slow every inode timestamp read with no
// CI signal.

fn bench_ext4_extra_nsec_epoch(c: &mut Criterion) {
    // Representative *_extra payloads: zero, all-ones, mid-range
    // nanoseconds, all four epoch values, and the explicit kernel
    // boundary (epoch=3, nsec=999_999_999).
    let inputs: Vec<u32> = vec![
        0x0000_0000,
        0xFFFF_FFFF,
        0x3B9A_C9FF, // nsec=249,999,999 epoch=3 — high-bit nsec
        0x0000_0001, // epoch=1 only
        0x0000_0002, // epoch=2 only
        0x0000_0003, // epoch=3 only
        // 999,999,999 ns << 2 | 0 epoch  = canonical max-nsec
        (999_999_999_u32) << 2,
        // 999,999,999 ns << 2 | 3 epoch  = max nsec + max epoch
        ((999_999_999_u32) << 2) | 0x3,
    ];
    c.bench_function("ext4_extra_nsec_epoch", |b| {
        b.iter(|| {
            for &extra in &inputs {
                black_box(Ext4Inode::extra_nsec(black_box(extra)));
                black_box(Ext4Inode::extra_epoch(black_box(extra)));
            }
        });
    });
}

fn bench_ext4_inode_atime_full(c: &mut Criterion) {
    // The composite atime_full path: sign-extend signed_base, shift
    // epoch into bits 32+, extract nsec, return (i64, u32). Run it
    // on a real parsed inode so the field accesses are realistic
    // rather than dummy struct.
    let data = load_sparse_fixture(&fixture_path("ext4_inode_regular_file.json"))
        .expect("load inode fixture");
    let inode = Ext4Inode::parse_from_bytes(&data).expect("inode parse");

    c.bench_function("ext4_inode_atime_full", |b| {
        b.iter(|| {
            black_box(black_box(&inode).atime_full());
        });
    });
}

fn bench_ext4_inode_all_timestamps(c: &mut Criterion) {
    // Representative stat() workload: every stat call decodes all
    // four timestamps (atime, mtime, ctime, crtime). A regression
    // in any single decoder would show up here as 4× the per-call
    // overhead.
    let data = load_sparse_fixture(&fixture_path("ext4_inode_regular_file.json"))
        .expect("load inode fixture");
    let inode = Ext4Inode::parse_from_bytes(&data).expect("inode parse");

    c.bench_function("ext4_inode_all_timestamps", |b| {
        b.iter(|| {
            let i = black_box(&inode);
            black_box(i.atime_full());
            black_box(i.mtime_full());
            black_box(i.ctime_full());
            black_box(i.crtime_full());
        });
    });
}

// bd-zc9l4 — Criterion benches for the Ext4Extent split-bit unwritten
// decoder (actual_len + is_unwritten). These run once per extent
// visited on every extent walk on every ext4 filesystem — high-
// frequency hot path for read, write, scrub, and repair. A regression
// that introduced per-call allocation, switched from a single
// subtract to a multi-step decode, or added unnecessary bounds checks
// would silently slow every extent walk with no CI signal.
//
// Pairs with bd-j0zo3 (proptest MR), bd-p0jgk (libfuzzer >1M iter)
// — same hot-path correctness/perf trio applied to the extent
// split-bit decoder.

fn bench_ext4_extent_actual_len_written(c: &mut Criterion) {
    // Workload of written extents (raw_len <= EXT_INIT_MAX_LEN).
    // Representative sizes: 1, 64, 4096, 0x7FFF, 0x8000 (boundary).
    let extents: Vec<Ext4Extent> = [1_u16, 64, 4096, 0x7FFF, EXT_INIT_MAX_LEN]
        .iter()
        .map(|&raw_len| Ext4Extent {
            logical_block: 0,
            raw_len,
            physical_start: 0,
        })
        .collect();
    c.bench_function("ext4_extent_actual_len_written", |b| {
        b.iter(|| {
            for ext in &extents {
                let e = black_box(*ext);
                black_box(e.actual_len());
                black_box(e.is_unwritten());
            }
        });
    });
}

fn bench_ext4_extent_actual_len_unwritten(c: &mut Criterion) {
    // Workload of unwritten extents (raw_len > EXT_INIT_MAX_LEN).
    // Representative sizes: MAX+1 (smallest unwritten, actual=1),
    // MAX+64, MAX+4096, MAX+0x7FFE, 0xFFFF (largest unwritten,
    // actual=0x7FFF).
    let extents: Vec<Ext4Extent> = [
        EXT_INIT_MAX_LEN + 1,
        EXT_INIT_MAX_LEN + 64,
        EXT_INIT_MAX_LEN + 4096,
        EXT_INIT_MAX_LEN + 0x7FFE,
        u16::MAX,
    ]
    .iter()
    .map(|&raw_len| Ext4Extent {
        logical_block: 0,
        raw_len,
        physical_start: 0,
    })
    .collect();
    c.bench_function("ext4_extent_actual_len_unwritten", |b| {
        b.iter(|| {
            for ext in &extents {
                let e = black_box(*ext);
                black_box(e.actual_len());
                black_box(e.is_unwritten());
            }
        });
    });
}

/// bd-tyzfe — verify_btrfs_superblock_checksum runs on every btrfs
/// mount path. The hot path computes CRC32C over [0x20..4096] and
/// compares against the bytes at [0..4]. A regression on this
/// function bloats every mount. Stamp a valid superblock once and
/// iterate verify in the bench loop.
fn bench_btrfs_verify_superblock_checksum(c: &mut Criterion) {
    const SUPERBLOCK_SIZE: usize = 4096;
    const CSUM_TYPE_OFFSET: usize = 0xC4;
    const COVERED_OFFSET: usize = 0x20;

    let mut sb = vec![0_u8; SUPERBLOCK_SIZE];
    sb[CSUM_TYPE_OFFSET..CSUM_TYPE_OFFSET + 2].copy_from_slice(&0_u16.to_le_bytes());
    let computed = crc32c::crc32c(&sb[COVERED_OFFSET..]);
    sb[0..4].copy_from_slice(&computed.to_le_bytes());

    c.bench_function("btrfs_verify_superblock_checksum", |b| {
        b.iter(|| {
            verify_btrfs_superblock_checksum(black_box(&sb)).expect("stamped superblock verifies");
        });
    });
}

/// bd-tyzfe — verify_btrfs_tree_block_checksum runs on every btrfs
/// tree block read (most frequent btrfs read-path call). Bench
/// against a stamped 4 KiB tree block with csum_type=0 (CRC32C),
/// matching production leaf-block size.
fn bench_btrfs_verify_tree_block_checksum(c: &mut Criterion) {
    const TREE_BLOCK_SIZE: usize = 4096;
    const COVERED_OFFSET: usize = 0x20;

    let mut tb = vec![0_u8; TREE_BLOCK_SIZE];
    let computed = crc32c::crc32c(&tb[COVERED_OFFSET..]);
    tb[0..4].copy_from_slice(&computed.to_le_bytes());

    c.bench_function("btrfs_verify_tree_block_checksum", |b| {
        b.iter(|| {
            verify_btrfs_tree_block_checksum(black_box(&tb), 0)
                .expect("stamped tree block verifies");
        });
    });
}

/// bd-coyy0 — parse_root_item runs on every subvolume enumeration
/// (read every entry of the root tree). Bench against the 239-byte
/// legacy minimum payload (uuid-era fields zeroed, generation_v2
/// disagrees → extension fields default to zero) which matches the
/// most common production root_item layout.
fn bench_btrfs_parse_root_item(c: &mut Criterion) {
    let mut payload = vec![0_u8; 239];
    // bytenr at offset 176 must be non-zero per parser invariant.
    payload[176..184].copy_from_slice(&0x1234_5678_9ABC_DEF0_u64.to_le_bytes());
    payload[238] = 0; // level=0

    c.bench_function("btrfs_parse_root_item", |b| {
        b.iter(|| {
            ffs_btrfs::parse_root_item(black_box(&payload)).expect("legacy root_item parses");
        });
    });
}

/// bd-8vrmt — parse_root_ref runs on every btrfs subvolume /
/// snapshot enumeration through ffs_core::OpenFs::enumerate_subvolumes
/// / enumerate_snapshots. Bench against an 18-byte header +
/// 19-byte name (typical "snap_2026_05_07_001" snapshot name)
/// = 37 bytes total. Pinned by bd-m9u35 (kernel-offset pin),
/// bd-ay4aw (MR proptests).
fn bench_btrfs_parse_root_ref(c: &mut Criterion) {
    let name: &[u8] = b"snap_2026_05_07_001";
    let mut payload = vec![0_u8; 18 + name.len()];
    payload[0..8].copy_from_slice(&0x1122_3344_5566_7788_u64.to_le_bytes()); // dirid
    payload[8..16].copy_from_slice(&0x1234_u64.to_le_bytes()); // sequence
    payload[16..18].copy_from_slice(
        &u16::try_from(name.len())
            .expect("name fits u16")
            .to_le_bytes(),
    );
    payload[18..18 + name.len()].copy_from_slice(name);

    c.bench_function("btrfs_parse_root_ref", |b| {
        b.iter(|| {
            ffs_btrfs::parse_root_ref(black_box(&payload)).expect("root_ref parses");
        });
    });
}

/// bd-coyy0 — parse_inode_refs runs on every inode_ref walk
/// (hardlink resolution, subvolume nav). Bench a single
/// 10-byte-header + 16-byte-name entry — the typical hardlink-target
/// shape.
fn bench_btrfs_parse_inode_refs(c: &mut Criterion) {
    let entry = BtrfsInodeRef {
        index: 0x1234_5678,
        name: b"hardlink-target1".to_vec(),
    };
    let payload = entry
        .try_to_bytes()
        .expect("typical inode_ref encodes within u16");

    c.bench_function("btrfs_parse_inode_refs", |b| {
        b.iter(|| {
            ffs_btrfs::parse_inode_refs(black_box(&payload)).expect("inode_ref parses");
        });
    });
}

/// bd-biy4b — BtrfsInodeRef::try_to_bytes encoder runs on every
/// btrfs hardlink creation through ffs_core::OpenFs and on every
/// snapshot / subvolume metadata write. Bench paired with
/// bd-coyy0 (parser side) so the perf gate tracks regressions on
/// both halves of the encode/decode bijection. Correctness pinned
/// by bd-kelr0 (parser kernel-offset pin), bd-bq6l8 (canonical
/// encoder bytes), bd-pt9pk + bd-9f8ef (round-trip + determinism
/// MR proptests). Typical hardlink-target shape: 10-byte header
/// + 16-byte name = 26 bytes.
fn bench_btrfs_inode_ref_try_to_bytes(c: &mut Criterion) {
    let entry = BtrfsInodeRef {
        index: 0x1234_5678,
        name: b"hardlink-target1".to_vec(),
    };

    c.bench_function("btrfs_inode_ref_try_to_bytes", |b| {
        b.iter(|| {
            let bytes = black_box(&entry)
                .try_to_bytes()
                .expect("typical inode_ref encodes within u16");
            black_box(bytes);
        });
    });
}

/// bd-coyy0 — parse_dir_items runs on every directory readdir.
/// Bench a single 30-byte-header + 16-byte-name entry — the typical
/// directory entry shape.
fn bench_btrfs_parse_dir_items(c: &mut Criterion) {
    let entry = BtrfsDirItem {
        child_objectid: 0x1000,
        child_key_type: 1, // INODE_ITEM
        child_key_offset: 0,
        file_type: 1, // BTRFS_FT_REG_FILE
        name: b"regular_file_xy.".to_vec(),
    };
    let payload = entry
        .try_to_bytes()
        .expect("typical dir_item encodes within u16");

    c.bench_function("btrfs_parse_dir_items", |b| {
        b.iter(|| {
            ffs_btrfs::parse_dir_items(black_box(&payload)).expect("dir_item parses");
        });
    });
}

/// bd-4ggv5 — BtrfsDirItem::try_to_bytes encoder runs on every
/// btrfs directory create, rename, mkdir, mknod, symlink, link
/// operation through ffs_core::OpenFs. Bench paired with bd-coyy0
/// (parser side) so the perf gate tracks regressions on both
/// halves of the encode/decode bijection. Correctness pinned by
/// bd-qwo4a (parser kernel-offset pin), bd-78fbx (round-trip MR),
/// bd-2gb89 (canonical encoder bytes). Typical directory-entry
/// shape: 30-byte header + 16-byte name = 46 bytes.
fn bench_btrfs_dir_item_try_to_bytes(c: &mut Criterion) {
    let entry = BtrfsDirItem {
        child_objectid: 0x1000,
        child_key_type: 1, // INODE_ITEM
        child_key_offset: 0,
        file_type: 1, // BTRFS_FT_REG_FILE
        name: b"regular_file_xy.".to_vec(),
    };

    c.bench_function("btrfs_dir_item_try_to_bytes", |b| {
        b.iter(|| {
            let bytes = black_box(&entry)
                .try_to_bytes()
                .expect("typical dir_item encodes within u16");
            black_box(bytes);
        });
    });
}

/// bd-maryc — parse_inode_item runs on every btrfs inode read
/// (open, stat, getattr, readdir-with-stat). Bench against a
/// kernel-stamped 160-byte payload matching the production hot path.
fn bench_btrfs_parse_inode_item(c: &mut Criterion) {
    let item = BtrfsInodeItem {
        generation: 0x1234,
        size: 0x10_0000, // 1 MiB
        nbytes: 0x10_0000,
        nlink: 1,
        uid: 1000,
        gid: 1000,
        mode: 0o100_644,
        rdev: 0,
        flags: 0,
        atime_sec: 1_700_000_000,
        atime_nsec: 123_456_789,
        ctime_sec: 1_700_000_001,
        ctime_nsec: 234_567_890,
        mtime_sec: 1_700_000_002,
        mtime_nsec: 345_678_901,
        otime_sec: 1_700_000_003,
        otime_nsec: 456_789_012,
    };
    let payload = item.to_bytes();

    c.bench_function("btrfs_parse_inode_item", |b| {
        b.iter(|| {
            ffs_btrfs::parse_inode_item(black_box(&payload)).expect("inode_item parses");
        });
    });
}

/// bd-maryc — BtrfsInodeItem::to_bytes runs on every btrfs inode
/// write (commit, fsync, truncate path). Bench the encoder against
/// the same hot-path inputs as the parse bench so perf comparator
/// can track both sides of the encode/decode bijection.
fn bench_btrfs_inode_item_to_bytes(c: &mut Criterion) {
    let item = BtrfsInodeItem {
        generation: 0x1234,
        size: 0x10_0000,
        nbytes: 0x10_0000,
        nlink: 1,
        uid: 1000,
        gid: 1000,
        mode: 0o100_644,
        rdev: 0,
        flags: 0,
        atime_sec: 1_700_000_000,
        atime_nsec: 123_456_789,
        ctime_sec: 1_700_000_001,
        ctime_nsec: 234_567_890,
        mtime_sec: 1_700_000_002,
        mtime_nsec: 345_678_901,
        otime_sec: 1_700_000_003,
        otime_nsec: 456_789_012,
    };

    c.bench_function("btrfs_inode_item_to_bytes", |b| {
        b.iter(|| {
            let bytes = black_box(&item).to_bytes();
            black_box(bytes);
        });
    });
}

/// bd-zuqtr — parse_extent_data runs on every btrfs file read /
/// mmap / readdir-with-stat path through ffs_core::OpenFs (12+
/// call sites). Bench against a 53-byte Regular payload with
/// BTRFS_FILE_EXTENT_REG type, BTRFS_COMPRESS_NONE compression,
/// disk_bytenr=0 sparse hole — the simplest path that exercises
/// the full 21-byte fixed header + 32-byte Regular address-field
/// arithmetic without engaging the source-slice validator.
/// Correctness is fuzzed by fuzz_btrfs_tree_items + bd-3niu3
/// proptest round-trip MR.
fn bench_btrfs_parse_extent_data_regular(c: &mut Criterion) {
    use ffs_btrfs::{BTRFS_COMPRESS_NONE, BTRFS_FILE_EXTENT_REG, BtrfsExtentData};
    let extent = BtrfsExtentData::Regular {
        generation: 0x1234,
        ram_bytes: 0x10_0000, // 1 MiB
        extent_type: BTRFS_FILE_EXTENT_REG,
        compression: BTRFS_COMPRESS_NONE,
        disk_bytenr: 0, // sparse hole — bypasses source-slice check
        disk_num_bytes: 0x10_0000,
        extent_offset: 0,
        num_bytes: 0x10_0000,
    };
    let payload = extent.to_bytes();

    c.bench_function("btrfs_parse_extent_data_regular", |b| {
        b.iter(|| {
            ffs_btrfs::parse_extent_data(black_box(&payload)).expect("extent_data parses");
        });
    });
}

/// bd-du0ax — BtrfsExtentData::to_bytes Regular encoder runs on
/// every btrfs file write commit, fsync, truncate, mark_written,
/// and snapshot operation through ffs_core::OpenFs. Bench paired
/// with bd-zuqtr (parser side) so the perf gate tracks regressions
/// on both halves of the encode/decode bijection. Correctness is
/// pinned by bd-yjzhk (canonical bytes) + bd-3niu3 (round-trip MR).
fn bench_btrfs_extent_data_regular_to_bytes(c: &mut Criterion) {
    use ffs_btrfs::{BTRFS_COMPRESS_NONE, BTRFS_FILE_EXTENT_REG, BtrfsExtentData};
    let extent = BtrfsExtentData::Regular {
        generation: 0x1234,
        ram_bytes: 0x10_0000, // 1 MiB
        extent_type: BTRFS_FILE_EXTENT_REG,
        compression: BTRFS_COMPRESS_NONE,
        disk_bytenr: 0,
        disk_num_bytes: 0x10_0000,
        extent_offset: 0,
        num_bytes: 0x10_0000,
    };

    c.bench_function("btrfs_extent_data_regular_to_bytes", |b| {
        b.iter(|| {
            let bytes = black_box(&extent).to_bytes();
            black_box(bytes);
        });
    });
}

/// bd-zixaq — BtrfsExtentData::to_bytes Inline branch is a
/// separate encoder code path from Regular with different cost
/// characteristics (variable inline-data tail vs fixed 53-byte
/// Regular tail). bd-du0ax benches the Regular branch; this
/// pairs it with the Inline branch. Typical small-file inlining
/// shape: 8-byte uncompressed inline data + 21-byte header = 29
/// bytes total. Correctness pinned by bd-fw55q (canonical bytes)
/// + bd-3niu3 (proptest round-trip MRs).
fn bench_btrfs_extent_data_inline_to_bytes(c: &mut Criterion) {
    use ffs_btrfs::{BTRFS_COMPRESS_NONE, BtrfsExtentData};
    let extent = BtrfsExtentData::Inline {
        generation: 0x1234,
        ram_bytes: 8, // NONE compression: must equal data.len()
        compression: BTRFS_COMPRESS_NONE,
        data: vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
    };

    c.bench_function("btrfs_extent_data_inline_to_bytes", |b| {
        b.iter(|| {
            let bytes = black_box(&extent).to_bytes();
            black_box(bytes);
        });
    });
}

/// bd-4o0be — parse_extent_data routes Inline through
/// parse_inline_extent_data, a separate code path from the Regular
/// branch with its own validate_inline_extent_ram_bytes invariant
/// (uncompressed inline_len must equal ram_bytes) that bd-zuqtr's
/// Regular bench cannot exercise. Pair with bd-zixaq (inline encoder)
/// so the perf gate tracks regressions on both halves of the inline-
/// extent encode/decode bijection. Typical small-file inlining shape:
/// 8-byte uncompressed inline data + 21-byte header = 29 bytes.
/// Correctness pinned by bd-fw55q (inline canonical bytes), bd-3niu3
/// (proptest round-trip MR for both variants).
fn bench_btrfs_parse_extent_data_inline(c: &mut Criterion) {
    use ffs_btrfs::{BTRFS_COMPRESS_NONE, BtrfsExtentData};
    let extent = BtrfsExtentData::Inline {
        generation: 0x1234,
        ram_bytes: 8, // NONE compression: must equal data.len()
        compression: BTRFS_COMPRESS_NONE,
        data: vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
    };
    let payload = extent.to_bytes();

    c.bench_function("btrfs_parse_extent_data_inline", |b| {
        b.iter(|| {
            ffs_btrfs::parse_extent_data(black_box(&payload)).expect("inline extent_data parses");
        });
    });
}

/// bd-m9661 — parse_xattr_items runs on every btrfs getxattr /
/// listxattr / llistxattr call through ffs_core::OpenFs. Bench
/// against a 30-byte-header + 17-byte-name + 17-byte-value
/// payload (typical "user.realname"="this-is-some-data" shape)
/// so the perf gate tracks regressions on the parser's
/// cur+=value_end recurrence and the data_len@+25 / name_len@+27
/// offset arithmetic. Correctness is fuzzed by bd-fhznm
/// proptest_xattr_items_payload_round_trip.
fn bench_btrfs_parse_xattr_items(c: &mut Criterion) {
    // Mirror the on-disk header used by parse_xattr_items:
    // location key (17) + transid (8) + data_len u16 LE @25 +
    // name_len u16 LE @27 + type (1) = 30 bytes.
    let name: &[u8] = b"user.realname____";
    let value: &[u8] = b"this-is-some-data";
    let mut payload = Vec::with_capacity(30 + name.len() + value.len());
    payload.extend_from_slice(&[0_u8; 17]);
    payload.extend_from_slice(&[0_u8; 8]);
    payload.extend_from_slice(
        &u16::try_from(value.len())
            .expect("value < u16")
            .to_le_bytes(),
    );
    payload.extend_from_slice(&u16::try_from(name.len()).expect("name < u16").to_le_bytes());
    payload.push(0); // type byte
    payload.extend_from_slice(name);
    payload.extend_from_slice(value);

    c.bench_function("btrfs_parse_xattr_items", |b| {
        b.iter(|| {
            ffs_btrfs::parse_xattr_items(black_box(&payload)).expect("xattr_items parses");
        });
    });
}

/// bd-tgkxl — ext4_chksum is the CRC32c-based checksum function
/// called by every ext4 checksum operation: verify_block_bitmap_*,
/// verify_inode_bitmap_*, verify_group_desc_*, verify_inode_*,
/// verify_dir_block_*, verify_extent_block_*, plus all stamp_*
/// counterparts. Bench against a 4 KiB region (typical inode /
/// dir / group_desc payload size) on a non-trivial seed so the
/// perf gate tracks regressions on the read AND write metadata
/// paths. Correctness is fuzzed by bd-e95p9 fuzz_ext4_chksum.
fn bench_ext4_chksum_4kb(c: &mut Criterion) {
    // 4 KiB block of pseudo-deterministic content (counter mod
    // 256) so the bench input is stable across hosts.
    let block: Vec<u8> = (0_usize..4096)
        .map(|i| u8::try_from(i & 0xFF).expect("byte fits"))
        .collect();
    let seed: u32 = 0xCAFE_BABE;

    c.bench_function("ext4_chksum_4kb", |b| {
        b.iter(|| {
            let csum = ext4_chksum(black_box(seed), black_box(&block));
            black_box(csum);
        });
    });
}

/// bd-gauub — same-binary A/B for runtime ext4 htree lookup wiring.
///
/// `old_linear_scan` preserves the previous production behavior: resolve every
/// directory block and scan entries linearly. `htree_with_linear_fallback` calls
/// the production `OpenFs::lookup_name_with_scope`, which now tries the ext4
/// DX/htree index first and falls back to that same linear scan on misses or
/// invalid indexes. Setup may generate a temporary ext4 dir_index image when
/// the ignored local golden image is unavailable on remote workers; generation
/// is outside Criterion's measured loop.
fn bench_ext4_runtime_htree_lookup_ab(c: &mut Criterion) {
    let (fs, cx, htree_inode, _image_guard) = open_runtime_htree_fixture();
    let scope = RequestScope::empty();
    let target = b"file_179.txt";

    let linear = linear_runtime_htree_lookup(&fs, &cx, &scope, &htree_inode, target)
        .expect("linear runtime htree lookup target");
    let htree = fs
        .lookup_name_with_scope(&cx, &scope, &htree_inode, target)
        .expect("runtime htree lookup")
        .expect("runtime htree lookup target");
    assert_eq!(
        htree, linear,
        "runtime htree lookup must match old linear scan for the target"
    );

    let mut group = c.benchmark_group("ext4_runtime_htree_lookup_ab");
    group.bench_function("old_linear_scan", |b| {
        b.iter(|| {
            let entry = linear_runtime_htree_lookup(
                black_box(&fs),
                black_box(&cx),
                black_box(&scope),
                black_box(&htree_inode),
                black_box(target),
            )
            .expect("linear runtime htree lookup target");
            black_box(entry);
        });
    });
    group.bench_function("htree_with_linear_fallback", |b| {
        b.iter(|| {
            let entry = fs
                .lookup_name_with_scope(
                    black_box(&cx),
                    black_box(&scope),
                    black_box(&htree_inode),
                    black_box(target),
                )
                .expect("runtime htree lookup")
                .expect("runtime htree lookup target");
            black_box(entry);
        });
    });
    group.finish();
}

criterion_group!(
    ondisk,
    bench_ext4_inode_parse,
    bench_ext4_group_desc_32,
    bench_ext4_group_desc_64,
    bench_ext4_group_desc_write_32,
    bench_ext4_group_desc_write_64,
    bench_ext4_dir_block_parse,
    bench_ext4_extent_tree_parse,
    bench_ext4_extent_tree_index_parse,
    bench_ext4_xattr_block_parse,
    bench_ext4_dx_root_parse,
    bench_btrfs_sys_chunk_parse,
    bench_btrfs_dev_item_parse,
    bench_btrfs_superblock_parse_region,
    bench_btrfs_leaf_items_parse,
    bench_btrfs_internal_items_parse,
    bench_btrfs_header_parse_from_block,
    bench_ext4_dx_hash,
    bench_ext4_casefold_key_ascii,
    bench_ext4_casefold_key_mixed_utf8,
    bench_ext4_casefold_key_long_utf8,
    bench_ext4_casefold_key_invalid_utf8,
    bench_btrfs_raid_profile_single,
    bench_btrfs_raid_profile_raid0,
    bench_btrfs_raid_profile_dup,
    bench_btrfs_raid_profile_mixed,
    bench_ext4_extra_nsec_epoch,
    bench_ext4_inode_atime_full,
    bench_ext4_inode_all_timestamps,
    bench_ext4_extent_actual_len_written,
    bench_ext4_extent_actual_len_unwritten,
    bench_btrfs_verify_superblock_checksum,
    bench_btrfs_verify_tree_block_checksum,
    bench_btrfs_parse_root_item,
    bench_btrfs_parse_root_ref,
    bench_btrfs_parse_inode_refs,
    bench_btrfs_inode_ref_try_to_bytes,
    bench_btrfs_parse_dir_items,
    bench_btrfs_dir_item_try_to_bytes,
    bench_btrfs_parse_inode_item,
    bench_btrfs_inode_item_to_bytes,
    bench_btrfs_parse_xattr_items,
    bench_btrfs_parse_extent_data_regular,
    bench_btrfs_parse_extent_data_inline,
    bench_btrfs_extent_data_regular_to_bytes,
    bench_btrfs_extent_data_inline_to_bytes,
    bench_ext4_chksum_4kb,
    bench_ext4_runtime_htree_lookup_ab,
);

fn main() {
    println!("bench_elf_sha256={}", self_identity());
    ondisk();
    Criterion::default().configure_from_args().final_summary();
}
