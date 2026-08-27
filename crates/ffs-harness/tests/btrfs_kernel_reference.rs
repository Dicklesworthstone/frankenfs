#![forbid(unsafe_code)]
//! End-to-end conformance: compare FrankenFS btrfs parsing against checked-in
//! golden JSON captured from real `mkfs.btrfs` images.
//!
//! Strategy:
//! 1. Create real btrfs images at test time with `mkfs.btrfs`.
//! 2. Populate them via `--rootdir`, `--compress`, and `--subvol` so the image
//!    exercises file trees, compressed extents, and subvolume metadata without
//!    needing a mounted loop device.
//! 3. Parse the image with FrankenFS (`OpenFs` + btrfs helpers).
//! 4. Compare the observed metadata against committed golden JSON.

use asupersync::Cx;
use ffs_btrfs::{
    BTRFS_FILE_EXTENT_PREALLOC, BTRFS_FIRST_FREE_OBJECTID, BTRFS_FS_TREE_OBJECTID,
    BTRFS_ITEM_EXTENT_DATA, BTRFS_ITEM_ROOT_ITEM, BTRFS_ITEM_ROOT_REF, BTRFS_SEND_STREAM_MAGIC,
    BtrfsExtentData, BtrfsLeafEntry, SendAttr, SendCommand, enumerate_subvolumes,
    parse_extent_data, parse_root_item, parse_root_ref, parse_send_stream,
};
use ffs_core::{FileType, InodeAttr, OpenFs, OpenOptions};
use ffs_types::InodeNumber;
use serde::{Deserialize, Serialize};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;

const SMALL_IMAGE_BYTES: u64 = 128 * 1024 * 1024;
const MEDIUM_IMAGE_BYTES: u64 = 160 * 1024 * 1024;
const LARGE_IMAGE_BYTES: u64 = 192 * 1024 * 1024;
const GOLDEN_VERSION: u32 = 1;
/// btrfs-progs version the committed goldens were captured with.
///
/// The btrfs on-disk layout these tests compare byte-for-byte (generation
/// numbers, chunk placement, compressed extents) and the mkfs flags they rely
/// on (e.g. `--compress`, only present in newer releases) vary across
/// btrfs-progs versions. The golden comparisons therefore only hold for this
/// exact version; running against any other version produces spurious
/// mismatches (or outright `mkfs.btrfs` failures on missing flags). CI runners
/// ship an older btrfs-progs, which is why these tests must self-skip there
/// rather than fail. Regenerate the goldens with `FFS_REGEN_BTRFS_GOLDENS=1`
/// on the anchor version and bump this constant when intentionally upgrading.
const GOLDEN_BTRFS_PROGS_VERSION: (u32, u32) = (6, 16);
const REGEN_ENV: &str = "FFS_REGEN_BTRFS_GOLDENS";
const CONTENT_HEX_LIMIT: usize = 4096;
const CONTENT_PREVIEW_BYTES: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Variant {
    Small,
    Medium,
    Large,
}

impl Variant {
    const fn golden_file(self) -> &'static str {
        match self {
            Self::Small => "btrfs_small.json",
            Self::Medium => "btrfs_medium.json",
            Self::Large => "btrfs_large.json",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Small => "btrfs_small",
            Self::Medium => "btrfs_medium",
            Self::Large => "btrfs_large",
        }
    }

    const fn size_bytes(self) -> u64 {
        match self {
            Self::Small => SMALL_IMAGE_BYTES,
            Self::Medium => MEDIUM_IMAGE_BYTES,
            Self::Large => LARGE_IMAGE_BYTES,
        }
    }

    const fn source(self) -> &'static str {
        match self {
            Self::Small => "mkfs.btrfs -r root",
            Self::Medium => "mkfs.btrfs -r root with nested files",
            Self::Large => {
                "mkfs.btrfs -r root --compress zlib --subvol rw:subvol-rw --subvol ro:subvol-ro"
            }
        }
    }

    const fn extra_mkfs_args(self) -> &'static [&'static str] {
        match self {
            Self::Small | Self::Medium => &[],
            Self::Large => &[
                "--compress",
                "zlib",
                "--subvol",
                "rw:subvol-rw",
                "--subvol",
                "ro:subvol-ro",
            ],
        }
    }

    const fn directories(self) -> &'static [&'static str] {
        match self {
            Self::Small => &["/"],
            Self::Medium => &["/", "/dir", "/dir/subdir"],
            Self::Large => &["/", "/data"],
        }
    }

    const fn files(self) -> &'static [&'static str] {
        match self {
            Self::Small => &["/README.txt"],
            Self::Medium => &["/README.txt", "/dir/subdir/file.txt"],
            Self::Large => &["/README.txt", "/data/repeat.bin"],
        }
    }

    fn populate_rootdir(self, root: &Path) {
        match self {
            Self::Small => {
                write_file(root, "README.txt", b"hello from btrfs small\n");
            }
            Self::Medium => {
                write_file(root, "README.txt", b"hello from btrfs medium\n");
                write_file(root, "dir/subdir/file.txt", b"nested medium file\n");
            }
            Self::Large => {
                write_file(root, "README.txt", b"hello from btrfs large\n");
                write_file(root, "data/repeat.bin", &repeated_fixture_bytes());
                write_file(root, "subvol-rw/note.txt", b"rw subvolume payload\n");
                write_file(root, "subvol-ro/note.txt", b"ro subvolume payload\n");
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BtrfsGoldenReference {
    filesystem: String,
    version: u32,
    source: String,
    image_params: BtrfsImageParams,
    sectorsize: u32,
    nodesize: u32,
    generation: u64,
    label: String,
    total_bytes: u64,
    bytes_used: u64,
    num_devices: u64,
    csum_type: u16,
    chunks: Vec<BtrfsChunkSummary>,
    root_tree: BtrfsRootTreeSummary,
    directories: Vec<BtrfsDirectorySummary>,
    files: Vec<BtrfsFileSummary>,
    subvolumes: Vec<BtrfsSubvolumeSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BtrfsImageParams {
    size_bytes: u64,
    label: String,
    variant: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BtrfsChunkSummary {
    logical_start: u64,
    length: u64,
    owner: u64,
    chunk_type_raw: u64,
    sector_size: u32,
    stripe_count: u16,
    stripes: Vec<BtrfsStripeSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BtrfsStripeSummary {
    devid: u64,
    physical_start: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BtrfsRootTreeSummary {
    system_root_objectids: Vec<u64>,
    user_subvolume_ids: Vec<u64>,
    root_ref_names: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BtrfsDirectorySummary {
    path: String,
    entries: Vec<BtrfsDirectoryEntrySummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BtrfsDirectoryEntrySummary {
    name: String,
    kind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BtrfsFileSummary {
    path: String,
    size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    content_hex: Option<String>,
    content_blake3: String,
    content_preview_hex: String,
    extents: Vec<BtrfsExtentSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BtrfsExtentSummary {
    logical_offset: u64,
    kind: BtrfsExtentKind,
    compression: u8,
    ram_bytes: u64,
    logical_bytes: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum BtrfsExtentKind {
    Inline,
    Regular,
    Prealloc,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct BtrfsSubvolumeSummary {
    id: u64,
    parent_id: u64,
    name: String,
    read_only: bool,
}

fn has_command(name: &str) -> bool {
    Command::new(name)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn btrfs_tools_available() -> bool {
    has_command("mkfs.btrfs") && has_command("btrfs")
}

/// Parse the `(major, minor)` of the installed btrfs-progs from
/// `btrfs --version` output (e.g. `btrfs-progs v6.16`). Returns `None` if the
/// command is missing or its output cannot be parsed.
fn btrfs_progs_version() -> Option<(u32, u32)> {
    let output = Command::new("btrfs").arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    // Find the `vX.Y[.Z]` token and take the leading major.minor.
    let token = text.split_whitespace().find(|word| {
        word.starts_with('v') && word[1..].starts_with(|c: char| c.is_ascii_digit())
    })?;
    let mut parts = token.trim_start_matches('v').split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((major, minor))
}

fn skip_without_btrfs_tools() -> bool {
    if !btrfs_tools_available() {
        eprintln!("btrfs tools unavailable, skipping");
        return true;
    }
    // When explicitly regenerating, run on whatever version is installed so the
    // refreshed goldens (and GOLDEN_BTRFS_PROGS_VERSION) can be updated.
    if regen_requested() {
        return false;
    }
    match btrfs_progs_version() {
        Some(version) if version == GOLDEN_BTRFS_PROGS_VERSION => false,
        Some((major, minor)) => {
            eprintln!(
                "btrfs-progs v{major}.{minor} != golden anchor v{}.{}; the byte-exact \
                 reference comparison is version-pinned, skipping. Regenerate with \
                 {REGEN_ENV}=1 on the anchor version to update.",
                GOLDEN_BTRFS_PROGS_VERSION.0, GOLDEN_BTRFS_PROGS_VERSION.1
            );
            true
        }
        None => {
            eprintln!("could not determine btrfs-progs version; skipping version-pinned goldens");
            true
        }
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn golden_path(variant: Variant) -> PathBuf {
    workspace_root()
        .join("conformance")
        .join("golden")
        .join(variant.golden_file())
}

fn regen_requested() -> bool {
    std::env::var_os(REGEN_ENV).is_some()
}

fn write_file(root: &Path, relative: &str, contents: &[u8]) {
    let path = root.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create parent directories");
    }
    fs::write(path, contents).expect("write fixture file");
}

fn repeated_fixture_bytes() -> Vec<u8> {
    let mut bytes = vec![b'A'; 65_536];
    bytes.extend(vec![b'B'; 65_536]);
    bytes
}

fn create_variant_image(variant: Variant) -> (TempDir, PathBuf) {
    let temp = TempDir::new().expect("create tempdir");
    let root = temp.path().join("root");
    fs::create_dir_all(&root).expect("create rootdir");
    variant.populate_rootdir(&root);

    let image = temp.path().join(format!("{}.img", variant.label()));
    let file = File::create(&image).expect("create image file");
    file.set_len(variant.size_bytes())
        .expect("set image length");
    drop(file);

    let mut args = vec![
        "-f".to_owned(),
        "-q".to_owned(),
        "-L".to_owned(),
        variant.label().to_owned(),
        "-n".to_owned(),
        "16k".to_owned(),
        "-s".to_owned(),
        "4k".to_owned(),
        "--nodiscard".to_owned(),
        "-r".to_owned(),
        root.display().to_string(),
    ];
    args.extend(
        variant
            .extra_mkfs_args()
            .iter()
            .map(|arg| (*arg).to_owned()),
    );
    args.push(image.display().to_string());

    let output = Command::new("mkfs.btrfs")
        .args(&args)
        .output()
        .expect("run mkfs.btrfs");
    assert!(
        output.status.success(),
        "mkfs.btrfs failed for {}:\nstdout:\n{}\nstderr:\n{}",
        variant.label(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    (temp, image)
}

fn lookup_path(fs: &OpenFs, cx: &Cx, path: &str) -> InodeAttr {
    if path == "/" {
        return fs.getattr(cx, InodeNumber(1)).expect("getattr root");
    }

    let mut attr = fs.getattr(cx, InodeNumber(1)).expect("getattr root");
    for component in path.split('/').filter(|segment| !segment.is_empty()) {
        attr = fs
            .lookup(cx, attr.ino, OsStr::new(component))
            .unwrap_or_else(|err| panic!("lookup {path} component {component}: {err}"));
    }
    attr
}

fn directory_entries(fs: &OpenFs, cx: &Cx, path: &str) -> Vec<BtrfsDirectoryEntrySummary> {
    let inode = lookup_path(fs, cx, path).ino;
    let mut entries: Vec<_> = fs
        .readdir(cx, inode, 0)
        .unwrap_or_else(|err| panic!("readdir {path}: {err}"))
        .into_iter()
        .filter_map(|entry| {
            let name = String::from_utf8_lossy(&entry.name).into_owned();
            if name == "." || name == ".." {
                None
            } else {
                Some(BtrfsDirectoryEntrySummary {
                    name,
                    kind: file_type_name(entry.kind).to_owned(),
                })
            }
        })
        .collect();
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    entries
}

fn file_type_name(kind: FileType) -> &'static str {
    match kind {
        FileType::Directory => "directory",
        FileType::RegularFile => "regular",
        FileType::Symlink => "symlink",
        FileType::BlockDevice => "block",
        FileType::CharDevice => "character",
        FileType::Fifo => "fifo",
        FileType::Socket => "socket",
    }
}

fn default_fs_tree_entries(
    fs: &OpenFs,
    cx: &Cx,
    root_entries: &[BtrfsLeafEntry],
) -> Vec<BtrfsLeafEntry> {
    let root_item = root_entries
        .iter()
        .find(|entry| {
            entry.key.objectid == BTRFS_FS_TREE_OBJECTID
                && entry.key.item_type == BTRFS_ITEM_ROOT_ITEM
        })
        .expect("FS_TREE ROOT_ITEM");
    let parsed = parse_root_item(&root_item.data).expect("parse FS_TREE root item");
    fs.walk_btrfs_tree(cx, parsed.bytenr)
        .expect("walk default fs tree")
}

fn capture_file_summary(
    fs: &OpenFs,
    cx: &Cx,
    fs_tree_entries: &[BtrfsLeafEntry],
    path: &str,
) -> BtrfsFileSummary {
    let attr = lookup_path(fs, cx, path);
    let size = u32::try_from(attr.size).expect("file size fits in u32");
    let content = fs
        .read(cx, attr.ino, 0, size)
        .unwrap_or_else(|err| panic!("read {path}: {err}"));
    let content_hex = (content.len() <= CONTENT_HEX_LIMIT).then(|| hex::encode(&content));
    let content_preview_len = content.len().min(CONTENT_PREVIEW_BYTES);

    let mut extents: Vec<_> = fs_tree_entries
        .iter()
        .filter(|entry| {
            entry.key.objectid == attr.ino.0 && entry.key.item_type == BTRFS_ITEM_EXTENT_DATA
        })
        .map(|entry| {
            let parsed = parse_extent_data(&entry.data)
                .unwrap_or_else(|err| panic!("parse extent data for {path}: {err}"));
            extent_summary(entry.key.offset, &parsed)
        })
        .collect();
    extents.sort_by_key(|extent| extent.logical_offset);

    BtrfsFileSummary {
        path: path.to_owned(),
        size: attr.size,
        content_hex,
        content_blake3: blake3::hash(&content).to_hex().to_string(),
        content_preview_hex: hex::encode(&content[..content_preview_len]),
        extents,
    }
}

fn extent_summary(logical_offset: u64, extent: &BtrfsExtentData) -> BtrfsExtentSummary {
    match extent {
        BtrfsExtentData::Inline {
            ram_bytes,
            compression,
            data,
            ..
        } => BtrfsExtentSummary {
            logical_offset,
            kind: BtrfsExtentKind::Inline,
            compression: *compression,
            ram_bytes: *ram_bytes,
            logical_bytes: u64::try_from(data.len()).expect("inline length fits u64"),
        },
        BtrfsExtentData::Regular {
            extent_type,
            compression,
            ram_bytes,
            num_bytes,
            ..
        } => BtrfsExtentSummary {
            logical_offset,
            kind: if *extent_type == BTRFS_FILE_EXTENT_PREALLOC {
                BtrfsExtentKind::Prealloc
            } else {
                BtrfsExtentKind::Regular
            },
            compression: *compression,
            ram_bytes: *ram_bytes,
            logical_bytes: *num_bytes,
        },
    }
}

fn capture_root_tree_summary(root_entries: &[BtrfsLeafEntry]) -> BtrfsRootTreeSummary {
    let mut system_root_objectids = Vec::new();
    let mut user_subvolume_ids = Vec::new();
    let mut root_ref_names = Vec::new();

    for entry in root_entries {
        if entry.key.item_type == BTRFS_ITEM_ROOT_ITEM {
            if entry.key.objectid >= BTRFS_FIRST_FREE_OBJECTID {
                user_subvolume_ids.push(entry.key.objectid);
            } else {
                system_root_objectids.push(entry.key.objectid);
            }
        } else if entry.key.item_type == BTRFS_ITEM_ROOT_REF {
            let root_ref = parse_root_ref(&entry.data).expect("parse root ref");
            root_ref_names.push(String::from_utf8_lossy(&root_ref.name).into_owned());
        }
    }

    system_root_objectids.sort_unstable();
    user_subvolume_ids.sort_unstable();
    root_ref_names.sort();

    BtrfsRootTreeSummary {
        system_root_objectids,
        user_subvolume_ids,
        root_ref_names,
    }
}

fn capture_subvolume_summaries(root_entries: &[BtrfsLeafEntry]) -> Vec<BtrfsSubvolumeSummary> {
    let mut subvolumes: Vec<_> = enumerate_subvolumes(root_entries)
        .into_iter()
        .map(|subvolume| BtrfsSubvolumeSummary {
            id: subvolume.id,
            parent_id: subvolume.parent_id,
            name: subvolume.name,
            read_only: subvolume.read_only,
        })
        .collect();
    subvolumes.sort_by_key(|subvolume| subvolume.id);
    subvolumes
}

fn capture_reference(variant: Variant, image: &Path) -> BtrfsGoldenReference {
    let cx = Cx::for_testing();
    let fs = OpenFs::open_with_options(&cx, image, &OpenOptions::default()).expect("open image");
    let superblock = fs.btrfs_superblock().expect("btrfs superblock");
    let context = fs.btrfs_context().expect("btrfs context");
    let root_entries = fs.walk_btrfs_root_tree(&cx).expect("walk root tree");
    let fs_tree_entries = default_fs_tree_entries(&fs, &cx, &root_entries);

    let mut chunks: Vec<_> = context
        .chunks
        .iter()
        .map(|chunk| BtrfsChunkSummary {
            logical_start: chunk.key.offset,
            length: chunk.length,
            owner: chunk.owner,
            chunk_type_raw: chunk.chunk_type,
            sector_size: chunk.sector_size,
            stripe_count: chunk.num_stripes,
            stripes: chunk
                .stripes
                .iter()
                .map(|stripe| BtrfsStripeSummary {
                    devid: stripe.devid,
                    physical_start: stripe.offset,
                })
                .collect(),
        })
        .collect();
    chunks.sort_by_key(|chunk| chunk.logical_start);

    let directories = variant
        .directories()
        .iter()
        .map(|path| BtrfsDirectorySummary {
            path: (*path).to_owned(),
            entries: directory_entries(&fs, &cx, path),
        })
        .collect();

    let files = variant
        .files()
        .iter()
        .map(|path| capture_file_summary(&fs, &cx, &fs_tree_entries, path))
        .collect();

    BtrfsGoldenReference {
        filesystem: "btrfs".to_owned(),
        version: GOLDEN_VERSION,
        source: variant.source().to_owned(),
        image_params: BtrfsImageParams {
            size_bytes: variant.size_bytes(),
            label: variant.label().to_owned(),
            variant: variant.label().to_owned(),
        },
        sectorsize: superblock.sectorsize,
        nodesize: superblock.nodesize,
        generation: superblock.generation,
        label: superblock.label.clone(),
        total_bytes: superblock.total_bytes,
        bytes_used: superblock.bytes_used,
        num_devices: superblock.num_devices,
        csum_type: superblock.csum_type,
        chunks,
        root_tree: capture_root_tree_summary(&root_entries),
        directories,
        files,
        subvolumes: capture_subvolume_summaries(&root_entries),
    }
}

fn capture_variant_reference(variant: Variant) -> BtrfsGoldenReference {
    let (_temp, image) = create_variant_image(variant);
    capture_reference(variant, &image)
}

fn load_or_regen_golden(variant: Variant, observed: &BtrfsGoldenReference) -> BtrfsGoldenReference {
    let path = golden_path(variant);
    let json = serde_json::to_string_pretty(observed).expect("serialize golden");
    if regen_requested() {
        fs::write(&path, json).expect("write golden json");
        return observed.clone();
    }

    let text = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read golden {}: {err}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("parse golden {}: {err}", path.display()))
}

fn load_golden(variant: Variant) -> BtrfsGoldenReference {
    let path = golden_path(variant);
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("read golden {}: {err}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|err| panic!("parse golden {}: {err}", path.display()))
}

fn find_file<'a>(golden: &'a BtrfsGoldenReference, path: &str) -> &'a BtrfsFileSummary {
    golden
        .files
        .iter()
        .find(|file| file.path == path)
        .unwrap_or_else(|| panic!("missing file {path} in golden"))
}

const BTRFS_SEND_CRC32C_POLY: u32 = 0x82F6_3B78;
const BTRFS_SEND_STREAM_TEST_UUID: [u8; 16] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
];

// btrfs-progs computes command CRC32C over the command header with the CRC
// field zeroed plus the payload bytes (`common/send-stream.c`).
fn btrfs_send_crc32c(seed: u32, data: &[u8]) -> u32 {
    let mut crc = seed;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 == 0 {
                crc >> 1
            } else {
                (crc >> 1) ^ BTRFS_SEND_CRC32C_POLY
            };
        }
    }
    crc
}

fn send_attr_bytes(attr: SendAttr, value: &[u8]) -> (SendAttr, Vec<u8>) {
    (attr, value.to_vec())
}

fn send_attr_u64(attr: SendAttr, value: u64) -> (SendAttr, Vec<u8>) {
    (attr, value.to_le_bytes().to_vec())
}

fn append_crc_valid_send_stream_command(
    stream: &mut Vec<u8>,
    cmd: SendCommand,
    attrs: &[(SendAttr, Vec<u8>)],
) {
    let mut payload = Vec::new();
    for (attr, value) in attrs {
        payload.extend_from_slice(&(*attr as u16).to_le_bytes());
        let value_len = u16::try_from(value.len()).expect("send attr length should fit in u16");
        payload.extend_from_slice(&value_len.to_le_bytes());
        payload.extend_from_slice(value);
    }

    let payload_len = u32::try_from(payload.len()).expect("send payload length should fit in u32");
    let mut command = Vec::with_capacity(10 + payload.len());
    command.extend_from_slice(&payload_len.to_le_bytes());
    command.extend_from_slice(&(cmd as u16).to_le_bytes());
    command.extend_from_slice(&0_u32.to_le_bytes());
    command.extend_from_slice(&payload);
    let crc = btrfs_send_crc32c(0, &command);
    command[6..10].copy_from_slice(&crc.to_le_bytes());
    stream.extend_from_slice(&command);
}

fn send_stream_attr(command: &ffs_btrfs::SendStreamCommand, attr: SendAttr) -> &[u8] {
    command
        .attrs
        .iter()
        .find_map(|(attr_id, value)| (*attr_id == attr as u16).then_some(value.as_slice()))
        .unwrap_or_else(|| panic!("missing send attr {attr:?}"))
}

fn send_stream_attr_u64(command: &ffs_btrfs::SendStreamCommand, attr: SendAttr) -> u64 {
    let raw = send_stream_attr(command, attr);
    let bytes: [u8; 8] = raw
        .try_into()
        .unwrap_or_else(|_| panic!("send attr {attr:?} should be 8 bytes, got {}", raw.len()));
    u64::from_le_bytes(bytes)
}

fn send_stream_attr_string(command: &ffs_btrfs::SendStreamCommand, attr: SendAttr) -> &str {
    std::str::from_utf8(send_stream_attr(command, attr))
        .unwrap_or_else(|err| panic!("send attr {attr:?} should be utf-8: {err}"))
}

fn format_btrfs_send_uuid(uuid: &[u8]) -> String {
    assert_eq!(uuid.len(), 16, "uuid should be 16 bytes");
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        uuid[0],
        uuid[1],
        uuid[2],
        uuid[3],
        uuid[4],
        uuid[5],
        uuid[6],
        uuid[7],
        uuid[8],
        uuid[9],
        uuid[10],
        uuid[11],
        uuid[12],
        uuid[13],
        uuid[14],
        uuid[15]
    )
}

fn normalize_btrfs_receive_dump(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| line.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect()
}

fn normalize_send_stream_path(subvolume: &str, relative_path: &str) -> String {
    if relative_path.is_empty() {
        format!("./{subvolume}")
    } else {
        format!("./{subvolume}/{relative_path}")
    }
}

fn normalize_send_stream_for_btrfs_dump(parsed: &ffs_btrfs::SendStreamParseResult) -> Vec<String> {
    let mut normalized = Vec::new();
    let mut current_subvolume = None::<String>;

    for command in &parsed.commands {
        match command.cmd {
            SendCommand::Subvol => {
                let path = send_stream_attr_string(command, SendAttr::Path).to_owned();
                let uuid = format_btrfs_send_uuid(send_stream_attr(command, SendAttr::Uuid));
                let ctransid = send_stream_attr_u64(command, SendAttr::Ctransid);
                normalized.push(format!("subvol ./{path} uuid={uuid} transid={ctransid}"));
                current_subvolume = Some(path);
            }
            SendCommand::Mkdir => {
                let subvolume = current_subvolume
                    .as_deref()
                    .expect("subvolume command should precede mkdir");
                let path = normalize_send_stream_path(
                    subvolume,
                    send_stream_attr_string(command, SendAttr::Path),
                );
                normalized.push(format!("mkdir {path}"));
            }
            SendCommand::Mkfile => {
                let subvolume = current_subvolume
                    .as_deref()
                    .expect("subvolume command should precede mkfile");
                let path = normalize_send_stream_path(
                    subvolume,
                    send_stream_attr_string(command, SendAttr::Path),
                );
                normalized.push(format!("mkfile {path}"));
            }
            SendCommand::Write => {
                let subvolume = current_subvolume
                    .as_deref()
                    .expect("subvolume command should precede write");
                let path = normalize_send_stream_path(
                    subvolume,
                    send_stream_attr_string(command, SendAttr::Path),
                );
                let offset = send_stream_attr_u64(command, SendAttr::FileOffset);
                let len = send_stream_attr(command, SendAttr::Data).len();
                normalized.push(format!("write {path} offset={offset} len={len}"));
            }
            SendCommand::Chmod => {
                let subvolume = current_subvolume
                    .as_deref()
                    .expect("subvolume command should precede chmod");
                let path = normalize_send_stream_path(
                    subvolume,
                    send_stream_attr_string(command, SendAttr::Path),
                );
                let mode = send_stream_attr_u64(command, SendAttr::Mode);
                normalized.push(format!("chmod {path} mode={mode:o}"));
            }
            SendCommand::Chown => {
                let subvolume = current_subvolume
                    .as_deref()
                    .expect("subvolume command should precede chown");
                let path = normalize_send_stream_path(
                    subvolume,
                    send_stream_attr_string(command, SendAttr::Path),
                );
                let gid = send_stream_attr_u64(command, SendAttr::Gid);
                let uid = send_stream_attr_u64(command, SendAttr::Uid);
                normalized.push(format!("chown {path} gid={gid} uid={uid}"));
            }
            SendCommand::Truncate => {
                let subvolume = current_subvolume
                    .as_deref()
                    .expect("subvolume command should precede truncate");
                let path = normalize_send_stream_path(
                    subvolume,
                    send_stream_attr_string(command, SendAttr::Path),
                );
                let size = send_stream_attr_u64(command, SendAttr::Size);
                normalized.push(format!("truncate {path} size={size}"));
            }
            SendCommand::Rename => {
                let subvolume = current_subvolume
                    .as_deref()
                    .expect("subvolume command should precede rename");
                let path = normalize_send_stream_path(
                    subvolume,
                    send_stream_attr_string(command, SendAttr::Path),
                );
                let dest = normalize_send_stream_path(
                    subvolume,
                    send_stream_attr_string(command, SendAttr::PathTo),
                );
                normalized.push(format!("rename {path} dest={dest}"));
            }
            SendCommand::End => break,
            other => panic!("unexpected send command in reference stream: {other:?}"),
        }
    }

    normalized
}

fn run_btrfs_receive_dump(stream: &[u8]) -> Vec<String> {
    let temp = TempDir::new().expect("tempdir for btrfs send stream");
    let stream_path = temp.path().join("reference.send");
    fs::write(&stream_path, stream).expect("write btrfs send stream fixture");

    let output = Command::new("btrfs")
        .args(["receive", "--dump", "-e", "-f"])
        .arg(&stream_path)
        .output()
        .expect("run btrfs receive --dump");
    assert!(
        output.status.success(),
        "btrfs receive --dump failed:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    normalize_btrfs_receive_dump(&String::from_utf8_lossy(&output.stdout))
}

#[test]
fn btrfs_golden_json_parses_and_is_consistent() {
    if regen_requested() {
        return;
    }

    for variant in [Variant::Small, Variant::Medium, Variant::Large] {
        let golden = load_golden(variant);
        assert_eq!(golden.filesystem, "btrfs");
        assert_eq!(golden.version, GOLDEN_VERSION);
        assert_eq!(golden.image_params.label, golden.label);
        assert_eq!(golden.image_params.variant, variant.label());
        assert_eq!(golden.image_params.size_bytes, golden.total_bytes);
        assert!(golden.sectorsize > 0);
        assert!(golden.nodesize > 0);
        assert!(golden.total_bytes >= SMALL_IMAGE_BYTES);
        assert_ne!(golden.directories, [] as [BtrfsDirectorySummary; 0]);
        assert_ne!(golden.files, [] as [BtrfsFileSummary; 0]);
        for file in &golden.files {
            if let Some(content_hex) = &file.content_hex {
                assert_eq!(
                    u64::try_from(content_hex.len() / 2).expect("hex length fits u64"),
                    file.size,
                    "golden content length should match file size for {}",
                    file.path
                );
            }
            assert_eq!(
                file.content_blake3.len(),
                64,
                "expected blake3 hex digest for {}",
                file.path
            );
            assert!(
                file.content_preview_hex.len() <= CONTENT_PREVIEW_BYTES * 2,
                "preview hex too large for {}",
                file.path
            );
            assert!(
                !file.extents.is_empty(),
                "expected extents for {}",
                file.path
            );
        }
    }
}

#[test]
fn btrfs_small_superblock_and_root_tree_match_golden() {
    if skip_without_btrfs_tools() {
        return;
    }

    let observed = capture_variant_reference(Variant::Small);
    let golden = load_or_regen_golden(Variant::Small, &observed);

    assert_eq!(observed.filesystem, golden.filesystem);
    assert_eq!(observed.sectorsize, golden.sectorsize);
    assert_eq!(observed.nodesize, golden.nodesize);
    assert_eq!(observed.generation, golden.generation);
    assert_eq!(observed.label, golden.label);
    assert_eq!(observed.total_bytes, golden.total_bytes);
    assert_eq!(observed.bytes_used, golden.bytes_used);
    assert_eq!(observed.num_devices, golden.num_devices);
    assert_eq!(observed.csum_type, golden.csum_type);
    assert_eq!(observed.root_tree, golden.root_tree);
}

#[test]
fn btrfs_small_chunk_layout_matches_golden() {
    if skip_without_btrfs_tools() {
        return;
    }

    let observed = capture_variant_reference(Variant::Small);
    let golden = load_or_regen_golden(Variant::Small, &observed);

    assert_eq!(observed.chunks, golden.chunks);
}

#[test]
fn btrfs_medium_directory_and_file_views_match_golden() {
    if skip_without_btrfs_tools() {
        return;
    }

    let observed = capture_variant_reference(Variant::Medium);
    let golden = load_or_regen_golden(Variant::Medium, &observed);

    assert_eq!(observed.directories, golden.directories);
    assert_eq!(observed.files, golden.files);
}

#[test]
fn btrfs_large_compressed_extent_and_readback_match_golden() {
    if skip_without_btrfs_tools() {
        return;
    }

    let observed = capture_variant_reference(Variant::Large);
    let golden = load_or_regen_golden(Variant::Large, &observed);
    let observed_file = find_file(&observed, "/data/repeat.bin");
    let golden_file = find_file(&golden, "/data/repeat.bin");

    assert_eq!(observed_file, golden_file);
    assert!(
        observed_file
            .extents
            .iter()
            .any(|extent| extent.kind == BtrfsExtentKind::Regular && extent.compression == 1),
        "expected at least one zlib-compressed regular extent"
    );
}

#[test]
fn btrfs_large_subvolume_catalog_matches_golden() {
    if skip_without_btrfs_tools() {
        return;
    }

    let observed = capture_variant_reference(Variant::Large);
    let golden = load_or_regen_golden(Variant::Large, &observed);

    assert_eq!(
        observed.root_tree.root_ref_names,
        golden.root_tree.root_ref_names
    );
    assert_eq!(
        observed.root_tree.user_subvolume_ids,
        golden.root_tree.user_subvolume_ids
    );

    let mut obs_subvols = observed.subvolumes;
    let mut gold_subvols = golden.subvolumes;
    obs_subvols.sort_by(|a, b| a.name.cmp(&b.name));
    gold_subvols.sort_by(|a, b| a.name.cmp(&b.name));

    for sv in &mut obs_subvols {
        sv.id = 0;
        sv.parent_id = 0;
    }
    for sv in &mut gold_subvols {
        sv.id = 0;
        sv.parent_id = 0;
    }

    assert_eq!(obs_subvols, gold_subvols);
    assert!(
        obs_subvols.iter().any(|subvolume| subvolume.read_only),
        "expected at least one read-only subvolume"
    );
}

#[test]
fn btrfs_send_stream_matches_btrfs_receive_dump_reference() {
    if !has_command("btrfs") {
        eprintln!("btrfs tool unavailable, skipping");
        return;
    }

    let mut stream = Vec::new();
    stream.extend_from_slice(BTRFS_SEND_STREAM_MAGIC);
    stream.extend_from_slice(&1_u32.to_le_bytes());
    append_crc_valid_send_stream_command(
        &mut stream,
        SendCommand::Subvol,
        &[
            send_attr_bytes(SendAttr::Path, b"snap"),
            send_attr_bytes(SendAttr::Uuid, &BTRFS_SEND_STREAM_TEST_UUID),
            send_attr_u64(SendAttr::Ctransid, 7),
        ],
    );
    append_crc_valid_send_stream_command(
        &mut stream,
        SendCommand::Mkdir,
        &[
            send_attr_bytes(SendAttr::Path, b"dir"),
            send_attr_u64(SendAttr::Ino, 257),
        ],
    );
    append_crc_valid_send_stream_command(
        &mut stream,
        SendCommand::Mkfile,
        &[
            send_attr_bytes(SendAttr::Path, b"dir/file.txt"),
            send_attr_u64(SendAttr::Ino, 258),
        ],
    );
    append_crc_valid_send_stream_command(
        &mut stream,
        SendCommand::Write,
        &[
            send_attr_bytes(SendAttr::Path, b"dir/file.txt"),
            send_attr_u64(SendAttr::FileOffset, 0),
            send_attr_bytes(SendAttr::Data, b"hello"),
        ],
    );
    append_crc_valid_send_stream_command(
        &mut stream,
        SendCommand::Chmod,
        &[
            send_attr_bytes(SendAttr::Path, b"dir/file.txt"),
            send_attr_u64(SendAttr::Mode, 0o644),
        ],
    );
    append_crc_valid_send_stream_command(
        &mut stream,
        SendCommand::Chown,
        &[
            send_attr_bytes(SendAttr::Path, b"dir/file.txt"),
            send_attr_u64(SendAttr::Uid, 1000),
            send_attr_u64(SendAttr::Gid, 1001),
        ],
    );
    append_crc_valid_send_stream_command(
        &mut stream,
        SendCommand::Truncate,
        &[
            send_attr_bytes(SendAttr::Path, b"dir/file.txt"),
            send_attr_u64(SendAttr::Size, 2),
        ],
    );
    append_crc_valid_send_stream_command(
        &mut stream,
        SendCommand::Rename,
        &[
            send_attr_bytes(SendAttr::Path, b"dir/file.txt"),
            send_attr_bytes(SendAttr::PathTo, b"dir/file2.txt"),
        ],
    );
    append_crc_valid_send_stream_command(&mut stream, SendCommand::End, &[]);

    let reference = run_btrfs_receive_dump(&stream);
    let parsed = parse_send_stream(&stream).expect("parse CRC-valid btrfs send stream");
    let observed = normalize_send_stream_for_btrfs_dump(&parsed);

    assert_eq!(observed, reference);
}
