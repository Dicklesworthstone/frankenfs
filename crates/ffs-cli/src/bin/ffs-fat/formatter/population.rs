//! Bounded source-tree population for the existing fresh-image formatter.
//!
//! Sources must remain immutable, including their parent paths, throughout
//! creation. Retained regular-file handles, metadata checks and three SHA-256
//! passes detect replacement or content changes; they are not a host snapshot.
//! No source entry is opened for writing and no destination is opened here.

use super::super::reader::{Directory, FatVolume, checkpoint};
use super::{FormatKind, ImageTarget, Layout, SECTOR_BYTES, Sector, dword, word};
use anyhow::{Context, Result, anyhow, bail};
use asupersync::Cx;
use ffs_error::FfsError;
use ffs_ondisk::fat::short_name_checksum;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MAX_NODES: usize = 4096;
const MAX_FILES: usize = 1024;
const MAX_DEPTH: usize = 64;
const MAX_DIRECTORY_SLOTS: usize = 65_536;
const COPY_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl Stamp {
    fn from(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            length: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

struct SourceFile {
    handle: File,
    digest: [u8; 32],
}

#[derive(Clone)]
struct NativeName {
    short: [u8; 11],
    case_flags: u8,
    long: Option<Vec<u16>>,
}

impl NativeName {
    fn slots(&self) -> usize {
        1 + self
            .long
            .as_ref()
            .map_or(0, |units| units.len().div_ceil(13))
    }

    fn append(&self, output: &mut Vec<u8>, directory: bool, cluster: u32, size: u32) {
        if let Some(units) = &self.long {
            let count = units.len().div_ceil(13);
            let checksum = short_name_checksum(&self.short);
            for ordinal in (1..=count).rev() {
                let mut slot = [0_u8; 32];
                slot[0] = ordinal as u8 | if ordinal == count { 0x40 } else { 0 };
                slot[11] = 0x0F;
                slot[13] = checksum;
                for (index, at) in [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30]
                    .into_iter()
                    .enumerate()
                {
                    let position = (ordinal - 1) * 13 + index;
                    let unit = units
                        .get(position)
                        .copied()
                        .unwrap_or(if position == units.len() { 0 } else { 0xFFFF });
                    word(&mut slot, at, unit);
                }
                output.extend_from_slice(&slot);
            }
        }
        output.extend_from_slice(&short_entry(
            &self.short,
            self.case_flags,
            directory,
            cluster,
            size,
        ));
    }
}

struct Node {
    path: PathBuf,
    name: String,
    parent: usize,
    depth: usize,
    stamp: Stamp,
    file: Option<SourceFile>,
    children: Vec<usize>,
    native: Option<NativeName>,
    first_cluster: u32,
    clusters: u32,
    directory_bytes: Vec<u8>,
}

impl Node {
    fn directory(&self) -> bool {
        self.file.is_none()
    }

    fn offset(&self, layout: Layout) -> u64 {
        if self.first_cluster == 0 {
            layout.root_sector() * SECTOR_BYTES
        } else {
            (u64::from(layout.first_data_sector)
                + u64::from(self.first_cluster - 2) * u64::from(layout.sectors_per_cluster))
                * SECTOR_BYTES
        }
    }
}

pub(super) struct Population {
    nodes: Vec<Node>,
    chain_ends: Vec<u32>,
    allocated: u32,
    files: u64,
    directories: u64,
    bytes: u64,
}

impl Population {
    pub(super) fn prepare(
        cx: &Cx,
        source: &Path,
        destination: &Path,
        layout: Layout,
        label: Option<&[u8; 11]>,
    ) -> Result<Self> {
        checkpoint(cx)?;
        let original = fs::symlink_metadata(source)
            .with_context(|| format!("reading source directory {}", source.display()))?;
        if !original.is_dir() || original.file_type().is_symlink() {
            bail!("--source-dir must be a directory, not a symlink or special file");
        }
        let source = source
            .canonicalize()
            .context("canonicalizing source directory")?;
        let root_metadata = fs::symlink_metadata(&source)?;
        if !root_metadata.is_dir() || Stamp::from(&original) != Stamp::from(&root_metadata) {
            bail!("source directory changed during preflight");
        }
        let parent = destination
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .canonicalize()
            .context("canonicalizing new-image parent before source preflight")?;
        if parent.starts_with(&source) {
            bail!("the new image must be outside --source-dir");
        }
        let mut population = Self {
            nodes: vec![Node {
                path: source,
                name: String::new(),
                parent: 0,
                depth: 0,
                stamp: Stamp::from(&root_metadata),
                file: None,
                children: Vec::new(),
                native: None,
                first_cluster: 0,
                clusters: 0,
                directory_bytes: Vec::new(),
            }],
            chain_ends: Vec::new(),
            allocated: 0,
            files: 0,
            directories: 1,
            bytes: 0,
        };
        let mut index = 0;
        while index < population.nodes.len() {
            checkpoint(cx)?;
            if population.nodes[index].directory() {
                population.scan_directory(cx, index)?;
            }
            index += 1;
        }
        population.plan_allocation(cx, layout, label)?;
        population.revalidate(cx)?;
        for node in &mut population.nodes {
            checkpoint(cx)?;
            if let Some(file) = &mut node.file {
                file.digest = hash_source(cx, &file.handle, node.stamp.length)
                    .with_context(|| format!("hashing source {}", node.path.display()))?;
                if Stamp::from(&file.handle.metadata()?) != node.stamp {
                    bail!("source file changed while hashing: {}", node.path.display());
                }
            }
        }
        population.revalidate(cx)?;
        Ok(population)
    }

    fn scan_directory(&mut self, cx: &Cx, parent: usize) -> Result<()> {
        let path = self.nodes[parent].path.clone();
        let depth = self.nodes[parent].depth + 1;
        let mut children = Vec::new();
        for entry in fs::read_dir(&path)
            .with_context(|| format!("listing source directory {}", path.display()))?
        {
            checkpoint(cx)?;
            if self.nodes.len() + children.len() >= MAX_NODES {
                bail!("source tree exceeds the {MAX_NODES}-node population budget");
            }
            if depth > MAX_DEPTH {
                bail!("source tree exceeds the {MAX_DEPTH}-level population budget");
            }
            let entry = entry?;
            let name = entry.file_name().into_string().map_err(|_| {
                anyhow!(
                    "source names must be lossless UTF-8: {}",
                    entry.path().display()
                )
            })?;
            validate_name(&name).with_context(|| format!("source name in {}", path.display()))?;
            children.push((name, entry.path()));
        }
        children.sort_by(|left, right| left.0.cmp(&right.0));
        let names: Vec<_> = children.iter().map(|(name, _)| name.as_str()).collect();
        let native = plan_names(&names)?;
        for ((name, child_path), native) in children.into_iter().zip(native) {
            checkpoint(cx)?;
            let metadata = fs::symlink_metadata(&child_path)?;
            let stamp = Stamp::from(&metadata);
            let file = if metadata.file_type().is_symlink() {
                bail!("source symlink is unsupported: {}", child_path.display());
            } else if metadata.is_file() {
                if self.files >= MAX_FILES as u64 {
                    bail!("source tree exceeds the {MAX_FILES}-open-file population budget");
                }
                if metadata.len() > u64::from(u32::MAX) {
                    return Err(io::Error::new(
                        io::ErrorKind::FileTooLarge,
                        format!(
                            "source exceeds FAT's 4294967295-byte file limit: {}",
                            child_path.display()
                        ),
                    )
                    .into());
                }
                // NOFOLLOW rejects a raced final symlink; NONBLOCK prevents a
                // raced FIFO from blocking before fstat rejects its file type.
                let handle = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(&child_path)?;
                let opened = handle.metadata()?;
                if !opened.is_file() || Stamp::from(&opened) != stamp {
                    bail!(
                        "source file changed while opening: {}",
                        child_path.display()
                    );
                }
                handle.try_lock_shared().map_err(|error| {
                    anyhow!("cannot share-lock source {}: {error}", child_path.display())
                })?;
                self.files += 1;
                self.bytes = self
                    .bytes
                    .checked_add(metadata.len())
                    .ok_or_else(|| anyhow!("source payload byte count overflow"))?;
                Some(SourceFile {
                    handle,
                    digest: [0; 32],
                })
            } else if metadata.is_dir() {
                self.directories += 1;
                None
            } else {
                bail!(
                    "source special file is unsupported: {}",
                    child_path.display()
                );
            };
            let index = self.nodes.len();
            self.nodes.push(Node {
                path: child_path,
                name,
                parent,
                depth,
                stamp,
                file,
                children: Vec::new(),
                native: Some(native),
                first_cluster: 0,
                clusters: 0,
                directory_bytes: Vec::new(),
            });
            self.nodes[parent].children.push(index);
        }
        self.check_node(parent)?;
        Ok(())
    }

    fn plan_allocation(&mut self, cx: &Cx, layout: Layout, label: Option<&[u8; 11]>) -> Result<()> {
        let cluster_bytes = u64::from(layout.sectors_per_cluster) * SECTOR_BYTES;
        let mut slots = vec![0_usize; self.nodes.len()];
        for (index, node) in self.nodes.iter().enumerate() {
            checkpoint(cx)?;
            if node.directory() {
                let initial = if index == 0 {
                    usize::from(label.is_some())
                } else {
                    2
                };
                let count = node.children.iter().try_fold(initial, |count, child| {
                    count
                        .checked_add(
                            self.nodes[*child]
                                .native
                                .as_ref()
                                .map_or(0, NativeName::slots),
                        )
                        .ok_or_else(|| anyhow!("native directory slot count overflow"))
                })?;
                let limit = if index == 0 && layout.kind == FormatKind::Fat16 {
                    512
                } else {
                    MAX_DIRECTORY_SLOTS
                };
                if count > limit {
                    return Err(FfsError::NoSpace).with_context(|| {
                        format!(
                            "source directory {} requires {count} native slots; limit is {limit}",
                            node.path.display()
                        )
                    });
                }
                slots[index] = count;
            }
        }
        for (index, node) in self.nodes.iter_mut().enumerate() {
            checkpoint(cx)?;
            let needed = if node.directory() {
                if index == 0 && layout.kind == FormatKind::Fat16 {
                    0
                } else {
                    (slots[index] as u64 * 32).div_ceil(cluster_bytes).max(1)
                }
            } else {
                node.stamp.length.div_ceil(cluster_bytes)
            };
            if needed > u64::from(layout.data_clusters - self.allocated) {
                return Err(FfsError::NoSpace)
                    .context("source tree does not fit the image's native data clusters");
            }
            node.clusters = needed as u32;
            if node.clusters != 0 {
                node.first_cluster = self.allocated + 2;
                self.allocated += node.clusters;
                self.chain_ends.push(self.allocated + 1);
            }
        }
        for index in 0..self.nodes.len() {
            checkpoint(cx)?;
            if !self.nodes[index].directory() {
                continue;
            }
            let mut bytes = Vec::with_capacity((slots[index] * 32).div_ceil(512).max(1) * 512);
            if index == 0 {
                if let Some(label) = label {
                    let mut entry = short_entry(label, 0, false, 0, 0);
                    entry[11] = 0x08;
                    bytes.extend_from_slice(&entry);
                }
            } else {
                bytes.extend_from_slice(&short_entry(
                    b".          ",
                    0,
                    true,
                    self.nodes[index].first_cluster,
                    0,
                ));
                let parent = self.nodes[index].parent;
                let parent_cluster = if parent == 0 {
                    0
                } else {
                    self.nodes[parent].first_cluster
                };
                bytes.extend_from_slice(&short_entry(b"..         ", 0, true, parent_cluster, 0));
            }
            for child in &self.nodes[index].children {
                let node = &self.nodes[*child];
                let native = node
                    .native
                    .as_ref()
                    .ok_or_else(|| anyhow!("missing planned native name"))?;
                let size = if node.directory() {
                    0
                } else {
                    node.stamp.length as u32
                };
                native.append(&mut bytes, node.directory(), node.first_cluster, size);
            }
            if bytes.len() != slots[index] * 32 {
                bail!("planned directory slot count does not match encoded entries");
            }
            bytes.resize(bytes.len().div_ceil(512).max(1) * 512, 0);
            self.nodes[index].directory_bytes = bytes;
        }
        Ok(())
    }

    fn check_node(&self, index: usize) -> Result<()> {
        let node = &self.nodes[index];
        let metadata = fs::symlink_metadata(&node.path)
            .with_context(|| format!("rechecking source {}", node.path.display()))?;
        if Stamp::from(&metadata) != node.stamp
            || metadata.file_type().is_symlink()
            || metadata.is_dir() != node.directory()
            || metadata.is_file() == node.directory()
        {
            bail!(
                "source changed during image creation: {}",
                node.path.display()
            );
        }
        if let Some(file) = &node.file
            && Stamp::from(&file.handle.metadata()?) != node.stamp
        {
            bail!(
                "opened source changed during image creation: {}",
                node.path.display()
            );
        }
        Ok(())
    }

    pub(super) fn revalidate(&self, cx: &Cx) -> Result<()> {
        for (index, node) in self.nodes.iter().enumerate() {
            checkpoint(cx)?;
            self.check_node(index)?;
            if node.directory() {
                let mut names = BTreeSet::new();
                for entry in fs::read_dir(&node.path)? {
                    checkpoint(cx)?;
                    if names.len() >= MAX_NODES {
                        bail!("source directory grew beyond the population budget");
                    }
                    let name = entry?
                        .file_name()
                        .into_string()
                        .map_err(|_| anyhow!("source acquired a non-UTF-8 name"))?;
                    if !names.insert(name) {
                        bail!("source directory returned duplicate names");
                    }
                }
                let expected: BTreeSet<_> = node
                    .children
                    .iter()
                    .map(|child| self.nodes[*child].name.clone())
                    .collect();
                if names != expected {
                    bail!(
                        "source directory changed during image creation: {}",
                        node.path.display()
                    );
                }
                self.check_node(index)?;
            }
        }
        checkpoint(cx)?;
        Ok(())
    }

    pub(super) fn allocated(&self) -> u64 {
        u64::from(self.allocated)
    }
    pub(super) fn files(&self) -> u64 {
        self.files
    }
    pub(super) fn directories(&self) -> u64 {
        self.directories
    }
    pub(super) fn bytes(&self) -> u64 {
        self.bytes
    }
    pub(super) fn source(&self) -> &Path {
        &self.nodes[0].path
    }

    fn fat_sector(&self, layout: Layout, page: u32) -> [u8; 512] {
        let width = layout.kind.native().entry_bytes() as usize;
        let per_sector = 512 / width;
        let eoc = if layout.kind == FormatKind::Fat16 {
            0xFFFF_u32
        } else {
            0x0FFF_FFFF
        };
        let mut bytes = [0_u8; 512];
        for slot in 0..per_sector {
            let cluster = page * per_sector as u32 + slot as u32;
            let value = match cluster {
                0 => eoc & !7,
                1 => eoc,
                value if value > self.allocated + 1 => 0,
                value if self.chain_ends.binary_search(&value).is_ok() => eoc,
                value => value + 1,
            };
            bytes[slot * width..(slot + 1) * width].copy_from_slice(&value.to_le_bytes()[..width]);
        }
        bytes
    }

    pub(super) fn update_headers(&self, layout: Layout, headers: &mut [Sector]) -> Result<()> {
        let fat0 = layout.kind.reserved_sectors() * SECTOR_BYTES;
        let fat1 = fat0 + u64::from(layout.fat_sectors) * SECTOR_BYTES;
        let root = layout.root_sector() * SECTOR_BYTES;
        for sector in headers {
            if sector.offset == fat0 || sector.offset == fat1 {
                sector.bytes = self.fat_sector(layout, 0);
            } else if sector.offset == root {
                sector
                    .bytes
                    .copy_from_slice(&self.nodes[0].directory_bytes[..512]);
            } else if layout.kind == FormatKind::Fat32 && matches!(sector.offset, 512 | 3584) {
                let free = layout.data_clusters - self.allocated;
                dword(&mut sector.bytes, 488, free);
                dword(
                    &mut sector.bytes,
                    492,
                    if free == 0 {
                        u32::MAX
                    } else {
                        self.allocated + 2
                    },
                );
            }
            if sector.offset + SECTOR_BYTES > layout.image_bytes() {
                bail!("populated metadata header exceeds the new image");
            }
        }
        Ok(())
    }

    pub(super) fn extra_sectors(&self, layout: Layout) -> impl Iterator<Item = Sector> + '_ {
        let pages = ((self.allocated + 2) * layout.kind.native().entry_bytes()).div_ceil(512);
        let fats = (1..pages).flat_map(move |page| {
            let bytes = self.fat_sector(layout, page);
            let first = layout.kind.reserved_sectors() + u64::from(page);
            [
                Sector {
                    offset: first * SECTOR_BYTES,
                    bytes,
                },
                Sector {
                    offset: (first + u64::from(layout.fat_sectors)) * SECTOR_BYTES,
                    bytes,
                },
            ]
        });
        let directories = self
            .nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| node.directory())
            .flat_map(move |(index, node)| {
                node.directory_bytes
                    .as_chunks::<512>()
                    .0
                    .iter()
                    .enumerate()
                    .filter(move |(page, _)| index != 0 || *page != 0)
                    .map(move |(page, source)| {
                        let mut bytes = [0_u8; 512];
                        bytes.copy_from_slice(source);
                        Sector {
                            offset: node.offset(layout) + page as u64 * SECTOR_BYTES,
                            bytes,
                        }
                    })
            });
        fats.chain(directories)
    }

    pub(super) fn write_payloads(
        &self,
        cx: &Cx,
        target: &impl ImageTarget,
        layout: Layout,
    ) -> Result<()> {
        let mut buffer = vec![0_u8; COPY_BYTES];
        for (index, node) in self.nodes.iter().enumerate() {
            checkpoint(cx)?;
            let Some(file) = &node.file else { continue };
            self.check_node(index)?;
            let mut digest = Sha256::new();
            let mut position = 0_u64;
            while position < node.stamp.length {
                checkpoint(cx)?;
                buffer.fill(0);
                let count = (node.stamp.length - position).min(COPY_BYTES as u64) as usize;
                file.handle
                    .read_exact_at(&mut buffer[..count], position)
                    .with_context(|| format!("reading source payload {}", node.path.display()))?;
                checkpoint(cx)?;
                digest.update(&buffer[..count]);
                let written = count.div_ceil(512) * 512;
                let offset = node.offset(layout) + position;
                let end = offset
                    .checked_add(written as u64)
                    .ok_or_else(|| anyhow!("source payload write offset overflow"))?;
                let chain_end = node.offset(layout)
                    + u64::from(node.clusters)
                        * u64::from(layout.sectors_per_cluster)
                        * SECTOR_BYTES;
                if end > chain_end || end > layout.image_bytes() {
                    bail!("source payload write exceeds its planned native allocation");
                }
                target.write_data(offset, &buffer[..written])?;
                checkpoint(cx)?;
                position += count as u64;
            }
            let copied: [u8; 32] = digest.finalize().into();
            if copied != file.digest {
                bail!(
                    "source payload changed since preflight: {}",
                    node.path.display()
                );
            }
            self.check_node(index)?;
        }
        checkpoint(cx)?;
        Ok(())
    }

    pub(super) fn verify(&self, cx: &Cx, volume: &FatVolume) -> Result<()> {
        for (index, node) in self.nodes.iter().enumerate() {
            checkpoint(cx)?;
            if !node.directory() {
                continue;
            }
            let directory = if index == 0 {
                Directory::Root
            } else {
                Directory::Cluster(node.first_cluster)
            };
            let entries = volume.list(cx, directory)?;
            if entries.len() != node.children.len() {
                bail!(
                    "native populated-directory entry count mismatch for {}",
                    node.path.display()
                );
            }
            let mut actual = BTreeMap::new();
            for entry in entries {
                if actual.insert(entry.native.short_name, entry).is_some() {
                    bail!("native populated-directory contains a duplicate short alias");
                }
            }
            for child in &node.children {
                checkpoint(cx)?;
                let expected = &self.nodes[*child];
                let native = expected
                    .native
                    .as_ref()
                    .ok_or_else(|| anyhow!("missing planned native name"))?;
                let entry = actual.remove(&native.short).ok_or_else(|| {
                    anyhow!("native populated-directory is missing {}", expected.name)
                })?;
                let expected_size = if expected.directory() {
                    0
                } else {
                    expected.stamp.length as u32
                };
                if entry.name()? != expected.name
                    || entry.native.long_name != native.long
                    || entry.native.case_flags != native.case_flags
                    || entry.native.attributes != if expected.directory() { 0x10 } else { 0x20 }
                    || entry.native.first_cluster != expected.first_cluster
                    || entry.native.size != expected_size
                {
                    bail!(
                        "native populated-directory identity mismatch for {}",
                        expected.path.display()
                    );
                }
                if let Some(source) = &expected.file {
                    let chain = volume.file_chain(cx, &entry)?;
                    if chain.clusters.len() as u64 != u64::from(expected.clusters)
                        || chain.clusters.first().copied().unwrap_or(0) != expected.first_cluster
                    {
                        bail!(
                            "native payload allocation mismatch for {}",
                            expected.path.display()
                        );
                    }
                    let mut digest = Sha256::new();
                    let mut position = 0_u64;
                    while position < expected.stamp.length {
                        checkpoint(cx)?;
                        let count =
                            (expected.stamp.length - position).min(COPY_BYTES as u64) as usize;
                        let bytes = volume.read(cx, &chain, position, count)?;
                        if bytes.len() != count {
                            bail!("native reader returned a short populated payload");
                        }
                        digest.update(&bytes);
                        position += count as u64;
                    }
                    let actual: [u8; 32] = digest.finalize().into();
                    if actual != source.digest {
                        bail!(
                            "native payload SHA-256 mismatch for {}",
                            expected.path.display()
                        );
                    }
                }
            }
        }
        checkpoint(cx)?;
        Ok(())
    }
}

fn hash_source(cx: &Cx, file: &File, length: u64) -> Result<[u8; 32]> {
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BYTES];
    let mut position = 0_u64;
    while position < length {
        checkpoint(cx)?;
        let count = (length - position).min(COPY_BYTES as u64) as usize;
        file.read_exact_at(&mut buffer[..count], position)?;
        checkpoint(cx)?;
        digest.update(&buffer[..count]);
        position += count as u64;
    }
    checkpoint(cx)?;
    Ok(digest.finalize().into())
}

fn short_entry(name: &[u8; 11], flags: u8, directory: bool, cluster: u32, size: u32) -> [u8; 32] {
    let mut entry = [0_u8; 32];
    entry[..11].copy_from_slice(name);
    entry[11] = if directory { 0x10 } else { 0x20 };
    entry[12] = flags;
    word(&mut entry, 16, 0x0021);
    word(&mut entry, 18, 0x0021);
    word(&mut entry, 20, (cluster >> 16) as u16);
    word(&mut entry, 24, 0x0021);
    word(&mut entry, 26, cluster as u16);
    dword(&mut entry, 28, size);
    entry
}

fn collision_key(value: &str) -> String {
    // A deliberately conservative creation profile, not a claim to reproduce
    // an OEM code page or Windows' versioned filesystem upcase tables.
    value.to_uppercase().to_lowercase()
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty() || name.len() > 255 || name.encode_utf16().count() > 255 {
        return Err(FfsError::NameTooLong)
            .context("source name must fit 255 UTF-8 bytes and 255 UTF-16 units");
    }
    if name == "."
        || name == ".."
        || name.ends_with([' ', '.'])
        || name.chars().any(|ch| {
            ch.is_control()
                || matches!(
                    ch,
                    '"' | '*' | '/' | ':' | '<' | '>' | '?' | '\\' | '|' | '\u{FFFF}'
                )
        })
    {
        bail!("source name is outside the portable FAT creation profile: {name:?}");
    }
    let base = name.split('.').next().unwrap_or("").to_uppercase();
    let numbered = base
        .strip_prefix("COM")
        .or_else(|| base.strip_prefix("LPT"));
    if matches!(
        base.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) || numbered.is_some_and(|suffix| {
        matches!(
            suffix,
            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
        )
    }) {
        bail!("reserved DOS device name is unsupported: {name:?}");
    }
    Ok(())
}

fn short_byte(byte: u8) -> bool {
    byte.is_ascii_uppercase()
        || byte.is_ascii_digit()
        || matches!(
            byte,
            b'$' | b'%'
                | b'\''
                | b'-'
                | b'_'
                | b'@'
                | b'~'
                | b'\x60'
                | b'!'
                | b'('
                | b')'
                | b'{'
                | b'}'
                | b'^'
                | b'#'
                | b'&'
        )
}

fn short_display(short: &[u8; 11], flags: u8) -> String {
    let base_end = short[..8]
        .iter()
        .rposition(|byte| *byte != b' ')
        .map_or(0, |at| at + 1);
    let ext_end = short[8..]
        .iter()
        .rposition(|byte| *byte != b' ')
        .map_or(0, |at| at + 1);
    let mut text = String::new();
    for byte in &short[..base_end] {
        text.push(char::from(if flags & 8 != 0 {
            byte.to_ascii_lowercase()
        } else {
            *byte
        }));
    }
    if ext_end != 0 {
        text.push('.');
        for byte in &short[8..8 + ext_end] {
            text.push(char::from(if flags & 16 != 0 {
                byte.to_ascii_lowercase()
            } else {
                *byte
            }));
        }
    }
    text
}

fn natural_short(name: &str) -> Option<NativeName> {
    let (base, extension) = name.rsplit_once('.').unwrap_or((name, ""));
    if base.is_empty()
        || base.len() > 8
        || extension.len() > 3
        || !base
            .bytes()
            .chain(extension.bytes())
            .all(|byte| short_byte(byte.to_ascii_uppercase()))
    {
        return None;
    }
    let mut short = [b' '; 11];
    for (target, byte) in short[..8].iter_mut().zip(base.bytes()) {
        *target = byte.to_ascii_uppercase();
    }
    for (target, byte) in short[8..].iter_mut().zip(extension.bytes()) {
        *target = byte.to_ascii_uppercase();
    }
    let mut flags = 0;
    for (part, flag) in [(base, 8), (extension, 16)] {
        if part.bytes().any(|byte| byte.is_ascii_lowercase())
            && !part.bytes().any(|byte| byte.is_ascii_uppercase())
        {
            flags |= flag;
        }
    }
    let long = (short_display(&short, flags) != name).then(|| name.encode_utf16().collect());
    Some(NativeName {
        short,
        case_flags: flags,
        long,
    })
}

fn plan_names(names: &[&str]) -> Result<Vec<NativeName>> {
    let mut visible = BTreeSet::new();
    for name in names {
        validate_name(name)?;
        if !visible.insert(collision_key(name)) {
            bail!("source sibling names collide under the FAT creation case profile: {name:?}");
        }
    }
    let mut planned: Vec<_> = names.iter().map(|name| natural_short(name)).collect();
    let mut used = BTreeSet::new();
    for native in planned.iter().flatten() {
        if !used.insert(native.short) {
            bail!("source sibling names require the same native short alias");
        }
    }
    for (index, name) in names.iter().enumerate() {
        if planned[index].is_some() {
            continue;
        }
        let (base, extension) = name.rsplit_once('.').unwrap_or((name, ""));
        let clean = |value: &str| -> Vec<u8> {
            value
                .chars()
                .filter(|ch| !matches!(ch, ' ' | '.'))
                .map(|ch| {
                    if ch.is_ascii() && short_byte((ch as u8).to_ascii_uppercase()) {
                        (ch as u8).to_ascii_uppercase()
                    } else {
                        b'_'
                    }
                })
                .collect()
        };
        let mut base = clean(base);
        if base.is_empty() {
            base.extend_from_slice(b"FILE");
        }
        let extension = clean(extension);
        // At most two reservations per source node (native and visible name)
        // can block a candidate; this finite search exceeds that whole set.
        for serial in 1..=2 * MAX_NODES + 1 {
            let suffix = format!("~{serial}");
            let prefix = base.len().min(8 - suffix.len());
            let mut short = [b' '; 11];
            short[..prefix].copy_from_slice(&base[..prefix]);
            short[prefix..prefix + suffix.len()].copy_from_slice(suffix.as_bytes());
            let extension_length = extension.len().min(3);
            short[8..8 + extension_length].copy_from_slice(&extension[..extension_length]);
            if used.contains(&short) || visible.contains(&collision_key(&short_display(&short, 0)))
            {
                continue;
            }
            used.insert(short);
            planned[index] = Some(NativeName {
                short,
                case_flags: 0,
                long: Some(name.encode_utf16().collect()),
            });
            break;
        }
        if planned[index].is_none() {
            bail!("source directory exhausts the bounded native short-alias search");
        }
    }
    planned
        .into_iter()
        .map(|name| name.ok_or_else(|| anyhow!("missing native short-alias plan")))
        .collect()
}
