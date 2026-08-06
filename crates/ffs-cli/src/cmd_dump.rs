//! CLI `dump` subcommand execution and formatting.
//!
//! Command definitions and serialized output types remain in the crate root so their paths stay
//! stable while the dump implementation lives behind this private module boundary.

use anyhow::{Context, Result, bail};
use ffs_btrfs::{
    BTRFS_FS_TREE_OBJECTID, BTRFS_ITEM_INODE_ITEM, BTRFS_ITEM_ROOT_ITEM, parse_inode_item,
    parse_root_item,
};
use ffs_core::{FsFlavor, OpenFs, OpenOptions, detect_filesystem_at_path};
use ffs_ondisk::{
    Ext4DirEntry, Ext4Extent, Ext4ImageReader, Ext4Inode, ExtentTree, parse_dx_root,
    parse_extent_tree, parse_inode_extent_tree,
};
use ffs_types::{
    BTRFS_SUPER_INFO_OFFSET, BTRFS_SUPER_INFO_SIZE, BlockNumber, EXT4_SUPERBLOCK_OFFSET,
    EXT4_SUPERBLOCK_SIZE, InodeNumber,
};
use std::fmt::Write;
use std::path::PathBuf;
use std::time::Instant;
use tracing::{info, info_span};

use crate::{
    DumpCommand, DumpDirEntryOutput, DumpDirOutput, DumpDxEntryOutput, DumpDxRootOutput,
    DumpExtentEntryOutput, DumpExtentNodeKindOutput, DumpExtentNodeOutput, DumpExtentOutput,
    DumpGroupOutput, DumpHexBlockOutput, DumpInodeOutput, DumpSuperblockOutput,
    build_btrfs_group_info, cli_cx, encode_btrfs_chunk_entry_bytes, filesystem_name,
    print_superblock_info, read_ext4_group_desc_from_path, read_ext4_inode_from_path,
    read_file_region, superblock_info_for,
};

pub(super) fn dump_cmd(command: &DumpCommand) -> Result<()> {
    match command {
        DumpCommand::Superblock { image, json, hex } => dump_superblock_cmd(image, *json, *hex),
        DumpCommand::Group {
            group,
            image,
            json,
            hex,
        } => dump_group_cmd(*group, image, *json, *hex),
        DumpCommand::Inode {
            inode,
            image,
            json,
            hex,
        } => dump_inode_cmd(*inode, image, *json, *hex),
        DumpCommand::Extents {
            inode,
            image,
            json,
            hex,
        } => dump_extents_cmd(*inode, image, *json, *hex),
        DumpCommand::Dir {
            inode,
            image,
            json,
            hex,
        } => dump_dir_cmd(*inode, image, *json, *hex),
    }
}

fn dump_superblock_cmd(path: &PathBuf, json: bool, hex: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::dump::superblock",
        "dump_superblock",
        image = %path.display(),
        output_json = json,
        include_hex = hex
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::dump::superblock", "dump_superblock_start");

    let cx = cli_cx();
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;

    let raw_hex = if hex {
        let (offset, len, label) = match &flavor {
            FsFlavor::Ext4(_) => (
                EXT4_SUPERBLOCK_OFFSET,
                EXT4_SUPERBLOCK_SIZE,
                "ext4 superblock",
            ),
            FsFlavor::Btrfs(_) => (
                BTRFS_SUPER_INFO_OFFSET,
                BTRFS_SUPER_INFO_SIZE,
                "btrfs superblock",
            ),
        };
        let bytes = read_file_region(path, offset, len, label)?;
        Some(bytes_to_hex_dump(&bytes))
    } else {
        None
    };

    let output = DumpSuperblockOutput {
        filesystem: filesystem_name(&flavor).to_owned(),
        superblock: superblock_info_for(&flavor),
        raw_hex,
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize dump superblock output")?
        );
    } else {
        println!("FrankenFS Dump: superblock");
        println!("filesystem: {}", output.filesystem);
        print_superblock_info(&output.superblock);
        if let Some(raw_hex) = &output.raw_hex {
            println!();
            println!("raw_hex:");
            println!("{raw_hex}");
        }
    }

    info!(
        target: "ffs::cli::dump::superblock",
        filesystem = output.filesystem,
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "dump_superblock_complete"
    );

    Ok(())
}

fn dump_group_cmd(group: u32, path: &PathBuf, json: bool, hex: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::dump::group",
        "dump_group",
        image = %path.display(),
        group,
        output_json = json,
        include_hex = hex
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::dump::group", "dump_group_start");

    let output = build_dump_group_output(path, group, hex)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize dump group output")?
        );
    } else {
        println!("FrankenFS Dump: group");
        println!("filesystem: {}", output.filesystem);
        println!("group: {}", output.group);
        if let Some(descriptor) = &output.descriptor {
            println!("descriptor:");
            println!("  block_bitmap: {}", descriptor.block_bitmap);
            println!("  inode_bitmap: {}", descriptor.inode_bitmap);
            println!("  inode_table: {}", descriptor.inode_table);
            println!("  free_blocks_count: {}", descriptor.free_blocks_count);
            println!("  free_inodes_count: {}", descriptor.free_inodes_count);
            println!("  used_dirs_count: {}", descriptor.used_dirs_count);
            println!("  itable_unused: {}", descriptor.itable_unused);
            println!("  flags: 0x{:04X}", descriptor.flags);
            println!("  checksum: 0x{:04X}", descriptor.checksum);
        }
        if let Some(chunk) = &output.btrfs_chunk {
            println!("chunk:");
            println!(
                "  logical: {}..{} (bytes={})",
                chunk.logical_start, chunk.logical_end_inclusive, chunk.logical_bytes
            );
            println!(
                "  type: {} ({})",
                chunk.chunk_type_raw,
                chunk.chunk_type_flags.join("|")
            );
            println!("  owner: {}", chunk.owner);
            println!("  stripe_len: {}", chunk.stripe_len);
            println!("  sector_size: {}", chunk.sector_size);
            println!("  stripes: {}", chunk.stripe_count);
            for stripe in &chunk.stripes {
                println!(
                    "    stripe={} devid={} physical={}..{}",
                    stripe.stripe_index,
                    stripe.devid,
                    stripe.physical_start,
                    stripe.physical_end_inclusive
                );
            }
        }

        if let Some(raw_hex) = &output.raw_hex {
            println!();
            println!("raw_hex:");
            println!("{raw_hex}");
        }
        if !output.limitations.is_empty() {
            println!();
            println!("limitations:");
            for limitation in &output.limitations {
                println!("  - {limitation}");
            }
        }
    }

    info!(
        target: "ffs::cli::dump::group",
        group,
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "dump_group_complete"
    );

    Ok(())
}

pub(super) fn build_dump_group_output(
    path: &PathBuf,
    group: u32,
    hex: bool,
) -> Result<DumpGroupOutput> {
    let cx = cli_cx();
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;

    match flavor {
        FsFlavor::Ext4(sb) => {
            let (desc, raw_desc) = read_ext4_group_desc_from_path(path, &sb, group)?;
            let raw_hex = if hex {
                Some(bytes_to_hex_dump(&raw_desc))
            } else {
                None
            };
            Ok(DumpGroupOutput {
                filesystem: "ext4".to_owned(),
                group,
                descriptor: Some(desc),
                btrfs_chunk: None,
                raw_hex,
                limitations: Vec::new(),
            })
        }
        FsFlavor::Btrfs(sb) => {
            let open_fs = OpenFs::open_with_options(&cx, path, &OpenOptions::default())
                .with_context(|| format!("failed to open image: {}", path.display()))?;
            let mut limitations = Vec::new();
            let entries = build_btrfs_group_info(&open_fs, &sb, &mut limitations);
            let index = usize::try_from(group)
                .with_context(|| format!("group index {group} does not fit usize"))?;
            let chunk = entries.get(index).cloned().ok_or_else(|| {
                anyhow::anyhow!(
                    "btrfs chunk index {} is out of range (available chunks: {})",
                    group,
                    entries.len()
                )
            })?;
            let raw_hex = if hex {
                open_fs
                    .btrfs_context()
                    .and_then(|ctx| ctx.chunks.get(index))
                    .map(encode_btrfs_chunk_entry_bytes)
                    .map(|bytes| bytes_to_hex_dump(&bytes))
            } else {
                None
            };
            Ok(DumpGroupOutput {
                filesystem: "btrfs".to_owned(),
                group,
                descriptor: None,
                btrfs_chunk: Some(chunk),
                raw_hex,
                limitations,
            })
        }
    }
}

fn dump_inode_cmd(inode: u64, path: &PathBuf, json: bool, hex: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::dump::inode",
        "dump_inode",
        image = %path.display(),
        inode,
        output_json = json,
        include_hex = hex
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::dump::inode", "dump_inode_start");

    let output = build_dump_inode_output(path, inode, hex)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize dump inode output")?
        );
    } else {
        println!("FrankenFS Dump: inode");
        println!("filesystem: {}", output.filesystem);
        println!("inode: {}", output.inode);

        if let Some(parsed) = &output.ext4_parsed {
            println!("mode: 0x{:04X}", parsed.mode);
            println!("uid: {}", parsed.uid);
            println!("gid: {}", parsed.gid);
            println!("size: {}", parsed.size);
            println!("links_count: {}", parsed.links_count);
            println!("blocks: {}", parsed.blocks);
            println!("flags: 0x{:08X}", parsed.flags);
            println!("generation: {}", parsed.generation);
            println!("file_acl: {}", parsed.file_acl);
            println!("atime: {}", parsed.atime);
            println!("ctime: {}", parsed.ctime);
            println!("mtime: {}", parsed.mtime);
            println!("dtime: {}", parsed.dtime);
            println!("extra_isize: {}", parsed.extra_isize);
            println!("checksum: 0x{:08X}", parsed.checksum);
            println!("projid: {}", parsed.projid);
        }

        if let Some(parsed) = &output.btrfs_parsed {
            println!("mode: 0o{:o}", parsed.mode);
            println!("uid: {}", parsed.uid);
            println!("gid: {}", parsed.gid);
            println!("size: {}", parsed.size);
            println!("nbytes: {}", parsed.nbytes);
            println!("nlink: {}", parsed.nlink);
            println!("rdev: {}", parsed.rdev);
            println!("atime: {}.{:09}", parsed.atime_sec, parsed.atime_nsec);
            println!("ctime: {}.{:09}", parsed.ctime_sec, parsed.ctime_nsec);
            println!("mtime: {}.{:09}", parsed.mtime_sec, parsed.mtime_nsec);
            println!("otime: {}.{:09}", parsed.otime_sec, parsed.otime_nsec);
        }

        if !output.limitations.is_empty() {
            println!("limitations:");
            for limitation in &output.limitations {
                println!("  - {limitation}");
            }
        }

        if let Some(raw_hex) = &output.raw_hex {
            println!();
            println!("raw_hex:");
            println!("{raw_hex}");
        }
    }

    info!(
        target: "ffs::cli::dump::inode",
        inode,
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "dump_inode_complete"
    );

    Ok(())
}

pub(super) fn build_dump_inode_output(
    path: &PathBuf,
    inode: u64,
    hex: bool,
) -> Result<DumpInodeOutput> {
    let cx = cli_cx();
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;
    match flavor {
        FsFlavor::Ext4(sb) => {
            let inode_number = InodeNumber(inode);
            let (parsed, raw_inode) = read_ext4_inode_from_path(path, &sb, inode_number)
                .with_context(|| format!("failed to read inode {inode}"))?;
            let raw_hex = if hex {
                Some(bytes_to_hex_dump(&raw_inode))
            } else {
                None
            };
            Ok(DumpInodeOutput {
                filesystem: "ext4".to_owned(),
                inode,
                ext4_parsed: Some(parsed),
                btrfs_parsed: None,
                raw_hex,
                limitations: Vec::new(),
            })
        }
        FsFlavor::Btrfs(sb) => {
            let open_fs = OpenFs::open(&cx, path)
                .with_context(|| format!("failed to open image: {}", path.display()))?;
            let root_items = open_fs
                .walk_btrfs_root_tree(&cx)
                .context("failed to walk btrfs root tree")?;
            let fs_tree_root_item = root_items
                .iter()
                .find(|item| {
                    item.key.objectid == BTRFS_FS_TREE_OBJECTID
                        && item.key.item_type == BTRFS_ITEM_ROOT_ITEM
                })
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "failed to locate btrfs FS tree root item (objectid={BTRFS_FS_TREE_OBJECTID})"
                    )
                })?;
            let fs_tree_root = parse_root_item(&fs_tree_root_item.data)
                .context("failed to parse btrfs FS tree root item")?;
            let fs_tree_entries = open_fs
                .walk_btrfs_tree(&cx, fs_tree_root.bytenr)
                .with_context(|| {
                    format!("failed to walk btrfs FS tree at {}", fs_tree_root.bytenr)
                })?;
            let canonical_inode = if inode == 1 {
                sb.root_dir_objectid
            } else {
                inode
            };
            let inode_item = fs_tree_entries
                .iter()
                .find(|item| {
                    item.key.objectid == canonical_inode
                        && item.key.item_type == BTRFS_ITEM_INODE_ITEM
                        && item.key.offset == 0
                })
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "failed to locate btrfs inode item for objectid {canonical_inode}"
                    )
                })?;
            let parsed = parse_inode_item(&inode_item.data).with_context(|| {
                format!("failed to parse btrfs inode item for objectid {canonical_inode}")
            })?;
            let mut limitations = Vec::new();
            if inode == 1 && canonical_inode != 1 {
                limitations.push(format!(
                    "inode 1 maps to btrfs root objectid {canonical_inode}"
                ));
            }
            let raw_hex = if hex {
                Some(bytes_to_hex_dump(&inode_item.data))
            } else {
                None
            };
            Ok(DumpInodeOutput {
                filesystem: "btrfs".to_owned(),
                inode,
                ext4_parsed: None,
                btrfs_parsed: Some(parsed.into()),
                raw_hex,
                limitations,
            })
        }
    }
}

#[allow(clippy::too_many_lines)]
fn dump_extents_cmd(inode: u64, path: &PathBuf, json: bool, hex: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::dump::extents",
        "dump_extents",
        image = %path.display(),
        inode,
        output_json = json,
        include_hex = hex
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::dump::extents", "dump_extents_start");

    let (image, reader) = load_ext4_reader(path, "dump extents")?;
    let inode_number = InodeNumber(inode);
    let parsed_inode = reader
        .read_inode(&image, inode_number)
        .with_context(|| format!("failed to read inode {inode}"))?;
    let (root_header, _) = parse_inode_extent_tree(&parsed_inode)
        .with_context(|| format!("inode {inode} is not extent-backed"))?;

    let mut nodes = Vec::new();
    collect_extent_nodes(
        &reader,
        &image,
        None,
        &parsed_inode.extent_bytes,
        root_header.depth,
        hex,
        &mut nodes,
    )?;

    let flattened_extents = reader
        .collect_extents(&image, &parsed_inode)
        .with_context(|| format!("failed to collect extents for inode {inode}"))?
        .into_iter()
        .map(dump_extent_entry)
        .collect();

    let output = DumpExtentOutput {
        filesystem: "ext4".to_owned(),
        inode,
        root_depth: root_header.depth,
        nodes,
        flattened_extents,
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize dump extents output")?
        );
    } else {
        println!("FrankenFS Dump: extents");
        println!("filesystem: {}", output.filesystem);
        println!("inode: {}", output.inode);
        println!("root_depth: {}", output.root_depth);
        println!("nodes: {}", output.nodes.len());

        for node in &output.nodes {
            let source = node
                .source_block
                .map_or_else(|| "inode_root".to_owned(), |block| block.to_string());
            println!(
                "  node source={} depth={} entries={} max_entries={} generation={}",
                source,
                node.header.depth,
                node.header.entries,
                node.header.max_entries,
                node.header.generation
            );
            match &node.node {
                DumpExtentNodeKindOutput::Leaf { extents } => {
                    for extent in extents {
                        println!(
                            "    leaf logical={} physical={}..{} len={} initialized={}",
                            extent.logical_block,
                            extent.physical_start,
                            extent.physical_end_inclusive,
                            extent.actual_len,
                            extent.initialized
                        );
                    }
                }
                DumpExtentNodeKindOutput::Index { indexes } => {
                    for index in indexes {
                        println!(
                            "    index logical={} child_block={}",
                            index.logical_block, index.leaf_block
                        );
                    }
                }
            }
            if let Some(raw_hex) = &node.raw_hex {
                println!("    raw_hex:");
                println!("{raw_hex}");
            }
        }
    }

    info!(
        target: "ffs::cli::dump::extents",
        inode,
        nodes = output.nodes.len(),
        flattened_extents = output.flattened_extents.len(),
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "dump_extents_complete"
    );

    Ok(())
}

#[allow(clippy::too_many_lines)]
fn dump_dir_cmd(inode: u64, path: &PathBuf, json: bool, hex: bool) -> Result<()> {
    let command_span = info_span!(
        target: "ffs::cli::dump::dir",
        "dump_dir",
        image = %path.display(),
        inode,
        output_json = json,
        include_hex = hex
    );
    let _command_guard = command_span.enter();
    let started = Instant::now();
    info!(target: "ffs::cli::dump::dir", "dump_dir_start");

    let output = build_dump_dir_output(path, inode, hex)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&output).context("serialize dump dir output")?
        );
    } else {
        println!("FrankenFS Dump: dir");
        println!("filesystem: {}", output.filesystem);
        println!("inode: {}", output.inode);
        println!("entries: {}", output.entries.len());
        for entry in &output.entries {
            println!(
                "  index={} inode={} rec_len={} type={} name={}",
                entry.index, entry.inode, entry.rec_len, entry.file_type, entry.name
            );
        }

        if let Some(htree) = &output.htree {
            println!();
            println!("htree:");
            println!("  hash_version: {}", htree.hash_version);
            println!("  indirect_levels: {}", htree.indirect_levels);
            for entry in &htree.entries {
                println!("  entry hash=0x{:08X} block={}", entry.hash, entry.block);
            }
        }

        if let Some(raw_hex_blocks) = &output.raw_hex_blocks {
            println!();
            println!("raw_hex_blocks: {}", raw_hex_blocks.len());
            for block in raw_hex_blocks {
                println!(
                    "  logical_block={} physical_block={}{}",
                    block.logical_block,
                    block.physical_block,
                    block
                        .item_kind
                        .as_ref()
                        .map(|kind| format!(" item_kind={kind}"))
                        .unwrap_or_default()
                );
                println!("{}", block.hex);
            }
        }

        if !output.limitations.is_empty() {
            println!();
            println!("limitations:");
            for limitation in &output.limitations {
                println!("  - {limitation}");
            }
        }
    }

    info!(
        target: "ffs::cli::dump::dir",
        inode,
        entries = output.entries.len(),
        has_htree = output.htree.is_some(),
        duration_us = u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX),
        "dump_dir_complete"
    );

    Ok(())
}

pub(super) fn build_dump_dir_output(
    path: &PathBuf,
    inode: u64,
    hex: bool,
) -> Result<DumpDirOutput> {
    let cx = cli_cx();
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;
    match flavor {
        FsFlavor::Ext4(_) => build_ext4_dump_dir_output(path, inode, hex),
        FsFlavor::Btrfs(_) => build_btrfs_dump_dir_output(path, inode, hex),
    }
}

fn build_ext4_dump_dir_output(path: &PathBuf, inode: u64, hex: bool) -> Result<DumpDirOutput> {
    let (image, reader) = load_ext4_reader(path, "dump dir")?;
    let inode_number = InodeNumber(inode);
    let parsed_inode = reader
        .read_inode(&image, inode_number)
        .with_context(|| format!("failed to read inode {inode}"))?;
    let entries = reader
        .read_dir(&image, &parsed_inode)
        .with_context(|| format!("failed to read directory entries for inode {inode}"))?;

    let htree = match reader
        .resolve_extent(&image, &parsed_inode, 0)
        .with_context(|| format!("failed to resolve first directory block for inode {inode}"))?
    {
        Some(physical_block) => {
            let block = reader
                .read_block(&image, BlockNumber(physical_block))
                .with_context(|| format!("failed to read directory block {physical_block}"))?;
            parse_dx_root(block).ok().map(|root| DumpDxRootOutput {
                hash_version: root.hash_version,
                indirect_levels: root.indirect_levels,
                entries: root
                    .entries
                    .iter()
                    .map(|entry| DumpDxEntryOutput {
                        hash: entry.hash,
                        block: entry.block,
                    })
                    .collect(),
            })
        }
        None => None,
    };

    let raw_hex_blocks = if hex {
        Some(read_ext4_directory_hex_blocks(
            &image,
            &reader,
            &parsed_inode,
        )?)
    } else {
        None
    };

    let mut limitations = Vec::new();
    limitations.push(
        "directory entry byte offsets are not exposed by parser APIs; `index` preserves on-disk iteration order"
            .to_owned(),
    );
    if htree.is_none() {
        limitations.push(
            "htree metadata is only shown for indexed directories with a parseable dx root"
                .to_owned(),
        );
    }

    Ok(DumpDirOutput {
        filesystem: "ext4".to_owned(),
        inode,
        entries: entries
            .iter()
            .enumerate()
            .map(|(index, entry)| dump_dir_entry(index, entry))
            .collect(),
        htree,
        raw_hex_blocks,
        limitations,
    })
}

fn build_btrfs_dump_dir_output(path: &PathBuf, inode: u64, hex: bool) -> Result<DumpDirOutput> {
    let cx = cli_cx();
    let open_fs = OpenFs::open(&cx, path)
        .with_context(|| format!("failed to open image: {}", path.display()))?;
    let entries = open_fs
        .readdir(&cx, InodeNumber(inode), 0)
        .with_context(|| format!("failed to read btrfs directory entries for inode {inode}"))?;
    let mut limitations = vec![
        "btrfs directory dump uses VFS readdir projection; on-disk rec_len offsets are not available"
            .to_owned(),
        "htree metadata is ext4-specific and not available for btrfs directories".to_owned(),
    ];
    let raw_hex_blocks = if hex {
        let items = open_fs
            .walk_btrfs_dir_entry_items(&cx, inode)
            .context("failed to read btrfs directory items")?;
        let blocks: Vec<DumpHexBlockOutput> = items
            .iter()
            .enumerate()
            .map(|(idx, (item_type, key_offset, raw))| {
                #[allow(clippy::cast_possible_truncation)]
                DumpHexBlockOutput {
                    logical_block: idx as u32,
                    physical_block: *key_offset,
                    item_kind: Some(
                        match *item_type {
                            ffs_btrfs::BTRFS_ITEM_DIR_ITEM => "dir_item",
                            ffs_btrfs::BTRFS_ITEM_DIR_INDEX => "dir_index",
                            _ => "unknown",
                        }
                        .to_owned(),
                    ),
                    hex: bytes_to_hex_dump(raw),
                }
            })
            .collect();
        limitations.push(
            "btrfs hex dump shows raw DIR_ITEM/DIR_INDEX payloads from B-tree leaves; \
             logical_block is the item index, physical_block is the key offset"
                .to_owned(),
        );
        Some(blocks)
    } else {
        None
    };
    Ok(DumpDirOutput {
        filesystem: "btrfs".to_owned(),
        inode,
        entries: entries
            .iter()
            .enumerate()
            .map(|(index, entry)| DumpDirEntryOutput {
                index,
                inode: entry.ino.0,
                rec_len: 0,
                file_type: format!("{:?}", entry.kind).to_ascii_lowercase(),
                name: entry.name_str(),
            })
            .collect(),
        htree: None,
        raw_hex_blocks,
        limitations,
    })
}

fn load_ext4_reader(path: &PathBuf, action: &str) -> Result<(Vec<u8>, Ext4ImageReader)> {
    let cx = cli_cx();
    let flavor = detect_filesystem_at_path(&cx, path)
        .with_context(|| format!("failed to detect ext4/btrfs metadata in {}", path.display()))?;
    if !matches!(flavor, FsFlavor::Ext4(_)) {
        bail!("{action} currently supports ext4 images only");
    }

    let image = std::fs::read(path)
        .with_context(|| format!("failed to read filesystem image: {}", path.display()))?;
    let reader = Ext4ImageReader::new(&image).context("failed to parse ext4 superblock")?;
    Ok((image, reader))
}

pub(super) fn bytes_to_hex_dump(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (line, chunk) in bytes.chunks(16).enumerate() {
        let offset = line.saturating_mul(16);
        write!(&mut out, "{offset:08x}:").expect("write to String cannot fail");
        for byte in chunk {
            write!(&mut out, " {byte:02x}").expect("write to String cannot fail");
        }
        out.push('\n');
    }
    out
}

fn dump_extent_entry(extent: Ext4Extent) -> DumpExtentEntryOutput {
    let actual_len = extent.actual_len();
    let initialized = !extent.is_unwritten();
    DumpExtentEntryOutput {
        logical_block: extent.logical_block,
        physical_start: extent.physical_start,
        physical_end_inclusive: extent
            .physical_start
            .saturating_add(u64::from(actual_len))
            .saturating_sub(1),
        raw_len: extent.raw_len,
        actual_len,
        initialized,
    }
}

fn collect_extent_nodes(
    reader: &Ext4ImageReader,
    image: &[u8],
    source_block: Option<u64>,
    raw_node: &[u8],
    expected_depth: u16,
    include_hex: bool,
    nodes: &mut Vec<DumpExtentNodeOutput>,
) -> Result<()> {
    let (header, tree) = parse_extent_tree(raw_node).context("failed to parse extent tree node")?;
    if header.depth != expected_depth {
        bail!(
            "extent tree depth mismatch: expected {expected_depth}, parsed {}",
            header.depth
        );
    }

    let raw_hex = include_hex.then(|| bytes_to_hex_dump(raw_node));

    match tree {
        ExtentTree::Leaf(extents) => {
            nodes.push(DumpExtentNodeOutput {
                source_block,
                header,
                node: DumpExtentNodeKindOutput::Leaf {
                    extents: extents.into_iter().map(dump_extent_entry).collect(),
                },
                raw_hex,
            });
        }
        ExtentTree::Index(indexes) => {
            nodes.push(DumpExtentNodeOutput {
                source_block,
                header,
                node: DumpExtentNodeKindOutput::Index {
                    indexes: indexes.clone(),
                },
                raw_hex,
            });

            let next_depth = expected_depth
                .checked_sub(1)
                .ok_or_else(|| anyhow::anyhow!("invalid extent depth transition from 0"))?;
            for index in indexes {
                let child = reader
                    .read_block(image, BlockNumber(index.leaf_block))
                    .with_context(|| {
                        format!(
                            "failed to read extent child block {} (logical={})",
                            index.leaf_block, index.logical_block
                        )
                    })?;
                collect_extent_nodes(
                    reader,
                    image,
                    Some(index.leaf_block),
                    child,
                    next_depth,
                    include_hex,
                    nodes,
                )?;
            }
        }
    }

    Ok(())
}

fn dump_dir_entry(index: usize, entry: &Ext4DirEntry) -> DumpDirEntryOutput {
    DumpDirEntryOutput {
        index,
        inode: u64::from(entry.inode),
        rec_len: entry.rec_len,
        file_type: format!("{:?}", entry.file_type).to_ascii_lowercase(),
        name: entry.name_str(),
    }
}

fn read_ext4_directory_hex_blocks(
    image: &[u8],
    reader: &Ext4ImageReader,
    inode: &Ext4Inode,
) -> Result<Vec<DumpHexBlockOutput>> {
    let block_size = u64::from(reader.sb.block_size);
    let block_count_u64 = inode.size.div_ceil(block_size);
    let block_count = u32::try_from(block_count_u64).with_context(|| {
        format!("directory block count exceeds supported range: {block_count_u64}")
    })?;

    let mut blocks = Vec::new();
    for logical_block in 0..block_count {
        if let Some(physical_block) = reader
            .resolve_extent(image, inode, logical_block)
            .with_context(|| format!("failed to resolve directory block {logical_block}"))?
        {
            let block = reader
                .read_block(image, BlockNumber(physical_block))
                .with_context(|| format!("failed to read directory block {physical_block}"))?;
            blocks.push(DumpHexBlockOutput {
                logical_block,
                physical_block,
                item_kind: None,
                hex: bytes_to_hex_dump(block),
            });
        }
    }

    Ok(blocks)
}
