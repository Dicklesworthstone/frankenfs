//! Conformance harness: ext4 block group descriptors via FFS vs `dumpe2fs`.
//!
//! For every block group in every reference image, this test parses the
//! group descriptor with [`ffs_ondisk::Ext4ImageReader`] *and* with `dumpe2fs`
//! from `e2fsprogs`, then asserts that every parsed field matches the
//! kernel/userspace reference. The descriptor's checksum (when the filesystem
//! has `metadata_csum`) is recomputed from the raw bytes and compared against
//! both the stored value and the value `dumpe2fs` printed.
//!
//! The suite covers ≥50 group-descriptor comparisons drawn from a mix of
//! geometries (4 KiB / 1 KiB blocks, with and without `flex_bg`, with and
//! without a journal) so a regression in a single feature path can be located
//! without running the full reference suite.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ffs_ondisk::ext4::Ext4GroupDescChecksumKind;
use ffs_ondisk::{Ext4GroupDesc, Ext4ImageReader, Ext4Superblock, verify_group_desc_checksum};
use ffs_types::GroupNumber;

// EXT4_BG_* flag bits — kept private here because they are only meaningful
// against the dumpe2fs reference text (which prints the symbolic names).
const BG_INODE_UNINIT: u16 = 0x0001;
const BG_BLOCK_UNINIT: u16 = 0x0002;
const BG_INODE_ZEROED: u16 = 0x0004;

fn has_command(name: &str) -> bool {
    Command::new(name)
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok()
}

fn ext4_tools_available() -> bool {
    has_command("mkfs.ext4") && has_command("dumpe2fs")
}

fn unique_image_path(tag: &str) -> PathBuf {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    std::env::temp_dir().join(format!("ffs_gd_conf_{tag}_{pid}_{nanos}.ext4"))
}

#[derive(Debug, Clone, Copy)]
struct ImageVariant {
    tag: &'static str,
    size_bytes: u64,
    block_size: u32,
    /// Comma-separated `mkfs.ext4 -O` argument, or empty for defaults.
    features: &'static str,
}

/// Variants chosen so that:
/// - the union covers ≥ 50 block groups,
/// - both 4 KiB and 1 KiB block sizes appear,
/// - both `flex_bg` and `^flex_bg` appear,
/// - both journaled and journal-less images appear,
/// - both 32-byte and 64-byte descriptors are likely (`64bit` toggles the
///   second 32 bytes).
const VARIANTS: &[ImageVariant] = &[
    // Largest variant: 384 MiB / 1 KiB blocks ⇒ 48 groups (8 192 blocks/group).
    ImageVariant {
        tag: "1k_journal",
        size_bytes: 384 * 1024 * 1024,
        block_size: 1024,
        features: "",
    },
    // 64 MiB / 4 KiB blocks ⇒ 2 groups, with journal + flex_bg (default).
    ImageVariant {
        tag: "4k_journal",
        size_bytes: 64 * 1024 * 1024,
        block_size: 4096,
        features: "",
    },
    // 256 MiB / 4 KiB blocks ⇒ 8 groups, no journal.
    ImageVariant {
        tag: "4k_nojournal",
        size_bytes: 256 * 1024 * 1024,
        block_size: 4096,
        features: "^has_journal",
    },
    // 256 MiB / 4 KiB blocks ⇒ 8 groups, no flex_bg, no journal.
    ImageVariant {
        tag: "4k_noflex",
        size_bytes: 256 * 1024 * 1024,
        block_size: 4096,
        features: "^has_journal,^flex_bg",
    },
    // 16 MiB / 1 KiB blocks ⇒ 2 groups, no journal — smallest sanity image.
    ImageVariant {
        tag: "1k_small",
        size_bytes: 16 * 1024 * 1024,
        block_size: 1024,
        features: "^has_journal",
    },
];

fn create_image(variant: &ImageVariant) -> PathBuf {
    let path = unique_image_path(variant.tag);
    let f = std::fs::File::create(&path).expect("create image file");
    f.set_len(variant.size_bytes).expect("set image length");
    drop(f);

    let block_size = variant.block_size.to_string();
    let mut cmd = Command::new("mkfs.ext4");
    cmd.args(["-q", "-F", "-b", &block_size]);
    if !variant.features.is_empty() {
        cmd.args(["-O", variant.features]);
    }
    cmd.arg(&path);
    cmd.stdout(Stdio::null()).stderr(Stdio::null());
    let st = cmd.status().expect("spawn mkfs.ext4");
    assert!(
        st.success(),
        "mkfs.ext4 failed for variant {} (size={}, block_size={}, features='{}')",
        variant.tag,
        variant.size_bytes,
        variant.block_size,
        variant.features
    );
    path
}

#[derive(Debug, Default, PartialEq, Eq)]
struct KernelGroupDesc {
    group: u32,
    csum: u16,
    flags: u16,
    block_bitmap: u64,
    block_bitmap_csum: u32,
    inode_bitmap: u64,
    inode_bitmap_csum: u32,
    inode_table: u64,
    free_blocks: u32,
    free_inodes: u32,
    used_dirs: u32,
}

/// Run `dumpe2fs <image>` and parse out one [`KernelGroupDesc`] per group.
///
/// The textual format produced by `dumpe2fs` is stable enough across
/// e2fsprogs versions that a line-oriented parser is reliable: every group
/// header is `Group N: (Blocks ...) csum 0xHHHH [FLAGS]`, followed by an
/// indented block whose fields each begin with a recognizable keyword.
fn capture_kernel_group_descs(image: &Path) -> Vec<KernelGroupDesc> {
    let out = Command::new("dumpe2fs")
        .arg(image)
        .stderr(Stdio::null())
        .output()
        .expect("run dumpe2fs");
    assert!(out.status.success(), "dumpe2fs failed");
    let text = String::from_utf8(out.stdout).expect("dumpe2fs produced non-UTF-8 output");

    let mut groups = Vec::new();
    let mut cur: Option<KernelGroupDesc> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("Group ") {
            // dumpe2fs prefixes both per-group blocks (`Group 0: (Blocks ...)`)
            // and superblock-summary lines (`Group descriptor size:`) with the
            // word "Group". Disambiguate by requiring the next character to be
            // a digit, which identifies the per-group blocks unambiguously.
            if rest.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                if let Some(prev) = cur.take() {
                    groups.push(prev);
                }
                cur = Some(parse_group_header(rest));
            }
            continue;
        }
        let Some(g) = cur.as_mut() else { continue };
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("Block bitmap at ") {
            let (block, csum) = parse_at_with_csum(rest);
            g.block_bitmap = block;
            g.block_bitmap_csum = csum;
        } else if let Some(rest) = trimmed.strip_prefix("Inode bitmap at ") {
            let (block, csum) = parse_at_with_csum(rest);
            g.inode_bitmap = block;
            g.inode_bitmap_csum = csum;
        } else if let Some(rest) = trimmed.strip_prefix("Inode table at ") {
            g.inode_table = parse_inode_table_start(rest);
        } else if trimmed.contains("free blocks") && trimmed.contains("free inodes") {
            let (fb, fi, ud) = parse_free_counts(trimmed);
            g.free_blocks = fb;
            g.free_inodes = fi;
            g.used_dirs = ud;
        }
    }
    if let Some(prev) = cur.take() {
        groups.push(prev);
    }
    groups
}

fn parse_group_header(rest: &str) -> KernelGroupDesc {
    // rest looks like: `0: (Blocks 0-32767) csum 0x29a0 [INODE_UNINIT, ITABLE_ZEROED]`
    let mut g = KernelGroupDesc::default();

    let colon = rest.find(':').expect("group header missing ':'");
    g.group = rest[..colon].trim().parse().expect("group number");

    if let Some(idx) = rest.find("csum ") {
        let after = &rest[idx + "csum ".len()..];
        let end = after
            .find(|c: char| c.is_whitespace() || c == '[')
            .unwrap_or(after.len());
        // The group-descriptor checksum is 16 bits on disk; dumpe2fs prints
        // at most 4 hex digits for this field, so the high half of the parsed
        // u32 is always zero.
        g.csum = u16::try_from(parse_hex_u32(&after[..end]) & 0xFFFF).expect("masked to 16 bits");
    }

    if let Some(start) = rest.find('[')
        && let Some(end) = rest.find(']')
    {
        let body = &rest[start + 1..end];
        for tok in body.split(',') {
            match tok.trim() {
                "INODE_UNINIT" => g.flags |= BG_INODE_UNINIT,
                "BLOCK_UNINIT" => g.flags |= BG_BLOCK_UNINIT,
                "ITABLE_ZEROED" => g.flags |= BG_INODE_ZEROED,
                "" => {}
                other => panic!("unknown bg flag from dumpe2fs: {other}"),
            }
        }
    }
    g
}

/// Parse a line like `33 (+33), csum 0xfdff71b2` or `34 (bg #0 + 34), csum ...`.
fn parse_at_with_csum(rest: &str) -> (u64, u32) {
    let end = rest.find([' ', ',']).unwrap_or(rest.len());
    let block: u64 = rest[..end].parse().expect("absolute block number");
    let csum = rest.find("csum ").map_or(0, |idx| {
        let after = &rest[idx + "csum ".len()..];
        let cend = after
            .find(|c: char| c.is_whitespace() || c == ',')
            .unwrap_or(after.len());
        parse_hex_u32(&after[..cend])
    });
    (block, csum)
}

/// Parse `41-1064 (+41)` and return the start block (`41`).
fn parse_inode_table_start(rest: &str) -> u64 {
    let end = rest.find('-').unwrap_or(rest.len());
    rest[..end].parse().expect("inode table start block")
}

/// Parse `15343 free blocks, 16373 free inodes, 2 directories, ...`.
fn parse_free_counts(rest: &str) -> (u32, u32, u32) {
    fn first_u32_before(haystack: &str, needle: &str) -> u32 {
        let idx = haystack
            .find(needle)
            .unwrap_or_else(|| panic!("missing '{needle}' in '{haystack}'"));
        let prefix = haystack[..idx].trim_end();
        let token_start = prefix.rfind(|c: char| c.is_whitespace() || c == ',');
        let token = token_start.map_or(prefix, |s| {
            prefix[s..].trim_start_matches(|c: char| c.is_whitespace() || c == ',')
        });
        token
            .parse()
            .unwrap_or_else(|e| panic!("non-numeric '{token}' for '{needle}': {e}"))
    }

    let fb = first_u32_before(rest, "free blocks");
    let fi = first_u32_before(rest, "free inodes");
    let ud = first_u32_before(rest, "directories");
    (fb, fi, ud)
}

fn parse_hex_u32(s: &str) -> u32 {
    let s = s.trim();
    let body = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u32::from_str_radix(body, 16).expect("hex literal")
}

/// dumpe2fs prints a 16-bit checksum for 32-byte descriptors and a 32-bit
/// checksum for 64-byte descriptors. ffs-ondisk always reports `u32`, so
/// truncate to whatever the kernel printed for an apples-to-apples compare.
fn truncate_csum_to_desc(value: u32, desc_size: u16) -> u32 {
    if desc_size >= 64 {
        value
    } else {
        value & 0xFFFF
    }
}

#[derive(Debug)]
struct Comparison {
    #[allow(dead_code)] // Read by Debug formatter in the corpus-floor assertion.
    image_tag: &'static str,
    block_size: u32,
    desc_size: u16,
    groups_compared: usize,
    descriptor_csum_kind: Ext4GroupDescChecksumKind,
}

// The body is intentionally one long sequence of `assert_field_eq` calls
// for every group descriptor field. Splitting it out into per-field helpers
// would just shuffle the comparisons through accessor functions without
// improving clarity, and the function is read top-to-bottom as the spec
// of "every field we promise to keep in sync with e2fsprogs."
#[allow(clippy::too_many_lines)]
fn compare_image(variant: &ImageVariant) -> Comparison {
    let path = create_image(variant);
    let bytes = std::fs::read(&path).expect("read formatted image");
    let kernel_groups = capture_kernel_group_descs(&path);

    // Image is no longer needed once we have raw bytes + dumpe2fs output.
    std::fs::remove_file(&path).ok();

    let reader = Ext4ImageReader::new(&bytes).expect("parse superblock");
    let sb: &Ext4Superblock = &reader.sb;
    let desc_size = sb.group_desc_size();
    let checksum_kind = sb.group_desc_checksum_kind();
    let groups_count = sb.groups_count();

    assert_eq!(
        groups_count as usize,
        kernel_groups.len(),
        "{}: groups_count mismatch (ffs={} dumpe2fs={})",
        variant.tag,
        groups_count,
        kernel_groups.len()
    );

    for kernel in &kernel_groups {
        let group = GroupNumber(kernel.group);
        let ffs = reader
            .read_group_desc(&bytes, group)
            .expect("read group descriptor");
        let raw_offset = sb
            .group_desc_offset(group)
            .expect("group descriptor offset");
        let raw_offset_usize = usize::try_from(raw_offset).expect("offset fits usize");
        let raw_desc = &bytes[raw_offset_usize..raw_offset_usize + usize::from(desc_size)];

        assert_field_eq(
            variant.tag,
            kernel.group,
            "block_bitmap",
            &ffs.block_bitmap,
            &kernel.block_bitmap,
        );
        assert_field_eq(
            variant.tag,
            kernel.group,
            "inode_bitmap",
            &ffs.inode_bitmap,
            &kernel.inode_bitmap,
        );
        assert_field_eq(
            variant.tag,
            kernel.group,
            "inode_table",
            &ffs.inode_table,
            &kernel.inode_table,
        );
        assert_field_eq(
            variant.tag,
            kernel.group,
            "free_blocks_count",
            &ffs.free_blocks_count,
            &kernel.free_blocks,
        );
        assert_field_eq(
            variant.tag,
            kernel.group,
            "free_inodes_count",
            &ffs.free_inodes_count,
            &kernel.free_inodes,
        );
        assert_field_eq(
            variant.tag,
            kernel.group,
            "used_dirs_count",
            &ffs.used_dirs_count,
            &kernel.used_dirs,
        );
        // ITABLE_ZEROED, INODE_UNINIT, BLOCK_UNINIT are the only flags
        // dumpe2fs prints; mask the ffs side to the same set.
        let ffs_flag_subset = ffs.flags & (BG_INODE_UNINIT | BG_BLOCK_UNINIT | BG_INODE_ZEROED);
        assert_field_eq(
            variant.tag,
            kernel.group,
            "flags",
            &ffs_flag_subset,
            &kernel.flags,
        );

        // The bitmap checksum widths differ by descriptor size; only compare
        // truncated values so a 32-byte descriptor doesn't fail the high
        // bits comparison.
        let ffs_block_csum = truncate_csum_to_desc(ffs.block_bitmap_csum, desc_size);
        let ffs_inode_csum = truncate_csum_to_desc(ffs.inode_bitmap_csum, desc_size);
        assert_field_eq(
            variant.tag,
            kernel.group,
            "block_bitmap_csum",
            &ffs_block_csum,
            &kernel.block_bitmap_csum,
        );
        assert_field_eq(
            variant.tag,
            kernel.group,
            "inode_bitmap_csum",
            &ffs_inode_csum,
            &kernel.inode_bitmap_csum,
        );

        // Group descriptor checksum: must match dumpe2fs and must verify
        // against the raw bytes via the metadata_csum/gdt_csum routines.
        assert_field_eq(
            variant.tag,
            kernel.group,
            "checksum",
            &ffs.checksum,
            &kernel.csum,
        );
        if checksum_kind != Ext4GroupDescChecksumKind::None {
            verify_group_desc_checksum(
                raw_desc,
                &sb.uuid,
                sb.csum_seed(),
                kernel.group,
                desc_size,
                checksum_kind,
            )
            .unwrap_or_else(|e| {
                panic!(
                    "{}: group {} checksum failed to verify against raw bytes: {:?}",
                    variant.tag, kernel.group, e
                );
            });
        }

        // Sanity: Ext4GroupDesc's own raw-byte view round-trips as an extra
        // safeguard against silent field-shuffling between parser and writer.
        let mut roundtrip = vec![0u8; usize::from(desc_size)];
        ffs.write_to_bytes(&mut roundtrip, desc_size)
            .expect("re-serialize group descriptor");
        let reparsed = Ext4GroupDesc::parse_from_bytes(&roundtrip, desc_size)
            .expect("re-parse round-tripped descriptor");
        assert_eq!(
            reparsed, ffs,
            "{}: group {} round-trip parse/serialize did not preserve fields",
            variant.tag, kernel.group
        );
    }

    Comparison {
        image_tag: variant.tag,
        block_size: variant.block_size,
        desc_size,
        groups_compared: kernel_groups.len(),
        descriptor_csum_kind: checksum_kind,
    }
}

fn assert_field_eq<T: std::fmt::Debug + PartialEq>(
    image_tag: &str,
    group: u32,
    field: &str,
    ffs: &T,
    kernel: &T,
) {
    assert!(
        ffs == kernel,
        "{image_tag}: group {group} field {field}: ffs={ffs:?} dumpe2fs={kernel:?}"
    );
}

#[test]
fn ext4_group_desc_kernel_reference_matches() {
    if !ext4_tools_available() {
        eprintln!("SKIPPED: ext4 kernel tools not available");
        return;
    }

    let mut total_groups = 0_usize;
    let mut comparisons = Vec::new();
    for variant in VARIANTS {
        let report = compare_image(variant);
        total_groups += report.groups_compared;
        comparisons.push(report);
    }

    // Conformance contract: at least 50 group-descriptor comparisons across
    // the assembled corpus. The variant set above is sized to exceed that
    // floor; the assertion guards against accidental shrinkage of the corpus.
    assert!(
        total_groups >= 50,
        "expected ≥50 group-descriptor comparisons, got {total_groups}: {comparisons:?}"
    );

    // Cross-variant invariants.
    let saw_4k = comparisons.iter().any(|c| c.block_size == 4096);
    let saw_1k = comparisons.iter().any(|c| c.block_size == 1024);
    assert!(
        saw_4k && saw_1k,
        "expected coverage of both 4KiB and 1KiB block sizes"
    );
    let saw_metadata_csum = comparisons
        .iter()
        .any(|c| c.descriptor_csum_kind == Ext4GroupDescChecksumKind::MetadataCsum);
    assert!(
        saw_metadata_csum,
        "expected at least one metadata_csum image (default mkfs.ext4 enables it)"
    );
    let saw_64bit_desc = comparisons.iter().any(|c| c.desc_size >= 64);
    assert!(
        saw_64bit_desc,
        "expected at least one 64-byte descriptor variant"
    );
}

// ── Unit tests for the dumpe2fs parser itself ───────────────────────

#[cfg(test)]
mod parser_unit_tests {
    use super::*;

    #[test]
    fn parses_group_header_with_multiple_flags() {
        let g =
            parse_group_header("1: (Blocks 32768-65535) csum 0x36a2 [INODE_UNINIT, ITABLE_ZEROED]");
        assert_eq!(g.group, 1);
        assert_eq!(g.csum, 0x36a2);
        assert_eq!(g.flags, BG_INODE_UNINIT | BG_INODE_ZEROED);
    }

    #[test]
    fn parses_group_header_with_no_flags() {
        let g = parse_group_header("0: (Blocks 0-8191) csum 0xabcd []");
        assert_eq!(g.group, 0);
        assert_eq!(g.csum, 0xabcd);
        assert_eq!(g.flags, 0);
    }

    #[test]
    fn parses_at_with_csum_flex_bg_form() {
        let (block, csum) = parse_at_with_csum("34 (bg #0 + 34), csum 0x6e3616c1");
        assert_eq!(block, 34);
        assert_eq!(csum, 0x6e36_16c1);
    }

    #[test]
    fn parses_at_with_csum_native_form() {
        let (block, csum) = parse_at_with_csum("33 (+33), csum 0xfdff71b2");
        assert_eq!(block, 33);
        assert_eq!(csum, 0xfdff_71b2);
    }

    #[test]
    fn parses_inode_table_start() {
        assert_eq!(parse_inode_table_start("41-1064 (+41)"), 41);
        assert_eq!(parse_inode_table_start("2085-4132 (bg #0 + 2085)"), 2085);
    }

    #[test]
    fn parses_free_counts() {
        assert_eq!(
            parse_free_counts(
                "15343 free blocks, 16373 free inodes, 2 directories, 16373 unused inodes",
            ),
            (15343, 16373, 2)
        );
        assert_eq!(
            parse_free_counts("0 free blocks, 0 free inodes, 0 directories, 0 unused inodes"),
            (0, 0, 0)
        );
    }
}
