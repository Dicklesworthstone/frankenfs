#![forbid(unsafe_code)]

pub use ffs_ondisk::ext4::*;

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_types::{EXT4_SUPER_MAGIC, EXT4_SUPERBLOCK_SIZE};

    #[test]
    fn ext4_state_constants_are_reexported() {
        assert_eq!(EXT4_VALID_FS, 0x0001);
        assert_eq!(EXT4_ERROR_FS, 0x0002);
        assert_eq!(EXT4_ORPHAN_FS, 0x0004);
    }

    #[test]
    fn checksum_helper_is_stable_and_input_sensitive() {
        let seed = 0xA5A5_5A5A;
        let crc_a = ext4_chksum(seed, b"frankenfs");
        let crc_b = ext4_chksum(seed, b"frankenfs");
        let crc_c = ext4_chksum(seed, b"frankenft");

        assert_eq!(crc_a, crc_b, "same input should be deterministic");
        assert_ne!(crc_a, crc_c, "different input should change checksum");
    }

    #[test]
    fn superblock_parser_reexport_reports_short_input() {
        assert!(
            Ext4Superblock::parse_superblock_region(&[]).is_err(),
            "empty region must be rejected"
        );
    }

    fn make_valid_superblock_region() -> [u8; EXT4_SUPERBLOCK_SIZE] {
        let mut sb = [0_u8; EXT4_SUPERBLOCK_SIZE];
        sb[0x38..0x3A].copy_from_slice(&EXT4_SUPER_MAGIC.to_le_bytes());
        sb[0x18..0x1C].copy_from_slice(&2_u32.to_le_bytes());
        sb[0x1C..0x20].copy_from_slice(&2_u32.to_le_bytes());
        sb[0x00..0x04].copy_from_slice(&8192_u32.to_le_bytes());
        sb[0x04..0x08].copy_from_slice(&32768_u32.to_le_bytes());
        sb[0x20..0x24].copy_from_slice(&32768_u32.to_le_bytes());
        sb[0x24..0x28].copy_from_slice(&32768_u32.to_le_bytes());
        sb[0x28..0x2C].copy_from_slice(&8192_u32.to_le_bytes());
        sb[0x58..0x5A].copy_from_slice(&256_u16.to_le_bytes());
        sb
    }

    #[test]
    fn dir_block_parser_reexport_handles_zero_initialized_block() {
        let block = vec![0_u8; 4096];
        let (entries, tail) = parse_dir_block(&block, 4096).expect("zero block parses");
        assert_eq!(entries, [] as [ffs_ondisk::Ext4DirEntry; 0]);
        assert!(tail.is_none());
    }

    #[test]
    fn superblock_reexport_exposes_quota_inode_metadata() {
        let mut sb = make_valid_superblock_region();
        let ro_compat =
            (Ext4RoCompatFeatures::QUOTA.0 | Ext4RoCompatFeatures::PROJECT.0).to_le_bytes();
        sb[0x64..0x68].copy_from_slice(&ro_compat);
        sb[0x240..0x244].copy_from_slice(&3_u32.to_le_bytes());
        sb[0x244..0x248].copy_from_slice(&4_u32.to_le_bytes());
        sb[0x26C..0x270].copy_from_slice(&11_u32.to_le_bytes());

        let parsed = Ext4Superblock::parse_superblock_region(&sb).expect("parse");
        assert_eq!(
            parsed.quota_inodes(),
            Ext4QuotaInodes {
                user: Some(3),
                group: Some(4),
                project: Some(11),
            }
        );
    }

    // ── Feature flag tests ──────────────────────────────────────────────

    #[test]
    fn compat_features_contains_and_bits() {
        let features = Ext4CompatFeatures(0x003F);
        assert!(features.contains(Ext4CompatFeatures::DIR_PREALLOC));
        assert!(features.contains(Ext4CompatFeatures::HAS_JOURNAL));
        assert!(features.contains(Ext4CompatFeatures::DIR_INDEX));
        assert!(!features.contains(Ext4CompatFeatures::SPARSE_SUPER2));
        assert_eq!(features.bits(), 0x003F);
    }

    #[test]
    fn compat_features_describe_returns_flag_names() {
        let features = Ext4CompatFeatures(0x0004 | 0x0008);
        let names = features.describe();
        assert!(names.contains(&"HAS_JOURNAL"));
        assert!(names.contains(&"EXT_ATTR"));
    }

    #[test]
    fn compat_features_unknown_bits_detected() {
        let features = Ext4CompatFeatures(0x8000_0000);
        assert_eq!(features.unknown_bits(), 0x8000_0000);
        assert!(features.describe().is_empty() || !features.describe().contains(&"HAS_JOURNAL"));
    }

    #[test]
    fn compat_features_display_formatting() {
        let features = Ext4CompatFeatures(0x0004);
        let display = format!("{features}");
        assert!(display.contains("HAS_JOURNAL"));
    }

    #[test]
    fn incompat_features_contains_known_flags() {
        let features = Ext4IncompatFeatures(0x0002 | 0x0040 | 0x0080);
        assert!(features.contains(Ext4IncompatFeatures::FILETYPE));
        assert!(features.contains(Ext4IncompatFeatures::EXTENTS));
        assert!(features.contains(Ext4IncompatFeatures::BIT64));
        assert!(!features.contains(Ext4IncompatFeatures::ENCRYPT));
    }

    #[test]
    fn ro_compat_features_contains_known_flags() {
        let features = Ext4RoCompatFeatures(0x0001 | 0x0002 | 0x0020);
        assert!(features.contains(Ext4RoCompatFeatures::SPARSE_SUPER));
        assert!(features.contains(Ext4RoCompatFeatures::LARGE_FILE));
        assert!(features.contains(Ext4RoCompatFeatures::DIR_NLINK));
        assert!(!features.contains(Ext4RoCompatFeatures::METADATA_CSUM));
    }

    // ── Feature diagnostics tests ───────────────────────────────────────

    #[test]
    fn feature_diagnostics_ok_when_no_issues() {
        let diag = FeatureDiagnostics {
            missing_required: Vec::new(),
            rejected_present: Vec::new(),
            unknown_incompat_bits: 0,
            unknown_ro_compat_bits: 0,
            incompat_display: "FILETYPE|EXTENTS".to_string(),
            ro_compat_display: "SPARSE_SUPER".to_string(),
            compat_display: "HAS_JOURNAL".to_string(),
        };
        assert!(diag.is_ok());
    }

    #[test]
    fn feature_diagnostics_not_ok_with_missing_required() {
        let diag = FeatureDiagnostics {
            missing_required: vec!["FILETYPE"],
            rejected_present: Vec::new(),
            unknown_incompat_bits: 0,
            unknown_ro_compat_bits: 0,
            incompat_display: String::new(),
            ro_compat_display: String::new(),
            compat_display: String::new(),
        };
        assert!(!diag.is_ok());
        assert_eq!(
            format!("{diag}"),
            "compat=, incompat=, ro_compat=; missing required: FILETYPE"
        );
    }

    #[test]
    fn feature_diagnostics_not_ok_with_rejected_present() {
        let diag = FeatureDiagnostics {
            missing_required: Vec::new(),
            rejected_present: vec!["ENCRYPT"],
            unknown_incompat_bits: 0,
            unknown_ro_compat_bits: 0,
            incompat_display: String::new(),
            ro_compat_display: String::new(),
            compat_display: String::new(),
        };
        assert!(!diag.is_ok());
        assert_eq!(
            format!("{diag}"),
            "compat=, incompat=, ro_compat=; rejected: ENCRYPT"
        );
    }

    #[test]
    fn feature_diagnostics_not_ok_with_unknown_incompat() {
        let diag = FeatureDiagnostics {
            missing_required: Vec::new(),
            rejected_present: Vec::new(),
            unknown_incompat_bits: 0xFF00,
            unknown_ro_compat_bits: 0,
            incompat_display: String::new(),
            ro_compat_display: String::new(),
            compat_display: String::new(),
        };
        assert!(!diag.is_ok());
        assert_eq!(
            format!("{diag}"),
            "compat=, incompat=, ro_compat=; unknown incompat: 0xFF00"
        );
    }

    #[test]
    fn feature_diagnostics_display_includes_unknown_ro_compat() {
        let diag = FeatureDiagnostics {
            missing_required: Vec::new(),
            rejected_present: Vec::new(),
            unknown_incompat_bits: 0,
            unknown_ro_compat_bits: 0xAB,
            incompat_display: "FILETYPE".to_string(),
            ro_compat_display: "SPARSE_SUPER".to_string(),
            compat_display: "HAS_JOURNAL".to_string(),
        };
        assert_eq!(
            format!("{diag}"),
            "compat=HAS_JOURNAL, incompat=FILETYPE, ro_compat=SPARSE_SUPER; \
unknown ro_compat: 0xAB"
        );
    }

    // ── Ext4FileType tests ──────────────────────────────────────────────

    #[test]
    fn ext4_file_type_from_raw_all_values() {
        assert!(matches!(Ext4FileType::from_raw(0), Ext4FileType::Unknown));
        assert!(matches!(Ext4FileType::from_raw(1), Ext4FileType::RegFile));
        assert!(matches!(Ext4FileType::from_raw(2), Ext4FileType::Dir));
        assert!(matches!(Ext4FileType::from_raw(3), Ext4FileType::Chrdev));
        assert!(matches!(Ext4FileType::from_raw(4), Ext4FileType::Blkdev));
        assert!(matches!(Ext4FileType::from_raw(5), Ext4FileType::Fifo));
        assert!(matches!(Ext4FileType::from_raw(6), Ext4FileType::Sock));
        assert!(matches!(Ext4FileType::from_raw(7), Ext4FileType::Symlink));
        assert!(matches!(Ext4FileType::from_raw(255), Ext4FileType::Unknown));
    }

    // ── Ext4DirEntry tests ──────────────────────────────────────────────

    #[test]
    fn dir_entry_actual_size_is_4_byte_aligned() {
        let entry = Ext4DirEntry {
            inode: 2,
            rec_len: 12,
            name_len: 1,
            file_type: Ext4FileType::Dir,
            name: b".".to_vec(),
        };
        assert_eq!(entry.actual_size(), 12); // 8 + 1 = 9, rounded to 12
        assert!(entry.is_dot());
        assert!(!entry.is_dotdot());
    }

    #[test]
    fn dir_entry_dotdot_detection() {
        let entry = Ext4DirEntry {
            inode: 2,
            rec_len: 12,
            name_len: 2,
            file_type: Ext4FileType::Dir,
            name: b"..".to_vec(),
        };
        assert!(entry.is_dotdot());
        assert!(!entry.is_dot());
        assert_eq!(entry.name_str(), "..");
    }

    #[test]
    fn dir_entry_name_str_converts_utf8() {
        let entry = Ext4DirEntry {
            inode: 11,
            rec_len: 24,
            name_len: 10,
            file_type: Ext4FileType::RegFile,
            name: b"README.txt".to_vec(),
        };
        assert_eq!(entry.name_str(), "README.txt");
        assert_eq!(entry.actual_size(), 20); // 8 + 10 = 18, rounded to 20
    }

    // ── Ext4Extent tests ────────────────────────────────────────────────

    #[test]
    fn ext4_extent_actual_len_normal() {
        let ext = Ext4Extent {
            logical_block: 0,
            raw_len: 100,
            physical_start: 500,
        };
        assert_eq!(ext.actual_len(), 100);
        assert!(!ext.is_unwritten());
    }

    #[test]
    fn ext4_extent_is_unwritten_high_bit() {
        let ext = Ext4Extent {
            logical_block: 0,
            raw_len: 0x8001, // > EXT_INIT_MAX_LEN (0x8000)
            physical_start: 500,
        };
        assert!(ext.is_unwritten());
        assert_eq!(ext.actual_len(), 1);
    }

    #[test]
    fn ext4_extent_boundary_max_initialized_len() {
        // raw_len = 0x8000 (32768) is the max initialized extent length
        let ext = Ext4Extent {
            logical_block: 0,
            raw_len: 0x8000,
            physical_start: 500,
        };
        // 0x8000 == EXT_INIT_MAX_LEN, so it's NOT unwritten
        assert!(!ext.is_unwritten());
        assert_eq!(ext.actual_len(), 0x8000);
    }

    // ── Extent tree parsing tests ───────────────────────────────────────

    #[test]
    fn parse_extent_tree_rejects_short_input() {
        assert!(parse_extent_tree(&[0; 8]).is_err());
    }

    #[test]
    fn parse_extent_tree_rejects_bad_magic() {
        let mut buf = [0_u8; 60];
        // Write wrong magic
        buf[0..2].copy_from_slice(&0xDEAD_u16.to_le_bytes());
        assert!(parse_extent_tree(&buf).is_err());
    }

    #[test]
    fn parse_extent_tree_parses_empty_leaf() {
        let mut buf = [0_u8; 60];
        // Magic: 0xF30A
        buf[0..2].copy_from_slice(&0xF30A_u16.to_le_bytes());
        // entries: 0
        buf[2..4].copy_from_slice(&0_u16.to_le_bytes());
        // max_entries: 4
        buf[4..6].copy_from_slice(&4_u16.to_le_bytes());
        // depth: 0 (leaf)
        buf[6..8].copy_from_slice(&0_u16.to_le_bytes());

        let (header, tree) = parse_extent_tree(&buf).expect("valid empty leaf");
        assert_eq!(header.magic, 0xF30A);
        assert_eq!(header.entries, 0);
        assert_eq!(header.depth, 0);
        assert!(matches!(tree, ExtentTree::Leaf(ref exts) if exts.is_empty()));
    }

    #[test]
    fn parse_extent_tree_parses_single_leaf_entry() {
        let mut buf = [0_u8; 60];
        // Magic
        buf[0..2].copy_from_slice(&0xF30A_u16.to_le_bytes());
        // entries: 1
        buf[2..4].copy_from_slice(&1_u16.to_le_bytes());
        // max_entries: 4
        buf[4..6].copy_from_slice(&4_u16.to_le_bytes());
        // depth: 0
        buf[6..8].copy_from_slice(&0_u16.to_le_bytes());
        // Leaf entry at offset 12:
        // logical_block: 0
        buf[12..16].copy_from_slice(&0_u32.to_le_bytes());
        // raw_len: 10
        buf[16..18].copy_from_slice(&10_u16.to_le_bytes());
        // physical_start_hi: 0
        buf[18..20].copy_from_slice(&0_u16.to_le_bytes());
        // physical_start_lo: 42
        buf[20..24].copy_from_slice(&42_u32.to_le_bytes());

        let (header, tree) = parse_extent_tree(&buf).expect("valid leaf with 1 extent");
        assert_eq!(header.entries, 1);
        assert!(matches!(tree, ExtentTree::Leaf(_)), "expected leaf tree");
        let ExtentTree::Leaf(extents) = tree else {
            return;
        };
        assert_eq!(extents.len(), 1);
        assert_eq!(extents[0].logical_block, 0);
        assert_eq!(extents[0].actual_len(), 10);
        assert_eq!(extents[0].physical_start, 42);
    }

    #[test]
    fn parse_extent_tree_rejects_entries_exceeding_max() {
        let mut buf = [0_u8; 60];
        buf[0..2].copy_from_slice(&0xF30A_u16.to_le_bytes());
        // entries: 5, max_entries: 4  → invalid
        buf[2..4].copy_from_slice(&5_u16.to_le_bytes());
        buf[4..6].copy_from_slice(&4_u16.to_le_bytes());
        buf[6..8].copy_from_slice(&0_u16.to_le_bytes());
        assert!(parse_extent_tree(&buf).is_err());
    }

    // ── Superblock parsing tests ────────────────────────────────────────

    #[test]
    fn superblock_parser_rejects_too_short_by_one() {
        let short = vec![0_u8; 1023];
        assert!(Ext4Superblock::parse_superblock_region(&short).is_err());
    }

    // ── Inode parsing tests ─────────────────────────────────────────────

    #[test]
    fn inode_parser_rejects_short_input() {
        assert!(Ext4Inode::parse_from_bytes(&[0; 64]).is_err());
    }

    #[test]
    fn inode_parser_accepts_minimum_128_bytes() {
        let buf = vec![0_u8; 128];
        let inode = Ext4Inode::parse_from_bytes(&buf).expect("128 bytes is minimum");
        assert_eq!(inode.mode, 0);
        assert_eq!(inode.uid, 0);
        assert_eq!(inode.size, 0);
        assert_eq!(inode.links_count, 0);
    }

    #[test]
    fn inode_parser_reads_basic_fields() {
        let mut buf = vec![0_u8; 256];
        // mode: regular file (0x8000) + rwx (0o755 = 0x1ED)
        let mode: u16 = 0x81ED; // S_IFREG | 0o755
        buf[0..2].copy_from_slice(&mode.to_le_bytes());
        // uid_lo: 1000
        buf[2..4].copy_from_slice(&1000_u16.to_le_bytes());
        // size_lo at 0x04: 4096
        buf[4..8].copy_from_slice(&4096_u32.to_le_bytes());
        // links_count at 0x1A: 1
        buf[0x1A..0x1C].copy_from_slice(&1_u16.to_le_bytes());

        let inode = Ext4Inode::parse_from_bytes(&buf).expect("valid inode");
        assert_eq!(inode.mode, mode);
        assert_eq!(inode.links_count, 1);
    }

    // ── Ext4Xattr tests ────────────────────────────────────────────────

    #[test]
    fn xattr_full_name_user_namespace() {
        let xattr = Ext4Xattr {
            name_index: 1, // EXT4_XATTR_INDEX_USER
            name: b"myattr".to_vec(),
            value: b"myval".to_vec(),
        };
        assert_eq!(xattr.full_name(), "user.myattr");
    }

    #[test]
    fn xattr_full_name_trusted_namespace() {
        let xattr = Ext4Xattr {
            name_index: 4, // EXT4_XATTR_INDEX_TRUSTED
            name: b"overlay.opaque".to_vec(),
            value: b"y".to_vec(),
        };
        assert_eq!(xattr.full_name(), "trusted.overlay.opaque");
    }

    #[test]
    fn xattr_full_name_security_namespace() {
        let xattr = Ext4Xattr {
            name_index: 6, // EXT4_XATTR_INDEX_SECURITY
            name: b"selinux".to_vec(),
            value: Vec::new(),
        };
        assert_eq!(xattr.full_name(), "security.selinux");
    }

    #[test]
    fn xattr_full_name_unknown_namespace() {
        let xattr = Ext4Xattr {
            name_index: 99,
            name: b"test".to_vec(),
            value: Vec::new(),
        };
        assert!(xattr.full_name().starts_with("unknown."));
    }

    // ── dx_hash tests ───────────────────────────────────────────────────

    #[test]
    fn dx_hash_is_deterministic() {
        let seed = [0_u32; 4];
        let (h1, m1) = dx_hash(1, b"hello", &seed);
        let (h2, m2) = dx_hash(1, b"hello", &seed);
        assert_eq!(h1, h2);
        assert_eq!(m1, m2);
    }

    #[test]
    fn dx_hash_different_names_produce_different_hashes() {
        let seed = [0x1234_u32, 0x5678, 0x9ABC, 0xDEF0];
        let (h1, _) = dx_hash(1, b"hello", &seed);
        let (h2, _) = dx_hash(1, b"world", &seed);
        assert_ne!(h1, h2);
    }

    #[test]
    fn dx_hash_tea_variant_produces_output() {
        let seed = [1_u32, 2, 3, 4];
        let (h, m) = dx_hash(3, b"testfile.txt", &seed); // DX_HASH_TEA = 3
        // Hash should produce non-zero output for non-empty name
        assert!(h != 0 || m != 0);
    }

    #[test]
    fn dx_hash_legacy_variant_produces_output() {
        let seed = [0_u32; 4];
        let (h, m) = dx_hash(0, b"a", &seed); // DX_HASH_LEGACY = 0
        assert!(h != 0 || m != 0);
    }

    #[test]
    fn dx_hash_major_has_low_bit_cleared_for_legacy() {
        let seed = [0_u32; 4];
        let (h, _) = dx_hash(0, b"test", &seed);
        assert_eq!(h & 1, 0, "legacy hash major should have low bit cleared");
    }

    // ── Checksum tests ──────────────────────────────────────────────────

    #[test]
    fn ext4_chksum_seed_zero_is_deterministic() {
        let a = ext4_chksum(0, b"ext4 test data");
        let b = ext4_chksum(0, b"ext4 test data");
        assert_eq!(a, b);
    }

    #[test]
    fn ext4_chksum_different_seeds_produce_different_results() {
        let a = ext4_chksum(0, b"data");
        let b = ext4_chksum(0xFFFF_FFFF, b"data");
        assert_ne!(a, b);
    }

    #[test]
    fn ext4_chksum_empty_data_returns_seed_dependent_value() {
        let a = ext4_chksum(0, b"");
        let b = ext4_chksum(1, b"");
        assert_ne!(a, b);
    }

    // ── parse_dir_block edge cases ──────────────────────────────────────

    #[test]
    fn parse_dir_block_with_single_dot_entry() {
        let mut block = vec![0_u8; 4096];
        // inode: 2
        block[0..4].copy_from_slice(&2_u32.to_le_bytes());
        // rec_len: 4096 (consumes entire block)
        block[4..6].copy_from_slice(&4096_u16.to_le_bytes());
        // name_len: 1
        block[6] = 1;
        // file_type: Dir(2)
        block[7] = 2;
        // name: "."
        block[8] = b'.';

        let (entries, _tail) = parse_dir_block(&block, 4096).expect("valid single-entry block");
        assert_eq!(entries.len(), 1);
        assert!(entries[0].is_dot());
        assert_eq!(entries[0].inode, 2);
    }

    #[test]
    fn lookup_in_dir_block_finds_name() {
        let mut block = vec![0_u8; 4096];
        // First entry: inode=2, rec_len=12, name="."
        block[0..4].copy_from_slice(&2_u32.to_le_bytes());
        block[4..6].copy_from_slice(&12_u16.to_le_bytes());
        block[6] = 1;
        block[7] = 2; // Dir
        block[8] = b'.';

        // Second entry at offset 12: inode=5, rec_len=4084, name="hello"
        block[12..16].copy_from_slice(&5_u32.to_le_bytes());
        block[16..18].copy_from_slice(&(4096_u16 - 12).to_le_bytes());
        block[18] = 5;
        block[19] = 1; // RegFile
        block[20..25].copy_from_slice(b"hello");

        let found = lookup_in_dir_block(&block, 4096, b"hello").unwrap();
        assert!(found.is_some());
        let entry = found.unwrap();
        assert_eq!(entry.inode, 5);
        assert_eq!(entry.name_str(), "hello");
    }

    #[test]
    fn lookup_in_dir_block_returns_none_for_missing_name() {
        let mut block = vec![0_u8; 4096];
        block[0..4].copy_from_slice(&2_u32.to_le_bytes());
        block[4..6].copy_from_slice(&4096_u16.to_le_bytes());
        block[6] = 1;
        block[7] = 2;
        block[8] = b'.';

        assert!(
            lookup_in_dir_block(&block, 4096, b"nonexistent")
                .unwrap()
                .is_none()
        );
    }

    // ── Ext4GroupDesc tests ─────────────────────────────────────────────

    #[test]
    fn group_desc_struct_is_constructable() {
        let gd = Ext4GroupDesc {
            block_bitmap: 100,
            inode_bitmap: 101,
            inode_table: 102,
            free_blocks_count: 500,
            free_inodes_count: 200,
            used_dirs_count: 10,
            flags: 0,
            itable_unused: 0,
            checksum: 0,
            block_bitmap_csum: 0,
            inode_bitmap_csum: 0,
        };
        assert_eq!(gd.block_bitmap, 100);
        assert_eq!(gd.free_blocks_count, 500);
    }

    // ── InodeLocation tests ─────────────────────────────────────────────

    #[test]
    fn inode_location_struct_is_constructable() {
        let loc = InodeLocation {
            group: ffs_types::GroupNumber(0),
            index: 5,
            offset_in_table: 1280,
        };
        assert_eq!(loc.group, ffs_types::GroupNumber(0));
        assert_eq!(loc.offset_in_table, 1280);
    }

    // ── parse_ibody_xattrs / parse_xattr_block error paths ─────────────

    #[test]
    fn parse_ibody_xattrs_empty_xattr_ibody_returns_empty() {
        let inode = Ext4Inode {
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            links_count: 0,
            blocks: 0,
            flags: 0,

            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 0,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        };
        let result = parse_ibody_xattrs(&inode);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), [] as [ffs_ondisk::Ext4Xattr; 0]);
    }

    #[test]
    fn parse_xattr_block_rejects_empty_block() {
        let result = parse_xattr_block(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_xattr_block_rejects_wrong_magic() {
        let mut block = vec![0_u8; 4096];
        // Write wrong magic at offset 0
        block[0..4].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());
        let result = parse_xattr_block(&block);
        assert!(result.is_err());
    }

    // ── iter_dir_block tests ────────────────────────────────────────────

    #[test]
    fn iter_dir_block_zero_block_yields_nothing() {
        let block = vec![0_u8; 4096];
        let mut iter = iter_dir_block(&block, 4096);
        assert!(iter.next().is_none());
    }

    // ── Ext4DirEntryTail tests ──────────────────────────────────────────

    #[test]
    fn dir_entry_tail_struct_is_constructable() {
        let tail = Ext4DirEntryTail { checksum: 0xABCD };
        assert_eq!(tail.checksum, 0xABCD);
    }

    // ── Ext4ExtentHeader and Index tests ────────────────────────────────

    #[test]
    fn extent_header_and_index_constructable() {
        let header = Ext4ExtentHeader {
            magic: 0xF30A,
            entries: 2,
            max_entries: 4,
            depth: 1,
            generation: 0,
        };
        assert_eq!(header.magic, 0xF30A);

        let idx = Ext4ExtentIndex {
            logical_block: 0,
            leaf_block: 1000,
        };
        assert_eq!(idx.leaf_block, 1000);
    }

    // ── Test helpers ───────────────────────────────────────────────────

    /// Build a minimal Ext4Inode with the given mode and flags.
    fn make_inode(mode: u16, flags: u32) -> Ext4Inode {
        Ext4Inode {
            mode,
            uid: 1000,
            gid: 1000,
            size: 0,
            links_count: 1,
            blocks: 0,
            flags,
            version: 0,
            generation: 0,
            file_acl: 0,
            atime: 0,
            ctime: 0,
            mtime: 0,
            dtime: 0,
            atime_extra: 0,
            ctime_extra: 0,
            mtime_extra: 0,
            crtime: 0,
            crtime_extra: 0,
            extra_isize: 0,
            checksum: 0,

            version_hi: 0,
            projid: 0,
            extent_bytes: vec![0; 60].into(),
            xattr_ibody: Vec::new(),
            number: 0,
        }
    }

    // ── Ext4IncompatFeatures additional tests ──────────────────────────

    #[test]
    fn incompat_features_describe_returns_flag_names() {
        let features = Ext4IncompatFeatures(0x0002 | 0x0040);
        let names = features.describe();
        assert!(names.contains(&"FILETYPE"));
        assert!(names.contains(&"EXTENTS"));
    }

    #[test]
    fn incompat_features_unknown_bits_detected() {
        let features = Ext4IncompatFeatures(0x8000_0000);
        assert_eq!(features.unknown_bits(), 0x8000_0000);
    }

    #[test]
    fn incompat_features_describe_missing_required_v1() {
        // No FILETYPE set (EXTENTS is optional)
        let features = Ext4IncompatFeatures(0);
        let missing = features.describe_missing_required_v1();
        assert!(missing.contains(&"FILETYPE"));
        assert!(!missing.contains(&"EXTENTS"));
    }

    #[test]
    fn incompat_features_describe_missing_required_v1_partial() {
        // FILETYPE set, nothing missing
        let features = Ext4IncompatFeatures(0x0002);
        let missing = features.describe_missing_required_v1();
        assert!(!missing.contains(&"FILETYPE"));
        assert!(!missing.contains(&"EXTENTS"));
    }

    #[test]
    fn incompat_features_describe_rejected_v1_all_allowed() {
        // All known features are now allowed — REJECTED_V1 is empty.
        let features = Ext4IncompatFeatures(
            Ext4IncompatFeatures::ENCRYPT.0
                | Ext4IncompatFeatures::INLINE_DATA.0
                | Ext4IncompatFeatures::CASEFOLD.0,
        );
        let rejected = features.describe_rejected_v1();
        assert_eq!(rejected, [] as [&str; 0]);
    }

    #[test]
    fn incompat_features_describe_rejected_v1_none_present() {
        let features = Ext4IncompatFeatures(0x0002 | 0x0040); // FILETYPE + EXTENTS only
        let rejected = features.describe_rejected_v1();
        assert_eq!(rejected, [] as [&str; 0]);
    }

    #[test]
    fn incompat_features_display_formatting() {
        let features = Ext4IncompatFeatures(0x0002 | 0x0040);
        let display = format!("{features}");
        assert!(display.contains("FILETYPE"));
        assert!(display.contains("EXTENTS"));
    }

    // ── Ext4RoCompatFeatures additional tests ──────────────────────────

    #[test]
    fn ro_compat_features_describe_returns_flag_names() {
        let features = Ext4RoCompatFeatures(0x0001 | 0x0400);
        let names = features.describe();
        assert!(names.contains(&"SPARSE_SUPER"));
        assert!(names.contains(&"METADATA_CSUM"));
    }

    #[test]
    fn ro_compat_features_unknown_bits_detected() {
        let features = Ext4RoCompatFeatures(0x4000_0000);
        assert_eq!(features.unknown_bits(), 0x4000_0000);
    }

    #[test]
    fn ro_compat_features_display_formatting() {
        let features = Ext4RoCompatFeatures(0x0001);
        let display = format!("{features}");
        assert!(display.contains("SPARSE_SUPER"));
    }

    // ── Ext4Inode file type detection tests ────────────────────────────

    #[test]
    fn inode_is_regular_file() {
        let inode = make_inode(ffs_types::S_IFREG | 0o644, 0);
        assert!(inode.is_regular());
        assert!(!inode.is_dir());
        assert!(!inode.is_symlink());
        assert!(!inode.is_chrdev());
        assert!(!inode.is_blkdev());
        assert!(!inode.is_fifo());
        assert!(!inode.is_socket());
        assert_eq!(inode.file_type_mode(), ffs_types::S_IFREG);
    }

    #[test]
    fn inode_is_directory() {
        let inode = make_inode(ffs_types::S_IFDIR | 0o755, 0);
        assert!(inode.is_dir());
        assert!(!inode.is_regular());
        assert_eq!(inode.file_type_mode(), ffs_types::S_IFDIR);
    }

    #[test]
    fn inode_is_symlink() {
        let inode = make_inode(ffs_types::S_IFLNK | 0o777, 0);
        assert!(inode.is_symlink());
        assert!(!inode.is_regular());
        assert_eq!(inode.file_type_mode(), ffs_types::S_IFLNK);
    }

    #[test]
    fn inode_is_chrdev() {
        let inode = make_inode(ffs_types::S_IFCHR | 0o660, 0);
        assert!(inode.is_chrdev());
        assert!(!inode.is_blkdev());
    }

    #[test]
    fn inode_is_blkdev() {
        let inode = make_inode(ffs_types::S_IFBLK | 0o660, 0);
        assert!(inode.is_blkdev());
        assert!(!inode.is_chrdev());
    }

    #[test]
    fn inode_is_fifo() {
        let inode = make_inode(ffs_types::S_IFIFO | 0o644, 0);
        assert!(inode.is_fifo());
        assert!(!inode.is_socket());
    }

    #[test]
    fn inode_is_socket() {
        let inode = make_inode(ffs_types::S_IFSOCK | 0o755, 0);
        assert!(inode.is_socket());
        assert!(!inode.is_fifo());
    }

    // ── Ext4Inode permission bits ──────────────────────────────────────

    #[test]
    fn inode_permission_bits_0o755() {
        let inode = make_inode(ffs_types::S_IFREG | 0o755, 0);
        assert_eq!(inode.permission_bits(), 0o755);
    }

    #[test]
    fn inode_permission_bits_0o644() {
        let inode = make_inode(ffs_types::S_IFREG | 0o644, 0);
        assert_eq!(inode.permission_bits(), 0o644);
    }

    #[test]
    fn inode_permission_bits_setuid() {
        // 0o4755 = setuid + rwxr-xr-x
        let inode = make_inode(ffs_types::S_IFREG | 0o4755, 0);
        assert_eq!(inode.permission_bits(), 0o4755);
    }

    // ── Ext4Inode flag tests ───────────────────────────────────────────

    #[test]
    fn inode_is_huge_file() {
        let inode = make_inode(ffs_types::S_IFREG, ffs_types::EXT4_HUGE_FILE_FL);
        assert!(inode.is_huge_file());
    }

    #[test]
    fn inode_not_huge_file() {
        let inode = make_inode(ffs_types::S_IFREG, 0);
        assert!(!inode.is_huge_file());
    }

    #[test]
    fn inode_uses_extents() {
        let inode = make_inode(ffs_types::S_IFREG, ffs_types::EXT4_EXTENTS_FL);
        assert!(inode.uses_extents());
    }

    #[test]
    fn inode_not_uses_extents() {
        let inode = make_inode(ffs_types::S_IFREG, 0);
        assert!(!inode.uses_extents());
    }

    #[test]
    fn inode_has_htree_index() {
        let inode = make_inode(ffs_types::S_IFDIR, ffs_types::EXT4_INDEX_FL);
        assert!(inode.has_htree_index());
    }

    #[test]
    fn inode_not_has_htree_index() {
        let inode = make_inode(ffs_types::S_IFDIR, 0);
        assert!(!inode.has_htree_index());
    }

    // ── Ext4Inode device number tests ──────────────────────────────────

    #[test]
    fn inode_device_number_for_non_device_is_zero() {
        let inode = make_inode(ffs_types::S_IFREG, 0);
        assert_eq!(inode.device_number(), 0);
        assert_eq!(inode.device_major(), 0);
        assert_eq!(inode.device_minor(), 0);
    }

    #[test]
    fn inode_device_number_old_format() {
        // Old format: block0 = 0x0801 => major=8, minor=1 (sda1)
        let mut inode = make_inode(ffs_types::S_IFBLK | 0o660, 0);
        inode.extent_bytes[0..4].copy_from_slice(&0x0801_u32.to_le_bytes());
        assert_eq!(inode.device_number(), 0x0801);
        assert_eq!(inode.device_major(), 8);
        assert_eq!(inode.device_minor(), 1);
    }

    #[test]
    fn inode_device_number_new_format() {
        // New format: block0 = 0, block1 = encoded device
        let mut inode = make_inode(ffs_types::S_IFCHR | 0o666, 0);
        inode.extent_bytes[0..4].copy_from_slice(&0_u32.to_le_bytes());
        // new_encode_dev(major=136, minor=0) = (136 << 8) | 0 = 0x8800
        inode.extent_bytes[4..8].copy_from_slice(&0x8800_u32.to_le_bytes());
        assert_eq!(inode.device_number(), 0x8800);
        assert_eq!(inode.device_major(), 136);
    }

    // ── Ext4Inode fast symlink tests ───────────────────────────────────

    #[test]
    fn inode_is_fast_symlink_short_target() {
        let mut inode = make_inode(ffs_types::S_IFLNK | 0o777, 0);
        let target = b"/bin/sh";
        inode.size = target.len() as u64;
        inode.extent_bytes[..target.len()].copy_from_slice(target);
        assert!(inode.is_fast_symlink());
        assert_eq!(inode.fast_symlink_target(), Some(target.as_slice()));
    }

    #[test]
    fn inode_is_not_fast_symlink_with_extents() {
        let mut inode = make_inode(ffs_types::S_IFLNK | 0o777, ffs_types::EXT4_EXTENTS_FL);
        inode.size = 10;
        assert!(!inode.is_fast_symlink());
        assert!(inode.fast_symlink_target().is_none());
    }

    #[test]
    fn inode_is_not_fast_symlink_too_long() {
        let mut inode = make_inode(ffs_types::S_IFLNK | 0o777, 0);
        inode.size = 61; // > 60 max
        assert!(!inode.is_fast_symlink());
    }

    #[test]
    fn inode_fast_symlink_target_none_for_regular() {
        let inode = make_inode(ffs_types::S_IFREG | 0o644, 0);
        assert!(inode.fast_symlink_target().is_none());
    }

    // ── Ext4Inode timestamp tests ──────────────────────────────────────

    #[test]
    fn inode_extra_nsec_extracts_nanoseconds() {
        // extra field: bits [31:2] = nanoseconds, bits [1:0] = epoch
        let extra = 0x3B9A_CA04; // nsec = 0x3B9A_CA04 >> 2 = 0x0EE6_B281 = 250000001
        assert_eq!(Ext4Inode::extra_nsec(extra), extra >> 2);
    }

    #[test]
    fn inode_extra_epoch_extracts_low_bits() {
        assert_eq!(Ext4Inode::extra_epoch(0x00), 0);
        assert_eq!(Ext4Inode::extra_epoch(0x01), 1);
        assert_eq!(Ext4Inode::extra_epoch(0x02), 2);
        assert_eq!(Ext4Inode::extra_epoch(0x03), 3);
        assert_eq!(Ext4Inode::extra_epoch(0xFF), 3);
    }

    #[test]
    fn inode_atime_full_basic() {
        let mut inode = make_inode(ffs_types::S_IFREG, 0);
        inode.atime = 1_700_000_000; // ~2023
        inode.atime_extra = 0;
        let (secs, nsec) = inode.atime_full();
        assert_eq!(secs, 1_700_000_000);
        assert_eq!(nsec, 0);
    }

    #[test]
    fn inode_mtime_full_with_nanoseconds() {
        let mut inode = make_inode(ffs_types::S_IFREG, 0);
        inode.mtime = 1_700_000_000;
        // extra = (500_000_000 << 2) | 0 = 0x7735_9400
        inode.mtime_extra = 500_000_000 << 2;
        let (secs, nsec) = inode.mtime_full();
        assert_eq!(secs, 1_700_000_000);
        assert_eq!(nsec, 500_000_000);
    }

    #[test]
    fn inode_ctime_full_with_epoch_extension() {
        let mut inode = make_inode(ffs_types::S_IFREG, 0);
        inode.ctime = 0; // base timestamp = 0
        inode.ctime_extra = 1; // epoch = 1 -> adds 2^32
        let (secs, _nsec) = inode.ctime_full();
        assert_eq!(secs, 1_i64 << 32);
    }

    #[test]
    fn inode_crtime_full_delegates() {
        let mut inode = make_inode(ffs_types::S_IFREG, 0);
        inode.crtime = 42;
        inode.crtime_extra = 0;
        let (secs, nsec) = inode.crtime_full();
        assert_eq!(secs, 42);
        assert_eq!(nsec, 0);
    }

    #[test]
    fn inode_to_system_time_positive() {
        let st = Ext4Inode::to_system_time(1_700_000_000, 0);
        assert!(st.is_some());
        let st = st.unwrap();
        let dur = st
            .duration_since(std::time::UNIX_EPOCH)
            .expect("after epoch");
        assert_eq!(dur.as_secs(), 1_700_000_000);
    }

    #[test]
    fn inode_to_system_time_zero() {
        let st = Ext4Inode::to_system_time(0, 0);
        assert!(st.is_some());
        assert_eq!(st.unwrap(), std::time::UNIX_EPOCH);
    }

    #[test]
    fn inode_to_system_time_negative() {
        // Pre-1970 timestamp
        let st = Ext4Inode::to_system_time(-86400, 0);
        assert!(st.is_some());
        let st = st.unwrap();
        assert!(st < std::time::UNIX_EPOCH);
    }

    #[test]
    fn inode_atime_system_time_returns_epoch_for_zero() {
        let inode = make_inode(ffs_types::S_IFREG, 0);
        let st = inode.atime_system_time();
        assert_eq!(st, std::time::UNIX_EPOCH);
    }

    #[test]
    fn inode_mtime_system_time_returns_valid() {
        let mut inode = make_inode(ffs_types::S_IFREG, 0);
        inode.mtime = 1_700_000_000;
        let st = inode.mtime_system_time();
        let dur = st.duration_since(std::time::UNIX_EPOCH).unwrap();
        assert_eq!(dur.as_secs(), 1_700_000_000);
    }

    #[test]
    fn inode_ctime_system_time_returns_valid() {
        let mut inode = make_inode(ffs_types::S_IFREG, 0);
        inode.ctime = 1_000_000;
        let st = inode.ctime_system_time();
        let dur = st.duration_since(std::time::UNIX_EPOCH).unwrap();
        assert_eq!(dur.as_secs(), 1_000_000);
    }

    #[test]
    fn inode_crtime_system_time_returns_valid() {
        let mut inode = make_inode(ffs_types::S_IFREG, 0);
        inode.crtime = 500_000;
        let st = inode.crtime_system_time();
        let dur = st.duration_since(std::time::UNIX_EPOCH).unwrap();
        assert_eq!(dur.as_secs(), 500_000);
    }

    // ── Ext4GroupDesc parse/write round-trip tests ──────────────────────

    #[test]
    fn group_desc_parse_from_bytes_32bit() {
        let mut buf = vec![0_u8; 32];
        // block_bitmap_lo at 0x00
        buf[0..4].copy_from_slice(&100_u32.to_le_bytes());
        // inode_bitmap_lo at 0x04
        buf[4..8].copy_from_slice(&200_u32.to_le_bytes());
        // inode_table_lo at 0x08
        buf[8..12].copy_from_slice(&300_u32.to_le_bytes());
        // free_blocks_lo at 0x0C
        buf[0x0C..0x0E].copy_from_slice(&500_u16.to_le_bytes());
        // free_inodes_lo at 0x0E
        buf[0x0E..0x10].copy_from_slice(&200_u16.to_le_bytes());
        // used_dirs_lo at 0x10
        buf[0x10..0x12].copy_from_slice(&10_u16.to_le_bytes());
        // flags at 0x12
        buf[0x12..0x14].copy_from_slice(&0x0004_u16.to_le_bytes());
        // itable_unused at 0x1C
        buf[0x1C..0x1E].copy_from_slice(&50_u16.to_le_bytes());
        // checksum at 0x1E
        buf[0x1E..0x20].copy_from_slice(&0xABCD_u16.to_le_bytes());

        let gd = Ext4GroupDesc::parse_from_bytes(&buf, 32).expect("valid 32-byte desc");
        assert_eq!(gd.block_bitmap, 100);
        assert_eq!(gd.inode_bitmap, 200);
        assert_eq!(gd.inode_table, 300);
        assert_eq!(gd.free_blocks_count, 500);
        assert_eq!(gd.free_inodes_count, 200);
        assert_eq!(gd.used_dirs_count, 10);
        assert_eq!(gd.flags, 0x0004);
        assert_eq!(gd.itable_unused, 50);
        assert_eq!(gd.checksum, 0xABCD);
    }

    #[test]
    fn group_desc_parse_rejects_too_small_desc_size() {
        let buf = vec![0_u8; 32];
        assert!(Ext4GroupDesc::parse_from_bytes(&buf, 16).is_err());
    }

    #[test]
    fn group_desc_parse_rejects_insufficient_data() {
        let buf = vec![0_u8; 20]; // less than desc_size=32
        assert!(Ext4GroupDesc::parse_from_bytes(&buf, 32).is_err());
    }

    #[test]
    fn group_desc_write_to_bytes_round_trip_32() {
        let gd = Ext4GroupDesc {
            block_bitmap: 100,
            inode_bitmap: 200,
            inode_table: 300,
            free_blocks_count: 500,
            free_inodes_count: 200,
            used_dirs_count: 10,
            flags: 0x0004,
            itable_unused: 50,
            checksum: 0xABCD,
            block_bitmap_csum: 0,
            inode_bitmap_csum: 0,
        };

        let mut buf = vec![0_u8; 32];
        gd.write_to_bytes(&mut buf, 32).expect("write succeeds");

        let gd2 = Ext4GroupDesc::parse_from_bytes(&buf, 32).expect("round-trip parse");
        assert_eq!(gd2.block_bitmap, 100);
        assert_eq!(gd2.inode_bitmap, 200);
        assert_eq!(gd2.inode_table, 300);
        assert_eq!(gd2.free_blocks_count, 500);
        assert_eq!(gd2.free_inodes_count, 200);
        assert_eq!(gd2.used_dirs_count, 10);
        assert_eq!(gd2.flags, 0x0004);
        assert_eq!(gd2.checksum, 0xABCD);
    }

    #[test]
    fn group_desc_write_to_bytes_64bit_round_trip() {
        let gd = Ext4GroupDesc {
            block_bitmap: 0x1_0000_0064, // high bits set
            inode_bitmap: 0x2_0000_00C8,
            inode_table: 0x3_0000_012C,
            free_blocks_count: 0x0002_01F4, // > 16-bit
            free_inodes_count: 0x0001_00C8,
            used_dirs_count: 0x0001_000A,
            flags: 0,
            itable_unused: 0x0001_0032,
            checksum: 0x1234,
            block_bitmap_csum: 0,
            inode_bitmap_csum: 0,
        };

        let mut buf = vec![0_u8; 64];
        gd.write_to_bytes(&mut buf, 64).expect("write succeeds");

        let gd2 = Ext4GroupDesc::parse_from_bytes(&buf, 64).expect("round-trip parse");
        assert_eq!(gd2.block_bitmap, gd.block_bitmap);
        assert_eq!(gd2.inode_bitmap, gd.inode_bitmap);
        assert_eq!(gd2.inode_table, gd.inode_table);
        assert_eq!(gd2.free_blocks_count, gd.free_blocks_count);
        assert_eq!(gd2.free_inodes_count, gd.free_inodes_count);
    }

    #[test]
    fn group_desc_write_rejects_short_buffer() {
        let gd = Ext4GroupDesc {
            block_bitmap: 0,
            inode_bitmap: 0,
            inode_table: 0,
            free_blocks_count: 0,
            free_inodes_count: 0,
            used_dirs_count: 0,
            flags: 0,
            itable_unused: 0,
            checksum: 0,
            block_bitmap_csum: 0,
            inode_bitmap_csum: 0,
        };
        let mut buf = vec![0_u8; 20];
        assert!(gd.write_to_bytes(&mut buf, 32).is_err());
    }

    // ── Group descriptor checksum stamp + verify round-trip ────────────

    #[test]
    fn stamp_and_verify_group_desc_checksum_round_trip() {
        let gd = Ext4GroupDesc {
            block_bitmap: 100,
            inode_bitmap: 200,
            inode_table: 300,
            free_blocks_count: 500,
            free_inodes_count: 200,
            used_dirs_count: 10,
            flags: 0,
            itable_unused: 0,
            checksum: 0,
            block_bitmap_csum: 0,
            inode_bitmap_csum: 0,
        };

        let mut buf = vec![0_u8; 32];
        gd.write_to_bytes(&mut buf, 32).unwrap();

        let uuid = [1_u8, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let csum_seed = ext4_chksum(0xFFFF_FFFF, &uuid);
        stamp_group_desc_checksum(
            &mut buf,
            &uuid,
            csum_seed,
            0,
            32,
            Ext4GroupDescChecksumKind::MetadataCsum,
        );

        // verify should pass
        assert!(
            verify_group_desc_checksum(
                &buf,
                &uuid,
                csum_seed,
                0,
                32,
                Ext4GroupDescChecksumKind::MetadataCsum,
            )
            .is_ok()
        );
    }

    #[test]
    fn verify_group_desc_checksum_fails_on_corruption() {
        let mut buf = vec![0_u8; 32];
        let uuid = [0_u8; 16];
        let csum_seed = 0x1234_5678;
        stamp_group_desc_checksum(
            &mut buf,
            &uuid,
            csum_seed,
            0,
            32,
            Ext4GroupDescChecksumKind::MetadataCsum,
        );

        // Corrupt a byte
        buf[0] ^= 0xFF;

        assert!(
            verify_group_desc_checksum(
                &buf,
                &uuid,
                csum_seed,
                0,
                32,
                Ext4GroupDescChecksumKind::MetadataCsum,
            )
            .is_err()
        );
    }

    // ── Bitmap verification tests ──────────────────────────────────────

    #[test]
    fn verify_inode_bitmap_free_count_all_free() {
        // 32 inodes, all zeros = 32 free
        let bitmap = vec![0_u8; 4];
        assert!(verify_inode_bitmap_free_count(&bitmap, 32, 32).is_ok());
    }

    #[test]
    fn verify_inode_bitmap_free_count_some_used() {
        // 16 inodes, first byte = 0xFF (8 used), second byte = 0x00 (8 free)
        let bitmap = vec![0xFF, 0x00];
        assert!(verify_inode_bitmap_free_count(&bitmap, 16, 8).is_ok());
    }

    #[test]
    fn verify_inode_bitmap_free_count_mismatch() {
        let bitmap = vec![0xFF, 0x00]; // 8 free out of 16
        assert!(verify_inode_bitmap_free_count(&bitmap, 16, 10).is_err());
    }

    #[test]
    fn verify_block_bitmap_free_count_all_used() {
        // 8 blocks, all 1s = 0 free
        let bitmap = vec![0xFF];
        assert!(verify_block_bitmap_free_count(&bitmap, 8, 0).is_ok());
    }

    #[test]
    fn verify_block_bitmap_free_count_partial_byte() {
        // 12 blocks: first byte = 0x0F (4 used, 4 free), second byte lower 4 bits = 0x0 (4 free)
        let bitmap = vec![0x0F, 0x00];
        assert!(verify_block_bitmap_free_count(&bitmap, 12, 8).is_ok());
    }

    // ── parse_dx_root tests ────────────────────────────────────────────

    #[test]
    fn parse_dx_root_rejects_short_block() {
        let block = vec![0_u8; 0x27]; // < 0x28
        assert!(parse_dx_root(&block).is_err());
    }

    #[test]
    fn parse_dx_root_rejects_wrong_info_length() {
        let mut block = vec![0_u8; 256];
        block[0x1C] = 1; // hash_version
        block[0x1D] = 7; // info_length != 8
        block[0x1E] = 0; // indirect_levels
        assert!(parse_dx_root(&block).is_err());
    }

    #[test]
    fn parse_dx_root_rejects_excessive_indirect_levels() {
        let mut block = vec![0_u8; 256];
        block[0x1C] = 1; // hash_version
        block[0x1D] = 8; // info_length = 8
        block[0x1E] = 3; // indirect_levels > 2
        assert!(parse_dx_root(&block).is_err());
    }

    #[test]
    fn parse_dx_root_accepts_level_three_with_large_dir() {
        let mut block = vec![0_u8; 256];
        block[0x1C] = 1; // hash_version
        block[0x1D] = 8; // info_length = 8
        block[0x1E] = 3; // level 3 allowed with LARGEDIR
        block[0x20..0x22].copy_from_slice(&10_u16.to_le_bytes());
        block[0x22..0x24].copy_from_slice(&1_u16.to_le_bytes());
        block[0x24..0x28].copy_from_slice(&5_u32.to_le_bytes());

        let root = parse_dx_root_with_large_dir(&block, true).expect("valid dx root");
        assert_eq!(root.indirect_levels, 3);
        assert_eq!(root.entries.len(), 1);
        assert_eq!(root.entries[0].block, 5);
    }

    fn write_dir_entry_test(
        image: &mut [u8],
        offset: usize,
        inode: u32,
        file_type: u8,
        name: &[u8],
        rec_len: u16,
    ) {
        image[offset..offset + 4].copy_from_slice(&inode.to_le_bytes());
        image[offset + 4..offset + 6].copy_from_slice(&rec_len.to_le_bytes());
        image[offset + 6] = u8::try_from(name.len()).expect("dir entry name length fits in u8");
        image[offset + 7] = file_type;
        image[offset + 8..offset + 8 + name.len()].copy_from_slice(name);
    }

    fn encode_dx_node_block(entries: &[Ext4DxEntry]) -> Vec<u8> {
        assert!(
            !entries.is_empty(),
            "DX node fixture needs at least the sentinel entry",
        );
        assert_eq!(
            entries[0].hash, 0,
            "DX node fixture sentinel hash must be zero",
        );

        let mut block = vec![0_u8; 4096];
        let count = u16::try_from(entries.len()).expect("DX node fixture count must fit in u16");
        block[0x08..0x0A].copy_from_slice(&count.to_le_bytes());
        block[0x0A..0x0C].copy_from_slice(&count.to_le_bytes());
        block[0x0C..0x10].copy_from_slice(&entries[0].block.to_le_bytes());

        let mut off = 0x10;
        for entry in entries.iter().skip(1) {
            block[off..off + 4].copy_from_slice(&entry.hash.to_le_bytes());
            block[off + 4..off + 8].copy_from_slice(&entry.block.to_le_bytes());
            off += 8;
        }
        block
    }

    #[allow(clippy::cast_possible_truncation)]
    fn build_large_dir_three_level_htree_image(
        has_large_dir: bool,
        root_hash_version: u8,
        deepest_entries: &[Ext4DxEntry],
        first_leaf_entries: &[(u32, &[u8])],
        second_leaf_entries: &[(u32, &[u8])],
    ) -> Vec<u8> {
        let block_size = 4096_usize;
        let image_blocks = 48_usize;
        let mut image = vec![0_u8; block_size * image_blocks];

        let sb_off = ffs_types::EXT4_SUPERBLOCK_OFFSET;
        let mut sb = [0_u8; ffs_types::EXT4_SUPERBLOCK_SIZE];
        sb[0x38..0x3A].copy_from_slice(&ffs_types::EXT4_SUPER_MAGIC.to_le_bytes());
        sb[0x18..0x1C].copy_from_slice(&2_u32.to_le_bytes()); // 4K blocks
        sb[0x00..0x04].copy_from_slice(&8192_u32.to_le_bytes());
        sb[0x04..0x08].copy_from_slice(&(image_blocks as u32).to_le_bytes());
        sb[0x14..0x18].copy_from_slice(&0_u32.to_le_bytes());
        sb[0x20..0x24].copy_from_slice(&(image_blocks as u32).to_le_bytes());
        sb[0x28..0x2C].copy_from_slice(&8192_u32.to_le_bytes());
        sb[0x54..0x58].copy_from_slice(&11_u32.to_le_bytes());
        sb[0x58..0x5A].copy_from_slice(&256_u16.to_le_bytes());
        let incompat = if has_large_dir {
            Ext4IncompatFeatures::LARGEDIR.0
        } else {
            0
        };
        sb[0x60..0x64].copy_from_slice(&incompat.to_le_bytes());
        image[sb_off..sb_off + ffs_types::EXT4_SUPERBLOCK_SIZE].copy_from_slice(&sb);

        let gdt_off = block_size;
        let mut gd = [0_u8; 32];
        gd[0x08..0x0C].copy_from_slice(&2_u32.to_le_bytes()); // inode table at block 2
        image[gdt_off..gdt_off + 32].copy_from_slice(&gd);

        let inode_table_off = 2 * block_size;
        let inode_off = inode_table_off + 256; // inode 2
        image[inode_off..inode_off + 2].copy_from_slice(&0o040_755_u16.to_le_bytes());
        image[inode_off + 0x04..inode_off + 0x08].copy_from_slice(&(6_u32 * 4096).to_le_bytes());
        image[inode_off + 0x1A..inode_off + 0x1C].copy_from_slice(&2_u16.to_le_bytes());
        image[inode_off + 0x20..inode_off + 0x24].copy_from_slice(
            &(ffs_types::EXT4_EXTENTS_FL | ffs_types::EXT4_INDEX_FL).to_le_bytes(),
        );
        image[inode_off + 0x64..inode_off + 0x68].copy_from_slice(&1_u32.to_le_bytes());

        let i_block = inode_off + 0x28;
        image[i_block..i_block + 2].copy_from_slice(&0xF30A_u16.to_le_bytes());
        image[i_block + 2..i_block + 4].copy_from_slice(&1_u16.to_le_bytes());
        image[i_block + 4..i_block + 6].copy_from_slice(&4_u16.to_le_bytes());
        image[i_block + 6..i_block + 8].copy_from_slice(&0_u16.to_le_bytes());
        image[i_block + 8..i_block + 12].copy_from_slice(&1_u32.to_le_bytes());
        let extent = i_block + 12;
        image[extent..extent + 4].copy_from_slice(&0_u32.to_le_bytes());
        image[extent + 4..extent + 6].copy_from_slice(&6_u16.to_le_bytes());
        image[extent + 6..extent + 8].copy_from_slice(&0_u16.to_le_bytes());
        image[extent + 8..extent + 12].copy_from_slice(&10_u32.to_le_bytes());

        let root_off = 10 * block_size;
        write_dir_entry_test(&mut image, root_off, 2, 2, b".", 12);
        write_dir_entry_test(&mut image, root_off + 12, 2, 2, b"..", 12);
        image[root_off + 0x1C] = root_hash_version;
        image[root_off + 0x1D] = 8;
        image[root_off + 0x1E] = 3; // three indirect levels with LARGEDIR
        image[root_off + 0x20..root_off + 0x22].copy_from_slice(&1_u16.to_le_bytes());
        image[root_off + 0x22..root_off + 0x24].copy_from_slice(&1_u16.to_le_bytes());
        image[root_off + 0x24..root_off + 0x28].copy_from_slice(&1_u32.to_le_bytes());

        let node1 = encode_dx_node_block(&[Ext4DxEntry { hash: 0, block: 2 }]);
        image[11 * block_size..12 * block_size].copy_from_slice(&node1);
        let node2 = encode_dx_node_block(&[Ext4DxEntry { hash: 0, block: 3 }]);
        image[12 * block_size..13 * block_size].copy_from_slice(&node2);
        let node3 = encode_dx_node_block(deepest_entries);
        image[13 * block_size..14 * block_size].copy_from_slice(&node3);

        let write_leaf = |image: &mut [u8], block_index: usize, entries: &[(u32, &[u8])]| {
            let leaf_off = block_index * block_size;
            let mut cursor = 0_usize;
            for (idx, (inode, name)) in entries.iter().enumerate() {
                let rec_len = if idx + 1 == entries.len() {
                    u16::try_from(block_size - cursor).expect("leaf rec_len fits u16")
                } else {
                    12_u16
                };
                write_dir_entry_test(image, leaf_off + cursor, *inode, 1, name, rec_len);
                cursor += usize::from(rec_len);
            }
        };

        write_leaf(&mut image, 14, first_leaf_entries);
        write_leaf(&mut image, 15, second_leaf_entries);
        image
    }

    #[test]
    fn htree_lookup_supports_large_dir_three_indirect_levels() {
        let target_name = b"triple-indirect-target";
        let image = build_large_dir_three_level_htree_image(
            true,
            1,
            &[Ext4DxEntry { hash: 0, block: 4 }],
            &[(42, target_name)],
            &[],
        );

        let reader = Ext4ImageReader::new(&image).expect("open indexed large_dir test image");
        let dir_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(2))
            .expect("read indexed directory inode");

        let found = reader
            .htree_lookup(&image, &dir_inode, target_name)
            .expect("htree lookup should succeed");
        let found = found.expect("lookup should reach the level-three successor leaf");
        assert_eq!(found.inode, 42);
        assert_eq!(found.name, target_name);
    }

    #[test]
    fn htree_lookup_follows_large_dir_three_level_collision_successor_leaf() {
        let target_name = b"triple-collision-target";
        let target_hash = dx_hash(1, target_name, &[0; 4]).0;
        let image = build_large_dir_three_level_htree_image(
            true,
            1,
            &[
                Ext4DxEntry { hash: 0, block: 4 },
                Ext4DxEntry {
                    hash: target_hash | 1,
                    block: 5,
                },
            ],
            &[(11, b"alpha")],
            &[(77, target_name)],
        );

        let reader = Ext4ImageReader::new(&image).expect("open indexed large_dir test image");
        let dir_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(2))
            .expect("read indexed directory inode");

        let found = reader
            .htree_lookup(&image, &dir_inode, target_name)
            .expect("htree lookup should succeed");
        let found = found.expect("lookup should follow the level-three collision successor leaf");
        assert_eq!(found.inode, 77);
        assert_eq!(found.name, target_name);
    }

    #[test]
    fn htree_lookup_follows_large_dir_three_level_unsigned_hash_split_successor() {
        let target_name = b"\xC3unsigned-split-target";
        let target_hash = dx_hash(4, target_name, &[0; 4]).0;
        let image = build_large_dir_three_level_htree_image(
            true,
            4,
            &[
                Ext4DxEntry { hash: 0, block: 4 },
                Ext4DxEntry {
                    hash: target_hash | 1,
                    block: 5,
                },
            ],
            &[(11, b"alpha")],
            &[(88, target_name)],
        );

        let reader = Ext4ImageReader::new(&image).expect("open indexed unsigned-hash test image");
        let dir_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(2))
            .expect("read indexed directory inode");

        let found = reader
            .htree_lookup(&image, &dir_inode, target_name)
            .expect("htree lookup should succeed");
        let found = found.expect("lookup should follow the unsigned-hash split successor leaf");
        assert_eq!(found.inode, 88);
        assert_eq!(found.name, target_name);
    }

    #[test]
    fn htree_lookup_rejects_three_indirect_levels_without_large_dir() {
        let target_name = b"triple-indirect-without-large-dir";
        let image = build_large_dir_three_level_htree_image(
            false,
            1,
            &[Ext4DxEntry { hash: 0, block: 4 }],
            &[(77, target_name)],
            &[],
        );

        let reader = Ext4ImageReader::new(&image).expect("open non-large-dir test image");
        let dir_inode = reader
            .read_inode(&image, ffs_types::InodeNumber(2))
            .expect("read indexed directory inode");

        let err = reader
            .htree_lookup(&image, &dir_inode, target_name)
            .expect_err("three indirect levels without LARGEDIR must be rejected");
        assert!(matches!(
            err,
            ffs_types::ParseError::InvalidField {
                field: "de_rec_len",
                ..
            }
        ));
    }

    #[test]
    fn parse_dx_root_with_empty_entries() {
        let mut block = vec![0_u8; 256];
        block[0x1C] = 1; // hash_version = HALF_MD4
        block[0x1D] = 8; // info_length = 8
        block[0x1E] = 0; // indirect_levels = 0
        // dx_countlimit at 0x20: limit=10, count=0
        block[0x20..0x22].copy_from_slice(&10_u16.to_le_bytes());
        block[0x22..0x24].copy_from_slice(&0_u16.to_le_bytes());

        let root = parse_dx_root(&block).expect("valid dx root");
        assert_eq!(root.hash_version, 1);
        assert_eq!(root.indirect_levels, 0);
        assert_eq!(root.entries, [] as [ffs_ondisk::Ext4DxEntry; 0]);
    }

    #[test]
    fn parse_dx_root_with_entries() {
        let mut block = vec![0_u8; 256];
        block[0x1C] = 2; // hash_version = TEA
        block[0x1D] = 8; // info_length = 8
        block[0x1E] = 0; // indirect_levels = 0
        // dx_countlimit at 0x20: limit=10, count=3
        block[0x20..0x22].copy_from_slice(&10_u16.to_le_bytes());
        block[0x22..0x24].copy_from_slice(&3_u16.to_le_bytes());
        // Entry 0 (implicit hash 0) block at 0x24
        block[0x24..0x28].copy_from_slice(&5_u32.to_le_bytes());

        // Entry 1 at 0x28: hash=0x1000, block=10
        block[0x28..0x2C].copy_from_slice(&0x1000_u32.to_le_bytes());
        block[0x2C..0x30].copy_from_slice(&10_u32.to_le_bytes());

        // Entry 2 at 0x30: hash=0x2000, block=15
        block[0x30..0x34].copy_from_slice(&0x2000_u32.to_le_bytes());
        block[0x34..0x38].copy_from_slice(&15_u32.to_le_bytes());

        let root = ffs_ondisk::parse_dx_root(&block).expect("valid dx root");
        assert_eq!(root.entries.len(), 3);
        assert_eq!(root.entries[0].hash, 0);
        assert_eq!(root.entries[0].block, 5);
        assert_eq!(root.entries[1].hash, 0x1000);
        assert_eq!(root.entries[1].block, 10);
        assert_eq!(root.entries[2].hash, 0x2000);
        assert_eq!(root.entries[2].block, 15);
    }

    // ── parse_inode_extent_tree tests ───────────────────────────────────

    #[test]
    fn parse_inode_extent_tree_empty_leaf() {
        let mut inode = make_inode(ffs_types::S_IFREG, ffs_types::EXT4_EXTENTS_FL);
        // Write valid extent tree header into extent_bytes
        inode.extent_bytes[0..2].copy_from_slice(&0xF30A_u16.to_le_bytes());
        inode.extent_bytes[2..4].copy_from_slice(&0_u16.to_le_bytes()); // entries: 0
        inode.extent_bytes[4..6].copy_from_slice(&4_u16.to_le_bytes()); // max: 4
        inode.extent_bytes[6..8].copy_from_slice(&0_u16.to_le_bytes()); // depth: 0

        let (header, tree) = parse_inode_extent_tree(&inode).expect("valid extent tree");
        assert_eq!(header.magic, 0xF30A);
        assert!(matches!(tree, ExtentTree::Leaf(ref e) if e.is_empty()));
    }

    #[test]
    fn parse_inode_extent_tree_with_extent() {
        let mut inode = make_inode(ffs_types::S_IFREG, ffs_types::EXT4_EXTENTS_FL);
        // Header
        inode.extent_bytes[0..2].copy_from_slice(&0xF30A_u16.to_le_bytes());
        inode.extent_bytes[2..4].copy_from_slice(&1_u16.to_le_bytes());
        inode.extent_bytes[4..6].copy_from_slice(&4_u16.to_le_bytes());
        inode.extent_bytes[6..8].copy_from_slice(&0_u16.to_le_bytes());
        // Extent entry at offset 12
        inode.extent_bytes[12..16].copy_from_slice(&0_u32.to_le_bytes()); // logical
        inode.extent_bytes[16..18].copy_from_slice(&5_u16.to_le_bytes()); // len
        inode.extent_bytes[18..20].copy_from_slice(&0_u16.to_le_bytes()); // phys_hi
        inode.extent_bytes[20..24].copy_from_slice(&100_u32.to_le_bytes()); // phys_lo

        let (_header, tree) = parse_inode_extent_tree(&inode).expect("valid");
        assert!(matches!(tree, ExtentTree::Leaf(_)), "expected leaf");
        let ExtentTree::Leaf(extents) = tree else {
            return;
        };
        assert_eq!(extents.len(), 1);
        assert_eq!(extents[0].logical_block, 0);
        assert_eq!(extents[0].actual_len(), 5);
        assert_eq!(extents[0].physical_start, 100);
    }

    // ── ExtentTree::Index variant tests ────────────────────────────────

    #[test]
    fn parse_extent_tree_index_node() {
        let mut buf = [0_u8; 60];
        // Header: magic, entries=1, max=4, depth=1 (index node)
        buf[0..2].copy_from_slice(&0xF30A_u16.to_le_bytes());
        buf[2..4].copy_from_slice(&1_u16.to_le_bytes());
        buf[4..6].copy_from_slice(&4_u16.to_le_bytes());
        buf[6..8].copy_from_slice(&1_u16.to_le_bytes()); // depth=1 → index node
        // Index entry at offset 12:
        // logical_block: 0
        buf[12..16].copy_from_slice(&0_u32.to_le_bytes());
        // leaf_block_lo: 500
        buf[16..20].copy_from_slice(&500_u32.to_le_bytes());
        // leaf_block_hi: 0
        buf[20..22].copy_from_slice(&0_u16.to_le_bytes());

        let (header, tree) = parse_extent_tree(&buf).expect("valid index node");
        assert_eq!(header.depth, 1);
        assert!(matches!(tree, ExtentTree::Index(_)), "expected index tree");
        let ExtentTree::Index(indices) = tree else {
            return;
        };
        assert_eq!(indices.len(), 1);
        assert_eq!(indices[0].logical_block, 0);
        assert_eq!(indices[0].leaf_block, 500);
    }

    // ── DirBlockIter / Ext4DirEntryRef tests ───────────────────────────

    #[test]
    fn dir_block_iter_yields_entries() {
        let mut block = vec![0_u8; 4096];
        // Entry 1: inode=2, rec_len=12, name_len=1, type=Dir, name="."
        block[0..4].copy_from_slice(&2_u32.to_le_bytes());
        block[4..6].copy_from_slice(&12_u16.to_le_bytes());
        block[6] = 1;
        block[7] = 2;
        block[8] = b'.';

        // Entry 2: inode=2, rec_len=4084, name_len=2, type=Dir, name=".."
        block[12..16].copy_from_slice(&2_u32.to_le_bytes());
        block[16..18].copy_from_slice(&(4096_u16 - 12).to_le_bytes());
        block[18] = 2;
        block[19] = 2;
        block[20] = b'.';
        block[21] = b'.';

        let iter = iter_dir_block(&block, 4096);
        let entries: Vec<_> = iter.filter_map(Result::ok).collect();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].is_dot());
        assert!(entries[1].is_dotdot());
    }

    #[test]
    fn dir_entry_ref_to_owned() {
        let mut block = vec![0_u8; 4096];
        block[0..4].copy_from_slice(&42_u32.to_le_bytes());
        block[4..6].copy_from_slice(&4096_u16.to_le_bytes());
        block[6] = 4;
        block[7] = 1; // RegFile
        block[8..12].copy_from_slice(b"test");

        let mut iter = iter_dir_block(&block, 4096);
        let entry_ref = iter.next().unwrap().unwrap();
        assert_eq!(entry_ref.inode, 42);
        assert_eq!(entry_ref.name_str(), "test");
        assert!(!entry_ref.is_dot());
        assert!(!entry_ref.is_dotdot());

        let owned = entry_ref.to_owned();
        assert_eq!(owned.inode, 42);
        assert_eq!(owned.name_str(), "test");
    }

    #[test]
    fn dir_block_iter_checksum_tail_none_for_plain_block() {
        let block = vec![0_u8; 4096];
        let iter = iter_dir_block(&block, 4096);
        assert!(iter.checksum_tail().is_none());
    }

    // ── Ext4DxEntry constructability ───────────────────────────────────

    #[test]
    fn dx_entry_struct_is_constructable() {
        let entry = Ext4DxEntry {
            hash: 0xDEAD_BEEF,
            block: 42,
        };
        assert_eq!(entry.hash, 0xDEAD_BEEF);
        assert_eq!(entry.block, 42);
    }

    // ── Ext4DxRoot constructability ────────────────────────────────────

    #[test]
    fn dx_root_struct_is_constructable() {
        let root = Ext4DxRoot {
            hash_version: 2,
            indirect_levels: 0,
            entries: vec![Ext4DxEntry { hash: 0, block: 1 }],
        };
        assert_eq!(root.hash_version, 2);
        assert_eq!(root.entries.len(), 1);
    }

    // ── Ext4Xattr system namespace ─────────────────────────────────────

    #[test]
    fn xattr_full_name_system_namespace() {
        let xattr = Ext4Xattr {
            name_index: 7, // EXT4_XATTR_INDEX_SYSTEM
            name: b"posix_acl_access".to_vec(),
            value: Vec::new(),
        };
        assert_eq!(xattr.full_name(), "system.posix_acl_access");
    }

    // ── dx_hash additional hash version tests ──────────────────────────

    #[test]
    fn dx_hash_half_md4_produces_output() {
        let seed = [0x1234_u32, 0x5678, 0x9ABC, 0xDEF0];
        let (h, m) = dx_hash(1, b"file.txt", &seed); // DX_HASH_HALF_MD4 = 1
        assert!(h != 0 || m != 0);
    }

    #[test]
    fn dx_hash_tea_unsigned_produces_output() {
        let seed = [0_u32; 4];
        let (h, m) = dx_hash(5, b"abc", &seed); // DX_HASH_TEA_UNSIGNED = 5
        assert!(h != 0 || m != 0);
    }

    #[test]
    fn dx_hash_different_seeds_produce_different_results() {
        let seed_a = [0_u32; 4];
        let seed_b = [1_u32, 2, 3, 4];
        let (h_a, _) = dx_hash(1, b"same", &seed_a);
        let (h_b, _) = dx_hash(1, b"same", &seed_b);
        assert_ne!(h_a, h_b);
    }

    #[test]
    fn dx_hash_empty_name() {
        let seed = [0_u32; 4];
        // Empty name should not panic
        let (_h, _m) = dx_hash(1, b"", &seed);
    }

    // ── Ext4Inode parsing extended fields ──────────────────────────────

    #[test]
    fn inode_parser_reads_extended_isize_field() {
        let mut buf = vec![0_u8; 256];
        // mode: regular file
        buf[0..2].copy_from_slice(&(ffs_types::S_IFREG).to_le_bytes());
        // extra_isize at 0x80 = 32 (covers up to 0xA0)
        buf[0x80..0x82].copy_from_slice(&32_u16.to_le_bytes());

        let inode = Ext4Inode::parse_from_bytes(&buf).expect("valid inode");
        assert_eq!(inode.extra_isize, 32);
    }

    #[test]
    fn inode_parser_rejects_extra_isize_beyond_boundary() {
        let mut buf = vec![0_u8; 256];
        buf[0..2].copy_from_slice(&(ffs_types::S_IFREG).to_le_bytes());
        // extra_isize = 200 > (256 - 128) = 128 → should fail
        buf[0x80..0x82].copy_from_slice(&200_u16.to_le_bytes());

        assert!(Ext4Inode::parse_from_bytes(&buf).is_err());
    }

    // ── Ext4Inode parsing uid/gid high bits ────────────────────────────

    #[test]
    fn inode_parser_assembles_32bit_uid_gid() {
        let mut buf = vec![0_u8; 256];
        buf[0..2].copy_from_slice(&(ffs_types::S_IFREG).to_le_bytes());
        // uid_lo at 0x02 = 1000
        buf[0x02..0x04].copy_from_slice(&1000_u16.to_le_bytes());
        // gid_lo at 0x18 = 2000
        buf[0x18..0x1A].copy_from_slice(&2000_u16.to_le_bytes());
        // uid_hi at 0x78 = 1
        buf[0x78..0x7A].copy_from_slice(&1_u16.to_le_bytes());
        // gid_hi at 0x7A = 2
        buf[0x7A..0x7C].copy_from_slice(&2_u16.to_le_bytes());

        let inode = Ext4Inode::parse_from_bytes(&buf).expect("valid inode");
        assert_eq!(inode.uid, (0x1_u32 << 16) | 0x03E8);
        assert_eq!(inode.gid, (0x2_u32 << 16) | 0x07D0);
    }

    // ── FeatureDiagnostics combined display ────────────────────────────

    #[test]
    fn feature_diagnostics_display_all_issues() {
        let diag = FeatureDiagnostics {
            missing_required: vec!["FILETYPE", "EXTENTS"],
            rejected_present: vec!["ENCRYPT"],
            unknown_incompat_bits: 0x1000,
            unknown_ro_compat_bits: 0x2000,
            incompat_display: "COMPRESSION".to_string(),
            ro_compat_display: "VERITY".to_string(),
            compat_display: "HAS_JOURNAL".to_string(),
        };
        assert!(!diag.is_ok());
        let display = format!("{diag}");
        assert!(display.contains("missing required"));
        assert!(display.contains("FILETYPE"));
        assert!(display.contains("EXTENTS"));
        assert!(display.contains("rejected"));
        assert!(display.contains("ENCRYPT"));
        assert!(display.contains("unknown incompat"));
        assert!(display.contains("1000"));
        assert!(display.contains("unknown ro_compat"));
        assert!(display.contains("2000"));
    }

    #[test]
    fn feature_diagnostics_display_exact_golden_contract() {
        let diag = FeatureDiagnostics {
            missing_required: vec!["FILETYPE", "EXTENTS"],
            rejected_present: vec!["ENCRYPT"],
            unknown_incompat_bits: 0x1000,
            unknown_ro_compat_bits: 0x2000,
            incompat_display: "COMPRESSION".to_string(),
            ro_compat_display: "VERITY".to_string(),
            compat_display: "HAS_JOURNAL".to_string(),
        };

        assert_eq!(
            format!("{diag}"),
            "compat=HAS_JOURNAL, incompat=COMPRESSION, ro_compat=VERITY; \
missing required: FILETYPE, EXTENTS; rejected: ENCRYPT; unknown incompat: \
0x1000; unknown ro_compat: 0x2000"
        );
    }

    // ── Ext4Inode flags field parsing ──────────────────────────────────

    #[test]
    fn inode_parser_reads_flags_field() {
        let mut buf = vec![0_u8; 256];
        buf[0..2].copy_from_slice(&(ffs_types::S_IFREG).to_le_bytes());
        // flags at 0x20
        let flags = ffs_types::EXT4_EXTENTS_FL | ffs_types::EXT4_HUGE_FILE_FL;
        buf[0x20..0x24].copy_from_slice(&flags.to_le_bytes());

        let inode = Ext4Inode::parse_from_bytes(&buf).expect("valid inode");
        assert!(inode.uses_extents());
        assert!(inode.is_huge_file());
    }

    // ── Ext4Inode generation field ─────────────────────────────────────

    #[test]
    fn inode_parser_reads_generation() {
        let mut buf = vec![0_u8; 256];
        buf[0..2].copy_from_slice(&(ffs_types::S_IFREG).to_le_bytes());
        // generation at 0x64
        buf[0x64..0x68].copy_from_slice(&0xDEAD_BEEF_u32.to_le_bytes());

        let inode = Ext4Inode::parse_from_bytes(&buf).expect("valid inode");
        assert_eq!(inode.generation, 0xDEAD_BEEF);
    }

    // ── Ext4Inode size assembly (64-bit for regular files) ─────────────

    #[test]
    fn inode_parser_assembles_64bit_size_for_regular_file() {
        let mut buf = vec![0_u8; 256];
        // mode: regular file
        buf[0..2].copy_from_slice(&(ffs_types::S_IFREG).to_le_bytes());
        // size_lo at 0x04
        buf[0x04..0x08].copy_from_slice(&0x1000_u32.to_le_bytes());
        // size_hi at 0x6C (dir_acl / size_hi)
        buf[0x6C..0x70].copy_from_slice(&0x0001_u32.to_le_bytes());

        let inode = Ext4Inode::parse_from_bytes(&buf).expect("valid inode");
        assert_eq!(inode.size, 0x0001_0000_1000);
    }

    // ── Multiple feature flags combined ────────────────────────────────

    #[test]
    fn compat_features_multiple_flags_combine() {
        let features = Ext4CompatFeatures(
            Ext4CompatFeatures::HAS_JOURNAL.0
                | Ext4CompatFeatures::EXT_ATTR.0
                | Ext4CompatFeatures::DIR_INDEX.0,
        );
        let names = features.describe();
        assert_eq!(names.len(), 3);
        assert!(names.contains(&"HAS_JOURNAL"));
        assert!(names.contains(&"EXT_ATTR"));
        assert!(names.contains(&"DIR_INDEX"));
    }

    #[test]
    fn incompat_features_all_v1_required_set() {
        let features = Ext4IncompatFeatures(
            Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0,
        );
        let missing = features.describe_missing_required_v1();
        assert!(
            missing.is_empty(),
            "both required flags set, nothing missing"
        );
    }

    // ── Ext4Inode blocks field ─────────────────────────────────────────

    #[test]
    fn inode_parser_reads_blocks_count() {
        let mut buf = vec![0_u8; 256];
        buf[0..2].copy_from_slice(&(ffs_types::S_IFREG).to_le_bytes());
        // blocks_lo at 0x1C
        buf[0x1C..0x20].copy_from_slice(&8_u32.to_le_bytes());

        let inode = Ext4Inode::parse_from_bytes(&buf).expect("valid inode");
        assert_eq!(inode.blocks, 8);
    }

    // ── Ext4Inode file_acl field ───────────────────────────────────────

    #[test]
    fn inode_parser_reads_file_acl() {
        let mut buf = vec![0_u8; 256];
        buf[0..2].copy_from_slice(&(ffs_types::S_IFREG).to_le_bytes());
        // file_acl_lo at 0x68
        buf[0x68..0x6C].copy_from_slice(&42_u32.to_le_bytes());
        // file_acl_hi at 0x76
        buf[0x76..0x78].copy_from_slice(&1_u16.to_le_bytes());

        let inode = Ext4Inode::parse_from_bytes(&buf).expect("valid inode");
        assert_eq!(inode.file_acl, (0x1_u64 << 32) | 0x2A);
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Ext4Superblock query/validation method tests
    // ══════════════════════════════════════════════════════════════════════

    /// Build a minimal valid Ext4Superblock suitable for unit testing.
    ///
    /// Defaults: 4K blocks, FILETYPE+EXTENTS incompat, 1 group, 256-byte
    /// inodes, 8192 blocks_per_group, 2048 inodes_per_group.
    #[expect(clippy::too_many_lines)]
    fn make_superblock() -> Ext4Superblock {
        Ext4Superblock {
            inodes_count: 2048,
            blocks_count: 8192,
            reserved_blocks_count: 0,
            free_blocks_count: 4000,
            free_inodes_count: 1900,
            first_data_block: 0,
            block_size: 4096,
            log_cluster_size: 2, // 2^(10+2) = 4096
            cluster_size: 4096,
            blocks_per_group: 8192,
            clusters_per_group: 8192,
            inodes_per_group: 2048,
            inode_size: 256,
            min_extra_isize: 0,
            want_extra_isize: 0,
            first_ino: 11,
            desc_size: 32,
            reserved_gdt_blocks: 0,
            first_meta_bg: 0,
            raid_stride: 0,
            raid_stripe_width: 0,
            kbytes_written: 0,
            magic: 0xEF53,
            uuid: [0; 16],
            volume_name: String::new(),
            last_mounted: String::new(),
            rev_level: 1,
            minor_rev_level: 0,
            creator_os: 0,
            feature_compat: Ext4CompatFeatures(
                Ext4CompatFeatures::HAS_JOURNAL.0 | Ext4CompatFeatures::EXT_ATTR.0,
            ),
            feature_incompat: Ext4IncompatFeatures(
                Ext4IncompatFeatures::FILETYPE.0 | Ext4IncompatFeatures::EXTENTS.0,
            ),
            feature_ro_compat: Ext4RoCompatFeatures(Ext4RoCompatFeatures::SPARSE_SUPER.0),
            super_flags: Ext4SuperFlags(0),
            default_mount_opts: 0,
            mount_opts: String::new(),
            state: EXT4_VALID_FS,
            errors: 1,
            mnt_count: 5,
            max_mnt_count: 100,
            checkinterval: 0,
            error_count: 0,
            def_resuid: 0,
            def_resgid: 0,
            block_group_nr: 0,
            algorithm_usage_bitmap: 0,
            prealloc_blocks: 0,
            prealloc_dir_blocks: 0,
            jnl_backup_type: 0,
            mtime: 1_700_000_000,
            wtime: 1_700_000_000,
            lastcheck: 1_700_000_000,
            mkfs_time: 1_690_000_000,
            first_error_time: 0,
            last_error_time: 0,
            wtime_hi: 0,
            mtime_hi: 0,
            mkfs_time_hi: 0,
            lastcheck_hi: 0,
            first_error_time_hi: 0,
            last_error_time_hi: 0,
            first_error_errcode: 0,
            last_error_errcode: 0,
            first_error_ino: 0,
            first_error_block: 0,
            first_error_func: String::new(),
            first_error_line: 0,
            last_error_ino: 0,
            last_error_block: 0,
            last_error_func: String::new(),
            last_error_line: 0,
            journal_inum: 8,
            journal_dev: 0,
            last_orphan: 0,
            journal_uuid: [0; 16],
            jnl_blocks: [0; 17],
            snapshot_inum: 0,
            snapshot_id: 0,
            snapshot_r_blocks_count: 0,
            snapshot_list: 0,
            hash_seed: [0x1234, 0x5678, 0x9ABC, 0xDEF0],
            def_hash_version: 1,
            log_groups_per_flex: 4,
            mmp_update_interval: 0,
            mmp_block: 0,
            usr_quota_inum: 0,
            grp_quota_inum: 0,
            prj_quota_inum: 0,
            overhead_clusters: 0,
            backup_bgs: [0; 2],
            encrypt_algos: [0; 4],
            encrypt_pw_salt: [0; 16],
            lost_found_ino: 0,
            encoding: 0,
            encoding_flags: 0,
            orphan_file_inum: 0,
            checksum_type: 0,
            checksum_seed: 0,
            checksum: 0,
        }
    }

    // ── has_compat / has_incompat / has_ro_compat ─────────────────────────

    #[test]
    fn superblock_has_compat_detects_set_flag() {
        let sb = make_superblock();
        assert!(sb.has_compat(Ext4CompatFeatures::HAS_JOURNAL));
        assert!(sb.has_compat(Ext4CompatFeatures::EXT_ATTR));
    }

    #[test]
    fn superblock_has_compat_detects_unset_flag() {
        let sb = make_superblock();
        assert!(!sb.has_compat(Ext4CompatFeatures::DIR_INDEX));
    }

    #[test]
    fn superblock_has_incompat_detects_set_flag() {
        let sb = make_superblock();
        assert!(sb.has_incompat(Ext4IncompatFeatures::FILETYPE));
        assert!(sb.has_incompat(Ext4IncompatFeatures::EXTENTS));
    }

    #[test]
    fn superblock_has_incompat_detects_unset_flag() {
        let sb = make_superblock();
        assert!(!sb.has_incompat(Ext4IncompatFeatures::ENCRYPT));
        assert!(!sb.has_incompat(Ext4IncompatFeatures::BIT64));
    }

    #[test]
    fn superblock_has_ro_compat_detects_set_flag() {
        let sb = make_superblock();
        assert!(sb.has_ro_compat(Ext4RoCompatFeatures::SPARSE_SUPER));
    }

    #[test]
    fn superblock_has_ro_compat_detects_unset_flag() {
        let sb = make_superblock();
        assert!(!sb.has_ro_compat(Ext4RoCompatFeatures::METADATA_CSUM));
    }

    // ── is_64bit ─────────────────────────────────────────────────────────

    #[test]
    fn superblock_is_not_64bit_without_flag() {
        let sb = make_superblock();
        assert!(!sb.is_64bit());
    }

    #[test]
    fn superblock_is_64bit_with_flag() {
        let mut sb = make_superblock();
        sb.feature_incompat.0 |= Ext4IncompatFeatures::BIT64.0;
        sb.desc_size = 64;
        assert!(sb.is_64bit());
    }

    // ── group_desc_size ──────────────────────────────────────────────────

    #[test]
    fn superblock_group_desc_size_32bit() {
        let sb = make_superblock();
        assert_eq!(sb.group_desc_size(), 32);
    }

    #[test]
    fn superblock_group_desc_size_64bit_clamps_to_64() {
        let mut sb = make_superblock();
        sb.feature_incompat.0 |= Ext4IncompatFeatures::BIT64.0;
        sb.desc_size = 32; // desc_size < 64 but 64BIT set → clamped to 64
        assert_eq!(sb.group_desc_size(), 64);
    }

    #[test]
    fn superblock_group_desc_size_64bit_respects_larger() {
        let mut sb = make_superblock();
        sb.feature_incompat.0 |= Ext4IncompatFeatures::BIT64.0;
        sb.desc_size = 128;
        assert_eq!(sb.group_desc_size(), 128);
    }

    // ── groups_count ─────────────────────────────────────────────────────

    #[test]
    fn superblock_groups_count_single_group() {
        let sb = make_superblock();
        // blocks_count=8192, first_data_block=0, blocks_per_group=8192
        // → (8192 - 0).div_ceil(8192) = 1
        assert_eq!(sb.groups_count(), 1);
    }

    #[test]
    fn superblock_groups_count_multiple_groups() {
        let mut sb = make_superblock();
        sb.blocks_count = 32768; // 4 groups
        sb.inodes_count = 8192;
        assert_eq!(sb.groups_count(), 4);
    }

    #[test]
    fn superblock_groups_count_partial_group_rounds_up() {
        let mut sb = make_superblock();
        sb.blocks_count = 8193; // 1 full + 1 partial
        assert_eq!(sb.groups_count(), 2);
    }

    #[test]
    fn superblock_groups_count_zero_blocks_per_group() {
        let mut sb = make_superblock();
        sb.blocks_per_group = 0;
        assert_eq!(sb.groups_count(), 0);
    }

    #[test]
    fn superblock_groups_count_with_first_data_block() {
        let mut sb = make_superblock();
        sb.block_size = 1024;
        sb.first_data_block = 1;
        sb.blocks_count = 8193; // data_blocks = 8193 - 1 = 8192
        assert_eq!(sb.groups_count(), 1);
    }

    // ── has_metadata_csum ────────────────────────────────────────────────

    #[test]
    fn superblock_has_metadata_csum_false_by_default() {
        let sb = make_superblock();
        assert!(!sb.has_metadata_csum());
    }

    #[test]
    fn superblock_has_metadata_csum_true_when_set() {
        let mut sb = make_superblock();
        sb.feature_ro_compat.0 |= Ext4RoCompatFeatures::METADATA_CSUM.0;
        assert!(sb.has_metadata_csum());
    }

    // ── csum_seed ────────────────────────────────────────────────────────

    #[test]
    fn superblock_csum_seed_computed_from_uuid() {
        let mut sb = make_superblock();
        sb.uuid = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
        let expected = ext4_chksum(!0u32, &sb.uuid);
        assert_eq!(sb.csum_seed(), expected);
    }

    #[test]
    fn superblock_csum_seed_uses_stored_when_csum_seed_flag() {
        let mut sb = make_superblock();
        sb.feature_incompat.0 |= Ext4IncompatFeatures::CSUM_SEED.0;
        sb.checksum_seed = 0xDEAD_BEEF;
        assert_eq!(sb.csum_seed(), 0xDEAD_BEEF);
    }

    #[test]
    fn superblock_csum_seed_zero_uuid_is_deterministic() {
        let sb = make_superblock(); // uuid is all zeros
        let seed1 = sb.csum_seed();
        let seed2 = sb.csum_seed();
        assert_eq!(seed1, seed2);
    }

    // ── validate_checksum ────────────────────────────────────────────────

    #[test]
    fn superblock_validate_checksum_skips_when_no_metadata_csum() {
        let sb = make_superblock();
        assert!(!sb.has_metadata_csum());
        assert!(sb.validate_checksum(&[0; 1024]).is_ok());
    }

    #[test]
    fn superblock_validate_checksum_rejects_short_region() {
        let mut sb = make_superblock();
        sb.feature_ro_compat.0 |= Ext4RoCompatFeatures::METADATA_CSUM.0;
        assert!(sb.validate_checksum(&[0; 100]).is_err());
    }

    #[test]
    fn superblock_validate_checksum_rejects_mismatch() {
        let mut sb = make_superblock();
        sb.feature_ro_compat.0 |= Ext4RoCompatFeatures::METADATA_CSUM.0;
        sb.checksum = 0xBAAD_F00D;
        let region = vec![0; 1024];
        assert!(sb.validate_checksum(&region).is_err());
    }

    // ── validate_geometry ────────────────────────────────────────────────

    #[test]
    fn superblock_validate_geometry_passes_for_valid() {
        let sb = make_superblock();
        assert!(sb.validate_geometry().is_ok());
    }

    #[test]
    fn superblock_validate_geometry_rejects_zero_blocks_per_group() {
        let mut sb = make_superblock();
        sb.blocks_per_group = 0;
        assert!(sb.validate_geometry().is_err());
    }

    #[test]
    fn superblock_validate_geometry_rejects_zero_inodes_per_group() {
        let mut sb = make_superblock();
        sb.inodes_per_group = 0;
        assert!(sb.validate_geometry().is_err());
    }

    #[test]
    fn superblock_validate_geometry_rejects_small_inode_size() {
        let mut sb = make_superblock();
        sb.inode_size = 64; // < 128
        assert!(sb.validate_geometry().is_err());
    }

    #[test]
    fn superblock_validate_geometry_rejects_non_power_of_two_inode_size() {
        let mut sb = make_superblock();
        sb.inode_size = 200;
        assert!(sb.validate_geometry().is_err());
    }

    #[test]
    fn superblock_validate_geometry_rejects_inode_size_exceeding_block_size() {
        let mut sb = make_superblock();
        sb.inode_size = 8192; // > block_size (4096)
        assert!(sb.validate_geometry().is_err());
    }

    #[test]
    fn superblock_validate_geometry_rejects_excessive_blocks_per_group() {
        let mut sb = make_superblock();
        // block_size * 8 = 32768
        sb.blocks_per_group = 40000; // > 32768
        assert!(sb.validate_geometry().is_err());
    }

    #[test]
    fn superblock_validate_geometry_rejects_excessive_inodes_per_group() {
        let mut sb = make_superblock();
        sb.inodes_per_group = 40000; // > 32768
        assert!(sb.validate_geometry().is_err());
    }

    #[test]
    fn superblock_validate_geometry_rejects_desc_size_too_small() {
        let mut sb = make_superblock();
        sb.desc_size = 16; // < 32
        assert!(sb.validate_geometry().is_err());
    }

    #[test]
    fn superblock_validate_geometry_rejects_64bit_with_small_desc_size() {
        let mut sb = make_superblock();
        sb.feature_incompat.0 |= Ext4IncompatFeatures::BIT64.0;
        sb.desc_size = 32; // < 64 but 64BIT set
        assert!(sb.validate_geometry().is_err());
    }

    #[test]
    fn superblock_validate_geometry_first_data_block_must_be_1_for_1k() {
        let mut sb = make_superblock();
        sb.block_size = 1024;
        sb.cluster_size = 1024;
        sb.first_data_block = 0; // must be 1 for 1K
        assert!(sb.validate_geometry().is_err());
    }

    #[test]
    fn superblock_validate_geometry_first_data_block_must_be_0_for_4k() {
        let mut sb = make_superblock();
        sb.first_data_block = 1; // must be 0 for 4K
        assert!(sb.validate_geometry().is_err());
    }

    #[test]
    fn superblock_validate_geometry_rejects_inodes_exceeding_capacity() {
        let mut sb = make_superblock();
        // groups * inodes_per_group = 1 * 2048 = 2048
        sb.inodes_count = 5000; // > 2048
        assert!(sb.validate_geometry().is_err());
    }

    // ── validate_v1 ──────────────────────────────────────────────────────

    #[test]
    fn superblock_validate_v1_passes_for_valid() {
        let sb = make_superblock();
        assert!(sb.validate_v1().is_ok());
    }

    #[test]
    fn superblock_validate_v1_rejects_missing_filetype() {
        let mut sb = make_superblock();
        sb.feature_incompat = Ext4IncompatFeatures(Ext4IncompatFeatures::EXTENTS.0);
        assert!(sb.validate_v1().is_err());
    }

    #[test]
    fn superblock_validate_v1_allows_missing_extents() {
        let mut sb = make_superblock();
        sb.feature_incompat = Ext4IncompatFeatures(Ext4IncompatFeatures::FILETYPE.0);
        assert!(sb.validate_v1().is_ok());
    }

    #[test]
    fn superblock_validate_v1_accepts_encrypt() {
        let mut sb = make_superblock();
        sb.feature_incompat.0 |= Ext4IncompatFeatures::ENCRYPT.0;
        assert!(sb.validate_v1().is_ok());
    }

    #[test]
    fn superblock_validate_v1_accepts_inline_data() {
        let mut sb = make_superblock();
        sb.feature_incompat.0 |= Ext4IncompatFeatures::INLINE_DATA.0;
        assert!(sb.validate_v1().is_ok());
    }

    #[test]
    fn superblock_validate_v1_accepts_casefold() {
        let mut sb = make_superblock();
        sb.feature_incompat.0 |= Ext4IncompatFeatures::CASEFOLD.0;
        assert!(sb.validate_v1().is_ok());
    }

    #[test]
    fn superblock_validate_v1_rejects_unknown_incompat_flags() {
        let mut sb = make_superblock();
        sb.feature_incompat.0 |= 0x8000_0000; // unknown flag
        assert!(sb.validate_v1().is_err());
    }

    #[test]
    fn superblock_validate_v1_accepts_allowed_flags() {
        let mut sb = make_superblock();
        // Add BIT64 + FLEX_BG — these are ALLOWED
        sb.feature_incompat.0 |= Ext4IncompatFeatures::BIT64.0 | Ext4IncompatFeatures::FLEX_BG.0;
        sb.desc_size = 64; // required for 64BIT
        assert!(sb.validate_v1().is_ok());
    }

    // ── feature_diagnostics_v1 ───────────────────────────────────────────

    #[test]
    fn superblock_feature_diagnostics_v1_ok_when_valid() {
        let sb = make_superblock();
        let diag = sb.feature_diagnostics_v1();
        assert!(diag.is_ok());
        assert_eq!(diag.missing_required, [] as [&str; 0]);
        assert_eq!(diag.rejected_present, [] as [&str; 0]);
        assert_eq!(diag.unknown_incompat_bits, 0);
    }

    #[test]
    fn superblock_feature_diagnostics_v1_reports_missing_required() {
        let mut sb = make_superblock();
        sb.feature_incompat = Ext4IncompatFeatures(0); // nothing set
        let diag = sb.feature_diagnostics_v1();
        assert!(!diag.is_ok());
        assert!(diag.missing_required.contains(&"FILETYPE"));
        assert!(!diag.missing_required.contains(&"EXTENTS"));
    }

    #[test]
    fn superblock_feature_diagnostics_v1_no_rejected() {
        // All known features are now allowed — REJECTED_V1 is empty.
        let mut sb = make_superblock();
        sb.feature_incompat.0 |= Ext4IncompatFeatures::ENCRYPT.0;
        let diag = sb.feature_diagnostics_v1();
        assert_eq!(diag.rejected_present, [] as [&str; 0]);
    }

    #[test]
    fn superblock_feature_diagnostics_v1_reports_unknown_bits() {
        let mut sb = make_superblock();
        sb.feature_incompat.0 |= 0x4000_0000;
        let diag = sb.feature_diagnostics_v1();
        assert_ne!(diag.unknown_incompat_bits, 0);
    }

    #[test]
    fn superblock_feature_diagnostics_v1_display_strings_populated() {
        let sb = make_superblock();
        let diag = sb.feature_diagnostics_v1();
        assert!(diag.incompat_display.contains("FILETYPE"));
        assert!(diag.incompat_display.contains("EXTENTS"));
        assert!(diag.compat_display.contains("HAS_JOURNAL"));
        assert!(diag.ro_compat_display.contains("SPARSE_SUPER"));
    }

    #[test]
    fn superblock_feature_diagnostics_v1_exact_golden_contract() {
        let mut sb = make_superblock();
        sb.feature_incompat =
            Ext4IncompatFeatures(Ext4IncompatFeatures::COMPRESSION.0 | 0x4000_0000);
        sb.feature_ro_compat =
            Ext4RoCompatFeatures(Ext4RoCompatFeatures::SPARSE_SUPER.0 | 0x8000_0000);

        let diag = sb.feature_diagnostics_v1();

        assert_eq!(
            format!("{diag}"),
            "compat=HAS_JOURNAL|EXT_ATTR, incompat=COMPRESSION|0x40000000, \
ro_compat=SPARSE_SUPER|0x80000000; missing required: FILETYPE; unknown \
incompat: 0x40000000; unknown ro_compat: 0x80000000"
        );
    }

    // ── group_desc_offset ────────────────────────────────────────────────

    #[test]
    fn superblock_group_desc_offset_4k_block() {
        let sb = make_superblock();
        // For 4K blocks: GDT starts at block 1 = byte 4096
        let off = sb.group_desc_offset(ffs_types::GroupNumber(0));
        assert_eq!(off, Some(4096));
    }

    #[test]
    fn superblock_group_desc_offset_1k_block() {
        let mut sb = make_superblock();
        sb.block_size = 1024;
        sb.cluster_size = 1024;
        sb.first_data_block = 1;
        // For 1K blocks: GDT starts at block 2 = byte 2048
        let off = sb.group_desc_offset(ffs_types::GroupNumber(0));
        assert_eq!(off, Some(2048));
    }

    #[test]
    fn superblock_group_desc_offset_second_group() {
        let sb = make_superblock();
        // group 1 offset = 4096 + 1 * 32 = 4128
        let off = sb.group_desc_offset(ffs_types::GroupNumber(1));
        assert_eq!(off, Some(4096 + 32));
    }

    // ── inode_table_offset ───────────────────────────────────────────────

    #[test]
    fn superblock_inode_table_offset_root_inode() {
        let sb = make_superblock();
        let (group, index, byte_offset) = sb.inode_table_offset(ffs_types::InodeNumber::ROOT);
        assert_eq!(group, ffs_types::GroupNumber(0));
        // inode 2: index = (2 - 1) % 2048 = 1
        assert_eq!(index, 1);
        assert_eq!(byte_offset, 256); // index * inode_size
    }

    #[test]
    fn superblock_inode_table_offset_first_inode() {
        let sb = make_superblock();
        let (group, index, byte_offset) = sb.inode_table_offset(ffs_types::InodeNumber(1));
        assert_eq!(group, ffs_types::GroupNumber(0));
        assert_eq!(index, 0);
        assert_eq!(byte_offset, 0);
    }

    // ── locate_inode ─────────────────────────────────────────────────────

    #[test]
    fn superblock_locate_inode_root() {
        let sb = make_superblock();
        let loc = sb
            .locate_inode(ffs_types::InodeNumber::ROOT)
            .expect("valid inode");
        assert_eq!(loc.group, ffs_types::GroupNumber(0));
        assert_eq!(loc.index, 1);
        assert_eq!(loc.offset_in_table, 256);
    }

    #[test]
    fn superblock_locate_inode_rejects_zero() {
        let sb = make_superblock();
        assert!(sb.locate_inode(ffs_types::InodeNumber(0)).is_err());
    }

    #[test]
    fn superblock_locate_inode_rejects_out_of_range() {
        let sb = make_superblock();
        assert!(sb.locate_inode(ffs_types::InodeNumber(9999)).is_err());
    }

    #[test]
    fn superblock_locate_inode_max_valid() {
        let sb = make_superblock();
        // inodes_count = 2048, so inode 2048 is valid
        let loc = sb
            .locate_inode(ffs_types::InodeNumber(2048))
            .expect("valid inode");
        assert_eq!(loc.group, ffs_types::GroupNumber(0));
        assert_eq!(loc.index, 2047);
        assert_eq!(loc.offset_in_table, 2047 * 256);
    }

    // ── inode_device_offset ──────────────────────────────────────────────

    #[test]
    fn superblock_inode_device_offset_basic() {
        let sb = make_superblock();
        let loc = sb
            .locate_inode(ffs_types::InodeNumber::ROOT)
            .expect("valid");
        // inode_table starts at block 100 → byte 100 * 4096 = 409600
        let dev_off = sb.inode_device_offset(&loc, 100).expect("valid");
        assert_eq!(dev_off, 100 * 4096 + 256);
    }

    #[test]
    fn superblock_inode_device_offset_first_inode() {
        let sb = make_superblock();
        let loc = InodeLocation {
            group: ffs_types::GroupNumber(0),
            index: 0,
            offset_in_table: 0,
        };
        let dev_off = sb.inode_device_offset(&loc, 50).expect("valid");
        assert_eq!(dev_off, 50 * 4096);
    }

    // ── parse_from_image ─────────────────────────────────────────────────

    #[test]
    fn superblock_parse_from_image_rejects_too_short() {
        // Image must be at least 1024 + 1024 = 2048 bytes
        let image = vec![0_u8; 2000];
        assert!(Ext4Superblock::parse_from_image(&image).is_err());
    }

    #[test]
    fn superblock_parse_from_image_rejects_empty() {
        assert!(Ext4Superblock::parse_from_image(&[]).is_err());
    }

    // ══════════════════════════════════════════════════════════════════════
    //  Checksum verification function tests
    // ══════════════════════════════════════════════════════════════════════

    // ── verify_inode_checksum ────────────────────────────────────────────

    #[test]
    fn verify_inode_checksum_rejects_short_input() {
        assert!(verify_inode_checksum(&[0; 64], 0, 2, 256).is_err());
    }

    #[test]
    fn verify_inode_checksum_rejects_inode_size_too_small() {
        let buf = vec![0_u8; 256];
        assert!(verify_inode_checksum(&buf, 0, 2, 64).is_err());
    }

    #[test]
    fn verify_inode_checksum_rejects_buffer_shorter_than_inode_size() {
        let buf = vec![0_u8; 128];
        assert!(verify_inode_checksum(&buf, 0, 2, 256).is_err());
    }

    #[test]
    fn verify_inode_checksum_round_trip() {
        // Build a 256-byte inode and manually stamp the checksum
        let mut raw = vec![0_u8; 256];
        // generation at 0x64
        raw[0x64..0x68].copy_from_slice(&42_u32.to_le_bytes());
        // extra_isize at 0x80 = 32 (standard)
        raw[0x80..0x82].copy_from_slice(&32_u16.to_le_bytes());

        let csum_seed = 0x1234_5678_u32;
        let ino = 11_u32;

        // Compute the correct checksum (mirroring the verification algorithm)
        let le_ino = ino.to_le_bytes();
        let ino_seed = ext4_chksum(csum_seed, &le_ino);
        let le_gen = 42_u32.to_le_bytes();
        let ino_seed = ext4_chksum(ino_seed, &le_gen);

        // Clear checksum fields before computing
        raw[0x7C..0x7E].copy_from_slice(&0_u16.to_le_bytes());
        raw[0x82..0x84].copy_from_slice(&0_u16.to_le_bytes());

        // CRC: bytes [0..0x7C], then zeros for checksum_lo, then [0x7E..128]
        let mut csum = ext4_chksum(ino_seed, &raw[..0x7C]);
        csum = ext4_chksum(csum, &[0, 0]);
        csum = ext4_chksum(csum, &raw[0x7E..128]);
        // Extended: [128..0x82], then zeros for checksum_hi, then [0x84..256]
        csum = ext4_chksum(csum, &raw[128..0x82]);
        csum = ext4_chksum(csum, &[0, 0]);
        csum = ext4_chksum(csum, &raw[0x84..256]);

        // Store checksum_lo and checksum_hi
        let csum_lo = (csum & 0xFFFF) as u16;
        let csum_hi = ((csum >> 16) & 0xFFFF) as u16;
        raw[0x7C..0x7E].copy_from_slice(&csum_lo.to_le_bytes());
        raw[0x82..0x84].copy_from_slice(&csum_hi.to_le_bytes());

        // Verify should pass
        assert!(verify_inode_checksum(&raw, csum_seed, ino, 256).is_ok());
    }

    #[test]
    fn verify_inode_checksum_detects_corruption() {
        // Build a valid checksummed inode, then corrupt a byte
        let mut raw = vec![0_u8; 256];
        raw[0x64..0x68].copy_from_slice(&1_u32.to_le_bytes()); // generation
        raw[0x80..0x82].copy_from_slice(&32_u16.to_le_bytes()); // extra_isize

        let csum_seed = 0_u32;
        let ino = 5_u32;

        let le_ino = ino.to_le_bytes();
        let ino_seed = ext4_chksum(csum_seed, &le_ino);
        let le_gen = 1_u32.to_le_bytes();
        let ino_seed = ext4_chksum(ino_seed, &le_gen);

        raw[0x7C..0x7E].copy_from_slice(&0_u16.to_le_bytes());
        raw[0x82..0x84].copy_from_slice(&0_u16.to_le_bytes());

        let mut csum = ext4_chksum(ino_seed, &raw[..0x7C]);
        csum = ext4_chksum(csum, &[0, 0]);
        csum = ext4_chksum(csum, &raw[0x7E..128]);
        csum = ext4_chksum(csum, &raw[128..0x82]);
        csum = ext4_chksum(csum, &[0, 0]);
        csum = ext4_chksum(csum, &raw[0x84..256]);

        let csum_lo = (csum & 0xFFFF) as u16;
        let csum_hi = ((csum >> 16) & 0xFFFF) as u16;
        raw[0x7C..0x7E].copy_from_slice(&csum_lo.to_le_bytes());
        raw[0x82..0x84].copy_from_slice(&csum_hi.to_le_bytes());

        // Corrupt byte 0 (mode field)
        raw[0] ^= 0xFF;
        assert!(verify_inode_checksum(&raw, csum_seed, ino, 256).is_err());
    }

    // ── verify_dir_block_checksum ────────────────────────────────────────

    #[test]
    fn verify_dir_block_checksum_rejects_short_input() {
        assert!(verify_dir_block_checksum(&[0; 8], 0, 2, 0).is_err());
    }

    #[test]
    fn verify_dir_block_checksum_round_trip() {
        let bs = 4096;
        let mut block = vec![0_u8; bs];

        let csum_seed = 0xABCD_EF01_u32;
        let ino = 2_u32;
        let generation = 10_u32;

        // Build the tail structure at the end (12 bytes)
        let tail_start = bs - 12;
        // det_reserved_zero1 (inode=0): already zero
        // det_rec_len = 12
        block[tail_start + 4..tail_start + 6].copy_from_slice(&12_u16.to_le_bytes());
        // det_reserved_zero2 (name_len=0): already zero
        // det_reserved_ft = 0xDE
        block[tail_start + 7] = 0xDE;

        // Compute the checksum
        let seed = ext4_chksum(csum_seed, &ino.to_le_bytes());
        let seed = ext4_chksum(seed, &generation.to_le_bytes());
        let computed = ext4_chksum(seed, &block[..bs - 12]);

        // Store checksum at block_size - 4
        block[bs - 4..bs].copy_from_slice(&computed.to_le_bytes());

        assert!(verify_dir_block_checksum(&block, csum_seed, ino, generation).is_ok());
    }

    #[test]
    fn verify_dir_block_checksum_detects_corruption() {
        let bs = 4096;
        let mut block = vec![0_u8; bs];

        let csum_seed = 0_u32;
        let ino = 3_u32;
        let generation = 0_u32;

        let seed = ext4_chksum(csum_seed, &ino.to_le_bytes());
        let seed = ext4_chksum(seed, &generation.to_le_bytes());
        let computed = ext4_chksum(seed, &block[..bs - 12]);
        block[bs - 4..bs].copy_from_slice(&computed.to_le_bytes());

        // Corrupt a directory entry byte
        block[0] = 0xFF;
        assert!(verify_dir_block_checksum(&block, csum_seed, ino, generation).is_err());
    }

    // ── verify_extent_block_checksum ─────────────────────────────────────

    #[test]
    fn verify_extent_block_checksum_rejects_short_input() {
        assert!(verify_extent_block_checksum(&[0; 12], 0, 2, 0).is_err());
    }

    #[test]
    fn verify_extent_block_checksum_round_trip() {
        // Build a minimal extent block: header (12 bytes) + eh_max=2 entries
        // tail_off = 12 + 12 * 2 = 36
        let block_len = 36 + 4; // extent data + checksum tail
        let mut block = vec![0_u8; block_len];

        // Extent header
        block[0..2].copy_from_slice(&0xF30A_u16.to_le_bytes()); // magic
        block[2..4].copy_from_slice(&0_u16.to_le_bytes()); // entries = 0
        block[4..6].copy_from_slice(&2_u16.to_le_bytes()); // max_entries = 2
        block[6..8].copy_from_slice(&0_u16.to_le_bytes()); // depth = 0

        let csum_seed = 0x5555_5555_u32;
        let ino = 100_u32;
        let generation = 7_u32;

        let seed = ext4_chksum(csum_seed, &ino.to_le_bytes());
        let seed = ext4_chksum(seed, &generation.to_le_bytes());
        let tail_off = 12 + 12 * 2; // 36
        let computed = ext4_chksum(seed, &block[..tail_off]);
        block[tail_off..tail_off + 4].copy_from_slice(&computed.to_le_bytes());

        assert!(verify_extent_block_checksum(&block, csum_seed, ino, generation).is_ok());
    }

    #[test]
    fn verify_extent_block_checksum_detects_corruption() {
        let block_len = 36 + 4;
        let mut block = vec![0_u8; block_len];
        block[0..2].copy_from_slice(&0xF30A_u16.to_le_bytes());
        block[2..4].copy_from_slice(&0_u16.to_le_bytes());
        block[4..6].copy_from_slice(&2_u16.to_le_bytes());
        block[6..8].copy_from_slice(&0_u16.to_le_bytes());

        let csum_seed = 0_u32;
        let ino = 50_u32;
        let generation = 0_u32;

        let seed = ext4_chksum(csum_seed, &ino.to_le_bytes());
        let seed = ext4_chksum(seed, &generation.to_le_bytes());
        let tail_off = 36;
        let computed = ext4_chksum(seed, &block[..tail_off]);
        block[tail_off..tail_off + 4].copy_from_slice(&computed.to_le_bytes());

        // Corrupt a header byte
        block[2] = 0xFF;
        assert!(verify_extent_block_checksum(&block, csum_seed, ino, generation).is_err());
    }

    #[test]
    fn verify_extent_block_checksum_rejects_eh_max_overflow() {
        // eh_max so large that tail_off overflows available space
        let mut block = vec![0_u8; 64];
        block[0..2].copy_from_slice(&0xF30A_u16.to_le_bytes());
        block[4..6].copy_from_slice(&1000_u16.to_le_bytes()); // eh_max=1000
        assert!(verify_extent_block_checksum(&block, 0, 1, 0).is_err());
    }
}
