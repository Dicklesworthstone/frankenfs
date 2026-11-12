#![no_main]

use ffs_ondisk::Ext4Inode;
use ffs_xattr::{
    get_xattr_for_access, list_xattrs, list_xattrs_for_access, parse_xattr_name, remove_xattr,
    set_xattr, XattrReadAccess, XattrWriteAccess,
};
use libfuzzer_sys::fuzz_target;
use std::collections::{BTreeMap, BTreeSet};

const INLINE_IBODY_LEN: usize = 160;
const EXTERNAL_BLOCK_LEN: usize = 4096;
const MAX_SUFFIX_LEN: usize = 48;
const MAX_VALUE_LEN: usize = 256;
const MAX_ENTRIES: usize = 8;

struct ByteCursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn next_u8(&mut self) -> u8 {
        let value = self.data.get(self.pos).copied().unwrap_or(0);
        self.pos = self.pos.saturating_add(1);
        value
    }

    fn next_index(&mut self, len: usize) -> usize {
        if len == 0 {
            0
        } else {
            usize::from(self.next_u8()) % len
        }
    }
}

fn make_inode(ibody_len: usize) -> Ext4Inode {
    Ext4Inode {
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
        extra_isize: 32,
        checksum: 0,
        version_hi: 0,
        projid: 0,
        extent_bytes: vec![0; 60].into(),
        xattr_ibody: vec![0; ibody_len],
        number: 0,
    }
}

fn sanitize_suffix(bytes: &[u8]) -> String {
    let mut suffix = String::new();
    for &byte in bytes.iter().take(MAX_SUFFIX_LEN) {
        let ch = char::from(b'a' + (byte % 26));
        suffix.push(ch);
    }
    if suffix.is_empty() {
        suffix.push('x');
    }
    suffix
}

fn build_name(cursor: &mut ByteCursor<'_>) -> String {
    let suffix_len = cursor.next_index(MAX_SUFFIX_LEN + 1);
    let mut raw_suffix = Vec::with_capacity(suffix_len);
    for _ in 0..suffix_len {
        raw_suffix.push(cursor.next_u8());
    }
    let suffix = sanitize_suffix(&raw_suffix);

    match cursor.next_u8() % 9 {
        0 => format!("user.{suffix}"),
        1 => format!("trusted.{suffix}"),
        2 => format!("security.{suffix}"),
        3 => format!("system.{suffix}"),
        4 => "system.posix_acl_access".to_owned(),
        5 => "system.posix_acl_default".to_owned(),
        6 => "system.richacl".to_owned(),
        7 => format!("user{}", suffix),
        _ => "user.".to_owned(),
    }
}

fn build_value(cursor: &mut ByteCursor<'_>) -> Vec<u8> {
    let len = cursor.next_index(MAX_VALUE_LEN + 1);
    (0..len).map(|_| cursor.next_u8()).collect()
}

fn is_default_visible(name: &str) -> bool {
    !name.starts_with("trusted.")
}

fn normalize_parse(result: ffs_error::Result<(u8, Vec<u8>)>) -> Result<(u8, Vec<u8>), String> {
    result.map_err(|err| err.to_string())
}

fn normalize_list(result: ffs_error::Result<Vec<String>>) -> Result<Vec<String>, String> {
    result.map_err(|err| err.to_string())
}

fn normalize_get(result: ffs_error::Result<Option<Vec<u8>>>) -> Result<Option<Vec<u8>>, String> {
    result.map_err(|err| err.to_string())
}

fn normalize_remove(result: ffs_error::Result<bool>) -> Result<bool, String> {
    result.map_err(|err| err.to_string())
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = ByteCursor::new(data);
    let entry_count = 1 + cursor.next_index(MAX_ENTRIES);

    let mut inode = make_inode(INLINE_IBODY_LEN);
    let mut external_block = vec![0_u8; EXTERNAL_BLOCK_LEN];
    let admin = XattrWriteAccess {
        is_owner: true,
        has_cap_fowner: true,
        has_cap_sys_admin: true,
    };
    let admin_read = XattrReadAccess {
        has_cap_sys_admin: true,
    };

    let mut expected_default = BTreeSet::new();
    let mut expected_admin = BTreeSet::new();
    let mut expected_values = BTreeMap::new();

    for _ in 0..entry_count {
        let full_name = build_name(&mut cursor);

        let parsed_first = normalize_parse(parse_xattr_name(&full_name));
        let parsed_second = normalize_parse(parse_xattr_name(&full_name));
        assert_eq!(
            parsed_first, parsed_second,
            "xattr name parsing must be deterministic"
        );

        if parsed_first.is_ok() {
            let value = build_value(&mut cursor);
            if set_xattr(
                &mut inode,
                Some(&mut external_block),
                &full_name,
                &value,
                admin,
            )
            .is_ok()
            {
                expected_values.insert(full_name.clone(), value);
                expected_admin.insert(full_name.clone());
                if is_default_visible(&full_name) {
                    expected_default.insert(full_name);
                }
            }
        }
    }

    let default_names_first = normalize_list(list_xattrs(&inode, Some(&external_block)));
    let default_names_second = normalize_list(list_xattrs(&inode, Some(&external_block)));
    assert_eq!(
        default_names_first, default_names_second,
        "default xattr listing must be deterministic"
    );

    let admin_names_first = normalize_list(list_xattrs_for_access(
        &inode,
        Some(&external_block),
        admin_read,
    ));
    let admin_names_second = normalize_list(list_xattrs_for_access(
        &inode,
        Some(&external_block),
        admin_read,
    ));
    assert_eq!(
        admin_names_first, admin_names_second,
        "admin xattr listing must be deterministic"
    );

    if let Ok(default_names) = default_names_first {
        let actual_default: BTreeSet<String> = default_names.into_iter().collect();
        assert_eq!(
            actual_default, expected_default,
            "default xattr listing should match the successfully stored visible names"
        );
    }

    if let Ok(admin_names) = admin_names_first {
        let actual_admin: BTreeSet<String> = admin_names.into_iter().collect();
        assert_eq!(
            actual_admin, expected_admin,
            "admin xattr listing should match all successfully stored names"
        );
    }

    for (name, value) in &expected_values {
        let admin_get_first = normalize_get(get_xattr_for_access(
            &inode,
            Some(&external_block),
            name,
            admin_read,
        ));
        let admin_get_second = normalize_get(get_xattr_for_access(
            &inode,
            Some(&external_block),
            name,
            admin_read,
        ));
        assert_eq!(
            admin_get_first, admin_get_second,
            "admin xattr get path must be deterministic"
        );
        assert_eq!(
            admin_get_first,
            Ok(Some(value.clone())),
            "admin xattr get should return the last successfully stored value"
        );

        let default_get = normalize_get(get_xattr_for_access(
            &inode,
            Some(&external_block),
            name,
            XattrReadAccess::default(),
        ));
        let expected_default_value = if is_default_visible(name) {
            Ok(Some(value.clone()))
        } else {
            Ok(None)
        };
        assert_eq!(
            default_get, expected_default_value,
            "default xattr get visibility should match default list visibility"
        );
    }

    if !expected_values.is_empty() {
        let remove_name = expected_values
            .keys()
            .nth(cursor.next_index(expected_values.len()))
            .cloned()
            .unwrap_or_default();
        let mut first_inode = inode.clone();
        let mut first_external_block = external_block.clone();
        let mut second_inode = inode.clone();
        let mut second_external_block = external_block.clone();

        let remove_first = normalize_remove(remove_xattr(
            &mut first_inode,
            Some(&mut first_external_block),
            &remove_name,
            admin,
        ));
        let remove_second = normalize_remove(remove_xattr(
            &mut second_inode,
            Some(&mut second_external_block),
            &remove_name,
            admin,
        ));
        assert_eq!(
            remove_first, remove_second,
            "xattr removal must be deterministic on identical state"
        );
        assert_eq!(
            remove_first,
            Ok(true),
            "removing a successfully stored xattr should report success"
        );

        let removed_admin = normalize_get(get_xattr_for_access(
            &first_inode,
            Some(&first_external_block),
            &remove_name,
            admin_read,
        ));
        assert_eq!(
            removed_admin,
            Ok(None),
            "removed xattr should no longer be visible to admin get"
        );

        if let Ok(names) =
            list_xattrs_for_access(&first_inode, Some(&first_external_block), admin_read)
        {
            assert!(
                !names.iter().any(|name| name == &remove_name),
                "removed xattr should no longer appear in admin listing"
            );
        }
        if is_default_visible(&remove_name) {
            if let Ok(names) = list_xattrs(&first_inode, Some(&first_external_block)) {
                assert!(
                    !names.iter().any(|name| name == &remove_name),
                    "removed xattr should no longer appear in default listing"
                );
            }
        }

        for (name, value) in expected_values
            .iter()
            .filter(|(name, _)| *name != &remove_name)
        {
            let remaining_admin = normalize_get(get_xattr_for_access(
                &first_inode,
                Some(&first_external_block),
                name,
                admin_read,
            ));
            assert_eq!(
                remaining_admin,
                Ok(Some(value.clone())),
                "removing one xattr should preserve the other stored values"
            );
        }
    }

    if inode.file_acl != 0 {
        let missing_external_first = normalize_list(list_xattrs(&inode, None));
        let missing_external_second = normalize_list(list_xattrs(&inode, None));
        assert_eq!(
            missing_external_first, missing_external_second,
            "missing-external error path must be deterministic"
        );
        assert!(
            missing_external_first.is_err(),
            "list_xattrs should fail when external xattrs exist but no block is supplied"
        );
    }
});
