#![forbid(unsafe_code)]
//! Extended attributes (xattr).
//!
//! Inline xattr storage (after inode extra fields within the inode table
//! entry) and external xattr block storage. Namespace routing for user,
//! system, security, and trusted attribute namespaces.

use ffs_error::{FfsError, Result};
use ffs_ondisk::{Ext4Inode, Ext4Xattr, parse_ibody_xattrs, parse_xattr_block};
use ffs_types::{
    EXT4_XATTR_INDEX_ENCRYPTION, EXT4_XATTR_INDEX_POSIX_ACL_ACCESS,
    EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT, EXT4_XATTR_INDEX_RICHACL, EXT4_XATTR_INDEX_SECURITY,
    EXT4_XATTR_INDEX_SYSTEM, EXT4_XATTR_INDEX_TRUSTED, EXT4_XATTR_INDEX_USER, EXT4_XATTR_MAGIC,
    ParseError, all_zero_bytes,
};

const INLINE_HEADER_LEN: usize = 4;
const EXTERNAL_HEADER_LEN: usize = 32;
const XATTR_ENTRY_HEADER_LEN: usize = 16;
const XATTR_NAME_MAX: usize = u8::MAX as usize;
const XATTR_VALUE_MAX: usize = 65_536;
const NAME_HASH_SHIFT: u32 = 5;
const VALUE_HASH_SHIFT: u32 = 16;

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn parse_to_ffs(err: &ParseError) -> FfsError {
    FfsError::Format(err.to_string())
}

fn parse_external_magic(block: &[u8]) -> Result<u32> {
    let Some(bytes) = block.get(0..4) else {
        return Err(FfsError::Format(
            "external xattr block shorter than 4-byte magic".to_owned(),
        ));
    };
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn parse_inline_entries(inode: &Ext4Inode) -> Result<Vec<Ext4Xattr>> {
    parse_ibody_xattrs(inode).map_err(|err| parse_to_ffs(&err))
}

fn parse_external_entries(block: &[u8], allow_zero_initialized: bool) -> Result<Vec<Ext4Xattr>> {
    if block.len() < EXTERNAL_HEADER_LEN {
        return Err(FfsError::Format(
            "external xattr block shorter than 32-byte header".to_owned(),
        ));
    }
    let magic = parse_external_magic(block)?;
    if magic != EXT4_XATTR_MAGIC {
        if allow_zero_initialized && all_zero_bytes(block) {
            return Ok(Vec::new());
        }
        return Err(FfsError::Format(
            "external xattr block has invalid magic".to_owned(),
        ));
    }
    parse_xattr_block(block).map_err(|err| parse_to_ffs(&err))
}

fn entry_index(entries: &[Ext4Xattr], name_index: u8, name: &[u8]) -> Option<usize> {
    entries
        .iter()
        .position(|e| e.name_index == name_index && e.name == name)
}

fn ext4_xattr_hash_step(hash: u32, shift: u32, value: u32) -> u32 {
    (hash << shift) ^ (hash >> (u32::BITS - shift)) ^ value
}

fn ext4_xattr_entry_hash(entry: &Ext4Xattr) -> u32 {
    let mut hash = 0_u32;
    for &byte in &entry.name {
        hash = ext4_xattr_hash_step(hash, NAME_HASH_SHIFT, u32::from(byte));
    }
    for chunk in entry.value.chunks(4) {
        let mut word = [0_u8; 4];
        word[..chunk.len()].copy_from_slice(chunk);
        hash = ext4_xattr_hash_step(hash, VALUE_HASH_SHIFT, u32::from_le_bytes(word));
    }
    hash
}

fn sort_external_entries(entries: &mut [Ext4Xattr]) {
    entries.sort_by(|left, right| {
        left.name_index
            .cmp(&right.name_index)
            .then(left.name.len().cmp(&right.name.len()))
            .then(left.name.cmp(&right.name))
    });
}

fn encode_entries_region(
    region_capacity: usize,
    entries: &[Ext4Xattr],
    value_offset_base: usize,
) -> Result<Vec<u8>> {
    encode_entries_region_with_hashes(region_capacity, entries, value_offset_base, false)
}

fn encode_entries_region_with_hashes(
    region_capacity: usize,
    entries: &[Ext4Xattr],
    value_offset_base: usize,
    write_entry_hashes: bool,
) -> Result<Vec<u8>> {
    let mut data = vec![0_u8; region_capacity];
    let mut next_entry = 0_usize;
    let mut value_tail = region_capacity;

    for entry in entries {
        if entry.name.len() > XATTR_NAME_MAX {
            return Err(FfsError::NameTooLong);
        }
        if entry.value.len() > XATTR_VALUE_MAX {
            return Err(FfsError::Format(
                "xattr value exceeds 65536-byte limit".to_owned(),
            ));
        }

        let entry_len = align4(
            XATTR_ENTRY_HEADER_LEN
                .checked_add(entry.name.len())
                .ok_or_else(|| FfsError::Format("xattr entry length overflow".to_owned()))?,
        );
        // For empty values there is nothing to align: aligning a zero-length
        // slice down to a 4-byte boundary would silently consume up to three
        // bytes of the values region without storing any data, eventually
        // producing spurious NoSpace errors when packing many empty xattrs.
        let value_start = if entry.value.is_empty() {
            value_tail
        } else {
            let unaligned_start = value_tail
                .checked_sub(entry.value.len())
                .ok_or(FfsError::NoSpace)?;
            unaligned_start & !3 // Align down to 4-byte boundary
        };

        let entry_end = next_entry
            .checked_add(entry_len)
            .ok_or_else(|| FfsError::Format("xattr entry offset overflow".to_owned()))?;
        let entry_end_with_term = entry_end
            .checked_add(4)
            .ok_or_else(|| FfsError::Format("xattr terminator offset overflow".to_owned()))?;
        if entry_end_with_term > value_start {
            return Err(FfsError::NoSpace);
        }

        data[value_start..value_start + entry.value.len()].copy_from_slice(&entry.value);
        value_tail = value_start;

        let value_offset = value_start
            .checked_add(value_offset_base)
            .ok_or_else(|| FfsError::Format("xattr value offset overflow".to_owned()))?;
        data[next_entry] = u8::try_from(entry.name.len()).map_err(|_| FfsError::NameTooLong)?;
        data[next_entry + 1] = entry.name_index;
        data[next_entry + 2..next_entry + 4].copy_from_slice(
            &u16::try_from(value_offset)
                .map_err(|_| FfsError::Format("xattr value offset exceeds u16".to_owned()))?
                .to_le_bytes(),
        );
        // e_value_block / e_value_inum is 0
        data[next_entry + 4..next_entry + 8].copy_from_slice(&0_u32.to_le_bytes());
        // e_value_size is at offset 8
        data[next_entry + 8..next_entry + 12].copy_from_slice(
            &u32::try_from(entry.value.len())
                .map_err(|_| FfsError::Format("xattr value size exceeds u32".to_owned()))?
                .to_le_bytes(),
        );
        let entry_hash = if write_entry_hashes {
            ext4_xattr_entry_hash(entry)
        } else {
            0
        };
        data[next_entry + 12..next_entry + 16].copy_from_slice(&entry_hash.to_le_bytes());

        data[next_entry + XATTR_ENTRY_HEADER_LEN
            ..next_entry + XATTR_ENTRY_HEADER_LEN + entry.name.len()]
            .copy_from_slice(&entry.name);

        next_entry = entry_end;
    }

    Ok(data)
}

fn build_inline_ibody(ibody_len: usize, entries: &[Ext4Xattr]) -> Result<Vec<u8>> {
    // Mirror parse_ibody_xattrs: an ibody too small for the 4-byte header
    // simply has no inline xattrs. Refuse only when the caller asks us to
    // *write* entries into a region that cannot hold them — that is a
    // capacity failure, not a format failure.
    if ibody_len < INLINE_HEADER_LEN {
        if entries.is_empty() {
            return Ok(vec![0_u8; ibody_len]);
        }
        return Err(FfsError::NoSpace);
    }

    let mut out = vec![0_u8; ibody_len];
    if entries.is_empty() {
        return Ok(out);
    }

    out[0..4].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());
    let encoded = encode_entries_region(ibody_len - INLINE_HEADER_LEN, entries, 0)?;
    out[INLINE_HEADER_LEN..].copy_from_slice(&encoded);
    Ok(out)
}

fn build_inline_ibody_for_inode_state(
    ibody_len: usize,
    entries: &[Ext4Xattr],
    has_external_xattrs: bool,
) -> Result<Vec<u8>> {
    let mut out = build_inline_ibody(ibody_len, entries)?;
    if entries.is_empty() && has_external_xattrs && ibody_len >= INLINE_HEADER_LEN {
        out[0..INLINE_HEADER_LEN].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());
    }
    Ok(out)
}

/// Borrowed-slice wrapper: clones to get a sortable owned `Vec`.
///
/// `#[cfg(test)]` because it has no production callers left (bd-3ao0l found it via
/// clippy's `dead_code`). All four owning setxattr/removexattr callers moved to
/// `build_external_block_owned` to skip this deep clone, which is the whole point
/// of that split. It is kept, rather than removed, as the REFERENCE
/// implementation the owned variant is differentially tested against — the owned
/// one is a perf lever whose claim of byte-identical output was otherwise
/// unverified.
#[cfg(test)]
fn build_external_block(block_len: usize, entries: &[Ext4Xattr]) -> Result<Vec<u8>> {
    build_external_block_owned(block_len, entries.to_vec())
}

/// Owned-entries variant: sorts the caller's `Vec` IN PLACE before encoding.
///
/// No `entries.to_vec()` deep clone of every name+value. The four production
/// setxattr/removexattr callers own their `external_entries` and do not reuse it,
/// so they hand it over here. Byte-identical output to the borrowed
/// `build_external_block` wrapper — same sort key, same encoding — which
/// `build_external_block_matches_the_owned_variant_byte_for_byte` verifies.
fn build_external_block_owned(block_len: usize, mut entries: Vec<Ext4Xattr>) -> Result<Vec<u8>> {
    if block_len < EXTERNAL_HEADER_LEN {
        return Err(FfsError::Format(
            "external xattr block shorter than 32-byte header".to_owned(),
        ));
    }

    let mut out = vec![0_u8; block_len];
    if entries.is_empty() {
        return Ok(out);
    }

    sort_external_entries(&mut entries);
    let sorted_entries = entries;

    out[0..4].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());
    out[4..8].copy_from_slice(&1_u32.to_le_bytes()); // h_refcount
    out[8..12].copy_from_slice(&1_u32.to_le_bytes()); // h_blocks
    // e2fsprogs/debugfs leaves h_hash unset when writing fresh EA blocks.
    out[12..16].copy_from_slice(&0_u32.to_le_bytes());

    let encoded = encode_entries_region_with_hashes(
        block_len - EXTERNAL_HEADER_LEN,
        &sorted_entries,
        EXTERNAL_HEADER_LEN,
        true,
    )?;
    out[EXTERNAL_HEADER_LEN..].copy_from_slice(&encoded);
    Ok(out)
}

fn ext4_name_index_from_full_name(full_name: &str) -> Result<(u8, &[u8])> {
    if let Some(name) = full_name.strip_prefix("user.") {
        if name.is_empty() {
            return Err(FfsError::Format(
                "xattr name after user. cannot be empty".to_owned(),
            ));
        }
        return Ok((EXT4_XATTR_INDEX_USER, name.as_bytes()));
    }

    if let Some(name) = full_name.strip_prefix("trusted.") {
        if name.is_empty() {
            return Err(FfsError::Format(
                "xattr name after trusted. cannot be empty".to_owned(),
            ));
        }
        return Ok((EXT4_XATTR_INDEX_TRUSTED, name.as_bytes()));
    }

    if let Some(name) = full_name.strip_prefix("security.") {
        if name.is_empty() {
            return Err(FfsError::Format(
                "xattr name after security. cannot be empty".to_owned(),
            ));
        }
        return Ok((EXT4_XATTR_INDEX_SECURITY, name.as_bytes()));
    }

    if full_name == "system.posix_acl_access" {
        return Ok((EXT4_XATTR_INDEX_POSIX_ACL_ACCESS, &[]));
    }
    if full_name == "system.posix_acl_default" {
        return Ok((EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT, &[]));
    }
    if full_name == "system.richacl" {
        return Ok((EXT4_XATTR_INDEX_RICHACL, &[]));
    }

    if let Some(name) = full_name.strip_prefix("system.") {
        if name.is_empty() {
            return Err(FfsError::Format(
                "xattr name after system. cannot be empty".to_owned(),
            ));
        }
        return Ok((EXT4_XATTR_INDEX_SYSTEM, name.as_bytes()));
    }

    Err(FfsError::Format(format!(
        "unsupported xattr namespace in '{full_name}'"
    )))
}

/// Permission context used for namespace write checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XattrWriteAccess {
    pub is_owner: bool,
    pub has_cap_fowner: bool,
    pub has_cap_sys_admin: bool,
}

/// Permission context used for namespace read/list checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct XattrReadAccess {
    pub has_cap_sys_admin: bool,
}

fn check_write_permissions(name_index: u8, access: XattrWriteAccess) -> Result<()> {
    let user_allowed = access.is_owner || access.has_cap_fowner || access.has_cap_sys_admin;
    match name_index {
        EXT4_XATTR_INDEX_USER => {
            if user_allowed {
                Ok(())
            } else {
                Err(FfsError::PermissionDenied)
            }
        }
        EXT4_XATTR_INDEX_TRUSTED
        | EXT4_XATTR_INDEX_SECURITY
        | EXT4_XATTR_INDEX_SYSTEM
        | EXT4_XATTR_INDEX_RICHACL
        | EXT4_XATTR_INDEX_POSIX_ACL_ACCESS
        | EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT => {
            if access.has_cap_sys_admin {
                Ok(())
            } else {
                Err(FfsError::PermissionDenied)
            }
        }
        _ => Err(FfsError::UnsupportedFeature(format!(
            "unsupported xattr name index: {name_index}"
        ))),
    }
}

fn can_read_name_index(name_index: u8, access: XattrReadAccess) -> bool {
    match name_index {
        EXT4_XATTR_INDEX_TRUSTED => access.has_cap_sys_admin,
        // fscrypt contexts are stored as hidden xattrs and should not surface
        // through getxattr/listxattr-style APIs.
        EXT4_XATTR_INDEX_ENCRYPTION => false,
        _ => true,
    }
}

/// Where a successful xattr mutation was stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XattrStorage {
    Inline,
    External,
}

/// Parse a full xattr name into an ext4 index and a borrowed namespace suffix.
pub fn parse_xattr_name_borrowed(full_name: &str) -> Result<(u8, &[u8])> {
    let (name_index, name) = ext4_name_index_from_full_name(full_name)?;
    if name.len() > XATTR_NAME_MAX {
        return Err(FfsError::NameTooLong);
    }
    Ok((name_index, name))
}

/// Parse a full xattr name (`user.foo`, `security.selinux`, ...) into owned ext4 components.
pub fn parse_xattr_name(full_name: &str) -> Result<(u8, Vec<u8>)> {
    let (name_index, name) = parse_xattr_name_borrowed(full_name)?;
    Ok((name_index, name.to_vec()))
}

/// Set or replace one extended attribute.
///
/// Behavior:
/// - Enforces namespace write permissions.
/// - Updates existing entries in-place in their current storage location.
/// - For new entries, tries inline storage first, then external block.
/// - If an inline update no longer fits, spills that entry to external storage.
pub fn set_xattr(
    inode: &mut Ext4Inode,
    mut external_block: Option<&mut [u8]>,
    full_name: &str,
    value: &[u8],
    access: XattrWriteAccess,
) -> Result<XattrStorage> {
    if value.len() > XATTR_VALUE_MAX {
        return Err(FfsError::Format(
            "xattr value exceeds 65536-byte limit".to_owned(),
        ));
    }

    let (name_index, name) = parse_xattr_name_borrowed(full_name)?;
    check_write_permissions(name_index, access)?;

    // get_xattr / list_xattrs / remove_xattr all refuse to operate when the
    // inode references an external xattr block but the caller did not provide
    // it. set_xattr previously skipped this check and silently treated the
    // external entries as empty, which could write a duplicate of an existing
    // attribute into the inline ibody and leave the on-disk external block
    // permanently shadowed by a divergent inline copy.
    if inode.file_acl != 0 && external_block.is_none() {
        return Err(FfsError::Format(
            "inode references external xattr block but none was provided".to_owned(),
        ));
    }

    let mut inline_entries = parse_inline_entries(inode)?;
    let mut external_entries = if let Some(block) = external_block.as_deref() {
        parse_external_entries(block, true)?
    } else {
        Vec::new()
    };

    if let Some(pos) = entry_index(&external_entries, name_index, name) {
        external_entries[pos].value.clear();
        external_entries[pos].value.extend_from_slice(value);
        let Some(block) = external_block.as_mut() else {
            return Err(FfsError::Format(
                "external xattr entries exist but no external block was provided".to_owned(),
            ));
        };
        let block = &mut **block;
        let new_block = build_external_block_owned(block.len(), external_entries)?;
        inode.xattr_ibody =
            build_inline_ibody_for_inode_state(inode.xattr_ibody.len(), &inline_entries, true)?;
        block.copy_from_slice(&new_block);
        return Ok(XattrStorage::External);
    }

    if let Some(pos) = entry_index(&inline_entries, name_index, name) {
        inline_entries[pos].value = value.to_vec();
        if let Ok(new_ibody) = build_inline_ibody(inode.xattr_ibody.len(), &inline_entries) {
            inode.xattr_ibody = new_ibody;
            return Ok(XattrStorage::Inline);
        }

        let mut inline_without_target = inline_entries;
        inline_without_target.remove(pos);
        let new_ibody = build_inline_ibody_for_inode_state(
            inode.xattr_ibody.len(),
            &inline_without_target,
            true,
        )?;

        let Some(block) = external_block.as_mut() else {
            return Err(FfsError::NoSpace);
        };
        let block = &mut **block;
        external_entries.push(Ext4Xattr {
            name_index,
            name: name.to_vec(),
            value: value.to_vec(),
        });
        let new_block = build_external_block_owned(block.len(), external_entries)?;

        inode.xattr_ibody = new_ibody;
        block.copy_from_slice(&new_block);
        return Ok(XattrStorage::External);
    }

    let mut inline_candidate = inline_entries;
    inline_candidate.push(Ext4Xattr {
        name_index,
        name: name.to_vec(),
        value: value.to_vec(),
    });
    if let Ok(new_ibody) = build_inline_ibody(inode.xattr_ibody.len(), &inline_candidate) {
        inode.xattr_ibody = new_ibody;
        return Ok(XattrStorage::Inline);
    }

    let new_entry = inline_candidate
        .pop()
        .expect("inline candidate contains the appended xattr");
    let inline_entries = inline_candidate;

    let Some(block) = external_block.as_mut() else {
        return Err(FfsError::NoSpace);
    };
    let block = &mut **block;
    external_entries.push(new_entry);
    let new_block = build_external_block_owned(block.len(), external_entries)?;
    inode.xattr_ibody =
        build_inline_ibody_for_inode_state(inode.xattr_ibody.len(), &inline_entries, true)?;
    block.copy_from_slice(&new_block);
    Ok(XattrStorage::External)
}

/// Remove one extended attribute by full name.
///
/// Returns `true` when an entry was removed.
pub fn remove_xattr(
    inode: &mut Ext4Inode,
    mut external_block: Option<&mut [u8]>,
    full_name: &str,
    access: XattrWriteAccess,
) -> Result<bool> {
    let (name_index, name) = parse_xattr_name_borrowed(full_name)?;
    check_write_permissions(name_index, access)?;

    let mut inline_entries = parse_inline_entries(inode)?;
    if let Some(pos) = entry_index(&inline_entries, name_index, name) {
        inline_entries.remove(pos);
        inode.xattr_ibody = build_inline_ibody_for_inode_state(
            inode.xattr_ibody.len(),
            &inline_entries,
            inode.file_acl != 0,
        )?;
        return Ok(true);
    }

    let Some(block) = external_block.as_mut() else {
        if inode.file_acl != 0 {
            return Err(FfsError::Format(
                "inode references external xattr block but none was provided".to_owned(),
            ));
        }
        return Ok(false);
    };
    let block = &mut **block;

    let mut external_entries = parse_external_entries(block, true)?;
    let Some(pos) = entry_index(&external_entries, name_index, name) else {
        return Ok(false);
    };
    external_entries.remove(pos);

    // Capture emptiness before handing ownership of `external_entries` to the
    // owned builder (which sorts it in place without a clone).
    let external_now_empty = external_entries.is_empty();
    if external_now_empty {
        let new_ibody =
            build_inline_ibody_for_inode_state(inode.xattr_ibody.len(), &inline_entries, false)?;
        inode.xattr_ibody = new_ibody;
        block.fill(0);
        inode.file_acl = 0;
        return Ok(true);
    }

    let new_block = build_external_block_owned(block.len(), external_entries)?;
    inode.xattr_ibody =
        build_inline_ibody_for_inode_state(inode.xattr_ibody.len(), &inline_entries, true)?;
    block.copy_from_slice(&new_block);
    Ok(true)
}

/// Whether this inode carries ANY extended attribute, in either of the two
/// places ext4 can put one.
///
/// Exists for `FFS_FUSE_XATTR_NO_SUPPORT=auto` (bd-ha71t). Suppressing the
/// kernel's per-path-op `security.capability` probe is worth `>= 4.661799x` on
/// warm stat -- it is the whole of that gap -- but the mechanism is
/// connection-wide and one-way, so it is correct ONLY on an image that carries
/// no extended attributes anywhere. Until now the operator asserted that. This
/// is the per-inode half of PROVING it instead.
///
/// Both locations must be checked and the cheap one is not enough: `file_acl`
/// points at an external xattr block, but ext4 also stores small xattrs INSIDE
/// the inode's extra space, and an inode can carry those with `file_acl == 0`.
/// Checking only `file_acl` would report an SELinux-labelled image as
/// attribute-free, which is precisely the mistake that would make the switch
/// silently wrong.
///
/// A parse error counts as PRESENT. This answer gates a one-way switch, so the
/// unreadable case must fail towards "there might be one", never towards
/// "there is none".
#[must_use]
pub fn inode_has_any_xattr(inode: &Ext4Inode) -> bool {
    if inode.file_acl != 0 {
        return true;
    }
    // `map_or`'s default is the ERROR arm: an inode whose inline area will not
    // parse counts as carrying an attribute.
    parse_inline_entries(inode).map_or(true, |entries| !entries.is_empty())
}

/// List all xattr names (`user.foo`, `security.selinux`, ...).
pub fn list_xattrs(inode: &Ext4Inode, external_block: Option<&[u8]>) -> Result<Vec<String>> {
    list_xattrs_for_access(inode, external_block, XattrReadAccess::default())
}

/// List xattr names for a specific caller view.
pub fn list_xattrs_for_access(
    inode: &Ext4Inode,
    external_block: Option<&[u8]>,
    access: XattrReadAccess,
) -> Result<Vec<String>> {
    let mut names = Vec::new();

    let inline_entries = parse_inline_entries(inode)?;
    names.extend(
        inline_entries
            .into_iter()
            .filter(|e| can_read_name_index(e.name_index, access))
            .map(|e| e.full_name()),
    );

    if inode.file_acl != 0 && external_block.is_none() {
        return Err(FfsError::Format(
            "inode references external xattr block but none was provided".to_owned(),
        ));
    }

    if let Some(block) = external_block {
        let ext_entries = parse_external_entries(block, true)?;
        names.extend(
            ext_entries
                .into_iter()
                .filter(|e| can_read_name_index(e.name_index, access))
                .map(|e| e.full_name()),
        );
    }

    Ok(names)
}

/// Get one xattr value by full name.
pub fn get_xattr(
    inode: &Ext4Inode,
    external_block: Option<&[u8]>,
    full_name: &str,
) -> Result<Option<Vec<u8>>> {
    get_xattr_for_access(inode, external_block, full_name, XattrReadAccess::default())
}

/// Get one xattr value by full name for a specific caller view.
pub fn get_xattr_for_access(
    inode: &Ext4Inode,
    external_block: Option<&[u8]>,
    full_name: &str,
    access: XattrReadAccess,
) -> Result<Option<Vec<u8>>> {
    let (name_index, name) = parse_xattr_name_borrowed(full_name)?;
    if !can_read_name_index(name_index, access) {
        return Ok(None);
    }

    let inline_entries = parse_inline_entries(inode)?;
    if let Some(entry) = inline_entries
        .iter()
        .find(|e| e.name_index == name_index && e.name.as_slice() == name)
    {
        return Ok(Some(entry.value.clone()));
    }

    if inode.file_acl != 0 && external_block.is_none() {
        return Err(FfsError::Format(
            "inode references external xattr block but none was provided".to_owned(),
        ));
    }

    if let Some(block) = external_block {
        let external_entries = parse_external_entries(block, true)?;
        if let Some(entry) = external_entries
            .iter()
            .find(|e| e.name_index == name_index && e.name.as_slice() == name)
        {
            return Ok(Some(entry.value.clone()));
        }
    }

    Ok(None)
}

/// Existence-only probe for `setxattr`'s `XATTR_CREATE`/`XATTR_REPLACE` mode
/// check.
///
/// `setxattr` only needs to know whether an attribute is *present*, not its
/// value. The old path called [`get_xattr_for_access`], which materialized
/// *every* inline + external entry (a name+value `Vec` allocation each) just to
/// take `is_some()`. This returns the identical observable answer — same name
/// parse, same [`can_read_name_index`] access gate, same inline-first-then-
/// external probe order, same "inode references external block but none
/// provided" error — but routes through the by-name early-exit finders
/// (`find_ibody_xattr_by_name` / `find_xattr_block_value_by_name`, bd-abu3z)
/// that stop at the first match and allocate only for the one matched value,
/// turning the O(N)-allocation existence scan into O(1) (bd-dwiti).
///
/// Isomorphic to `get_xattr_for_access(..)?.is_some()`: on a well-formed xattr
/// region the early-exit finders return the same hit/miss as the materialize-
/// all scan (names are unique, ibody probed first), and the access gate +
/// external-missing error are replicated verbatim. The post-W110 getxattr path
/// already relies on this same early-exit equivalence.
pub fn xattr_exists_for_access(
    inode: &Ext4Inode,
    external_block: Option<&[u8]>,
    full_name: &str,
    access: XattrReadAccess,
) -> Result<bool> {
    let (name_index, _name) = parse_xattr_name_borrowed(full_name)?;
    if !can_read_name_index(name_index, access) {
        return Ok(false);
    }

    if ffs_ondisk::find_ibody_xattr_by_name(inode, full_name)
        .map_err(|err| parse_to_ffs(&err))?
        .is_some()
    {
        return Ok(true);
    }

    if inode.file_acl != 0 && external_block.is_none() {
        return Err(FfsError::Format(
            "inode references external xattr block but none was provided".to_owned(),
        ));
    }

    if let Some(block) = external_block
        && ffs_ondisk::find_xattr_block_value_by_name(block, full_name)
            .map_err(|err| parse_to_ffs(&err))?
            .is_some()
    {
        return Ok(true);
    }

    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `build_external_block_owned`'s doc claims it produces "Byte-identical
    /// output to `build_external_block` — same sort key, same encoding". Nothing
    /// verified that, and the borrowed wrapper had drifted to zero callers, which
    /// is how clippy's `dead_code` found it (bd-3ao0l).
    ///
    /// Keeping the wrapper and PROVING the claim is better than deleting it: the
    /// owned variant exists purely as a perf lever (it sorts in place instead of
    /// deep-cloning every name and value), and a lever whose equivalence to the
    /// obvious implementation is unproven is exactly the kind of thing this
    /// campaign is supposed to catch.
    ///
    /// Entries are supplied deliberately OUT OF ORDER and with names that collide
    /// on length but not on bytes, so a divergent sort key would show up as a
    /// different encoding rather than an identical one.
    #[test]
    fn build_external_block_matches_the_owned_variant_byte_for_byte() {
        let entries = vec![
            Ext4Xattr {
                name_index: 1,
                name: b"zulu".to_vec(),
                value: b"third".to_vec(),
            },
            Ext4Xattr {
                name_index: 1,
                name: b"alfa".to_vec(),
                value: b"first-value".to_vec(),
            },
            Ext4Xattr {
                name_index: 7,
                name: b"alfa".to_vec(),
                value: b"same-name-other-index".to_vec(),
            },
            Ext4Xattr {
                name_index: 1,
                name: b"mike".to_vec(),
                value: Vec::new(),
            },
        ];

        for block_len in [256_usize, 1024, 4096] {
            let borrowed = build_external_block(block_len, &entries)
                .expect("borrowed variant encodes the block");
            let owned = build_external_block_owned(block_len, entries.clone())
                .expect("owned variant encodes the block");
            assert_eq!(
                borrowed, owned,
                "the two encoders must agree byte-for-byte at block_len {block_len}"
            );
            assert_eq!(borrowed.len(), block_len, "encoded block fills block_len");
        }
    }

    /// The borrowed wrapper must not mutate the caller's slice. It clones before
    /// sorting; the owned variant sorts in place, which is the whole point of the
    /// split, so a wrapper that accidentally sorted through the borrow would be a
    /// silent aliasing bug for every non-owning caller.
    #[test]
    fn build_external_block_leaves_the_callers_entries_untouched() {
        let entries = vec![
            Ext4Xattr {
                name_index: 1,
                name: b"zulu".to_vec(),
                value: b"z".to_vec(),
            },
            Ext4Xattr {
                name_index: 1,
                name: b"alfa".to_vec(),
                value: b"a".to_vec(),
            },
        ];
        let before = entries.clone();
        let _ = build_external_block(1024, &entries).expect("encodes");
        assert_eq!(
            entries, before,
            "the borrowed wrapper must clone, never sort the caller's slice"
        );
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

    fn representative_external_block_entries() -> Vec<Ext4Xattr> {
        vec![
            Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_SECURITY,
                name: b"selinux".to_vec(),
                value: b"u:obj".to_vec(),
            },
            Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_USER,
                name: b"alpha".to_vec(),
                value: b"A".to_vec(),
            },
            Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_TRUSTED,
                name: b"zeta".to_vec(),
                value: b"trust".to_vec(),
            },
            Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_USER,
                name: b"b".to_vec(),
                value: b"bee!".to_vec(),
            },
        ]
    }

    const REPRESENTATIVE_EXTERNAL_BLOCK_GOLDEN: &str = concat!(
        "header\n",
        "  magic=0xea020000\n",
        "  refcount=1\n",
        "  blocks=1\n",
        "  block_hash=0x00000000\n",
        "  terminator_offset=120\n",
        "entries\n",
        "  [0] offset=32 name_index=1 name=user.b value_off=252 value_size=4 hash=0x21076562\n",
        "  [1] offset=52 name_index=1 name=user.alpha value_off=248 value_size=1 hash=0xcd610666\n",
        "  [2] offset=76 name_index=4 name=trusted.zeta value_off=240 value_size=5 hash=0x7248e9e0\n",
        "  [3] offset=96 name_index=6 name=security.selinux value_off=232 value_size=5 hash=0x368054c1\n",
        "parsed\n",
        "  user.b=[62, 65, 65, 21]\n",
        "  user.alpha=[41]\n",
        "  trusted.zeta=[74, 72, 75, 73, 74]\n",
        "  security.selinux=[75, 3a, 6f, 62, 6a]\n",
        "entry_region_prefix=[01, 01, fc, 00, 00, 00, 00, 00, 04, 00, 00, 00, 62, 65, 07, 21, 62, 00, 00, 00, 05, 01, f8, 00, 00, 00, 00, 00, 01, 00, 00, 00, 66, 06, 61, cd, 61, 6c, 70, 68, 61, 00, 00, 00, 04, 04, f0, 00, 00, 00, 00, 00, 05, 00, 00, 00, e0, e9, 48, 72, 7a, 65, 74, 61, 07, 06, e8, 00, 00, 00, 00, 00, 05, 00, 00, 00, c1, 54, 80, 36, 73, 65, 6c, 69, 6e, 75, 78, 00, 00, 00, 00, 00, 00, 00, 00, 00]\n",
        "value_region_tail=[00, 00, 00, 00, 00, 00, 00, 00, 75, 3a, 6f, 62, 6a, 00, 00, 00, 74, 72, 75, 73, 74, 00, 00, 00, 41, 00, 00, 00, 62, 65, 65, 21]"
    );

    fn representative_external_block_golden_contract_actual() -> String {
        let block = build_external_block(256, &representative_external_block_entries())
            .expect("build representative external xattr block");
        let parsed =
            parse_external_entries(&block, false).expect("parse representative external block");

        let mut offset = EXTERNAL_HEADER_LEN;
        let mut entry_lines = Vec::new();
        let mut entry_idx = 0_usize;
        while offset + 4 <= block.len() {
            let name_len = usize::from(block[offset]);
            let name_index = block[offset + 1];
            if name_len == 0 && name_index == 0 {
                break;
            }

            let value_off = u16::from_le_bytes([block[offset + 2], block[offset + 3]]);
            let value_size = u32::from_le_bytes([
                block[offset + 8],
                block[offset + 9],
                block[offset + 10],
                block[offset + 11],
            ]);
            let hash = u32::from_le_bytes([
                block[offset + 12],
                block[offset + 13],
                block[offset + 14],
                block[offset + 15],
            ]);
            let name = block
                [offset + XATTR_ENTRY_HEADER_LEN..offset + XATTR_ENTRY_HEADER_LEN + name_len]
                .to_vec();
            let full_name = Ext4Xattr {
                name_index,
                name,
                value: Vec::new(),
            }
            .full_name();
            entry_lines.push(format!(
                "  [{entry_idx}] offset={offset} name_index={name_index} name={full_name} value_off={value_off} value_size={value_size} hash=0x{hash:08x}"
            ));

            offset += align4(XATTR_ENTRY_HEADER_LEN + name_len);
            entry_idx += 1;
        }

        let parsed_lines = parsed
            .iter()
            .map(|entry| format!("  {}={:02x?}", entry.full_name(), entry.value))
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            concat!(
                "header\n",
                "  magic=0x{:08x}\n",
                "  refcount={}\n",
                "  blocks={}\n",
                "  block_hash=0x{:08x}\n",
                "  terminator_offset={}\n",
                "entries\n",
                "{}\n",
                "parsed\n",
                "{}\n",
                "entry_region_prefix={:02x?}\n",
                "value_region_tail={:02x?}"
            ),
            u32::from_le_bytes([block[0], block[1], block[2], block[3]]),
            u32::from_le_bytes([block[4], block[5], block[6], block[7]]),
            u32::from_le_bytes([block[8], block[9], block[10], block[11]]),
            u32::from_le_bytes([block[12], block[13], block[14], block[15]]),
            offset,
            entry_lines.join("\n"),
            parsed_lines,
            &block[EXTERNAL_HEADER_LEN..EXTERNAL_HEADER_LEN + 96],
            &block[224..],
        )
    }

    #[test]
    fn parse_xattr_name_maps_namespaces() {
        let (idx_user, name_user) = parse_xattr_name("user.mime").unwrap();
        assert_eq!(idx_user, EXT4_XATTR_INDEX_USER);
        assert_eq!(name_user, b"mime".to_vec());

        let (idx_trusted, name_trusted) = parse_xattr_name("trusted.hash").unwrap();
        assert_eq!(idx_trusted, EXT4_XATTR_INDEX_TRUSTED);
        assert_eq!(name_trusted, b"hash".to_vec());

        let (idx_security, name_security) = parse_xattr_name("security.selinux").unwrap();
        assert_eq!(idx_security, EXT4_XATTR_INDEX_SECURITY);
        assert_eq!(name_security, b"selinux".to_vec());

        let (idx_acl, name_acl) = parse_xattr_name("system.posix_acl_access").unwrap();
        assert_eq!(idx_acl, EXT4_XATTR_INDEX_POSIX_ACL_ACCESS);
        assert!(name_acl.is_empty());

        let (idx_acl_default, name_acl_default) =
            parse_xattr_name("system.posix_acl_default").unwrap();
        assert_eq!(idx_acl_default, EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT);
        assert!(name_acl_default.is_empty());

        let (idx_richacl, name_richacl) = parse_xattr_name("system.richacl").unwrap();
        assert_eq!(idx_richacl, EXT4_XATTR_INDEX_RICHACL);
        assert!(name_richacl.is_empty());
    }

    #[test]
    fn parse_xattr_name_rejects_suffix_over_u8_limit() {
        let too_long = format!("user.{}", "a".repeat(XATTR_NAME_MAX + 1));
        let err = parse_xattr_name(&too_long).unwrap_err();
        assert!(matches!(err, FfsError::NameTooLong));
    }

    #[test]
    fn user_namespace_requires_owner_or_capability() {
        let mut inode = make_inode(96);
        let err = set_xattr(
            &mut inode,
            None,
            "user.test",
            b"v",
            XattrWriteAccess {
                is_owner: false,
                has_cap_fowner: false,
                has_cap_sys_admin: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::PermissionDenied));
    }

    #[test]
    fn set_get_list_remove_inline_xattr() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        let stored = set_xattr(&mut inode, None, "user.mime", b"image", access).unwrap();
        assert_eq!(stored, XattrStorage::Inline);

        let value = get_xattr(&inode, None, "user.mime").unwrap();
        assert_eq!(value, Some(b"image".to_vec()));

        let names = list_xattrs(&inode, None).unwrap();
        assert_eq!(names, vec!["user.mime".to_owned()]);

        let removed = remove_xattr(&mut inode, None, "user.mime", access).unwrap();
        assert!(removed);
        assert_eq!(get_xattr(&inode, None, "user.mime").unwrap(), None);
    }

    #[test]
    fn set_xattr_falls_back_to_external_when_inline_full() {
        let mut inode = make_inode(20);
        let mut external = vec![0_u8; 1024];
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        let stored = set_xattr(
            &mut inode,
            Some(&mut external),
            "user.payload",
            b"value",
            access,
        )
        .unwrap();
        assert_eq!(stored, XattrStorage::External);
        assert_eq!(
            u32::from_le_bytes([external[0], external[1], external[2], external[3]]),
            EXT4_XATTR_MAGIC
        );
        assert_eq!(
            get_xattr(&inode, Some(&external), "user.payload").unwrap(),
            Some(b"value".to_vec())
        );
    }

    #[test]
    fn remove_xattr_from_external_clears_block_and_pointer() {
        let mut inode = make_inode(20);
        inode.file_acl = 123;
        let mut external = vec![0_u8; 1024];
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        set_xattr(
            &mut inode,
            Some(&mut external),
            "user.payload",
            b"value",
            access,
        )
        .unwrap();
        assert!(remove_xattr(&mut inode, Some(&mut external), "user.payload", access).unwrap());
        assert_eq!(inode.file_acl, 0);
        assert!(external.iter().all(|b| *b == 0));
    }

    #[test]
    fn trusted_namespace_requires_sys_admin() {
        let mut inode = make_inode(128);
        let err = set_xattr(
            &mut inode,
            None,
            "trusted.fsmeta",
            b"v",
            XattrWriteAccess {
                is_owner: true,
                has_cap_fowner: false,
                has_cap_sys_admin: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::PermissionDenied));
    }

    #[test]
    fn system_acl_write_allowed_for_sys_admin() {
        let mut inode = make_inode(128);
        let stored = set_xattr(
            &mut inode,
            None,
            "system.posix_acl_access",
            b"acl",
            XattrWriteAccess {
                is_owner: false,
                has_cap_fowner: false,
                has_cap_sys_admin: true,
            },
        )
        .unwrap();
        assert_eq!(stored, XattrStorage::Inline);
    }

    #[test]
    fn value_size_limit_enforced() {
        let mut inode = make_inode(128);
        let too_large = vec![0_u8; XATTR_VALUE_MAX + 1];
        let err = set_xattr(
            &mut inode,
            None,
            "user.too_large",
            &too_large,
            XattrWriteAccess {
                is_owner: true,
                has_cap_fowner: false,
                has_cap_sys_admin: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn set_xattr_rejects_external_block_shorter_than_header() {
        let mut inode = make_inode(128);
        let mut short_external = vec![0_u8; EXTERNAL_HEADER_LEN - 1];
        let err = set_xattr(
            &mut inode,
            Some(&mut short_external),
            "user.key",
            b"value",
            XattrWriteAccess {
                is_owner: true,
                has_cap_fowner: false,
                has_cap_sys_admin: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn list_xattrs_rejects_corrupt_external_magic() {
        let inode = make_inode(128);
        let mut external = vec![0_u8; 1024];
        external[0] = 0x7f; // Non-zero garbage magic, not all-zero initialized.
        let err = list_xattrs(&inode, Some(&external)).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn updating_inline_xattr_spills_to_external_and_preserves_others() {
        let mut inode = make_inode(80);
        let mut external = vec![0_u8; 1024];
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        set_xattr(&mut inode, None, "user.keep", b"k", access).unwrap();
        set_xattr(&mut inode, None, "user.move", b"small", access).unwrap();

        let big_value = vec![b'Z'; 80];
        let stored = set_xattr(
            &mut inode,
            Some(&mut external),
            "user.move",
            &big_value,
            access,
        )
        .unwrap();
        assert_eq!(stored, XattrStorage::External);
        assert_eq!(
            get_xattr(&inode, Some(&external), "user.keep").unwrap(),
            Some(b"k".to_vec())
        );
        assert_eq!(
            get_xattr(&inode, Some(&external), "user.move").unwrap(),
            Some(big_value)
        );
    }

    #[test]
    fn spillover_failure_keeps_existing_inline_value_intact() {
        let mut inode = make_inode(80);
        let mut external = vec![0_u8; EXTERNAL_HEADER_LEN];
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        set_xattr(&mut inode, None, "user.move", b"old", access).unwrap();
        let err = set_xattr(
            &mut inode,
            Some(&mut external),
            "user.move",
            &[b'X'; 64],
            access,
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::NoSpace));
        assert_eq!(
            get_xattr(&inode, None, "user.move").unwrap(),
            Some(b"old".to_vec())
        );
        assert!(external.iter().all(|b| *b == 0));
    }

    #[test]
    fn remove_xattr_requires_external_block_when_file_acl_is_set() {
        let mut inode = make_inode(128);
        inode.file_acl = 42;
        let err = remove_xattr(
            &mut inode,
            None,
            "user.any",
            XattrWriteAccess {
                is_owner: true,
                has_cap_fowner: false,
                has_cap_sys_admin: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn list_xattrs_requires_external_block_when_file_acl_is_set() {
        let mut inode = make_inode(128);
        inode.file_acl = 7;

        let err = list_xattrs(&inode, None).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn get_xattr_requires_external_block_when_file_acl_is_set() {
        let mut inode = make_inode(128);
        inode.file_acl = 7;

        let err = get_xattr(&inode, None, "user.any").unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn remove_xattr_denies_user_namespace_without_privileges() {
        let mut inode = make_inode(128);
        let err = remove_xattr(
            &mut inode,
            None,
            "user.any",
            XattrWriteAccess {
                is_owner: false,
                has_cap_fowner: false,
                has_cap_sys_admin: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::PermissionDenied));
    }

    #[test]
    fn parse_external_magic_rejects_short_block() {
        let err = parse_external_magic(&[]).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn build_inline_ibody_rejects_too_short_header_region_when_writing_entries() {
        // Empty entries into a sub-header region is a no-op (mirrors
        // parse_ibody_xattrs, which returns Ok(empty)). Writing a real entry
        // into the same region is a capacity failure (NoSpace).
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: b"x".to_vec(),
            value: b"v".to_vec(),
        };
        let err =
            build_inline_ibody(INLINE_HEADER_LEN - 1, std::slice::from_ref(&entry)).unwrap_err();
        assert!(matches!(err, FfsError::NoSpace), "got {err:?}");
    }

    // ── Additional edge-case tests ───────────────────────────────────

    #[test]
    fn parse_xattr_name_rejects_unknown_namespace() {
        let err = parse_xattr_name("unknown.key").unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn parse_xattr_name_rejects_empty_after_prefix() {
        assert!(parse_xattr_name("user.").is_err());
        assert!(parse_xattr_name("trusted.").is_err());
        assert!(parse_xattr_name("security.").is_err());
        assert!(parse_xattr_name("system.").is_err());
    }

    #[test]
    fn get_xattr_returns_none_for_missing() {
        let inode = make_inode(128);
        let result = get_xattr(&inode, None, "user.nonexistent").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn remove_nonexistent_xattr_returns_false() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };
        let removed = remove_xattr(&mut inode, None, "user.nope", access).unwrap();
        assert!(!removed);
    }

    #[test]
    fn list_xattrs_empty_returns_empty() {
        let inode = make_inode(128);
        let names = list_xattrs(&inode, None).unwrap();
        assert!(names.is_empty());
    }

    #[test]
    fn set_multiple_inline_xattrs() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        set_xattr(&mut inode, None, "user.a", b"v1", access).unwrap();
        set_xattr(&mut inode, None, "user.b", b"v2", access).unwrap();

        assert_eq!(
            get_xattr(&inode, None, "user.a").unwrap(),
            Some(b"v1".to_vec())
        );
        assert_eq!(
            get_xattr(&inode, None, "user.b").unwrap(),
            Some(b"v2".to_vec())
        );

        let mut names = list_xattrs(&inode, None).unwrap();
        names.sort();
        assert_eq!(names, vec!["user.a", "user.b"]);
    }

    #[test]
    fn set_xattr_updates_existing_value() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        set_xattr(&mut inode, None, "user.key", b"old", access).unwrap();
        set_xattr(&mut inode, None, "user.key", b"new", access).unwrap();

        assert_eq!(
            get_xattr(&inode, None, "user.key").unwrap(),
            Some(b"new".to_vec())
        );

        // Should still be just one entry.
        let names = list_xattrs(&inode, None).unwrap();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn cap_fowner_allows_user_xattr_write() {
        let mut inode = make_inode(128);
        let stored = set_xattr(
            &mut inode,
            None,
            "user.test",
            b"v",
            XattrWriteAccess {
                is_owner: false,
                has_cap_fowner: true,
                has_cap_sys_admin: false,
            },
        )
        .unwrap();
        assert_eq!(stored, XattrStorage::Inline);
    }

    #[test]
    fn security_namespace_requires_sys_admin() {
        let mut inode = make_inode(128);
        let err = set_xattr(
            &mut inode,
            None,
            "security.selinux",
            b"context",
            XattrWriteAccess {
                is_owner: true,
                has_cap_fowner: true,
                has_cap_sys_admin: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::PermissionDenied));
    }

    #[test]
    fn no_inline_space_no_external_returns_error() {
        let mut inode = make_inode(0); // zero ibody space
        let err = set_xattr(
            &mut inode,
            None,
            "user.key",
            b"value",
            XattrWriteAccess {
                is_owner: true,
                has_cap_fowner: false,
                has_cap_sys_admin: false,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::NoSpace));
    }

    #[test]
    fn xattr_write_access_default_denies_all() {
        let access = XattrWriteAccess::default();
        assert!(!access.is_owner);
        assert!(!access.has_cap_fowner);
        assert!(!access.has_cap_sys_admin);
    }

    // ── Hardening edge-case tests ────────────────────────────────────

    #[test]
    fn constants_match_ext4_spec() {
        assert_eq!(INLINE_HEADER_LEN, 4);
        assert_eq!(EXTERNAL_HEADER_LEN, 32);
        assert_eq!(XATTR_ENTRY_HEADER_LEN, 16);
        assert_eq!(XATTR_NAME_MAX, 255);
        assert_eq!(XATTR_VALUE_MAX, 65_536);
    }

    #[test]
    fn align4_boundaries() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(2), 4);
        assert_eq!(align4(3), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
        assert_eq!(align4(16), 16);
        assert_eq!(align4(17), 20);
    }

    #[test]
    fn xattr_write_access_debug_clone_copy_eq() {
        let a = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: true,
        };
        let b = a; // Copy
        assert_eq!(a, b);
        let c = a; // Copy (same as clone for Copy types)
        assert_eq!(a, c);
        let _ = format!("{a:?}");

        let d = XattrWriteAccess {
            is_owner: false,
            ..a
        };
        assert_ne!(a, d);
    }

    #[test]
    fn xattr_storage_debug_clone_copy_eq() {
        let s = XattrStorage::Inline;
        let t = s; // Copy
        assert_eq!(s, t);
        assert_ne!(XattrStorage::Inline, XattrStorage::External);
        let _ = format!("{s:?}");
    }

    #[test]
    fn can_read_name_index_enforces_trusted_and_encryption_visibility() {
        let unprivileged = XattrReadAccess {
            has_cap_sys_admin: false,
        };
        let admin = XattrReadAccess {
            has_cap_sys_admin: true,
        };
        // trusted.* is readable only with CAP_SYS_ADMIN.
        assert!(!can_read_name_index(EXT4_XATTR_INDEX_TRUSTED, unprivileged));
        assert!(can_read_name_index(EXT4_XATTR_INDEX_TRUSTED, admin));
        // fscrypt encryption contexts never surface, even to an admin.
        assert!(!can_read_name_index(EXT4_XATTR_INDEX_ENCRYPTION, admin));
        // user / security / system namespaces are readable by anyone.
        assert!(can_read_name_index(EXT4_XATTR_INDEX_USER, unprivileged));
        assert!(can_read_name_index(EXT4_XATTR_INDEX_SECURITY, unprivileged));
    }

    #[test]
    fn check_write_permissions_denies_unprivileged_and_non_admin_writes() {
        // An unprivileged non-owner cannot write a user.* xattr.
        let unprivileged = XattrWriteAccess {
            is_owner: false,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };
        assert!(matches!(
            check_write_permissions(EXT4_XATTR_INDEX_USER, unprivileged),
            Err(FfsError::PermissionDenied)
        ));
        // The owner can write user.* with no capabilities.
        let owner = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };
        assert!(check_write_permissions(EXT4_XATTR_INDEX_USER, owner).is_ok());
        // But the owner cannot write trusted.* / security.* without CAP_SYS_ADMIN.
        assert!(matches!(
            check_write_permissions(EXT4_XATTR_INDEX_TRUSTED, owner),
            Err(FfsError::PermissionDenied)
        ));
        assert!(matches!(
            check_write_permissions(EXT4_XATTR_INDEX_SECURITY, owner),
            Err(FfsError::PermissionDenied)
        ));
    }

    #[test]
    fn check_write_permissions_unknown_index_returns_unsupported() {
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: true,
            has_cap_sys_admin: true,
        };
        let err = check_write_permissions(255, access).unwrap_err();
        assert!(matches!(err, FfsError::UnsupportedFeature(_)));
    }

    #[test]
    fn check_write_permissions_sys_admin_allows_all_known_indexes() {
        let access = XattrWriteAccess {
            is_owner: false,
            has_cap_fowner: false,
            has_cap_sys_admin: true,
        };
        for idx in [
            EXT4_XATTR_INDEX_USER,
            EXT4_XATTR_INDEX_TRUSTED,
            EXT4_XATTR_INDEX_SECURITY,
            EXT4_XATTR_INDEX_SYSTEM,
            EXT4_XATTR_INDEX_POSIX_ACL_ACCESS,
            EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT,
        ] {
            assert!(
                check_write_permissions(idx, access).is_ok(),
                "index {idx} should be allowed"
            );
        }
    }

    #[test]
    fn build_inline_ibody_zero_len_empty_entries_returns_empty() {
        let data = build_inline_ibody(0, &[]).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn build_inline_ibody_zero_len_with_entries_returns_no_space() {
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: b"k".to_vec(),
            value: b"v".to_vec(),
        };
        let err = build_inline_ibody(0, &[entry]).unwrap_err();
        assert!(matches!(err, FfsError::NoSpace));
    }

    #[test]
    fn build_external_block_rejects_short_block() {
        let err = build_external_block(EXTERNAL_HEADER_LEN - 1, &[]).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn parse_external_entries_all_zeros_allowed() {
        let block = vec![0_u8; 1024];
        let entries = parse_external_entries(&block, true).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_external_entries_all_zeros_rejected_without_flag() {
        let block = vec![0_u8; 1024];
        let err = parse_external_entries(&block, false).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn entry_index_finds_correct_position() {
        let entries = vec![
            Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_USER,
                name: b"alpha".to_vec(),
                value: b"a".to_vec(),
            },
            Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_USER,
                name: b"beta".to_vec(),
                value: b"b".to_vec(),
            },
            Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_TRUSTED,
                name: b"gamma".to_vec(),
                value: b"c".to_vec(),
            },
        ];
        assert_eq!(
            entry_index(&entries, EXT4_XATTR_INDEX_USER, b"alpha"),
            Some(0)
        );
        assert_eq!(
            entry_index(&entries, EXT4_XATTR_INDEX_USER, b"beta"),
            Some(1)
        );
        assert_eq!(
            entry_index(&entries, EXT4_XATTR_INDEX_TRUSTED, b"gamma"),
            Some(2)
        );
        assert_eq!(entry_index(&entries, EXT4_XATTR_INDEX_USER, b"gamma"), None);
        assert_eq!(
            entry_index(&entries, EXT4_XATTR_INDEX_TRUSTED, b"alpha"),
            None
        );
    }

    #[test]
    fn update_existing_external_entry_stays_external() {
        let mut inode = make_inode(20);
        let mut external = vec![0_u8; 1024];
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        // First set goes to external (inline too small).
        let stored = set_xattr(
            &mut inode,
            Some(&mut external),
            "user.key",
            b"value1",
            access,
        )
        .unwrap();
        assert_eq!(stored, XattrStorage::External);

        // Update the same key — should stay external.
        let stored = set_xattr(
            &mut inode,
            Some(&mut external),
            "user.key",
            b"value2",
            access,
        )
        .unwrap();
        assert_eq!(stored, XattrStorage::External);

        assert_eq!(
            get_xattr(&inode, Some(&external), "user.key").unwrap(),
            Some(b"value2".to_vec())
        );
    }

    #[test]
    fn list_xattrs_combines_inline_and_external() {
        let mut inode = make_inode(80);
        let mut external = vec![0_u8; 1024];
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        // First xattr fits inline.
        set_xattr(&mut inode, Some(&mut external), "user.a", b"v", access).unwrap();
        // Fill up inline, force next to external.
        let big = vec![b'X'; 60];
        set_xattr(&mut inode, Some(&mut external), "user.big", &big, access).unwrap();

        let mut names = list_xattrs(&inode, Some(&external)).unwrap();
        names.sort();
        assert!(names.contains(&"user.a".to_owned()));
        assert!(names.contains(&"user.big".to_owned()));
        assert_eq!(names.len(), 2);
    }

    #[test]
    fn remove_external_xattr_does_not_affect_inline() {
        let mut inode = make_inode(80);
        let mut external = vec![0_u8; 1024];
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        // Put one inline.
        set_xattr(&mut inode, Some(&mut external), "user.inline", b"i", access).unwrap();
        // Put one that spills to external.
        let big = vec![b'Y'; 60];
        set_xattr(&mut inode, Some(&mut external), "user.ext", &big, access).unwrap();

        // Remove external entry.
        let removed = remove_xattr(&mut inode, Some(&mut external), "user.ext", access).unwrap();
        assert!(removed);

        // Inline entry should still be present.
        assert_eq!(
            get_xattr(&inode, Some(&external), "user.inline").unwrap(),
            Some(b"i".to_vec())
        );
    }

    #[test]
    fn set_xattr_empty_value_allowed() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        let stored = set_xattr(&mut inode, None, "user.empty", b"", access).unwrap();
        assert_eq!(stored, XattrStorage::Inline);
        assert_eq!(
            get_xattr(&inode, None, "user.empty").unwrap(),
            Some(b"".to_vec())
        );
    }

    #[test]
    fn parse_xattr_name_system_generic() {
        let (idx, name) = parse_xattr_name("system.data").unwrap();
        assert_eq!(idx, EXT4_XATTR_INDEX_SYSTEM);
        assert_eq!(name, b"data".to_vec());
    }

    #[test]
    fn encode_entries_region_rejects_oversized_name() {
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: vec![b'a'; XATTR_NAME_MAX + 1],
            value: b"v".to_vec(),
        };
        let err = encode_entries_region(4096, &[entry], 0).unwrap_err();
        assert!(matches!(err, FfsError::NameTooLong));
    }

    #[test]
    fn encode_entries_region_rejects_oversized_value() {
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: b"k".to_vec(),
            value: vec![0_u8; XATTR_VALUE_MAX + 1],
        };
        let err = encode_entries_region(XATTR_VALUE_MAX + 100, &[entry], 0).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn encode_entries_region_no_space_when_too_small() {
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: b"key".to_vec(),
            value: b"value".to_vec(),
        };
        // Region too small to hold even one entry + value.
        let err = encode_entries_region(10, &[entry], 0).unwrap_err();
        assert!(matches!(err, FfsError::NoSpace));
    }

    // ── Proptest property-based tests ──────────────────────────────────

    use proptest::prelude::*;

    /// Generate a valid xattr suffix name (1..20 alphanumeric bytes).
    fn xattr_suffix_strategy() -> impl Strategy<Value = String> {
        prop::collection::vec(
            prop::sample::select(
                (b'a'..=b'z')
                    .chain(b'A'..=b'Z')
                    .chain(b'0'..=b'9')
                    .collect::<Vec<u8>>(),
            ),
            1..20,
        )
        .prop_map(|bytes| String::from_utf8(bytes).unwrap())
    }

    /// Generate a small xattr value (0..64 bytes).
    fn xattr_value_strategy() -> impl Strategy<Value = Vec<u8>> {
        prop::collection::vec(any::<u8>(), 0..64)
    }

    /// Generate unique external xattr entries across a few namespaces.
    fn external_xattr_entries_strategy() -> impl Strategy<Value = Vec<Ext4Xattr>> {
        prop::collection::btree_map(
            (
                prop::sample::select(vec![
                    EXT4_XATTR_INDEX_USER,
                    EXT4_XATTR_INDEX_TRUSTED,
                    EXT4_XATTR_INDEX_SECURITY,
                ]),
                xattr_suffix_strategy(),
            ),
            xattr_value_strategy(),
            1..6,
        )
        .prop_map(|entries| {
            entries
                .into_iter()
                .map(|((name_index, suffix), value)| Ext4Xattr {
                    name_index,
                    name: suffix.into_bytes(),
                    value,
                })
                .collect()
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// set_xattr followed by get_xattr always returns the set value.
        #[test]
        fn proptest_set_get_roundtrip(
            name in xattr_suffix_strategy(),
            value in xattr_value_strategy(),
        ) {
            let mut inode = make_inode(256);
            let mut external = vec![0_u8; 1024];
            let access = XattrWriteAccess { is_owner: true, ..Default::default() };
            let full_name = format!("user.{name}");

            set_xattr(&mut inode, Some(&mut external), &full_name, &value, access)
                .unwrap();
            let got = get_xattr(&inode, Some(&external), &full_name).unwrap();
            prop_assert_eq!(got, Some(value));
        }

        /// set then remove ⟹ get returns None.
        #[test]
        fn proptest_set_remove_get_none(
            name in xattr_suffix_strategy(),
            value in xattr_value_strategy(),
        ) {
            let mut inode = make_inode(256);
            let mut external = vec![0_u8; 1024];
            let access = XattrWriteAccess { is_owner: true, ..Default::default() };
            let full_name = format!("user.{name}");

            set_xattr(&mut inode, Some(&mut external), &full_name, &value, access)
                .unwrap();
            remove_xattr(&mut inode, Some(&mut external), &full_name, access).unwrap();
            let got = get_xattr(&inode, Some(&external), &full_name).unwrap();
            prop_assert_eq!(got, None);
        }

        /// Overwriting a value preserves other xattrs.
        #[test]
        fn proptest_overwrite_preserves_others(
            suffix_a in xattr_suffix_strategy(),
            suffix_b in xattr_suffix_strategy(),
            val_a in xattr_value_strategy(),
            val_b1 in xattr_value_strategy(),
        ) {
            // Ensure distinct names.
            prop_assume!(suffix_a != suffix_b);

            let mut inode = make_inode(256);
            let mut external = vec![0_u8; 1024];
            let access = XattrWriteAccess { is_owner: true, ..Default::default() };
            let name_a = format!("user.{suffix_a}");
            let name_b = format!("user.{suffix_b}");

            set_xattr(&mut inode, Some(&mut external), &name_a, &val_a, access).unwrap();
            set_xattr(&mut inode, Some(&mut external), &name_b, &val_b1, access).unwrap();

            // Overwrite B with new value.
            let new_b = b"replaced";
            set_xattr(&mut inode, Some(&mut external), &name_b, new_b, access).unwrap();

            // A should be unchanged.
            let got_a = get_xattr(&inode, Some(&external), &name_a).unwrap();
            prop_assert_eq!(got_a, Some(val_a));
            // B should be the new value.
            let got_b = get_xattr(&inode, Some(&external), &name_b).unwrap();
            prop_assert_eq!(got_b, Some(new_b.to_vec()));
        }

        /// Setting N unique xattrs ⟹ list returns exactly those N names.
        #[test]
        fn proptest_set_multiple_list_complete(
            suffixes in prop::collection::hash_set(xattr_suffix_strategy(), 1..8),
        ) {
            let mut inode = make_inode(256);
            let mut external = vec![0_u8; 4096];
            let access = XattrWriteAccess { is_owner: true, ..Default::default() };

            let mut expected: Vec<String> = Vec::new();
            for suffix in &suffixes {
                let full_name = format!("user.{suffix}");
                set_xattr(&mut inode, Some(&mut external), &full_name, b"v", access)
                    .unwrap();
                expected.push(full_name);
            }

            let mut listed = list_xattrs(&inode, Some(&external)).unwrap();
            listed.sort();
            expected.sort();
            prop_assert_eq!(listed, expected);
        }

        /// encode_entries_region → parse roundtrip: encoded entries parse back identically.
        #[test]
        fn proptest_encode_parse_external_roundtrip(
            suffixes in prop::collection::hash_set(xattr_suffix_strategy(), 1..5),
            values in prop::collection::vec(xattr_value_strategy(), 1..5),
        ) {
            let entries: Vec<Ext4Xattr> = suffixes.iter().zip(values.iter()).map(|(s, v)| {
                Ext4Xattr {
                    name_index: EXT4_XATTR_INDEX_USER,
                    name: s.as_bytes().to_vec(),
                    value: v.clone(),
                }
            }).collect();
            let mut expected = entries.clone();
            sort_external_entries(&mut expected);

            // Build an external block and parse it back.
            let block_len = 4096;
            let block = build_external_block(block_len, &entries).unwrap();
            let parsed = parse_external_entries(&block, false).unwrap();

            prop_assert_eq!(parsed.len(), expected.len());
            for (orig, parsed_e) in expected.iter().zip(parsed.iter()) {
                prop_assert_eq!(orig.name_index, parsed_e.name_index);
                prop_assert_eq!(&orig.name, &parsed_e.name);
                prop_assert_eq!(&orig.value, &parsed_e.value);
            }
        }

        /// Reordering a unique external-xattr set must not change the logical external block,
        /// and extra trailing block capacity must not change the parsed entries.
        #[test]
        fn proptest_build_external_block_is_order_and_capacity_invariant(
            entries in external_xattr_entries_strategy(),
            rotation in 0_usize..8,
        ) {
            let mut rotated = entries.clone();
            let rotation = rotation % rotated.len();
            rotated.rotate_left(rotation);

            let forward = build_external_block(4096, &entries).unwrap();
            let rotated_block = build_external_block(4096, &rotated).unwrap();
            prop_assert_eq!(
                &forward,
                &rotated_block,
                "external block encoding must be invariant to input order permutations"
            );

            let parsed = parse_external_entries(&forward, false).unwrap();
            let larger_capacity = build_external_block(8192, &rotated).unwrap();
            let parsed_larger_capacity = parse_external_entries(&larger_capacity, false).unwrap();
            let mut expected = entries;
            sort_external_entries(&mut expected);

            prop_assert_eq!(parsed.len(), expected.len());
            for (expected_entry, parsed_entry) in expected.iter().zip(parsed.iter()) {
                prop_assert_eq!(expected_entry.name_index, parsed_entry.name_index);
                prop_assert_eq!(&expected_entry.name, &parsed_entry.name);
                prop_assert_eq!(&expected_entry.value, &parsed_entry.value);
            }

            prop_assert_eq!(
                parsed_larger_capacity.len(),
                expected.len(),
                "larger external block capacity must preserve parsed entry count"
            );
            for (expected_entry, parsed_entry) in expected.iter().zip(parsed_larger_capacity.iter()) {
                prop_assert_eq!(expected_entry.name_index, parsed_entry.name_index);
                prop_assert_eq!(&expected_entry.name, &parsed_entry.name);
                prop_assert_eq!(&expected_entry.value, &parsed_entry.value);
            }
        }

        /// Every external-block entry hash written to disk must match the
        /// logical entry recovered by the ondisk parser. This checks the full
        /// sorted entry stream, not only the single-entry smoke case.
        #[test]
        fn proptest_external_block_entry_hashes_match_parsed_entries(
            entries in external_xattr_entries_strategy(),
        ) {
            let block = build_external_block(4096, &entries).unwrap();
            let parsed = parse_xattr_block(&block).unwrap();
            prop_assert_eq!(parsed.len(), entries.len());

            let mut offset = EXTERNAL_HEADER_LEN;
            for parsed_entry in &parsed {
                let header: &[u8; XATTR_ENTRY_HEADER_LEN] = block
                    .get(offset..offset + XATTR_ENTRY_HEADER_LEN)
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or_else(|| {
                        proptest::test_runner::TestCaseError::fail(
                            "entry header must fit inside external block",
                        )
                    })?;
                let [
                    name_len_raw,
                    name_index,
                    _,
                    _,
                    _,
                    _,
                    _,
                    _,
                    _,
                    _,
                    _,
                    _,
                    hash_0,
                    hash_1,
                    hash_2,
                    hash_3,
                ] = *header;
                let name_len = usize::from(name_len_raw);
                let name_start = offset + XATTR_ENTRY_HEADER_LEN;
                let name_end = name_start + name_len;
                let name_bytes = block.get(name_start..name_end).ok_or_else(|| {
                    proptest::test_runner::TestCaseError::fail(
                        "entry name must fit inside external block",
                    )
                })?;
                let entry_hash = u32::from_le_bytes([hash_0, hash_1, hash_2, hash_3]);

                prop_assert_eq!(name_index, parsed_entry.name_index);
                prop_assert_eq!(name_len, parsed_entry.name.len());
                prop_assert_eq!(name_bytes, parsed_entry.name.as_slice());
                prop_assert_eq!(
                    entry_hash,
                    ext4_xattr_entry_hash(parsed_entry),
                    "stored e_hash must match recomputed ext4 xattr entry hash"
                );

                offset += align4(XATTR_ENTRY_HEADER_LEN + name_len);
            }

            let terminator = block.get(offset..offset + 4).ok_or_else(|| {
                proptest::test_runner::TestCaseError::fail(
                    "external block must retain a 4-byte zero terminator",
                )
            })?;
            prop_assert_eq!(terminator, [0, 0, 0, 0].as_slice());
        }

        /// The allocation-saving existence probe must stay isomorphic to the
        /// public getxattr path for visible user xattrs, including mixed
        /// inline/external storage.
        #[test]
        fn proptest_xattr_exists_matches_get_for_user_entries(
            entries in prop::collection::btree_map(
                xattr_suffix_strategy(),
                xattr_value_strategy(),
                1..6,
            ),
        ) {
            let mut inode = make_inode(80);
            let mut external = vec![0_u8; 4096];
            let write_access = XattrWriteAccess { is_owner: true, ..Default::default() };
            let read_access = XattrReadAccess::default();
            let mut full_names = Vec::new();

            let stored = set_xattr(
                &mut inode,
                Some(&mut external),
                "user.inline_control",
                b"i",
                write_access,
            )
            .map_err(|_| {
                proptest::test_runner::TestCaseError::fail(
                    "inline control xattr must be writable",
                )
            })?;
            prop_assert_eq!(stored, XattrStorage::Inline);
            full_names.push("user.inline_control".to_owned());

            let external_value = [b'x'; 128];
            let stored = set_xattr(
                &mut inode,
                Some(&mut external),
                "user.external_control",
                &external_value,
                write_access,
            )
            .map_err(|_| {
                proptest::test_runner::TestCaseError::fail(
                    "external control xattr must be writable",
                )
            })?;
            prop_assert_eq!(stored, XattrStorage::External);
            full_names.push("user.external_control".to_owned());

            for (suffix, value) in &entries {
                let full_name = format!("user.{suffix}");
                set_xattr(
                    &mut inode,
                    Some(&mut external),
                    &full_name,
                    value,
                    write_access,
                )
                .map_err(|_| {
                    proptest::test_runner::TestCaseError::fail(
                        "generated user xattr must be writable",
                    )
                })?;
                full_names.push(full_name);
            }

            for full_name in &full_names {
                let got = get_xattr_for_access(
                    &inode,
                    Some(&external),
                    full_name,
                    read_access,
                )
                .map_err(|_| {
                    proptest::test_runner::TestCaseError::fail(
                        "get_xattr_for_access must read written xattr",
                    )
                })?
                .is_some();
                let exists = xattr_exists_for_access(
                    &inode,
                    Some(&external),
                    full_name,
                    read_access,
                )
                .map_err(|_| {
                    proptest::test_runner::TestCaseError::fail(
                        "xattr_exists_for_access must probe written xattr",
                    )
                })?;
                prop_assert_eq!(exists, got);
            }

            let absent_name = "user.__absent__";
            let got_absent = get_xattr_for_access(
                &inode,
                Some(&external),
                absent_name,
                read_access,
            )
            .map_err(|_| {
                proptest::test_runner::TestCaseError::fail(
                    "get_xattr_for_access must handle absent user xattr",
                )
            })?
            .is_some();
            let exists_absent = xattr_exists_for_access(
                &inode,
                Some(&external),
                absent_name,
                read_access,
            )
            .map_err(|_| {
                proptest::test_runner::TestCaseError::fail(
                    "xattr_exists_for_access must handle absent user xattr",
                )
            })?;
            prop_assert_eq!(got_absent, false);
            prop_assert_eq!(exists_absent, got_absent);
        }

        /// Removing all xattrs one-by-one leaves list empty.
        #[test]
        fn proptest_remove_all_leaves_empty(
            suffixes in prop::collection::hash_set(xattr_suffix_strategy(), 1..6),
        ) {
            let mut inode = make_inode(256);
            let mut external = vec![0_u8; 4096];
            let access = XattrWriteAccess { is_owner: true, ..Default::default() };

            let names: Vec<String> = suffixes.iter().map(|s| format!("user.{s}")).collect();
            for name in &names {
                set_xattr(&mut inode, Some(&mut external), name, b"val", access).unwrap();
            }

            for name in &names {
                remove_xattr(&mut inode, Some(&mut external), name, access).unwrap();
            }

            let listed = list_xattrs(&inode, Some(&external)).unwrap();
            prop_assert!(listed.is_empty(), "expected empty list, got: {:?}", listed);
        }

        /// parse_xattr_name is a pure function: two identical inputs produce
        /// identical outputs. Locks against any future caching / mutation
        /// regression in the namespace-prefix dispatcher.
        #[test]
        fn proptest_parse_xattr_name_is_deterministic(
            prefix in prop::sample::select(vec!["user.", "trusted.", "security.", "system."]),
            suffix in xattr_suffix_strategy(),
        ) {
            let full = format!("{prefix}{suffix}");
            let a = parse_xattr_name(&full);
            let b = parse_xattr_name(&full);
            match (a, b) {
                (Ok(x), Ok(y)) => prop_assert_eq!(x, y),
                (Err(_), Err(_)) => {}
                (lhs, rhs) => prop_assert!(
                    false,
                    "parse_xattr_name disagreed on identical input '{}': {:?} vs {:?}",
                    full, lhs, rhs
                ),
            }
        }

        /// Prefix-dispatch round-trip: each ext4 user/trusted/security/system
        /// prefix routes to its matching kernel EXT4_XATTR_INDEX_* constant,
        /// and the parsed name bytes equal the original suffix bytes.
        #[test]
        fn proptest_parse_xattr_name_prefix_dispatch_roundtrip(
            suffix in xattr_suffix_strategy(),
        ) {
            let cases: [(&str, u8); 4] = [
                ("user.",     EXT4_XATTR_INDEX_USER),
                ("trusted.",  EXT4_XATTR_INDEX_TRUSTED),
                ("security.", EXT4_XATTR_INDEX_SECURITY),
                ("system.",   EXT4_XATTR_INDEX_SYSTEM),
            ];
            for (prefix, expected_idx) in cases {
                let full = format!("{prefix}{suffix}");
                let (idx, name_bytes) = parse_xattr_name(&full).unwrap();
                prop_assert_eq!(
                    idx, expected_idx,
                    "prefix '{}' must route to EXT4_XATTR_INDEX={}, got {} for input '{}'",
                    prefix, expected_idx, idx, full
                );
                prop_assert_eq!(
                    name_bytes.as_slice(),
                    suffix.as_bytes(),
                    "parsed name bytes must equal suffix bytes",
                );
            }
        }

        /// Length-cap: any prefix + suffix whose suffix byte length exceeds
        /// XATTR_NAME_MAX (255, == kernel's XATTR_NAME_MAX) must be rejected
        /// with NameTooLong. Guards against silent truncation of long names
        /// onto disk.
        #[test]
        fn proptest_parse_xattr_name_rejects_oversized(
            prefix in prop::sample::select(vec!["user.", "trusted.", "security.", "system."]),
            over_by in 1_usize..32,
        ) {
            let suffix = "a".repeat(XATTR_NAME_MAX + over_by);
            let full = format!("{prefix}{suffix}");
            let err = parse_xattr_name(&full)
                .expect_err("oversize xattr name must be rejected");
            prop_assert!(
                matches!(err, FfsError::NameTooLong),
                "expected FfsError::NameTooLong for {}-byte suffix, got {:?}",
                suffix.len(), err
            );
        }

        /// Unsupported namespace prefixes (no leading user./trusted./security./
        /// system.) are rejected with an FfsError::Format. Locks against any
        /// future overly-permissive prefix matcher.
        #[test]
        fn proptest_parse_xattr_name_rejects_unknown_namespace(
            head in "[a-z][a-z0-9]{0,15}",
            suffix in xattr_suffix_strategy(),
        ) {
            // Skip strings that happen to match a known prefix or POSIX-ACL
            // exact-match string by construction. The strategy uses a strict
            // ASCII subset so equality checks below are sufficient.
            prop_assume!(head != "user");
            prop_assume!(head != "trusted");
            prop_assume!(head != "security");
            prop_assume!(head != "system");
            let full = format!("{head}.{suffix}");
            let err = parse_xattr_name(&full)
                .expect_err("unknown xattr namespace must be rejected");
            prop_assert!(
                matches!(err, FfsError::Format(_)),
                "expected FfsError::Format for unknown namespace '{}', got {:?}",
                full, err
            );
        }
    }

    /// Kernel pin: parse_xattr_name's three POSIX-ACL exact-match strings
    /// map to the three EXT4_XATTR_INDEX_* constants drawn from
    /// fs/ext4/xattr.h, and each returns an empty name body (the kernel
    /// uses the index alone to dispatch). Any silent rename of these
    /// strings or constants is an on-disk ABI break.
    #[test]
    fn parse_xattr_name_posix_acl_exact_match_kernel_pin() {
        let (idx, name) = parse_xattr_name("system.posix_acl_access").unwrap();
        assert_eq!(idx, EXT4_XATTR_INDEX_POSIX_ACL_ACCESS);
        assert_eq!(idx, 2, "kernel fs/ext4/xattr.h: POSIX_ACL_ACCESS == 2");
        assert!(name.is_empty(), "POSIX-ACL strings carry no trailing name");

        let (idx, name) = parse_xattr_name("system.posix_acl_default").unwrap();
        assert_eq!(idx, EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT);
        assert_eq!(idx, 3, "kernel fs/ext4/xattr.h: POSIX_ACL_DEFAULT == 3");
        assert!(name.is_empty());

        let (idx, name) = parse_xattr_name("system.richacl").unwrap();
        assert_eq!(idx, EXT4_XATTR_INDEX_RICHACL);
        assert_eq!(idx, 8, "kernel fs/ext4/xattr.h: RICHACL == 8");
        assert!(name.is_empty());

        // Sibling kernel constants the dispatcher names elsewhere; pinned
        // here so a stray renumbering in ffs-types is caught by this crate's
        // own test surface.
        assert_eq!(EXT4_XATTR_INDEX_USER, 1);
        assert_eq!(EXT4_XATTR_INDEX_TRUSTED, 4);
        assert_eq!(EXT4_XATTR_INDEX_SECURITY, 6);
        assert_eq!(EXT4_XATTR_INDEX_SYSTEM, 7);
    }

    // ── Additional edge-case and boundary tests ─────────────────────────

    #[test]
    fn align4_values() {
        assert_eq!(align4(0), 0);
        assert_eq!(align4(1), 4);
        assert_eq!(align4(2), 4);
        assert_eq!(align4(3), 4);
        assert_eq!(align4(4), 4);
        assert_eq!(align4(5), 8);
        assert_eq!(align4(16), 16);
        assert_eq!(align4(17), 20);
    }

    #[test]
    fn build_external_block_too_short_errors() {
        let err = build_external_block(EXTERNAL_HEADER_LEN - 1, &[]).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn build_external_block_empty_entries_returns_zeroed() {
        let block = build_external_block(1024, &[]).unwrap();
        assert!(block.iter().all(|b| *b == 0));
    }

    #[test]
    fn build_external_block_populates_entry_hash_and_leaves_block_hash_zero() {
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: b"mime".to_vec(),
            value: b"image/png".to_vec(),
        };

        let block = build_external_block(1024, std::slice::from_ref(&entry)).unwrap();
        let block_hash = u32::from_le_bytes([block[12], block[13], block[14], block[15]]);
        let entry_hash = u32::from_le_bytes([block[44], block[45], block[46], block[47]]);

        assert_eq!(entry_hash, ext4_xattr_entry_hash(&entry));
        assert_eq!(block_hash, 0);
        assert_ne!(entry_hash, 0);
    }

    #[test]
    fn build_external_block_sorts_entries_by_ext4_order() {
        let entries = vec![
            Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_TRUSTED,
                name: b"zeta".to_vec(),
                value: b"trusted".to_vec(),
            },
            Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_USER,
                name: b"alpha".to_vec(),
                value: b"user-a".to_vec(),
            },
            Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_USER,
                name: b"b".to_vec(),
                value: b"user-b".to_vec(),
            },
        ];

        let block = build_external_block(1024, &entries).unwrap();
        let parsed = parse_xattr_block(&block).expect("parse sorted external block");
        let names: Vec<String> = parsed.into_iter().map(|entry| entry.full_name()).collect();
        assert_eq!(names, vec!["user.b", "user.alpha", "trusted.zeta"]);
    }

    #[test]
    fn representative_external_block_encoding_exact_golden_contract() {
        assert_eq!(
            representative_external_block_golden_contract_actual(),
            REPRESENTATIVE_EXTERNAL_BLOCK_GOLDEN
        );
    }

    #[test]
    fn build_inline_ibody_zero_length_empty_entries() {
        let out = build_inline_ibody(0, &[]).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn build_inline_ibody_zero_length_nonempty_entries_errors() {
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: b"k".to_vec(),
            value: b"v".to_vec(),
        };
        let err = build_inline_ibody(0, &[entry]).unwrap_err();
        assert!(matches!(err, FfsError::NoSpace));
    }

    #[test]
    fn build_inline_ibody_with_entry_writes_magic() {
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: b"k".to_vec(),
            value: b"v".to_vec(),
        };
        let out = build_inline_ibody(128, &[entry]).unwrap();
        let magic = u32::from_le_bytes([out[0], out[1], out[2], out[3]]);
        assert_eq!(magic, EXT4_XATTR_MAGIC);
    }

    #[test]
    fn build_inline_ibody_value_offset_is_relative_to_entry_region() {
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: b"mime".to_vec(),
            value: b"image".to_vec(),
        };
        let out = build_inline_ibody(96, &[entry]).unwrap();
        let value_offs = u16::from_le_bytes([out[6], out[7]]);
        assert_eq!(value_offs, 84);
        assert_eq!(
            &out[INLINE_HEADER_LEN + usize::from(value_offs)
                ..INLINE_HEADER_LEN + usize::from(value_offs) + 5],
            b"image"
        );
    }

    #[test]
    fn build_inline_ibody_for_inode_state_stamps_magic_for_external_only_xattrs() {
        let out = build_inline_ibody_for_inode_state(32, &[], true).unwrap();
        let magic = u32::from_le_bytes([out[0], out[1], out[2], out[3]]);
        assert_eq!(magic, EXT4_XATTR_MAGIC);
        assert!(out[4..].iter().all(|byte| *byte == 0));
    }

    #[test]
    fn check_write_permissions_unsupported_index() {
        let err = check_write_permissions(
            255, // unsupported
            XattrWriteAccess {
                is_owner: true,
                has_cap_fowner: true,
                has_cap_sys_admin: true,
            },
        )
        .unwrap_err();
        assert!(matches!(err, FfsError::UnsupportedFeature(_)));
    }

    #[test]
    fn parse_external_entries_accepts_zero_initialized() {
        let block = vec![0_u8; 1024];
        let entries = parse_external_entries(&block, true).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_external_entries_rejects_zero_initialized_when_not_allowed() {
        let block = vec![0_u8; 1024];
        let err = parse_external_entries(&block, false).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn entry_index_finds_correct_entry() {
        let entries = vec![
            Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_USER,
                name: b"foo".to_vec(),
                value: b"v1".to_vec(),
            },
            Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_USER,
                name: b"bar".to_vec(),
                value: b"v2".to_vec(),
            },
            Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_TRUSTED,
                name: b"foo".to_vec(),
                value: b"v3".to_vec(),
            },
        ];
        assert_eq!(
            entry_index(&entries, EXT4_XATTR_INDEX_USER, b"foo"),
            Some(0)
        );
        assert_eq!(
            entry_index(&entries, EXT4_XATTR_INDEX_USER, b"bar"),
            Some(1)
        );
        assert_eq!(
            entry_index(&entries, EXT4_XATTR_INDEX_TRUSTED, b"foo"),
            Some(2)
        );
        // Same name, different index → not found.
        assert_eq!(
            entry_index(&entries, EXT4_XATTR_INDEX_SECURITY, b"foo"),
            None
        );
        // Missing name entirely.
        assert_eq!(
            entry_index(&entries, EXT4_XATTR_INDEX_USER, b"missing"),
            None
        );
    }

    #[test]
    fn set_xattr_update_existing_external_entry() {
        let mut inode = make_inode(20); // small inline
        let mut external = vec![0_u8; 1024];
        let access = XattrWriteAccess {
            is_owner: true,
            ..Default::default()
        };

        // First set goes to external (inline too small).
        set_xattr(
            &mut inode,
            Some(&mut external),
            "user.key",
            b"original",
            access,
        )
        .unwrap();

        // Update the existing external entry.
        let stored = set_xattr(
            &mut inode,
            Some(&mut external),
            "user.key",
            b"updated",
            access,
        )
        .unwrap();
        assert_eq!(stored, XattrStorage::External);

        let val = get_xattr(&inode, Some(&external), "user.key").unwrap();
        assert_eq!(val, Some(b"updated".to_vec()));
    }

    #[test]
    fn set_xattr_external_only_stamps_ibody_magic() {
        let mut inode = make_inode(20);
        inode.file_acl = 123;
        let mut external = vec![0_u8; 1024];
        let access = XattrWriteAccess {
            is_owner: true,
            ..Default::default()
        };

        let stored = set_xattr(
            &mut inode,
            Some(&mut external),
            "user.big",
            &[b'X'; 128],
            access,
        )
        .unwrap();
        assert_eq!(stored, XattrStorage::External);
        assert_eq!(
            u32::from_le_bytes([
                inode.xattr_ibody[0],
                inode.xattr_ibody[1],
                inode.xattr_ibody[2],
                inode.xattr_ibody[3],
            ]),
            EXT4_XATTR_MAGIC
        );
        assert_eq!(parse_ibody_xattrs(&inode).unwrap(), Vec::<Ext4Xattr>::new());
    }

    #[test]
    fn remove_last_external_xattr_clears_header_only_ibody_magic() {
        let mut inode = make_inode(20);
        inode.file_acl = 321;
        inode.xattr_ibody[0..4].copy_from_slice(&EXT4_XATTR_MAGIC.to_le_bytes());
        let mut external = vec![0_u8; 1024];
        let access = XattrWriteAccess {
            is_owner: true,
            ..Default::default()
        };

        set_xattr(
            &mut inode,
            Some(&mut external),
            "user.big",
            &[b'Y'; 128],
            access,
        )
        .unwrap();
        assert!(remove_xattr(&mut inode, Some(&mut external), "user.big", access).unwrap());
        assert_eq!(inode.file_acl, 0);
        assert!(inode.xattr_ibody.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn remove_one_of_multiple_external_xattrs() {
        let mut inode = make_inode(20);
        let mut external = vec![0_u8; 4096];
        let access = XattrWriteAccess {
            is_owner: true,
            ..Default::default()
        };

        set_xattr(&mut inode, Some(&mut external), "user.keep", b"v1", access).unwrap();
        set_xattr(
            &mut inode,
            Some(&mut external),
            "user.remove_me",
            b"v2",
            access,
        )
        .unwrap();

        let removed =
            remove_xattr(&mut inode, Some(&mut external), "user.remove_me", access).unwrap();
        assert!(removed);

        // "keep" should still be there.
        let val = get_xattr(&inode, Some(&external), "user.keep").unwrap();
        assert_eq!(val, Some(b"v1".to_vec()));

        // "remove_me" should be gone.
        let val = get_xattr(&inode, Some(&external), "user.remove_me").unwrap();
        assert_eq!(val, None);

        // file_acl should still be set because there are remaining entries.
        let names = list_xattrs(&inode, Some(&external)).unwrap();
        assert_eq!(names.len(), 1);
    }

    #[test]
    fn list_and_get_xattrs_hide_trusted_from_unprivileged_reader() {
        let mut inode = make_inode(256);
        let mut external = vec![0_u8; 4096];
        let admin = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: true,
            has_cap_sys_admin: true,
        };
        let unprivileged = XattrReadAccess::default();

        set_xattr(&mut inode, Some(&mut external), "user.tag", b"u", admin).unwrap();
        set_xattr(
            &mut inode,
            Some(&mut external),
            "security.selinux",
            b"context",
            admin,
        )
        .unwrap();
        set_xattr(&mut inode, Some(&mut external), "trusted.meta", b"t", admin).unwrap();

        // An unprivileged listing must omit the trusted.* name (info-leak guard).
        let mut names = list_xattrs_for_access(&inode, Some(&external), unprivileged).unwrap();
        names.sort();
        assert_eq!(names, vec!["security.selinux", "user.tag"]);
        assert!(!names.contains(&"trusted.meta".to_string()));

        // And getting the trusted value returns None (hidden), not the bytes.
        assert_eq!(
            get_xattr_for_access(&inode, Some(&external), "trusted.meta", unprivileged).unwrap(),
            None
        );
    }

    #[test]
    fn mixed_namespace_xattrs() {
        let mut inode = make_inode(256);
        let mut external = vec![0_u8; 4096];
        let admin = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: true,
            has_cap_sys_admin: true,
        };
        let admin_read = XattrReadAccess {
            has_cap_sys_admin: true,
        };

        set_xattr(&mut inode, Some(&mut external), "user.tag", b"u", admin).unwrap();
        set_xattr(
            &mut inode,
            Some(&mut external),
            "security.selinux",
            b"context",
            admin,
        )
        .unwrap();
        set_xattr(&mut inode, Some(&mut external), "trusted.meta", b"t", admin).unwrap();

        let mut names = list_xattrs_for_access(&inode, Some(&external), admin_read).unwrap();
        names.sort();
        assert_eq!(names, vec!["security.selinux", "trusted.meta", "user.tag"]);

        assert_eq!(
            get_xattr_for_access(&inode, Some(&external), "user.tag", admin_read).unwrap(),
            Some(b"u".to_vec())
        );
        assert_eq!(
            get_xattr_for_access(&inode, Some(&external), "security.selinux", admin_read).unwrap(),
            Some(b"context".to_vec())
        );
        assert_eq!(
            get_xattr_for_access(&inode, Some(&external), "trusted.meta", admin_read).unwrap(),
            Some(b"t".to_vec())
        );
    }

    #[test]
    fn trusted_namespace_hidden_from_unprivileged_default_view() {
        let mut inode = make_inode(0);
        let mut external = vec![0_u8; 4096];
        let admin = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: true,
            has_cap_sys_admin: true,
        };
        let admin_read = XattrReadAccess {
            has_cap_sys_admin: true,
        };

        set_xattr(&mut inode, Some(&mut external), "user.public", b"u", admin).unwrap();
        set_xattr(&mut inode, Some(&mut external), "trusted.meta", b"t", admin).unwrap();

        let mut names = list_xattrs(&inode, Some(&external)).unwrap();
        names.sort();
        assert_eq!(names, vec!["user.public"]);

        let mut admin_names = list_xattrs_for_access(&inode, Some(&external), admin_read).unwrap();
        admin_names.sort();
        assert_eq!(admin_names, vec!["trusted.meta", "user.public"]);

        assert_eq!(
            get_xattr(&inode, Some(&external), "trusted.meta").unwrap(),
            None
        );
        assert_eq!(
            get_xattr_for_access(&inode, Some(&external), "trusted.meta", admin_read).unwrap(),
            Some(b"t".to_vec())
        );
        assert_eq!(
            get_xattr(&inode, Some(&external), "user.public").unwrap(),
            Some(b"u".to_vec())
        );
    }

    #[test]
    fn xattr_exists_for_access_honors_trusted_visibility() -> Result<()> {
        let mut inode = make_inode(0);
        let mut external = vec![0_u8; 4096];
        let admin = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: true,
            has_cap_sys_admin: true,
        };
        let admin_read = XattrReadAccess {
            has_cap_sys_admin: true,
        };

        set_xattr(
            &mut inode,
            Some(&mut external),
            "trusted.meta",
            b"secret",
            admin,
        )?;

        if xattr_exists_for_access(
            &inode,
            Some(&external),
            "trusted.meta",
            XattrReadAccess::default(),
        )? {
            return Err(FfsError::Format(
                "trusted xattr exists for default reader".to_owned(),
            ));
        }
        if !xattr_exists_for_access(&inode, Some(&external), "trusted.meta", admin_read)? {
            return Err(FfsError::Format(
                "trusted xattr hidden from admin reader".to_owned(),
            ));
        }
        if get_xattr_for_access(
            &inode,
            Some(&external),
            "trusted.meta",
            XattrReadAccess::default(),
        )?
        .is_some()
        {
            return Err(FfsError::Format(
                "trusted xattr get succeeded for default reader".to_owned(),
            ));
        }
        if get_xattr_for_access(&inode, Some(&external), "trusted.meta", admin_read)?
            != Some(b"secret".to_vec())
        {
            return Err(FfsError::Format(
                "trusted xattr get failed for admin reader".to_owned(),
            ));
        }

        Ok(())
    }

    #[test]
    fn xattr_exists_for_access_requires_external_block_on_miss() -> Result<()> {
        let mut inode = make_inode(128);
        inode.xattr_ibody = build_inline_ibody(
            128,
            &[Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_USER,
                name: b"public".to_vec(),
                value: b"u".to_vec(),
            }],
        )?;
        inode.file_acl = 4242;

        if !xattr_exists_for_access(&inode, None, "user.public", XattrReadAccess::default())? {
            return Err(FfsError::Format(
                "inline xattr missing from existence probe".to_owned(),
            ));
        }

        match xattr_exists_for_access(&inode, None, "user.missing", XattrReadAccess::default()) {
            Err(FfsError::Format(message)) if message.contains("external xattr block") => Ok(()),
            _ => Err(FfsError::Format(
                "missing external xattr block was not rejected".to_owned(),
            )),
        }
    }

    #[test]
    fn xattr_exists_for_access_skips_external_block_when_namespace_denied() -> Result<()> {
        let mut inode = make_inode(128);
        inode.file_acl = 4242;
        let default_read = XattrReadAccess::default();
        let admin_read = XattrReadAccess {
            has_cap_sys_admin: true,
        };

        if xattr_exists_for_access(&inode, None, "trusted.secret", default_read)? {
            return Err(FfsError::Format(
                "trusted xattr exists for default reader".to_owned(),
            ));
        }
        if get_xattr_for_access(&inode, None, "trusted.secret", default_read)?.is_some() {
            return Err(FfsError::Format(
                "trusted xattr get succeeded for default reader".to_owned(),
            ));
        }

        match xattr_exists_for_access(&inode, None, "trusted.secret", admin_read) {
            Err(FfsError::Format(message)) if message.contains("external xattr block") => Ok(()),
            _ => Err(FfsError::Format(
                "admin-visible external xattr miss did not require the block".to_owned(),
            )),
        }
    }

    #[test]
    fn encryption_namespace_hidden_from_all_xattr_views() {
        let inode = Ext4Inode {
            xattr_ibody: build_inline_ibody(
                256,
                &[
                    Ext4Xattr {
                        name_index: EXT4_XATTR_INDEX_ENCRYPTION,
                        name: b"c".to_vec(),
                        value: b"context".to_vec(),
                    },
                    Ext4Xattr {
                        name_index: EXT4_XATTR_INDEX_USER,
                        name: b"public".to_vec(),
                        value: b"u".to_vec(),
                    },
                ],
            )
            .unwrap(),
            ..make_inode(256)
        };
        let admin_read = XattrReadAccess {
            has_cap_sys_admin: true,
        };

        let mut names = list_xattrs(&inode, None).unwrap();
        names.sort();
        assert_eq!(names, vec!["user.public"]);

        let mut admin_names = list_xattrs_for_access(&inode, None, admin_read).unwrap();
        admin_names.sort();
        assert_eq!(admin_names, vec!["user.public"]);
    }

    #[test]
    fn system_generic_xattr_allowed_for_sys_admin() {
        let mut inode = make_inode(128);
        let admin = XattrWriteAccess {
            is_owner: false,
            has_cap_fowner: false,
            has_cap_sys_admin: true,
        };

        let stored = set_xattr(&mut inode, None, "system.custom_attr", b"val", admin).unwrap();
        assert_eq!(stored, XattrStorage::Inline);

        let val = get_xattr(&inode, None, "system.custom_attr").unwrap();
        assert_eq!(val, Some(b"val".to_vec()));
    }

    #[test]
    fn richacl_xattr_allowed_for_sys_admin() {
        let mut inode = make_inode(128);
        let admin = XattrWriteAccess {
            is_owner: false,
            has_cap_fowner: false,
            has_cap_sys_admin: true,
        };

        let stored = set_xattr(&mut inode, None, "system.richacl", b"acl", admin).unwrap();
        assert_eq!(stored, XattrStorage::Inline);

        let val = get_xattr(&inode, None, "system.richacl").unwrap();
        assert_eq!(val, Some(b"acl".to_vec()));
    }

    #[test]
    fn encode_entries_region_name_too_long_errors() {
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: vec![b'x'; 256], // exceeds u8::MAX
            value: b"v".to_vec(),
        };
        let err = encode_entries_region(4096, &[entry], 0).unwrap_err();
        assert!(matches!(err, FfsError::NameTooLong));
    }

    #[test]
    fn encode_entries_region_value_too_large_errors() {
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: b"k".to_vec(),
            value: vec![0u8; XATTR_VALUE_MAX + 1],
        };
        let err = encode_entries_region(65600, &[entry], 0).unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn encode_entries_region_nospace_when_too_small() {
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: b"key".to_vec(),
            value: vec![b'v'; 100],
        };
        // Region too small to hold entry header + name + value.
        let err = encode_entries_region(32, &[entry], 0).unwrap_err();
        assert!(matches!(err, FfsError::NoSpace));
    }

    #[test]
    fn parse_xattr_name_system_posix_acl_default() {
        let (idx, name) = parse_xattr_name("system.posix_acl_default").unwrap();
        assert_eq!(idx, EXT4_XATTR_INDEX_POSIX_ACL_DEFAULT);
        assert!(name.is_empty());
    }

    #[test]
    fn xattr_storage_variants() {
        // Ensure XattrStorage derives work correctly.
        let inline = XattrStorage::Inline;
        let external = XattrStorage::External;
        assert_ne!(inline, external);
        assert_eq!(inline, XattrStorage::Inline);
        assert_eq!(external, XattrStorage::External);
        let _ = format!("{inline:?}");
        let _ = format!("{external:?}");
    }

    #[test]
    fn xattr_write_access_debug_and_clone() {
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: true,
        };
        let cloned = access;
        assert_eq!(access, cloned);
        let _ = format!("{access:?}");
    }

    #[test]
    fn set_xattr_empty_value() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            ..Default::default()
        };

        // Empty value is valid.
        set_xattr(&mut inode, None, "user.empty", b"", access).unwrap();
        let val = get_xattr(&inode, None, "user.empty").unwrap();
        assert_eq!(val, Some(Vec::new()));
    }

    #[test]
    fn set_xattr_replaces_with_empty_value() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            ..Default::default()
        };

        set_xattr(&mut inode, None, "user.key", b"nonempty", access).unwrap();
        set_xattr(&mut inode, None, "user.key", b"", access).unwrap();
        let val = get_xattr(&inode, None, "user.key").unwrap();
        assert_eq!(val, Some(Vec::new()));
    }

    // ── Boundary value tests ────────────────────────────────────────────

    #[test]
    fn set_xattr_max_suffix_length_255() {
        let mut inode = make_inode(512);
        let access = XattrWriteAccess {
            is_owner: true,
            ..Default::default()
        };
        // The ext4 xattr name_len field is u8, so suffix max is 255 bytes.
        // The "user." prefix is stripped before the suffix length check.
        let suffix = "a".repeat(255);
        let name = format!("user.{suffix}");
        set_xattr(&mut inode, None, &name, b"val", access).unwrap();
        let val = get_xattr(&inode, None, &name).unwrap();
        assert_eq!(val, Some(b"val".to_vec()));
    }

    #[test]
    fn set_xattr_large_value_near_limit() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            ..Default::default()
        };
        let mut ext_block = vec![0u8; 4096];
        // Value just under typical block capacity
        let value = vec![0xAB_u8; 3000];
        set_xattr(&mut inode, Some(&mut ext_block), "user.big", &value, access).unwrap();
        let got = get_xattr(&inode, Some(&ext_block), "user.big").unwrap();
        assert_eq!(got.as_deref(), Some(value.as_slice()));
    }

    // ── Multiple overwrite cycles ───────────────────────────────────────

    #[test]
    fn set_xattr_overwrite_five_times() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            ..Default::default()
        };
        for i in 0..5_u8 {
            let val = vec![i; (i as usize + 1) * 10];
            set_xattr(&mut inode, None, "user.cycle", &val, access).unwrap();
            let got = get_xattr(&inode, None, "user.cycle").unwrap();
            assert_eq!(got, Some(val));
        }
    }

    // ── External block edge cases ───────────────────────────────────────

    #[test]
    fn external_block_exactly_header_size() {
        let mut inode = make_inode(0);
        let access = XattrWriteAccess {
            is_owner: true,
            ..Default::default()
        };
        // 32 bytes = header only, no room for entries
        let mut ext_block = vec![0u8; 32];
        let err = set_xattr(&mut inode, Some(&mut ext_block), "user.x", b"v", access).unwrap_err();
        assert!(matches!(err, FfsError::NoSpace));
    }

    #[test]
    fn get_xattr_missing_returns_none_with_external() {
        let inode = make_inode(128);
        let ext_block = vec![0u8; 4096];
        let val = get_xattr(&inode, Some(&ext_block), "user.nope").unwrap();
        assert_eq!(val, None);
    }

    #[test]
    fn list_xattrs_empty_with_external_block() {
        let inode = make_inode(128);
        let ext_block = vec![0u8; 4096];
        let names = list_xattrs(&inode, Some(&ext_block)).unwrap();
        assert!(names.is_empty());
    }

    // ── All namespace types simultaneously ──────────────────────────────

    #[test]
    fn all_namespace_types_coexist() {
        let mut inode = make_inode(256);
        let admin = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: true,
            has_cap_sys_admin: true,
        };
        let mut ext_block = vec![0u8; 4096];

        set_xattr(&mut inode, Some(&mut ext_block), "user.u", b"1", admin).unwrap();
        set_xattr(&mut inode, Some(&mut ext_block), "trusted.t", b"2", admin).unwrap();
        set_xattr(&mut inode, Some(&mut ext_block), "security.s", b"3", admin).unwrap();
        set_xattr(
            &mut inode,
            Some(&mut ext_block),
            "system.posix_acl_access",
            b"4",
            admin,
        )
        .unwrap();

        let names = list_xattrs(&inode, Some(&ext_block)).unwrap();
        assert!(names.contains(&"user.u".to_owned()));
        assert!(names.contains(&"security.s".to_owned()));
        assert!(names.contains(&"system.posix_acl_access".to_owned()));
        assert_eq!(names.len(), 3);
    }

    // ── Remove all then verify clean state ──────────────────────────────

    #[test]
    fn remove_all_xattrs_leaves_empty_list() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            ..Default::default()
        };

        for i in 0..5 {
            let name = format!("user.k{i}");
            set_xattr(&mut inode, None, &name, b"v", access).unwrap();
        }
        for i in 0..5 {
            let name = format!("user.k{i}");
            remove_xattr(&mut inode, None, &name, access).unwrap();
        }
        let names = list_xattrs(&inode, None).unwrap();
        assert!(names.is_empty());
    }

    // ── Permission denial edge cases ────────────────────────────────────

    #[test]
    fn get_xattr_does_not_require_write_access() {
        let mut inode = make_inode(128);
        let writer = XattrWriteAccess {
            is_owner: true,
            ..Default::default()
        };
        set_xattr(&mut inode, None, "user.readable", b"hello", writer).unwrap();
        // get_xattr has no access parameter — always readable
        let val = get_xattr(&inode, None, "user.readable").unwrap();
        assert_eq!(val, Some(b"hello".to_vec()));
    }

    #[test]
    fn list_xattrs_does_not_require_write_access() {
        let mut inode = make_inode(128);
        let writer = XattrWriteAccess {
            is_owner: true,
            ..Default::default()
        };
        set_xattr(&mut inode, None, "user.listed", b"v", writer).unwrap();
        let names = list_xattrs(&inode, None).unwrap();
        assert!(names.contains(&"user.listed".to_owned()));
    }

    // ── XattrStorage enum coverage ──────────────────────────────────────

    #[test]
    fn set_xattr_returns_inline_storage() {
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            ..Default::default()
        };
        let storage = set_xattr(&mut inode, None, "user.small", b"v", access).unwrap();
        assert_eq!(storage, XattrStorage::Inline);
    }

    #[test]
    fn set_xattr_returns_external_storage_on_spillover() {
        let mut inode = make_inode(16); // very small inline area
        let access = XattrWriteAccess {
            is_owner: true,
            ..Default::default()
        };
        let mut ext_block = vec![0u8; 4096];
        let value = vec![0xCC; 100];
        let storage =
            set_xattr(&mut inode, Some(&mut ext_block), "user.big", &value, access).unwrap();
        assert_eq!(storage, XattrStorage::External);
    }

    // ── parse_xattr_name edge cases ─────────────────────────────────────

    #[test]
    fn parse_xattr_name_rejects_no_dot() {
        let err = parse_xattr_name("userfoo").unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn parse_xattr_name_rejects_bare_dot() {
        let err = parse_xattr_name("user.").unwrap_err();
        assert!(matches!(err, FfsError::Format(_)));
    }

    #[test]
    fn parse_xattr_name_binary_suffix() {
        // Non-ASCII suffix bytes are valid (ext4 doesn't require UTF-8)
        let (idx, name) = parse_xattr_name("user.abc").unwrap();
        assert_eq!(idx, 1); // EXT4_XATTR_INDEX_USER
        assert_eq!(name, b"abc");
    }

    // ── Multi-pass audit regressions ───────────────────────────────────

    /// `set_xattr` must refuse to write when the inode advertises an external
    /// xattr block but the caller forgot to pass it. Previously this case
    /// silently treated external as empty and could install a duplicate of an
    /// existing attribute into the inline ibody, shadowing the on-disk
    /// external value forever.
    #[test]
    fn set_xattr_rejects_missing_external_block_when_file_acl_nonzero() {
        let mut inode = make_inode(128);
        inode.file_acl = 4242; // pretends an external block exists on disk
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };

        let before = inode.xattr_ibody.clone();
        let err = set_xattr(&mut inode, None, "user.shadow", b"new", access).unwrap_err();

        assert!(
            matches!(err, FfsError::Format(_)),
            "expected Format error, got {err:?}"
        );
        assert_eq!(
            inode.xattr_ibody, before,
            "rejected set_xattr must not mutate the inode"
        );
        assert_eq!(inode.file_acl, 4242, "file_acl pointer must be preserved");
    }

    /// `build_inline_ibody` must accept tiny (1..4-byte) empty regions so a
    /// roundtrip parse-then-rebuild succeeds for inodes whose ibody is too
    /// small for the 4-byte xattr header. `parse_ibody_xattrs` already returns
    /// `Ok(empty)` in that case.
    #[test]
    fn build_inline_ibody_tolerates_subheader_empty_region() {
        for ibody_len in 0..INLINE_HEADER_LEN {
            let out = build_inline_ibody(ibody_len, &[]).unwrap_or_else(|e| {
                panic!("ibody_len={ibody_len} with no entries should round-trip: {e:?}")
            });
            assert_eq!(out.len(), ibody_len);
            assert!(
                out.iter().all(|b| *b == 0),
                "ibody_len={ibody_len} output must be all zeros"
            );
        }

        // Asking to write a non-empty entry into a sub-header region is a
        // capacity failure, not a format failure — distinguishable so callers
        // can recover by spilling to external storage.
        let entry = Ext4Xattr {
            name_index: EXT4_XATTR_INDEX_USER,
            name: b"x".to_vec(),
            value: b"v".to_vec(),
        };
        let err = build_inline_ibody(2, std::slice::from_ref(&entry)).unwrap_err();
        assert!(matches!(err, FfsError::NoSpace), "got {err:?}");
    }

    /// Empty xattr values must not consume padding bytes in the values region.
    /// Previously `value_start = (value_tail - 0) & !3` rounded *down* by up
    /// to 3 bytes per empty value, eventually producing spurious NoSpace
    /// errors when many empty xattrs were packed together.
    #[test]
    fn encode_entries_region_does_not_pad_empty_values() {
        // A 64-byte region with two empty-value entries (header is 16 bytes
        // each, plus the 4-byte trailing terminator; values consume 0). With
        // the previous behaviour we would lose 4-6 bytes to alignment padding
        // and the second entry's terminator check would fail spuriously when
        // the region was sized close to the minimum.
        let entries = vec![
            Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_USER,
                name: b"a".to_vec(),
                value: Vec::new(),
            },
            Ext4Xattr {
                name_index: EXT4_XATTR_INDEX_USER,
                name: b"b".to_vec(),
                value: Vec::new(),
            },
        ];
        // Two entry headers (20 bytes each after align4(16+1)) + 4-byte
        // terminator = 44 bytes. Padding-free packing fits in 44 bytes.
        let region = encode_entries_region(44, &entries, 0)
            .expect("two empty-value entries must fit without padding");
        assert_eq!(region.len(), 44);

        // With the bug, even a 50-byte region would underflow value_tail
        // for the second entry — verify the round-trip parse here too via the
        // public set_xattr path that exercises the same encoder.
        let mut inode = make_inode(128);
        let access = XattrWriteAccess {
            is_owner: true,
            has_cap_fowner: false,
            has_cap_sys_admin: false,
        };
        for name in ["user.e1", "user.e2", "user.e3", "user.e4"] {
            set_xattr(&mut inode, None, name, b"", access)
                .unwrap_or_else(|e| panic!("set_xattr {name:?} with empty value failed: {e:?}"));
        }
        let mut listed = list_xattrs(&inode, None).unwrap();
        listed.sort();
        assert_eq!(
            listed,
            vec![
                "user.e1".to_owned(),
                "user.e2".to_owned(),
                "user.e3".to_owned(),
                "user.e4".to_owned()
            ],
        );
    }

    // The crate's own fixture, so these tests exercise the same inode shape the
    // rest of the module is tested against.
    fn bare_inode() -> Ext4Inode {
        make_inode(128)
    }

    /// The whole point of the function: an inode with nothing on it must be
    /// reported clean, because that is what lets `auto` prove absence.
    #[test]
    fn a_bare_inode_carries_nothing_bd_ha71t() {
        assert!(!inode_has_any_xattr(&bare_inode()));
    }

    /// The cheap check. An external xattr block is a hard yes without parsing
    /// anything.
    #[test]
    fn an_external_xattr_block_counts_bd_ha71t() {
        let mut inode = bare_inode();
        inode.file_acl = 42;
        assert!(inode_has_any_xattr(&inode));
    }

    /// The check that `file_acl` alone would miss, and the reason this function
    /// exists at all: a small xattr lives inside the inode with `file_acl == 0`.
    /// An image labelled by SELinux looks exactly like this.
    #[test]
    fn an_in_inode_xattr_counts_even_with_no_external_block_bd_ha71t() {
        let mut inode = bare_inode();
        set_xattr(
            &mut inode,
            None,
            "security.selinux",
            b"system_u:object_r:t",
            XattrWriteAccess {
                is_owner: true,
                has_cap_fowner: false,
                has_cap_sys_admin: true,
            },
        )
        .expect("in-inode set must fit");
        assert_eq!(
            inode.file_acl, 0,
            "this fixture must exercise the INLINE path"
        );
        assert!(
            inode_has_any_xattr(&inode),
            "an in-inode xattr must count: reporting this image attribute-free \
             would make the one-way suppression switch silently wrong"
        );
    }
}
