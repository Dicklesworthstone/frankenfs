//! General extent backref editing (bd-5elw6).
//!
//! FrankenFS's own writes only ever produce root-keyed references
//! (`TREE_BLOCK_REF` / `EXTENT_DATA_REF`). Filesystems the kernel has
//! snapshotted or relocated (`btrfs balance`) also carry parent-keyed ones
//! (`SHARED_BLOCK_REF` / `SHARED_DATA_REF`) and `FULL_BACKREF` tree blocks.
//! Releasing a subvolume tree that shares blocks with such a filesystem needs
//! to read and edit every form: inline refs inside the `EXTENT_ITEM` /
//! skinny `METADATA_ITEM`, and the keyed ref items beside it.
//!
//! New references are always added as keyed items, which btrfs accepts for
//! every ref type and which avoids re-sorting an item's inline list.
//! Removals find the ref wherever it lives (inline or keyed).
//! Count and keyed-payload validation happens before the first tree edit, so
//! rejected arithmetic or malformed keyed payloads cannot skew live refcounts.
//! Multi-item edits share one COW publication boundary: allocation or tree
//! errors discard the entire staged change, and only a committed last-reference
//! removal may pin the released extent.

use crate::{
    BTRFS_ITEM_EXTENT_DATA_REF, BTRFS_ITEM_EXTENT_ITEM, BTRFS_ITEM_METADATA_ITEM,
    BTRFS_ITEM_TREE_BLOCK_REF, BtrfsBTree, BtrfsExtentAllocator, BtrfsExtentDataRef, BtrfsKey,
    BtrfsMutationError, InMemoryCowBtrfsTree,
};

/// Parent-keyed tree block backref (`BTRFS_SHARED_BLOCK_REF_KEY`).
pub const BTRFS_ITEM_SHARED_BLOCK_REF: u8 = 182;
/// Parent-keyed data backref (`BTRFS_SHARED_DATA_REF_KEY`).
pub const BTRFS_ITEM_SHARED_DATA_REF: u8 = 184;
/// Simple-quota owner ref (`BTRFS_EXTENT_OWNER_REF_KEY`), inline only.
pub const BTRFS_ITEM_EXTENT_OWNER_REF: u8 = 172;
/// Extent item flag: this tree block's children are referenced by parent
/// (`SHARED_*_REF` with this block as parent), not by root.
pub const BTRFS_EXTENT_FLAG_FULL_BACKREF: u64 = 1 << 8;
/// Extent item flag: the item describes a tree block.
const BTRFS_EXTENT_FLAG_TREE_BLOCK: u64 = 2;

const EXTENT_ITEM_HEADER: usize = 24;
const TREE_BLOCK_INFO: usize = 18;
const DATA_REF_PAYLOAD: usize = 28;

/// Who holds a reference to a tree block.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeBlockBackref {
    /// A tree root (keyed `TREE_BLOCK_REF`, offset = root objectid).
    Root(u64),
    /// A `FULL_BACKREF` parent block (`SHARED_BLOCK_REF`, offset = parent bytenr).
    Parent(u64),
}

/// Refcount and flags of an extent item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtentRefState {
    pub refs: u64,
    pub flags: u64,
}

impl ExtentRefState {
    #[must_use]
    pub const fn full_backref(self) -> bool {
        self.flags & BTRFS_EXTENT_FLAG_FULL_BACKREF != 0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum InlineRef {
    TreeRoot(u64),
    TreeParent(u64),
    Data(BtrfsExtentDataRef),
    SharedData { parent: u64, count: u32 },
    Owner(u64),
}

impl InlineRef {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::TreeRoot(root) => {
                out.push(BTRFS_ITEM_TREE_BLOCK_REF);
                out.extend_from_slice(&root.to_le_bytes());
            }
            Self::TreeParent(parent) => {
                out.push(BTRFS_ITEM_SHARED_BLOCK_REF);
                out.extend_from_slice(&parent.to_le_bytes());
            }
            Self::Data(data_ref) => {
                out.push(BTRFS_ITEM_EXTENT_DATA_REF);
                out.extend_from_slice(&data_ref.to_bytes());
            }
            Self::SharedData { parent, count } => {
                out.push(BTRFS_ITEM_SHARED_DATA_REF);
                out.extend_from_slice(&parent.to_le_bytes());
                out.extend_from_slice(&count.to_le_bytes());
            }
            Self::Owner(root) => {
                out.push(BTRFS_ITEM_EXTENT_OWNER_REF);
                out.extend_from_slice(&root.to_le_bytes());
            }
        }
    }
}

/// An `EXTENT_ITEM` / `METADATA_ITEM` value split into its parts.
#[derive(Debug, Clone)]
struct ExtentItem {
    refs: u64,
    generation: u64,
    flags: u64,
    /// Non-skinny tree blocks carry `btrfs_tree_block_info` before the refs.
    tree_block_info: Option<Vec<u8>>,
    inline: Vec<InlineRef>,
}

fn read_u64(bytes: &[u8], at: usize) -> Result<u64, BtrfsMutationError> {
    bytes
        .get(at..at + 8)
        .map(|b| u64::from_le_bytes(b.try_into().expect("8 bytes")))
        .ok_or(BtrfsMutationError::BrokenInvariant("truncated extent item"))
}

fn shared_data_ref_count(value: &[u8]) -> Result<u32, BtrfsMutationError> {
    let bytes = value
        .try_into()
        .map_err(|_| BtrfsMutationError::BrokenInvariant("invalid keyed SHARED_DATA_REF size"))?;
    let count = u32::from_le_bytes(bytes);
    if count == 0 {
        return Err(BtrfsMutationError::BrokenInvariant(
            "zero keyed SHARED_DATA_REF count",
        ));
    }
    Ok(count)
}

impl ExtentItem {
    fn parse(key: BtrfsKey, value: &[u8]) -> Result<Self, BtrfsMutationError> {
        let refs = read_u64(value, 0)?;
        let generation = read_u64(value, 8)?;
        let flags = read_u64(value, 16)?;
        let mut cursor = EXTENT_ITEM_HEADER;
        let tree_block_info = if key.item_type == BTRFS_ITEM_EXTENT_ITEM
            && flags & BTRFS_EXTENT_FLAG_TREE_BLOCK != 0
        {
            let info = value
                .get(cursor..cursor + TREE_BLOCK_INFO)
                .ok_or(BtrfsMutationError::BrokenInvariant(
                    "truncated tree_block_info",
                ))?
                .to_vec();
            cursor += TREE_BLOCK_INFO;
            Some(info)
        } else {
            None
        };
        let mut inline = Vec::new();
        while cursor < value.len() {
            let kind = value[cursor];
            cursor += 1;
            let entry = match kind {
                BTRFS_ITEM_TREE_BLOCK_REF => {
                    let root = read_u64(value, cursor)?;
                    cursor += 8;
                    InlineRef::TreeRoot(root)
                }
                BTRFS_ITEM_SHARED_BLOCK_REF => {
                    let parent = read_u64(value, cursor)?;
                    cursor += 8;
                    InlineRef::TreeParent(parent)
                }
                BTRFS_ITEM_EXTENT_OWNER_REF => {
                    let root = read_u64(value, cursor)?;
                    cursor += 8;
                    InlineRef::Owner(root)
                }
                BTRFS_ITEM_EXTENT_DATA_REF => {
                    let data_ref = value
                        .get(cursor..cursor + DATA_REF_PAYLOAD)
                        .and_then(BtrfsExtentDataRef::from_bytes)
                        .ok_or(BtrfsMutationError::BrokenInvariant(
                            "truncated inline EXTENT_DATA_REF",
                        ))?;
                    cursor += DATA_REF_PAYLOAD;
                    InlineRef::Data(data_ref)
                }
                BTRFS_ITEM_SHARED_DATA_REF => {
                    let parent = read_u64(value, cursor)?;
                    let count = value
                        .get(cursor + 8..cursor + 12)
                        .map(|b| u32::from_le_bytes(b.try_into().expect("4 bytes")))
                        .ok_or(BtrfsMutationError::BrokenInvariant(
                            "truncated inline SHARED_DATA_REF",
                        ))?;
                    cursor += 12;
                    InlineRef::SharedData { parent, count }
                }
                _ => {
                    return Err(BtrfsMutationError::BrokenInvariant(
                        "unknown inline backref type in extent item",
                    ));
                }
            };
            inline.push(entry);
        }
        Ok(Self {
            refs,
            generation,
            flags,
            tree_block_info,
            inline,
        })
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(EXTENT_ITEM_HEADER + 64);
        out.extend_from_slice(&self.refs.to_le_bytes());
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        if let Some(info) = &self.tree_block_info {
            out.extend_from_slice(info);
        }
        for entry in &self.inline {
            entry.encode(&mut out);
        }
        out
    }
}

fn tree_ref_key(bytenr: u64, backref: TreeBlockBackref) -> BtrfsKey {
    match backref {
        TreeBlockBackref::Root(root) => BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_TREE_BLOCK_REF,
            offset: root,
        },
        TreeBlockBackref::Parent(parent) => BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_SHARED_BLOCK_REF,
            offset: parent,
        },
    }
}

#[derive(Debug)]
enum BackrefEdit<'a> {
    Insert(BtrfsKey, &'a [u8]),
    Replace(BtrfsKey, &'a [u8]),
    Remove(BtrfsKey),
}

/// Publish an extent item and its keyed references together. Thread a PRIVATE
/// root through the existing COW primitives, not the independently committing
/// public insert/update/delete methods. Only this batch's nodes may be changed
/// in place; rollback removes them without changing the committed root or its
/// retirement generation. This is in-memory error atomicity, not a disk commit.
fn edit_backref_items(
    tree: &mut InMemoryCowBtrfsTree,
    edits: &[BackrefEdit<'_>],
) -> Result<(), BtrfsMutationError> {
    if edits.is_empty() {
        return Ok(());
    }
    if !tree.staged_allocations.is_empty() || !tree.staged_deferred_frees.is_empty() {
        return Err(BtrfsMutationError::BrokenInvariant(
            "backref edit cannot nest inside a staged tree mutation",
        ));
    }
    let mut root = tree.root;
    for edit in edits {
        let result = match edit {
            BackrefEdit::Insert(key, value) => {
                tree.apply_staged_inserts(&mut root, &[(*key, value)])
            }
            BackrefEdit::Replace(key, value) => tree
                .replace_existing_in_root(root, key, value)
                .map(|updated| root = updated),
            BackrefEdit::Remove(key) => {
                tree.apply_staged_removals(&mut root, std::slice::from_ref(key))
            }
        };
        if let Err(error) = result {
            tree.rollback_mutation();
            return Err(error);
        }
    }
    tree.root = root;
    tree.commit_allocated_nodes();
    tree.commit_retired_nodes();
    Ok(())
}

impl BtrfsExtentAllocator {
    /// Key of the extent item describing the tree block at `bytenr`: a skinny
    /// `METADATA_ITEM` (offset = level) or a classic `EXTENT_ITEM`.
    fn tree_block_item_key(&self, bytenr: u64) -> Result<Option<BtrfsKey>, BtrfsMutationError> {
        let mut found = None;
        let lo = BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_EXTENT_ITEM,
            offset: 0,
        };
        let hi = BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_METADATA_ITEM,
            offset: u64::MAX,
        };
        self.extent_tree.range_with(&lo, &hi, |key, _| {
            if found.is_none()
                && (key.item_type == BTRFS_ITEM_METADATA_ITEM
                    || key.item_type == BTRFS_ITEM_EXTENT_ITEM)
            {
                found = Some(key);
            }
        })?;
        Ok(found)
    }

    fn load_extent_item(&self, key: BtrfsKey) -> Result<ExtentItem, BtrfsMutationError> {
        let value = self
            .extent_tree
            .get(&key)
            .ok_or(BtrfsMutationError::KeyNotFound)?;
        ExtentItem::parse(key, &value)
    }

    /// Refcount and flags of the tree block at `bytenr`, if it has an item.
    ///
    /// # Errors
    /// A malformed extent item or an extent-tree error.
    pub fn tree_block_ref_state(
        &self,
        bytenr: u64,
    ) -> Result<Option<ExtentRefState>, BtrfsMutationError> {
        let Some(key) = self.tree_block_item_key(bytenr)? else {
            return Ok(None);
        };
        let item = self.load_extent_item(key)?;
        Ok(Some(ExtentRefState {
            refs: item.refs,
            flags: item.flags,
        }))
    }

    /// Add one reference to the tree block at `bytenr` (keyed ref item).
    ///
    /// # Errors
    /// `KeyNotFound` without an extent item, `BrokenInvariant` if that exact
    /// reference already exists, or an extent-tree error.
    pub fn add_tree_block_backref(
        &mut self,
        bytenr: u64,
        backref: TreeBlockBackref,
    ) -> Result<(), BtrfsMutationError> {
        let key = self
            .tree_block_item_key(bytenr)?
            .ok_or(BtrfsMutationError::KeyNotFound)?;
        let mut item = self.load_extent_item(key)?;
        let inline_dup = item.inline.iter().any(|entry| {
            matches!(
                (entry, backref),
                (InlineRef::TreeRoot(r), TreeBlockBackref::Root(want)) if *r == want
            ) || matches!(
                (entry, backref),
                (InlineRef::TreeParent(p), TreeBlockBackref::Parent(want)) if *p == want
            )
        });
        let ref_key = tree_ref_key(bytenr, backref);
        if inline_dup || self.extent_tree.get(&ref_key).is_some() {
            return Err(BtrfsMutationError::BrokenInvariant(
                "tree block backref already present",
            ));
        }
        item.refs = item
            .refs
            .checked_add(1)
            .ok_or(BtrfsMutationError::AddressOverflow)?;
        edit_backref_items(
            &mut self.extent_tree,
            &[
                BackrefEdit::Insert(ref_key, &[]),
                BackrefEdit::Replace(key, &item.encode()),
            ],
        )
    }

    /// Drop one reference to the tree block at `bytenr`. Returns the remaining
    /// refcount; at zero the extent item is deleted and the block's space is
    /// pinned until the superblock that still points at it is replaced.
    ///
    /// # Errors
    /// `KeyNotFound` without an extent item, `BrokenInvariant` if the reference
    /// is not present, or an extent-tree error.
    pub fn remove_tree_block_backref(
        &mut self,
        bytenr: u64,
        backref: TreeBlockBackref,
    ) -> Result<u64, BtrfsMutationError> {
        let key = self
            .tree_block_item_key(bytenr)?
            .ok_or(BtrfsMutationError::KeyNotFound)?;
        let mut item = self.load_extent_item(key)?;
        // Validate the extent-wide count before deleting a keyed reference.
        item.refs = item
            .refs
            .checked_sub(1)
            .ok_or(BtrfsMutationError::BrokenInvariant(
                "tree block refcount underflow",
            ))?;
        let position = item.inline.iter().position(|entry| match (entry, backref) {
            (InlineRef::TreeRoot(r), TreeBlockBackref::Root(want)) => *r == want,
            (InlineRef::TreeParent(p), TreeBlockBackref::Parent(want)) => *p == want,
            _ => false,
        });
        let keyed_ref = if let Some(position) = position {
            item.inline.remove(position);
            None
        } else {
            let ref_key = tree_ref_key(bytenr, backref);
            if self.extent_tree.get(&ref_key).is_none() {
                return Err(BtrfsMutationError::BrokenInvariant(
                    "tree block backref to remove is not present",
                ));
            }
            Some(ref_key)
        };
        let encoded = item.encode();
        let extent_edit = if item.refs == 0 {
            BackrefEdit::Remove(key)
        } else {
            BackrefEdit::Replace(key, &encoded)
        };
        if let Some(ref_key) = keyed_ref {
            edit_backref_items(
                &mut self.extent_tree,
                &[BackrefEdit::Remove(ref_key), extent_edit],
            )?;
        } else {
            edit_backref_items(&mut self.extent_tree, &[extent_edit])?;
        }
        if item.refs == 0 {
            self.pin_extent(bytenr, self.nodesize, false);
            self.invalidate_tail_cursors();
        }
        Ok(item.refs)
    }

    /// Mark the tree block at `bytenr` `FULL_BACKREF`: its children are from
    /// now on referenced by this block's bytenr, not by its owner root.
    ///
    /// # Errors
    /// `KeyNotFound` without an extent item, or an extent-tree error.
    pub fn set_tree_block_full_backref(&mut self, bytenr: u64) -> Result<(), BtrfsMutationError> {
        let key = self
            .tree_block_item_key(bytenr)?
            .ok_or(BtrfsMutationError::KeyNotFound)?;
        let mut item = self.load_extent_item(key)?;
        item.flags |= BTRFS_EXTENT_FLAG_FULL_BACKREF;
        self.extent_tree.update(&key, &item.encode())?;
        Ok(())
    }

    /// Add `count` parent-keyed references (`SHARED_DATA_REF`, parent =
    /// `parent`) to the data extent `bytenr`/`num_bytes`.
    ///
    /// # Errors
    /// `KeyNotFound` without an extent item, `BrokenInvariant` for a zero
    /// count or malformed keyed reference, `AddressOverflow` if either count
    /// overflows, or an extent-tree error. Errors leave both the extent item
    /// and the keyed reference unchanged.
    pub fn add_shared_data_backref(
        &mut self,
        bytenr: u64,
        num_bytes: u64,
        parent: u64,
        count: u32,
    ) -> Result<(), BtrfsMutationError> {
        if count == 0 {
            return Err(BtrfsMutationError::BrokenInvariant(
                "shared data backref increment must be nonzero",
            ));
        }
        let key = BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_EXTENT_ITEM,
            offset: num_bytes,
        };
        let mut item = self.load_extent_item(key)?;
        item.refs = item
            .refs
            .checked_add(u64::from(count))
            .ok_or(BtrfsMutationError::AddressOverflow)?;
        if let Some(InlineRef::SharedData {
            count: existing, ..
        }) = item
            .inline
            .iter_mut()
            .find(|entry| matches!(entry, InlineRef::SharedData { parent: p, .. } if *p == parent))
        {
            *existing = existing
                .checked_add(count)
                .ok_or(BtrfsMutationError::AddressOverflow)?;
            self.extent_tree.update(&key, &item.encode())?;
            return Ok(());
        }
        let ref_key = BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_SHARED_DATA_REF,
            offset: parent,
        };
        let existing = self.extent_tree.get(&ref_key);
        let merged = match &existing {
            Some(value) => shared_data_ref_count(value)?
                .checked_add(count)
                .ok_or(BtrfsMutationError::AddressOverflow)?,
            None => count,
        };
        // Both the u64 extent total and the u32 keyed count are now valid.
        let encoded_count = merged.to_le_bytes();
        let ref_edit = if existing.is_some() {
            BackrefEdit::Replace(ref_key, &encoded_count)
        } else {
            BackrefEdit::Insert(ref_key, &encoded_count)
        };
        edit_backref_items(
            &mut self.extent_tree,
            &[ref_edit, BackrefEdit::Replace(key, &item.encode())],
        )
    }

    /// Remove `count` parent-keyed references (parent = `parent`) from the
    /// data extent. Returns the remaining refcount; the caller frees the extent
    /// at zero (this does not touch its space or checksums).
    ///
    /// # Errors
    /// `KeyNotFound` without an extent item, `BrokenInvariant` for a zero
    /// count, malformed keyed reference, or either count underflow, or an
    /// extent-tree error. Errors leave both the extent item and the keyed
    /// reference unchanged.
    pub fn remove_shared_data_backref(
        &mut self,
        bytenr: u64,
        num_bytes: u64,
        parent: u64,
        count: u32,
    ) -> Result<u64, BtrfsMutationError> {
        if count == 0 {
            return Err(BtrfsMutationError::BrokenInvariant(
                "shared data backref decrement must be nonzero",
            ));
        }
        let key = BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_EXTENT_ITEM,
            offset: num_bytes,
        };
        let mut item = self.load_extent_item(key)?;
        // A keyed ref may be decremented or deleted below. Reject a corrupt
        // extent total before publishing either change to the live tree.
        item.refs =
            item.refs
                .checked_sub(u64::from(count))
                .ok_or(BtrfsMutationError::BrokenInvariant(
                    "data extent refcount underflow",
                ))?;
        let position = item.inline.iter().position(
            |entry| matches!(entry, InlineRef::SharedData { parent: p, .. } if *p == parent),
        );
        if let Some(position) = position {
            let InlineRef::SharedData { count: have, .. } = &mut item.inline[position] else {
                unreachable!("position matched SharedData");
            };
            if *have < count {
                return Err(BtrfsMutationError::BrokenInvariant(
                    "shared data backref count underflow",
                ));
            }
            *have -= count;
            if *have == 0 {
                item.inline.remove(position);
            }
        } else {
            let ref_key = BtrfsKey {
                objectid: bytenr,
                item_type: BTRFS_ITEM_SHARED_DATA_REF,
                offset: parent,
            };
            let value =
                self.extent_tree
                    .get(&ref_key)
                    .ok_or(BtrfsMutationError::BrokenInvariant(
                        "shared data backref to remove is not present",
                    ))?;
            let have = shared_data_ref_count(&value)?;
            if have < count {
                return Err(BtrfsMutationError::BrokenInvariant(
                    "shared data backref count underflow",
                ));
            }
            let encoded_count = (have - count).to_le_bytes();
            let ref_edit = if have == count {
                BackrefEdit::Remove(ref_key)
            } else {
                BackrefEdit::Replace(ref_key, &encoded_count)
            };
            edit_backref_items(
                &mut self.extent_tree,
                &[ref_edit, BackrefEdit::Replace(key, &item.encode())],
            )?;
            return Ok(item.refs);
        }
        self.extent_tree.update(&key, &item.encode())?;
        Ok(item.refs)
    }
}

/// Byte length of the inline ref starting at `value[cursor]` (type byte
/// included), or `None` for an unknown type.
pub(crate) fn inline_ref_len(kind: u8) -> Option<usize> {
    match kind {
        BTRFS_ITEM_TREE_BLOCK_REF | BTRFS_ITEM_SHARED_BLOCK_REF | BTRFS_ITEM_EXTENT_OWNER_REF => {
            Some(9)
        }
        BTRFS_ITEM_EXTENT_DATA_REF => Some(1 + DATA_REF_PAYLOAD),
        BTRFS_ITEM_SHARED_DATA_REF => Some(13),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    const NODE: u64 = 16384;

    fn allocator() -> BtrfsExtentAllocator {
        let mut alloc = BtrfsExtentAllocator::new(7).expect("allocator");
        alloc.set_nodesize(NODE);
        alloc
    }

    fn metadata_key(bytenr: u64, level: u64) -> BtrfsKey {
        BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_METADATA_ITEM,
            offset: level,
        }
    }

    fn insert_tree_block(alloc: &mut BtrfsExtentAllocator, bytenr: u64, inline: Vec<InlineRef>) {
        let item = ExtentItem {
            refs: u64::try_from(inline.len()).expect("fits"),
            generation: 5,
            flags: BTRFS_EXTENT_FLAG_TREE_BLOCK,
            tree_block_info: None,
            inline,
        };
        alloc
            .extent_tree
            .insert(metadata_key(bytenr, 1), &item.encode())
            .expect("insert metadata item");
    }

    fn insert_keyed_data_ref(
        alloc: &mut BtrfsExtentAllocator,
        refs: u64,
        payload: &[u8],
    ) -> [BtrfsKey; 2] {
        let key = BtrfsKey {
            objectid: 40 << 20,
            item_type: BTRFS_ITEM_EXTENT_ITEM,
            offset: 4096,
        };
        let ref_key = BtrfsKey {
            objectid: key.objectid,
            item_type: BTRFS_ITEM_SHARED_DATA_REF,
            offset: 200 << 20,
        };
        let item = ExtentItem {
            refs,
            generation: 5,
            flags: 1,
            tree_block_info: None,
            inline: Vec::new(),
        };
        alloc
            .extent_tree
            .insert(key, &item.encode())
            .expect("insert data extent");
        alloc
            .extent_tree
            .insert(ref_key, payload)
            .expect("insert keyed data ref");
        [key, ref_key]
    }

    fn backref_state(alloc: &BtrfsExtentAllocator, keys: [BtrfsKey; 2]) -> [Option<Vec<u8>>; 2] {
        keys.map(|key| {
            alloc.extent_tree.get(&key).map(|value| {
                let bytes: &[u8] = &value;
                bytes.to_vec()
            })
        })
    }

    #[derive(Debug, PartialEq, Eq)]
    struct TreeState {
        root: u64,
        nodes: crate::FxHashMap<u64, crate::BtrfsCowNode>,
        deferred: Vec<u64>,
        previous: Vec<u64>,
    }

    fn tree_state(tree: &InMemoryCowBtrfsTree) -> TreeState {
        TreeState {
            root: tree.root,
            nodes: tree.nodes.clone(),
            deferred: tree.deferred_frees.clone(),
            previous: tree.prev_committed_retired.clone(),
        }
    }

    #[derive(Debug)]
    struct BudgetAllocator {
        next: u64,
        remaining: Arc<AtomicUsize>,
        returned: Arc<AtomicUsize>,
    }

    impl crate::BtrfsAllocator for BudgetAllocator {
        fn alloc_block(&mut self) -> Result<u64, BtrfsMutationError> {
            if self.remaining.load(Ordering::Relaxed) == 0 {
                return Err(BtrfsMutationError::NoSpace);
            }
            self.remaining.fetch_sub(1, Ordering::Relaxed);
            let block = self.next;
            self.next += 1;
            Ok(block)
        }

        fn defer_free(&mut self, _block: u64) {
            self.returned.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum Operation {
        AddTree,
        RemoveTree,
        RemoveLastTree,
        RemoveInlineTree,
        AddShared,
        IncrementShared,
        DecrementShared,
        RemoveShared,
    }

    fn fault_fixture(wide: bool, operation: Operation) -> BtrfsExtentAllocator {
        let mut alloc = allocator();
        if wide {
            alloc.extent_tree = InMemoryCowBtrfsTree::new(3).expect("small nodes");
        }
        insert_tree_block(&mut alloc, 2 << 20, vec![InlineRef::TreeRoot(5)]);
        alloc
            .add_tree_block_backref(2 << 20, TreeBlockBackref::Parent(9 << 20))
            .expect("initial parent");
        if matches!(operation, Operation::RemoveLastTree) {
            alloc
                .remove_tree_block_backref(2 << 20, TreeBlockBackref::Root(5))
                .expect("leave only the keyed parent");
        }
        insert_keyed_data_ref(&mut alloc, 2, &2_u32.to_le_bytes());
        if wide {
            for index in 0..64 {
                let key = BtrfsKey {
                    objectid: (index << 20) + 123,
                    item_type: 1,
                    offset: 0,
                };
                alloc.extent_tree.insert(key, &[0x5a; 32]).expect("filler");
            }
            assert!(alloc.extent_tree.height().expect("height") > 2);
        }
        alloc
            .extent_tree
            .validate_invariants()
            .expect("valid input");
        alloc
    }

    fn perform(
        alloc: &mut BtrfsExtentAllocator,
        operation: Operation,
    ) -> Result<(), BtrfsMutationError> {
        match operation {
            Operation::AddTree => {
                alloc.add_tree_block_backref(2 << 20, TreeBlockBackref::Root(256))
            }
            Operation::RemoveTree | Operation::RemoveLastTree => alloc
                .remove_tree_block_backref(2 << 20, TreeBlockBackref::Parent(9 << 20))
                .map(|_| ()),
            Operation::RemoveInlineTree => alloc
                .remove_tree_block_backref(2 << 20, TreeBlockBackref::Root(5))
                .map(|_| ()),
            Operation::AddShared => {
                alloc.add_shared_data_backref(40 << 20, 4096, (200 << 20) + NODE, 1)
            }
            Operation::IncrementShared => {
                alloc.add_shared_data_backref(40 << 20, 4096, 200 << 20, 1)
            }
            Operation::DecrementShared => alloc
                .remove_shared_data_backref(40 << 20, 4096, 200 << 20, 1)
                .map(|_| ()),
            Operation::RemoveShared => alloc
                .remove_shared_data_backref(40 << 20, 4096, 200 << 20, 2)
                .map(|_| ()),
        }
    }

    fn assert_operation_committed(alloc: &BtrfsExtentAllocator, operation: Operation) {
        let tree_refs = alloc.tree_block_ref_state(2 << 20).expect("tree state");
        let data_key = BtrfsKey {
            objectid: 40 << 20,
            item_type: BTRFS_ITEM_EXTENT_ITEM,
            offset: 4096,
        };
        let data_refs = alloc.load_extent_item(data_key).expect("data extent").refs;
        let (expected_tree, expected_data) = match operation {
            Operation::AddTree => (Some(3), 2),
            Operation::RemoveTree | Operation::RemoveInlineTree => (Some(1), 2),
            Operation::RemoveLastTree => (None, 2),
            Operation::AddShared | Operation::IncrementShared => (Some(2), 3),
            Operation::DecrementShared => (Some(2), 1),
            Operation::RemoveShared => (Some(2), 0),
        };
        assert_eq!(tree_refs.map(|state| state.refs), expected_tree);
        assert_eq!(data_refs, expected_data);
        let parent_key = tree_ref_key(2 << 20, TreeBlockBackref::Parent(9 << 20));
        let new_root_key = tree_ref_key(2 << 20, TreeBlockBackref::Root(256));
        assert_eq!(
            alloc.extent_tree.get(&parent_key),
            if matches!(operation, Operation::RemoveTree | Operation::RemoveLastTree) {
                None
            } else {
                Some(Vec::new())
            }
        );
        assert_eq!(
            alloc.extent_tree.get(&new_root_key),
            matches!(operation, Operation::AddTree).then(Vec::new)
        );
        let shared_key = BtrfsKey {
            item_type: BTRFS_ITEM_SHARED_DATA_REF,
            offset: 200 << 20,
            ..data_key
        };
        let expected_count: Option<u32> = match operation {
            Operation::IncrementShared => Some(3),
            Operation::DecrementShared => Some(1),
            Operation::RemoveShared => None,
            _ => Some(2),
        };
        assert_eq!(
            alloc.extent_tree.get(&shared_key),
            expected_count.map(|count| count.to_le_bytes().to_vec())
        );
        let new_shared_key = BtrfsKey {
            offset: shared_key.offset + NODE,
            ..shared_key
        };
        assert_eq!(
            alloc.extent_tree.get(&new_shared_key),
            matches!(operation, Operation::AddShared).then(|| 1_u32.to_le_bytes().to_vec())
        );
        assert_eq!(
            alloc.is_pinned(2 << 20),
            matches!(operation, Operation::RemoveLastTree)
        );
        alloc
            .extent_tree
            .validate_invariants()
            .expect("valid output");
    }

    #[test]
    fn allocation_failures_preserve_backrefs_and_support_retry() {
        let mut late_failures = 0;
        for wide in [false, true] {
            for operation in [
                Operation::AddTree,
                Operation::RemoveTree,
                Operation::RemoveLastTree,
                Operation::RemoveInlineTree,
                Operation::AddShared,
                Operation::IncrementShared,
                Operation::DecrementShared,
                Operation::RemoveShared,
            ] {
                let mut reached_success = false;
                for budget in 0..64 {
                    let mut alloc = fault_fixture(wide, operation);
                    let before = tree_state(&alloc.extent_tree);
                    let remaining = Arc::new(AtomicUsize::new(budget));
                    let returned = Arc::new(AtomicUsize::new(0));
                    let next = alloc.extent_tree.nodes.keys().copied().max().unwrap() + 1;
                    alloc.extent_tree.allocator = Box::new(BudgetAllocator {
                        next,
                        remaining: Arc::clone(&remaining),
                        returned: Arc::clone(&returned),
                    });
                    match perform(&mut alloc, operation) {
                        Ok(()) => reached_success = true,
                        Err(BtrfsMutationError::NoSpace) => {
                            assert_eq!(tree_state(&alloc.extent_tree), before);
                            assert_eq!(alloc.extent_tree.staged_allocations, Vec::<u64>::new());
                            assert_eq!(alloc.extent_tree.staged_deferred_frees, Vec::<u64>::new());
                            assert_eq!(returned.load(Ordering::Relaxed), budget);
                            assert!(!alloc.is_pinned(2 << 20));
                            late_failures += usize::from(budget > 0);
                            remaining.store(usize::MAX, Ordering::Relaxed);
                            perform(&mut alloc, operation).expect("retry after rollback");
                        }
                        Err(error) => panic!("unexpected {operation:?} failure: {error}"),
                    }
                    assert_operation_committed(&alloc, operation);
                    let previous_root = alloc
                        .extent_tree
                        .node_snapshot(before.root)
                        .expect("old root");
                    assert_eq!(previous_root, before.nodes[&before.root]);
                    if reached_success {
                        break;
                    }
                }
                assert!(reached_success, "allocation sweep exhausted: {operation:?}");
            }
        }
        assert!(late_failures > 0, "must fail after staging real COW nodes");
    }

    #[test]
    fn late_key_errors_discard_all_staged_backref_edits() {
        for wide in [false, true] {
            let mut alloc = fault_fixture(wide, Operation::AddTree);
            let key = metadata_key(2 << 20, 1);
            let absent = metadata_key(1000 << 20, 1);
            for edits in [
                [
                    BackrefEdit::Insert(absent, &[1]),
                    BackrefEdit::Remove(absent),
                ],
                [BackrefEdit::Replace(key, &[2]), BackrefEdit::Remove(key)],
                [BackrefEdit::Remove(key), BackrefEdit::Insert(key, &[3])],
            ] {
                let before = tree_state(&alloc.extent_tree);
                // Both preceding edits are valid against the PRIVATE root.
                // Only this final update is invalid, after actual COW work.
                let missing = metadata_key(1001 << 20, 1);
                let [first, second] = edits;
                let error = edit_backref_items(
                    &mut alloc.extent_tree,
                    &[first, second, BackrefEdit::Replace(missing, &[4])],
                )
                .expect_err("missing final update");
                assert_eq!(error, BtrfsMutationError::KeyNotFound);
                assert_eq!(tree_state(&alloc.extent_tree), before);
                assert_eq!(alloc.extent_tree.staged_allocations, Vec::<u64>::new());
                assert_eq!(alloc.extent_tree.staged_deferred_frees, Vec::<u64>::new());
                alloc
                    .extent_tree
                    .validate_invariants()
                    .expect("unchanged tree");
            }
        }
    }

    #[test]
    fn backref_batch_does_not_consume_another_staged_transaction() {
        let mut alloc = fault_fixture(false, Operation::AddTree);
        let tree = &mut alloc.extent_tree;
        let staged = tree
            .alloc_node(crate::BtrfsCowNode::Leaf { items: Vec::new() })
            .expect("existing staged node");
        let before = tree_state(tree);
        assert!(matches!(
            edit_backref_items(tree, &[BackrefEdit::Remove(metadata_key(2 << 20, 1))]),
            Err(BtrfsMutationError::BrokenInvariant(_))
        ));
        assert_eq!(tree_state(tree), before);
        assert_eq!(tree.staged_allocations, vec![staged]);
        tree.rollback_mutation();
    }

    #[test]
    fn keyed_tree_ref_underflow_preserves_both_items_and_does_not_pin() {
        for backref in [TreeBlockBackref::Root(5), TreeBlockBackref::Parent(9 << 20)] {
            let mut alloc = allocator();
            let bytenr = 2 << 20;
            // A corrupt zero total must not cause deletion of a live keyed ref.
            insert_tree_block(&mut alloc, bytenr, Vec::new());
            let ref_key = tree_ref_key(bytenr, backref);
            alloc.extent_tree.insert(ref_key, &[]).expect("keyed ref");
            let keys = [metadata_key(bytenr, 1), ref_key];
            let before = backref_state(&alloc, keys);
            assert!(matches!(
                alloc.remove_tree_block_backref(bytenr, backref),
                Err(BtrfsMutationError::BrokenInvariant(_))
            ));
            assert_eq!(backref_state(&alloc, keys), before);
            assert!(!alloc.is_pinned(bytenr));
        }
    }

    #[test]
    fn keyed_shared_ref_overflow_preserves_extent_total() {
        let mut alloc = allocator();
        let keys = insert_keyed_data_ref(&mut alloc, u64::from(u32::MAX), &u32::MAX.to_le_bytes());
        let before = backref_state(&alloc, keys);
        assert!(matches!(
            alloc.add_shared_data_backref(keys[0].objectid, 4096, keys[1].offset, 1),
            Err(BtrfsMutationError::AddressOverflow)
        ));
        assert_eq!(backref_state(&alloc, keys), before);
    }

    #[test]
    fn shared_ref_total_underflow_precedes_keyed_update_or_deletion() {
        // Exercise both a partial keyed decrement and removal of the last
        // keyed count when the extent-wide total is already inconsistent.
        for (total, decrement) in [(0, 1), (1, 2)] {
            let mut alloc = allocator();
            let keys = insert_keyed_data_ref(&mut alloc, total, &2_u32.to_le_bytes());
            let before = backref_state(&alloc, keys);
            assert!(matches!(
                alloc.remove_shared_data_backref(keys[0].objectid, 4096, keys[1].offset, decrement),
                Err(BtrfsMutationError::BrokenInvariant(_))
            ));
            assert_eq!(backref_state(&alloc, keys), before);
            assert!(!alloc.is_pinned(keys[0].objectid));
        }
    }

    #[test]
    fn malformed_keyed_shared_refs_are_not_replaced_or_truncated() {
        for payload in [
            vec![],
            vec![1],
            vec![1, 0, 0],
            vec![1, 0, 0, 0, 0],
            vec![0; 4],
        ] {
            let mut alloc = allocator();
            let keys = insert_keyed_data_ref(&mut alloc, 2, &payload);
            let before = backref_state(&alloc, keys);
            assert!(matches!(
                alloc.add_shared_data_backref(keys[0].objectid, 4096, keys[1].offset, 1),
                Err(BtrfsMutationError::BrokenInvariant(_))
            ));
            assert_eq!(backref_state(&alloc, keys), before);
            assert!(matches!(
                alloc.remove_shared_data_backref(keys[0].objectid, 4096, keys[1].offset, 1),
                Err(BtrfsMutationError::BrokenInvariant(_))
            ));
            assert_eq!(backref_state(&alloc, keys), before);
        }
    }

    #[test]
    fn zero_count_requests_neither_create_nor_edit_shared_refs() {
        let mut alloc = allocator();
        let keys = insert_keyed_data_ref(&mut alloc, 2, &2_u32.to_le_bytes());
        for parent in [keys[1].offset, keys[1].offset + NODE] {
            let before = backref_state(&alloc, keys);
            assert!(
                alloc
                    .add_shared_data_backref(keys[0].objectid, 4096, parent, 0)
                    .is_err()
            );
            assert!(
                alloc
                    .remove_shared_data_backref(keys[0].objectid, 4096, parent, 0)
                    .is_err()
            );
            assert_eq!(backref_state(&alloc, keys), before);
            if parent != keys[1].offset {
                assert!(
                    alloc
                        .extent_tree
                        .get(&BtrfsKey {
                            offset: parent,
                            ..keys[1]
                        })
                        .is_none()
                );
            }
        }
    }

    #[test]
    fn maximum_valid_shared_ref_count_round_trips() {
        let mut alloc = allocator();
        let initial = u32::MAX - 1;
        let keys = insert_keyed_data_ref(&mut alloc, u64::from(initial), &initial.to_le_bytes());
        let before = backref_state(&alloc, keys);
        alloc
            .add_shared_data_backref(keys[0].objectid, 4096, keys[1].offset, 1)
            .expect("u32::MAX is a valid count");
        assert_eq!(
            alloc.load_extent_item(keys[0]).expect("extent").refs,
            u64::from(u32::MAX)
        );
        assert_eq!(
            shared_data_ref_count(&alloc.extent_tree.get(&keys[1]).expect("keyed ref"))
                .expect("valid payload"),
            u32::MAX
        );
        assert_eq!(
            alloc
                .remove_shared_data_backref(keys[0].objectid, 4096, keys[1].offset, 1)
                .expect("decrement"),
            u64::from(initial)
        );
        assert_eq!(backref_state(&alloc, keys), before);
    }

    /// A kernel-snapshotted block: refs 2, inline [root 256, root 5]. Dropping
    /// root 5's reference keeps the item with only root 256's.
    #[test]
    fn removing_one_root_ref_of_a_shared_block_keeps_the_other() {
        let mut alloc = allocator();
        insert_tree_block(
            &mut alloc,
            1 << 20,
            vec![InlineRef::TreeRoot(256), InlineRef::TreeRoot(5)],
        );
        let left = alloc
            .remove_tree_block_backref(1 << 20, TreeBlockBackref::Root(5))
            .expect("remove root 5");
        assert_eq!(left, 1);
        let item = alloc
            .load_extent_item(metadata_key(1 << 20, 1))
            .expect("item survives");
        assert_eq!(item.inline, vec![InlineRef::TreeRoot(256)]);
        assert!(!alloc.is_pinned(1 << 20));
    }

    /// Keyed refs round-trip, the last removal deletes the item and pins the
    /// block (the old superblock may still point at it).
    #[test]
    fn keyed_parent_ref_round_trips_and_the_last_ref_pins() {
        let mut alloc = allocator();
        insert_tree_block(&mut alloc, 2 << 20, vec![InlineRef::TreeRoot(5)]);
        alloc
            .add_tree_block_backref(2 << 20, TreeBlockBackref::Parent(9 << 20))
            .expect("add parent ref");
        assert!(
            alloc
                .add_tree_block_backref(2 << 20, TreeBlockBackref::Parent(9 << 20))
                .is_err(),
            "duplicate refs are refused"
        );
        assert_eq!(
            alloc
                .tree_block_ref_state(2 << 20)
                .expect("state")
                .expect("item")
                .refs,
            2
        );
        assert_eq!(
            alloc
                .remove_tree_block_backref(2 << 20, TreeBlockBackref::Root(5))
                .expect("remove inline"),
            1
        );
        assert_eq!(
            alloc
                .remove_tree_block_backref(2 << 20, TreeBlockBackref::Parent(9 << 20))
                .expect("remove keyed"),
            0
        );
        assert!(
            alloc
                .tree_block_ref_state(2 << 20)
                .expect("state")
                .is_none()
        );
        assert!(alloc.is_pinned(2 << 20));
        assert!(
            alloc
                .remove_tree_block_backref(2 << 20, TreeBlockBackref::Root(5))
                .is_err(),
            "a missing item is an error, not a silent no-op"
        );
    }

    #[test]
    fn full_backref_flag_is_set_and_reported() {
        let mut alloc = allocator();
        insert_tree_block(&mut alloc, 3 << 20, vec![InlineRef::TreeRoot(5)]);
        assert!(
            !alloc
                .tree_block_ref_state(3 << 20)
                .unwrap()
                .unwrap()
                .full_backref()
        );
        alloc
            .set_tree_block_full_backref(3 << 20)
            .expect("set flag");
        assert!(
            alloc
                .tree_block_ref_state(3 << 20)
                .unwrap()
                .unwrap()
                .full_backref()
        );
    }

    /// A kernel data extent with an inline root-5 ref and an inline shared ref
    /// (what a balance leaves). Shared refs add/remove by parent, and removing
    /// the root-keyed ref steps over the shared inline entry instead of failing.
    #[test]
    fn shared_data_refs_and_root_ref_removal_coexist() {
        let mut alloc = allocator();
        let key = BtrfsKey {
            objectid: 40 << 20,
            item_type: BTRFS_ITEM_EXTENT_ITEM,
            offset: 4096,
        };
        let item = ExtentItem {
            refs: 2,
            generation: 5,
            flags: 1,
            tree_block_info: None,
            inline: vec![
                InlineRef::SharedData {
                    parent: 100 << 20,
                    count: 1,
                },
                InlineRef::Data(BtrfsExtentDataRef {
                    root: 5,
                    objectid: 257,
                    offset: 0,
                    count: 1,
                }),
            ],
        };
        alloc
            .extent_tree
            .insert(key, &item.encode())
            .expect("insert");

        alloc
            .add_shared_data_backref(40 << 20, 4096, 200 << 20, 1)
            .expect("keyed shared ref");
        assert_eq!(alloc.load_extent_item(key).unwrap().refs, 3);
        alloc
            .remove_data_extent_ref(40 << 20, 4096, 5, 257, 0)
            .expect("root ref removal steps over the shared inline ref");
        assert_eq!(
            alloc
                .remove_shared_data_backref(40 << 20, 4096, 100 << 20, 1)
                .expect("inline shared"),
            1
        );
        assert_eq!(
            alloc
                .remove_shared_data_backref(40 << 20, 4096, 200 << 20, 1)
                .expect("keyed shared"),
            0
        );
        assert_eq!(alloc.load_extent_item(key).unwrap().inline, Vec::new());
        assert!(
            alloc
                .remove_shared_data_backref(40 << 20, 4096, 200 << 20, 1)
                .is_err()
        );
    }

    #[test]
    fn unknown_inline_types_are_refused_not_misparsed() {
        let mut value = vec![0_u8; EXTENT_ITEM_HEADER];
        value.push(0x99);
        value.extend_from_slice(&[0; 8]);
        assert!(ExtentItem::parse(metadata_key(1, 0), &value).is_err());
    }
}
