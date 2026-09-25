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

use crate::{
    BTRFS_ITEM_EXTENT_DATA_REF, BTRFS_ITEM_EXTENT_ITEM, BTRFS_ITEM_METADATA_ITEM,
    BTRFS_ITEM_TREE_BLOCK_REF, BtrfsBTree, BtrfsExtentAllocator, BtrfsExtentDataRef, BtrfsKey,
    BtrfsMutationError,
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
        self.extent_tree.update(&key, &item.encode())?;
        self.extent_tree.insert(ref_key, &[])?;
        Ok(())
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
        let position = item.inline.iter().position(|entry| match (entry, backref) {
            (InlineRef::TreeRoot(r), TreeBlockBackref::Root(want)) => *r == want,
            (InlineRef::TreeParent(p), TreeBlockBackref::Parent(want)) => *p == want,
            _ => false,
        });
        if let Some(position) = position {
            item.inline.remove(position);
        } else {
            let ref_key = tree_ref_key(bytenr, backref);
            if self.extent_tree.get(&ref_key).is_none() {
                return Err(BtrfsMutationError::BrokenInvariant(
                    "tree block backref to remove is not present",
                ));
            }
            self.extent_tree.delete(&ref_key)?;
        }
        item.refs = item
            .refs
            .checked_sub(1)
            .ok_or(BtrfsMutationError::BrokenInvariant(
                "tree block refcount underflow",
            ))?;
        if item.refs == 0 {
            self.extent_tree.delete(&key)?;
            self.pin_extent(bytenr, self.nodesize, false);
            self.invalidate_tail_cursors();
        } else {
            self.extent_tree.update(&key, &item.encode())?;
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
    /// `KeyNotFound` without an extent item, or an extent-tree error.
    pub fn add_shared_data_backref(
        &mut self,
        bytenr: u64,
        num_bytes: u64,
        parent: u64,
        count: u32,
    ) -> Result<(), BtrfsMutationError> {
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
        self.extent_tree.update(&key, &item.encode())?;
        let ref_key = BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_SHARED_DATA_REF,
            offset: parent,
        };
        let merged = match self.extent_tree.get(&ref_key) {
            Some(existing) if existing.len() >= 4 => {
                u32::from_le_bytes(existing[0..4].try_into().expect("4 bytes"))
                    .checked_add(count)
                    .ok_or(BtrfsMutationError::AddressOverflow)?
            }
            _ => count,
        };
        if self.extent_tree.get(&ref_key).is_some() {
            self.extent_tree.update(&ref_key, &merged.to_le_bytes())?;
        } else {
            self.extent_tree.insert(ref_key, &merged.to_le_bytes())?;
        }
        Ok(())
    }

    /// Remove `count` parent-keyed references (parent = `parent`) from the
    /// data extent. Returns the remaining refcount; the caller frees the extent
    /// at zero (this does not touch its space or checksums).
    ///
    /// # Errors
    /// `KeyNotFound` without an extent item, `BrokenInvariant` if fewer than
    /// `count` such references exist, or an extent-tree error.
    pub fn remove_shared_data_backref(
        &mut self,
        bytenr: u64,
        num_bytes: u64,
        parent: u64,
        count: u32,
    ) -> Result<u64, BtrfsMutationError> {
        let key = BtrfsKey {
            objectid: bytenr,
            item_type: BTRFS_ITEM_EXTENT_ITEM,
            offset: num_bytes,
        };
        let mut item = self.load_extent_item(key)?;
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
            let have = self
                .extent_tree
                .get(&ref_key)
                .filter(|v| v.len() >= 4)
                .map(|v| u32::from_le_bytes(v[0..4].try_into().expect("4 bytes")))
                .ok_or(BtrfsMutationError::BrokenInvariant(
                    "shared data backref to remove is not present",
                ))?;
            if have < count {
                return Err(BtrfsMutationError::BrokenInvariant(
                    "shared data backref count underflow",
                ));
            }
            if have == count {
                self.extent_tree.delete(&ref_key)?;
            } else {
                self.extent_tree
                    .update(&ref_key, &(have - count).to_le_bytes())?;
            }
        }
        item.refs =
            item.refs
                .checked_sub(u64::from(count))
                .ok_or(BtrfsMutationError::BrokenInvariant(
                    "data extent refcount underflow",
                ))?;
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
