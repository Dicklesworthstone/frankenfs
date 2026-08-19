//! VFS operation dispatch for [`OpenFs`].

use super::*;
use crate::vfs::XattrPresence;

/// The largest inode table this scan will walk before giving up.
///
/// A bound, not a tuning knob: the scan runs once at mount and its answer is
/// only useful if it is cheap enough that nobody is tempted to skip it. At
/// 256Ki inodes it is a few thousand cached block reads. Past that the honest
/// answer is [`XattrPresence::Unknown`], which costs a caller only the
/// suppression they never had.
const XATTR_SCAN_INODE_LIMIT: u32 = 262_144;

impl OpenFs {
    /// Walk the inode table and decide whether ANY inode carries an xattr.
    ///
    /// Every exit that is not a completed clean walk returns
    /// [`XattrPresence::Unknown`] or [`XattrPresence::Present`]. This answer
    /// gates a switch that cannot be un-thrown for the life of a FUSE
    /// connection, so an unreadable inode, a missing superblock, or an inode
    /// table larger than the bound must all fail towards "there might be one".
    fn ext4_scan_for_any_xattr(&self, cx: &Cx) -> XattrPresence {
        let Some(sb) = self.ext4_superblock() else {
            return XattrPresence::Unknown;
        };
        let count = sb.inodes_count;
        if count == 0 || count > XATTR_SCAN_INODE_LIMIT {
            return XattrPresence::Unknown;
        }
        for ino in 1..=count {
            match self.read_inode(cx, InodeNumber(u64::from(ino))) {
                Ok(inode) => {
                    if ffs_xattr::inode_has_any_xattr(&inode) {
                        tracing::debug!(ino, "xattr scan: found one, suppression unavailable");
                        return XattrPresence::Present;
                    }
                }
                // An inode that DOES NOT EXIST is skipped, not treated as a
                // failure. Reserved and free inodes read as NotFound -- ext4
                // inode 1 (bad blocks) is the very first one -- and an inode
                // nothing can read cannot serve an xattr to anyone, because
                // every xattr read goes through this same read. Bailing here
                // was the first version of this scan and it made `auto` return
                // Unknown on every image in existence.
                Err(FfsError::NotFound(_)) => {}
                // Anything else is a real failure and must fail towards
                // "there might be one".
                Err(e) => {
                    // Warn, not debug: the operator ASKED for `auto` and is not getting it,
                    // and the inode that refused the proof is the only useful thing to say.
                    tracing::warn!(ino, error = %e, "xattr scan: unreadable inode, no proof");
                    return XattrPresence::Unknown;
                }
            }
        }
        XattrPresence::ProvenAbsent
    }
}

/// The most fs-tree NODES the btrfs xattr scan will read before giving up.
///
/// A bound on NODES, not on bytes, and the difference is the whole point. The
/// first version of this bounded on the superblock's `bytes_used` and was
/// wrong: memory here scales with the number of ITEMS in the fs tree, which
/// `bytes_used` does not constrain at all. A 4 GiB filesystem holding one 4 GiB
/// file has a handful of items; a 4 GiB filesystem holding four million small
/// files has millions, and the old code materialised every one of them into a
/// `Vec<BtrfsLeafEntry>` at mount before looking at any of them.
///
/// Measured on the 2048-entry fixture: the whole-tree walk cost +7.5 MB of peak
/// RSS (56,388 kB -> 63,852 kB) for ~2100 files, i.e. roughly 3.5 kB per file
/// held live at once. Extrapolated to a few million files that is gigabytes, at
/// mount, for a question that can be answered by reading one node at a time.
///
/// At 16 kB nodes this cap is ~4 GiB of tree read in the worst case, but only
/// one node is ever live, and the scan stops at the FIRST `XATTR_ITEM` it sees.
const XATTR_SCAN_BTRFS_NODE_LIMIT: usize = 262_144;

impl OpenFs {
    /// Decide whether ANY btrfs `XATTR_ITEM` exists in the fs tree.
    ///
    /// Same contract as the ext4 scan: every exit that is not a completed clean
    /// walk returns [`XattrPresence::Unknown`] or [`XattrPresence::Present`],
    /// because the answer gates a switch that cannot be un-thrown for the life
    /// of a FUSE connection.
    ///
    /// Note what is NOT checked: subvolumes other than the mounted one. This
    /// walks the fs tree this mount serves, which is exactly the scope the
    /// suppression applies to -- the kernel's `no_getxattr` is per connection,
    /// and a connection serves one subvolume.
    fn btrfs_scan_for_any_xattr(&self, cx: &Cx) -> XattrPresence {
        // One node at a time, and stop at the first hit. The previous version
        // called `walk_btrfs_fs_tree`, which materialises EVERY item in the
        // filesystem into one `Vec` before the first key is examined -- for a
        // yes/no question whose answer is usually decided by the first
        // `XATTR_ITEM` encountered, or not at all.
        let subvol = self
            .btrfs_context()
            .map_or(BTRFS_FS_TREE_OBJECTID, |ctx| ctx.subvol_objectid);
        let Ok(root) = self.btrfs_fs_tree_root_bytenr(cx, subvol) else {
            return XattrPresence::Unknown;
        };
        let Ok(nodes) = self.btrfs_tree_node_addresses(cx, root) else {
            return XattrPresence::Unknown;
        };
        if nodes.len() > XATTR_SCAN_BTRFS_NODE_LIMIT {
            return XattrPresence::Unknown;
        }
        for logical in nodes {
            let Ok(node) = self.btrfs_read_parsed_node(cx, logical) else {
                // An unreadable node is not proof of absence, and this answer
                // gates a switch that cannot be un-thrown.
                return XattrPresence::Unknown;
            };
            if let BtrfsParsedNode::Leaf { items, .. } = node.as_ref()
                && items
                    .iter()
                    .any(|item| item.key.item_type == BTRFS_ITEM_XATTR_ITEM)
            {
                return XattrPresence::Present;
            }
        }
        XattrPresence::ProvenAbsent
    }
}

/// One parent/child generation disagreement found by [`OpenFs::btrfs_transid_mismatches`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BtrfsTransidMismatch {
    /// Logical address of the CHILD block whose header disagrees.
    pub logical: u64,
    /// Generation the parent's key-pointer claims.
    pub wanted: u64,
    /// Generation the child block actually carries.
    pub found: u64,
}

impl OpenFs {
    /// Every parent/child generation disagreement reachable from a tree root.
    ///
    /// This is the kernel's `parent transid verify`, run on our side (bd-73bi2).
    /// Above ~4000 creates through a FrankenFS mount, an image acquires a free-
    /// space-tree pointer claiming generation 10 over a block still carrying 9,
    /// and the kernel refuses to open the filesystem -- while FrankenFS reads it
    /// back perfectly and lists every file. That asymmetry is why this exists:
    /// no test that round-trips through FrankenFS alone can see the corruption,
    /// and that is most of our btrfs coverage.
    ///
    /// Reads one node at a time and returns the disagreements rather than the
    /// first, so a caller can tell "one stale block" from "the whole tree is a
    /// generation behind" -- those are different bugs.
    pub fn btrfs_transid_mismatches(
        &self,
        cx: &Cx,
        root_logical: u64,
    ) -> Result<Vec<BtrfsTransidMismatch>, FfsError> {
        let mut found = Vec::new();
        for logical in self.btrfs_tree_node_addresses(cx, root_logical)? {
            let node = self
                .btrfs_read_parsed_node(cx, logical)
                .map_err(|e| parse_to_ffs_error(&e))?;
            let BtrfsParsedNode::Internal { ptrs } = node.as_ref() else {
                continue;
            };
            for ptr in ptrs {
                // Read the CHILD's own header and compare it against what this
                // pointer claims. `btrfs_read_parsed_node` verifies the block's
                // checksum on the way in, so a mismatch reported here is a
                // generation disagreement and not a torn block.
                let child = self
                    .btrfs_read_parsed_node(cx, ptr.blockptr)
                    .map_err(|e| parse_to_ffs_error(&e))?;
                let generation = match child.as_ref() {
                    BtrfsParsedNode::Leaf { block, .. } => {
                        ffs_btrfs::parent_transid_mismatch(ptr.generation, block)
                    }
                    // An internal child's parsed form drops its header, so ask
                    // the layer that still has the bytes.
                    BtrfsParsedNode::Internal { .. } => self
                        .btrfs_tree_block_generation(cx, ptr.blockptr)
                        .map(|actual| {
                            (actual != ptr.generation).then_some((ptr.generation, actual))
                        })
                        .unwrap_or(None),
                };
                if let Some((wanted, actual)) = generation {
                    found.push(BtrfsTransidMismatch {
                        logical: ptr.blockptr,
                        wanted,
                        found: actual,
                    });
                }
            }
        }
        Ok(found)
    }

    /// Every ROOT_ITEM whose generation disagrees with the block it points at.
    ///
    /// The internal-node walk above cannot see this class, and bd-73bi2 is
    /// exactly this class: the root tree's ROOT_ITEM for the free space tree
    /// (objectid 10) claims generation 10 over a block still carrying 9, and the
    /// kernel says `parent transid verify failed on logical 30474240 wanted 10
    /// found 9` before it has descended into any tree at all. A detector that
    /// only compares key-pointers to children reports such an image CLEAN --
    /// which is what the first version of this did.
    pub fn btrfs_root_item_transid_mismatches(
        &self,
        cx: &Cx,
    ) -> Result<Vec<BtrfsTransidMismatch>, FfsError> {
        let Some(sb) = self.btrfs_superblock() else {
            return Ok(Vec::new());
        };
        let mut found = Vec::new();
        for logical in self.btrfs_tree_node_addresses(cx, sb.root)? {
            let node = self
                .btrfs_read_parsed_node(cx, logical)
                .map_err(|e| parse_to_ffs_error(&e))?;
            let BtrfsParsedNode::Leaf { block, items } = node.as_ref() else {
                continue;
            };
            for item in items {
                if item.key.item_type != BTRFS_ITEM_ROOT_ITEM {
                    continue;
                }
                let start = item.data_offset as usize;
                let end = start + item.data_size as usize;
                let Some(payload) = block.get(start..end) else {
                    continue;
                };
                let Ok(root_item) = ffs_btrfs::parse_root_item(payload) else {
                    continue;
                };
                if let Some(actual) = self.btrfs_tree_block_generation(cx, root_item.bytenr)
                    && actual != root_item.generation
                {
                    found.push(BtrfsTransidMismatch {
                        logical: root_item.bytenr,
                        wanted: root_item.generation,
                        found: actual,
                    });
                }
            }
        }
        Ok(found)
    }

    /// The generation in a tree block's header, read directly.
    fn btrfs_tree_block_generation(&self, cx: &Cx, logical: u64) -> Option<u64> {
        let ctx = self.btrfs_context()?;
        let ns = usize::try_from(ctx.nodesize).ok()?;
        let mapping = map_logical_to_physical(&ctx.chunks, logical).ok()??;
        let mut buf = vec![0_u8; ns];
        self.dev
            .read_exact_at(cx, ByteOffset(mapping.physical), &mut buf)
            .ok()?;
        ffs_btrfs::BtrfsHeader::parse_from_block(&buf)
            .ok()
            .map(|header| header.generation)
    }
}

impl FsOps for OpenFs {
    fn xattr_presence(&self, cx: &Cx) -> XattrPresence {
        match &self.flavor {
            FsFlavor::Ext4(_) => self.ext4_scan_for_any_xattr(cx),
            FsFlavor::Btrfs(_) => self.btrfs_scan_for_any_xattr(cx),
        }
    }

    /// Resolve many inodes, visiting them in INODE ORDER regardless of the order
    /// asked for (bd-xfe7z / bd-5vis3).
    ///
    /// The trait default loops in the caller's order, which for btrfs is readdir
    /// order — and btrfs readdir returns entries in DIR_INDEX order, unrelated to
    /// objectid. Each `getattr` is then an independent floor descent that lands in
    /// a different leaf from the last, so the retained-leaf memo misses on
    /// essentially every entry. Sorting first makes consecutive lookups fall in the
    /// same leaf, which is the locality the memo exists to exploit: bd-5vis3's
    /// finding is that what pays is amortising the descent ACROSS inodes that share
    /// a leaf, not caching individual inodes.
    ///
    /// ⚠️ THE RETURNED ORDER IS THE REQUESTED ORDER. The trait contract is one
    /// result per requested inode, positionally, so the caller can zip it against
    /// its entries; only the VISIT order changes. Getting that wrong would attach
    /// every entry's attributes to the wrong name — silent and severe — so the
    /// permutation is inverted explicitly rather than by re-sorting the results.
    ///
    /// ONE ENTRY PER PAGE IS EXEMPT, and the claim is stated exactly rather than
    /// approximately. The sort key is the PRESENTED inode, while the descent uses
    /// the canonical one. Both canonicalisers are the identity except for the VFS
    /// root alias — `btrfs_canonical_inode` maps `1` to the subvolume's
    /// `subvol_root_dirid`, `ext4_canonical_inode` maps `1` to `2` — so presented
    /// order IS canonical order for every entry except `.`, which sorts as 1 and
    /// resolves elsewhere. That costs at most one extra descent per page and
    /// cannot affect correctness, since visit order only influences locality.
    /// Canonicalising inside the sort key would add a fallible call per entry to
    /// save that one descent, which is the wrong trade.
    ///
    /// Independent of `FFS_FUSE_READDIRPLUS_INODE_ORDER`, which sorts at the FUSE
    /// layer and is opt-in: this makes the locality available to every batch
    /// caller. Sorting an already-sorted slice is near-free, so the two compose
    /// rather than conflict.
    fn getattr_batch(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        inos: &[InodeNumber],
    ) -> Vec<ffs_error::Result<InodeAttr>> {
        // Not worth permuting for a batch this small; the sort would cost more
        // than the locality it buys.
        if inos.len() < 2 {
            return inos
                .iter()
                .map(|ino| <Self as FsOps>::getattr(self, cx, scope, *ino))
                .collect();
        }
        let mut order: Vec<usize> = (0..inos.len()).collect();
        order.sort_unstable_by_key(|&index| inos[index].0);

        let mut slots: Vec<Option<ffs_error::Result<InodeAttr>>> =
            (0..inos.len()).map(|_| None).collect();
        for index in order {
            // FULLY QUALIFIED, and it must be. `self.getattr(..)` resolves to the
            // INHERENT `OpenFs::getattr`, which takes (cx, ino) and wraps itself in
            // `with_latest_scope` — so it would not merely fail to compile, it would
            // open a FRESH request scope per inode and throw away the one thing a
            // batch is for. The compiler caught the arity; the scope is the reason.
            slots[index] = Some(<Self as FsOps>::getattr(self, cx, scope, inos[index]));
        }
        slots
            .into_iter()
            .map(|slot| slot.expect("every slot is filled exactly once by the permutation"))
            .collect()
    }

    fn getattr(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<InodeAttr> {
        match &self.flavor {
            FsFlavor::Ext4(_) => self
                .read_inode_attr_with_scope(cx, scope, Self::ext4_canonical_inode(ino))
                .map(Self::ext4_present_attr),
            FsFlavor::Btrfs(_) => self.btrfs_read_inode_attr(cx, ino),
        }
    }

    fn lookup(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
    ) -> ffs_error::Result<InodeAttr> {
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                let parent_ino = Self::ext4_canonical_inode(parent);
                // Reuse the parsed, dir-verified parent across a directory scan's
                // repeated lookups (RO mount → immutable) instead of re-reading +
                // re-parsing the parent inode every time (bd-cc-ext4-hotparent).
                let read_only = !self.is_writable();
                // Hold the arc_swap Guard and BORROW the parent inode straight
                // out of it instead of `Arc::clone`-ing the inner Arc per hit —
                // the clone's incref/decref pair was part of the 8.46% arc_swap
                // self-time on `lookup-bench` (same-dir stream → hits every
                // lookup). The Guard keeps the slot alive for the borrow's
                // lifetime; a concurrent `store` keeps the old value live until
                // this Guard drops.
                let hot_guard = if read_only {
                    Some(self.ext4_hot_parent.load())
                } else {
                    None
                };
                let hot_parent: Option<&Arc<Ext4Inode>> = hot_guard.as_ref().and_then(|g| {
                    g.as_ref()
                        .filter(|slot| slot.0 == parent_ino.0)
                        .map(|slot| &slot.1)
                });
                let parent_storage;
                let parent_inode: &Ext4Inode = match hot_parent {
                    Some(arc) => arc.as_ref(),
                    None => {
                        let parsed = self.read_inode_metadata_with_scope(cx, scope, parent_ino)?;
                        if !parsed.is_dir() {
                            return Err(FfsError::NotDirectory);
                        }
                        if read_only {
                            self.ext4_hot_parent
                                .store(Some(Arc::new((parent_ino.0, Arc::new(parsed.clone())))));
                        }
                        parent_storage = parsed;
                        &parent_storage
                    }
                };

                let name_bytes = name.as_encoded_bytes();
                let entry = self
                    .lookup_name_with_scope(cx, scope, parent_inode, name_bytes)?
                    .ok_or_else(|| FfsError::NotFound(name.to_string_lossy().into_owned()))?;

                let child_ino = InodeNumber(u64::from(entry.inode));
                self.read_inode_attr_with_scope(cx, scope, child_ino)
                    .map(Self::ext4_present_attr)
            }
            FsFlavor::Btrfs(_) => self.btrfs_lookup_child(cx, parent, name.as_encoded_bytes()),
        }
    }

    fn readdir(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
    ) -> ffs_error::Result<ReaddirPage> {
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                let canonical = Self::ext4_canonical_inode(ino);
                let inode = self.read_inode_metadata_with_scope(cx, scope, canonical)?;
                if !inode.is_dir() {
                    return Err(FfsError::NotDirectory);
                }

                // Serve a later page from the snapshot if the directory is
                // unchanged since it was taken (any mutation bumps ctime/mtime) —
                // avoiding a full re-read+re-parse per paginated readdir call.
                let validation = ReaddirValidation {
                    ctime: (u64::from(inode.ctime) << 32) | u64::from(inode.ctime_extra),
                    mtime: u64::from(inode.mtime),
                    size: inode.size,
                };
                if let Some(page) =
                    readdir_snapshot_serve(&self.readdir_snapshot, canonical.0, validation, offset)
                {
                    if !scope.skip_readdir_prefetch
                        && !self
                            .readdir_prefetch_disabled
                            .load(std::sync::atomic::Ordering::Relaxed)
                    {
                        self.prefetch_ext4_readdir_inode_table_blocks(cx, scope, page.as_slice());
                    }
                    return Ok(page);
                }

                #[cfg(test)]
                self.readdir_full_reads
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let raw_entries = self.read_dir_with_scope(cx, scope, &inode)?;
                // On a read-only mount the directory is immutable, so cache this full
                // readdir as a name->dirent snapshot: subsequent present-name lookups
                // (ls -l, directory scans) answer O(1) from it instead of descending
                // the htree + linearly scanning the hash-leaf per name. Non-casefold
                // only (keys on exact name bytes); read-only only (never goes stale)
                // (bd-cc-ext4-presentidx).
                //
                // Skip the build entirely for a ONE-PASS consumer (the
                // `readonly_lookup_cache_disabled` contract): `ls -f`,
                // getdents/name-enumeration, and any `walk` (--no-stat OR full stat,
                // which getattrs by inode and never issues a name `lookup`) never
                // query this index, so cloning every name into an FxHashMap per
                // readdir is pure dead work (~7% of a 30000-entry read-only
                // `walk --no-stat`; still ~2% under a full stat walk).
                if canonical.0 != 0
                    && !self.is_writable()
                    && inode.flags & ffs_types::EXT4_CASEFOLD_FL == 0
                    && !self
                        .readonly_lookup_cache_disabled
                        .load(std::sync::atomic::Ordering::Relaxed)
                {
                    let present: rustc_hash::FxHashMap<Vec<u8>, (u32, Ext4FileType)> = raw_entries
                        .iter()
                        .map(|e| (e.name.clone(), (e.inode, e.file_type)))
                        .collect();
                    *self.dir_name_index_shard(canonical.0).lock() = Some(DirNameIndex {
                        inode: canonical.0,
                        validation,
                        // `present` is complete and lookup consults it first, so
                        // cloning every key into `names` would only duplicate
                        // ownership. Demotion moves these keys into the set.
                        names: rustc_hash::FxHashSet::default(),
                        present: Some(present),
                    });
                }
                // Build the FULL list (offset 0) once; cookies are 1-indexed
                // positions (ascending), so the binary-search slice serves any
                // page exactly.
                let full: Vec<DirEntry> = raw_entries
                    .into_iter()
                    .enumerate()
                    .map(|(idx, e)| {
                        Self::ext4_present_dir_entry(DirEntry {
                            ino: InodeNumber(u64::from(e.inode)),
                            offset: (idx as u64) + 1,
                            kind: dir_entry_file_type(e.file_type),
                            name: e.name,
                        })
                    })
                    .collect();
                let full = Arc::new(full);
                let page = slice_readdir_snapshot(Arc::clone(&full), offset);
                if !scope.skip_readdir_prefetch
                    && !self
                        .readdir_prefetch_disabled
                        .load(std::sync::atomic::Ordering::Relaxed)
                {
                    self.prefetch_ext4_readdir_inode_table_blocks(cx, scope, page.as_slice());
                }
                readdir_snapshot_store(&self.readdir_snapshot, canonical.0, validation, full);
                Ok(page)
            }
            FsFlavor::Btrfs(_) => {
                // Same snapshot lever as ext4: a paginated readdir otherwise
                // re-walks the dir's DIR_INDEX items on every call (O(N^2)).
                //
                // Active on BOTH read-only and writable mounts. Correctness on
                // the writable path rests on EXPLICIT invalidation, not on
                // timestamp self-validation: every FsOps directory mutation
                // (create/mknod/mkdir/unlink/rmdir/rename/rename2/link/symlink)
                // calls clear_readdir_snapshot() before mutating, so a later
                // readdir can never serve a listing that predates a change —
                // including a rename's '..' update, which does not reliably bump
                // the dir's change-time (the reason an earlier revision gated
                // this to read-only). readdir vs. mutation on the same dir is
                // serialized by the FUSE dispatcher's inode locks, identical to
                // the ext4 writable snapshot above.
                let canonical = self.btrfs_canonical_inode(ino)?;
                // bd-btrfs-ro-readdir: on a mount that cannot be written through,
                // the snapshot cannot go stale, so skip the per-call attr lookup
                // that exists only to build the validation key. On btrfs that
                // lookup is a tree descent, paid once per readdir PAGE for a
                // listing already in hand -- ~209 descents for a 20000-entry
                // directory, each one a fresh chance to miss the block cache.
                // That per-call variance is the leading remaining suspect for
                // the btrfs readdir+stat A/A null, which has never cleared in 7
                // attempts and whose best is only 0.5 points over the ceiling.
                //
                // `btrfs_alloc_state` is `None` exactly when the mount is
                // read-only, which is the same condition the writable path below
                // branches on, so this cannot diverge from it.
                if btrfs_ro_readdir_snapshot_enabled() && self.btrfs_alloc_state.is_none() {
                    if let Some(page) = readdir_snapshot_serve_unvalidated(
                        &self.readdir_snapshot,
                        canonical,
                        offset,
                    ) {
                        // bd-btrfs-readdir-stat-8x-8y7vp: warm THIS page, not just
                        // the first. A full listing is paginated, and every page
                        // after the first is served from the snapshot and returns
                        // here — so hooking only the fresh walk below warmed one
                        // page out of a directory's worth. ext4 hooks its snapshot
                        // path for the same reason.
                        self.maybe_prefetch_btrfs_readdir_leaves(cx, scope, page.as_slice());
                        return Ok(page);
                    }
                }
                let attr = self.btrfs_read_inode_attr(cx, ino)?;
                if attr.kind != FileType::Directory {
                    return Err(FfsError::NotDirectory);
                }
                let validation = ReaddirValidation {
                    ctime: systemtime_nanos(attr.ctime),
                    mtime: systemtime_nanos(attr.mtime),
                    size: attr.size,
                };
                if let Some(page) =
                    readdir_snapshot_serve(&self.readdir_snapshot, canonical, validation, offset)
                {
                    self.maybe_prefetch_btrfs_readdir_leaves(cx, scope, page.as_slice());
                    return Ok(page);
                }

                #[cfg(test)]
                self.readdir_full_reads
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let rows = self.btrfs_readdir_entries(cx, ino)?;
                // Rows arrive sorted by DIR_INDEX key; the cookie is key+1, so the
                // full list is cookie-ascending and the binary-search slice serves
                // any page identically to the prior `key >= offset` filter.
                let full: Vec<DirEntry> = rows
                    .into_iter()
                    .map(|(key, mut e)| {
                        e.offset = key.saturating_add(1);
                        e
                    })
                    .collect();
                let full = Arc::new(full);
                let page = slice_readdir_snapshot(Arc::clone(&full), offset);
                readdir_snapshot_store(&self.readdir_snapshot, canonical, validation, full);
                self.maybe_prefetch_btrfs_readdir_leaves(cx, scope, page.as_slice());
                Ok(page)
            }
        }
    }

    fn read(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        size: u32,
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                let inode =
                    self.read_inode_with_scope(cx, scope, Self::ext4_canonical_inode(ino))?;
                if inode.is_dir() {
                    return Err(FfsError::IsDirectory);
                }
                if inode.is_symlink() {
                    return Err(FfsError::Format("cannot read a symlink".into()));
                }
                // No fscrypt support: never return raw ciphertext as plaintext.
                Self::ext4_reject_encrypted(&inode)?;

                // e2compr compressed inode: if COMPRBLK_FL is set, the file
                // contains at least one compressed cluster. Route to the
                // compressed read path which handles mixed compressed/
                // uncompressed clusters transparently.
                if inode.flags & EXT4_COMPRBLK_FL != 0 {
                    return self.read_ext4_compressed(cx, scope, &inode, offset, size);
                }

                // Inline data: file content stored directly in inode's i_block area.
                if Self::ext4_inode_uses_inline_data(&inode) {
                    return Self::read_ext4_inline_data(&inode, offset, size);
                }

                // Indirect block addressing (legacy pre-extent inodes).
                if inode.flags & ffs_types::EXT4_EXTENTS_FL == 0 {
                    return self.read_ext4_indirect(cx, scope, &inode, offset, size);
                }

                let mut buf = vec![0_u8; ext4_read_buffer_len(inode.size, offset, size)?];
                let n = self.read_file_data(cx, scope, &inode, offset, &mut buf)?;
                buf.truncate(n);
                Ok(buf)
            }
            FsFlavor::Btrfs(_) => {
                let attr = self.btrfs_read_inode_attr(cx, ino)?;
                if attr.kind == FileType::Directory {
                    return Err(FfsError::IsDirectory);
                }
                if attr.kind == FileType::Symlink {
                    return Err(FfsError::Format("cannot read a symlink".into()));
                }
                self.btrfs_read_file(cx, ino, offset, size, false)
            }
        }
    }

    fn readlink(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                let inode =
                    self.read_inode_with_scope(cx, scope, Self::ext4_canonical_inode(ino))?;
                if !inode.is_symlink() {
                    return Err(FfsError::Format("not a symlink".into()));
                }
                if inode.is_encrypted() {
                    return Err(FfsError::UnsupportedFeature(
                        "encrypted symlink target requires fscrypt context".into(),
                    ));
                }

                if inode.size <= 60 {
                    // Fast symlink: data is stored directly in the inode's block field.
                    #[expect(clippy::cast_possible_truncation)]
                    let len = inode.size as usize;
                    Ok(inode.extent_bytes[..len].to_vec())
                } else {
                    // Slow symlink: data is stored in separate blocks.
                    let capped = inode.size.min(LINUX_PATH_MAX);
                    let mut buf = vec![0_u8; capped as usize];
                    let n = self.read_file_data(cx, scope, &inode, 0, &mut buf)?;
                    buf.truncate(n);
                    Ok(buf)
                }
            }
            FsFlavor::Btrfs(_) => {
                let attr = self.btrfs_read_inode_attr(cx, ino)?;
                if attr.kind != FileType::Symlink {
                    return Err(FfsError::Format("not a symlink".into()));
                }
                // PATH_MAX is 4096 on Linux; symlinks cannot exceed this.
                let capped = attr.size.min(LINUX_PATH_MAX);
                let read_size = u32::try_from(capped)
                    .map_err(|_| FfsError::Format("symlink size exceeds u32 capacity".into()))?;
                let mut target = self.btrfs_read_file(cx, ino, 0, read_size, true)?;
                if let Some(nul) = first_nul(&target) {
                    target.truncate(nul);
                }
                Ok(target)
            }
        }
    }

    fn statfs(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<FsStat> {
        match &self.flavor {
            FsFlavor::Ext4(sb) => {
                // On a writable fs the in-memory group stats mirror the on-disk
                // group descriptors and are kept current on every alloc/free, so
                // sum those directly — one lock + O(group_count) field reads —
                // instead of re-reading and csum-verifying + parsing every group
                // descriptor block per statfs (O(group_count) device GD parses).
                // This is the exact aggregation ext4_sync_superblock_free_totals
                // persists, so the totals are identical (bd-qsmav). A read-only
                // fs has no alloc state and falls back to the descriptor read.
                let (mut blocks_free, mut files_free) = if let Ok(alloc_mutex) =
                    self.require_alloc_state()
                {
                    let alloc = alloc_mutex.read();
                    // One fused pass over the group array (same aggregation as
                    // ext4_sync_superblock_free_totals): two separate `.sum()`
                    // passes reload every ~96-byte group struct a second time
                    // from memory on a large fs; free_blocks + free_inodes share a
                    // cache line, so fold both totals at once.
                    let totals = alloc
                        .groups
                        .iter()
                        .fold((0_u64, 0_u64), |(blocks, inodes), g| {
                            (
                                blocks + u64::from(g.free_blocks),
                                inodes + u64::from(g.free_inodes),
                            )
                        });
                    drop(alloc);
                    totals
                } else if let Some(&cached) = self.ext4_ro_statfs_totals.get() {
                    // Read-only mount: the group descriptors are immutable, so the
                    // summed totals are constant — serve the memoized O(1) value
                    // instead of re-reading + csum-verifying every group descriptor
                    // (O(group_count)) on each statfs.
                    cached
                } else {
                    let geo = FsGeometry::from_superblock(sb);
                    let totals = self.read_only_statfs_group_desc_totals(cx, scope, sb, &geo)?;
                    // Memoize for subsequent statfs calls. `set` is a no-op if a
                    // concurrent statfs already populated it with the same constant.
                    let _ = self.ext4_ro_statfs_totals.set(totals);
                    totals
                };
                blocks_free = blocks_free.min(sb.blocks_count);
                files_free = files_free.min(u64::from(sb.inodes_count));
                let blocks_available = blocks_free.saturating_sub(sb.reserved_blocks_count);
                Ok(FsStat {
                    blocks: sb.blocks_count,
                    blocks_free,
                    blocks_available,
                    files: u64::from(sb.inodes_count),
                    files_free,
                    block_size: sb.block_size,
                    name_max: 255,
                    fragment_size: sb.block_size,
                })
            }
            FsFlavor::Btrfs(sb) => {
                let unit = sb.sectorsize.max(1);
                let unit_u64 = u64::from(unit);
                // Use live allocator stats when writes are enabled,
                // otherwise fall back to the on-disk superblock.
                let used_bytes = self
                    .btrfs_alloc_state
                    .as_ref()
                    .map_or(sb.bytes_used, |alloc_mutex| {
                        alloc_mutex.read().extent_alloc.total_used()
                    });
                let total_bytes = sb.total_bytes;
                let free_bytes = total_bytes.saturating_sub(used_bytes);
                Ok(FsStat {
                    blocks: total_bytes / unit_u64,
                    blocks_free: free_bytes / unit_u64,
                    blocks_available: free_bytes / unit_u64,
                    files: 1_000_000_000,
                    files_free: 1_000_000_000,
                    block_size: unit,
                    name_max: 255,
                    fragment_size: unit,
                })
            }
        }
    }

    fn listxattr(&self, cx: &Cx, ino: InodeNumber) -> ffs_error::Result<Vec<String>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                let inode = self.read_inode(cx, Self::ext4_canonical_inode(ino))?;
                // Names-only walk: skip the per-attribute value `Vec` allocation
                // the materialise-all path built and then discarded (~1.67x,
                // bench `listxattr_names`). Same names, same order (ibody first).
                let mut names = ffs_ondisk::parse_ibody_xattr_names(&inode)
                    .map_err(|e| parse_to_ffs_error(&e))?;
                if inode.file_acl != 0 {
                    let block_data = self.read_block_vec(cx, BlockNumber(inode.file_acl))?;
                    names.extend(
                        ffs_ondisk::parse_xattr_block_names(&block_data)
                            .map_err(|e| parse_to_ffs_error(&e))?,
                    );
                }
                Ok(names)
            }
            FsFlavor::Btrfs(_) => self.btrfs_listxattr(cx, ino),
        }
    }

    fn getxattr(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        name: &str,
    ) -> ffs_error::Result<Option<Vec<u8>>> {
        // An over-long name is ERANGE (kernel pre-fs check), not a spurious
        // not-found.
        Self::xattr_name_within_limit_or_erange(name)?;
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                let inode = self.read_inode(cx, Self::ext4_canonical_inode(ino))?;
                // ext4 stores each attribute in exactly one place (inode body or
                // the external block), so probe the inode body first and only
                // read+parse the external ACL block on a miss — resolving an
                // inline attribute no longer pays for the external block, and a
                // by-name finder materializes only the matched value instead of
                // every attribute's name+value (bd-abu3z). Isomorphic: the old
                // code concatenated ibody++block and took the first full_name
                // match, which (names being unique, ibody first) is the same
                // entry this returns.
                //
                // Resolve the namespace ONCE into (index, suffix) and match each
                // entry by index + raw-byte suffix — the way the write path
                // (`entry_index`) and the kernel's xattr handler already match,
                // and ~2x cheaper per entry than re-stripping the prefix and
                // running a `from_utf8_lossy` UTF-8 validity scan of every name
                // (bench `xattr_lookup::ext4_getxattr_finder_*`: 2.06x at 4
                // entries, 3.5x at 24). For a name in no known namespace
                // (`parse_xattr_name` errors — e.g. an unhandled prefix, which
                // the kernel VFS rejects before ext4 anyway) fall back to the
                // by-name finder so observable behavior is unchanged there.
                let found = match ffs_xattr::parse_xattr_name_borrowed(name) {
                    Ok((name_index, suffix)) => {
                        let found =
                            ffs_ondisk::find_ibody_xattr_by_index_name(&inode, name_index, suffix)
                                .map_err(|e| parse_to_ffs_error(&e))?;
                        match found {
                            Some(v) => Some(v),
                            None if inode.file_acl != 0 => {
                                let block_data =
                                    self.read_block_vec(cx, BlockNumber(inode.file_acl))?;
                                ffs_ondisk::find_xattr_block_value_by_index_name(
                                    &block_data,
                                    name_index,
                                    suffix,
                                )
                                .map_err(|e| parse_to_ffs_error(&e))?
                            }
                            None => None,
                        }
                    }
                    Err(_) => {
                        let found = ffs_ondisk::find_ibody_xattr_by_name(&inode, name)
                            .map_err(|e| parse_to_ffs_error(&e))?;
                        match found {
                            Some(v) => Some(v),
                            None if inode.file_acl != 0 => {
                                let block_data =
                                    self.read_block_vec(cx, BlockNumber(inode.file_acl))?;
                                ffs_ondisk::find_xattr_block_value_by_name(&block_data, name)
                                    .map_err(|e| parse_to_ffs_error(&e))?
                            }
                            None => None,
                        }
                    }
                };
                let Some((name_index, value, value_inum)) = found else {
                    return Ok(None);
                };
                // EA_INODE-backed value: the payload lives in a separate inode
                // (the in-block value is an empty placeholder). Read it.
                let value = if value_inum != 0 {
                    self.ext4_read_ea_inode_value(cx, value_inum)?
                } else {
                    value
                };
                // POSIX ACL values need the ext4->generic expansion, keyed on
                // name_index — apply exactly as the parse path did via
                // ext4_present_xattr_value (name is unused there).
                Ok(Some(ext4_present_xattr_value(Ext4Xattr {
                    name_index,
                    name: Vec::new(),
                    value,
                })?))
            }
            FsFlavor::Btrfs(_) => self.btrfs_getxattr(cx, ino, name),
        }
    }

    fn setxattr(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        name: &str,
        value: &[u8],
        mode: XattrSetMode,
    ) -> ffs_error::Result<()> {
        // setxattr(2): the kernel's generic syscall path rejects a value larger
        // than XATTR_SIZE_MAX (65536) with E2BIG before reaching any filesystem,
        // so the limit is uniform across ext4 and btrfs. A FUSE mount never
        // forwards such a request, but the public OpenFs::setxattr library API
        // must enforce it — ext4_setxattr previously surfaced EINVAL (Format, via
        // ffs_xattr::set_xattr) and btrfs_setxattr had no check at all (it would
        // silently store the oversized value).
        const XATTR_SIZE_MAX: usize = 65_536;
        // The kernel copies the name first (ERANGE if it exceeds XATTR_NAME_MAX)
        // and then checks the value size, so the name check comes first.
        Self::xattr_name_within_limit_or_erange(name)?;
        if value.len() > XATTR_SIZE_MAX {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(libc::E2BIG)));
        }
        match &self.flavor {
            FsFlavor::Ext4(_) => self.ext4_setxattr(
                cx,
                scope,
                Self::ext4_canonical_inode(ino),
                name,
                value,
                mode,
            ),
            FsFlavor::Btrfs(_) => {
                self.check_btrfs_mutation_allowed("setxattr")?;
                self.btrfs_setxattr(cx, scope, ino, name, value, mode)
            }
        }
    }

    fn removexattr(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        name: &str,
    ) -> ffs_error::Result<bool> {
        // An over-long name is ERANGE (kernel pre-fs check).
        Self::xattr_name_within_limit_or_erange(name)?;
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                self.ext4_removexattr(cx, scope, Self::ext4_canonical_inode(ino), name)
            }
            FsFlavor::Btrfs(_) => {
                self.check_btrfs_mutation_allowed("removexattr")?;
                self.btrfs_removexattr(cx, scope, ino, name)
            }
        }
    }

    // ── Write operations ──────────────────────────────────────────────

    fn create(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        mode: u16,
        uid: u32,
        gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        clear_readdir_snapshot(&self.readdir_snapshot);
        match &self.flavor {
            FsFlavor::Ext4(_) => self
                .ext4_create(
                    cx,
                    scope,
                    Self::ext4_canonical_inode(parent),
                    name.as_encoded_bytes(),
                    mode,
                    uid,
                    gid,
                )
                .map(Self::ext4_present_attr),
            FsFlavor::Btrfs(_) => {
                self.check_btrfs_mutation_allowed("create")?;
                self.btrfs_create(cx, parent, name.as_encoded_bytes(), mode, uid, gid)
            }
        }
    }

    fn mknod(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        mode: u16,
        rdev: u32,
        uid: u32,
        gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        clear_readdir_snapshot(&self.readdir_snapshot);
        match &self.flavor {
            FsFlavor::Ext4(_) => self
                .ext4_mknod(
                    cx,
                    scope,
                    Self::ext4_canonical_inode(parent),
                    name.as_encoded_bytes(),
                    mode,
                    rdev,
                    uid,
                    gid,
                )
                .map(Self::ext4_present_attr),
            FsFlavor::Btrfs(_) => {
                self.check_btrfs_mutation_allowed("mknod")?;
                self.btrfs_mknod(cx, parent, name.as_encoded_bytes(), mode, rdev, uid, gid)
            }
        }
    }

    fn mkdir(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        mode: u16,
        uid: u32,
        gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        clear_readdir_snapshot(&self.readdir_snapshot);
        match &self.flavor {
            FsFlavor::Ext4(_) => self
                .ext4_mkdir(
                    cx,
                    scope,
                    Self::ext4_canonical_inode(parent),
                    name.as_encoded_bytes(),
                    mode,
                    uid,
                    gid,
                )
                .map(Self::ext4_present_attr),
            FsFlavor::Btrfs(_) => {
                self.check_btrfs_mutation_allowed("mkdir")?;
                self.btrfs_mkdir(cx, parent, name.as_encoded_bytes(), mode, uid, gid)
            }
        }
    }

    fn unlink(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
    ) -> ffs_error::Result<()> {
        clear_readdir_snapshot(&self.readdir_snapshot);
        match &self.flavor {
            FsFlavor::Ext4(_) => self.ext4_unlink_impl(
                cx,
                scope,
                Self::ext4_canonical_inode(parent),
                name.as_encoded_bytes(),
                false,
            ),
            FsFlavor::Btrfs(_) => {
                self.check_btrfs_mutation_allowed("unlink")?;
                self.btrfs_unlink_impl(cx, scope, parent, name.as_encoded_bytes(), false)
            }
        }
    }

    fn rmdir(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
    ) -> ffs_error::Result<()> {
        clear_readdir_snapshot(&self.readdir_snapshot);
        match &self.flavor {
            FsFlavor::Ext4(_) => self.ext4_unlink_impl(
                cx,
                scope,
                Self::ext4_canonical_inode(parent),
                name.as_encoded_bytes(),
                true,
            ),
            FsFlavor::Btrfs(_) => {
                self.check_btrfs_mutation_allowed("rmdir")?;
                self.btrfs_unlink_impl(cx, scope, parent, name.as_encoded_bytes(), true)
            }
        }
    }

    fn rename(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        new_parent: InodeNumber,
        new_name: &OsStr,
    ) -> ffs_error::Result<()> {
        clear_readdir_snapshot(&self.readdir_snapshot);
        match &self.flavor {
            FsFlavor::Ext4(_) => self.ext4_rename(
                cx,
                scope,
                Self::ext4_canonical_inode(parent),
                name.as_encoded_bytes(),
                Self::ext4_canonical_inode(new_parent),
                new_name.as_encoded_bytes(),
            ),
            FsFlavor::Btrfs(_) => {
                self.check_btrfs_mutation_allowed("rename")?;
                self.btrfs_rename(
                    cx,
                    parent,
                    name.as_encoded_bytes(),
                    new_parent,
                    new_name.as_encoded_bytes(),
                )
            }
        }
    }

    fn rename2(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        new_parent: InodeNumber,
        new_name: &OsStr,
        flags: u32,
    ) -> ffs_error::Result<()> {
        // Reject combinations that linux/fs.h forbids before doing any work.
        // The kernel itself never sets more than one bit at a time but a
        // malformed FUSE request could; mirror ext4's strict check.
        const RENAME_NOREPLACE: u32 = libc::RENAME_NOREPLACE;
        const RENAME_EXCHANGE: u32 = libc::RENAME_EXCHANGE;
        const RENAME_WHITEOUT: u32 = libc::RENAME_WHITEOUT;
        const SUPPORTED: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE;
        const KNOWN: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT;
        if flags & !KNOWN != 0 {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                libc::EINVAL,
            )));
        }
        if flags & RENAME_NOREPLACE != 0 && flags & RENAME_EXCHANGE != 0 {
            // EINVAL per renameat2(2): NOREPLACE + EXCHANGE is contradictory.
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                libc::EINVAL,
            )));
        }
        if flags & !SUPPORTED != 0 {
            // RENAME_WHITEOUT still needs a fresh char-device inode from
            // the unused-inode pool. Return EINVAL until it lands so the
            // kernel surfaces a real error rather than degrading to
            // overwrite.
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                libc::EINVAL,
            )));
        }

        if flags & RENAME_NOREPLACE != 0 {
            // The caller (FUSE dispatcher) holds parent + new_parent inode
            // guards via FuseInodeLocks, so the lookup + rename below is
            // one atomic critical section against concurrent
            // create/mkdir/rename on the same parents.
            match <Self as FsOps>::lookup(self, cx, scope, new_parent, new_name) {
                Ok(_existing) => {
                    return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                        libc::EEXIST,
                    )));
                }
                Err(FfsError::NotFound(_)) => {}
                Err(e) => return Err(e),
            }
        }

        if flags & RENAME_EXCHANGE != 0 {
            clear_readdir_snapshot(&self.readdir_snapshot);
            return match &self.flavor {
                FsFlavor::Ext4(_) => {
                    self.ext4_rename2_exchange(cx, scope, parent, name, new_parent, new_name)
                }
                FsFlavor::Btrfs(_) => {
                    self.check_btrfs_mutation_allowed("rename")?;
                    self.btrfs_rename2_exchange(
                        parent,
                        name.as_encoded_bytes(),
                        new_parent,
                        new_name.as_encoded_bytes(),
                    )
                }
            };
        }

        <Self as FsOps>::rename(self, cx, scope, parent, name, new_parent, new_name)
    }

    fn write(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        data: &[u8],
    ) -> ffs_error::Result<u32> {
        match &self.flavor {
            FsFlavor::Ext4(_) => self.ext4_write(
                cx,
                scope,
                Self::ext4_canonical_inode(ino),
                offset,
                data,
                true,
            ),
            FsFlavor::Btrfs(_) => {
                self.check_btrfs_mutation_allowed("write")?;
                self.btrfs_write(cx, ino, offset, data)
            }
        }
    }

    fn link(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        new_parent: InodeNumber,
        new_name: &OsStr,
    ) -> ffs_error::Result<InodeAttr> {
        clear_readdir_snapshot(&self.readdir_snapshot);
        match &self.flavor {
            FsFlavor::Ext4(_) => self
                .ext4_link(
                    cx,
                    scope,
                    Self::ext4_canonical_inode(ino),
                    Self::ext4_canonical_inode(new_parent),
                    new_name.as_encoded_bytes(),
                )
                .map(Self::ext4_present_attr),
            FsFlavor::Btrfs(_) => {
                self.check_btrfs_mutation_allowed("link")?;
                self.btrfs_link(cx, ino, new_parent, new_name.as_encoded_bytes())
            }
        }
    }

    fn symlink(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        parent: InodeNumber,
        name: &OsStr,
        target: &Path,
        uid: u32,
        gid: u32,
    ) -> ffs_error::Result<InodeAttr> {
        let target_bytes = target.as_os_str().as_encoded_bytes();
        let target_len = target_bytes.len();
        let target_len_exceeds_max =
            u64::try_from(target_len).map_or(true, |len| len > LINUX_SYMLINK_TARGET_MAX);
        if target_len == 0 || target_len_exceeds_max {
            return Err(FfsError::NameTooLong);
        }
        if first_nul(target_bytes).is_some() {
            return Err(FfsError::Format(
                "symlink target must not contain NUL".into(),
            ));
        }
        clear_readdir_snapshot(&self.readdir_snapshot);
        match &self.flavor {
            FsFlavor::Ext4(_) => self
                .ext4_symlink(
                    cx,
                    scope,
                    Self::ext4_canonical_inode(parent),
                    name.as_encoded_bytes(),
                    target,
                    uid,
                    gid,
                )
                .map(Self::ext4_present_attr),
            FsFlavor::Btrfs(_) => {
                self.check_btrfs_mutation_allowed("symlink")?;
                self.btrfs_symlink(cx, parent, name.as_encoded_bytes(), target, uid, gid)
            }
        }
    }

    fn fallocate(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        length: u64,
        mode: i32,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => self.ext4_fallocate(
                cx,
                scope,
                Self::ext4_canonical_inode(ino),
                offset,
                length,
                mode,
            ),
            FsFlavor::Btrfs(_) => {
                self.check_btrfs_mutation_allowed("fallocate")?;
                self.btrfs_fallocate(cx, ino, offset, length, mode)
            }
        }
    }

    fn fiemap(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        start: u64,
        length: u64,
    ) -> ffs_error::Result<Vec<FiemapExtent>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => self.ext4_fiemap(cx, scope, ino, start, length),
            FsFlavor::Btrfs(_) => self.btrfs_fiemap(cx, ino, start, length),
        }
    }

    fn lseek(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        offset: u64,
        whence: SeekWhence,
    ) -> ffs_error::Result<u64> {
        match whence {
            SeekWhence::Data => match &self.flavor {
                FsFlavor::Ext4(_) => self.ext4_lseek_data(cx, scope, ino, offset),
                FsFlavor::Btrfs(_) => self.btrfs_lseek_data(cx, ino, offset),
            },
            SeekWhence::Hole => match &self.flavor {
                FsFlavor::Ext4(_) => self.ext4_lseek_hole(cx, scope, ino, offset),
                FsFlavor::Btrfs(_) => self.btrfs_lseek_hole(cx, ino, offset),
            },
            // SEEK_SET/CUR/END are handled by the FUSE layer directly, so the
            // filesystem only ever sees SEEK_DATA/SEEK_HOLE. Reaching here is an
            // unsupported whence at the fs layer -> EINVAL (Format).
            SeekWhence::Set | SeekWhence::Cur | SeekWhence::End => Err(FfsError::Format(
                "fs-level lseek only supports SEEK_DATA/SEEK_HOLE".into(),
            )),
        }
    }

    fn get_inode_flags(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<u32> {
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                let inode =
                    self.read_inode_with_scope(cx, scope, Self::ext4_canonical_inode(ino))?;
                Ok(inode.flags)
            }
            FsFlavor::Btrfs(_) => {
                let canonical = self.btrfs_canonical_inode(ino)?;
                let btrfs_flags = if let Some(alloc_mutex) = self.btrfs_alloc_state.as_ref() {
                    let alloc = alloc_mutex.read();
                    let inode = self.btrfs_read_inode_from_tree(&alloc, canonical)?;
                    drop(alloc);
                    inode.flags
                } else {
                    self.btrfs_read_ondisk_inode_item(cx, canonical)?.flags
                };
                Ok(btrfs_inode_flags_to_fsflags(btrfs_flags))
            }
        }
    }

    fn get_inode_state(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<u32> {
        // EXT4_STATE_FLAG_* bits are kernel-side transient flags
        // (EXT_PRECACHED is a per-mount cache flag, NEW/NEWENTRY are
        // kernel allocator hints, DA_ALLOC_CLOSE is a delayed-alloc
        // close marker) with no meaningful counterpart in our
        // userspace MVCC backend. Validate the inode exists so a bogus
        // ino surfaces as ENOENT/EINVAL, then return an empty bitmap.
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                let _ = self.read_inode_with_scope(cx, scope, Self::ext4_canonical_inode(ino))?;
                Ok(0)
            }
            FsFlavor::Btrfs(_) => {
                let _ = self.btrfs_read_inode_attr(cx, ino)?;
                Ok(0)
            }
        }
    }

    fn get_inode_fsxattr(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<FsxattrInfo> {
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                let canonical = Self::ext4_canonical_inode(ino);
                let inode = self.read_inode_with_scope(cx, scope, canonical)?;
                let xflags = ext4_flags_to_xflags(inode.flags);
                // Inline-data + non-extent-tree inodes report 0 extents
                // (matches ext4's nextents accounting in fs/ext4/ioctl.c).
                let nextents = if (inode.flags & ffs_types::EXT4_EXTENTS_FL) != 0 {
                    // Only the count is reported, so sum leaf eh_entries headers
                    // instead of materializing every extent (bd-mh4tz).
                    self.count_extents(cx, scope, &inode).unwrap_or(0)
                } else {
                    0
                };
                Ok(FsxattrInfo {
                    xflags,
                    extsize: 0,
                    nextents,
                    projid: inode.projid,
                    cowextsize: 0,
                })
            }
            FsFlavor::Btrfs(_) => {
                let canonical = self.btrfs_canonical_inode(ino)?;
                let btrfs_flags = if let Some(alloc_mutex) = self.btrfs_alloc_state.as_ref() {
                    let alloc = alloc_mutex.read();
                    let inode = self.btrfs_read_inode_from_tree(&alloc, canonical)?;
                    drop(alloc);
                    inode.flags
                } else {
                    self.btrfs_read_ondisk_inode_item(cx, canonical)?.flags
                };
                Ok(FsxattrInfo {
                    xflags: btrfs_inode_flags_to_xflags(btrfs_flags),
                    extsize: 0,
                    nextents: 0,
                    projid: 0,
                    cowextsize: 0,
                })
            }
        }
    }

    fn fs_uuid(&self) -> ffs_error::Result<[u8; 16]> {
        match &self.flavor {
            FsFlavor::Ext4(sb) => Ok(sb.uuid),
            // btrfs `fsid` is the 16-byte filesystem UUID; the kernel
            // reports it as super_block::s_uuid for FS_IOC_GETFSUUID.
            FsFlavor::Btrfs(sb) => Ok(sb.fsid),
        }
    }

    fn trim_range(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        start: u64,
        len: u64,
        _min_len: u64,
    ) -> ffs_error::Result<u64> {
        // Validate the range fits inside the device's byte span.
        // ext4_trim_fs and btrfs_trim_fs both reject out-of-bounds
        // calls with EINVAL — match that behaviour rather than
        // silently truncating the request.
        let device_bytes = self.dev.len_bytes();
        if start >= device_bytes {
            return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                libc::EINVAL,
            )));
        }
        // Length saturates against the tail of the device; the kernel
        // does the same so a user passing fstrim_range.len = u64::MAX
        // (the documented "trim everything past start") works.
        let _effective = len.min(device_bytes - start);

        // FrankenFS sits over an opaque BlockDevice trait that has no
        // discard syscall, so no physical bytes are released. Return 0
        // — userspace fstrim(8) will report "0 bytes were trimmed"
        // which is the correct outcome for a discard-incapable
        // backing device.
        Ok(0)
    }

    fn set_inode_fsxattr(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        fsx: FsxattrInfo,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                // ext4 does not implement extsize / cowextsize hints,
                // so any non-zero value is a programmer / userspace
                // misuse — surface EINVAL up-front before we mutate
                // anything (matches fs/ext4/ioctl.c::ext4_fileattr_set).
                if fsx.extsize != 0 || fsx.cowextsize != 0 {
                    return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                        libc::EINVAL,
                    )));
                }
                let canonical = Self::ext4_canonical_inode(ino);
                let current = self.read_inode_with_scope(cx, scope, canonical)?;
                let new_flags = xflags_to_ext4_flags(fsx.xflags, current.flags)?;

                // Reuse the existing user-flag pipeline so the
                // EXT4_USER_SETTABLE_FLAGS gate, EXT4_COMPR_FL feature
                // check, and journal-aware write path all stay in one
                // place. set_inode_flags only touches the user-settable
                // subset, so PROJINHERIT etc. round-trip cleanly.
                <Self as FsOps>::set_inode_flags(self, cx, scope, ino, new_flags)?;

                // Project-ID is a separate field — apply it directly
                // unless it matches what's already on disk.
                if fsx.projid != current.projid {
                    let mut updated = self.read_inode_with_scope(cx, scope, canonical)?;
                    updated.projid = fsx.projid;
                    let alloc_mutex = self.require_alloc_state()?;
                    let block_dev = self.block_device_adapter();
                    let sb = self
                        .ext4_superblock()
                        .ok_or_else(|| FfsError::Format("not an ext4 filesystem".into()))?;
                    let csum_seed = sb.csum_seed();
                    let alloc = alloc_mutex.read();
                    ffs_inode::write_inode(
                        cx,
                        &block_dev,
                        &alloc.geo,
                        &alloc.groups,
                        canonical,
                        &updated,
                        csum_seed,
                    )?;
                }
                Ok(())
            }
            FsFlavor::Btrfs(_) => {
                self.require_btrfs_rw_allowed("setfsxattr")?;

                if fsx.extsize != 0 || fsx.cowextsize != 0 {
                    return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                        libc::EINVAL,
                    )));
                }
                if fsx.projid != 0 {
                    return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                        libc::EOPNOTSUPP,
                    )));
                }

                let unsupported = fsx.xflags & !BTRFS_USER_SETTABLE_XFLAGS;
                if unsupported != 0 {
                    return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                        libc::EOPNOTSUPP,
                    )));
                }

                let alloc_mutex = self.require_btrfs_alloc_state()?;
                let canonical = self.btrfs_canonical_inode(ino)?;

                let mut alloc = alloc_mutex.write();
                let mut inode = self.btrfs_read_inode_from_tree(&alloc, canonical)?;

                let requested_btrfs = xflags_to_btrfs_inode_flags(fsx.xflags);
                let user_settable_btrfs = xflags_to_btrfs_inode_flags(BTRFS_USER_SETTABLE_XFLAGS);
                inode.flags =
                    (inode.flags & !user_settable_btrfs) | (requested_btrfs & user_settable_btrfs);

                let (secs, nanos) = Self::btrfs_now_timestamp();
                inode.ctime_sec = secs;
                inode.ctime_nsec = nanos;

                let inode_key = BtrfsKey {
                    objectid: canonical,
                    item_type: BTRFS_ITEM_INODE_ITEM,
                    offset: 0,
                };
                alloc
                    .fs_tree
                    .update(&inode_key, &inode.to_bytes())
                    .map_err(|e| btrfs_mutation_to_ffs(&e))?;
                drop(alloc);

                Ok(())
            }
        }
    }

    fn precache_extents(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<()> {
        // ext4_ext_precache walks the extent tree to pull index/leaf
        // blocks into the page cache so subsequent reads don't stall on
        // metadata I/O. The kernel returns 0 for inodes with no extents
        // (block-mapped legacy inodes, fast-symlinks) — match that
        // contract by treating non-extent inodes as a successful no-op
        // rather than EOPNOTSUPP. For extent-based inodes we walk the
        // tree via collect_extents_with_scope; the side effect of that
        // walk is that ffs-extent's per-scope block cache populates
        // every internal/leaf block exactly once, which is what
        // userspace was asking for.
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                let inode =
                    self.read_inode_with_scope(cx, scope, Self::ext4_canonical_inode(ino))?;
                if inode.flags & ffs_types::EXT4_EXTENTS_FL != 0 {
                    let _ = self.collect_extents_with_scope(cx, scope, &inode)?;
                }
                Ok(())
            }
            // btrfs stores extent items inline in the FS tree alongside
            // inode metadata, so reading the inode already touches the
            // same blocks ext4_ext_precache would warm. Validate the
            // inode exists and return Ok.
            FsFlavor::Btrfs(_) => {
                let _ = self.btrfs_read_inode_attr(cx, ino)?;
                Ok(())
            }
        }
    }

    fn clear_extent_status_cache(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<()> {
        // FrankenFS keeps extent-status state per-RequestScope rather
        // than in a process-lifetime per-inode cache, so there is
        // nothing for ext4_clear_inode_es to drop. Read the inode
        // through the ext4 / btrfs canonical lookup so a bogus inode
        // number surfaces as ENOENT/EINVAL the same way the kernel
        // path would, then return Ok — matches the kernel's "best
        // effort, never an error for a valid inode" contract.
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                let _ = self.read_inode_with_scope(cx, scope, Self::ext4_canonical_inode(ino))?;
                Ok(())
            }
            FsFlavor::Btrfs(_) => {
                let _ = self.btrfs_read_inode_attr(cx, ino)?;
                Ok(())
            }
        }
    }

    fn get_inode_generation(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<u32> {
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                let inode =
                    self.read_inode_with_scope(cx, scope, Self::ext4_canonical_inode(ino))?;
                Ok(inode.generation)
            }
            FsFlavor::Btrfs(_) => {
                let canonical = self.btrfs_canonical_inode(ino)?;
                let generation = if let Some(alloc_mutex) = self.btrfs_alloc_state.as_ref() {
                    let alloc = alloc_mutex.read();
                    let inode = self.btrfs_read_inode_from_tree(&alloc, canonical)?;
                    drop(alloc);
                    inode.generation
                } else {
                    self.btrfs_read_ondisk_inode_item(cx, canonical)?.generation
                };
                u32::try_from(generation).map_err(|_| {
                    FfsError::Format(format!(
                        "btrfs inode {canonical} generation {generation} does not fit FS_IOC_GETVERSION"
                    ))
                })
            }
        }
    }

    fn set_inode_generation(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        generation: u32,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                let canonical = Self::ext4_canonical_inode(ino);
                let alloc_mutex = self.require_alloc_state()?;
                let block_dev = self.block_device_adapter();
                let sb = self
                    .ext4_superblock()
                    .ok_or_else(|| FfsError::Format("not an ext4 filesystem".into()))?;
                let csum_seed = sb.csum_seed();

                let mut inode = self.read_inode_with_scope(cx, scope, canonical)?;
                inode.generation = generation;

                if let Some(tx) = &mut scope.tx {
                    let tx_dev = TransactionBlockAdapter {
                        base: &block_dev,
                        tx: Mutex::new(tx),
                    };
                    let alloc = alloc_mutex.read();
                    ffs_inode::write_inode(
                        cx,
                        &tx_dev,
                        &alloc.geo,
                        &alloc.groups,
                        canonical,
                        &inode,
                        csum_seed,
                    )?;
                } else {
                    let alloc = alloc_mutex.read();
                    ffs_inode::write_inode(
                        cx,
                        &block_dev,
                        &alloc.geo,
                        &alloc.groups,
                        canonical,
                        &inode,
                        csum_seed,
                    )?;
                }
                Ok(())
            }
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "set_inode_generation is not supported for btrfs".to_owned(),
            )),
        }
    }

    fn get_encryption_policy_v1(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<[u8; FSCRYPT_POLICY_V1_SIZE]> {
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                let sb = self
                    .ext4_superblock()
                    .ok_or_else(|| FfsError::Format("not an ext4 filesystem".into()))?;
                if !sb.has_incompat(ffs_ondisk::Ext4IncompatFeatures::ENCRYPT) {
                    return Err(FfsError::UnsupportedFeature(
                        "ext4 ENCRYPT incompat feature is not enabled".into(),
                    ));
                }

                let inode =
                    self.read_inode_with_scope(cx, scope, Self::ext4_canonical_inode(ino))?;
                if !inode.is_encrypted() {
                    return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                        libc::ENODATA,
                    )));
                }

                let mut xattrs =
                    ffs_ondisk::parse_ibody_xattrs(&inode).map_err(|e| parse_to_ffs_error(&e))?;
                if inode.file_acl != 0 {
                    let block_data = self.read_block_vec(cx, BlockNumber(inode.file_acl))?;
                    let block_xattrs = ffs_ondisk::parse_xattr_block(&block_data)
                        .map_err(|e| parse_to_ffs_error(&e))?;
                    xattrs.extend(block_xattrs);
                }

                let context = xattrs
                    .into_iter()
                    .find(|xattr| {
                        xattr.name_index == ffs_types::EXT4_XATTR_INDEX_ENCRYPTION
                            && xattr.name == EXT4_ENCRYPTION_XATTR_NAME
                    })
                    .map(|xattr| xattr.value)
                    .ok_or_else(|| {
                        FfsError::Format("encrypted inode is missing fscrypt context".into())
                    })?;

                let Some(version) = context.first().copied() else {
                    return Err(FfsError::Format("fscrypt context is empty".into()));
                };
                if version != FSCRYPT_POLICY_V1_VERSION {
                    return Err(FfsError::Format(format!(
                        "FS_IOC_GET_ENCRYPTION_POLICY only supports fscrypt v1, found version {version}"
                    )));
                }
                if context.len() < FSCRYPT_CONTEXT_V1_SIZE {
                    return Err(FfsError::Format("fscrypt v1 context is truncated".into()));
                }

                let mut policy = [0_u8; FSCRYPT_POLICY_V1_SIZE];
                policy.copy_from_slice(&context[..FSCRYPT_POLICY_V1_SIZE]);
                Ok(policy)
            }
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "get_encryption_policy_v1 is not supported for btrfs".to_owned(),
            )),
        }
    }

    fn get_fs_label(&self, cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                let sb_region = read_ext4_superblock_region(cx, self.dev.as_ref())?;
                let sb = Ext4Superblock::parse_superblock_region(&sb_region)
                    .map_err(|e| parse_to_ffs_error(&e))?;
                let mut label = sb.volume_name.as_bytes().to_vec();
                label.push(0);
                Ok(label)
            }
            FsFlavor::Btrfs(sb) => {
                let mut label = sb.label.as_bytes().to_vec();
                label.push(0);
                Ok(label)
            }
        }
    }

    fn get_quota_info(&self, cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<QuotaInfo> {
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                let sb_region = read_ext4_superblock_region(cx, self.dev.as_ref())?;
                let sb = Ext4Superblock::parse_superblock_region(&sb_region)
                    .map_err(|e| parse_to_ffs_error(&e))?;
                let quota_inodes = sb.quota_inodes();
                Ok(QuotaInfo {
                    user_quota_enabled: quota_inodes.user.is_some(),
                    user_quota_inum: quota_inodes.user,
                    group_quota_enabled: quota_inodes.group.is_some(),
                    group_quota_inum: quota_inodes.group,
                    project_quota_enabled: quota_inodes.project.is_some(),
                    project_quota_inum: quota_inodes.project,
                })
            }
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "btrfs uses qgroups, not traditional quotas".to_owned(),
            )),
        }
    }

    fn btrfs_wait_quota_rescan(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_QUOTA_RESCAN_WAIT is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "btrfs qgroup quota rescan wait is not implemented".to_owned(),
            )),
        }
    }

    fn btrfs_quota_rescan_status(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_QUOTA_RESCAN_STATUS is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "btrfs qgroup quota rescan status is not implemented".to_owned(),
            )),
        }
    }

    fn btrfs_start_quota_rescan(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _flags: u64,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_QUOTA_RESCAN is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "btrfs qgroup quota rescan is not implemented".to_owned(),
            )),
        }
    }

    fn btrfs_quota_control(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _cmd: u64,
        _status: u64,
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_QUOTA_CTL is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "btrfs qgroup quota control is not implemented".to_owned(),
            )),
        }
    }

    fn btrfs_assign_qgroup(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _assign: u64,
        _src: u64,
        _dst: u64,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_QGROUP_ASSIGN is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "btrfs qgroup assign is not implemented".to_owned(),
            )),
        }
    }

    fn btrfs_create_qgroup(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _create: u64,
        _qgroupid: u64,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_QGROUP_CREATE is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "btrfs qgroup create is not implemented".to_owned(),
            )),
        }
    }

    fn btrfs_limit_qgroup(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _limit: BtrfsQgroupLimitRequest,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_QGROUP_LIMIT is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "btrfs qgroup limit is not implemented".to_owned(),
            )),
        }
    }

    fn set_fs_label(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        label: &[u8],
    ) -> ffs_error::Result<()> {
        const EXT4_LABEL_MAX: usize = 16;
        const EXT4_VOLUME_NAME_OFFSET: usize = 0x78;

        match &self.flavor {
            FsFlavor::Ext4(_) => {
                if label.len() > EXT4_LABEL_MAX || label.contains(&0) {
                    return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                        libc::EINVAL,
                    )));
                }

                let sb = self
                    .ext4_superblock()
                    .ok_or_else(|| FfsError::Format("not an ext4 filesystem".into()))?;
                // The superblock may not be in block 0 on a 1024-byte-block fs
                // (bd-icebl): use its true block + in-block offset.
                let (sb_block, sb_off) = self.ext4_superblock_location();
                let block_dev = self.direct_block_device_adapter();
                let mut block_data = block_dev.read_block(cx, sb_block)?.into_inner();

                let label_start = sb_off + EXT4_VOLUME_NAME_OFFSET;
                let label_end = label_start + EXT4_LABEL_MAX;
                block_data[label_start..label_end].fill(0);
                block_data[label_start..label_start + label.len()].copy_from_slice(label);

                if sb.has_metadata_csum() {
                    let checksum = ffs_ondisk::ext4::ext4_chksum_skip_zero_tail(
                        !0u32,
                        &block_data[sb_off..sb_off + EXT4_SB_CHECKSUM_OFFSET],
                    );
                    block_data
                        [sb_off + EXT4_SB_CHECKSUM_OFFSET..sb_off + EXT4_SB_CHECKSUM_OFFSET + 4]
                        .copy_from_slice(&checksum.to_le_bytes());
                }

                if let Some(tx) = &mut scope.tx {
                    let tx_dev = TransactionBlockAdapter {
                        base: &block_dev,
                        tx: Mutex::new(tx),
                    };
                    tx_dev.write_block(cx, sb_block, &block_data)?;
                } else {
                    block_dev.write_block(cx, sb_block, &block_data)?;
                }
                Ok(())
            }
            FsFlavor::Btrfs(_) => {
                const BTRFS_LABEL_MAX: usize = 256;
                const BTRFS_LABEL_OFFSET: usize = 0x12B;

                self.require_btrfs_rw_allowed("setfslabel")?;

                if label.len() >= BTRFS_LABEL_MAX || label.contains(&0) {
                    return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                        libc::EINVAL,
                    )));
                }

                let sb_region = read_btrfs_superblock_region(cx, self.dev.as_ref())?;
                let mut sb_data = sb_region.to_vec();

                sb_data[BTRFS_LABEL_OFFSET..BTRFS_LABEL_OFFSET + BTRFS_LABEL_MAX].fill(0);
                sb_data[BTRFS_LABEL_OFFSET..BTRFS_LABEL_OFFSET + label.len()]
                    .copy_from_slice(label);

                let csum = ffs_types::crc32c(&sb_data[0x20..]);
                sb_data[0..4].copy_from_slice(&csum.to_le_bytes());

                let sb_offset = ByteOffset(u64::try_from(BTRFS_SUPER_INFO_OFFSET).unwrap());
                self.dev.write_all_at(cx, sb_offset, &sb_data)?;

                Ok(())
            }
        }
    }

    fn get_btrfs_fs_info(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_FS_INFO is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(sb) => Ok(encode_btrfs_fs_info_args(sb)),
        }
    }

    fn btrfs_start_sync(&self, cx: &Cx, scope: &mut RequestScope) -> ffs_error::Result<u64> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_START_SYNC is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(sb) => {
                self.sync_fs(cx, scope)?;
                let generation = self
                    .btrfs_alloc_state
                    .as_ref()
                    .map_or(sb.generation, |alloc_mutex| alloc_mutex.read().generation);
                Ok(generation)
            }
        }
    }

    fn btrfs_wait_sync(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        _transid: u64,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_WAIT_SYNC is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => self.sync_fs(cx, scope),
        }
    }

    fn get_btrfs_features(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_GET_FEATURES is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(sb) => {
                let mut buf = vec![0_u8; 24];
                buf[0..8].copy_from_slice(&sb.compat_flags.to_le_bytes());
                buf[8..16].copy_from_slice(&sb.compat_ro_flags.to_le_bytes());
                buf[16..24].copy_from_slice(&sb.incompat_flags.to_le_bytes());
                Ok(buf)
            }
        }
    }

    fn get_btrfs_supported_features(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_GET_SUPPORTED_FEATURES is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => Ok(encode_btrfs_supported_feature_flags()),
        }
    }

    fn set_btrfs_features(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _feature_flags: &[u8],
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_SET_FEATURES is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "btrfs feature flag mutation is not implemented".to_owned(),
            )),
        }
    }

    fn get_btrfs_space_info(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        space_slots: u64,
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_SPACE_INFO is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                let space_infos = self
                    .require_btrfs_alloc_state()?
                    .read()
                    .extent_alloc
                    .space_info();
                let total_spaces = u64::try_from(space_infos.len()).map_err(|_| {
                    FfsError::Format("BTRFS_IOC_SPACE_INFO entry count exceeds u64".to_owned())
                })?;

                // Header: space_slots (ignored on output), total_spaces
                let mut buf = Vec::with_capacity(16 + space_infos.len().saturating_mul(24));
                buf.extend_from_slice(&0_u64.to_le_bytes()); // space_slots (unused in output)
                buf.extend_from_slice(&total_spaces.to_le_bytes());

                // If caller requested entries, add them
                let slots_to_return = if space_slots == 0 {
                    0
                } else {
                    usize::try_from(space_slots)
                        .unwrap_or(usize::MAX)
                        .min(space_infos.len())
                };

                for (flags, total_bytes, used_bytes) in
                    space_infos.into_iter().take(slots_to_return)
                {
                    buf.extend_from_slice(&flags.to_le_bytes());
                    buf.extend_from_slice(&total_bytes.to_le_bytes());
                    buf.extend_from_slice(&used_bytes.to_le_bytes());
                }

                Ok(buf)
            }
        }
    }

    fn btrfs_tree_search(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        key: BtrfsTreeSearchKey,
    ) -> ffs_error::Result<(u32, Vec<u8>)> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_TREE_SEARCH is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(sb) => {
                let entries = self.btrfs_tree_search_entries(cx, &key)?;
                encode_btrfs_tree_search_results(&key, sb.generation, entries)
            }
        }
    }

    fn get_btrfs_ino_paths(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        inum: u64,
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_INO_PATHS is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                let treeid = self
                    .btrfs_context
                    .as_ref()
                    .map_or(BTRFS_FS_TREE_OBJECTID, |ctx| ctx.subvol_objectid);
                let paths = self.btrfs_resolve_all_inode_paths_in_tree(cx, treeid, inum)?;
                encode_btrfs_ino_paths_container(&paths, BTRFS_INO_PATHS_MAX_BYTES_U64)
            }
        }
    }

    fn get_btrfs_logical_ino(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        logical: u64,
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_LOGICAL_INO is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // Look up extent back-references for the given logical address.
                // Returns all (ino, offset, root) tuples that reference this extent.
                // The address usually points into the middle of an extent, so
                // resolve the covering EXTENT_ITEM's start bytenr first (bd-uv16n).
                let alloc = self.require_btrfs_alloc_state()?;
                let data_refs = {
                    let alloc_guard = alloc.read();
                    let extent_start = alloc_guard
                        .extent_alloc
                        .resolve_containing_data_extent(logical)
                        .map_err(|e| FfsError::Parse(format!("extent lookup failed: {e}")))?
                        .unwrap_or(logical);
                    alloc_guard
                        .extent_alloc
                        .get_extent_data_refs(extent_start)
                        .map_err(|e| FfsError::Parse(format!("extent lookup failed: {e}")))?
                };

                // Output format: struct btrfs_data_container
                // u32 bytes_left (0), u32 bytes_missing (0),
                // u64 elem_cnt, u64 elem_missed (0),
                // u64 val[] — (ino, offset, root) per entry
                let elem_cnt = data_refs.len();
                let header_size = 4 + 4 + 8 + 8; // 24 bytes
                let entry_size = 24; // 3 * u64
                let mut buf = Vec::with_capacity(header_size + elem_cnt * entry_size);

                // bytes_left (u32) — 0, no preceding data
                buf.extend_from_slice(&0_u32.to_le_bytes());
                // bytes_missing (u32) — 0, all fits
                buf.extend_from_slice(&0_u32.to_le_bytes());
                // elem_cnt (u64)
                buf.extend_from_slice(&(elem_cnt as u64).to_le_bytes());
                // elem_missed (u64)
                buf.extend_from_slice(&0_u64.to_le_bytes());

                // val[] — (ino, offset, root) tuples
                for data_ref in &data_refs {
                    buf.extend_from_slice(&data_ref.objectid.to_le_bytes()); // ino
                    buf.extend_from_slice(&data_ref.offset.to_le_bytes()); // offset
                    buf.extend_from_slice(&data_ref.root.to_le_bytes()); // root
                }

                Ok(buf)
            }
        }
    }

    fn get_btrfs_logical_ino_v2(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        logical: u64,
        _args: &[u8],
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_LOGICAL_INO_V2 is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // V2 adds a flags field (ignore_offset, etc). We currently return
                // all backrefs of the containing extent, which matches the
                // IGNORE_OFFSET semantics; offset-precise filtering for the
                // default flag set is a separate follow-up (bd-uv16n).
                // Resolve the covering EXTENT_ITEM so a mid-extent address (the
                // common case) is not silently empty (bd-uv16n).
                let alloc = self.require_btrfs_alloc_state()?;
                let data_refs = {
                    let alloc_guard = alloc.read();
                    let extent_start = alloc_guard
                        .extent_alloc
                        .resolve_containing_data_extent(logical)
                        .map_err(|e| FfsError::Parse(format!("extent lookup failed: {e}")))?
                        .unwrap_or(logical);
                    alloc_guard
                        .extent_alloc
                        .get_extent_data_refs(extent_start)
                        .map_err(|e| FfsError::Parse(format!("extent lookup failed: {e}")))?
                };

                let elem_cnt = data_refs.len();
                let header_size = 4 + 4 + 8 + 8;
                let entry_size = 24;
                let mut buf = Vec::with_capacity(header_size + elem_cnt * entry_size);

                buf.extend_from_slice(&0_u32.to_le_bytes()); // bytes_left
                buf.extend_from_slice(&0_u32.to_le_bytes()); // bytes_missing
                buf.extend_from_slice(&(elem_cnt as u64).to_le_bytes());
                buf.extend_from_slice(&0_u64.to_le_bytes()); // elem_missed

                for data_ref in data_refs {
                    buf.extend_from_slice(&data_ref.objectid.to_le_bytes());
                    buf.extend_from_slice(&data_ref.offset.to_le_bytes());
                    buf.extend_from_slice(&data_ref.root.to_le_bytes());
                }

                Ok(buf)
            }
        }
    }

    fn btrfs_scrub_start(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _devid: u64,
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_SCRUB is not supported on ext4 filesystems".to_owned(),
            )),
            // V1.x: ioctl-based scrub is not implemented. The kernel btrfs scrub
            // reads every block which can take hours on large filesystems.
            // FrankenFS provides scrub/recovery via `ffs repair` command instead.
            // Return empty progress struct = no ioctl-based scrub running (correct).
            // See bd-f37vs for rationale (closed as wont_fix).
            FsFlavor::Btrfs(_) => Ok(vec![0_u8; 1024]),
        }
    }

    fn btrfs_scrub_cancel(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_SCRUB_CANCEL is not supported on ext4 filesystems".to_owned(),
            )),
            // No async scrub running via ioctl - return ENOTCONN as kernel does
            FsFlavor::Btrfs(_) => Err(FfsError::Io(std::io::Error::from_raw_os_error(
                libc::ENOTCONN,
            ))),
        }
    }

    fn btrfs_scrub_progress(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _devid: u64,
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_SCRUB_PROGRESS is not supported on ext4 filesystems".to_owned(),
            )),
            // No async scrub running via ioctl - return empty progress struct.
            // Note: ScrubDaemon in ffs-repair can still verify/repair checksums,
            // just not via this ioctl interface yet.
            FsFlavor::Btrfs(_) => Ok(vec![0_u8; 1024]),
        }
    }

    fn btrfs_defrag_range(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _fh: u64,
        _start: u64,
        _len: u64,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_DEFRAG_RANGE is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // Defrag requires extent tree manipulation - return EROFS for read-only mounts
                // For RW mode, actual implementation would rewrite extents
                Err(FfsError::ReadOnly)
            }
        }
    }

    fn btrfs_snap_create(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _vol_args: &[u8],
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_SNAP_CREATE_V2 is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // Snapshot creation requires ROOT_ITEM creation and tree cloning
                Err(FfsError::ReadOnly)
            }
        }
    }

    fn btrfs_snap_destroy(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _vol_args: &[u8],
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_SNAP_DESTROY is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // Snapshot deletion requires orphan handling and tree removal
                Err(FfsError::ReadOnly)
            }
        }
    }

    fn btrfs_snap_destroy_v2(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _vol_args: &[u8],
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_SNAP_DESTROY_V2 is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // V2 uses subvolid instead of name but still requires tree removal
                Err(FfsError::ReadOnly)
            }
        }
    }

    #[expect(clippy::too_many_lines)]
    fn btrfs_encoded_read(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: u64,
        args: &[u8],
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_ENCODED_READ is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // Parse btrfs_ioctl_encoded_io_args (64 bytes minimum):
                // - iov pointer (8) + iovcnt (8) = 16 bytes (ignored for FUSE, data returned directly)
                // - offset: u64 at byte 16
                // - flags: u64 at byte 24
                // - len: u64 at byte 32 (max length to return)
                if args.len() < 40 {
                    return Err(FfsError::Format("encoded_io_args too short".into()));
                }
                let file_offset = u64::from_le_bytes(args[16..24].try_into().unwrap());
                let _flags = u64::from_le_bytes(args[24..32].try_into().unwrap());
                let max_len = u64::from_le_bytes(args[32..40].try_into().unwrap());

                let canonical = self.btrfs_canonical_inode(InodeNumber(ino))?;

                // The encoded read must respect i_size: the kernel returns 0 at
                // or past EOF, and never reports unencoded bytes beyond it. An
                // extent can legitimately extend past i_size today (e.g. a
                // fallocate KEEP_SIZE prealloc extent on a shorter file), and
                // will routinely once extents become sector-aligned (bd-7mi0p);
                // without this clamp the ioctl returns data for the region past
                // EOF. `btrfs_read_inode_attr` resolves i_size on both the
                // writable (alloc-state) and read-only (tree-walk) paths.
                let file_size = self.btrfs_read_inode_attr(cx, InodeNumber(ino))?.size;
                if file_offset >= file_size {
                    // At/past EOF: no valid file data. Return the bare 32-byte
                    // metadata header with len = unencoded_len = 0.
                    let mut eof = Vec::with_capacity(32);
                    eof.extend_from_slice(&0_u64.to_le_bytes()); // len
                    eof.extend_from_slice(&0_u64.to_le_bytes()); // unencoded_len
                    eof.extend_from_slice(&0_u64.to_le_bytes()); // unencoded_offset
                    eof.extend_from_slice(&0_u32.to_le_bytes()); // compression
                    eof.extend_from_slice(&0_u32.to_le_bytes()); // encryption
                    return Ok(eof);
                }

                // Find extent at the requested offset
                let extent_opt: Option<(u64, BtrfsExtentData)> = if let Some(alloc_mutex) =
                    self.btrfs_alloc_state.as_ref()
                {
                    let alloc = alloc_mutex.read();
                    // The covering extent is the floor of file_offset in the
                    // EXTENT_DATA span (sorted, non-overlapping), so seek it with
                    // floor_key + get instead of ranging every extent of the file
                    // — O(log N) not O(extents) per encoded_read (bd-chbrj, the
                    // writable sibling of bd-phd7z). The COW tree has no separate
                    // tree log, so no walk-all fallback is needed.
                    let seek = BtrfsKey {
                        objectid: canonical,
                        item_type: BTRFS_ITEM_EXTENT_DATA,
                        offset: file_offset,
                    };
                    let covering = match alloc
                        .fs_tree
                        .floor_key(&seek)
                        .map_err(|e| btrfs_mutation_to_ffs(&e))?
                    {
                        Some(k)
                            if k.objectid == canonical && k.item_type == BTRFS_ITEM_EXTENT_DATA =>
                        {
                            alloc
                                .fs_tree
                                .get(&k)
                                .and_then(|v| parse_extent_data(&v).ok().map(|e| (k.offset, e)))
                        }
                        _ => None,
                    };
                    drop(alloc);
                    covering.filter(|(start, ext)| {
                        let end = match ext {
                            BtrfsExtentData::Inline { data, .. } => {
                                start.saturating_add(data.len() as u64)
                            }
                            BtrfsExtentData::Regular { num_bytes, .. } => {
                                start.saturating_add(*num_bytes)
                            }
                        };
                        file_offset >= *start && file_offset < end
                    })
                } else if self.btrfs_tree_log_items.is_empty() {
                    // The covering extent is the EXTENT_DATA with the greatest
                    // key offset <= file_offset (extents are sorted and
                    // non-overlapping), so seek that floor directly instead of
                    // walking every extent of the file — O(log N) not
                    // O(extents) per encoded_read, the cost a full `btrfs send`
                    // of a fragmented file otherwise pays per extent (bd-phd7z).
                    // The floor descent does not see tree-log items, so the
                    // walk-all fallback below handles a pending tree log.
                    let seek = BtrfsKey {
                        objectid: canonical,
                        item_type: BTRFS_ITEM_EXTENT_DATA,
                        offset: file_offset,
                    };
                    self.walk_btrfs_fs_tree_floor(cx, seek)?
                        .filter(|e| {
                            e.key.objectid == canonical && e.key.item_type == BTRFS_ITEM_EXTENT_DATA
                        })
                        .and_then(|e| {
                            parse_extent_data(&e.data)
                                .ok()
                                .map(|ext| (e.key.offset, ext))
                        })
                        .filter(|(start, ext)| {
                            let end = match ext {
                                BtrfsExtentData::Inline { data, .. } => {
                                    start.saturating_add(data.len() as u64)
                                }
                                BtrfsExtentData::Regular { num_bytes, .. } => {
                                    start.saturating_add(*num_bytes)
                                }
                            };
                            file_offset >= *start && file_offset < end
                        })
                } else {
                    let items = self.walk_btrfs_fs_tree_object(cx, canonical)?;
                    items
                        .iter()
                        .filter(|item| {
                            item.key.objectid == canonical
                                && item.key.item_type == BTRFS_ITEM_EXTENT_DATA
                        })
                        .filter_map(|item| {
                            parse_extent_data(&item.data)
                                .ok()
                                .map(|e| (item.key.offset, e))
                        })
                        .find(|(start, ext)| {
                            let end = match ext {
                                BtrfsExtentData::Inline { data, .. } => {
                                    start.saturating_add(data.len() as u64)
                                }
                                BtrfsExtentData::Regular { num_bytes, .. } => {
                                    start.saturating_add(*num_bytes)
                                }
                            };
                            file_offset >= *start && file_offset < end
                        })
                };

                let (extent_start, extent) =
                    extent_opt.ok_or_else(|| FfsError::NotFound("no extent at offset".into()))?;

                // An extent may extend past EOF (prealloc KEEP_SIZE, or a
                // sector-aligned tail). Only the [extent_start, i_size) portion
                // is valid file data, so the reported unencoded length is capped
                // to it — file_offset < file_size is guaranteed above, so this is
                // always >= 1 (bd-7mi0p item 4 / encoded-read EOF parity).
                let in_file_unencoded = file_size.saturating_sub(extent_start);

                // Build response: encoded data + metadata
                // Output format (after encoded data): metadata header
                // len(8) + unencoded_len(8) + unencoded_offset(8) + compression(4) + encryption(4)
                let (encoded_data, compression, unencoded_len, unencoded_offset) = match &extent {
                    BtrfsExtentData::Inline {
                        data, compression, ..
                    } => {
                        let offset_in_extent = file_offset.saturating_sub(extent_start);
                        (
                            data.clone(),
                            *compression,
                            data.len() as u64,
                            offset_in_extent,
                        )
                    }
                    BtrfsExtentData::Regular {
                        compression,
                        disk_bytenr,
                        disk_num_bytes,
                        extent_offset,
                        num_bytes,
                        ..
                    } => {
                        if *disk_bytenr == 0 {
                            // Hole - return zeros
                            #[expect(clippy::cast_possible_truncation)]
                            let len = (*num_bytes).min(max_len) as usize;
                            (vec![0u8; len], 0, *num_bytes, file_offset - extent_start)
                        } else {
                            // Read raw extent data from disk
                            let mapping = map_logical_to_physical(
                                &self.btrfs_context().unwrap().chunks,
                                *disk_bytenr,
                            )
                            .map_err(|e| FfsError::Parse(format!("{e}")))?
                            .ok_or_else(|| {
                                FfsError::Format("extent not covered by chunk".into())
                            })?;
                            #[expect(clippy::cast_possible_truncation)]
                            let read_len = (*disk_num_bytes).min(max_len) as usize;
                            let mut buf = vec![0u8; read_len];
                            self.dev
                                .read_exact_at(cx, ByteOffset(mapping.physical), &mut buf)?;
                            let offset_in_extent = file_offset
                                .saturating_sub(extent_start)
                                .saturating_add(*extent_offset);
                            (buf, *compression, *num_bytes, offset_in_extent)
                        }
                    }
                };

                // Build output: 32-byte metadata header + encoded data
                // len(8) + unencoded_len(8) + unencoded_offset(8) + compression(4) + encryption(4)
                #[expect(clippy::cast_possible_truncation)]
                let actual_len = encoded_data.len().min(max_len as usize);
                let mut result = Vec::with_capacity(32 + actual_len);
                result.extend_from_slice(&(actual_len as u64).to_le_bytes()); // len
                let unencoded_len = unencoded_len.min(in_file_unencoded); // cap to in-file bytes
                result.extend_from_slice(&unencoded_len.to_le_bytes()); // unencoded_len
                result.extend_from_slice(&unencoded_offset.to_le_bytes()); // unencoded_offset
                result.extend_from_slice(&u32::from(compression).to_le_bytes()); // compression
                result.extend_from_slice(&0_u32.to_le_bytes()); // encryption (always 0)
                result.extend_from_slice(&encoded_data[..actual_len]);

                Ok(result)
            }
        }
    }

    fn btrfs_encoded_write(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: u64,
        _args: &[u8],
    ) -> ffs_error::Result<usize> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_ENCODED_WRITE is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // Write requires read-write mode
                Err(FfsError::ReadOnly)
            }
        }
    }

    fn btrfs_resize(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_RESIZE is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // Resize requires read-write mode
                Err(FfsError::ReadOnly)
            }
        }
    }

    fn btrfs_dev_replace(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        args: &[u8],
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_DEV_REPLACE is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // Return status indicating no replacement in progress
                // cmd field at offset 0: 0=start, 1=status, 2=cancel
                let cmd = if args.len() >= 8 {
                    u64::from_le_bytes(args[0..8].try_into().unwrap_or([0; 8]))
                } else {
                    1 // default to status query
                };
                let mut out = vec![0u8; 2600];
                out[0..8].copy_from_slice(&cmd.to_le_bytes());
                // result at offset 8: 0 = no error
                // status.replace_state at offset 16: 0 = not started
                Ok(out)
            }
        }
    }

    fn btrfs_defrag(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: u64,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_DEFRAG is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // Defrag requires write access
                Err(FfsError::ReadOnly)
            }
        }
    }

    fn btrfs_scan_dev(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_SCAN_DEV is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // Device scanning is not applicable in FUSE context
                Err(FfsError::UnsupportedFeature(
                    "BTRFS_IOC_SCAN_DEV not applicable in FUSE context".to_owned(),
                ))
            }
        }
    }

    fn btrfs_forget_dev(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_FORGET_DEV is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_FORGET_DEV not applicable in FUSE context".to_owned(),
            )),
        }
    }

    fn btrfs_send(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        args: &[u8],
        caller_pid: u32,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_SEND is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(sb) => {
                // Parse btrfs_ioctl_send_args:
                //   __s64 send_fd           (0-7)
                //   __u64 clone_sources_count (8-15)
                //   __u64 *clone_sources    (16-23, userspace ptr - not usable in FUSE)
                //   __u64 parent_root       (24-31)
                //   __u64 flags             (32-39)
                //   __u32 version           (40-43)
                //   __u8 reserved[28]       (44-71)
                if args.len() < 72 {
                    return Err(FfsError::Format("BTRFS_IOC_SEND args too short".to_owned()));
                }
                let send_fd = i64::from_le_bytes(args[0..8].try_into().unwrap());
                let clone_sources_count = u64::from_le_bytes(args[8..16].try_into().unwrap());
                let parent_root = u64::from_le_bytes(args[24..32].try_into().unwrap());
                let _flags = u64::from_le_bytes(args[32..40].try_into().unwrap());

                // Incremental sends (with parent or clone sources) are not supported
                if parent_root != 0 {
                    return Err(FfsError::UnsupportedFeature(
                        "BTRFS_IOC_SEND: incremental sends (parent_root != 0) not supported"
                            .to_owned(),
                    ));
                }
                if clone_sources_count != 0 {
                    return Err(FfsError::UnsupportedFeature(
                        "BTRFS_IOC_SEND: clone sources not supported".to_owned(),
                    ));
                }

                // Validate send_fd
                if send_fd < 0 {
                    return Err(FfsError::Io(std::io::Error::from_raw_os_error(libc::EBADF)));
                }

                // Resolve the send_fd via /proc/<pid>/fd/<fd>
                let proc_fd_path =
                    std::path::PathBuf::from(format!("/proc/{caller_pid}/fd/{send_fd}"));
                let mut output_file = std::fs::OpenOptions::new()
                    .write(true)
                    .open(&proc_fd_path)
                    .map_err(|e| {
                        if e.kind() == std::io::ErrorKind::NotFound {
                            FfsError::Io(std::io::Error::from_raw_os_error(libc::EBADF))
                        } else {
                            FfsError::Io(e)
                        }
                    })?;

                // Get the mounted subvolume info from BtrfsContext
                let ctx = self
                    .btrfs_context()
                    .ok_or_else(|| FfsError::Format("btrfs context not available".to_owned()))?;
                let subvol_objectid = ctx.subvol_objectid;
                let subvol_name = format!("subvol_{subvol_objectid}");
                let subvol_uuid = sb.fsid;
                let ctransid = sb.generation;

                // Walk the FS tree to collect all items
                let fs_tree_items = self.walk_btrfs_fs_tree(cx)?;

                // Generate the send stream.
                let stream = generate_send_stream(
                    &fs_tree_items,
                    subvol_name.as_bytes(),
                    &subvol_uuid,
                    ctransid,
                    |disk_bytenr, disk_num_bytes, ram_bytes, compression| {
                        // Read the on-disk extent bytes through the
                        // chunk-boundary-aware read path (bd-ttrw5): a data extent
                        // can straddle a chunk boundary, where the physical mapping
                        // is discontiguous, so a single map+read would emit wrong
                        // bytes. Then DECOMPRESS compressed extents (bd-...): the
                        // on-disk bytes are compressed but the send stream carries
                        // uncompressed data, so emitting the raw compressed bytes
                        // produces a corrupt stream.
                        let raw_len = usize::try_from(disk_num_bytes).map_err(|_| {
                            ffs_types::ParseError::IntegerConversion {
                                field: "extent_length",
                            }
                        })?;
                        let mut raw = vec![0u8; raw_len];
                        self.btrfs_read_logical_into(cx, disk_bytenr, &mut raw)
                            .map_err(|_| ffs_types::ParseError::InvalidField {
                                field: "extent_data",
                                reason: "logical read failed",
                            })?;
                        if compression == ffs_btrfs::BTRFS_COMPRESS_NONE {
                            return Ok(raw);
                        }
                        let uncompressed = usize::try_from(ram_bytes).map_err(|_| {
                            ffs_types::ParseError::IntegerConversion { field: "ram_bytes" }
                        })?;
                        Self::btrfs_decompress(&raw, compression, uncompressed).map_err(|_| {
                            ffs_types::ParseError::InvalidField {
                                field: "extent_data",
                                reason: "decompression failed",
                            }
                        })
                    },
                )
                .map_err(|e| FfsError::Format(format!("generate_send_stream: {e}")))?;

                // Write the stream to the output fd
                std::io::Write::write_all(&mut output_file, &stream).map_err(FfsError::Io)?;

                Ok(())
            }
        }
    }

    fn btrfs_set_received_subvol(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_SET_RECEIVED_SUBVOL is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // Setting received UUID requires write access
                Err(FfsError::ReadOnly)
            }
        }
    }

    fn btrfs_set_fslabel(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_SET_FSLABEL is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => Err(FfsError::ReadOnly),
        }
    }

    fn btrfs_file_extent_same(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: u64,
        _args: &[u8],
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_FILE_EXTENT_SAME is not supported on ext4 filesystems".to_owned(),
            )),
            // FILE_EXTENT_SAME requires reading from destination fds passed by the
            // caller. In FUSE context, we cannot access these fds (they belong to
            // the caller's process). Additionally, this is a read-only mount so
            // actual deduplication (CoW sharing) cannot occur.
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_FILE_EXTENT_SAME: cannot access caller fds in FUSE context (read-only mount cannot dedupe)"
                    .to_owned(),
            )),
        }
    }

    fn btrfs_subvol_create(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _vol_args: &[u8],
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_SUBVOL_CREATE_V2 is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // Subvolume creation requires ROOT_ITEM creation and tree initialization
                Err(FfsError::ReadOnly)
            }
        }
    }

    fn btrfs_rm_dev_v2(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _vol_args: &[u8],
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_RM_DEV_V2 is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "btrfs device removal is not implemented".to_owned(),
            )),
        }
    }

    fn btrfs_add_dev(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _vol_args: &[u8],
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_ADD_DEV is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "btrfs device add is not implemented".to_owned(),
            )),
        }
    }

    fn btrfs_rm_dev(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _vol_args: &[u8],
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_RM_DEV is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "btrfs device removal is not implemented".to_owned(),
            )),
        }
    }

    fn btrfs_balance_start(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_BALANCE_V2 is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // Balance requires data and metadata block relocation
                Err(FfsError::ReadOnly)
            }
        }
    }

    fn btrfs_balance_ctl(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _cmd: i32,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_BALANCE_CTL is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // Balance control requires an active balance operation
                Err(FfsError::ReadOnly)
            }
        }
    }

    fn btrfs_balance_progress(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_BALANCE_PROGRESS is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // No balance operation in progress on read-only mount
                Err(FfsError::Io(std::io::Error::from_raw_os_error(
                    libc::ENOTCONN,
                )))
            }
        }
    }

    fn btrfs_get_fslabel(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_GET_FSLABEL is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(state) => {
                let label = state.label.as_bytes();
                let nul_pos = label.iter().position(|&b| b == 0).unwrap_or(label.len());
                Ok(label[..nul_pos].to_vec())
            }
        }
    }

    fn btrfs_get_dev_stats(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        devid: u64,
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_GET_DEV_STATS is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // Return zeroed stats struct - FrankenFS is read-only and doesn't track device errors
                // struct btrfs_ioctl_get_dev_stats = 1032 bytes
                // Layout: devid(8) + nr_items(8) + flags(8) + values[5](40) + unused[121..](968)
                let mut out = vec![0u8; 1032];
                out[0..8].copy_from_slice(&devid.to_le_bytes());
                out[8..16].copy_from_slice(&5u64.to_le_bytes()); // nr_items = 5 counters
                Ok(out)
            }
        }
    }

    fn btrfs_get_subvol_info(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_GET_SUBVOL_INFO is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // struct btrfs_ioctl_get_subvol_info_args = 504 bytes
                // For now return minimal info for the root subvolume
                let subvol_id = self
                    .btrfs_context
                    .as_ref()
                    .map_or(BTRFS_FS_TREE_OBJECTID, |ctx| ctx.subvol_objectid);
                let mut out = vec![0u8; 504];
                // treeid at offset 0
                out[0..8].copy_from_slice(&subvol_id.to_le_bytes());
                Ok(out)
            }
        }
    }

    fn btrfs_tree_search_v2(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        args: &[u8],
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_TREE_SEARCH_V2 is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(sb) => {
                if args.len() < BTRFS_TREE_SEARCH_V2_HEADER_SIZE {
                    return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                        libc::EINVAL,
                    )));
                }
                let key = parse_btrfs_tree_search_key_bytes(&args[..BTRFS_TREE_SEARCH_KEY_SIZE])?;
                let raw_buf_size = u64::from_ne_bytes(
                    args[BTRFS_TREE_SEARCH_KEY_SIZE..BTRFS_TREE_SEARCH_V2_HEADER_SIZE]
                        .try_into()
                        .expect("validated btrfs tree-search-v2 buf_size field"),
                );
                let buf_size = usize::try_from(raw_buf_size).unwrap_or(usize::MAX);
                let entries = self.btrfs_tree_search_entries(cx, &key)?;
                let (nr_items, results) = encode_btrfs_tree_search_results_with_limit(
                    &key,
                    sb.generation,
                    entries,
                    buf_size,
                )?;

                let mut out = vec![0u8; BTRFS_TREE_SEARCH_V2_HEADER_SIZE + results.len()];
                out[..BTRFS_TREE_SEARCH_KEY_SIZE]
                    .copy_from_slice(&args[..BTRFS_TREE_SEARCH_KEY_SIZE]);
                out[64..68].copy_from_slice(&nr_items.to_ne_bytes());
                out[BTRFS_TREE_SEARCH_KEY_SIZE..BTRFS_TREE_SEARCH_V2_HEADER_SIZE]
                    .copy_from_slice(&raw_buf_size.to_ne_bytes());
                out[BTRFS_TREE_SEARCH_V2_HEADER_SIZE..].copy_from_slice(&results);
                Ok(out)
            }
        }
    }

    fn btrfs_ino_lookup_user(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        treeid: u64,
        dirid: u64,
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_INO_LOOKUP_USER is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                let root_items = self.walk_btrfs_root_tree(cx)?;
                let name = root_items
                    .iter()
                    .find_map(|entry| {
                        if entry.key.item_type == BTRFS_ITEM_ROOT_REF && entry.key.offset == treeid
                        {
                            let root_ref = ffs_btrfs::parse_root_ref(&entry.data).ok()?;
                            if root_ref.dirid == dirid {
                                Some(root_ref.name)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    })
                    .ok_or_else(|| {
                        FfsError::NotFound(format!(
                            "btrfs root ref for tree {treeid} at dirid {dirid} not found"
                        ))
                    })?;
                let (_resolved_treeid, path) = self.btrfs_ino_lookup(cx, scope, 0, dirid)?;

                let mut out = vec![0u8; BTRFS_INO_LOOKUP_USER_ARGS_SIZE];
                out[0..8].copy_from_slice(&dirid.to_ne_bytes());
                out[8..16].copy_from_slice(&treeid.to_ne_bytes());

                let name_len = name.len().min(BTRFS_INO_LOOKUP_USER_NAME_SIZE - 1);
                out[BTRFS_INO_LOOKUP_USER_NAME_OFFSET
                    ..BTRFS_INO_LOOKUP_USER_NAME_OFFSET + name_len]
                    .copy_from_slice(&name[..name_len]);

                let path_len = path
                    .iter()
                    .position(|&byte| byte == 0)
                    .map_or(path.len(), |nul| nul + 1)
                    .min(BTRFS_INO_LOOKUP_USER_PATH_SIZE);
                out[BTRFS_INO_LOOKUP_USER_PATH_OFFSET
                    ..BTRFS_INO_LOOKUP_USER_PATH_OFFSET + path_len]
                    .copy_from_slice(&path[..path_len]);
                Ok(out)
            }
        }
    }

    fn btrfs_get_subvol_rootref(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        args: &[u8],
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_GET_SUBVOL_ROOTREF is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                if args.len() < BTRFS_SUBVOL_ROOTREF_ARGS_SIZE {
                    return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                        libc::EINVAL,
                    )));
                }
                let min_treeid = u64::from_ne_bytes(
                    args[0..8]
                        .try_into()
                        .expect("validated btrfs subvol-rootref min_treeid"),
                );
                let parent_treeid = self
                    .btrfs_context
                    .as_ref()
                    .map_or(BTRFS_FS_TREE_OBJECTID, |ctx| ctx.subvol_objectid);
                let root_items = self.walk_btrfs_root_tree(cx)?;
                let mut rootrefs = root_items
                    .iter()
                    .filter_map(|entry| {
                        if entry.key.item_type == BTRFS_ITEM_ROOT_REF
                            && entry.key.objectid == parent_treeid
                            && entry.key.offset >= min_treeid
                        {
                            let root_ref = ffs_btrfs::parse_root_ref(&entry.data).ok()?;
                            Some((entry.key.offset, root_ref.dirid))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                rootrefs.sort_unstable();

                let mut out = vec![0u8; BTRFS_SUBVOL_ROOTREF_ARGS_SIZE];
                let take_count = rootrefs.len().min(BTRFS_MAX_ROOTREF_BUFFER_NUM);
                let next_min_treeid = rootrefs
                    .get(take_count.saturating_sub(1))
                    .map_or(min_treeid, |(treeid, _)| treeid.saturating_add(1));
                out[0..8].copy_from_slice(&next_min_treeid.to_ne_bytes());
                for (slot, (treeid, dirid)) in rootrefs.into_iter().take(take_count).enumerate() {
                    let offset = 8 + slot * BTRFS_ROOTREF_ENTRY_SIZE;
                    out[offset..offset + 8].copy_from_slice(&treeid.to_ne_bytes());
                    out[offset + 8..offset + 16].copy_from_slice(&dirid.to_ne_bytes());
                }
                out[BTRFS_SUBVOL_ROOTREF_NUM_ITEMS_OFFSET] =
                    u8::try_from(take_count).expect("take_count capped at u8-compatible size");
                Ok(out)
            }
        }
    }

    fn clone_file(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        dest_ino: InodeNumber,
        src_ino: InodeNumber,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "FICLONE is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // Reflink: share every src EXTENT_DATA into dst (refs++,
                // EXTENT_DATA_REF backref, dst i_size = src i_size). FUSE has
                // already resolved src_ino on the same device. bd-vh8p9.
                self.require_btrfs_rw_allowed("clone_file")?;
                let src_canonical = self.btrfs_canonical_inode(src_ino)?;
                let dst_canonical = self.btrfs_canonical_inode(dest_ino)?;
                let alloc_mutex = self.require_btrfs_alloc_state()?;
                let mut alloc = alloc_mutex.write();
                self.btrfs_clone_file_data(&mut alloc, src_canonical, dst_canonical)
            }
        }
    }

    #[allow(clippy::significant_drop_tightening)]
    fn clone_file_range(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        dest_ino: InodeNumber,
        src_ino: InodeNumber,
        src_offset: u64,
        src_length: u64,
        dest_offset: u64,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "FICLONERANGE is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                self.require_btrfs_rw_allowed("clone_file_range")?;
                let src_canonical = self.btrfs_canonical_inode(src_ino)?;
                let dst_canonical = self.btrfs_canonical_inode(dest_ino)?;
                let alloc_mutex = self.require_btrfs_alloc_state()?;
                let mut alloc = alloc_mutex.write();
                // src_length == 0 means "to source EOF" (FICLONERANGE semantics).
                let src_size = self.btrfs_read_inode_from_tree(&alloc, src_canonical)?.size;
                let len = if src_length == 0 {
                    src_size.saturating_sub(src_offset)
                } else {
                    src_length
                };
                // FICLONERANGE alignment (kernel remap_check_alignment): the
                // source and destination offsets must be sector-aligned, and the
                // length must be sector-aligned UNLESS the range reaches the
                // source EOF (the final partial block may be cloned). Otherwise
                // EINVAL — which also keeps every cloned extent sector-aligned so
                // the on-disk image stays btrfs-check-clean (bd-70gyh).
                let ss = u64::from(alloc.sectorsize);
                let reaches_src_eof = src_offset.saturating_add(len) >= src_size;
                if src_offset % ss != 0
                    || dest_offset % ss != 0
                    || (!reaches_src_eof && len % ss != 0)
                {
                    return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                        libc::EINVAL,
                    )));
                }
                // A range covering the whole source from 0 into dst@0 reduces to
                // a full reflink (verbatim extent copy). Any other window uses
                // boundary-split sharing (bd-jbtd2).
                if src_offset == 0 && dest_offset == 0 && len >= src_size {
                    self.btrfs_clone_file_data(&mut alloc, src_canonical, dst_canonical)
                } else if len == 0 {
                    Ok(()) // empty range (e.g. src_offset past EOF): nothing to share
                } else {
                    self.btrfs_clone_file_range_data(
                        cx,
                        &mut alloc,
                        src_canonical,
                        dst_canonical,
                        src_offset,
                        len,
                        dest_offset,
                    )
                }
            }
        }
    }

    fn btrfs_ino_lookup(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        treeid: u64,
        objectid: u64,
    ) -> ffs_error::Result<(u64, Vec<u8>)> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_INO_LOOKUP is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                let mounted_treeid = self
                    .btrfs_context
                    .as_ref()
                    .map_or(BTRFS_FS_TREE_OBJECTID, |ctx| ctx.subvol_objectid);
                // If treeid is 0, use the mounted subvolume's tree.
                let resolved_treeid = if treeid == 0 { mounted_treeid } else { treeid };
                if objectid == BTRFS_FIRST_FREE_OBJECTID {
                    // Subvolume root: NUL-terminated empty path.
                    return Ok((resolved_treeid, vec![0_u8]));
                }
                // Non-root inode: walk INODE_REF back-references inside the
                // requested subvolume tree up to that tree's root, prepending
                // each name component. This mirrors Linux's
                // btrfs_ioctl_ino_lookup treeid contract while keeping the
                // writable fast path scoped to the mounted tree.
                let path = if resolved_treeid == mounted_treeid {
                    self.btrfs_resolve_inode_path(cx, objectid)?
                } else {
                    self.btrfs_resolve_inode_path_in_tree(cx, resolved_treeid, objectid)?
                };
                Ok((resolved_treeid, path))
            }
        }
    }

    fn get_btrfs_dev_info(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        devid_in: u64,
        uuid_in: [u8; 16],
    ) -> ffs_error::Result<Vec<u8>> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_DEV_INFO is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(sb) => encode_btrfs_dev_info_args(sb, devid_in, &uuid_in),
        }
    }

    fn get_subvol_flags(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
    ) -> ffs_error::Result<u64> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_SUBVOL_GETFLAGS is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                let subvol_id = self
                    .btrfs_context
                    .as_ref()
                    .map_or(BTRFS_FS_TREE_OBJECTID, |ctx| ctx.subvol_objectid);
                let root_items = self.walk_btrfs_root_tree(cx)?;
                let fs_tree_root = root_items
                    .iter()
                    .find(|item| {
                        item.key.objectid == subvol_id && item.key.item_type == BTRFS_ITEM_ROOT_ITEM
                    })
                    .ok_or_else(|| {
                        FfsError::NotFound(format!(
                            "btrfs ROOT_ITEM for subvolume objectid {subvol_id}"
                        ))
                    })?;
                let root_item =
                    parse_root_item(&fs_tree_root.data).map_err(|e| parse_to_ffs_error(&e))?;
                Ok(root_item.flags)
            }
        }
    }

    fn set_subvol_flags(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: InodeNumber,
        flags: u64,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_SUBVOL_SETFLAGS is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                self.require_btrfs_rw_allowed("subvol_setflags")?;

                // Only BTRFS_ROOT_SUBVOL_RDONLY (bit 0) is user-settable
                if flags & !BTRFS_ROOT_SUBVOL_RDONLY != 0 {
                    return Err(FfsError::UnsupportedFeature(format!(
                        "invalid subvol flags 0x{flags:x}: only RDONLY (0x1) is settable"
                    )));
                }

                let subvol_id = self
                    .btrfs_context
                    .as_ref()
                    .map_or(BTRFS_FS_TREE_OBJECTID, |ctx| ctx.subvol_objectid);

                let root_key = BtrfsKey {
                    objectid: subvol_id,
                    item_type: BTRFS_ITEM_ROOT_ITEM,
                    offset: 0,
                };

                let alloc_mutex = self.require_btrfs_alloc_state()?;
                {
                    let mut alloc = alloc_mutex.write();

                    let mut root_item_data = alloc.root_tree.get(&root_key).ok_or_else(|| {
                        FfsError::NotFound(format!(
                            "btrfs ROOT_ITEM for subvolume objectid {subvol_id}"
                        ))
                    })?;

                    BtrfsRootItem::patch_flags(&mut root_item_data, flags).map_err(|e| {
                        FfsError::Parse(format!("ROOT_ITEM flags patch failed: {e}"))
                    })?;

                    alloc
                        .root_tree
                        .update(&root_key, &root_item_data)
                        .map_err(|e| btrfs_mutation_to_ffs(&e))?;
                }

                Ok(())
            }
        }
    }

    fn btrfs_set_default_subvol(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _treeid: u64,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_DEFAULT_SUBVOL is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // Updating the default subvolume requires persistent root-tree
                // metadata mutation; fail closed while btrfs writeback remains
                // guarded/non-persistent.
                Err(FfsError::ReadOnly)
            }
        }
    }

    fn btrfs_start_transaction(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_TRANS_START is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // Explicit transaction lifecycle ioctls require durable btrfs
                // metadata mutation; fail closed while btrfs writeback remains
                // guarded/non-persistent.
                Err(FfsError::ReadOnly)
            }
        }
    }

    fn btrfs_end_transaction(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::UnsupportedFeature(
                "BTRFS_IOC_TRANS_END is not supported on ext4 filesystems".to_owned(),
            )),
            FsFlavor::Btrfs(_) => {
                // See `btrfs_start_transaction`: the matching end ioctl is
                // still a write-side transaction control surface.
                Err(FfsError::ReadOnly)
            }
        }
    }

    fn get_encryption_policy_ex(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
    ) -> ffs_error::Result<(u8, Vec<u8>)> {
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                let sb = self
                    .ext4_superblock()
                    .ok_or_else(|| FfsError::Format("not an ext4 filesystem".into()))?;
                if !sb.has_incompat(ffs_ondisk::Ext4IncompatFeatures::ENCRYPT) {
                    return Err(FfsError::UnsupportedFeature(
                        "ext4 ENCRYPT incompat feature is not enabled".into(),
                    ));
                }

                let inode =
                    self.read_inode_with_scope(cx, scope, Self::ext4_canonical_inode(ino))?;
                if !inode.is_encrypted() {
                    return Err(FfsError::Io(std::io::Error::from_raw_os_error(
                        libc::ENODATA,
                    )));
                }

                let mut xattrs =
                    ffs_ondisk::parse_ibody_xattrs(&inode).map_err(|e| parse_to_ffs_error(&e))?;
                if inode.file_acl != 0 {
                    let block_data = self.read_block_vec(cx, BlockNumber(inode.file_acl))?;
                    let block_xattrs = ffs_ondisk::parse_xattr_block(&block_data)
                        .map_err(|e| parse_to_ffs_error(&e))?;
                    xattrs.extend(block_xattrs);
                }

                let context = xattrs
                    .into_iter()
                    .find(|xattr| {
                        xattr.name_index == ffs_types::EXT4_XATTR_INDEX_ENCRYPTION
                            && xattr.name == EXT4_ENCRYPTION_XATTR_NAME
                    })
                    .map(|xattr| xattr.value)
                    .ok_or_else(|| {
                        FfsError::Format("encrypted inode is missing fscrypt context".into())
                    })?;

                let Some(version) = context.first().copied() else {
                    return Err(FfsError::Format("fscrypt context is empty".into()));
                };

                match version {
                    FSCRYPT_POLICY_V1_VERSION => {
                        if context.len() < FSCRYPT_CONTEXT_V1_SIZE {
                            return Err(FfsError::Format("fscrypt v1 context is truncated".into()));
                        }
                        Ok((version, context[..FSCRYPT_POLICY_V1_SIZE].to_vec()))
                    }
                    FSCRYPT_POLICY_V2_VERSION => {
                        if context.len() < FSCRYPT_CONTEXT_V2_SIZE {
                            return Err(FfsError::Format("fscrypt v2 context is truncated".into()));
                        }
                        Ok((version, context[..FSCRYPT_POLICY_V2_SIZE].to_vec()))
                    }
                    _ => Err(FfsError::Format(format!(
                        "unsupported fscrypt policy version {version}"
                    ))),
                }
            }
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "get_encryption_policy_ex is not supported for btrfs".to_owned(),
            )),
        }
    }

    fn set_inode_flags(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        flags: u32,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                let canonical = Self::ext4_canonical_inode(ino);
                let alloc_mutex = self.require_alloc_state()?;
                let block_dev = self.block_device_adapter();
                let sb = self
                    .ext4_superblock()
                    .ok_or_else(|| FfsError::Format("not an ext4 filesystem".into()))?;
                let csum_seed = sb.csum_seed();

                let mut inode = self.read_inode_with_scope(cx, scope, canonical)?;
                let requested_user_flags = flags & Self::EXT4_USER_SETTABLE_FLAGS;
                let wants_compression = requested_user_flags & ffs_types::EXT4_COMPR_FL != 0;
                if wants_compression
                    && !sb.has_incompat(ffs_ondisk::Ext4IncompatFeatures::COMPRESSION)
                {
                    return Err(FfsError::UnsupportedFeature(
                        "EXT4_COMPR_FL requires the ext4 COMPRESSION incompat feature".into(),
                    ));
                }
                let enabling_compression =
                    wants_compression && inode.flags & ffs_types::EXT4_COMPR_FL == 0;
                if enabling_compression {
                    if !inode.is_regular() {
                        return Err(FfsError::ModeViolation(
                            "EXT4_COMPR_FL can only be enabled on regular files".into(),
                        ));
                    }
                    if inode.size != 0 {
                        return Err(FfsError::UnsupportedFeature(
                            "EXT4_COMPR_FL can only be enabled on empty files".into(),
                        ));
                    }
                }

                let mut new_flags =
                    (inode.flags & !Self::EXT4_USER_SETTABLE_FLAGS) | requested_user_flags;
                if enabling_compression {
                    inode.flags = new_flags;
                    Self::seed_e2compr_defaults_for_inode(&mut inode);
                    new_flags = inode.flags;
                }
                inode.flags = new_flags;

                if let Some(tx) = &mut scope.tx {
                    let tx_dev = TransactionBlockAdapter {
                        base: &block_dev,
                        tx: Mutex::new(tx),
                    };
                    let alloc = alloc_mutex.read();
                    ffs_inode::write_inode(
                        cx,
                        &tx_dev,
                        &alloc.geo,
                        &alloc.groups,
                        canonical,
                        &inode,
                        csum_seed,
                    )?;
                } else {
                    let alloc = alloc_mutex.read();
                    ffs_inode::write_inode(
                        cx,
                        &block_dev,
                        &alloc.geo,
                        &alloc.groups,
                        canonical,
                        &inode,
                        csum_seed,
                    )?;
                }
                Ok(())
            }
            FsFlavor::Btrfs(_) => {
                self.require_btrfs_rw_allowed("setflags")?;
                let alloc_mutex = self.require_btrfs_alloc_state()?;
                let canonical = self.btrfs_canonical_inode(ino)?;

                let mut alloc = alloc_mutex.write();
                let mut inode = self.btrfs_read_inode_from_tree(&alloc, canonical)?;

                let requested_btrfs = fsflags_to_btrfs_inode_flags(flags);
                let old_btrfs = inode.flags;
                let user_settable_btrfs = fsflags_to_btrfs_inode_flags(BTRFS_USER_SETTABLE_FSFLAGS);
                inode.flags =
                    (old_btrfs & !user_settable_btrfs) | (requested_btrfs & user_settable_btrfs);

                let (secs, nanos) = Self::btrfs_now_timestamp();
                inode.ctime_sec = secs;
                inode.ctime_nsec = nanos;

                let inode_key = BtrfsKey {
                    objectid: canonical,
                    item_type: BTRFS_ITEM_INODE_ITEM,
                    offset: 0,
                };
                alloc
                    .fs_tree
                    .update(&inode_key, &inode.to_bytes())
                    .map_err(|e| btrfs_mutation_to_ffs(&e))?;
                drop(alloc);

                Ok(())
            }
        }
    }

    fn move_ext(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        donor_fd: u32,
        orig_start: u64,
        donor_start: u64,
        len: u64,
    ) -> ffs_error::Result<u64> {
        match &self.flavor {
            FsFlavor::Ext4(_) => self.ext4_move_ext(
                cx,
                scope,
                Ext4MoveExtRequest {
                    ino,
                    donor_fd,
                    orig_start,
                    donor_start,
                    len,
                },
            ),
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "move_ext is not supported for btrfs".to_owned(),
            )),
        }
    }

    fn register_move_ext_donor_fd(
        &self,
        donor_fd: u32,
        donor_ino: InodeNumber,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                self.move_ext_donor_fds
                    .lock()
                    .insert(donor_fd, Self::ext4_canonical_inode(donor_ino));
                Ok(())
            }
            FsFlavor::Btrfs(_) => Ok(()),
        }
    }

    fn unregister_move_ext_donor_fd(&self, donor_fd: u32) {
        if matches!(self.flavor, FsFlavor::Ext4(_)) {
            self.move_ext_donor_fds.lock().remove(&donor_fd);
        }
    }

    fn ext4_group_extend(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::ReadOnly),
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "EXT4_IOC_GROUP_EXTEND is not supported on btrfs filesystems".to_owned(),
            )),
        }
    }

    fn ext4_resize_fs(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::ReadOnly),
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "EXT4_IOC_RESIZE_FS is not supported on btrfs filesystems".to_owned(),
            )),
        }
    }

    fn ext4_group_add(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _args: &[u8],
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::ReadOnly),
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "EXT4_IOC_GROUP_ADD is not supported on btrfs filesystems".to_owned(),
            )),
        }
    }

    fn ext4_alloc_da_blks(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: u64,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::ReadOnly),
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "EXT4_IOC_ALLOC_DA_BLKS is not supported on btrfs filesystems".to_owned(),
            )),
        }
    }

    fn ext4_migrate(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: u64,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::ReadOnly),
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "EXT4_IOC_MIGRATE is not supported on btrfs filesystems".to_owned(),
            )),
        }
    }

    fn ext4_swap_boot(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _ino: u64,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => Err(FfsError::ReadOnly),
            FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "EXT4_IOC_SWAP_BOOT is not supported on btrfs filesystems".to_owned(),
            )),
        }
    }

    fn fs_shutdown(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        _flags: &[u8],
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) | FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "FS_IOC_SHUTDOWN is not supported (emergency stop requires kernel integration)"
                    .to_owned(),
            )),
        }
    }

    fn fs_freeze(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<i32> {
        match &self.flavor {
            FsFlavor::Ext4(_) | FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "FIFREEZE requires kernel-level freeze support".to_owned(),
            )),
        }
    }

    fn fs_thaw(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) | FsFlavor::Btrfs(_) => Err(FfsError::UnsupportedFeature(
                "FITHAW requires kernel-level freeze support".to_owned(),
            )),
        }
    }

    fn get_block_size(&self, _cx: &Cx, _scope: &mut RequestScope) -> ffs_error::Result<u32> {
        match &self.flavor {
            FsFlavor::Ext4(sb) => Ok(sb.block_size),
            FsFlavor::Btrfs(sb) => Ok(sb.sectorsize),
        }
    }

    fn setattr(
        &self,
        cx: &Cx,
        scope: &mut RequestScope,
        ino: InodeNumber,
        attrs: &SetAttrRequest,
    ) -> ffs_error::Result<InodeAttr> {
        match &self.flavor {
            FsFlavor::Ext4(_) => self
                .ext4_setattr(cx, scope, Self::ext4_canonical_inode(ino), attrs)
                .map(Self::ext4_present_attr),
            FsFlavor::Btrfs(_) => {
                self.check_btrfs_mutation_allowed("setattr")?;
                self.btrfs_setattr(cx, ino, attrs)
            }
        }
    }

    fn flush(
        &self,
        _cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        fh: u64,
        lock_owner: u64,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => {
                let scenario_id = Self::EXT4_RW_SCENARIO_FLUSH;
                // operation_id feeds only the two info! records below; skip its
                // per-flush format+alloc when INFO is disabled (see the same guard
                // in ext4_sync_with_logging).
                let operation_id = if tracing::enabled!(target: "ffs::ext4::rw", tracing::Level::INFO)
                {
                    Self::ext4_flush_operation_id(ino, fh, lock_owner)
                } else {
                    String::new()
                };
                info!(
                    target: "ffs::ext4::rw",
                    operation_id = %operation_id,
                    scenario_id,
                    outcome = "start",
                    ino = ino.0,
                    fh,
                    lock_owner,
                    durability_boundary = "none",
                    "ext4_sync_start"
                );
                info!(
                    target: "ffs::ext4::rw",
                    operation_id = %operation_id,
                    scenario_id,
                    outcome = "applied",
                    ino = ino.0,
                    fh,
                    lock_owner,
                    durability_boundary = "none",
                    "ext4_sync_applied"
                );
            }
            FsFlavor::Btrfs(_) => {
                let scenario_id = Self::BTRFS_RW_SCENARIO_FLUSH;
                // Only the two info! records below use operation_id — skip its
                // per-flush format+alloc when INFO is disabled.
                let operation_id = if tracing::enabled!(target: "ffs::btrfs::rw", tracing::Level::INFO)
                {
                    Self::btrfs_flush_operation_id(ino, fh, lock_owner)
                } else {
                    String::new()
                };
                info!(
                    target: "ffs::btrfs::rw",
                    operation_id = %operation_id,
                    scenario_id,
                    outcome = "start",
                    ino = ino.0,
                    fh,
                    lock_owner,
                    durability_boundary = "none",
                    "btrfs_sync_start"
                );
                info!(
                    target: "ffs::btrfs::rw",
                    operation_id = %operation_id,
                    scenario_id,
                    outcome = "applied",
                    ino = ino.0,
                    fh,
                    lock_owner,
                    durability_boundary = "none",
                    "btrfs_sync_applied"
                );
            }
        }
        Ok(())
    }

    fn fsync(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        _fh: u64,
        datasync: bool,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => self.ext4_sync_with_logging(
                cx,
                "fsync",
                Self::EXT4_RW_SCENARIO_FSYNC,
                ino,
                datasync,
            ),
            FsFlavor::Btrfs(_) => self.btrfs_sync_with_logging(
                cx,
                "fsync",
                Self::BTRFS_RW_SCENARIO_FSYNC,
                ino,
                datasync,
            ),
        }
    }

    fn fsyncdir(
        &self,
        cx: &Cx,
        _scope: &mut RequestScope,
        ino: InodeNumber,
        _fh: u64,
        datasync: bool,
    ) -> ffs_error::Result<()> {
        match &self.flavor {
            FsFlavor::Ext4(_) => self.ext4_sync_with_logging(
                cx,
                "fsyncdir",
                Self::EXT4_RW_SCENARIO_FSYNCDIR,
                ino,
                datasync,
            ),
            FsFlavor::Btrfs(_) => self.btrfs_sync_with_logging(
                cx,
                "fsyncdir",
                Self::BTRFS_RW_SCENARIO_FSYNCDIR,
                ino,
                datasync,
            ),
        }
    }

    fn begin_request_scope(&self, _cx: &Cx, op: RequestOp) -> ffs_error::Result<RequestScope> {
        let (snapshot, tx) = if op.is_write() {
            // Write operations must use a transaction for isolation and atomicity.
            let txn = self.mvcc_store.begin();
            let snapshot = txn.snapshot;
            self.mvcc_store.register_snapshot(snapshot);
            trace!(
                target: "ffs::mvcc",
                op = ?op,
                txn_id = txn.id().0,
                "mvcc_request_scope_begin_write"
            );
            (Some(snapshot), Some(txn))
        } else {
            // Read operations carry a snapshot VALUE but do NOT register it in the
            // global `active_snapshots` map. Registration exists only to hold the GC
            // watermark down so prune cannot remove a version the request still needs
            // — but a read op never reads a pinned overlay version: every use of
            // `scope.snapshot` to read an MVCC version is gated on `scope.tx.is_some()`
            // (writes; see 12019/12135 overlay_snapshot and 11856/11910/11947), and
            // `can_cache_ext4_read_only_block` bails on writable mounts before touching
            // it; block reads go through the read-your-writes / base-direct adapter that
            // is itself already unregistered (bd-bhh0i, block_device_adapter). So the
            // per-read register+release was two acquisitions of the GLOBAL
            // `active_snapshots` WRITE lock per read op with zero effect on read RESULTS
            // — a serialization point on the parallel read path, now removed.
            // `scope.snapshot` stays `Some` for the cacheability existence checks.
            let snapshot = self.current_snapshot();
            trace!(
                target: "ffs::mvcc",
                op = ?op,
                snapshot_high = snapshot.high.0,
                "mvcc_request_scope_begin_read"
            );
            (Some(snapshot), None)
        };

        Ok(RequestScope {
            snapshot,
            tx,
            commit_mode: RequestCommitMode::PerRequest,
            skip_readdir_prefetch: false,
        })
    }

    fn end_request_scope(
        &self,
        _cx: &Cx,
        op: RequestOp,
        scope: RequestScope,
    ) -> ffs_error::Result<()> {
        // Only WRITE scopes register a snapshot (see begin_request_scope); read
        // scopes carry a snapshot value but never pin it in `active_snapshots`, so
        // there is nothing to release. Keyed on `op.is_write()` (symmetric with the
        // register condition) rather than `scope.tx`, because a committed write has
        // already consumed its `tx` yet its snapshot is still registered.
        if op.is_write() {
            if let Some(snapshot) = scope.snapshot {
                let released = self.mvcc_store.release_snapshot(snapshot);
                if released {
                    trace!(
                        target: "ffs::mvcc",
                        op = ?op,
                        snapshot_high = snapshot.high.0,
                        "mvcc_request_scope_end_write"
                    );
                } else {
                    warn!(
                        target: "ffs::mvcc",
                        op = ?op,
                        snapshot_high = snapshot.high.0,
                        "mvcc_request_scope_release_missed"
                    );
                }
            }
        }

        if let Some(tx) = scope.tx {
            let txn_id = tx.id().0;
            self.mvcc_store
                .abort(tx, ffs_mvcc::TxnAbortReason::Timeout, None);
            trace!(
                target: "ffs::mvcc",
                op = ?op,
                txn_id,
                "mvcc_request_scope_end_write_aborted"
            );
        }

        Ok(())
    }
    /// Commit any transaction in the request scope.
    ///
    /// # Errors
    ///
    /// Returns `FfsError::Conflict` if the transaction cannot be committed.
    fn commit_request_scope(&self, scope: &mut RequestScope) -> ffs_error::Result<CommitSeq> {
        let tx_id = scope.tx.as_ref().map(ffs_mvcc::Transaction::id);
        // Only the repair-flush lifecycle consumes write_blocks; when it is not
        // attached (normal operation) skip the per-commit Vec allocation of every
        // write-set key (the notify no-ops on an empty slice anyway).
        let write_blocks = if self.repair_flush_lifecycle.is_some() {
            scope
                .tx
                .as_ref()
                .map_or_else(Vec::new, |tx| tx.write_set().keys().copied().collect())
        } else {
            Vec::new()
        };
        let result = scope.commit_if_write(&self.mvcc_store);
        if let Ok(commit_seq) = &result {
            self.prune_mvcc_after_commit_if_due(*commit_seq);
            if let Some(tx_id) = tx_id {
                self.notify_repair_flush_lifecycle(tx_id, &write_blocks);
            }
        }
        result
    }

    fn flush_on_destroy(&self, cx: &Cx) -> ffs_error::Result<()> {
        if !self.is_writable() {
            return Ok(());
        }

        // Drain and join the home-location compactor before the final full
        // checkpoint. The synchronous checkpoint remains authoritative even if
        // an earlier background batch failed, and the WAL is retained unless the
        // checkpoint and device sync both succeed.
        self.shutdown_metadata_compactor();

        // Flush committed MVCC block versions (covers ext4 metadata and any
        // file-data extents staged through the block-versioned path).
        let flushed = self.flush_mvcc_to_device(cx)?;
        if flushed > 0 {
            info!(flushed_blocks = flushed, "flush_on_destroy");
        }
        self.checkpoint_metadata_log()?;

        // btrfs commit-on-destroy: flush dirty COW trees to disk so
        // mutations performed through the mounted FUSE path survive
        // unmount/remount. The full transaction commit allocates real
        // chunk-covered logical addresses for each node, rewrites internal
        // blockptrs to those addresses, translates them through
        // `map_logical_to_physical` for the device write, patches the
        // FS_TREE ROOT_ITEM in root_tree, and finally writes a new
        // superblock pointing at the root_tree's allocated logical address.
        // (bd-jdo53 / bd-1ving.)
        if matches!(self.flavor, FsFlavor::Btrfs(_)) && self.btrfs_alloc_state.is_some() {
            let operation_id =
                format!("destroy-{:016x}", std::ptr::addr_of!(*self) as usize as u64);
            info!(
                target: "ffs::btrfs::rw",
                operation_id = %operation_id,
                scenario_id = "btrfs_rw_destroy",
                outcome = "start",
                durability_boundary = "destroy",
                "btrfs_destroy_commit_start"
            );
            match self.btrfs_full_transaction_commit(cx, &operation_id) {
                Ok(stats) => {
                    info!(
                        target: "ffs::btrfs::rw",
                        operation_id = %operation_id,
                        scenario_id = "btrfs_rw_destroy",
                        outcome = "applied",
                        nodes_written = stats.nodes_written,
                        bytes_written = stats.bytes_written,
                        new_generation = stats.new_generation,
                        fsync_barrier_issued = stats.fsync_barrier_issued,
                        durability_boundary = "destroy",
                        "btrfs_destroy_commit_applied"
                    );
                }
                Err(e) => {
                    warn!(
                        target: "ffs::btrfs::rw",
                        operation_id = %operation_id,
                        scenario_id = "btrfs_rw_destroy",
                        outcome = "rejected",
                        error_class = "destroy_commit_failed",
                        error = %e,
                        durability_boundary = "destroy",
                        "btrfs_destroy_commit_rejected"
                    );
                    return Err(e);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod xattr_scan_tests {
    use super::*;

    /// bd-73bi2: the detector must FIRE on an image the kernel rejects and stay
    /// SILENT on one it accepts.
    ///
    /// Both fixtures are built the same way by
    /// `scripts/make_btrfs_fixture.py`, differing only in file count -- 2000
    /// (kernel mounts it) against 5000 (kernel refuses with `parent transid
    /// verify failed ... failed to load root free space`). Without the negative
    /// half, a detector that reported every image as corrupt would pass.
    #[test]
    fn the_transid_detector_fires_only_on_the_image_the_kernel_rejects_bd_73bi2() {
        let good = std::path::Path::new("/home/ubuntu/btrfs-fixture-2k.img");
        let bad = std::path::Path::new("/home/ubuntu/btrfs-bisect-r5000.img");
        if !good.exists() || !bad.exists() {
            eprintln!("skipping: fixtures absent; rebuild with scripts/make_btrfs_fixture.py");
            return;
        }
        let cx = Cx::for_testing();
        for (image, expect_mismatch) in [(good, false), (bad, true)] {
            let fs = OpenFs::open(&cx, image).expect("image must open through OUR reader");
            let sb = fs.btrfs_superblock().expect("btrfs superblock");
            // Every tree, not just the root tree. The kernel's complaint on the
            // bad image is `failed to load root free space`, so a detector aimed
            // only at `sb.root` finds nothing and reports a corrupt image clean
            // -- which is exactly what it did on the first run of this test.
            let mut mismatches = fs
                .btrfs_transid_mismatches(&cx, sb.root)
                .expect("the walk itself must not fail");
            for objectid in [
                ffs_btrfs::BTRFS_FS_TREE_OBJECTID,
                ffs_btrfs::BTRFS_CSUM_TREE_OBJECTID,
                ffs_btrfs::BTRFS_FREE_SPACE_TREE_OBJECTID,
            ] {
                if let Ok(root) = fs.btrfs_fs_tree_root_bytenr(&cx, objectid) {
                    mismatches.extend(
                        fs.btrfs_transid_mismatches(&cx, root)
                            .expect("the walk itself must not fail"),
                    );
                }
            }
            // The class bd-73bi2 actually belongs to: a ROOT_ITEM disagreeing
            // with the block it points at, before any tree is descended.
            mismatches.extend(
                fs.btrfs_root_item_transid_mismatches(&cx)
                    .expect("the root-item walk must not fail"),
            );
            assert_eq!(
                !mismatches.is_empty(),
                expect_mismatch,
                "{}: expected mismatch={expect_mismatch}, found {mismatches:?}",
                image.display()
            );
        }
    }

    /// bd-ha71t / bd-btrfs-warm-stat-5x-9pxn1: the btrfs half of the proof.
    ///
    /// btrfs pays the same per-path-op `security.capability` probe as ext4 --
    /// its warm stat is `4.977803x` against kernel btrfs and its readdir+stat
    /// `8.32x`, the worst row in the bank -- so the suppression is worth as much
    /// here, and it needs the same proof. This asserts the scan reaches a real
    /// btrfs image and returns a DECIDED answer rather than the `Unknown` a
    /// missing implementation would return.
    #[test]
    fn the_btrfs_scan_decides_on_a_real_image_bd_ha71t() {
        let image = std::path::Path::new("/data/tmp/probe_xfs/btrfs.img");
        if !image.exists() {
            eprintln!("skipping: no btrfs image at {}", image.display());
            return;
        }
        let cx = Cx::for_testing();
        let Ok(fs) = OpenFs::open(&cx, image) else {
            eprintln!("skipping: image at {} did not open", image.display());
            return;
        };
        let presence = FsOps::xattr_presence(&fs, &cx);
        assert_ne!(
            presence,
            XattrPresence::Unknown,
            "the btrfs arm must DECIDE on an image this size; Unknown here means the \
             walk did not run, which is what an unimplemented arm returns"
        );
        // Both directions were checked on real mounts when the walk was made
        // bounded (2026-08-17): the 2048-entry fixture resolves ACTIVE, and the
        // SAME image with one `user.planted` xattr on one of its 2048 files
        // resolves REFUSED. The second is the data-loss direction -- an
        // early-exit walk that could no longer SEE an XATTR_ITEM would suppress
        // on an image that has one, and the kernel would stop asking for an
        // attribute that exists.
    }

    /// bd-ha71t: the scan must PROVE absence on a real image, not merely decline
    /// to find anything.
    ///
    /// This test exists because the first end-to-end run of
    /// `FFS_FUSE_XATTR_NO_SUPPORT=auto` came back REFUSED with
    /// `presence=Unknown` on an image that provably has no xattrs (`listxattr`
    /// returns `[]`, `getxattr` returns `ENODATA`), and a log line could not say
    /// whether the scan had run and failed or had never been reached at all.
    /// A test can.
    #[test]
    fn the_scan_proves_absence_on_an_xattr_free_image_bd_ha71t() {
        let image = std::path::Path::new("/data/tmp/ffs-pgo-train.img");
        if !image.exists() {
            // The fixture is a scratch artifact and scratch is reaped; skipping
            // is honest, silently passing on a missing image would not be.
            eprintln!("skipping: no image at {}", image.display());
            return;
        }
        let cx = Cx::for_testing();
        let fs = OpenFs::open(&cx, image).expect("image must open");
        assert_eq!(
            FsOps::xattr_presence(&fs, &cx),
            XattrPresence::ProvenAbsent,
            "this image carries no extended attributes, so the scan must say so; \
             Unknown here means the scan did not run, not that it found something"
        );
    }
}
