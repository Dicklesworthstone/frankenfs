//! Read-only ZPL namespace and file bytes at an explicitly selected head root.
//! Native paths stay inside this view; no host paths, log replay or mutation.

mod path;
mod seek;
pub mod snapshots;
mod xattrs;
mod zil_records;

pub use path::PathPolicy;

use super::zil::{self, OwnedEdit};
use super::{
    BTreeSet, BlockPointer, Cx, FfsError, MAX_READ_BYTES, Object, ObjectSet, Objects, Result,
    VecDeque, checkpoint, corrupt, parse, unsupported,
};
use ffs_ondisk::zfs_dmu::{ZapEntry, ZilHeader, ZilRecordPayload};
use ffs_ondisk::zfs_zpl::{Attributes, Kind, Metadata, SA_BYTES, SaRegistry, directory_reference};
use std::collections::BTreeMap;
use std::sync::Arc;

const MAX_PATH: usize = 65_536;
const MAX_COMPONENTS: usize = 256;
const MAX_DIRECTORY_BYTES: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ZilReplayStats {
    pub blocks_visited: usize,
    pub records_replayed: usize,
    pub last_txg: u64,
    pub last_seq: u64,
    /// Native unclaimed logs normally end at an allocated unwritten LWB.
    pub unverified_tail: bool,
}

#[derive(Debug, Clone)]
struct RecoveredFile {
    original_size: u64,
    edits: Vec<OwnedEdit>,
}

#[derive(Debug, Clone, Default)]
struct ZilOverlay {
    stats: ZilReplayStats,
    objects: BTreeMap<u64, Metadata>,
    dir_entries: BTreeMap<u64, BTreeMap<Vec<u8>, Option<u64>>>,
    file_edits: BTreeMap<u64, Arc<RecoveredFile>>,
    created: BTreeSet<u64>,
    removed_objects: BTreeSet<u64>,
}

pub struct Zpl {
    objects: Objects,
    pub root: u64,
    pub dataset_guid: u64,
    pub version: u64,
    registry: Option<SaRegistry>,
    utf8_only: bool,
    referenced_bytes: u64,
    pub zil_header: ZilHeader,
    zil_overlay: Option<ZilOverlay>,
    mos: Option<(Box<Objects>, Vec<Vec<u8>>)>,
}
#[derive(Debug)]
pub struct DirectoryEntry {
    pub name: Vec<u8>,
    pub object: u64,
    pub metadata: Metadata,
}

fn value(entries: &[ZapEntry], name: &[u8]) -> Option<u64> {
    entries
        .iter()
        .find(|entry| entry.name == name)
        .map(|entry| entry.value)
}
fn required(entries: &[ZapEntry], name: &[u8]) -> Result<u64> {
    value(entries, name).ok_or_else(|| corrupt("required ZPL master-node attribute is absent"))
}
fn typed_map(view: &mut Objects, cx: &Cx, number: u64, kind: u8) -> Result<Vec<ZapEntry>> {
    if number == 0 || view.object(cx, number)?.object_type() != kind {
        return Err(corrupt("ZPL metadata reference has the wrong object type"));
    }
    view.zap(cx, number)
}

impl Objects {
    /// Selection is through the validated DSL inventory, never an arbitrary
    /// physical pointer. The returned dataset owns a NEW root-local cache.
    pub fn zpl(&mut self, cx: &Cx, components: &[Vec<u8>]) -> Result<Zpl> {
        checkpoint(cx)?;
        let dataset = self
            .datasets(cx)?
            .into_iter()
            .find(|row| row.components == components)
            .ok_or_else(|| FfsError::NotFound("ZFS head dataset".into()))?;
        if dataset.objectset_kind != 2 || dataset.flags & 0x1_0000 != 0 {
            return Err(unsupported(
                "ZPL reads require a case-sensitive filesystem head",
            ));
        }
        let object = self.load(cx, dataset.head_object)?;
        let referenced_bytes = object
            .node
            .order()
            .u64(object.node.bonus(), 72)
            .map_err(|error| parse(&error))?;
        let bp = BlockPointer::parse(&object.node.bonus()[128..256], object.node.order())
            .map_err(|error| parse(&error))?;
        let raw = self
            .checked(cx, &bp, 11, 0, bp.logical_bytes(), object.ceiling)?
            .ok_or_else(|| corrupt("ZPL head object set is a hole"))?;
        let os = ObjectSet::parse(&raw.bytes, raw.order).map_err(|error| parse(&error))?;
        if os.kind != 2 || bp.birth() != dataset.root_birth {
            return Err(corrupt("selected ZPL head identity changed"));
        }
        let zil_header = os.zil_header;
        let view = Self {
            pool: self.pool.clone(),
            config: self.config.clone(),
            txg: self.txg,
            root_birth: bp.birth(),
            meta: os.meta,
            cache: VecDeque::new(),
            cached_bytes: 0,
        };
        Zpl::open(
            cx,
            view,
            dataset.guid,
            referenced_bytes,
            zil_header,
            Some((Box::new(self.clone_mos()), components.to_vec())),
        )
    }
}

impl Zpl {
    /// Scrub this exact head or snapshot's DMU object set, including allocated
    /// private objects that namespace enumeration would not visit. Never switch
    /// to the MOS or live head; the selected historical birth ceiling is retained.
    pub fn scrub(
        &self,
        cx: &Cx,
        limits: super::scrub::ScrubLimits,
    ) -> Result<super::scrub::ScrubReport> {
        self.objects.scrub(cx, limits)
    }

    fn open(
        cx: &Cx,
        mut objects: Objects,
        dataset_guid: u64,
        referenced_bytes: u64,
        zil_header: ZilHeader,
        mos: Option<(Box<Objects>, Vec<Vec<u8>>)>,
    ) -> Result<Self> {
        let master = typed_map(&mut objects, cx, 1, 21)?;
        let root = required(&master, b"ROOT")?;
        let version = required(&master, b"VERSION")?;
        let utf8 = value(&master, b"utf8only").unwrap_or(0);
        if !(1..=5).contains(&version)
            || utf8 > 1
            || value(&master, b"normalization").unwrap_or(0) != 0
            || value(&master, b"casesensitivity").unwrap_or(0) != 0
        {
            return Err(unsupported(
                "ZPL version or normalization/case policy is not implemented",
            ));
        }
        let registry = if let Some(number) = value(&master, b"SA_ATTRS").filter(|id| *id != 0) {
            if version < 5 {
                return Err(corrupt("SA registry on a pre-SA ZPL version"));
            }
            let sa = typed_map(&mut objects, cx, number, 45)?;
            let registry = required(&sa, b"REGISTRY")?;
            let layouts = required(&sa, b"LAYOUTS")?;
            if registry == 0
                || layouts == 0
                || registry == layouts
                || objects.object(cx, registry)?.object_type() != 46
                || objects.object(cx, layouts)?.object_type() != 47
            {
                return Err(corrupt("invalid SA registry/layout object identities"));
            }
            Some(
                SaRegistry::from_zaps(
                    &objects.zap_values(cx, registry)?,
                    &objects.zap_values(cx, layouts)?,
                )
                .map_err(|error| parse(&error))?,
            )
        } else {
            None
        };
        let mut zpl = Self {
            objects,
            root,
            dataset_guid,
            version,
            registry,
            utf8_only: utf8 != 0,
            referenced_bytes,
            zil_header,
            zil_overlay: None,
            mos,
        };
        let (_, metadata) = zpl.file(cx, root)?;
        if metadata.kind != Kind::Directory || metadata.parent != root {
            return Err(corrupt("ZPL ROOT is not a self-parented directory"));
        }
        checkpoint(cx)?;
        Ok(zpl)
    }

    #[cfg(test)]
    #[must_use]
    pub fn zil_replay_stats(&self) -> Option<&ZilReplayStats> {
        self.zil_overlay.as_ref().map(|ov| &ov.stats)
    }

    /// Replay the ZIL intent-log chain (`zh_log`) into an in-memory ZPL overlay.
    pub fn replay_zil(&mut self, cx: &Cx) -> Result<ZilReplayStats> {
        checkpoint(cx)?;
        let (mos, components) = self
            .mos
            .as_mut()
            .ok_or_else(|| unsupported("ZIL replay requires a selected filesystem head"))?;
        let log = mos.intent_log(cx, components)?;
        if log.dataset_guid != self.dataset_guid
            || log.selected_txg != self.objects.txg
            || log.header.claim_txg != self.zil_header.claim_txg
            || log.header.replay_sequence != self.zil_header.replay_seq
        {
            return Err(corrupt("ZIL selection differs from its ZPL owner"));
        }
        // Native zil_check_log_chain accepts an unclaimed checksum-invalid
        // terminal LWB. The scanner distinguishes that from I/O/cancellation,
        // malformed verified records and a damaged claimed chain.
        let mut records = Vec::new();
        for (index, record) in log
            .records
            .iter()
            .enumerate()
            .filter(|(_, record)| record.pending)
        {
            records.push((
                index,
                zil_records::verified(cx, record.bytes(), record.order())?,
            ));
        }
        let plan = zil::indirect::Plan::for_namespace(cx, &log.records)?;
        let mut data = plan.load_all(cx, &self.objects)?;
        let mut overlay = ZilOverlay {
            stats: ZilReplayStats {
                blocks_visited: log.verified_blocks,
                unverified_tail: log.termination == zil::Termination::UnverifiedTail,
                ..ZilReplayStats::default()
            },
            ..ZilOverlay::default()
        };
        for (index, record) in records {
            checkpoint(cx)?;
            let write = if matches!(&record.payload, ZilRecordPayload::Write { .. }) {
                Some(zil::indirect::take_write(
                    &log.records[index],
                    index,
                    &mut data,
                )?)
            } else {
                None
            };
            self.apply_zil_record(cx, &mut overlay, &record.payload, write)?;
            overlay.stats.records_replayed += 1;
            overlay.stats.last_txg = overlay.stats.last_txg.max(record.txg);
            overlay.stats.last_seq = record.seq;
        }
        let stats = overlay.stats.clone();
        checkpoint(cx)?;
        self.zil_overlay = Some(overlay);
        Ok(stats)
    }

    fn ensure_overlay_metadata(
        &mut self,
        cx: &Cx,
        overlay: &mut ZilOverlay,
        object_id: u64,
    ) -> Result<Metadata> {
        checkpoint(cx)?;
        if overlay.removed_objects.contains(&object_id) {
            return Err(FfsError::NotFound(format!(
                "ZFS object {object_id} removed in ZIL"
            )));
        }
        if let Some(meta) = overlay.objects.get(&object_id) {
            return Ok(meta.clone());
        }
        let (_, meta) = self.committed_file(cx, object_id, false)?;
        overlay.objects.insert(object_id, meta.clone());
        Ok(meta)
    }

    fn apply_file_edit(
        &mut self,
        cx: &Cx,
        overlay: &mut ZilOverlay,
        object_id: u64,
        edit: OwnedEdit,
    ) -> Result<()> {
        let mut meta = self.ensure_overlay_metadata(cx, overlay, object_id)?;
        if meta.kind != Kind::Regular {
            return Err(unsupported("ZIL data edit requires a regular file"));
        }
        let original_size = meta.size;
        meta.size = edit.borrowed().size_after(meta.size);
        let file = overlay.file_edits.entry(object_id).or_insert_with(|| {
            Arc::new(RecoveredFile {
                original_size,
                edits: Vec::new(),
            })
        });
        Arc::make_mut(file).edits.push(edit);
        overlay.objects.insert(object_id, meta);
        Ok(())
    }

    fn staged_directory(
        &mut self,
        cx: &Cx,
        overlay: &mut ZilOverlay,
        number: u64,
    ) -> Result<BTreeMap<Vec<u8>, u64>> {
        if self.ensure_overlay_metadata(cx, overlay, number)?.kind != Kind::Directory {
            return Err(FfsError::NotDirectory);
        }
        let mut entries = BTreeMap::new();
        if !overlay.created.contains(&number) {
            for entry in self.objects.zap(cx, number)? {
                checkpoint(cx)?;
                self.component(&entry.name)?;
                let (object, tag) =
                    directory_reference(entry.value).map_err(|error| parse(&error))?;
                // A tombstone/replacement takes precedence even over a retired
                // base object: do not read a superseded reference.
                if overlay
                    .dir_entries
                    .get(&number)
                    .is_some_and(|changes| changes.contains_key(&entry.name))
                {
                    continue;
                }
                let meta = self.ensure_overlay_metadata(cx, overlay, object)?;
                if tag.is_some_and(|kind| kind != meta.kind) {
                    return Err(corrupt("ZIL base directory tag disagrees with its target"));
                }
                entries.insert(entry.name, object);
            }
        }
        if let Some(changes) = overlay.dir_entries.get(&number) {
            for (name, target) in changes {
                if let Some(object) = target {
                    entries.insert(name.clone(), *object);
                } else {
                    entries.remove(name);
                }
            }
        }
        let mut bytes = 0_usize;
        let mut directories = BTreeSet::new();
        for (name, object) in &entries {
            checkpoint(cx)?;
            self.component(name)?;
            let meta = self.ensure_overlay_metadata(cx, overlay, *object)?;
            if meta.kind == Kind::Directory
                && (*object == self.root
                    || *object == number
                    || meta.parent != number
                    || !directories.insert(*object))
            {
                return Err(corrupt("ZIL directory contains an alias or foreign parent"));
            }
            bytes = bytes
                .checked_add(name.len() + std::mem::size_of::<DirectoryEntry>())
                .filter(|bytes| *bytes <= MAX_DIRECTORY_BYTES)
                .ok_or_else(|| unsupported("ZIL directory exceeds 32 MiB"))?;
        }
        checkpoint(cx)?;
        Ok(entries)
    }

    fn adjust_directory(
        &mut self,
        cx: &Cx,
        overlay: &mut ZilOverlay,
        number: u64,
        entries: i64,
        links: i64,
    ) -> Result<()> {
        let mut meta = self.ensure_overlay_metadata(cx, overlay, number)?;
        if meta.kind != Kind::Directory {
            return Err(FfsError::NotDirectory);
        }
        meta.size = meta
            .size
            .checked_add_signed(entries)
            .filter(|size| *size >= 2)
            .ok_or_else(|| corrupt("ZIL directory size underflow/overflow"))?;
        meta.links = meta
            .links
            .checked_add_signed(links)
            .filter(|links| *links >= 2)
            .ok_or_else(|| corrupt("ZIL directory links underflow/overflow"))?;
        overlay.objects.insert(number, meta);
        Ok(())
    }

    fn remove_entry(
        &mut self,
        cx: &Cx,
        overlay: &mut ZilOverlay,
        dir: u64,
        name: &[u8],
        is_dir: bool,
    ) -> Result<()> {
        self.component(name)?;
        let target = self
            .staged_directory(cx, overlay, dir)?
            .get(name)
            .copied()
            .ok_or_else(|| FfsError::NotFound("ZIL removal target".into()))?;
        if target == self.root {
            return Err(corrupt("ZIL cannot remove the root directory"));
        }
        let mut meta = self.ensure_overlay_metadata(cx, overlay, target)?;
        if (meta.kind == Kind::Directory) != is_dir {
            return Err(corrupt("ZIL remove/rmdir disagrees with target kind"));
        }
        if is_dir && !self.staged_directory(cx, overlay, target)?.is_empty() {
            return Err(corrupt("ZIL rmdir target is not empty"));
        }
        self.adjust_directory(cx, overlay, dir, -1, -i64::from(is_dir))?;
        overlay
            .dir_entries
            .entry(dir)
            .or_default()
            .insert(name.to_vec(), None);
        meta.links = if is_dir {
            0
        } else {
            meta.links
                .checked_sub(1)
                .ok_or_else(|| corrupt("ZIL file links underflow"))?
        };
        if meta.links == 0 {
            overlay.removed_objects.insert(target);
            overlay.objects.remove(&target);
            overlay.file_edits.remove(&target);
        } else {
            overlay.objects.insert(target, meta);
        }
        Ok(())
    }

    fn rename_entry(
        &mut self,
        cx: &Cx,
        overlay: &mut ZilOverlay,
        src: u64,
        dst: u64,
        from: &[u8],
        to: &[u8],
    ) -> Result<()> {
        self.component(from)?;
        self.component(to)?;
        let source = self
            .staged_directory(cx, overlay, src)?
            .get(from)
            .copied()
            .ok_or_else(|| FfsError::NotFound("ZIL rename source".into()))?;
        let destination = self.staged_directory(cx, overlay, dst)?.get(to).copied();
        if destination == Some(source) {
            return Ok(()); // Native rename of one name/hardlink onto itself.
        }
        let mut meta = self.ensure_overlay_metadata(cx, overlay, source)?;
        let directory = meta.kind == Kind::Directory;
        if source == self.root {
            return Err(corrupt("ZIL cannot rename the root directory"));
        }
        if directory {
            let mut parent = dst;
            let mut visited = BTreeSet::new();
            loop {
                checkpoint(cx)?;
                if parent == source || !visited.insert(parent) || visited.len() > MAX_COMPONENTS {
                    return Err(corrupt("ZIL directory rename forms a cycle"));
                }
                if parent == self.root {
                    break;
                }
                let ancestor = self.ensure_overlay_metadata(cx, overlay, parent)?;
                if ancestor.kind != Kind::Directory {
                    return Err(corrupt("ZIL directory ancestry contains a non-directory"));
                }
                parent = ancestor.parent;
            }
        }
        if let Some(target) = destination {
            if (self.ensure_overlay_metadata(cx, overlay, target)?.kind == Kind::Directory)
                != directory
            {
                return Err(corrupt("ZIL rename replacement changes directory kind"));
            }
            self.remove_entry(cx, overlay, dst, to, directory)?;
        }
        self.adjust_directory(cx, overlay, src, -1, -i64::from(directory))?;
        self.adjust_directory(cx, overlay, dst, 1, i64::from(directory))?;
        overlay
            .dir_entries
            .entry(src)
            .or_default()
            .insert(from.to_vec(), None);
        overlay
            .dir_entries
            .entry(dst)
            .or_default()
            .insert(to.to_vec(), Some(source));
        meta.parent = dst;
        overlay.objects.insert(source, meta);
        Ok(())
    }

    fn apply_zil_record(
        &mut self,
        cx: &Cx,
        overlay: &mut ZilOverlay,
        payload: &ZilRecordPayload,
        write: Option<OwnedEdit>,
    ) -> Result<()> {
        match payload {
            ZilRecordPayload::Create {
                dir_obj,
                file_obj,
                mode,
                uid,
                gid,
                generation,
                crtime,
                name,
                symlink_target,
                is_dir,
            } => {
                self.component(name)?;
                if *file_obj == 0
                    || *file_obj >= 1_u64 << 48
                    || *generation == 0
                    || crtime[1] >= 1_000_000_000
                {
                    return Err(corrupt("invalid ZIL create identity, generation or time"));
                }
                if self
                    .staged_directory(cx, overlay, *dir_obj)?
                    .contains_key(name)
                {
                    return Err(corrupt("ZIL create name already exists"));
                }
                if !overlay.removed_objects.contains(file_obj) {
                    if overlay.objects.contains_key(file_obj) {
                        return Err(corrupt("ZIL create reuses a live object"));
                    }
                    match self.committed_file(cx, *file_obj, false) {
                        Err(FfsError::NotFound(_)) => {}
                        Err(error) => return Err(error),
                        Ok(_) => return Err(corrupt("ZIL create reuses a committed live object")),
                    }
                }
                let kind = if symlink_target.is_some() && (*mode & 0o170_000) == 0o120_000 {
                    Kind::Symlink
                } else if *is_dir && (*mode & 0o170_000) == 0o040_000 {
                    Kind::Directory
                } else if !is_dir && symlink_target.is_none() && (*mode & 0o170_000) == 0o100_000 {
                    Kind::Regular
                } else {
                    return Err(unsupported("ZIL plain create kind/mode is not implemented"));
                };
                let size = symlink_target
                    .as_ref()
                    .map_or(if *is_dir { 2 } else { 0 }, |t| t.len() as u64);
                let ts = ffs_ondisk::zfs_zpl::Timestamp {
                    seconds: i64::from_le_bytes(crtime[0].to_le_bytes()),
                    nanos: crtime[1] as u32,
                };
                let meta = Metadata {
                    mode: (*mode) & 0o7777,
                    kind,
                    uid: *uid,
                    gid: *gid,
                    size,
                    links: if *is_dir { 2 } else { 1 },
                    parent: *dir_obj,
                    flags: 0,
                    generation: *generation,
                    times: [ts, ts, ts, ts],
                    inline_symlink: symlink_target.clone(),
                };
                overlay.removed_objects.remove(file_obj);
                overlay.created.insert(*file_obj);
                overlay.dir_entries.remove(file_obj);
                overlay.file_edits.remove(file_obj);
                self.adjust_directory(cx, overlay, *dir_obj, 1, i64::from(*is_dir))?;
                overlay.objects.insert(*file_obj, meta);
                overlay
                    .dir_entries
                    .entry(*dir_obj)
                    .or_default()
                    .insert(name.clone(), Some(*file_obj));
                if kind == Kind::Regular {
                    overlay.file_edits.insert(
                        *file_obj,
                        Arc::new(RecoveredFile {
                            original_size: 0,
                            edits: Vec::new(),
                        }),
                    );
                }
            }
            ZilRecordPayload::Remove {
                dir_obj,
                name,
                is_dir,
            } => {
                self.remove_entry(cx, overlay, *dir_obj, name, *is_dir)?;
            }
            ZilRecordPayload::Rename {
                src_dir_obj,
                dst_dir_obj,
                src_name,
                dst_name,
            } => {
                self.rename_entry(cx, overlay, *src_dir_obj, *dst_dir_obj, src_name, dst_name)?;
            }
            ZilRecordPayload::Write { file_obj, .. } => {
                let edit = write.ok_or_else(|| corrupt("ZIL write was not admitted"))?;
                // Native writes may be logged after the target was unlinked.
                // Only ENOENT is ignorable, never read/parse/cancel errors.
                if let Err(error) = self.apply_file_edit(cx, overlay, *file_obj, edit)
                    && !matches!(error, FfsError::NotFound(_))
                {
                    return Err(error);
                }
            }
            ZilRecordPayload::Truncate {
                file_obj,
                offset,
                length,
            } => {
                let edit = if *length == 0 {
                    OwnedEdit::Truncate {
                        object: *file_obj,
                        size: *offset,
                    }
                } else {
                    OwnedEdit::Free {
                        object: *file_obj,
                        offset: *offset,
                        end: offset + length,
                    }
                };
                self.apply_file_edit(cx, overlay, *file_obj, edit)?;
            }
            ZilRecordPayload::Setattr {
                file_obj,
                mask,
                mode,
                uid,
                gid,
                size,
                atime,
                mtime,
            } => {
                self.ensure_overlay_metadata(cx, overlay, *file_obj)?;
                if mask & 8 != 0 {
                    if *size > i64::MAX as u64 {
                        return Err(corrupt("ZIL setattr size overflows"));
                    }
                    self.apply_file_edit(
                        cx,
                        overlay,
                        *file_obj,
                        OwnedEdit::Truncate {
                            object: *file_obj,
                            size: *size,
                        },
                    )?;
                }
                if mask & 16 != 0 && atime[1] >= 1_000_000_000
                    || mask & 32 != 0 && mtime[1] >= 1_000_000_000
                {
                    return Err(corrupt("invalid ZIL setattr timestamp"));
                }
                if let Some(meta) = overlay.objects.get_mut(file_obj) {
                    if mask & 1 != 0 {
                        meta.mode = (*mode) & 0o7777;
                    }
                    if mask & 2 != 0 {
                        meta.uid = *uid;
                    }
                    if mask & 4 != 0 {
                        meta.gid = *gid;
                    }
                    if mask & 8 != 0 {
                        meta.size = *size;
                    }
                    if mask & 16 != 0 {
                        meta.times[0] = ffs_ondisk::zfs_zpl::Timestamp {
                            seconds: i64::from_le_bytes(atime[0].to_le_bytes()),
                            nanos: atime[1] as u32,
                        };
                    }
                    if mask & 32 != 0 {
                        meta.times[1] = ffs_ondisk::zfs_zpl::Timestamp {
                            seconds: i64::from_le_bytes(mtime[0].to_le_bytes()),
                            nanos: mtime[1] as u32,
                        };
                    }
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub const fn has_snapshot_dir(&self) -> bool {
        self.mos.is_some()
    }

    pub fn snapshots(&mut self, cx: &Cx) -> Result<Vec<snapshots::Snapshot>> {
        let Some((mos, components)) = &mut self.mos else {
            return Ok(Vec::new());
        };
        mos.snapshots(cx, components)
    }

    pub fn open_snapshot(&mut self, cx: &Cx, name: &[u8]) -> Result<Self> {
        let Some((mos, components)) = &mut self.mos else {
            return Err(FfsError::NotFound("ZFS named snapshot".into()));
        };
        mos.zpl_snapshot(cx, components, name)
    }

    #[must_use]
    pub fn statfs_info(&self) -> ffs_core::FsStat {
        let bsize = 4096_u64;
        let total_bytes = self.objects.config.total_data_bytes();
        let used_bytes = self.referenced_bytes.max(self.objects.meta.used_bytes());
        let blocks = total_bytes / bsize;
        let bfree = total_bytes.saturating_sub(used_bytes) / bsize;
        let dnodes_per_block =
            (ffs_ondisk::zfs_dmu::DNODE_BLOCK_BYTES / ffs_ondisk::zfs_dmu::DNODE_BYTES) as u64;
        let files = self
            .objects
            .meta
            .max_block()
            .saturating_add(1)
            .saturating_mul(dnodes_per_block);
        let max_objects = 1_u64 << 48;
        let frsize = (1_u32 << self.objects.config.ashift.clamp(9, 16)).max(512);
        ffs_core::FsStat {
            blocks,
            blocks_free: bfree,
            blocks_available: bfree,
            files,
            files_free: max_objects.saturating_sub(files),
            block_size: bsize as u32,
            name_max: 255,
            fragment_size: frsize,
        }
    }

    fn file(&mut self, cx: &Cx, number: u64) -> Result<(Object, Metadata)> {
        self.file_in_namespace(cx, number, false)
    }

    fn sa_attributes(&mut self, cx: &Cx, object: &Object) -> Result<Attributes> {
        let node = &object.node;
        let spill = if let Some(bp) = node.spill() {
            if bp.logical_bytes() > SA_BYTES {
                return Err(unsupported("SA spill exceeds 128 KiB"));
            }
            Some(
                self.objects
                    .checked(cx, bp, 44, 0, bp.logical_bytes(), object.ceiling)?
                    .ok_or_else(|| corrupt("SA spill pointer is a hole"))?,
            )
        } else {
            None
        };
        self.registry
            .as_ref()
            .ok_or_else(|| corrupt("SA file has no dataset registry"))?
            .decode(
                node.bonus(),
                spill.as_ref().map(|block| block.bytes.as_slice()),
            )
            .map_err(|error| parse(&error))
    }

    fn file_in_namespace(
        &mut self,
        cx: &Cx,
        number: u64,
        private_xattr: bool,
    ) -> Result<(Object, Metadata)> {
        checkpoint(cx)?;
        if number == 0 {
            return Err(corrupt("meta-dnode is not a ZPL file"));
        }
        if !private_xattr && let Some(ov) = &self.zil_overlay {
            if ov.removed_objects.contains(&number) {
                return Err(FfsError::NotFound(format!(
                    "ZFS object {number} removed in ZIL"
                )));
            }
            if let Some(meta) = ov.objects.get(&number).cloned() {
                let object = if ov.created.contains(&number) {
                    Object {
                        node: self.objects.meta.clone(),
                        ceiling: self.objects.root_birth,
                    }
                } else {
                    self.objects.load(cx, number)?
                };
                checkpoint(cx)?;
                return Ok((object, meta));
            }
        }
        self.committed_file(cx, number, private_xattr)
    }

    fn committed_file(
        &mut self,
        cx: &Cx,
        number: u64,
        private_xattr: bool,
    ) -> Result<(Object, Metadata)> {
        checkpoint(cx)?;
        if number == 0 {
            return Err(corrupt("meta-dnode is not a ZPL file"));
        }
        let object = self.objects.load(cx, number)?;
        let node = &object.node;
        if !matches!(node.object_type(), 19 | 20) {
            return Err(unsupported("object is not ZPL file or directory content"));
        }
        let metadata = match node.bonus_type() {
            17 => {
                if node.spill().is_some() {
                    return Err(corrupt("legacy znode has an SA spill pointer"));
                }
                Metadata::legacy(node.bonus(), node.order()).map_err(|error| parse(&error))?
            }
            44 => self
                .sa_attributes(cx, &object)?
                .metadata()
                .map_err(|error| parse(&error))?,
            _ => return Err(unsupported("unknown ZPL bonus representation")),
        };
        if (metadata.kind == Kind::Directory) != (node.object_type() == 20)
            || metadata.generation > object.ceiling
            || metadata.generation > self.objects.txg
            || metadata.links == 0
        {
            return Err(corrupt(
                "ZPL kind, creation generation or live link count is inconsistent",
            ));
        }
        if metadata.flags & ((1 << 43) | (1 << 44)) != 0 {
            return Err(unsupported("reparse or offline ZPL object"));
        }
        // Only the checked owner -> xattr directory -> value traversal may
        // enter the private namespace. Ordinary lookup/stat/read cannot do so.
        if (metadata.flags & 1 != 0) != private_xattr {
            return Err(if private_xattr {
                corrupt("xattr reference targets an ordinary ZPL object")
            } else {
                unsupported("private xattr object is not ordinary file content")
            });
        }
        if metadata.kind == Kind::Directory && number != self.root && metadata.parent == number {
            return Err(corrupt("non-root ZPL directory is self-parented"));
        }
        if metadata.kind == Kind::Symlink
            && node.bonus_type() == 44
            && metadata.inline_symlink.is_none()
        {
            return Err(corrupt("SA symlink has no native symlink attribute"));
        }
        checkpoint(cx)?;
        Ok((object, metadata))
    }

    pub fn stat(&mut self, cx: &Cx, number: u64) -> Result<(Metadata, u64)> {
        let (object, metadata) = self.file(cx, number)?;
        let used =
            if self.zil_overlay.as_ref().is_some_and(|ov| {
                ov.file_edits.contains_key(&number) || ov.created.contains(&number)
            }) {
                metadata
                    .size
                    .checked_next_multiple_of(512)
                    .ok_or_else(|| corrupt("ZIL reported file allocation overflows"))?
            } else {
                object.node.used_bytes()
            };
        Ok((metadata, used))
    }

    fn component(&self, name: &[u8]) -> Result<()> {
        if name.is_empty()
            || name.len() > 255
            || name == b"."
            || name == b".."
            || name.contains(&0)
            || name.contains(&b'/')
        {
            return Err(corrupt("invalid ZPL directory component"));
        }
        if self.utf8_only && std::str::from_utf8(name).is_err() {
            return Err(corrupt("non-UTF8 name on a UTF8-only ZPL dataset"));
        }
        Ok(())
    }

    /// Complete admitted directory snapshot. No partial list escapes if a later
    /// target is corrupt. File hard links may have another stored parent; directory
    /// parents, however, must identify this exact directory.
    pub fn list(&mut self, cx: &Cx, number: u64) -> Result<Vec<DirectoryEntry>> {
        let (_, parent) = self.file(cx, number)?;
        if parent.kind != Kind::Directory {
            return Err(FfsError::NotDirectory);
        }
        let entries = if self
            .zil_overlay
            .as_ref()
            .is_some_and(|ov| ov.created.contains(&number))
        {
            Vec::new()
        } else {
            self.objects.zap(cx, number)?
        };
        let dir_overrides = self
            .zil_overlay
            .as_ref()
            .and_then(|ov| ov.dir_entries.get(&number))
            .cloned();
        let mut result = Vec::new();
        let mut directories = BTreeSet::new();
        let mut seen_names = BTreeSet::new();
        let mut bytes = 0_usize;
        for entry in entries {
            checkpoint(cx)?;
            if let Some(overrides) = &dir_overrides
                && let Some(override_target) = overrides.get(&entry.name)
            {
                seen_names.insert(entry.name.clone());
                let Some(object) = *override_target else {
                    continue;
                };
                self.component(&entry.name)?;
                let (_, metadata) = self.file(cx, object)?;
                if metadata.kind == Kind::Directory
                    && (object == self.root
                        || object == number
                        || metadata.parent != number
                        || !directories.insert(object))
                {
                    return Err(corrupt("ZPL directory contains an alias or foreign parent"));
                }
                bytes += std::mem::size_of::<DirectoryEntry>()
                    + entry.name.len()
                    + metadata.inline_symlink.as_ref().map_or(0, Vec::len);
                if bytes > MAX_DIRECTORY_BYTES {
                    return Err(unsupported("ZPL directory result exceeds 32 MiB"));
                }
                result.push(DirectoryEntry {
                    name: entry.name,
                    object,
                    metadata,
                });
                continue;
            }
            self.component(&entry.name)?;
            let (object, tag) = directory_reference(entry.value).map_err(|error| parse(&error))?;
            let (_, metadata) = self.file(cx, object)?;
            if tag.is_some_and(|kind| kind != metadata.kind) {
                return Err(corrupt("ZPL directory tag disagrees with target mode"));
            }
            if metadata.kind == Kind::Directory
                && (object == self.root
                    || object == number
                    || metadata.parent != number
                    || !directories.insert(object))
            {
                return Err(corrupt("ZPL directory contains an alias or foreign parent"));
            }
            bytes += std::mem::size_of::<DirectoryEntry>()
                + entry.name.len()
                + metadata.inline_symlink.as_ref().map_or(0, Vec::len);
            if bytes > MAX_DIRECTORY_BYTES {
                return Err(unsupported("ZPL directory result exceeds 32 MiB"));
            }
            result.push(DirectoryEntry {
                name: entry.name,
                object,
                metadata,
            });
        }
        if let Some(overrides) = dir_overrides {
            for (name, target_opt) in overrides {
                if seen_names.contains(&name) {
                    continue;
                }
                let Some(object) = target_opt else {
                    continue;
                };
                self.component(&name)?;
                let (_, metadata) = self.file(cx, object)?;
                if metadata.kind == Kind::Directory
                    && (object == self.root
                        || object == number
                        || metadata.parent != number
                        || !directories.insert(object))
                {
                    return Err(corrupt("ZPL directory contains an alias or foreign parent"));
                }
                bytes += std::mem::size_of::<DirectoryEntry>()
                    + name.len()
                    + metadata.inline_symlink.as_ref().map_or(0, Vec::len);
                if bytes > MAX_DIRECTORY_BYTES {
                    return Err(unsupported("ZPL directory result exceeds 32 MiB"));
                }
                result.push(DirectoryEntry {
                    name,
                    object,
                    metadata,
                });
            }
        }
        checkpoint(cx)?;
        Ok(result)
    }

    fn contents(
        &mut self,
        cx: &Cx,
        number: u64,
        object: &Object,
        file_size: u64,
        start: u64,
        size: usize,
    ) -> Result<Vec<u8>> {
        checkpoint(cx)?;
        if size > MAX_READ_BYTES {
            return Err(unsupported("ZPL read exceeds 16 MiB"));
        }
        let length = file_size.saturating_sub(start).min(size as u64) as usize;
        if let Some(file) = self
            .zil_overlay
            .as_ref()
            .and_then(|ov| ov.file_edits.get(&number))
            .cloned()
        {
            let edits: Vec<_> = file.edits.iter().map(OwnedEdit::borrowed).collect();
            return zil::recovery::read(
                cx,
                file.original_size,
                start,
                length,
                &edits,
                |at, count| self.committed_contents(cx, object, file.original_size, at, count),
            );
        }
        self.committed_contents(cx, object, file_size, start, length)
    }

    fn committed_contents(
        &mut self,
        cx: &Cx,
        object: &Object,
        file_size: u64,
        start: u64,
        size: usize,
    ) -> Result<Vec<u8>> {
        checkpoint(cx)?;
        let length = file_size.saturating_sub(start).min(size as u64) as usize;
        let mut result = Vec::new();
        result
            .try_reserve_exact(length)
            .map_err(|error| FfsError::Io(std::io::Error::other(error)))?;
        result.resize(length, 0);
        let block_bytes = object.node.data_bytes() as u64;
        let mut done = 0;
        while done < length {
            checkpoint(cx)?;
            let logical = start + done as u64;
            let id = logical / block_bytes;
            let within = (logical % block_bytes) as usize;
            let count = (length - done).min(object.node.data_bytes() - within);
            // EOF is ZPL_SIZE, not dn_maxblkid: a sparse file may end arbitrarily
            // far past its last allocated block. No dnode route is invented there.
            if id <= object.node.max_block()
                && let Some(block) = self.objects.data_block(cx, object, id)?
            {
                result[done..done + count].copy_from_slice(&block.bytes[within..within + count]);
            }
            done += count;
        }
        checkpoint(cx)?;
        Ok(result)
    }

    pub fn read(&mut self, cx: &Cx, number: u64, start: u64, size: usize) -> Result<Vec<u8>> {
        if size > MAX_READ_BYTES {
            return Err(unsupported("ZPL read exceeds 16 MiB"));
        }
        let (object, metadata) = self.file(cx, number)?;
        if metadata.kind == Kind::Directory {
            return Err(FfsError::IsDirectory);
        }
        if metadata.kind != Kind::Regular {
            return Err(unsupported(
                "read requires a regular ZPL file; links are not followed",
            ));
        }
        self.contents(cx, number, &object, metadata.size, start, size)
    }

    pub fn readlink(&mut self, cx: &Cx, number: u64) -> Result<Vec<u8>> {
        let (object, metadata) = self.file(cx, number)?;
        if metadata.kind != Kind::Symlink {
            return Err(unsupported("object is not a ZPL symlink"));
        }
        if metadata.size > MAX_PATH as u64 {
            return Err(FfsError::NameTooLong);
        }
        let bytes = if let Some(bytes) = metadata.inline_symlink {
            bytes
        } else {
            self.contents(
                cx,
                number,
                &object,
                metadata.size,
                0,
                metadata.size as usize,
            )?
        };
        if bytes.contains(&0) {
            return Err(corrupt("ZPL symlink target contains NUL"));
        }
        checkpoint(cx)?;
        Ok(bytes)
    }
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
