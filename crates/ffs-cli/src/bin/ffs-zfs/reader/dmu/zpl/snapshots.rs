//! Native named snapshot inventory and immutable historical ZPL views.
//! Names are resolved through the selected head's snapnames ZAP and checked
//! against its predecessor chain. No rewind, clone traversal, replay or writes.

use super::{
    BlockPointer, Cx, FfsError, Object, ObjectSet, Objects, Result, VecDeque, Zpl, checkpoint,
    corrupt, parse, unsupported,
};
use ffs_ondisk::zfs_zap::names::NamePolicy;
use std::collections::{BTreeMap, BTreeSet};

const MAX_SNAPSHOTS: usize = 4096;
const MAX_SNAPSHOT_NAMES: usize = 1024 * 1024;

impl Zpl {
    /// Pool candidate TXG for heads; native creation TXG for snapshot views.
    #[must_use]
    pub const fn view_txg(&self) -> u64 {
        self.objects.txg
    }
}

#[derive(Debug, Clone)]
pub struct Snapshot {
    /// Stored name, not an uppercase alias or a host path.
    pub name: Vec<u8>,
    pub object: u64,
    pub guid: u64,
    pub creation_txg: u64,
    pub creation_time: u64,
    pub referenced_bytes: u64,
    pub flags: u64,
    pub root_birth: u64,
    pub objectset_kind: u64,
}

struct SnapshotRoot {
    info: Snapshot,
    root: BlockPointer,
}

struct Record {
    directory: u64,
    previous: u64,
    previous_txg: u64,
    next: u64,
    names: u64,
    children: u64,
    creation_time: u64,
    creation_txg: u64,
    referenced_bytes: u64,
    guid: u64,
    flags: u64,
    next_clones: u64,
    root: BlockPointer,
    ceiling: u64,
}

impl Record {
    fn parse(object: &Object, txg: u64) -> Result<Self> {
        let node = &object.node;
        if node.bonus_type() != 16
            || node.bonus().len() != 320
            || node.spill().is_some()
            || !matches!(node.object_type(), 16 | 196)
        {
            return Err(unsupported(
                "snapshot lineage requires a native DSL dataset bonus",
            ));
        }
        let word = |at| {
            node.order()
                .u64(node.bonus(), at)
                .map_err(|error| parse(&error))
        };
        let result = Self {
            directory: word(0)?,
            previous: word(8)?,
            previous_txg: word(16)?,
            next: word(24)?,
            names: word(32)?,
            children: word(40)?,
            creation_time: word(48)?,
            creation_txg: word(56)?,
            referenced_bytes: word(72)?,
            guid: word(112)?,
            flags: word(120)?,
            next_clones: word(256)?,
            root: BlockPointer::parse(&node.bonus()[128..256], node.order())
                .map_err(|error| parse(&error))?,
            ceiling: object.ceiling,
        };
        if result.directory == 0
            || result.guid == 0
            || result.creation_txg == 0
            || result.creation_txg > txg
            || result.creation_txg > object.ceiling
            || result.previous_txg > txg
            || (result.previous == 0) != (result.previous_txg == 0)
        {
            return Err(corrupt(
                "invalid DSL snapshot identity or transaction bounds",
            ));
        }
        // A deferred-destroy snapshot still has readable retained data. It is
        // not permission to destroy, repair or publish anything from this reader.
        if result.flags & !0x1_000e != 0 {
            return Err(unsupported("inconsistent or unknown DSL snapshot state"));
        }
        Ok(result)
    }

    fn require_snapshot(&self) -> Result<()> {
        if self.next == 0 || self.names != 0 || self.children == 0 {
            return Err(corrupt(
                "snapshot map or lineage points to a non-snapshot dataset",
            ));
        }
        Ok(())
    }
}

fn valid_name(name: &[u8]) -> Result<()> {
    if name.is_empty()
        || name.len() > 255
        || matches!(name, b"." | b"..")
        || name
            .iter()
            .any(|byte| matches!(byte, 0 | b'/' | b'@' | b'#'))
    {
        return Err(corrupt("expected one native snapshot name component"));
    }
    Ok(())
}

impl Objects {
    /// Return all named snapshots of exactly this head, never a partly checked
    /// list. Origin snapshots belong to another namespace and are not included.
    pub fn snapshots(&mut self, cx: &Cx, components: &[Vec<u8>]) -> Result<Vec<Snapshot>> {
        Ok(self
            .snapshot_roots(cx, components)?
            .into_iter()
            .map(|row| row.info)
            .collect())
    }

    fn snapshot_roots(&mut self, cx: &Cx, components: &[Vec<u8>]) -> Result<Vec<SnapshotRoot>> {
        checkpoint(cx)?;
        let dataset = self
            .datasets(cx)?
            .into_iter()
            .find(|row| row.components == components)
            .ok_or_else(|| FfsError::NotFound("ZFS head dataset".into()))?;
        let dir = self.load(cx, dataset.directory_object)?;
        let origin = dir
            .node
            .order()
            .u64(dir.node.bonus(), 24)
            .map_err(|error| parse(&error))?;
        let head = Record::parse(&self.load(cx, dataset.head_object)?, self.txg)?;
        let owns_directory = head.directory == dataset.directory_object;
        if !owns_directory
            || head.guid != dataset.guid
            || head.next != 0
            || head.names == 0
            || head.children != 0
        {
            return Err(corrupt(
                "snapshot owner no longer matches its selected DSL head",
            ));
        }
        if !matches!(self.object(cx, head.names)?.object_type(), 14 | 196) {
            return Err(corrupt("snapshot-name map has the wrong DMU type"));
        }
        let entries = self.zap_values_with_names(cx, head.names, NamePolicy::AsciiUppercase)?;
        if entries.len() > MAX_SNAPSHOTS {
            return Err(unsupported("snapshot inventory exceeds 4096 entries"));
        }
        let mut names = BTreeMap::new();
        let mut name_bytes = 0_usize;
        for entry in entries {
            checkpoint(cx)?;
            valid_name(&entry.name)?;
            name_bytes += entry.name.len();
            if name_bytes > MAX_SNAPSHOT_NAMES {
                return Err(unsupported("snapshot name payload exceeds 1 MiB"));
            }
            let id = entry.scalar().map_err(|error| parse(&error))?;
            if id == 0
                || id == dataset.head_object
                || id == origin
                || names.insert(id, entry.name).is_some()
            {
                return Err(corrupt(
                    "snapshot names alias an object, head or foreign origin",
                ));
            }
        }
        let mut next = dataset.head_object;
        let mut previous = head.previous;
        let mut expected_txg = head.previous_txg;
        let mut newer_txg = None;
        let mut guids = BTreeSet::from([head.guid]);
        let mut result = Vec::new();
        while previous != origin {
            checkpoint(cx)?;
            if previous == 0 || result.len() >= MAX_SNAPSHOTS {
                return Err(corrupt(
                    "snapshot lineage misses its origin or exceeds the walk bound",
                ));
            }
            let name = names.remove(&previous).ok_or_else(|| {
                corrupt("snapshot chain contains a cycle or an unnamed local record")
            })?;
            let record = Record::parse(&self.load(cx, previous)?, self.txg)?;
            record.require_snapshot()?;
            if record.directory != dataset.directory_object
                || record.next != next
                || record.creation_txg != expected_txg
                || newer_txg.is_some_and(|cut| record.creation_txg >= cut)
                || !guids.insert(record.guid)
            {
                return Err(corrupt(
                    "snapshot name, owner, successor, GUID or creation order disagrees",
                ));
            }
            if !matches!(record.root.logical_bytes(), 1024 | 2048 | 4096) {
                return Err(corrupt(
                    "snapshot object-set size is outside the native profile",
                ));
            }
            let block = self
                .checked(
                    cx,
                    &record.root,
                    11,
                    0,
                    record.root.logical_bytes(),
                    record.ceiling.min(record.creation_txg),
                )?
                .ok_or_else(|| corrupt("named snapshot has a missing object-set root"))?;
            let os = ObjectSet::parse(&block.bytes, block.order).map_err(|error| parse(&error))?;
            if os.kind != dataset.objectset_kind {
                return Err(corrupt(
                    "snapshot object-set kind differs from its owning dataset",
                ));
            }
            let info = Snapshot {
                name,
                object: previous,
                guid: record.guid,
                creation_txg: record.creation_txg,
                creation_time: record.creation_time,
                referenced_bytes: record.referenced_bytes,
                flags: record.flags,
                root_birth: record.root.birth(),
                objectset_kind: os.kind,
            };
            result.push(SnapshotRoot {
                info,
                root: record.root,
            });
            newer_txg = Some(record.creation_txg);
            next = previous;
            previous = record.previous;
            expected_txg = record.previous_txg;
        }
        if !names.is_empty() {
            return Err(corrupt(
                "snapshot name map contains records absent from the local lineage",
            ));
        }
        if origin == 0 {
            if expected_txg != 0 {
                return Err(corrupt("snapshot zero-origin transaction is not zero"));
            }
        } else {
            self.check_snapshot_origin(cx, origin, next, expected_txg, newer_txg)?;
        }
        result.sort_unstable_by(|a, b| a.info.name.cmp(&b.info.name));
        checkpoint(cx)?;
        Ok(result)
    }

    /// Native new filesystems can also refer to the pool's hidden origin. Stop
    /// there, but verify the branch instead of trusting a foreign prev pointer.
    fn check_snapshot_origin(
        &mut self,
        cx: &Cx,
        origin: u64,
        next: u64,
        expected_txg: u64,
        newer_txg: Option<u64>,
    ) -> Result<()> {
        if origin == next {
            return Err(corrupt("snapshot origin aliases the local successor"));
        }
        let record = Record::parse(&self.load(cx, origin)?, self.txg)?;
        record.require_snapshot()?;
        if record.creation_txg != expected_txg
            || newer_txg.is_some_and(|cut| record.creation_txg >= cut)
        {
            return Err(corrupt(
                "snapshot origin transaction disagrees with predecessor link",
            ));
        }
        if record.next == next {
            return Ok(());
        }
        if record.children < 2 || record.next_clones == 0 {
            return Err(unsupported(
                "snapshot origin branch lacks a native next-clones catalog",
            ));
        }
        if !matches!(self.object(cx, record.next_clones)?.object_type(), 37 | 196) {
            return Err(corrupt(
                "snapshot origin next-clones catalog has the wrong type",
            ));
        }
        let branches = self.zap(cx, record.next_clones)?;
        if branches.len() > MAX_SNAPSHOTS || branches.len() as u64 + 1 != record.children {
            return Err(corrupt(
                "snapshot origin child count disagrees with next-clones map",
            ));
        }
        let mut found = false;
        for branch in branches {
            checkpoint(cx)?;
            if branch.value == 0
                || branch.value == origin
                || branch.value == record.next
                || branch.name != format!("{:x}", branch.value).as_bytes()
            {
                return Err(corrupt("noncanonical snapshot origin branch identity"));
            }
            found |= branch.value == next;
        }
        if !found {
            return Err(corrupt(
                "snapshot lineage is absent from its origin's branch map",
            ));
        }
        checkpoint(cx)
    }

    /// Exact stored-name selection, not case-folded alias selection. A missing
    /// snapshot is an error; never fall back to current head bytes or rewind TXG.
    pub fn zpl_snapshot(&mut self, cx: &Cx, components: &[Vec<u8>], name: &[u8]) -> Result<Zpl> {
        valid_name(name)?;
        let selected = self
            .snapshot_roots(cx, components)?
            .into_iter()
            .find(|row| row.info.name == name)
            .ok_or_else(|| FfsError::NotFound("ZFS named snapshot".into()))?;
        if selected.info.objectset_kind != 2 || selected.info.flags & 0x1_0000 != 0 {
            return Err(unsupported(
                "ZPL snapshot reads require a case-sensitive filesystem",
            ));
        }
        let block = self
            .checked(
                cx,
                &selected.root,
                11,
                0,
                selected.root.logical_bytes(),
                selected.info.creation_txg,
            )?
            .ok_or_else(|| corrupt("selected snapshot object set is a hole"))?;
        let os = ObjectSet::parse(&block.bytes, block.order).map_err(|error| parse(&error))?;
        let view = Self {
            pool: self.pool.clone(),
            config: self.config.clone(),
            txg: selected.info.creation_txg,
            root_birth: selected.root.birth(),
            meta: os.meta,
            cache: VecDeque::new(),
            cached_bytes: 0,
        };
        Zpl::open(cx, view, selected.info.guid)
    }
}

#[cfg(test)]
mod tests;
