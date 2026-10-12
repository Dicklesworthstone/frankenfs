//! Read-only ZPL namespace and file bytes at an explicitly selected head root.
//! No host-path resolution, symlink following, log replay, mutation or mounting.

pub mod snapshots;
mod xattrs;

use super::{
    BTreeSet, BlockPointer, Cx, FfsError, MAX_READ_BYTES, Object, ObjectSet, Objects, Result,
    VecDeque, checkpoint, corrupt, parse, unsupported,
};
use ffs_ondisk::zfs_dmu::ZapEntry;
use ffs_ondisk::zfs_zpl::{Attributes, Kind, Metadata, SA_BYTES, SaRegistry, directory_reference};

const MAX_PATH: usize = 65_536;
const MAX_COMPONENTS: usize = 256;
const MAX_DIRECTORY_BYTES: usize = 32 * 1024 * 1024;

pub struct Zpl {
    objects: Objects,
    pub root: u64,
    pub dataset_guid: u64,
    pub version: u64,
    registry: Option<SaRegistry>,
    utf8_only: bool,
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
        let bp = BlockPointer::parse(&object.node.bonus()[128..256], object.node.order())
            .map_err(|error| parse(&error))?;
        let raw = self
            .checked(cx, &bp, 11, 0, bp.logical_bytes(), object.ceiling)?
            .ok_or_else(|| corrupt("ZPL head object set is a hole"))?;
        let os = ObjectSet::parse(&raw.bytes, raw.order).map_err(|error| parse(&error))?;
        if os.kind != 2 || bp.birth() != dataset.root_birth {
            return Err(corrupt("selected ZPL head identity changed"));
        }
        let view = Objects {
            pool: self.pool.clone(),
            config: self.config.clone(),
            txg: self.txg,
            root_birth: bp.birth(),
            meta: os.meta,
            cache: VecDeque::new(),
            cached_bytes: 0,
        };
        Zpl::open(cx, view, dataset.guid)
    }
}

impl Zpl {
    fn open(cx: &Cx, mut objects: Objects, dataset_guid: u64) -> Result<Self> {
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
        };
        let (_, metadata) = zpl.file(cx, root)?;
        if metadata.kind != Kind::Directory || metadata.parent != root {
            return Err(corrupt("ZPL ROOT is not a self-parented directory"));
        }
        checkpoint(cx)?;
        Ok(zpl)
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
        Ok((metadata, object.node.used_bytes()))
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
        let entries = self.objects.zap(cx, number)?;
        let mut result = Vec::new();
        let mut directories = BTreeSet::new();
        let mut bytes = 0_usize;
        for entry in entries {
            checkpoint(cx)?;
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
        checkpoint(cx)?;
        Ok(result)
    }

    pub fn resolve(&mut self, cx: &Cx, path: &[u8]) -> Result<u64> {
        checkpoint(cx)?;
        if path.len() > MAX_PATH || path.contains(&0) {
            return Err(FfsError::NameTooLong);
        }
        let mut current = self.root;
        let mut kind = Kind::Directory;
        let mut ancestors = BTreeSet::from([self.root]);
        let mut count = 0;
        for component in path
            .split(|byte| *byte == b'/')
            .filter(|part| !part.is_empty())
        {
            checkpoint(cx)?;
            count += 1;
            if count > MAX_COMPONENTS {
                return Err(FfsError::NameTooLong);
            }
            if kind != Kind::Directory {
                return Err(FfsError::NotDirectory);
            }
            if component == b"." {
                continue;
            }
            self.component(component)?; // Parent traversal is deliberately refused.
            let entry = self
                .list(cx, current)?
                .into_iter()
                .find(|entry| entry.name == component)
                .ok_or_else(|| FfsError::NotFound("ZPL path component".into()))?;
            current = entry.object;
            kind = entry.metadata.kind;
            if kind == Kind::Directory && !ancestors.insert(current) {
                return Err(corrupt("ZPL path returns to an ancestor"));
            }
        }
        if path.last() == Some(&b'/') && kind != Kind::Directory {
            return Err(FfsError::NotDirectory);
        }
        checkpoint(cx)?;
        Ok(current)
    }

    fn contents(
        &mut self,
        cx: &Cx,
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
        self.contents(cx, &object, metadata.size, start, size)
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
            self.contents(cx, &object, metadata.size, 0, metadata.size as usize)?
        };
        if bytes.contains(&0) {
            return Err(corrupt("ZPL symlink target contains NUL"));
        }
        checkpoint(cx)?;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests;
