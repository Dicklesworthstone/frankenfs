//! Native user xattrs from SA nvlists and checked private ZPL directories.
//! OpenZFS zfs-2.3.0 zpl_xattr.c defines prefixed-name fallback and SA priority.

use super::{
    Cx, FfsError, Kind, Result, Zpl, checkpoint, corrupt, directory_reference, parse, unsupported,
};
use ffs_ondisk::zfs_zpl::{XATTR_BYTES, XATTR_COUNT, XATTR_NAME_BYTES, XattrSources};
use std::collections::{BTreeMap, BTreeSet};

const USER: &[u8] = b"user.";

fn reserved(name: &[u8]) -> bool {
    [
        b"freebsd:".as_slice(),
        b"security.",
        b"system.",
        b"trusted.",
        USER,
    ]
    .iter()
    .any(|prefix| name.starts_with(prefix))
}

/// Match the native Linux compatibility namespace, without projecting ACLs,
/// capabilities or trusted attributes through a user-readable alias.
fn user_name(raw: &[u8]) -> Result<Option<String>> {
    if raw.is_empty() || raw.len() > XATTR_NAME_BYTES || raw.contains(&0) {
        return Err(corrupt("invalid native xattr name"));
    }
    let suffix = if let Some(suffix) = raw.strip_prefix(USER) {
        if suffix.is_empty() || reserved(suffix) {
            return Ok(None);
        }
        suffix
    } else if reserved(raw) {
        return Ok(None);
    } else {
        raw
    };
    if USER.len() + suffix.len() > XATTR_NAME_BYTES {
        return Err(unsupported(
            "compatibility xattr name exceeds the host name limit",
        ));
    }
    let suffix =
        std::str::from_utf8(suffix).map_err(|_| unsupported("user xattr name is not UTF-8"))?;
    Ok(Some(format!("user.{suffix}")))
}

#[derive(Clone, Copy)]
struct ValueFile {
    object: u64,
    generation: u64,
    size: u64,
}

struct Catalog {
    inline: BTreeMap<String, Vec<u8>>,
    directory: BTreeMap<Vec<u8>, ValueFile>,
    parent: u64,
    names: Vec<String>,
}

impl Zpl {
    fn xattr_catalog(&mut self, cx: &Cx, owner: u64) -> Result<Catalog> {
        let (object, _) = self.file(cx, owner)?;
        let source = match object.node.bonus_type() {
            17 => XattrSources::legacy(object.node.bonus(), object.node.order()),
            44 => self.sa_attributes(cx, &object)?.xattrs(),
            _ => return Err(corrupt("xattr owner has an unknown bonus representation")),
        }
        .map_err(|error| parse(&error))?;
        let mut directory = BTreeMap::new();
        if source.directory != 0 {
            if source.directory == owner || source.directory == self.root {
                return Err(corrupt(
                    "xattr directory aliases its owner or the dataset root",
                ));
            }
            let (_, metadata) = self.file_in_namespace(cx, source.directory, true)?;
            if metadata.kind != Kind::Directory || metadata.parent != owner {
                return Err(corrupt("xattr directory has the wrong kind or owner"));
            }
            let entries = self.objects.zap(cx, source.directory)?;
            if entries.len() + source.inline.len() > XATTR_COUNT {
                return Err(unsupported("xattr catalog exceeds 4096 native names"));
            }
            for entry in entries {
                checkpoint(cx)?;
                // Native zfs_dirlook synthesizes dot entries; they are never
                // stored value names. SA names remain independent byte keys.
                if entry.name == b"." || entry.name == b".." {
                    return Err(corrupt("stored dot entry in private xattr directory"));
                }
                let (number, tag) =
                    directory_reference(entry.value).map_err(|error| parse(&error))?;
                let (_, metadata) = self.file_in_namespace(cx, number, true)?;
                if metadata.kind != Kind::Regular
                    || metadata.parent != source.directory
                    || tag.is_some_and(|kind| kind != Kind::Regular)
                {
                    return Err(corrupt("xattr value has the wrong kind or private parent"));
                }
                if directory
                    .insert(
                        entry.name,
                        ValueFile {
                            object: number,
                            generation: metadata.generation,
                            size: metadata.size,
                        },
                    )
                    .is_some()
                {
                    return Err(corrupt("duplicate private xattr directory name"));
                }
            }
        }
        let mut names = BTreeSet::new();
        let mut bytes = 0_usize;
        for raw in source
            .inline
            .keys()
            .map(String::as_bytes)
            .chain(directory.keys().map(Vec::as_slice))
        {
            checkpoint(cx)?;
            if let Some(name) = user_name(raw)?
                && !names.contains(&name)
            {
                bytes += name.len() + 1;
                if bytes > XATTR_BYTES {
                    return Err(unsupported("user xattr name list exceeds 64 KiB"));
                }
                names.insert(name);
            }
        }
        checkpoint(cx)?;
        Ok(Catalog {
            inline: source.inline,
            directory,
            parent: source.directory,
            names: names.into_iter().collect(),
        })
    }

    /// Complete, sorted, unique host user names. Both native representations
    /// are admitted before publishing names; attribute payloads are read on get.
    pub fn listxattr(&mut self, cx: &Cx, owner: u64) -> Result<Vec<String>> {
        Ok(self.xattr_catalog(cx, owner)?.names)
    }

    pub fn getxattr(&mut self, cx: &Cx, owner: u64, name: &str) -> Result<Option<Vec<u8>>> {
        checkpoint(cx)?;
        if name.len() > XATTR_NAME_BYTES {
            return Err(FfsError::NameTooLong);
        }
        let Some(suffix) = name.strip_prefix("user.") else {
            return Err(unsupported("only the ZPL user xattr namespace is exposed"));
        };
        if suffix.is_empty() || suffix.as_bytes().contains(&0) || reserved(suffix.as_bytes()) {
            return Err(FfsError::Format("invalid user xattr suffix".into()));
        }
        let mut catalog = self.xattr_catalog(cx, owner)?;
        // Native __zpl_xattr_user_get retries an unprefixed name only after
        // both SA and directory lookup of the prefixed name return ENODATA.
        for native in [name, suffix] {
            if let Some(bytes) = catalog.inline.remove(native) {
                checkpoint(cx)?;
                return Ok(Some(bytes));
            }
            if let Some(value) = catalog.directory.get(native.as_bytes()) {
                if value.size > XATTR_BYTES as u64 {
                    return Err(unsupported("xattr value exceeds the 64 KiB read profile"));
                }
                let (object, metadata) = self.file_in_namespace(cx, value.object, true)?;
                if metadata.kind != Kind::Regular
                    || metadata.parent != catalog.parent
                    || metadata.generation != value.generation
                    || metadata.size != value.size
                {
                    return Err(corrupt(
                        "xattr value identity changed within the selected root",
                    ));
                }
                return self
                    .contents(cx, value.object, &object, value.size, 0, value.size as usize)
                    .map(Some);
            }
        }
        checkpoint(cx)?;
        Ok(None)
    }
}
