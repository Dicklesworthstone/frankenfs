//! Native user xattrs from SA nvlists and checked private ZPL directories.
//! OpenZFS zfs-2.3.0 zpl_xattr.c defines prefixed-name fallback and SA priority.

use super::{
    Cx, FfsError, Kind, Object, Result, ZilOverlay, Zpl, checkpoint, corrupt, directory_reference,
    parse, unsupported,
};
use ffs_ondisk::zfs_zpl::{XATTR_BYTES, XATTR_COUNT, XATTR_NAME_BYTES, XattrSources};
use std::collections::{BTreeMap, BTreeSet, btree_map::Entry};

const USER: &[u8] = b"user.";
const REPLAY_XATTR_WORK_BYTES: usize = 64 * 1024 * 1024;

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

fn packed_sa_size(values: &BTreeMap<String, Vec<u8>>) -> Result<usize> {
    // Native NV_ENCODE_XDR: 12-byte nvlist header, two terminating words,
    // and each nvpair's five words plus aligned name and byte-array payload.
    let bytes = values.iter().try_fold(20_usize, |total, (name, value)| {
        total.checked_add(20 + name.len().next_multiple_of(4) + value.len().next_multiple_of(4))
    });
    bytes
        .filter(|bytes| u16::try_from(*bytes).is_ok() && values.len() <= XATTR_COUNT)
        .ok_or_else(|| unsupported("recovered SA xattr nvlist exceeds native attribute limits"))
}

fn charge_sa_work(work: &mut usize, before: usize, after: usize) -> Result<()> {
    *work = work
        .checked_add(before)
        .and_then(|bytes| bytes.checked_add(after))
        .filter(|bytes| *bytes <= REPLAY_XATTR_WORK_BYTES)
        .ok_or_else(|| unsupported("ZIL SA xattr replay exceeds 64 MiB of map work"))?;
    Ok(())
}

impl Zpl {
    fn native_xattr_sources(&mut self, cx: &Cx, object: &Object) -> Result<XattrSources> {
        match object.node.bonus_type() {
            17 => XattrSources::legacy(object.node.bonus(), object.node.order()),
            44 => self.sa_attributes(cx, object)?.xattrs(),
            _ => return Err(corrupt("xattr owner has an unknown bonus representation")),
        }
        .map_err(|error| parse(&error))
    }

    pub(super) fn replay_sa_xattr(
        &mut self,
        cx: &Cx,
        overlay: &mut ZilOverlay,
        owner: u64,
        name: &[u8],
        value: Option<&[u8]>,
    ) -> Result<()> {
        // TX_SETSAXATTR is TX_OOO: native zil_replay_log_record skips an
        // already-unallocated owner before dispatch. Only this lookup's
        // ENOENT is ignorable; a missing SA key on a live owner is an error.
        match self.ensure_overlay_metadata(cx, overlay, owner) {
            Ok(_) => {}
            Err(FfsError::NotFound(_)) => return Ok(()),
            Err(error) => return Err(error),
        }
        if user_name(name)?.is_none() {
            return Err(unsupported(
                "ZIL SA xattr replay admits only user attributes",
            ));
        }
        let name =
            std::str::from_utf8(name).map_err(|_| unsupported("ZIL SA xattr name is not UTF-8"))?;
        if self.version < 5 || self.registry.is_none() {
            return Err(unsupported(
                "ZIL SA xattr replay requires a native SA dataset",
            ));
        }
        if let Entry::Vacant(entry) = overlay.sa_xattrs.entry(owner) {
            let values = if overlay.created.contains(&owner) {
                BTreeMap::new()
            } else {
                // Replay always rebuilds from the committed root. The previous
                // published overlay must not supply this record's starting SA.
                let (object, _) = self.committed_file(cx, owner, false)?;
                if object.node.bonus_type() != 44 {
                    return Err(unsupported("ZIL SA xattr owner is not SA formatted"));
                }
                self.native_xattr_sources(cx, &object)?.inline
            };
            entry.insert(values);
        }
        let values = overlay
            .sa_xattrs
            .get_mut(&owner)
            .ok_or_else(|| corrupt("ZIL SA xattr map was not staged"))?;
        let before = packed_sa_size(values)?;
        if let Some(value) = value {
            values.insert(name.to_owned(), value.to_vec());
        } else if values.remove(name).is_none() {
            // Native zfs_replay_setsaxattr removes only the SA nvpair. It
            // neither ignores a missing key nor deletes a directory fallback.
            return Err(FfsError::NotFound("ZIL SA xattr removal target".into()));
        }
        let after = packed_sa_size(values)?;
        charge_sa_work(&mut overlay.sa_xattr_work_bytes, before, after)?;
        checkpoint(cx)
    }

    fn xattr_catalog(&mut self, cx: &Cx, owner: u64) -> Result<Catalog> {
        let (object, _) = self.file(cx, owner)?;
        let mut source = if self
            .zil_overlay
            .as_ref()
            .is_some_and(|overlay| overlay.created.contains(&owner))
        {
            // Created/reused objects have no committed SA or private xattr
            // directory. file() returns a metadata-only placeholder for them.
            XattrSources {
                directory: 0,
                inline: BTreeMap::new(),
            }
        } else {
            self.native_xattr_sources(cx, &object)?
        };
        if let Some(values) = self
            .zil_overlay
            .as_ref()
            .and_then(|overlay| overlay.sa_xattrs.get(&owner))
        {
            source.inline.clone_from(values);
        }
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
                    .contents(
                        cx,
                        value.object,
                        &object,
                        value.size,
                        0,
                        value.size as usize,
                    )
                    .map(Some);
            }
        }
        checkpoint(cx)?;
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovered_sa_maps_obey_the_native_packed_attribute_boundary() {
        // Each six-byte name consumes 28 XDR bytes before its value; the
        // nvlist adds 20. Both values independently fit DXATTR_MAX_ENTRY_SIZE.
        let mut values = BTreeMap::from([
            ("user.a".to_owned(), vec![0xA5; 32_720]),
            ("user.b".to_owned(), vec![0x5A; 32_720]),
        ]);
        assert_eq!(packed_sa_size(&values).unwrap(), 65_516);
        values.get_mut("user.b").unwrap().resize(32_736, 0);
        assert_eq!(packed_sa_size(&values).unwrap(), 65_532);
        values.get_mut("user.b").unwrap().push(0);
        assert!(
            packed_sa_size(&values).is_err(),
            "65,536 cannot fit a native u16 SA length"
        );
        values.remove("user.a");
        assert_eq!(packed_sa_size(&values).unwrap(), 32_788);
    }

    #[test]
    fn sa_replay_work_budget_has_an_exact_boundary_and_never_wraps() {
        let mut work = 64 * 1024 * 1024 - 2 * 65_535;
        charge_sa_work(&mut work, 65_535, 65_535).unwrap();
        assert_eq!(work, 64 * 1024 * 1024);
        assert!(charge_sa_work(&mut work, 0, 1).is_err());
        assert_eq!(
            work,
            64 * 1024 * 1024,
            "a refused charge must not change the budget"
        );
        for (before, after) in [(usize::MAX, 0), (0, usize::MAX)] {
            assert!(charge_sa_work(&mut work, before, after).is_err());
            assert_eq!(work, 64 * 1024 * 1024);
        }
    }
}
