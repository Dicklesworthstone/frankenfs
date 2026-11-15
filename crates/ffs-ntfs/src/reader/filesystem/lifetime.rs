//! Mount-local handles, alternate-stream identities, retained namespace entries
//! and directory cookies. None of these records claims persistent export IDs.

use super::{
    Cx, DATA, DirEntry, FfsError, FileType, InodeAttr, InodeNumber, NtfsFs, NtfsReference,
    OpenHandleOracle, OsStr, ROOT, Result, Stream, checkpoint, corrupt, reference, unsupported,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard};

const ADS_BIT: u64 = 1 << 63;
const MAX_HANDLES: usize = 65_536;
const MAX_ADS_IDENTITIES: usize = 65_536;
const MAX_RETAINED: usize = 4_096;
const MAX_COOKIE_DIRECTORIES: usize = 4_096;
const MAX_COOKIE_ENTRIES: usize = 262_144;
const MAX_COOKIE_NAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Clone)]
struct AdsIdentity {
    reference: NtfsReference,
    name: Vec<u16>,
}

#[derive(Default)]
struct DirectoryCookies {
    entries: BTreeMap<(Vec<u8>, InodeNumber), u64>,
    next: u64,
}

#[derive(Default)]
pub(super) struct NtfsLifetime {
    oracle: Option<OpenHandleOracle>,
    handles: BTreeMap<u64, InodeNumber>,
    counts: BTreeMap<InodeNumber, u64>,
    next_handle: u64,
    ads: BTreeMap<InodeNumber, AdsIdentity>,
    ads_keys: BTreeMap<(InodeNumber, Vec<u16>), InodeNumber>,
    next_ads: u64,
    retained: BTreeMap<InodeNumber, Vec<u16>>,
    directories: BTreeMap<InodeNumber, DirectoryCookies>,
}

fn locked(lifetime: &Mutex<NtfsLifetime>) -> Result<MutexGuard<'_, NtfsLifetime>> {
    lifetime
        .lock()
        .map_err(|_| FfsError::Io(std::io::Error::other("NTFS lifetime registry poisoned")))
}

fn errno(value: i32) -> FfsError {
    FfsError::Io(std::io::Error::from_raw_os_error(value))
}

pub(super) const fn is_ads_ino(ino: InodeNumber) -> bool {
    ino.0 & ADS_BIT != 0
}

/// Called only after attempting a literal native-name lookup. A real colon in
/// a native filename therefore takes precedence over this host convention.
pub(super) fn parse_ads_component(name: &str) -> Result<Option<(Vec<u16>, Vec<u16>)>> {
    let Some((base, suffix)) = name.split_once(':') else {
        return Ok(None);
    };
    let stream = if let Some((stream, kind)) = suffix.split_once(':') {
        if !kind.eq_ignore_ascii_case("$DATA") {
            return Err(unsupported("only named NTFS $DATA streams are projected"));
        }
        stream
    } else {
        suffix
    };
    if base.is_empty()
        || stream.is_empty()
        || matches!(base, "." | "..")
        || base.contains(['/', '\\', '\0'])
        || stream.contains(['/', '\\', '\0', ':'])
    {
        return Err(FfsError::Format(
            "invalid NTFS alternate stream component".into(),
        ));
    }
    let base: Vec<_> = base.encode_utf16().collect();
    let stream: Vec<_> = stream.encode_utf16().collect();
    if base.len() > 255 || stream.len() > 255 {
        return Err(FfsError::NameTooLong);
    }
    Ok(Some((base, stream)))
}

impl NtfsLifetime {
    fn register_open(&mut self, ino: InodeNumber) -> Result<u64> {
        if self.handles.len() >= MAX_HANDLES {
            return Err(errno(libc::EMFILE));
        }
        let handle = self
            .next_handle
            .checked_add(1)
            .ok_or_else(|| errno(libc::EOVERFLOW))?;
        let count = self
            .counts
            .get(&ino)
            .copied()
            .unwrap_or(0)
            .checked_add(1)
            .ok_or_else(|| errno(libc::EOVERFLOW))?;
        self.handles.insert(handle, ino);
        self.counts.insert(ino, count);
        self.next_handle = handle;
        Ok(handle)
    }

    fn release_open(&mut self, ino: InodeNumber, handle: u64) -> Result<()> {
        if self.handles.get(&handle) != Some(&ino) {
            return Err(errno(libc::EBADF));
        }
        let count = self
            .counts
            .get_mut(&ino)
            .ok_or_else(|| corrupt(0, "NTFS open handle has no lifetime count"))?;
        *count = count
            .checked_sub(1)
            .ok_or_else(|| corrupt(0, "NTFS open lifetime count underflow"))?;
        if *count == 0 {
            self.counts.remove(&ino);
        }
        self.handles.remove(&handle);
        Ok(())
    }

    fn register_ads(
        &mut self,
        base: InodeNumber,
        reference: NtfsReference,
        name: &[u16],
    ) -> Result<InodeNumber> {
        let key = (base, name.to_vec());
        if let Some(ino) = self.ads_keys.get(&key) {
            return Ok(*ino);
        }
        if self.ads.len() >= MAX_ADS_IDENTITIES {
            return Err(errno(libc::ENOSPC));
        }
        let serial = self
            .next_ads
            .checked_add(1)
            .filter(|serial| *serial < ADS_BIT)
            .ok_or_else(|| errno(libc::EOVERFLOW))?;
        let ino = InodeNumber(ADS_BIT | serial);
        self.ads.insert(
            ino,
            AdsIdentity {
                reference,
                name: name.to_vec(),
            },
        );
        self.ads_keys.insert(key, ino);
        self.next_ads = serial;
        Ok(ino)
    }

    fn retire_ads(&mut self, ino: InodeNumber) -> Result<()> {
        self.ads
            .remove(&ino)
            .ok_or_else(|| FfsError::NotFound(format!("NTFS stream inode {}", ino.0)))?;
        self.ads_keys.retain(|_, candidate| *candidate != ino);
        // Never decrement next_ads: recreating the same stream gets a fresh
        // identity even when its native attribute number is reused.
        Ok(())
    }

    fn assign_dir_cookies(&mut self, parent: InodeNumber, entries: &mut [DirEntry]) -> Result<()> {
        if !self.directories.contains_key(&parent)
            && self.directories.len() >= MAX_COOKIE_DIRECTORIES
        {
            return Err(unsupported("NTFS directory cookie table budget exceeded"));
        }
        let keys: BTreeSet<_> = entries
            .iter()
            .filter(|entry| entry.name != b"." && entry.name != b"..")
            .map(|entry| (entry.name.clone(), entry.ino))
            .collect();
        let old = self.directories.get(&parent);
        let added = keys
            .iter()
            .filter(|key| old.is_none_or(|old| !old.entries.contains_key(*key)))
            .count();
        let next = old.map_or(2, |old| old.next.max(2));
        next.checked_add(added as u64)
            .ok_or_else(|| errno(libc::EOVERFLOW))?;
        let (other_count, other_bytes) = self
            .directories
            .iter()
            .filter(|(ino, _)| **ino != parent)
            .fold((0_usize, 0_usize), |(count, bytes), (_, directory)| {
                (
                    count + directory.entries.len(),
                    bytes
                        + directory
                            .entries
                            .keys()
                            .map(|(name, _)| name.len())
                            .sum::<usize>(),
                )
            });
        if other_count + keys.len() > MAX_COOKIE_ENTRIES
            || other_bytes + keys.iter().map(|(name, _)| name.len()).sum::<usize>()
                > MAX_COOKIE_NAME_BYTES
        {
            return Err(unsupported(
                "NTFS directory cookie lifetime budget exceeded",
            ));
        }
        let directory = self.directories.entry(parent).or_default();
        directory.next = next;
        directory.entries.retain(|key, _| keys.contains(key));
        for entry in entries.iter_mut() {
            entry.offset = if entry.name == b"." {
                1
            } else if entry.name == b".." {
                2
            } else {
                *directory
                    .entries
                    .entry((entry.name.clone(), entry.ino))
                    .or_insert_with(|| {
                        directory.next += 1;
                        directory.next
                    })
            };
        }
        // FsOps pagination uses partition_point on cookies, so native index
        // order must not silently reorder existing cookies after an insertion.
        entries.sort_by_key(|entry| entry.offset);
        Ok(())
    }
}

impl NtfsFs {
    pub(super) fn install_lifetime_oracle(&self, oracle: OpenHandleOracle) {
        if let Ok(mut state) = self.lifetime.lock()
            && state.oracle.is_none()
        {
            state.oracle = Some(oracle);
        }
    }

    pub(super) fn register_open(&self, ino: InodeNumber, _flags: i32) -> Result<u64> {
        locked(&self.lifetime)?.register_open(ino)
    }

    pub(super) fn release_open(&self, ino: InodeNumber, handle: u64) -> Result<()> {
        // CREATE can be transport-owned and carry the stateless handle zero.
        if handle == 0 {
            return Ok(());
        }
        locked(&self.lifetime)?.release_open(ino, handle)
    }

    pub(super) fn pinned(&self, ino: InodeNumber) -> Result<bool> {
        let (own, candidates, oracle) = {
            let state = locked(&self.lifetime)?;
            let mut candidates = vec![ino];
            if !is_ads_ino(ino) {
                for (&stream, identity) in &state.ads {
                    if self.inode(identity.reference)? == ino {
                        candidates.push(stream);
                    }
                }
            }
            let own = candidates
                .iter()
                .any(|ino| state.counts.get(ino).copied().unwrap_or(0) != 0);
            (own, candidates, state.oracle.clone())
        };
        // The callback may reenter transport state; invoke outside our mutex.
        Ok(own || oracle.is_some_and(|oracle| candidates.into_iter().any(|ino| oracle(ino) != 0)))
    }

    /// The caller holds the exclusive operation gate, so a successful check
    /// remains valid until its following native rename and registration.
    pub(super) fn check_retained_file(&self, ino: InodeNumber, name: &[u16]) -> Result<()> {
        if is_ads_ino(ino) || ino == ROOT || name.is_empty() || name.len() > 255 {
            return Err(corrupt(0, "invalid NTFS retained file identity"));
        }
        let folded = self.fold_units(name);
        let state = locked(&self.lifetime)?;
        if state.retained.len() >= MAX_RETAINED {
            return Err(errno(libc::ENOSPC));
        }
        if state.retained.contains_key(&ino)
            || state
                .retained
                .values()
                .any(|name| self.fold_units(name) == folded)
        {
            return Err(FfsError::Exists);
        }
        Ok(())
    }

    pub(super) fn register_retained_file(&self, ino: InodeNumber, name: Vec<u16>) -> Result<()> {
        self.check_retained_file(ino, &name)?;
        locked(&self.lifetime)?.retained.insert(ino, name);
        Ok(())
    }

    pub(super) fn retained_file_name(&self, ino: InodeNumber) -> Result<Option<Vec<u16>>> {
        Ok(locked(&self.lifetime)?.retained.get(&ino).cloned())
    }

    pub(super) fn retained_files(&self) -> Result<Vec<(InodeNumber, Vec<u16>)>> {
        Ok(locked(&self.lifetime)?
            .retained
            .iter()
            .map(|(ino, name)| (*ino, name.clone()))
            .collect())
    }

    pub(super) fn forget_retained_file(&self, ino: InodeNumber) -> Result<()> {
        self.retire_ads_for_base(ino)?;
        locked(&self.lifetime)?.retained.remove(&ino);
        Ok(())
    }

    pub(super) fn is_retained_file(&self, ino: InodeNumber) -> Result<bool> {
        Ok(locked(&self.lifetime)?.retained.contains_key(&ino))
    }

    pub(super) fn is_hidden_root_folded_name(&self, name: &[u16]) -> Result<bool> {
        Ok(locked(&self.lifetime)?
            .retained
            .values()
            .any(|candidate| self.fold_units(candidate) == name))
    }

    pub(super) fn fold_units(&self, name: &[u16]) -> Vec<u16> {
        name.iter()
            .map(|unit| self.upcase[usize::from(*unit)])
            .collect()
    }

    pub(super) fn assign_dir_cookies(
        &self,
        ino: InodeNumber,
        entries: &mut [DirEntry],
    ) -> Result<()> {
        locked(&self.lifetime)?.assign_dir_cookies(ino, entries)
    }

    pub(super) fn register_ads(
        &self,
        reference: NtfsReference,
        name: &[u16],
    ) -> Result<InodeNumber> {
        if name.is_empty() || name.len() > 255 {
            return Err(FfsError::Format("invalid NTFS stream identity".into()));
        }
        let base = self.inode(reference)?;
        locked(&self.lifetime)?.register_ads(base, reference, name)
    }

    pub(super) fn ads_target(&self, ino: InodeNumber) -> Result<(NtfsReference, Vec<u16>)> {
        let state = locked(&self.lifetime)?;
        let identity = state
            .ads
            .get(&ino)
            .ok_or_else(|| FfsError::NotFound(format!("NTFS stream inode {}", ino.0)))?;
        Ok((identity.reference, identity.name.clone()))
    }

    pub(super) fn retire_ads(&self, ino: InodeNumber) -> Result<()> {
        locked(&self.lifetime)?.retire_ads(ino)?;
        let mut cache = self.cache()?;
        cache.attributes.remove(&ino);
        cache.streams.remove(&ino);
        Ok(())
    }

    pub(super) fn retire_ads_for_base(&self, base: InodeNumber) -> Result<()> {
        let identities = {
            let state = locked(&self.lifetime)?;
            state
                .ads
                .iter()
                .filter_map(|(ino, identity)| {
                    (self.inode(identity.reference).ok() == Some(base)).then_some(*ino)
                })
                .collect::<Vec<_>>()
        };
        for ino in identities {
            self.retire_ads(ino)?;
        }
        Ok(())
    }

    pub(super) fn lookup_ads_component(
        &self,
        cx: &Cx,
        parent: InodeNumber,
        base: &[u16],
        name: &[u16],
    ) -> Result<InodeAttr> {
        checkpoint(cx)?;
        let base_name = String::from_utf16(base)
            .map_err(|_| unsupported("NTFS stream base name is not lossless UTF-8"))?;
        if base_name.is_empty() || base_name.contains([':', '/', '\\', '\0']) {
            return Err(FfsError::Format("invalid NTFS stream base name".into()));
        }
        let base_attr = self.lookup_indexed(cx, parent, OsStr::new(&base_name))?;
        let record = self.record(cx, base_attr.ino)?;
        let volume = self.active_volume()?;
        let catalog = volume.attributes(cx, &record)?;
        let names: BTreeSet<_> = catalog
            .all()?
            .into_iter()
            .filter(|attribute| attribute.kind == DATA && !attribute.name.is_empty())
            .map(|attribute| attribute.name)
            .collect();
        let selected = if let Some(exact) = names.get(name) {
            exact.clone()
        } else {
            let folded = self.fold_units(name);
            let mut matches = names
                .iter()
                .filter(|candidate| self.fold_units(candidate) == folded);
            let selected = matches
                .next()
                .ok_or_else(|| FfsError::NotFound("NTFS alternate data stream".into()))?;
            if matches.next().is_some() {
                return Err(corrupt(0, "ambiguous NTFS folded stream name"));
            }
            selected.clone()
        };
        volume.data_stream(cx, &record, &selected)?;
        checkpoint(cx)?;
        let ino = self.register_ads(reference(&record), &selected)?;
        drop(volume);
        self.describe(cx, ino)
    }

    pub(super) fn ads_stream_uncached(&self, cx: &Cx, ino: InodeNumber) -> Result<Stream> {
        let (reference, name) = self.ads_target(ino)?;
        let volume = self.active_volume()?;
        let record = self.record_by_ref(cx, &volume, reference, true)?;
        volume.data_stream(cx, &record, &name)
    }

    pub(super) fn describe_ads_uncached(&self, cx: &Cx, ino: InodeNumber) -> Result<InodeAttr> {
        let (reference, name) = self.ads_target(ino)?;
        let base = self.inode(reference)?;
        let mut attr = self.describe(cx, base)?;
        let volume = self.active_volume()?;
        let record = self.record_by_ref(cx, &volume, reference, true)?;
        let stream = volume.data_stream(cx, &record, &name)?;
        attr.ino = ino;
        attr.kind = FileType::RegularFile;
        attr.size = stream.size;
        attr.blocks = if stream.resident() {
            0
        } else {
            stream.allocated.div_ceil(512)
        };
        attr.perm &= 0o666;
        checkpoint(cx)?;
        Ok(attr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &[u8], ino: u64) -> DirEntry {
        DirEntry {
            ino: InodeNumber(ino),
            offset: 0,
            kind: FileType::RegularFile,
            name: name.to_vec(),
        }
    }

    #[test]
    fn handle_release_checks_both_identity_and_generation() {
        let mut state = NtfsLifetime::default();
        let ino = InodeNumber(7);
        let first = state.register_open(ino).unwrap();
        assert_eq!(
            state
                .release_open(InodeNumber(8), first)
                .unwrap_err()
                .to_errno(),
            libc::EBADF
        );
        assert_eq!(state.counts[&ino], 1);
        state.release_open(ino, first).unwrap();
        let second = state.register_open(ino).unwrap();
        assert!(second > first);
        assert_eq!(
            state.release_open(ino, first).unwrap_err().to_errno(),
            libc::EBADF
        );
        assert_eq!(state.counts[&ino], 1);
        state.release_open(ino, second).unwrap();
        assert!(state.counts.is_empty());
    }

    #[test]
    fn stream_recreation_and_mft_reuse_never_recycle_a_live_identity() {
        let mut state = NtfsLifetime::default();
        let reference = NtfsReference {
            record: 25,
            sequence: 7,
        };
        let base = InodeNumber((7 << 32) + 27);
        let name: Vec<_> = "notes".encode_utf16().collect();
        let first = state.register_ads(base, reference, &name).unwrap();
        assert!(is_ads_ino(first));
        assert_eq!(state.register_ads(base, reference, &name).unwrap(), first);
        state.retire_ads(first).unwrap();
        let next = state.register_ads(base, reference, &name).unwrap();
        assert_ne!(first, next);
        assert!(!state.ads.contains_key(&first));
        let reused = state
            .register_ads(
                InodeNumber((8 << 32) + 27),
                NtfsReference {
                    sequence: 8,
                    ..reference
                },
                &name,
            )
            .unwrap();
        assert_ne!(reused, next);
        assert_eq!(state.ads[&next].reference.sequence, 7);
    }

    #[test]
    fn directory_insertion_and_slot_reuse_preserve_resume_cookies() {
        let mut state = NtfsLifetime::default();
        let mut first = vec![
            entry(b".", 1),
            entry(b"..", 1),
            entry(b"middle", 3),
            entry(b"last", 4),
        ];
        state.assign_dir_cookies(ROOT, &mut first).unwrap();
        let old = first
            .iter()
            .find(|entry| entry.name == b"middle")
            .unwrap()
            .offset;
        let last = first
            .iter()
            .find(|entry| entry.name == b"last")
            .unwrap()
            .offset;
        let mut next = vec![entry(b"first", 5), entry(b"last", 4), entry(b"middle", 6)];
        state.assign_dir_cookies(ROOT, &mut next).unwrap();
        assert_eq!(
            next.iter()
                .find(|entry| entry.name == b"last")
                .unwrap()
                .offset,
            last
        );
        assert!(
            next.iter()
                .find(|entry| entry.name == b"middle")
                .unwrap()
                .offset
                > last
        );
        assert!(next.windows(2).all(|pair| pair[0].offset < pair[1].offset));
        assert_eq!(next.iter().filter(|entry| entry.offset > old).count(), 3);
    }

    #[test]
    fn alternate_stream_syntax_is_explicit_and_bounded() {
        assert!(parse_ads_component("file").unwrap().is_none());
        let expected = Some((
            "file".encode_utf16().collect(),
            "Notes".encode_utf16().collect(),
        ));
        assert_eq!(parse_ads_component("file:Notes").unwrap(), expected);
        assert_eq!(parse_ads_component("file:Notes:$data").unwrap(), expected);
        for name in [
            ":notes",
            "file:",
            "file:notes:other",
            "file:n:more:$DATA",
            "../f:n",
            "file:n/x",
            "..:n",
        ] {
            assert!(parse_ads_component(name).is_err(), "{name}");
        }
        assert_eq!(
            parse_ads_component(&format!("file:{}", "a".repeat(256)))
                .unwrap_err()
                .to_errno(),
            libc::ENAMETOOLONG
        );
    }
}
