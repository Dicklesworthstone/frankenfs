//! Opt-in index-directed lookup, not a whole-directory consistency check.
//!
//! Native FILE_NAME collation groups names by the volume's UpCase mapping.
//! Search the complete folded-equality range, including both sides of an equal
//! separator: an exact-case entry can occur after a case-insensitive candidate.
//! No host Unicode folding, speculative MFT scan, or unverified fallback.
//! Format references: Linux v6.12 fs/ntfs3/{index,upcase}.c and NTFS-3G
//! 2022.10.3 libntfs-3g/dir.c. This is independently written traversal code.

use super::{
    Cx, DirectoryEntry, MAX_ENTRIES, NtfsFileName, NtfsFileRecord, NtfsIndexEntry, NtfsReference,
    NtfsVolume, Result, Walker, checkpoint, corrupt, unsupported,
};
use std::cmp::Ordering;
use std::collections::BTreeSet;

type Key = (NtfsReference, NtfsFileName);

fn compare(left: &[u16], right: &[u16], table: &[u16]) -> Ordering {
    left.iter()
        .map(|unit| table[usize::from(*unit)])
        .cmp(right.iter().map(|unit| table[usize::from(*unit)]))
}

fn within(name: &[u16], lower: Option<&[u16]>, upper: Option<&[u16]>, table: &[u16]) -> bool {
    lower.is_none_or(|bound| compare(name, bound, table) != Ordering::Less)
        && upper.is_none_or(|bound| compare(name, bound, table) != Ordering::Greater)
}

#[derive(Default)]
struct Candidate {
    key: Option<Key>,
    ambiguous: bool,
}

impl Candidate {
    fn observe(&mut self, key: &Key) {
        if let Some((reference, _)) = &self.key {
            self.ambiguous |= *reference != key.0;
        } else {
            self.key = Some(key.clone());
        }
    }

    fn finish(self) -> Result<Option<Key>> {
        if self.ambiguous {
            return Err(corrupt(0, "ambiguous NTFS indexed name"));
        }
        Ok(self.key)
    }
}

struct Search<'a, 'volume> {
    walker: &'a mut Walker<'volume>,
    parent: NtfsReference,
    name: &'a [u16],
    table: &'a [u16],
    keys_examined: usize,
    declared_children: BTreeSet<u64>,
    exact: Candidate,
    folded: Candidate,
}

impl Search<'_, '_> {
    fn validate_node(
        &mut self,
        entries: &[NtfsIndexEntry],
        lower: Option<&[u16]>,
        upper: Option<&[u16]>,
    ) -> Result<()> {
        checkpoint(self.walker.cx)?;
        // Validate the entire loaded node before trusting any separator or
        // candidate. Unvisited descendant contents are deliberately not read.
        let (terminal, keys) = entries
            .split_last()
            .ok_or_else(|| corrupt(0, "empty NTFS index node"))?;
        if terminal.key.is_some() {
            return Err(corrupt(0, "missing terminal NTFS index entry"));
        }
        let mut previous = lower;
        for entry in keys {
            checkpoint(self.walker.cx)?;
            if self.keys_examined == MAX_ENTRIES {
                return Err(unsupported("NTFS indexed search exceeds 65536 examined keys"));
            }
            self.keys_examined += 1;
            let (reference, filename) = entry.key.as_ref()
                .ok_or_else(|| corrupt(0, "interior terminal NTFS index entry"))?;
            if filename.parent != self.parent
                || filename.name == [46, 46]
                || (filename.name == [46] && *reference != self.parent)
            {
                return Err(corrupt(0, "NTFS indexed key has an invalid parent or dot identity"));
            }
            if !within(&filename.name, previous, upper, self.table) {
                return Err(corrupt(0, "NTFS index keys violate native UpCase search bounds"));
            }
            previous = Some(&filename.name);
        }
        for entry in entries {
            checkpoint(self.walker.cx)?;
            if let Some(vcn) = entry.child_vcn {
                self.walker.child_offset(vcn)?;
                if !self.declared_children.insert(vcn) {
                    return Err(corrupt(0, "cyclic or aliased NTFS indexed child"));
                }
            }
        }

        checkpoint(self.walker.cx)
    }

    fn visit(
        &mut self,
        entries: Vec<NtfsIndexEntry>,
        depth: usize,
        lower: Option<&[u16]>,
        upper: Option<&[u16]>,
    ) -> Result<()> {
        checkpoint(self.walker.cx)?;
        if depth > 32 {
            return Err(unsupported("NTFS index tree depth exceeds 32"));
        }
        self.validate_node(&entries, lower, upper)?;
        let mut previous = lower;
        for entry in &entries {
            checkpoint(self.walker.cx)?;
            let boundary = entry.key.as_ref().map_or(upper, |(_, key)| Some(key.name.as_slice()));
            if let Some(vcn) = entry.child_vcn
                && within(self.name, previous, boundary, self.table)
            {
                if depth == 32 {
                    return Err(unsupported("NTFS index tree depth exceeds 32"));
                }
                let children = self.walker.read_child(vcn)?;
                self.visit(children, depth + 1, previous, boundary)?;
            }
            if let Some(key) = &entry.key {
                if key.1.name == self.name {
                    self.exact.observe(key);
                } else if key.1.namespace != 0
                    && compare(&key.1.name, self.name, self.table) == Ordering::Equal
                {
                    // Do not reject folded ambiguity yet: a later exact-case
                    // match wins, just as it does in the default strict reader.
                    self.folded.observe(key);
                }
                previous = Some(&key.1.name);
            }
        }
        checkpoint(self.walker.cx)
    }
}

impl NtfsVolume {
    /// Mount-only bridge: the filesystem retains the already validated native
    /// UpCase table. Do not expose a caller-supplied collation table publicly.
    pub(in crate::reader) fn lookup_indexed_entry(
        &self,
        cx: &Cx,
        directory: &NtfsFileRecord,
        name: &[u16],
        table: &[u16],
    ) -> Result<Option<DirectoryEntry>> {
        lookup_entry(self, cx, directory, name, table)
    }

    /// Admit the root node and every descriptor it contains without reading
    /// child blocks or sibling FILEs. This is not whole-directory validation.
    pub(in crate::reader) fn admit_indexed_directory(
        &self,
        cx: &Cx,
        directory: &NtfsFileRecord,
        table: &[u16],
    ) -> Result<()> {
        checkpoint(cx)?;
        if table.len() != 65_536 {
            return Err(corrupt(0, "invalid NTFS indexed mount UpCase table"));
        }
        let (mut walker, entries) = self.directory_index(cx, directory)?;
        let mut search = Search {
            walker: &mut walker,
            parent: NtfsReference {
                record: u64::from(directory.number),
                sequence: directory.sequence,
            },
            name: &[],
            table,
            keys_examined: 0,
            declared_children: BTreeSet::new(),
            exact: Candidate::default(),
            folded: Candidate::default(),
        };
        search.validate_node(&entries, None, None)?;
        checkpoint(cx)
    }
}

pub(super) fn lookup(
    volume: &NtfsVolume,
    cx: &Cx,
    directory: &NtfsFileRecord,
    name: &[u16],
    table: &[u16],
) -> Result<Option<NtfsReference>> {
    lookup_entry(volume, cx, directory, name, table)
        .map(|entry| entry.map(|entry| entry.reference))
}

fn lookup_entry(
    volume: &NtfsVolume,
    cx: &Cx,
    directory: &NtfsFileRecord,
    name: &[u16],
    table: &[u16],
) -> Result<Option<DirectoryEntry>> {
    checkpoint(cx)?;
    // Only the validated volume UpCase table reaches this internal boundary.
    // Keep an explicit length guard rather than indexing a truncated table.
    if table.len() != 65_536 || name.is_empty() || name.len() > 255 {
        return Err(corrupt(0, "invalid NTFS indexed search name or UpCase table"));
    }
    let (mut walker, entries) = volume.directory_index(cx, directory)?;
    let mut search = Search {
        walker: &mut walker,
        parent: NtfsReference { record: u64::from(directory.number), sequence: directory.sequence },
        name,
        table,
        keys_examined: 0,
        declared_children: BTreeSet::new(),
        exact: Candidate::default(),
        folded: Candidate::default(),
    };
    search.visit(entries, 0, None, None)?;
    let candidate = if search.exact.key.is_some() {
        search.exact.finish()?
    } else {
        search.folded.finish()?
    };
    let result = match candidate {
        Some((reference, filename)) => {
            // Reuse complete catalog/sequence/FILE_NAME/provider validation,
            // but do not load unrelated siblings' MFT records.
            Some(volume.verify_directory_entry(cx, reference, filename)?)
        }
        None => None,
    };
    checkpoint(cx)?;
    Ok(result)
}

#[cfg(test)]
mod tests;
