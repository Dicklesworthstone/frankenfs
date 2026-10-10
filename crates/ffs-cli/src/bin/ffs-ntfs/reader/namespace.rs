//! Bounded directory-tree walks and native $UpCase-based path lookup.

use super::*;
use ffs_ondisk::ntfs::index::{NtfsFileName, NtfsIndexEntry, NtfsIndexRoot, parse_index_block};
use std::collections::{BTreeMap, BTreeSet};

const I30: &[u16] = &[36, 73, 51, 48];
const MAX_ENTRIES: usize = 65_536;
const MAX_BLOCKS: usize = 16_384;

#[derive(Debug, Clone)]
pub struct DirectoryEntry {
    pub reference: NtfsReference,
    pub filename: NtfsFileName,
    pub directory: bool,
}

impl NtfsVolume {
    /// Enumerate the reachable native index tree, not a speculative MFT scan.
    /// Every link is checked against its target record's FILE_NAME identity.
    pub fn list_directory(&self, cx: &Cx, record: &NtfsFileRecord) -> Result<Vec<DirectoryEntry>> {
        checkpoint(cx)?;
        if !record.is_directory() { return Err(FfsError::NotDirectory); }
        let catalog = self.attributes(cx, record)?;
        let attributes = catalog.all()?;
        reject_reparse(&attributes)?;
        let root = catalog.select(&self.geometry, 0x90, I30)?;
        if !root.resident() { return Err(corrupt(0, "INDEX_ROOT must be resident")); }
        let bytes = self.read(cx, &root, 0, 65_536)?;
        let root = NtfsIndexRoot::parse(&bytes, self.geometry.cluster_bytes()).map_err(parse)?;
        if root.block_bytes != self.geometry.index_bytes() {
            return Err(unsupported("directory index block size differs from admitted boot geometry"));
        }
        let external = root.entries.iter().any(|entry| entry.child_vcn.is_some())
            || attributes.iter().any(|attr| matches!(attr.kind, 0xA0 | 0xB0) && attr.name == I30);
        let (allocation, bitmap) = if external {
            let allocation = catalog.select(&self.geometry, 0xA0, I30)?;
            let bitmap = catalog.select(&self.geometry, 0xB0, I30)?;
            if allocation.resident() || allocation.initialized != allocation.size
                || !allocation.size.is_multiple_of(u64::from(root.block_bytes))
                || allocation.size / u64::from(root.block_bytes) > MAX_BLOCKS as u64
                || bitmap.size > MAX_BLOCKS.div_ceil(8) as u64 || bitmap.initialized != bitmap.size {
                return Err(unsupported("directory allocation or bitmap exceeds the initialized read profile"));
            }
            if let Storage::Mapped(runs) = &allocation.storage
                && runs.iter().any(|run| run.lcn.is_none()) {
                return Err(corrupt(0, "directory INDEX_ALLOCATION contains sparse holes"));
            }
            let bitmap = self.read(cx, &bitmap, 0, bitmap.size as usize)?;
            (Some(allocation), bitmap)
        } else { (None, Vec::new()) };
        let mut walker = Walker { volume: self, cx, block_bytes: root.block_bytes,
            vcn_bytes: root.vcn_bytes, allocation, bitmap, visited: BTreeSet::new(),
            keys: Vec::new() };
        walker.visit(root.entries, 0)?;
        for (byte_index, byte) in walker.bitmap.iter().enumerate() {
            for bit in 0..8 {
                if byte & (1 << bit) != 0 && !walker.visited.contains(&(byte_index as u64 * 8 + bit)) {
                    return Err(corrupt(0, "directory bitmap contains an unreachable allocated index block"));
                }
            }
        }
        let parent = NtfsReference { record: u64::from(record.number), sequence: record.sequence };
        let mut names = BTreeMap::new();
        let mut result = Vec::with_capacity(walker.keys.len());
        for (reference, filename) in walker.keys {
            checkpoint(cx)?;
            if filename.parent != parent { return Err(corrupt(0, "directory index has the wrong parent reference")); }
            if filename.name == [46] && reference == parent { continue; }
            if filename.name == [46] || filename.name == [46, 46] {
                return Err(corrupt(0, "invalid dot entry in NTFS directory index"));
            }
            if names.insert(filename.name.clone(), reference).is_some_and(|old| old != reference) {
                return Err(corrupt(0, "duplicate directory name points at different file records"));
            }
            let target = self.record(cx, reference.record, Some(reference.sequence))?;
            let target_catalog = self.attributes(cx, &target)?;
            let attributes = target_catalog.all()?;
            let mut matched = false;
            for attr in attributes.iter().filter(|attr| attr.kind == 0x30) {
                if attr.flags != 0 || !attr.name.is_empty() { return Err(corrupt(0, "invalid FILE_NAME storage or attribute name")); }
                let NtfsValue::Resident(value) = &attr.value else { return Err(corrupt(0, "nonresident FILE_NAME")); };
                if NtfsFileName::parse(value).map_err(parse)? == filename { matched = true; }
            }
            if !matched { return Err(corrupt(0, "directory index does not match target FILE_NAME")); }
            result.push(DirectoryEntry { reference, filename, directory: target.is_directory() });
        }
        checkpoint(cx)?;
        Ok(result)
    }

    pub fn resolve(&self, cx: &Cx, path: &str) -> Result<NtfsFileRecord> {
        checkpoint(cx)?;
        if path.len() > 65_536 || path.contains(['\\', '\0']) {
            return Err(FfsError::NameTooLong);
        }
        let components: Vec<_> = path.split('/').filter(|part| !part.is_empty() && *part != ".").take(257).collect();
        if components.len() > 256 { return Err(FfsError::NameTooLong); }
        let mut record = self.record(cx, 5, None)?;
        if !record.is_directory() { return Err(corrupt(0, "NTFS root record is not a directory")); }
        let table = if components.is_empty() { Vec::new() } else { self.upcase(cx)? };
        let mut ancestors = BTreeSet::from([5_u64]);
        for component in components {
            checkpoint(cx)?;
            if component == ".." { return Err(unsupported("parent traversal in image paths is not admitted")); }
            let name: Vec<u16> = component.encode_utf16().collect();
            if name.len() > 255 { return Err(FfsError::NameTooLong); }
            let entries = self.list_directory(cx, &record)?;
            let exact = entries.iter().any(|entry| entry.filename.name == name);
            let mut found = None;
            for entry in &entries {
                let matches = if exact { entry.filename.name == name } else {
                    entry.filename.namespace != 0 && entry.filename.name.len() == name.len()
                        && entry.filename.name.iter().zip(&name).all(|(a, b)| table[usize::from(*a)] == table[usize::from(*b)])
                };
                if matches {
                    if found.is_some_and(|old| old != entry.reference) {
                        return Err(corrupt(0, "ambiguous NTFS case-insensitive name"));
                    }
                    found = Some(entry.reference);
                }
            }
            let reference = found.ok_or(FfsError::NotFound)?;
            record = self.record(cx, reference.record, Some(reference.sequence))?;
            let catalog = self.attributes(cx, &record)?;
            reject_reparse(&catalog.all()?)?;
            if record.is_directory() && !ancestors.insert(reference.record) {
                return Err(corrupt(0, "NTFS directory links to an ancestor"));
            }
        }
        let catalog = self.attributes(cx, &record)?;
        reject_reparse(&catalog.all()?)?;
        drop(catalog);
        if path.ends_with('/') && !record.is_directory() { return Err(FfsError::NotDirectory); }
        checkpoint(cx)?;
        Ok(record)
    }

    fn upcase(&self, cx: &Cx) -> Result<Vec<u16>> {
        let record = self.record(cx, 10, None)?;
        let stream = self.select_stream(cx, &record, DATA, &[])?;
        if stream.size != 131_072 || stream.initialized != stream.size {
            return Err(corrupt(0, "invalid NTFS UpCase table size or initialized boundary"));
        }
        let bytes = self.read(cx, &stream, 0, 131_072)?;
        let table: Vec<_> = bytes.chunks_exact(2).map(|word| u16::from_le_bytes([word[0], word[1]])).collect();
        for (index, &upper) in table.iter().enumerate() {
            if index.is_multiple_of(1024) { checkpoint(cx)?; }
            if table[usize::from(upper)] != upper { return Err(corrupt(0, "non-idempotent NTFS UpCase mapping")); }
        }
        for lower in b'a'..=b'z' {
            if table[usize::from(lower)] != u16::from(lower.to_ascii_uppercase()) {
                return Err(corrupt(0, "NTFS UpCase table has invalid ASCII mappings"));
            }
        }
        Ok(table)
    }
}

fn reject_reparse(attributes: &[NtfsAttribute<'_>]) -> Result<()> {
    if attributes.iter().any(|attr| attr.kind == 0xC0) {
        return Err(unsupported("NTFS reparse traversal is not implemented"));
    }
    Ok(())
}

struct Walker<'a> {
    volume: &'a NtfsVolume,
    cx: &'a Cx,
    block_bytes: u32,
    vcn_bytes: u32,
    allocation: Option<Stream>,
    bitmap: Vec<u8>,
    visited: BTreeSet<u64>,
    keys: Vec<(NtfsReference, NtfsFileName)>,
}
impl Walker<'_> {
    fn visit(&mut self, entries: Vec<NtfsIndexEntry>, depth: usize) -> Result<()> {
        checkpoint(self.cx)?;
        if depth > 32 { return Err(unsupported("NTFS index tree depth exceeds 32")); }
        for entry in entries {
            checkpoint(self.cx)?;
            if let Some(vcn) = entry.child_vcn {
                let offset = vcn.checked_mul(u64::from(self.vcn_bytes)).ok_or_else(|| corrupt(0, "index VBN overflow"))?;
                if !offset.is_multiple_of(u64::from(self.block_bytes)) { return Err(corrupt(offset, "unaligned index child")); }
                let block = offset / u64::from(self.block_bytes);
                if block >= MAX_BLOCKS as u64 || !self.visited.insert(block) {
                    return Err(corrupt(offset, "cyclic, aliased or excessive index child"));
                }
                let bitmap = self.bitmap.get((block / 8) as usize).ok_or_else(|| corrupt(offset, "index child outside bitmap"))?;
                if bitmap & (1 << (block % 8)) == 0 { return Err(corrupt(offset, "index child is not allocated in its bitmap")); }
                let stream = self.allocation.as_ref().ok_or_else(|| corrupt(offset, "missing index allocation"))?;
                if offset.checked_add(u64::from(self.block_bytes)).is_none_or(|end| end > stream.initialized) {
                    return Err(corrupt(offset, "index child outside initialized allocation"));
                }
                let raw = self.volume.read(self.cx, stream, offset, self.block_bytes as usize)?;
                let children = parse_index_block(&raw, vcn).map_err(parse)?;
                self.visit(children, depth + 1)?;
            }
            if let Some(key) = entry.key {
                if self.keys.len() == MAX_ENTRIES { return Err(unsupported("NTFS directory exceeds 65536 entries")); }
                self.keys.push(key);
            }
        }
        Ok(())
    }
}
