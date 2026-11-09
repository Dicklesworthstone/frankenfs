//! Bounded, read-only reconciliation of native FILE_NAME and $I30 identities.
//!
//! Cluster ownership, security indexes, DOS-pair accounting and native
//! journal recovery remain separate checks. A report never authorizes mutation.

use super::ownership::{Work, catalog};
use super::{
    AllocationIssue, Cx, FfsError, MAX_ISSUES, MAX_RECORDS, NtfsVolume, Result, Storage, Stream,
    bit, checkpoint, corrupt, parse, read_bitmap, unsupported,
};
use crate::reader::attributes::AttributeSet;
use crate::reader::namespace::parse_file_name;
use crate::reader::{DATA, NtfsFileRecord, NtfsReference, REPARSE_POINT};
use ffs_ondisk::ntfs::index::{NtfsFileName, NtfsIndexEntry, NtfsIndexRoot, parse_index_block};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const I30: &[u16] = &[36, 73, 51, 48];
const MAX_ENTRIES: u64 = 16_777_216;
const MAX_BLOCKS: u64 = 16_384;

#[derive(Debug, Clone, Copy)]
pub struct NamespaceLimits {
    pub records: u64,
    /// FILE, ATTRIBUTE_LIST, index, bitmap and UpCase bytes; repeated reads count.
    pub metadata_bytes: u64,
    /// Combined FILE_NAME and native index key count, across the whole volume.
    pub entries: u64,
}

impl Default for NamespaceLimits {
    fn default() -> Self {
        Self {
            records: 1_048_576,
            metadata_bytes: 1 << 30,
            entries: 1_048_576,
        }
    }
}

impl NamespaceLimits {
    pub fn validate(self) -> Result<()> {
        if !(1..=MAX_RECORDS).contains(&self.records)
            || !(1..=(1_u64 << 40)).contains(&self.metadata_bytes)
            || !(1..=MAX_ENTRIES).contains(&self.entries)
        {
            return Err(FfsError::Format(
                "namespace limits require 1..=16777216 records and entries, and 1..=1099511627776 metadata bytes".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Default)]
pub struct NamespaceReport {
    pub logical_records: u64,
    pub initialized_records: u64,
    pub record_slots_examined: u64,
    pub base_records_examined: u64,
    pub directories_examined: u64,
    pub file_names_examined: u64,
    pub index_entries_examined: u64,
    pub metadata_bytes_attempted: u64,
    /// Unknown if any allocated base catalog or directory was not fully read.
    pub missing_index_entries: Option<u64>,
    /// Named base records and user records (>=24) unreachable from root record 5.
    /// Unnamed reserved system slots are not asserted to be ordinary orphans.
    pub unreachable_records: Option<u64>,
    pub complete: bool,
    pub limit_reached: Option<&'static str>,
    pub errors: u64,
    pub unsupported: u64,
    pub issues: Vec<AllocationIssue>,
    pub omitted_issues: u64,
}

impl NamespaceReport {
    #[must_use]
    pub fn is_consistent(&self) -> bool {
        self.complete
            && self.limit_reached.is_none()
            && self.errors == 0
            && self.unsupported == 0
            && self.missing_index_entries == Some(0)
            && self.unreachable_records == Some(0)
    }

    fn stop(&mut self, reason: &'static str) {
        self.complete = false;
        self.limit_reached = Some(reason);
    }

    fn issue(&mut self, record: u64, category: &'static str, detail: &str) {
        if category == "unsupported" {
            self.unsupported += 1;
        } else {
            self.errors += 1;
        }
        if self.issues.len() == MAX_ISSUES {
            self.omitted_issues += 1;
            return;
        }
        self.issues.push(AllocationIssue {
            category,
            record: Some(record),
            attribute_id: None,
            other_record: None,
            other_attribute_id: None,
            first_cluster: None,
            clusters: 0,
            detail: detail.chars().take(512).collect(),
        });
    }

    fn failed_record(&mut self, number: u64, error: FfsError) -> Result<()> {
        if matches!(error, FfsError::Cancelled) {
            return Err(error);
        }
        self.complete = false;
        let category = match &error {
            FfsError::UnsupportedFeature(_) => "unsupported",
            FfsError::Io(_) => "io",
            _ => "namespace_metadata",
        };
        self.issue(number, category, &error.to_string());
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Identity {
    parent: u64,
    parent_sequence: u16,
    record: u64,
    sequence: u16,
    namespace: u8,
    name: Vec<u16>,
}

impl Identity {
    fn new(reference: NtfsReference, name: NtfsFileName) -> Self {
        Self {
            parent: name.parent.record,
            parent_sequence: name.parent.sequence,
            record: reference.record,
            sequence: reference.sequence,
            namespace: name.namespace,
            name: name.name,
        }
    }

    fn root_dot(&self) -> bool {
        self.record == 5
            && self.parent == 5
            && self.sequence == self.parent_sequence
            && self.name == [46]
    }
}

struct Record {
    sequence: u16,
    directory: bool,
    named: bool,
}

struct Scan {
    work: Work,
    entry_limit: u64,
    report: NamespaceReport,
    records: BTreeMap<u64, Record>,
    names: BTreeSet<Identity>,
    keys: BTreeSet<Identity>,
}

impl Scan {
    fn entry(&mut self, index: bool) -> Result<()> {
        if self.report.file_names_examined + self.report.index_entries_examined == self.entry_limit
        {
            self.report.stop("namespace entry budget");
            return Err(unsupported("namespace entry budget exhausted"));
        }
        if index {
            self.report.index_entries_examined += 1;
        } else {
            self.report.file_names_examined += 1;
        }
        Ok(())
    }

    fn read(&mut self, volume: &NtfsVolume, cx: &Cx, stream: &Stream) -> Result<Vec<u8>> {
        self.work.reserve(stream.size)?;
        let length =
            usize::try_from(stream.size).map_err(|_| corrupt(0, "metadata size overflow"))?;
        let bytes = volume.read(cx, stream, 0, length)?;
        if bytes.len() != length {
            return Err(corrupt(0, "short namespace metadata read"));
        }
        Ok(bytes)
    }

    fn file_names(
        &mut self,
        record: &NtfsFileRecord,
        attrs: &AttributeSet<'_>,
        cx: &Cx,
    ) -> Result<bool> {
        let mut named = false;
        let first_name = self.report.file_names_examined;
        for attr in attrs.all()?.iter().filter(|attr| attr.kind == 0x30) {
            checkpoint(cx)?;
            self.entry(false)?;
            let name = parse_file_name(attr)?;
            let identity = Identity::new(
                NtfsReference {
                    record: u64::from(record.number),
                    sequence: record.sequence,
                },
                name,
            );
            if (identity.name == [46] || identity.name == [46, 46]) && !identity.root_dot() {
                self.report.issue(
                    identity.record,
                    "invalid_dot",
                    "FILE_NAME contains an invalid dot identity",
                );
            }
            named = true;
            if !self.names.insert(identity) {
                self.report.issue(
                    u64::from(record.number),
                    "duplicate_file_name",
                    "base catalog repeats a FILE_NAME identity",
                );
            }
        }
        // This comparison requires the complete validated catalog, including
        // extension names and DOS aliases. A partial parse or exhausted budget
        // returns above without claiming that an unobserved name is absent.
        let native_names = self.report.file_names_examined - first_name;
        if native_names != u64::from(record.hard_links) {
            self.report.issue(
                u64::from(record.number),
                "link_count_mismatch",
                &format!(
                    "FILE header declares {} links but its complete catalog contains {native_names} FILE_NAME attributes (including DOS aliases)",
                    record.hard_links
                ),
            );
        }
        Ok(named)
    }

    fn directory(
        &mut self,
        volume: &NtfsVolume,
        cx: &Cx,
        record: &NtfsFileRecord,
        attrs: &AttributeSet<'_>,
        upcase: &[u16],
    ) -> Result<()> {
        self.report.directories_examined += 1;
        if attrs.all()?.iter().any(|attr| attr.kind == REPARSE_POINT) {
            return Err(unsupported(
                "namespace checking does not interpret reparse directory providers",
            ));
        }
        let root = attrs.select(&volume.geometry, 0x90, I30)?;
        if !root.resident() {
            return Err(corrupt(0, "INDEX_ROOT must be resident"));
        }
        let bytes = self.read(volume, cx, &root)?;
        let root = NtfsIndexRoot::parse(&bytes, volume.geometry.cluster_bytes())
            .map_err(|error| parse(&error))?;
        if root.block_bytes != volume.geometry.index_bytes() {
            return Err(unsupported(
                "index size differs from admitted boot geometry",
            ));
        }
        let external = root.entries.iter().any(|entry| entry.child_vcn.is_some())
            || attrs
                .all()?
                .iter()
                .any(|attr| matches!(attr.kind, 0xA0 | 0xB0) && attr.name == I30);
        let (allocation, bitmap) = if external {
            let allocation = attrs.select(&volume.geometry, 0xA0, I30)?;
            let bitmap = attrs.select(&volume.geometry, 0xB0, I30)?;
            if allocation.resident()
                || allocation.initialized != allocation.size
                || !allocation.size.is_multiple_of(u64::from(root.block_bytes))
                || allocation.size / u64::from(root.block_bytes) > MAX_BLOCKS
                || bitmap.size > MAX_BLOCKS.div_ceil(8)
                || bitmap.initialized != bitmap.size
            {
                return Err(unsupported(
                    "index allocation/bitmap exceeds initialized bounded profile",
                ));
            }
            if !matches!(&allocation.storage, Storage::Mapped(runs) if runs.iter().all(|run| run.lcn.is_some()))
            {
                return Err(corrupt(
                    0,
                    "INDEX_ALLOCATION must have plain nonsparse storage",
                ));
            }
            if !matches!(&bitmap.storage, Storage::Resident(_))
                && !matches!(&bitmap.storage, Storage::Mapped(runs) if runs.iter().all(|run| run.lcn.is_some()))
            {
                return Err(unsupported(
                    "namespace index bitmaps require plain nonsparse storage",
                ));
            }
            (Some(allocation), self.read(volume, cx, &bitmap)?)
        } else {
            (None, Vec::new())
        };
        let mut tree = Index {
            volume,
            cx,
            parent: NtfsReference {
                record: u64::from(record.number),
                sequence: record.sequence,
            },
            block_bytes: root.block_bytes,
            vcn_bytes: root.vcn_bytes,
            allocation,
            bitmap,
            visited: BTreeSet::new(),
            previous: None,
            upcase,
        };
        tree.visit(self, root.entries, 0)?;
        for (byte, value) in tree.bitmap.iter().enumerate() {
            checkpoint(cx)?;
            for bit in 0..8 {
                if value & (1 << bit) != 0 && !tree.visited.contains(&(byte as u64 * 8 + bit)) {
                    return Err(corrupt(
                        0,
                        "directory bitmap allocates an unreachable index block",
                    ));
                }
            }
        }
        Ok(())
    }

    fn reconcile(&mut self, cx: &Cx) -> Result<()> {
        if !self.records.get(&5).is_some_and(|record| record.directory) {
            self.report.issue(
                5,
                "missing_root",
                "allocated base directory record 5 is missing",
            );
        }
        let mut missing = 0;
        let mut directory_parents: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        for name in &self.names {
            checkpoint(cx)?;
            if name.record == 5 && !name.root_dot() {
                self.report.issue(
                    5,
                    "invalid_root_name",
                    "the root directory may only have its native self-referencing dot identity",
                );
            }
            if self
                .records
                .get(&name.record)
                .is_some_and(|record| record.directory)
                && !name.root_dot()
            {
                directory_parents
                    .entry(name.record)
                    .or_default()
                    .insert(name.parent);
            }
            if !self
                .records
                .get(&name.parent)
                .is_some_and(|record| record.directory && record.sequence == name.parent_sequence)
            {
                self.report.issue(
                    name.record,
                    "invalid_parent",
                    "FILE_NAME parent is not an allocated sequence-matching base directory",
                );
            }
            if !name.root_dot() && !self.keys.contains(name) {
                missing += 1;
                self.report.issue(
                    name.record,
                    "missing_index_entry",
                    "FILE_NAME has no matching parent $I30 identity",
                );
            }
        }
        for (number, parents) in directory_parents {
            checkpoint(cx)?;
            if parents.len() > 1 {
                self.report.issue(
                    number,
                    "multiple_directory_parents",
                    "directory FILE_NAME identities claim more than one parent; long/DOS aliases in one parent remain allowed",
                );
            }
        }
        let mut children: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
        let mut exact_names = BTreeMap::new();
        for key in &self.keys {
            checkpoint(cx)?;
            if exact_names
                .insert((key.parent, &key.name), (key.record, key.sequence))
                .is_some_and(|previous| previous != (key.record, key.sequence))
            {
                self.report.issue(
                    key.parent,
                    "conflicting_index_name",
                    "the same exact directory name refers to different native file identities",
                );
            }
            if self
                .records
                .get(&key.record)
                .is_none_or(|record| record.sequence != key.sequence)
            {
                self.report.issue(
                    key.record,
                    "invalid_index_target",
                    "$I30 target is not an allocated sequence-matching base record",
                );
            } else if !self.names.contains(key) {
                self.report.issue(
                    key.record,
                    "missing_file_name",
                    "$I30 identity is absent from the target's complete FILE_NAME catalog",
                );
            } else if !key.root_dot() {
                children.entry(key.parent).or_default().insert(key.record);
            }
        }
        self.directory_cycles(cx, &children)?;
        let mut reachable = BTreeSet::from([5]);
        let mut queue = VecDeque::from([5]);
        while let Some(parent) = queue.pop_front() {
            checkpoint(cx)?;
            if let Some(entries) = children.get(&parent) {
                for &child in entries {
                    checkpoint(cx)?;
                    if reachable.insert(child) {
                        queue.push_back(child);
                    }
                }
            }
        }
        let mut unreachable = 0;
        for (&number, record) in &self.records {
            checkpoint(cx)?;
            if (number >= 24 || record.named) && !reachable.contains(&number) {
                unreachable += 1;
                self.report.issue(number, "unreachable_record", "allocated base record is unreachable through verified root namespace links; not reclamation authority");
            }
        }
        self.report.missing_index_entries = Some(missing);
        self.report.unreachable_records = Some(unreachable);
        Ok(())
    }

    fn directory_cycles(&mut self, cx: &Cx, children: &BTreeMap<u64, BTreeSet<u64>>) -> Result<()> {
        // Kahn's algorithm bounds stack use even for a hostile, MFT-sized chain.
        // Native long/DOS aliases between the same directories count once.
        let mut incoming: BTreeMap<_, u64> = BTreeMap::new();
        for (&number, record) in &self.records {
            checkpoint(cx)?;
            if record.directory {
                incoming.insert(number, 0);
            }
        }
        for entries in children.values() {
            checkpoint(cx)?;
            for child in entries {
                checkpoint(cx)?;
                if let Some(count) = incoming.get_mut(child) {
                    *count += 1;
                }
            }
        }
        let mut queue = VecDeque::new();
        for (&number, &count) in &incoming {
            checkpoint(cx)?;
            if count == 0 {
                queue.push_back(number);
            }
        }
        while let Some(number) = queue.pop_front() {
            checkpoint(cx)?;
            if let Some(entries) = children.get(&number) {
                for child in entries {
                    checkpoint(cx)?;
                    if let Some(count) = incoming.get_mut(child) {
                        *count -= 1;
                        if *count == 0 {
                            queue.push_back(*child);
                        }
                    }
                }
            }
        }
        if let Some((&number, _)) = incoming.iter().find(|(_, count)| **count != 0) {
            self.report.issue(
                number,
                "directory_cycle",
                "verified directory references contain a cycle; native directory ancestry is not a tree",
            );
        }
        Ok(())
    }
}

struct Index<'a> {
    volume: &'a NtfsVolume,
    cx: &'a Cx,
    parent: NtfsReference,
    block_bytes: u32,
    vcn_bytes: u32,
    allocation: Option<Stream>,
    bitmap: Vec<u8>,
    visited: BTreeSet<u64>,
    previous: Option<Vec<u16>>,
    upcase: &'a [u16],
}

impl Index<'_> {
    fn visit(&mut self, scan: &mut Scan, entries: Vec<NtfsIndexEntry>, depth: u8) -> Result<()> {
        checkpoint(self.cx)?;
        if depth > 32 {
            return Err(unsupported("namespace index depth exceeds 32"));
        }
        for entry in entries {
            checkpoint(self.cx)?;
            if let Some(vcn) = entry.child_vcn {
                let offset = vcn
                    .checked_mul(u64::from(self.vcn_bytes))
                    .ok_or_else(|| corrupt(0, "index VCN overflow"))?;
                let block = offset / u64::from(self.block_bytes);
                if !offset.is_multiple_of(u64::from(self.block_bytes))
                    || block >= MAX_BLOCKS
                    || self
                        .bitmap
                        .get((block / 8) as usize)
                        .is_none_or(|value| value & (1 << (block % 8)) == 0)
                    || !self.visited.insert(block)
                {
                    return Err(corrupt(
                        offset,
                        "unaligned, unallocated, aliased or cyclic index child",
                    ));
                }
                let allocation = self
                    .allocation
                    .as_ref()
                    .ok_or_else(|| corrupt(offset, "missing index allocation"))?;
                if offset
                    .checked_add(u64::from(self.block_bytes))
                    .is_none_or(|end| end > allocation.initialized)
                {
                    return Err(corrupt(
                        offset,
                        "index child exceeds initialized allocation",
                    ));
                }
                scan.work.reserve(u64::from(self.block_bytes))?;
                let bytes =
                    self.volume
                        .read(self.cx, allocation, offset, self.block_bytes as usize)?;
                let child = parse_index_block(&bytes, vcn).map_err(|error| parse(&error))?;
                self.visit(scan, child, depth + 1)?;
            }
            if let Some((reference, filename)) = entry.key {
                scan.entry(true)?;
                let folded: Vec<_> = filename
                    .name
                    .iter()
                    .map(|unit| self.upcase[usize::from(*unit)])
                    .collect();
                if self
                    .previous
                    .as_ref()
                    .is_some_and(|previous| *previous > folded)
                {
                    return Err(corrupt(
                        0,
                        "native $I30 keys violate UpCase collation order",
                    ));
                }
                self.previous = Some(folded);
                if filename.parent != self.parent {
                    return Err(corrupt(
                        0,
                        "index key has the wrong native parent reference",
                    ));
                }
                let identity = Identity::new(reference, filename);
                if (identity.name == [46] || identity.name == [46, 46]) && !identity.root_dot() {
                    return Err(corrupt(0, "index contains an invalid dot identity"));
                }
                if !scan.keys.insert(identity) {
                    scan.report.issue(
                        self.parent.record,
                        "duplicate_index_entry",
                        "$I30 repeats a native name identity",
                    );
                }
            }
        }
        Ok(())
    }
}

fn upcase(volume: &NtfsVolume, cx: &Cx, allocated: &[u8], scan: &mut Scan) -> Result<Vec<u16>> {
    if scan.report.initialized_records <= 10 || !bit(allocated, 10) {
        return Err(corrupt(
            0,
            "$UpCase is not allocated within initialized MFT data",
        ));
    }
    scan.work
        .reserve(u64::from(volume.geometry.record_bytes()))?;
    let record = volume.record(cx, 10, None)?;
    let attrs = catalog(
        volume,
        cx,
        &record,
        &mut scan.work,
        Some(allocated),
        scan.report.logical_records,
    )?;
    let stream = attrs.select(&volume.geometry, DATA, &[])?;
    if stream.size != 131_072
        || stream.initialized != stream.size
        || !matches!(&stream.storage, Storage::Mapped(runs) if runs.iter().all(|run| run.lcn.is_some()))
    {
        return Err(corrupt(0, "invalid initialized plain $UpCase stream"));
    }
    let bytes = scan.read(volume, cx, &stream)?;
    let table: Vec<_> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|word| u16::from_le_bytes(*word))
        .collect();
    for (index, &upper) in table.iter().enumerate() {
        if index.is_multiple_of(1024) {
            checkpoint(cx)?;
        }
        if table[usize::from(upper)] != upper {
            return Err(corrupt(0, "non-idempotent native UpCase mapping"));
        }
    }
    for lower in b'a'..=b'z' {
        if table[usize::from(lower)] != u16::from(lower.to_ascii_uppercase()) {
            return Err(corrupt(0, "invalid native UpCase ASCII mapping"));
        }
    }
    Ok(table)
}

impl NtfsVolume {
    /// Compare allocated base FILE_NAME catalogs with every native directory
    /// index, then derive reachability only after complete bounded inspection.
    /// This does not read ordinary file payloads, replay a log or write bytes.
    pub fn check_namespace(&self, cx: &Cx, limits: NamespaceLimits) -> Result<NamespaceReport> {
        checkpoint(cx)?;
        limits.validate()?;
        if self.volume_flags != 0
            || self.logfile_recovery.is_some()
            || !self.source.overlay.is_empty()
        {
            return Err(unsupported(
                "namespace checking requires original clean-flag bytes without a recovery overlay",
            ));
        }
        let record_bytes = u64::from(self.geometry.record_bytes());
        let records = self.mft.size / record_bytes;
        let mut scan = Scan {
            work: Work {
                used: 0,
                limit: limits.metadata_bytes,
                stopped: false,
            },
            entry_limit: limits.entries,
            report: NamespaceReport {
                logical_records: records,
                initialized_records: self.record_count(),
                complete: true,
                ..NamespaceReport::default()
            },
            records: BTreeMap::new(),
            names: BTreeSet::new(),
            keys: BTreeSet::new(),
        };
        if records > limits.records {
            scan.report.stop("MFT record budget");
            return Ok(scan.report);
        }
        let authority = (|| -> Result<(Vec<u8>, Vec<u16>)> {
            scan.work.reserve(record_bytes)?;
            let mft = self.record(cx, 0, None)?;
            let attrs = catalog(self, cx, &mft, &mut scan.work, None, records)?;
            let bitmap = attrs.select(&self.geometry, 0xB0, &[])?;
            scan.work.reserve(records.div_ceil(8))?;
            let allocated = read_bitmap(cx, self, &bitmap, records)?;
            if records == 0 || !bit(&allocated, 0) {
                return Err(corrupt(
                    0,
                    "$MFT bitmap does not allocate its own base record",
                ));
            }
            let table = upcase(self, cx, &allocated, &mut scan)?;
            Ok((allocated, table))
        })();
        let (allocated, table) = match authority {
            Ok(authority) => authority,
            Err(_) if scan.work.stopped => {
                scan.report.stop("metadata work budget");
                scan.report.metadata_bytes_attempted = scan.work.used;
                checkpoint(cx)?;
                return Ok(scan.report);
            }
            Err(error) => return Err(error),
        };
        for number in 0..records {
            checkpoint(cx)?;
            scan.report.record_slots_examined += 1;
            if !bit(&allocated, number) {
                continue;
            }
            let result = (|| -> Result<()> {
                if number >= scan.report.initialized_records {
                    return Err(corrupt(0, "allocated FILE is beyond initialized MFT data"));
                }
                scan.work.reserve(record_bytes)?;
                let record = self.record(cx, number, None)?;
                if record.base.record != 0 || record.base.sequence != 0 {
                    return Ok(());
                }
                scan.report.base_records_examined += 1;
                let attrs = catalog(self, cx, &record, &mut scan.work, Some(&allocated), records)?;
                let named = scan.file_names(&record, &attrs, cx)?;
                scan.records.insert(
                    number,
                    Record {
                        sequence: record.sequence,
                        directory: record.is_directory(),
                        named,
                    },
                );
                if record.is_directory() {
                    scan.directory(self, cx, &record, &attrs, &table)?;
                }
                Ok(())
            })();
            if let Err(error) = result {
                if scan.work.stopped {
                    scan.report.stop("metadata work budget");
                    break;
                }
                if scan.report.limit_reached.is_some() {
                    break;
                }
                scan.report.failed_record(number, error)?;
            }
        }
        scan.report.metadata_bytes_attempted = scan.work.used;
        if scan.report.complete {
            scan.reconcile(cx)?;
        }
        checkpoint(cx)?;
        Ok(scan.report)
    }
}
