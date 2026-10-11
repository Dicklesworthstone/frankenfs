//! Non-mutating allocation/namespace consistency checks for admitted FAT images.
//!
//! Ownership is evidence of reachability, never repair authority. In particular,
//! unreadable directories or disagreeing FATs suppress lost-allocation claims:
//! a cluster not reached by an incomplete scan is not proved to be an orphan.

use super::{
    Cx, Directory, Entry, FatDirectoryDecoder, FatEntry, FatKind, FatTable, FatVolume, FfsError,
    MAX_CHAIN_CLUSTERS, MAX_DIRECTORY_SLOTS, Result, allocate, checkpoint, corrupt,
};
use serde::Serialize;
use std::collections::{BTreeMap, VecDeque};

const UNKNOWN_ENTRY: u32 = u32::MAX;
const MAX_OBJECTS: usize = 131_072;
const MAX_TOTAL_DIRECTORY_SLOTS: u64 = 4_194_304;
const MAX_FINDINGS: usize = 1024;

#[derive(Debug, Serialize)]
pub struct CheckIssue {
    pub kind: &'static str,
    /// Volume-relative short-entry offset; None identifies the root or FAT.
    pub entry_offset: Option<u64>,
    pub cluster: Option<u32>,
    /// For a cross-link this identifies the other directory-entry owner.
    pub other_entry_offset: Option<u64>,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct FatCheckReport {
    pub format: &'static str,
    pub read_only: bool,
    pub scope: &'static str,
    pub status: &'static str,
    pub clean: bool,
    /// False if namespace reachability or required allocation evidence is incomplete.
    pub namespace_complete: bool,
    pub complete: bool,
    pub volume_offset: u64,
    pub volume_bytes: u64,
    pub data_clusters: u32,
    pub scanned_clusters: u64,
    pub free_clusters: u64,
    pub allocated_clusters: u64,
    pub bad_clusters: u64,
    pub reserved_clusters: u64,
    pub conflicting_clusters: u64,
    pub referenced_clusters: u64,
    /// Reachable file allocation beyond EOF; allowed by the admitted read profile.
    pub preallocated_clusters: u64,
    pub files: u64,
    /// Includes the native root, even when FAT16 stores it outside the chains.
    pub directories: u64,
    /// None when full namespace reachability cannot be established.
    pub lost_clusters: Option<u64>,
    pub fs_info_free_hint: Option<u32>,
    pub issues: Vec<CheckIssue>,
    pub omitted_issues: u64,
}

impl FatCheckReport {
    pub fn is_clean(&self) -> bool {
        self.complete && self.issues.is_empty() && self.omitted_issues == 0
    }

    fn finding(
        &mut self,
        kind: &'static str,
        entry_offset: Option<u64>,
        cluster: Option<u32>,
        detail: impl Into<String>,
    ) {
        self.record(CheckIssue {
            kind,
            entry_offset,
            cluster,
            other_entry_offset: None,
            detail: detail.into(),
        });
    }

    fn record(&mut self, issue: CheckIssue) {
        if self.issues.len() < MAX_FINDINGS {
            self.issues.push(issue);
        } else {
            self.omitted_issues += 1;
        }
    }
}

#[derive(Clone, Copy)]
struct PendingDirectory {
    directory: Directory,
    owner: u32,
    parent_cluster: u32,
    depth: u16,
}

#[derive(Default)]
struct DirectoryScan {
    decoder: FatDirectoryDecoder,
    entries: Vec<Entry>,
    slots: u64,
}

struct Checker<'a> {
    volume: &'a FatVolume,
    fat: Vec<u32>,
    owners: Vec<u32>,
    owner_offsets: Vec<Option<u64>>,
    report: FatCheckReport,
    directory_slots: u64,
    chain_steps: usize,
}

fn words(length: usize) -> Result<Vec<u32>> {
    let mut values = Vec::new();
    values
        .try_reserve_exact(length)
        .map_err(|error| FfsError::Format(format!("FAT checker allocation failed: {error}")))?;
    values.resize(length, 0);
    Ok(values)
}

impl FatVolume {
    /// Check allocation ownership, chain lengths, directory structure and the
    /// primary FAT32 FSInfo hints. This reads no file payload and performs no
    /// repair, replay, state change, flush, or guessed selection of a FAT copy.
    /// Native OEM/Unicode collation and content integrity are separate checks.
    pub fn check(&self, cx: &Cx) -> Result<FatCheckReport> {
        checkpoint(cx)?;
        let count = self.geometry.cluster_count() as usize;
        if count > MAX_CHAIN_CLUSTERS {
            return Err(FfsError::UnsupportedFeature(format!(
                "FAT checker supports at most {MAX_CHAIN_CLUSTERS} data clusters"
            )));
        }
        let mut checker = Checker {
            volume: self,
            fat: words(count + 2)?,
            owners: words(count + 2)?,
            owner_offsets: vec![None, None], // zero is unowned; one is the root.
            report: FatCheckReport {
                format: match self.geometry.kind() {
                    FatKind::Fat16 => "Fat16",
                    FatKind::Fat32 => "Fat32",
                },
                read_only: true,
                scope: "allocation ownership, chain lengths, directory structure and primary FSInfo; file-content integrity, full native name collation and repair are not covered",
                status: "incomplete",
                clean: false,
                namespace_complete: true,
                complete: true,
                volume_offset: self.base,
                volume_bytes: self.geometry.volume_bytes(),
                data_clusters: self.geometry.cluster_count(),
                scanned_clusters: 0,
                free_clusters: 0,
                allocated_clusters: 0,
                bad_clusters: 0,
                reserved_clusters: 0,
                conflicting_clusters: 0,
                referenced_clusters: 0,
                preallocated_clusters: 0,
                files: 0,
                directories: 1,
                lost_clusters: None,
                fs_info_free_hint: None,
                issues: Vec::new(),
                omitted_issues: 0,
            },
            directory_slots: 0,
            chain_steps: 0,
        };
        checker.scan_allocation(cx)?;
        checker.walk_namespace(cx)?;
        checker.find_lost_allocation(cx)?;
        checker.check_fs_info(cx)?;
        checkpoint(cx)?;
        checker.report.namespace_complete = checker.report.complete;
        checker.report.clean = checker.report.is_clean();
        checker.report.status = if !checker.report.complete {
            "incomplete"
        } else if checker.report.clean {
            "clean"
        } else {
            "issues_found"
        };
        Ok(checker.report)
    }
}

impl Checker<'_> {
    fn scan_allocation(&mut self, cx: &Cx) -> Result<()> {
        let geometry = &self.volume.geometry;
        let mut table = FatTable::new(self.volume);
        for cluster in 2..=geometry.cluster_count() + 1 {
            checkpoint(cx)?;
            if geometry.cluster_offset(cluster).is_err() {
                self.fat[cluster as usize] = UNKNOWN_ENTRY;
                self.report.complete = false;
                self.report.finding(
                    "unaddressable_cluster",
                    None,
                    Some(cluster),
                    "BPB data region extends into reserved cluster numbers",
                );
                continue;
            }
            let mut value = None;
            let mut conflict = false;
            for copy in self.volume.copies() {
                let current = table.raw_entry(cx, copy, cluster)?;
                if value.is_some_and(|previous| previous != current) {
                    conflict = true;
                }
                value = Some(current);
            }
            self.report.scanned_clusters += 1;
            let raw = value.ok_or_else(|| FfsError::Format("no admitted FAT copy".into()))?;
            if conflict {
                self.fat[cluster as usize] = UNKNOWN_ENTRY;
                self.report.conflicting_clusters += 1;
                self.report.complete = false;
                self.report.finding(
                    "fat_copies_disagree",
                    None,
                    Some(cluster),
                    "mirrored copies disagree; neither value was selected",
                );
                continue;
            }
            self.fat[cluster as usize] = raw;
            match geometry.kind().decode_entry(raw) {
                FatEntry::Free => self.report.free_clusters += 1,
                FatEntry::Bad => self.report.bad_clusters += 1,
                FatEntry::Reserved => {
                    self.report.reserved_clusters += 1;
                    self.report.finding(
                        "reserved_allocation",
                        None,
                        Some(cluster),
                        "reserved FAT value in the data-cluster namespace",
                    );
                }
                FatEntry::End => self.report.allocated_clusters += 1,
                FatEntry::Next(next) => {
                    self.report.allocated_clusters += 1;
                    if geometry.cluster_offset(next).is_err() {
                        self.report.finding(
                            "invalid_successor",
                            None,
                            Some(cluster),
                            format!("successor {next} is not an addressable data cluster"),
                        );
                    }
                }
            }
        }
        Ok(())
    }

    /// Retain every native owner conflict without assigning a preferred owner.
    /// Revisited suffixes share a global work budget. Brent cycle detection also
    /// covers a cycle whose clusters all belong to a different object.
    fn claim_chain(&mut self, cx: &Cx, first: u32, owner: u32) -> Result<Option<u64>> {
        let offset = self.owner_offsets[owner as usize];
        let mut cluster = first;
        let mut length = 0_u64;
        let mut exclusive = true;
        let mut anchor = first;
        let mut power = 1_u64;
        let mut distance = 0_u64;
        loop {
            checkpoint(cx)?;
            if self.volume.geometry.cluster_offset(cluster).is_err() {
                self.report.finding(
                    "invalid_chain_cluster",
                    offset,
                    Some(cluster),
                    "chain references an unaddressable cluster",
                );
                return Ok(None);
            }
            if self.chain_steps == MAX_CHAIN_CLUSTERS {
                self.report.complete = false;
                self.report.finding(
                    "chain_work_limit",
                    offset,
                    Some(cluster),
                    "total chain traversal exceeds the bounded checker work budget",
                );
                return Ok(None);
            }
            self.chain_steps += 1;
            let previous = self.owners[cluster as usize];
            if previous == owner {
                self.report.finding(
                    "cyclic_chain",
                    offset,
                    Some(cluster),
                    "allocation chain returns to a previously visited cluster",
                );
                return Ok(None);
            }
            if previous != 0 {
                exclusive = false;
                self.report.record(CheckIssue {
                    kind: "cross_link",
                    entry_offset: offset,
                    cluster: Some(cluster),
                    other_entry_offset: self.owner_offsets[previous as usize],
                    detail:
                        "multiple native objects reference this allocation; ownership is ambiguous"
                            .into(),
                });
            } else {
                self.owners[cluster as usize] = owner;
                self.report.referenced_clusters += 1;
            }
            length += 1;
            let raw = self.fat[cluster as usize];
            if raw == UNKNOWN_ENTRY {
                return Ok(None);
            }
            match self.volume.geometry.kind().decode_entry(raw) {
                FatEntry::End => return Ok(exclusive.then_some(length)),
                FatEntry::Next(next) => {
                    distance += 1;
                    if next == anchor {
                        self.report.finding(
                            "cyclic_chain",
                            offset,
                            Some(next),
                            "allocation chain returns to a previously visited cluster",
                        );
                        return Ok(None);
                    }
                    if distance == power {
                        anchor = next;
                        power *= 2;
                        distance = 0;
                    }
                    cluster = next;
                }
                state => {
                    self.report.finding(
                        "invalid_live_chain",
                        offset,
                        Some(cluster),
                        format!("live allocation chain contains a {state:?} entry"),
                    );
                    return Ok(None);
                }
            }
        }
    }

    fn walk_namespace(&mut self, cx: &Cx) -> Result<()> {
        let mut pending = VecDeque::from([PendingDirectory {
            directory: Directory::Root,
            owner: 1,
            parent_cluster: 0,
            depth: 0,
        }]);
        while let Some(directory) = pending.pop_front() {
            checkpoint(cx)?;
            let Some(bytes) = self.directory_bytes(cx, directory)? else {
                continue;
            };
            let slots = bytes / 32;
            self.directory_slots += slots;
            if slots > MAX_DIRECTORY_SLOTS as u64
                || self.directory_slots > MAX_TOTAL_DIRECTORY_SLOTS
            {
                self.report.complete = false;
                self.report.finding(
                    "directory_work_limit",
                    self.owner_offsets[directory.owner as usize],
                    None,
                    "directory allocation exceeds the bounded checker work budget",
                );
                continue;
            }
            let entries = self.directory_records(cx, directory)?;
            self.check_directory_names(cx, &entries)?;
            for entry in entries {
                checkpoint(cx)?;
                if self.owner_offsets.len() > MAX_OBJECTS {
                    self.report.complete = false;
                    self.report.finding(
                        "object_work_limit",
                        Some(entry.offset),
                        None,
                        "namespace exceeds the bounded checker object budget",
                    );
                    return Ok(());
                }
                let owner = u32::try_from(self.owner_offsets.len())
                    .map_err(|_| FfsError::Format("FAT checker owner index overflow".into()))?;
                self.owner_offsets.push(Some(entry.offset));
                if entry.native.is_directory() {
                    self.report.directories += 1;
                    self.enqueue_directory(directory, &entry, owner, &mut pending);
                } else {
                    self.report.files += 1;
                    self.check_file(cx, &entry, owner)?;
                }
            }
        }
        Ok(())
    }

    fn directory_bytes(&mut self, cx: &Cx, directory: PendingDirectory) -> Result<Option<u64>> {
        let first = match directory.directory {
            Directory::Root => {
                if let Some((_, bytes)) = self.volume.geometry.fixed_root() {
                    return Ok(Some(bytes));
                }
                self.volume.geometry.root_cluster()
            }
            Directory::Cluster(first) => first,
        };
        let length = self.claim_chain(cx, first, directory.owner)?;
        if length.is_none() {
            self.report.complete = false;
        }
        Ok(length.map(|count| count * u64::from(self.volume.geometry.cluster_bytes())))
    }

    fn enqueue_directory(
        &mut self,
        parent: PendingDirectory,
        entry: &Entry,
        owner: u32,
        pending: &mut VecDeque<PendingDirectory>,
    ) {
        if entry.native.size != 0 {
            self.report.finding(
                "directory_size",
                Some(entry.offset),
                Some(entry.native.first_cluster),
                "native FAT directory size field must be zero",
            );
        }
        if parent.depth >= 256 {
            self.report.complete = false;
            self.report.finding(
                "directory_depth_limit",
                Some(entry.offset),
                Some(entry.native.first_cluster),
                "directory nesting exceeds the bounded checker depth",
            );
            return;
        }
        pending.push_back(PendingDirectory {
            directory: Directory::Cluster(entry.native.first_cluster),
            owner,
            parent_cluster: match parent.directory {
                Directory::Root => 0,
                Directory::Cluster(first) => first,
            },
            depth: parent.depth + 1,
        });
    }

    /// Unlike the ordinary reader, a checker cannot silently discard malformed
    /// LFN sets or misplaced dot records. The pure decoder still owns all native
    /// grammar; this pass retains its diagnostics and every short-entry owner.
    fn directory_records(&mut self, cx: &Cx, directory: PendingDirectory) -> Result<Vec<Entry>> {
        let fixed = if directory.directory == Directory::Root {
            self.volume.geometry.fixed_root()
        } else {
            None
        };
        let mut cluster = match directory.directory {
            Directory::Root => self.volume.geometry.root_cluster(),
            Directory::Cluster(first) => first,
        };
        let buffer_size = if fixed.is_some() {
            self.volume.geometry.sector_bytes()
        } else {
            self.volume.geometry.cluster_bytes()
        };
        let mut bytes = allocate(buffer_size as usize)?;
        let mut fixed_done = 0_u64;
        let mut scan = DirectoryScan::default();
        loop {
            checkpoint(cx)?;
            let offset = if let Some((start, _)) = fixed {
                start + fixed_done
            } else {
                self.volume.cluster_offset(cluster)?
            };
            self.volume.read_exact(cx, offset, &mut bytes)?;
            for (index, slot) in bytes.as_chunks::<32>().0.iter().enumerate() {
                checkpoint(cx)?;
                self.check_directory_slot(directory, &mut scan, slot, offset + index as u64 * 32);
                scan.slots += 1;
                if scan.decoder.ended() {
                    break;
                }
            }
            if scan.decoder.ended() {
                break;
            }
            if let Some((_, length)) = fixed {
                fixed_done += u64::from(buffer_size);
                if fixed_done == length {
                    break;
                }
            } else {
                match self
                    .volume
                    .geometry
                    .kind()
                    .decode_entry(self.fat[cluster as usize])
                {
                    FatEntry::Next(next) => cluster = next,
                    FatEntry::End => break,
                    _ => return Err(corrupt(offset, "checked directory chain changed")),
                }
            }
        }
        scan.decoder.finish();
        if scan.decoder.has_malformed_long_name() {
            self.report.finding(
                "invalid_long_name",
                self.owner_offsets[directory.owner as usize],
                None,
                "directory contains a malformed or orphaned long-name record set",
            );
        }
        Ok(scan.entries)
    }

    fn check_directory_slot(
        &mut self,
        directory: PendingDirectory,
        scan: &mut DirectoryScan,
        slot: &[u8; 32],
        offset: u64,
    ) {
        let native = match scan.decoder.push(slot, self.volume.geometry.kind()) {
            Ok(native) => native,
            Err(error) => {
                self.report.complete = false;
                self.report.finding(
                    "unreadable_directory",
                    Some(offset),
                    None,
                    error.to_string(),
                );
                return;
            }
        };
        if let Directory::Cluster(first) = directory.directory
            && scan.slots < 2
        {
            let (name, expected) = if scan.slots == 0 {
                (*b".          ", first)
            } else {
                (*b"..         ", directory.parent_cluster)
            };
            if !matches!(native, Some(ref entry) if entry.short_name == name
                && entry.is_directory() && entry.first_cluster == expected && entry.size == 0)
            {
                self.report.finding(
                    "parent_link",
                    Some(offset),
                    Some(first),
                    format!(
                        "directory slot {} must identify native cluster {expected}",
                        scan.slots
                    ),
                );
            }
        }
        let Some(native) = native else {
            return;
        };
        if native.short_name == *b".          " || native.short_name == *b"..         " {
            if directory.directory == Directory::Root || scan.slots >= 2 {
                self.report.finding(
                    "misplaced_dot_entry",
                    Some(offset),
                    Some(native.first_cluster),
                    "dot entries are permitted only in the first two non-root directory slots",
                );
            }
            return;
        }
        scan.entries.push(Entry { offset, native });
    }

    fn check_directory_names(&mut self, cx: &Cx, entries: &[Entry]) -> Result<()> {
        let mut short_names = BTreeMap::new();
        let mut native_names = BTreeMap::new();
        for entry in entries {
            checkpoint(cx)?;
            let short = entry
                .native
                .short_name
                .map(|byte| byte.to_ascii_uppercase());
            let mut other = short_names.insert(short, entry.offset);
            let alias = entry.native.ascii_short_name();
            if entry.native.short_name.is_ascii()
                && entry.native.short_name[0] != 5
                && alias.is_none()
            {
                self.report.finding(
                    "invalid_short_name",
                    Some(entry.offset),
                    None,
                    "short name cannot represent a native ASCII path component",
                );
            }
            let alias_units = alias
                .as_ref()
                .map(|name| name.encode_utf16().collect::<Vec<_>>());
            if let Some(long) = &entry.native.long_name
                && (long.as_slice() == [46]
                    || long.as_slice() == [46, 46]
                    || long.iter().any(|unit| matches!(*unit, 0x2F | 0x5C)))
            {
                self.report.finding(
                    "invalid_long_name",
                    Some(entry.offset),
                    None,
                    "long name is not a native path component",
                );
            }
            for candidate in alias_units.iter().chain(entry.native.long_name.iter()) {
                let key: Vec<_> = candidate
                    .iter()
                    .map(|&unit| {
                        if (u16::from(b'a')..=u16::from(b'z')).contains(&unit) {
                            unit - 32
                        } else {
                            unit
                        }
                    })
                    .collect();
                if let Some(previous) = native_names.insert(key, entry.offset)
                    && previous != entry.offset
                {
                    other.get_or_insert(previous);
                }
            }
            if let Some(other) = other {
                self.report.record(CheckIssue {
                    kind: "name_collision",
                    entry_offset: Some(entry.offset),
                    cluster: None,
                    other_entry_offset: Some(other),
                    detail: "duplicate native short name, long name, or ASCII alias".into(),
                });
            }
        }
        Ok(())
    }

    fn check_file(&mut self, cx: &Cx, entry: &Entry, owner: u32) -> Result<()> {
        let expected =
            u64::from(entry.native.size).div_ceil(u64::from(self.volume.geometry.cluster_bytes()));
        let actual = if entry.native.first_cluster == 0 {
            Some(0)
        } else {
            self.claim_chain(cx, entry.native.first_cluster, owner)?
        };
        if let Some(actual) = actual {
            if actual < expected {
                self.report.finding(
                    "short_file_chain",
                    Some(entry.offset),
                    Some(entry.native.first_cluster),
                    format!("logical size requires {expected} clusters; chain contains {actual}"),
                );
            } else {
                // The ordinary reader admits reachable preallocation, including
                // allocated empty files. Count it without exposing it as data.
                self.report.preallocated_clusters += actual - expected;
            }
        }
        Ok(())
    }

    fn find_lost_allocation(&mut self, cx: &Cx) -> Result<()> {
        if !self.report.complete {
            return Ok(());
        }
        let mut count = 0_u64;
        let mut first = None;
        for cluster in 2..=self.volume.geometry.cluster_count() + 1 {
            checkpoint(cx)?;
            if self.owners[cluster as usize] == 0
                && matches!(
                    self.volume
                        .geometry
                        .kind()
                        .decode_entry(self.fat[cluster as usize]),
                    FatEntry::Next(_) | FatEntry::End
                )
            {
                count += 1;
                first.get_or_insert(cluster);
            }
        }
        self.report.lost_clusters = Some(count);
        if count != 0 {
            self.report.finding(
                "lost_allocation",
                None,
                first,
                format!("{count} allocated clusters are unreachable from the complete namespace"),
            );
        }
        Ok(())
    }

    fn check_fs_info(&mut self, cx: &Cx) -> Result<()> {
        let Some(sector) = self.volume.geometry.fs_info_sector() else {
            return Ok(());
        };
        let offset = u64::from(sector) * u64::from(self.volume.geometry.sector_bytes());
        let mut bytes = [0_u8; 512];
        self.volume.read_exact(cx, offset, &mut bytes)?;
        let word = |at: usize| {
            u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
        };
        if word(0) != 0x4161_5252 || word(484) != 0x6141_7272 || word(508) != 0xAA55_0000 {
            self.report.finding(
                "fs_info_signature",
                Some(offset),
                None,
                format!("invalid FAT32 FSInfo signatures at volume byte {offset}"),
            );
            return Ok(());
        }
        let free = word(488);
        self.report.fs_info_free_hint = (free != u32::MAX).then_some(free);
        if free != u32::MAX
            && (free > self.volume.geometry.cluster_count()
                || (self.report.conflicting_clusters == 0
                    && self.report.scanned_clusters == u64::from(self.report.data_clusters)
                    && u64::from(free) != self.report.free_clusters))
        {
            self.report.finding(
                "fs_info_free_count",
                Some(offset + 488),
                None,
                format!("FSInfo free-count hint {free} disagrees with checked allocation"),
            );
        }
        // Linux and dosfstools can store the last allocated cluster here. This
        // is a search hint, not proof that the named cluster is currently free.
        let next = word(492);
        if next != u32::MAX && self.volume.geometry.cluster_offset(next).is_err() {
            self.report.finding(
                "fs_info_next_free",
                Some(offset + 492),
                Some(next),
                "FSInfo search hint is outside the addressable data clusters",
            );
        }
        Ok(())
    }
}
