//! Bounded, non-mutating allocation and namespace checks for admitted FAT images.
//!
//! This checks structural reachability, not file-content integrity or the complete
//! FAT specification. A skipped cross-linked directory makes lost-allocation
//! classification inconclusive; it can never produce a clean result.

use super::{
    Directory, Entry, FatTable, FatVolume, MAX_CHAIN_CLUSTERS, MAX_DIRECTORY_SLOTS, checkpoint,
};
use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::fat::{FatEntry, FatKind};
use serde::Serialize;
use std::collections::BTreeMap;

const MAX_CHECK_OBJECTS: usize = 131_072;
const MAX_CHECK_DIRECTORY_BYTES: u64 = 128 * 1024 * 1024;
const MAX_CHECK_ISSUES: usize = 1024;

#[derive(Debug, Serialize)]
pub struct CheckIssue {
    pub kind: &'static str,
    pub entry_offset: Option<u64>,
    pub cluster: Option<u32>,
    pub other_entry_offset: Option<u64>,
    pub detail: String,
}

#[derive(Debug, Serialize)]
pub struct FatCheckReport {
    pub format: &'static str,
    pub read_only: bool,
    pub scope: &'static str,
    pub clean: bool,
    pub namespace_complete: bool,
    pub files: u64,
    pub directories: u64,
    pub scanned_clusters: u64,
    pub allocated_clusters: u64,
    pub free_clusters: u64,
    pub bad_clusters: u64,
    /// Reachable file allocation beyond EOF; allowed by this read profile.
    pub preallocated_clusters: u64,
    /// None means a directory could not be uniquely traversed.
    pub lost_clusters: Option<u64>,
    pub fs_info_free_hint: Option<u32>,
    pub issues: Vec<CheckIssue>,
    pub omitted_issues: u64,
}

impl FatCheckReport {
    fn issue(&mut self, issue: CheckIssue) {
        if self.issues.len() < MAX_CHECK_ISSUES {
            self.issues.push(issue);
        } else {
            self.omitted_issues += 1;
        }
    }
}

struct PendingDirectory {
    directory: Directory,
    entry_offset: Option<u64>,
    parent_cluster: u32,
    depth: u16,
}

struct Checker<'a> {
    volume: &'a FatVolume,
    owners: Vec<u32>,
    owner_offsets: Vec<Option<u64>>,
    traversed_clusters: usize,
    directory_bytes: u64,
    report: FatCheckReport,
}

impl FatVolume {
    /// Check allocation ownership and admitted directory reachability without
    /// reading file payloads or modifying backing bytes. Resource, I/O, malformed
    /// chain and unsupported-name failures return errors, never a clean report.
    pub fn check(&self, cx: &Cx) -> Result<FatCheckReport> {
        checkpoint(cx)?;
        let count = self.geometry.cluster_count() as usize;
        if count > MAX_CHAIN_CLUSTERS {
            return Err(FfsError::UnsupportedFeature(
                "FAT allocation check exceeds 8388608 data clusters".into(),
            ));
        }
        let mut owners = Vec::new();
        owners
            .try_reserve_exact(count + 2)
            .map_err(|error| FfsError::Format(format!("FAT ownership allocation failed: {error}")))?;
        owners.resize(count + 2, 0);
        let mut checker = Checker {
            volume: self,
            owners,
            owner_offsets: vec![None],
            traversed_clusters: 0,
            directory_bytes: 0,
            report: FatCheckReport {
                format: match self.geometry.kind() {
                    FatKind::Fat16 => "Fat16",
                    FatKind::Fat32 => "Fat32",
                },
                read_only: true,
                scope: "allocation, directory reachability, parent links, ASCII name collisions and FSInfo; not file-content verification or complete native fsck",
                clean: false,
                namespace_complete: true,
                files: 0,
                directories: 0,
                scanned_clusters: 0,
                allocated_clusters: 0,
                free_clusters: 0,
                bad_clusters: 0,
                preallocated_clusters: 0,
                lost_clusters: None,
                fs_info_free_hint: None,
                issues: Vec::new(),
                omitted_issues: 0,
            },
        };
        let mut pending = vec![PendingDirectory {
            directory: Directory::Root,
            entry_offset: None,
            parent_cluster: 0,
            depth: 0,
        }];
        let mut discovered = 1_usize;
        while let Some(directory) = pending.pop() {
            checkpoint(cx)?;
            let entries = checker.directory(cx, &directory)?;
            discovered = discovered
                .checked_add(entries.len())
                .ok_or_else(|| FfsError::Format("FAT object-count overflow".into()))?;
            if discovered > MAX_CHECK_OBJECTS {
                return Err(FfsError::UnsupportedFeature(
                    "FAT allocation check exceeds 131072 namespace objects".into(),
                ));
            }
            checker.names(cx, &entries)?;
            let parent_cluster = match directory.directory {
                Directory::Root => 0, // Native '..' names the root with zero, even on FAT32.
                Directory::Cluster(cluster) => cluster,
            };
            for entry in entries {
                checkpoint(cx)?;
                if entry.native.is_directory() {
                    if directory.depth == 256 {
                        return Err(FfsError::UnsupportedFeature(
                            "FAT allocation check exceeds 256 directory levels".into(),
                        ));
                    }
                    if entry.native.size != 0 {
                        checker.report.issue(CheckIssue {
                            kind: "directory_size",
                            entry_offset: Some(entry.offset),
                            cluster: Some(entry.native.first_cluster),
                            other_entry_offset: None,
                            detail: "native FAT directory size must be zero".into(),
                        });
                    }
                    pending.push(PendingDirectory {
                        directory: entry.directory()?,
                        entry_offset: Some(entry.offset),
                        parent_cluster,
                        depth: directory.depth + 1,
                    });
                } else {
                    checker.file(cx, &entry)?;
                }
            }
        }
        checker.scan_allocation(cx)?;
        checker.fs_info(cx)?;
        checkpoint(cx)?;
        checker.report.clean = checker.report.namespace_complete
            && checker.report.issues.is_empty()
            && checker.report.omitted_issues == 0;
        Ok(checker.report)
    }
}

impl Checker<'_> {
    fn claim(&mut self, cx: &Cx, clusters: &[u32], entry_offset: Option<u64>) -> Result<bool> {
        checkpoint(cx)?;
        self.traversed_clusters = self
            .traversed_clusters
            .checked_add(clusters.len())
            .ok_or_else(|| FfsError::Format("FAT traversal-count overflow".into()))?;
        if self.traversed_clusters > MAX_CHAIN_CLUSTERS {
            return Err(FfsError::UnsupportedFeature(
                "FAT allocation check exceeds its total chain-work limit".into(),
            ));
        }
        let owner = u32::try_from(self.owner_offsets.len())
            .map_err(|_| FfsError::Format("FAT ownership identifier overflow".into()))?;
        if self.owner_offsets.len() > MAX_CHECK_OBJECTS {
            return Err(FfsError::UnsupportedFeature(
                "FAT allocation check exceeds its ownership limit".into(),
            ));
        }
        self.owner_offsets.push(entry_offset);
        let mut exclusive = true;
        for &cluster in clusters {
            checkpoint(cx)?;
            let previous = self.owners[cluster as usize];
            if previous == 0 {
                self.owners[cluster as usize] = owner;
            } else {
                exclusive = false;
                self.report.issue(CheckIssue {
                    kind: "cross_link",
                    entry_offset,
                    cluster: Some(cluster),
                    other_entry_offset: self.owner_offsets[previous as usize],
                    detail: "cluster is reachable from multiple namespace objects; no owner is selected for repair".into(),
                });
            }
        }
        Ok(exclusive)
    }

    fn directory(&mut self, cx: &Cx, pending: &PendingDirectory) -> Result<Vec<Entry>> {
        self.report.directories += 1;
        let geometry = &self.volume.geometry;
        let (clusters, bytes) = if pending.directory == Directory::Root
            && let Some((_, bytes)) = geometry.fixed_root()
        {
            (Vec::new(), bytes)
        } else {
            let first = match pending.directory {
                Directory::Root => geometry.root_cluster(),
                Directory::Cluster(cluster) => cluster,
            };
            let clusters = self.volume.allocation_chain(
                cx,
                first,
                1,
                pending.entry_offset.unwrap_or(0),
                (MAX_DIRECTORY_SLOTS * 32).div_ceil(geometry.cluster_bytes() as usize),
            )?;
            let bytes = clusters.len() as u64 * u64::from(geometry.cluster_bytes());
            (clusters, bytes)
        };
        if !self.claim(cx, &clusters, pending.entry_offset)? {
            // Re-reading shared directory slots would invent independent owners
            // and could recurse forever through a directory/ancestor alias.
            self.report.namespace_complete = false;
            return Ok(Vec::new());
        }
        self.directory_bytes += bytes;
        if self.directory_bytes > MAX_CHECK_DIRECTORY_BYTES {
            return Err(FfsError::UnsupportedFeature(
                "FAT allocation check exceeds 128 MiB of directory allocation".into(),
            ));
        }
        if let Directory::Cluster(first) = pending.directory {
            self.parent_links(cx, first, pending.parent_cluster, pending.entry_offset)?;
        }
        self.volume.list(cx, pending.directory)
    }

    fn file(&mut self, cx: &Cx, entry: &Entry) -> Result<()> {
        self.report.files += 1;
        let chain = self.volume.file_chain(cx, entry)?;
        self.claim(cx, &chain.clusters, Some(entry.offset))?;
        let required =
            u64::from(chain.size).div_ceil(u64::from(self.volume.geometry.cluster_bytes()));
        // Preallocation is admitted by the reader. Count it as reachable
        // allocation, without labelling it lost or selecting it for repair.
        self.report.preallocated_clusters += (chain.clusters.len() as u64) - required;
        Ok(())
    }

    fn names(&mut self, cx: &Cx, entries: &[Entry]) -> Result<()> {
        let mut names = BTreeMap::new();
        for entry in entries {
            checkpoint(cx)?;
            let name = entry.name()?;
            let alias = entry.native.ascii_short_name();
            for candidate in std::iter::once(name.as_str()).chain(alias.as_deref()) {
                let folded = candidate.to_ascii_lowercase();
                if let Some(previous) = names.insert(folded, entry.offset)
                    && previous != entry.offset
                {
                    self.report.issue(CheckIssue {
                        kind: "name_collision",
                        entry_offset: Some(entry.offset),
                        cluster: None,
                        other_entry_offset: Some(previous),
                        detail: "ambiguous display name or ASCII short alias".into(),
                    });
                }
            }
        }
        Ok(())
    }

    fn parent_links(
        &mut self,
        cx: &Cx,
        first: u32,
        parent: u32,
        entry_offset: Option<u64>,
    ) -> Result<()> {
        let offset = self.volume.cluster_offset(first)?;
        let mut slots = [0_u8; 64];
        self.volume.read_exact(cx, offset, &mut slots)?;
        for (index, name, expected) in [
            (0, b".          ", first),
            (1, b"..         ", parent),
        ] {
            let slot = &slots[index * 32..(index + 1) * 32];
            let low = u32::from(u16::from_le_bytes([slot[26], slot[27]]));
            let actual = match self.volume.geometry.kind() {
                FatKind::Fat16 => low,
                FatKind::Fat32 => {
                    low | (u32::from(u16::from_le_bytes([slot[20], slot[21]]) & 0x0FFF) << 16)
                }
            };
            let size = u32::from_le_bytes([slot[28], slot[29], slot[30], slot[31]]);
            if &slot[..11] != name
                || slot[11] & 0x10 == 0
                || slot[11] & 0xC8 != 0
                || actual != expected
                || size != 0
            {
                self.report.issue(CheckIssue {
                    kind: "parent_link",
                    entry_offset: Some(offset + index as u64 * 32),
                    cluster: Some(first),
                    other_entry_offset: entry_offset,
                    detail: format!(
                        "directory {} entry must reference cluster {expected} with zero size",
                        if index == 0 { "." } else { ".." }
                    ),
                });
            }
        }
        Ok(())
    }

    fn scan_allocation(&mut self, cx: &Cx) -> Result<()> {
        let mut table = FatTable::new(self.volume);
        let mut lost = 0_u64;
        let mut first_lost = None;
        for cluster in 2..=self.volume.geometry.cluster_count() + 1 {
            checkpoint(cx)?;
            if self.volume.geometry.cluster_offset(cluster).is_err() {
                continue; // Dialect-reserved cluster numbers are not allocatable.
            }
            self.report.scanned_clusters += 1;
            let entry = table.entry(cx, cluster)?;
            match entry {
                FatEntry::Free => self.report.free_clusters += 1,
                FatEntry::Bad => self.report.bad_clusters += 1,
                FatEntry::Reserved => self.report.issue(CheckIssue {
                    kind: "reserved_allocation",
                    entry_offset: None,
                    cluster: Some(cluster),
                    other_entry_offset: None,
                    detail: "reserved FAT value in an addressable data-cluster entry".into(),
                }),
                FatEntry::Next(_) | FatEntry::End => {
                    self.report.allocated_clusters += 1;
                    if let FatEntry::Next(next) = entry
                        && self.volume.geometry.cluster_offset(next).is_err()
                    {
                        self.report.issue(CheckIssue {
                            kind: "invalid_successor",
                            entry_offset: None,
                            cluster: Some(cluster),
                            other_entry_offset: None,
                            detail: format!("allocation points outside the legal cluster namespace: {next}"),
                        });
                    }
                    if self.owners[cluster as usize] == 0 {
                        lost += 1;
                        first_lost.get_or_insert(cluster);
                    }
                }
            }
        }
        if self.report.namespace_complete {
            self.report.lost_clusters = Some(lost);
            if lost != 0 {
                self.report.issue(CheckIssue {
                    kind: "lost_allocation",
                    entry_offset: None,
                    cluster: first_lost,
                    other_entry_offset: None,
                    detail: format!("{lost} allocated clusters are unreachable from the directory tree"),
                });
            }
        }
        Ok(())
    }

    fn fs_info(&mut self, cx: &Cx) -> Result<()> {
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
            self.report.issue(CheckIssue {
                kind: "fs_info_signature",
                entry_offset: Some(offset),
                cluster: None,
                other_entry_offset: None,
                detail: "FAT32 FSInfo signatures are invalid; hints are not trusted".into(),
            });
            return Ok(());
        }
        let free = word(488);
        if free != u32::MAX {
            self.report.fs_info_free_hint = Some(free);
            if u64::from(free) != self.report.free_clusters {
                self.report.issue(CheckIssue {
                    kind: "fs_info_free_count",
                    entry_offset: Some(offset + 488),
                    cluster: None,
                    other_entry_offset: None,
                    detail: format!(
                        "FSInfo hints at {free} free clusters; admitted FAT copies contain {}",
                        self.report.free_clusters
                    ),
                });
            }
        }
        let next = word(492);
        if next != u32::MAX && self.volume.geometry.cluster_offset(next).is_err() {
            self.report.issue(CheckIssue {
                kind: "fs_info_next_free",
                entry_offset: Some(offset + 492),
                cluster: Some(next),
                other_entry_offset: None,
                detail: "FSInfo search hint is outside the legal cluster namespace".into(),
            });
        }
        Ok(())
    }
}
