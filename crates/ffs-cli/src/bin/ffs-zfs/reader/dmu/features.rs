//! Native MOS read admission (OpenZFS zfs-2.3.0 zfeature.c/zfeature_common.c).
//!
//! Labels contain only active MOS/bootstrap features, not the complete set of
//! features required for reads. An unknown enabled-but-inactive feature is not
//! an unknown active feature. Write-only features do not authorize any writes.

use super::{Cx, Objects, Result, checkpoint, corrupt, unsupported};
use ffs_ondisk::zfs::nvlist::Value;
use ffs_ondisk::zfs_zap::Entry;
use std::collections::BTreeMap;

const MAX_FEATURES: usize = 1024;
const MAX_GUID_BYTES: usize = 255;
const EXTENSIBLE: &[&str] = &["com.delphix:extensible_dataset"];
const BOOKMARK_V2: &[&str] = &[
    "com.delphix:extensible_dataset",
    "com.delphix:bookmarks",
];
const REDACTION: &[&str] = &[
    "com.datto:bookmark_v2",
    "com.delphix:extensible_dataset",
    "com.delphix:bookmarks",
];

struct Policy {
    for_write: bool,
    mos: bool,
    read_supported: bool,
    dependencies: &'static [&'static str],
}

/// Native classification is independent of our implementation status. In
/// particular an unsupported read feature cannot move to the write-only map
/// and thereby evade admission. Unknown write-only GUIDs follow native RO
/// compatibility; reached structures still pass their ordinary parser gates.
fn policy(name: &str) -> Option<Policy> {
    let (for_write, mos, read_supported, dependencies): (_, _, _, &[&str]) = match name {
        "org.illumos:lz4_compress" | "com.delphix:extensible_dataset" =>
            (false, false, true, &[]),
        "com.delphix:embedded_data" => (false, true, true, &[]),
        "org.open-zfs:large_blocks" | "org.zfsonlinux:large_dnode"
        | "org.illumos:sha512" | "org.freebsd:zstd_compress" =>
            (false, false, true, EXTENSIBLE),
        "com.delphix:hole_birth" =>
            (false, true, true, &["com.delphix:enabled_txg"]),
        "org.illumos:skein" | "org.illumos:edonr" | "org.openzfs:blake3"
        | "com.delphix:redacted_datasets" | "org.zfsonlinux:longname" =>
            (false, false, false, EXTENSIBLE),
        "com.datto:encryption" => (false, false, false, &[
            "com.delphix:extensible_dataset", "com.datto:bookmark_v2",
        ]),
        "com.datto:bookmark_v2" => (false, false, false, BOOKMARK_V2),
        "com.delphix:redaction_bookmarks" | "com.delphix:bookmark_written" =>
            (false, false, false, REDACTION),
        "com.delphix:redaction_list_spill" =>
            (false, false, false, &["com.delphix:redaction_bookmarks"]),
        "com.joyent:multi_vdev_crash_dump" | "com.delphix:head_errlog" =>
            (false, false, false, &[]),
        "com.delphix:device_removal" | "org.openzfs:draid"
        | "com.klarasystems:vdev_zaps_v2" | "org.openzfs:raidz_expansion" =>
            (false, true, false, &[]),
        "com.delphix:async_destroy" | "com.delphix:empty_bpobj"
        | "com.delphix:spacemap_histogram" | "com.delphix:enabled_txg"
        | "com.delphix:zpool_checkpoint" | "com.delphix:spacemap_v2"
        | "org.zfsonlinux:allocation_classes" | "com.datto:resilver_defer"
        | "org.openzfs:device_rebuild" | "com.fudosecurity:block_cloning"
        | "com.klarasystems:fast_dedup" => (true, false, false, &[]),
        "com.delphix:bookmarks" | "com.joyent:filesystem_limits"
        | "com.delphix:livelist" | "org.zfsonlinux:userobj_accounting"
        | "org.zfsonlinux:project_quota" | "org.openzfs:zilsaxattr" =>
            (true, false, false, EXTENSIBLE),
        "com.delphix:log_spacemap" =>
            (true, false, false, &["com.delphix:spacemap_v2"]),
        "com.delphix:obsolete_counts" => (true, false, false, &[
            "com.delphix:extensible_dataset", "com.delphix:device_removal",
        ]),
        "com.klarasystems:large_microzap" => (true, false, false, &[
            "com.delphix:extensible_dataset", "org.open-zfs:large_blocks",
        ]),
        _ => return None,
    };
    Some(Policy { for_write, mos, read_supported, dependencies })
}

/// Bootstrap and full MOS admission share one implementation registry. Retain
/// the existing label spelling for lz4 although the pinned upstream registry
/// no longer marks it MOS-required. Ordinary dataset features do not belong in
/// this label allowlist just because their reached structures can be read.
pub(in super::super) fn supported_label_feature(name: &str, value: &Value) -> bool {
    matches!(value, Value::Boolean(true))
        && policy(name).is_some_and(|known| {
            !known.for_write && known.read_supported
                && (known.mos || name == "org.illumos:lz4_compress")
        })
}

fn guid(bytes: &[u8]) -> Result<&str> {
    if bytes.len() > MAX_GUID_BYTES {
        return Err(unsupported("ZFS feature GUID exceeds read budget"));
    }
    let mut colon = false;
    for &byte in bytes {
        if byte == b':' && !colon {
            colon = true;
        } else if !(byte.is_ascii_lowercase() || byte.is_ascii_digit()
            || (colon && byte == b'_')
            || (!colon && matches!(byte, b'.' | b'-')))
        {
            return Err(corrupt("invalid native ZFS feature GUID"));
        }
    }
    if !colon {
        return Err(corrupt("ZFS feature GUID has no namespace separator"));
    }
    std::str::from_utf8(bytes).map_err(|_| corrupt("non-ASCII ZFS feature GUID"))
}

fn scalar(entry: &Entry) -> Result<u64> {
    if entry.integer_bytes != 8 || entry.values.len() != 1 {
        return Err(corrupt("ZFS feature metadata is not one native uint64"));
    }
    Ok(entry.values[0])
}

fn admit(cx: &Cx, read: &[Entry], write: &[Entry], labels: &[String]) -> Result<()> {
    checkpoint(cx)?;
    if read.len().saturating_add(write.len()) > MAX_FEATURES || labels.len() > MAX_FEATURES {
        return Err(unsupported("ZFS feature catalog exceeds read budget"));
    }
    let mut all = BTreeMap::new();
    for (rows, for_write) in [(read, false), (write, true)] {
        for row in rows {
            checkpoint(cx)?;
            let name = guid(&row.name)?;
            let count = scalar(row)?;
            if all.insert(name, (count, for_write)).is_some() {
                return Err(corrupt("ZFS feature GUID repeats within or across catalogs"));
            }
            if let Some(known) = policy(name)
                && known.for_write != for_write
            {
                return Err(corrupt(format!("ZFS feature {name} is in the wrong native catalog")));
            }
        }
    }
    // Validate relationships after BOTH maps are complete. Dependencies need
    // to be enabled (present), not active; a zero dependency refcount is legal.
    for (&name, &(count, for_write)) in &all {
        checkpoint(cx)?;
        if let Some(known) = policy(name) {
            for dependency in known.dependencies {
                if !all.contains_key(dependency) {
                    return Err(corrupt(format!("ZFS feature {name} lacks dependency {dependency}")));
                }
            }
            if count != 0 && known.mos && !labels.iter().any(|label| label == name) {
                return Err(corrupt(format!("active MOS feature {name} is absent from labels")));
            }
        }
        if count != 0 && !for_write && !policy(name).is_some_and(|known| known.read_supported) {
            return Err(unsupported(format!("active ZFS read feature {name} is not implemented")));
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for label in labels {
        checkpoint(cx)?;
        guid(label.as_bytes())?;
        if !seen.insert(label) || !matches!(all.get(label.as_str()), Some((count, false)) if *count != 0) {
            return Err(corrupt(format!("label feature {label} has no unique active MOS read entry")));
        }
    }
    checkpoint(cx)
}

impl Objects {
    pub(super) fn admit_features(&mut self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        if self.config.version != 5000 {
            return Ok(()); // Historical numbered versions have no feature ZAPs.
        }
        if self.object(cx, 1)?.object_type() != 1 {
            return Err(corrupt("MOS object 1 is not the pool directory"));
        }
        let directory = self.zap_values(cx, 1)?;
        let mut ids = Vec::with_capacity(3);
        for name in [b"features_for_read".as_slice(), b"features_for_write", b"feature_descriptions"] {
            let row = directory.iter().find(|row| row.name == name)
                .ok_or_else(|| corrupt("MOS is missing a required native feature catalog"))?;
            let id = scalar(row)?;
            if id <= 1 || ids.contains(&id) || self.object(cx, id)?.object_type() != 196 {
                return Err(corrupt("MOS feature catalog has an invalid or aliased object identity"));
            }
            ids.push(id);
        }
        // Description strings are not compatibility authority. Validate their
        // object identity but do not interpret their payload as feature state.
        let read = self.zap_values(cx, ids[0])?;
        let write = self.zap_values(cx, ids[1])?;
        admit(cx, &read, &write, &self.config.read_features)
    }
}

companion_bin_tests! {
    #[cfg(test)]
    pub(super) mod tests;
}
