//! Native MOS read admission (pinned OpenZFS `zfs-2.4.0` feature manifest).
//!
//! Delegates classification and policy to [`ffs_ondisk::zfs::features`] so the
//! read-only reader and writable native TXG engine share one authoritative
//! OpenZFS 2.4.x manifest. Labels contain only active MOS/bootstrap features,
//! not the complete set of features required for reads. An unknown
//! enabled-but-inactive feature is not an unknown active feature. Proprietary
//! `com.oracle:*` features and unknown/unimplemented active read features
//! (including `com.klarasystems:dynamic_gang_header`) are hard-refused.

use super::{Cx, Objects, Result, checkpoint, corrupt, unsupported};
use ffs_ondisk::zfs::features::{
    FeaturePolicy, MAX_FEATURES, MAX_GUID_BYTES, PoolVersionProfile, classify_pool_version,
    is_oracle_feature, is_supported_label_feature, lookup_feature, validate_feature_guid,
};
use ffs_ondisk::zfs::nvlist::Value;
use ffs_ondisk::zfs_zap::Entry;
use std::collections::BTreeMap;

fn policy(name: &str) -> Option<FeaturePolicy> {
    lookup_feature(name)
}

/// Bootstrap and full MOS admission share one implementation registry. Retain
/// the existing label spelling for lz4 although the pinned upstream registry
/// no longer marks it MOS-required. Ordinary dataset features do not belong in
/// this label allowlist just because their reached structures can be read.
pub(in super::super) fn supported_label_feature(name: &str, value: &Value) -> bool {
    matches!(value, Value::Boolean(true)) && is_supported_label_feature(name)
}

fn guid(bytes: &[u8]) -> Result<&str> {
    if bytes.len() > MAX_GUID_BYTES {
        return Err(unsupported("ZFS feature GUID exceeds read budget"));
    }
    validate_feature_guid(bytes).map_err(|_| corrupt("invalid native ZFS feature GUID"))
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
            if is_oracle_feature(name) {
                return Err(unsupported(format!(
                    "proprietary Oracle ZFS feature {name} is excluded"
                )));
            }
            let count = scalar(row)?;
            if all.insert(name, (count, for_write)).is_some() {
                return Err(corrupt(
                    "ZFS feature GUID repeats within or across catalogs",
                ));
            }
            if let Some(known) = policy(name)
                && known.for_write != for_write
            {
                return Err(corrupt(format!(
                    "ZFS feature {name} is in the wrong native catalog"
                )));
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
                    return Err(corrupt(format!(
                        "ZFS feature {name} lacks dependency {dependency}"
                    )));
                }
            }
            if count != 0 && known.mos && !labels.iter().any(|label| label == name) {
                return Err(corrupt(format!(
                    "active MOS feature {name} is absent from labels"
                )));
            }
        }
        if count != 0 && !for_write && !policy(name).is_some_and(|known| known.read_supported) {
            return Err(unsupported(format!(
                "active ZFS read feature {name} is not implemented"
            )));
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for label in labels {
        checkpoint(cx)?;
        let label_name = guid(label.as_bytes())?;
        if is_oracle_feature(label_name) {
            return Err(unsupported(format!(
                "proprietary Oracle ZFS label feature {label_name} is excluded"
            )));
        }
        if !seen.insert(label)
            || !matches!(all.get(label.as_str()), Some((count, false)) if *count != 0)
        {
            return Err(corrupt(format!(
                "label feature {label} has no unique active MOS read entry"
            )));
        }
    }
    checkpoint(cx)
}

impl Objects {
    pub(super) fn admit_features(&mut self, cx: &Cx) -> Result<()> {
        checkpoint(cx)?;
        match classify_pool_version(self.config.version) {
            PoolVersionProfile::HistoricalSunIllumos => return Ok(()),
            PoolVersionProfile::OpenZfsFeatureFlags => {}
            PoolVersionProfile::ProprietaryOracle => {
                return Err(unsupported(
                    "proprietary Oracle ZFS pool versions (29..=4999) are excluded",
                ));
            }
            PoolVersionProfile::Unknown => {
                return Err(unsupported("unsupported ZFS pool version"));
            }
        }
        if self.object(cx, 1)?.object_type() != 1 {
            return Err(corrupt("MOS object 1 is not the pool directory"));
        }
        let directory = self.zap_values(cx, 1)?;
        let mut ids = Vec::with_capacity(3);
        for name in [
            b"features_for_read".as_slice(),
            b"features_for_write",
            b"feature_descriptions",
        ] {
            let row = directory
                .iter()
                .find(|row| row.name == name)
                .ok_or_else(|| corrupt("MOS is missing a required native feature catalog"))?;
            let id = scalar(row)?;
            if id <= 1 || ids.contains(&id) || self.object(cx, id)?.object_type() != 196 {
                return Err(corrupt(
                    "MOS feature catalog has an invalid or aliased object identity",
                ));
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
