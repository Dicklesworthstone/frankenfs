//! Pinned OpenZFS 2.4.x feature and pool-version admission manifest.
//!
//! Single authoritative registry shared by read-only ZFS readers and writable
//! native TXG / pool-lifecycle engines. Native classification (`for_write`,
//! `mos`, `dependencies`) follows OpenZFS `zfs-2.4.0`
//! (`module/zcommon/zfeature_common.c`) independently of our implementation
//! status so an unimplemented read-required feature can never slip into the
//! write-only catalog and evade admission.
//!
//! Version profile separation:
//! - `1..=28`: Historical Sun / illumos numbered pool versions (RO profile; no
//!   feature ZAPs).
//! - `29..=4999` and any `com.oracle:*` GUID: Proprietary Oracle ZFS
//!   extensions (explicitly excluded and hard-refused).
//! - `5000`: OpenZFS 2.4.x feature-flags profile governed by [`lookup_feature`].
//! - `0` or `>5000`: Unknown / future pool versions (hard-refused).

use ffs_types::ParseError;

/// Pinned upstream OpenZFS revision governing this feature catalog.
pub const OPENZFS_PINNED_RELEASE: &str = "zfs-2.4.0";

/// Maximum feature entries admitted in a single pool catalog.
pub const MAX_FEATURES: usize = 1024;

/// Maximum byte length of a native ZFS feature GUID.
pub const MAX_GUID_BYTES: usize = 255;

/// Classification of a ZFS pool `version` number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PoolVersionProfile {
    /// Historical numbered Sun/illumos pools (`1..=28`, no feature ZAPs).
    HistoricalSunIllumos,
    /// OpenZFS feature-flags pools (`5000`).
    OpenZfsFeatureFlags,
    /// Proprietary Oracle ZFS numbered pools (`29..=4999`) — excluded.
    ProprietaryOracle,
    /// Zero or future unknown versions — refused.
    Unknown,
}

/// Classify a pool `version` field from a label or uberblock.
#[must_use]
pub const fn classify_pool_version(version: u64) -> PoolVersionProfile {
    match version {
        1..=28 => PoolVersionProfile::HistoricalSunIllumos,
        29..=4999 => PoolVersionProfile::ProprietaryOracle,
        5000 => PoolVersionProfile::OpenZfsFeatureFlags,
        _ => PoolVersionProfile::Unknown,
    }
}

/// Returns `true` if `guid` belongs to the explicitly excluded proprietary
/// Oracle ZFS namespace (`com.oracle:*`).
#[must_use]
pub fn is_oracle_feature(guid: &str) -> bool {
    guid.starts_with("com.oracle:")
}

/// Admission metadata for a single pinned OpenZFS 2.4.x feature GUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeaturePolicy {
    /// Canonical OpenZFS feature GUID (`<reverse-dns>:<name>`).
    pub guid: &'static str,
    /// `true` if `ZFEATURE_FLAG_READONLY_COMPAT` (`features_for_write`),
    /// `false` if read-required (`features_for_read`).
    pub for_write: bool,
    /// `true` if `ZFEATURE_FLAG_MOS` (must appear in vdev label
    /// `features_for_read` whenever its MOS refcount is nonzero).
    pub mos: bool,
    /// `true` if FrankenFS's read path implements and admits this feature when
    /// active (`count > 0`).
    pub read_supported: bool,
    /// `true` if FrankenFS's writable TXG / pool-lifecycle engine admits this
    /// feature when active (`count > 0`).
    pub write_supported: bool,
    /// Feature GUIDs that must be enabled (present in either catalog, even
    /// with count 0) whenever this feature is present.
    pub dependencies: &'static [&'static str],
}

const EXTENSIBLE: &[&str] = &["com.delphix:extensible_dataset"];
const BOOKMARK_V2_DEPS: &[&str] = &["com.delphix:extensible_dataset", "com.delphix:bookmarks"];
const ENCRYPTION_DEPS: &[&str] = &["com.delphix:extensible_dataset", "com.datto:bookmark_v2"];
const REDACTION_DEPS: &[&str] = &[
    "com.datto:bookmark_v2",
    "com.delphix:extensible_dataset",
    "com.delphix:bookmarks",
];
const OBSOLETE_COUNTS_DEPS: &[&str] = &[
    "com.delphix:extensible_dataset",
    "com.delphix:device_removal",
];
const LARGE_MICROZAP_DEPS: &[&str] = &[
    "com.delphix:extensible_dataset",
    "org.open-zfs:large_blocks",
];

/// Complete pinned OpenZFS 2.4.0 feature table (`47` upstream features from
/// `module/zcommon/zfeature_common.c`).
pub const OPENZFS_2_4_FEATURES: &[FeaturePolicy] = &[
    // ── Read-required (`features_for_read`), admitted RO + RW ───────────────
    FeaturePolicy {
        guid: "org.illumos:lz4_compress",
        for_write: false,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: &[],
    },
    FeaturePolicy {
        guid: "com.delphix:extensible_dataset",
        for_write: false,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: &[],
    },
    FeaturePolicy {
        guid: "com.delphix:embedded_data",
        for_write: false,
        mos: true,
        read_supported: true,
        write_supported: true,
        dependencies: &[],
    },
    FeaturePolicy {
        guid: "org.open-zfs:large_blocks",
        for_write: false,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: EXTENSIBLE,
    },
    FeaturePolicy {
        guid: "org.zfsonlinux:large_dnode",
        for_write: false,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: EXTENSIBLE,
    },
    FeaturePolicy {
        guid: "org.illumos:sha512",
        for_write: false,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: EXTENSIBLE,
    },
    FeaturePolicy {
        guid: "org.freebsd:zstd_compress",
        for_write: false,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: EXTENSIBLE,
    },
    FeaturePolicy {
        guid: "com.delphix:hole_birth",
        for_write: false,
        mos: true,
        read_supported: true,
        write_supported: true,
        dependencies: &["com.delphix:enabled_txg"],
    },
    FeaturePolicy {
        guid: "com.datto:bookmark_v2",
        for_write: false,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: BOOKMARK_V2_DEPS,
    },
    FeaturePolicy {
        guid: "com.datto:encryption",
        for_write: false,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: ENCRYPTION_DEPS,
    },
    // Advanced topology & vdev ZAP MOS features admitted in bd-i6em8:
    FeaturePolicy {
        guid: "com.delphix:device_removal",
        for_write: false,
        mos: true,
        read_supported: true,
        write_supported: true,
        dependencies: &[],
    },
    FeaturePolicy {
        guid: "org.openzfs:draid",
        for_write: false,
        mos: true,
        read_supported: true,
        write_supported: true,
        dependencies: &[],
    },
    FeaturePolicy {
        guid: "com.klarasystems:vdev_zaps_v2",
        for_write: false,
        mos: true,
        read_supported: true,
        write_supported: true,
        dependencies: &[],
    },
    FeaturePolicy {
        guid: "org.openzfs:raidz_expansion",
        for_write: false,
        mos: true,
        read_supported: true,
        write_supported: true,
        dependencies: &[],
    },
    // ── Read-required (`features_for_read`), explicitly refused when active ─
    FeaturePolicy {
        guid: "org.illumos:skein",
        for_write: false,
        mos: false,
        read_supported: false,
        write_supported: false,
        dependencies: EXTENSIBLE,
    },
    FeaturePolicy {
        guid: "org.illumos:edonr",
        for_write: false,
        mos: false,
        read_supported: false,
        write_supported: false,
        dependencies: EXTENSIBLE,
    },
    FeaturePolicy {
        guid: "org.openzfs:blake3",
        for_write: false,
        mos: false,
        read_supported: false,
        write_supported: false,
        dependencies: EXTENSIBLE,
    },
    FeaturePolicy {
        guid: "com.delphix:redacted_datasets",
        for_write: false,
        mos: false,
        read_supported: false,
        write_supported: false,
        dependencies: EXTENSIBLE,
    },
    FeaturePolicy {
        guid: "org.zfsonlinux:longname",
        for_write: false,
        mos: false,
        read_supported: false,
        write_supported: false,
        dependencies: EXTENSIBLE,
    },
    FeaturePolicy {
        guid: "com.delphix:redaction_bookmarks",
        for_write: false,
        mos: false,
        read_supported: false,
        write_supported: false,
        dependencies: REDACTION_DEPS,
    },
    FeaturePolicy {
        guid: "com.delphix:bookmark_written",
        for_write: false,
        mos: false,
        read_supported: false,
        write_supported: false,
        dependencies: REDACTION_DEPS,
    },
    FeaturePolicy {
        guid: "com.delphix:redaction_list_spill",
        for_write: false,
        mos: false,
        read_supported: false,
        write_supported: false,
        dependencies: &["com.delphix:redaction_bookmarks"],
    },
    FeaturePolicy {
        guid: "com.joyent:multi_vdev_crash_dump",
        for_write: false,
        mos: false,
        read_supported: false,
        write_supported: false,
        dependencies: &[],
    },
    FeaturePolicy {
        guid: "com.delphix:head_errlog",
        for_write: false,
        mos: false,
        read_supported: false,
        write_supported: false,
        dependencies: &[],
    },
    FeaturePolicy {
        guid: "com.klarasystems:dynamic_gang_header",
        for_write: false,
        mos: true,
        read_supported: false,
        write_supported: false,
        dependencies: &[],
    },
    // ── Write-only / RO-compat (`features_for_write`), admitted RO + RW ─────
    FeaturePolicy {
        guid: "com.delphix:async_destroy",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: &[],
    },
    FeaturePolicy {
        guid: "com.delphix:empty_bpobj",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: &[],
    },
    FeaturePolicy {
        guid: "com.delphix:spacemap_histogram",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: &[],
    },
    FeaturePolicy {
        guid: "com.delphix:enabled_txg",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: &[],
    },
    FeaturePolicy {
        guid: "com.delphix:spacemap_v2",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: &[],
    },
    FeaturePolicy {
        guid: "com.delphix:bookmarks",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: EXTENSIBLE,
    },
    FeaturePolicy {
        guid: "com.joyent:filesystem_limits",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: EXTENSIBLE,
    },
    FeaturePolicy {
        guid: "org.zfsonlinux:userobj_accounting",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: EXTENSIBLE,
    },
    FeaturePolicy {
        guid: "org.zfsonlinux:project_quota",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: EXTENSIBLE,
    },
    FeaturePolicy {
        guid: "org.zfsonlinux:allocation_classes",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: &[],
    },
    FeaturePolicy {
        guid: "com.delphix:zpool_checkpoint",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: &[],
    },
    FeaturePolicy {
        guid: "com.delphix:obsolete_counts",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: OBSOLETE_COUNTS_DEPS,
    },
    FeaturePolicy {
        guid: "com.datto:resilver_defer",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: &[],
    },
    FeaturePolicy {
        guid: "org.openzfs:device_rebuild",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: false,
        dependencies: &[],
    },
    FeaturePolicy {
        guid: "org.openzfs:zilsaxattr",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: true,
        dependencies: EXTENSIBLE,
    },
    // ── Write-only / RO-compat (`features_for_write`), RO-only (refused RW) ─
    FeaturePolicy {
        guid: "com.delphix:livelist",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: false,
        dependencies: EXTENSIBLE,
    },
    FeaturePolicy {
        guid: "com.delphix:log_spacemap",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: false,
        dependencies: &["com.delphix:spacemap_v2"],
    },
    FeaturePolicy {
        guid: "com.fudosecurity:block_cloning",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: false,
        dependencies: &[],
    },
    FeaturePolicy {
        guid: "com.truenas:block_cloning_endian",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: false,
        dependencies: &[],
    },
    FeaturePolicy {
        guid: "com.klarasystems:fast_dedup",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: false,
        dependencies: &[],
    },
    FeaturePolicy {
        guid: "com.klarasystems:large_microzap",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: false,
        dependencies: LARGE_MICROZAP_DEPS,
    },
    FeaturePolicy {
        guid: "com.truenas:physical_rewrite",
        for_write: true,
        mos: false,
        read_supported: true,
        write_supported: false,
        dependencies: EXTENSIBLE,
    },
];

/// Look up a feature GUID in the pinned OpenZFS 2.4.0 manifest.
#[must_use]
pub fn lookup_feature(guid: &str) -> Option<FeaturePolicy> {
    OPENZFS_2_4_FEATURES
        .iter()
        .find(|entry| entry.guid == guid)
        .copied()
}

/// Returns `true` if `guid` is permitted as an active (`true`) entry in a vdev
/// label's `features_for_read` nvlist.
///
/// Retains the historical label spelling for `org.illumos:lz4_compress` even
/// though upstream OpenZFS no longer marks it `ZFEATURE_FLAG_MOS`.
#[must_use]
pub fn is_supported_label_feature(guid: &str) -> bool {
    if is_oracle_feature(guid) {
        return false;
    }
    lookup_feature(guid).is_some_and(|known| {
        !known.for_write
            && known.read_supported
            && (known.mos || guid == "org.illumos:lz4_compress")
    })
}

/// Returns `true` if `guid` is admitted as an active (`count > 0`) entry in
/// MOS `features_for_write` when opening a pool for native writes / lifecycle.
#[must_use]
pub fn is_admitted_active_write_feature(guid: &str) -> bool {
    if is_oracle_feature(guid) {
        return false;
    }
    lookup_feature(guid).is_some_and(|known| known.for_write && known.write_supported)
}

/// Returns `true` if `guid` is admitted as an active (`count > 0`) entry in
/// MOS `features_for_read` when opening a pool for native writes / lifecycle.
#[must_use]
pub fn is_admitted_active_read_feature_for_write(guid: &str) -> bool {
    if is_oracle_feature(guid) {
        return false;
    }
    lookup_feature(guid)
        .is_some_and(|known| !known.for_write && known.read_supported && known.write_supported)
}

/// Validate canonical OpenZFS feature GUID syntax (`<org-domain>:<feature_name>`).
pub fn validate_feature_guid(bytes: &[u8]) -> Result<&str, ParseError> {
    if bytes.is_empty() || bytes.len() > MAX_GUID_BYTES {
        return Err(ParseError::InvalidField {
            field: "zfs",
            reason: "ZFS feature GUID length out of bounds",
        });
    }
    let mut colon = false;
    let mut colon_pos = 0_usize;
    for (idx, &byte) in bytes.iter().enumerate() {
        if byte == b':' && !colon {
            colon = true;
            colon_pos = idx;
        } else if !(byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || (colon && byte == b'_')
            || (!colon && matches!(byte, b'.' | b'-')))
        {
            return Err(ParseError::InvalidField {
                field: "zfs",
                reason: "invalid character in ZFS feature GUID",
            });
        }
    }
    if !colon || colon_pos == 0 || colon_pos + 1 == bytes.len() {
        return Err(ParseError::InvalidField {
            field: "zfs",
            reason: "ZFS feature GUID missing namespace or feature name",
        });
    }
    std::str::from_utf8(bytes).map_err(|_| ParseError::InvalidField {
        field: "zfs",
        reason: "non-UTF8 ZFS feature GUID",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn manifest_has_unique_valid_guids_and_valid_dependencies() {
        assert_eq!(OPENZFS_2_4_FEATURES.len(), 47);
        let mut seen = BTreeSet::new();
        for entry in OPENZFS_2_4_FEATURES {
            assert_eq!(
                validate_feature_guid(entry.guid.as_bytes()).unwrap(),
                entry.guid
            );
            assert!(
                seen.insert(entry.guid),
                "duplicate feature GUID {}",
                entry.guid
            );
            assert!(!is_oracle_feature(entry.guid));
        }
        for entry in OPENZFS_2_4_FEATURES {
            for dep in entry.dependencies {
                assert!(
                    seen.contains(dep),
                    "feature {} lists unknown dependency {dep}",
                    entry.guid
                );
            }
        }
    }

    #[test]
    fn version_profiles_and_oracle_features_separate_cleanly() {
        assert_eq!(classify_pool_version(0), PoolVersionProfile::Unknown);
        assert_eq!(
            classify_pool_version(28),
            PoolVersionProfile::HistoricalSunIllumos
        );
        assert_eq!(
            classify_pool_version(29),
            PoolVersionProfile::ProprietaryOracle
        );
        assert_eq!(
            classify_pool_version(44),
            PoolVersionProfile::ProprietaryOracle
        );
        assert_eq!(
            classify_pool_version(5000),
            PoolVersionProfile::OpenZfsFeatureFlags
        );
        assert_eq!(classify_pool_version(5001), PoolVersionProfile::Unknown);

        assert!(is_oracle_feature("com.oracle:encryption"));
        assert!(!is_supported_label_feature("com.oracle:anything"));
        assert!(!is_admitted_active_write_feature("com.oracle:anything"));
    }

    #[test]
    fn advanced_topology_features_admitted_and_dynamic_gang_refused() {
        for guid in [
            "org.openzfs:draid",
            "org.openzfs:raidz_expansion",
            "com.delphix:device_removal",
            "com.klarasystems:vdev_zaps_v2",
            "com.delphix:embedded_data",
            "com.delphix:hole_birth",
            "org.illumos:lz4_compress",
        ] {
            assert!(
                is_supported_label_feature(guid),
                "expected label admission for {guid}"
            );
            assert!(is_admitted_active_read_feature_for_write(guid));
        }
        assert!(!is_supported_label_feature(
            "com.klarasystems:dynamic_gang_header"
        ));
        assert!(!is_admitted_active_read_feature_for_write(
            "com.klarasystems:dynamic_gang_header"
        ));
        assert!(!is_supported_label_feature("org.openzfs:unknown_future"));
        for guid in [
            "org.zfsonlinux:allocation_classes",
            "com.delphix:zpool_checkpoint",
            "com.delphix:obsolete_counts",
            "com.datto:resilver_defer",
            "org.openzfs:zilsaxattr",
        ] {
            assert!(
                is_admitted_active_write_feature(guid),
                "expected write admission for {guid}"
            );
        }
        for ro_only in [
            "org.openzfs:device_rebuild",
            "com.delphix:log_spacemap",
            "com.fudosecurity:block_cloning",
            "com.truenas:block_cloning_endian",
            "com.klarasystems:fast_dedup",
            "com.klarasystems:large_microzap",
            "com.truenas:physical_rewrite",
            "com.example:future_write_feature",
        ] {
            assert!(
                !is_admitted_active_write_feature(ro_only),
                "expected RW refusal for {ro_only}"
            );
        }
    }
}
