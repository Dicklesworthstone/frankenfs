//! Explicit committed-view extraction from surviving exported mirror members.
//!
//! Missing GUIDs describe the exact complement of the retained devices. They
//! are not permission to ignore an unreadable supplied device, a missing vdev,
//! an active pool, or a changed topology. No unavailable device is fabricated.

use super::{
    BTreeSet, Cx, GroupConfig, Leaf, MAX_MEMBERS, Pool, Result, checkpoint, corrupt, integer,
    unsupported,
};

impl Pool {
    /// Validate only the bounded request shape, before the CLI opens any image.
    /// Native membership is established separately from every surviving label.
    pub fn check_mirror_survivors(supplied: usize, missing: &[u64]) -> Result<()> {
        if supplied == 0
            || supplied >= MAX_MEMBERS
            || missing.is_empty()
            || supplied
                .checked_add(missing.len())
                .is_none_or(|total| total > MAX_MEMBERS)
        {
            return Err(unsupported(
                "missing-member extraction needs one or more survivors and at most eight total mirror children",
            ));
        }
        let mut seen = BTreeSet::new();
        for &guid in missing {
            if guid == 0 || !seen.insert(guid) {
                return Err(unsupported(
                    "missing mirror GUIDs must be nonzero and unique",
                ));
            }
        }
        Ok(())
    }

    /// Retain an explicitly incomplete mirror for read-only candidate extraction.
    ///
    /// The complete four-label configuration of every survivor must agree on
    /// one exported ordinary mirror. Supplied and explicitly missing GUIDs must
    /// partition its children exactly. The caller still selects a pool GUID,
    /// label and uberblock slot through `root` or `objects`; this constructor
    /// neither selects a TXG nor certifies that absent members lack newer state.
    pub fn from_mirror_survivors(cx: &Cx, members: Vec<Leaf>, missing: Vec<u64>) -> Result<Self> {
        checkpoint(cx)?;
        Self::check_mirror_survivors(members.len(), &missing)?;
        let pool = Self {
            members,
            missing_mirror_guids: missing,
            missing_raidz_guids: Vec::new(),
            top_levels: None,
        };
        let first = pool.members[0].label(cx, 0)?;
        let pool_guid = integer(&first.config, "pool_guid")?;
        let (selected, _) = first.group_config_with_mode(pool_guid, false)?;
        let mut supplied = Vec::with_capacity(pool.members.len());
        for member in &pool.members {
            checkpoint(cx)?;
            let (config, guid) = member
                .label(cx, 0)?
                .group_config_with_mode(pool_guid, false)?;
            if config != selected {
                return Err(corrupt("surviving mirror configurations disagree"));
            }
            for index in 1..4 {
                checkpoint(cx)?;
                let (other, other_guid) = member
                    .label(cx, index)?
                    .group_config_with_mode(pool_guid, false)?;
                if other != selected || other_guid != guid {
                    return Err(corrupt(
                        "surviving mirror labels disagree on identity or configuration",
                    ));
                }
            }
            supplied.push(guid);
        }
        pool.validate_mirror_complement(&selected, &supplied)?;
        checkpoint(cx)?;
        Ok(pool)
    }

    pub(super) fn validate_mirror_complement(
        &self,
        selected: &GroupConfig,
        supplied: &[u64],
    ) -> Result<()> {
        if self.missing_mirror_guids.is_empty() {
            return Ok(());
        }
        Self::check_mirror_survivors(supplied.len(), &self.missing_mirror_guids)?;
        if selected.raidz_parity != 0 || selected.tree.text("type") != Some("mirror") {
            return Err(unsupported(
                "missing-member extraction supports ordinary mirrors only",
            ));
        }
        let configured: BTreeSet<_> = selected.member_guids.iter().copied().collect();
        let mut accounted = BTreeSet::new();
        for &guid in supplied.iter().chain(&self.missing_mirror_guids) {
            if !configured.contains(&guid) || !accounted.insert(guid) {
                return Err(corrupt(
                    "present and missing mirror GUIDs overlap, repeat, or name an unconfigured child",
                ));
            }
        }
        if accounted != configured {
            return Err(unsupported(
                "every absent mirror child must be explicitly identified by GUID",
            ));
        }
        Ok(())
    }
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
