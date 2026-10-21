//! Explicit, read-only extraction from a selected exported RAIDZ candidate.
//!
//! Native width and child order never shrink to the supplied-image count.
//! The exact configured/supplied/missing partition is established before any
//! payload read. An absent route has no Leaf, file descriptor or host path.

use super::{
    BTreeSet, Cx, FfsError, GroupConfig, Leaf, MAX_MEMBERS, Pool, RaidzGroup, RaidzMember, Result,
    VdevConfig, checkpoint, corrupt, integer, unsupported,
};

// Reserved only for explicitly declared absent RAIDZ children. Complete RAIDZ,
// stripe and ZIL routes retain ordinary supplied indices. Every RAIDZ access
// goes through raidz_source, which also verifies the absent GUID declaration.
pub(super) const ABSENT_RAIDZ_INDEX: usize = usize::MAX;

impl Pool {
    /// Readability from surviving copies is not intact native redundancy.
    pub(in crate::reader) fn missing_member_count(&self) -> usize {
        self.missing_mirror_guids.len() + self.missing_raidz_guids.len()
    }

    /// Request-shape checks do not require opening an image. Native parity and
    /// GUID membership still have to be established from the surviving labels.
    pub fn check_raidz_survivors(supplied: usize, missing: &[u64]) -> Result<()> {
        if supplied == 0
            || supplied >= MAX_MEMBERS
            || !(1..=3).contains(&missing.len())
            || supplied
                .checked_add(missing.len())
                .is_none_or(|total| total > MAX_MEMBERS)
        {
            return Err(unsupported(
                "missing RAIDZ extraction needs survivors, one through three missing GUIDs, and at most eight total children",
            ));
        }
        let mut seen = BTreeSet::new();
        for &guid in missing {
            if guid == 0 || !seen.insert(guid) {
                return Err(unsupported(
                    "missing RAIDZ GUIDs must be nonzero and unique",
                ));
            }
        }
        Ok(())
    }

    /// An operator-selected committed view, not automatic degraded import.
    /// All four surviving labels must describe the same exported ordinary
    /// RAIDZ1/2/3 group. Absent children count against its native parity budget.
    pub fn from_raidz_survivors(cx: &Cx, members: Vec<Leaf>, missing: Vec<u64>) -> Result<Self> {
        checkpoint(cx)?;
        Self::check_raidz_survivors(members.len(), &missing)?;
        let mut pool = Self::from_leaves(members)?;
        pool.missing_raidz_guids = missing;
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
                return Err(corrupt("surviving RAIDZ configurations disagree"));
            }
            for index in 1..4 {
                checkpoint(cx)?;
                let (other, other_guid) = member
                    .label(cx, index)?
                    .group_config_with_mode(pool_guid, false)?;
                if other != selected || other_guid != guid {
                    return Err(corrupt(
                        "surviving RAIDZ labels disagree on identity or configuration",
                    ));
                }
            }
            supplied.push(guid);
        }
        pool.validate_raidz_complement(&selected, &supplied)?;
        checkpoint(cx)?;
        Ok(pool)
    }

    pub(super) fn validate_raidz_complement(
        &self,
        selected: &GroupConfig,
        supplied: &[u64],
    ) -> Result<()> {
        if self.missing_raidz_guids.is_empty() {
            return Ok(());
        }
        Self::check_raidz_survivors(supplied.len(), &self.missing_raidz_guids)?;
        if !self.missing_mirror_guids.is_empty()
            || selected.tree.text("type") != Some("raidz")
            || !(1..=3).contains(&selected.raidz_parity)
            || self.missing_raidz_guids.len() > selected.raidz_parity
        {
            return Err(unsupported(
                "missing RAIDZ extraction requires one ordinary group within its native parity budget",
            ));
        }
        let configured: BTreeSet<_> = selected.member_guids.iter().copied().collect();
        let mut accounted = BTreeSet::new();
        for &guid in supplied.iter().chain(&self.missing_raidz_guids) {
            if !configured.contains(&guid) || !accounted.insert(guid) {
                return Err(corrupt(
                    "present and missing RAIDZ GUIDs overlap, repeat, or name an unconfigured child",
                ));
            }
        }
        if accounted != configured {
            return Err(unsupported(
                "every absent RAIDZ child must be explicitly identified by GUID",
            ));
        }
        Ok(())
    }

    /// Convert the retained route to an optional physical source. A sentinel
    /// alone never authorizes erasure recovery, and a missing GUID must never
    /// alias a real supplied device. Validate this before interpreting any DVA.
    pub(super) fn raidz_source(&self, member: &RaidzMember) -> Result<Option<&Leaf>> {
        let declared = self.missing_raidz_guids.contains(&member.guid);
        if member.supplied_index == ABSENT_RAIDZ_INDEX {
            return if declared {
                Ok(None)
            } else {
                Err(corrupt("RAIDZ route has an undeclared absent child"))
            };
        }
        if declared {
            return Err(corrupt("absent RAIDZ child aliases a supplied image"));
        }
        self.members
            .get(member.supplied_index)
            .map(Some)
            .ok_or_else(|| corrupt("RAIDZ child maps outside supplied members"))
    }

    pub(super) fn read_raidz_member(
        &self,
        cx: &Cx,
        member: &RaidzMember,
        offset: u64,
        bytes: usize,
    ) -> Result<Vec<u8>> {
        checkpoint(cx)?;
        let source = self.raidz_source(member)?.ok_or_else(|| {
            // This is a known erasure, not a fabricated device/read result.
            FfsError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("explicitly absent RAIDZ member GUID {}", member.guid),
            ))
        })?;
        source.read(cx, offset, bytes)
    }
}

impl GroupConfig {
    pub(super) fn mapped_raidz_survivors(
        self,
        supplied: &[u64],
        missing: &[u64],
    ) -> Result<VdevConfig> {
        let mut config = self.vdev;
        let mut members = Vec::with_capacity(self.member_guids.len());
        for guid in self.member_guids {
            let supplied_index = match supplied.iter().position(|candidate| *candidate == guid) {
                Some(index) if !missing.contains(&guid) => index,
                None if missing.contains(&guid) => ABSENT_RAIDZ_INDEX,
                _ => {
                    return Err(corrupt(
                        "RAIDZ route does not match the admitted member partition",
                    ));
                }
            };
            members.push(RaidzMember {
                supplied_index,
                guid,
                ashift: config.ashift,
                allocated_bytes: config.allocated_bytes,
            });
        }
        config.raidz_members = Some(RaidzGroup {
            parity: self.raidz_parity,
            members,
        });
        Ok(config)
    }
}
