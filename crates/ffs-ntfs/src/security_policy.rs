//! Explicit NTFS SID/ACL host-projection policy and MS-DTYP security patch helpers.
//!
//! By default (`NtfsSidPolicy::Synthetic`), `NtfsFs` retains synthetic host `uid`/`gid`
//! ownership without fabricating Windows-to-Linux identity mappings. When callers
//! supply an explicit [`NtfsSidMap`] (`NtfsSidPolicy::Mapped`), `NtfsFs` projects
//! native owner/group SIDs, enforces MS-DTYP DACL rules (DENY before ALLOW), and
//! translates `chmod`/`chown` onto real `$Secure` descriptors while preserving SACLs
//! and non-POSIX ACEs.

use std::collections::BTreeMap;

use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs_security::{
    ACE_TYPE_ACCESS_ALLOWED, ACE_TYPE_ACCESS_DENIED, FILE_ALL_ACCESS, FILE_DELETE_CHILD,
    FILE_EXECUTE, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_READ_DATA,
    FILE_WRITE_DATA, NtfsAccessToken, NtfsAce, NtfsAcl, NtfsSecurityDescriptor, NtfsSid,
    SE_DACL_PRESENT, SE_SELF_RELATIVE, STANDARD_DELETE, STANDARD_READ_CONTROL, STANDARD_WRITE_DAC,
    STANDARD_WRITE_OWNER, evaluate_dacl_access,
};

/// POSIX NFSv4-style mapped UID/GID SID authority (`S-1-5-88-1-<uid>`, `S-1-5-88-2-<gid>`).
const NFS_SID_AUTHORITY: u64 = 5;
const NFS_SID_SUBAUTH: u32 = 88;
const NFS_UID_KIND: u32 = 1;
const NFS_GID_KIND: u32 = 2;

/// Explicit mapping policy between POSIX `uid`/`gid` and native NTFS [`NtfsSid`]s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtfsSidMap {
    /// Enforce MS-DTYP DACL evaluation (`PermissionDenied` on DENY/insufficient rights).
    pub enforce_acl: bool,
    /// When `true`, unmapped UIDs/GIDs deterministically project via Microsoft's
    /// NFSv4 POSIX SID convention (`S-1-5-88-1-<uid>`, `S-1-5-88-2-<gid>`).
    pub posix_nfs_sids: bool,
    pub uid_to_sid: BTreeMap<u32, NtfsSid>,
    pub gid_to_sid: BTreeMap<u32, NtfsSid>,
    pub default_owner: NtfsSid,
    pub default_group: NtfsSid,
    /// Fallback synthetic host uid/gid for native SIDs absent from `uid_to_sid`/`gid_to_sid`.
    pub fallback_uid: u32,
    pub fallback_gid: u32,
}

impl Default for NtfsSidMap {
    fn default() -> Self {
        Self {
            enforce_acl: true,
            posix_nfs_sids: true,
            uid_to_sid: BTreeMap::new(),
            gid_to_sid: BTreeMap::new(),
            default_owner: NtfsSid {
                authority: 5,
                subauthorities: vec![32, 544], // BUILTIN\Administrators
            },
            default_group: NtfsSid {
                authority: 5,
                subauthorities: vec![18], // NT AUTHORITY\SYSTEM
            },
            fallback_uid: 0,
            fallback_gid: 0,
        }
    }
}

impl NtfsSidMap {
    /// Map a POSIX `uid` to its configured native [`NtfsSid`].
    pub fn sid_for_uid(&self, uid: u32) -> Result<NtfsSid> {
        if let Some(sid) = self.uid_to_sid.get(&uid) {
            return Ok(sid.clone());
        }
        if self.posix_nfs_sids {
            return Ok(NtfsSid {
                authority: NFS_SID_AUTHORITY,
                subauthorities: vec![NFS_SID_SUBAUTH, NFS_UID_KIND, uid],
            });
        }
        Err(FfsError::UnsupportedFeature(format!(
            "POSIX uid {uid} has no explicit NTFS SID mapping"
        )))
    }

    /// Map a POSIX `gid` to its configured native [`NtfsSid`].
    pub fn sid_for_gid(&self, gid: u32) -> Result<NtfsSid> {
        if let Some(sid) = self.gid_to_sid.get(&gid) {
            return Ok(sid.clone());
        }
        if self.posix_nfs_sids {
            return Ok(NtfsSid {
                authority: NFS_SID_AUTHORITY,
                subauthorities: vec![NFS_SID_SUBAUTH, NFS_GID_KIND, gid],
            });
        }
        Err(FfsError::UnsupportedFeature(format!(
            "POSIX gid {gid} has no explicit NTFS SID mapping"
        )))
    }

    /// Project a native owner [`NtfsSid`] to a host `uid`.
    #[must_use]
    pub fn uid_for_sid(&self, sid: &NtfsSid) -> u32 {
        for (&uid, mapped) in &self.uid_to_sid {
            if mapped == sid {
                return uid;
            }
        }
        if self.posix_nfs_sids
            && sid.authority == NFS_SID_AUTHORITY
            && sid.subauthorities.len() == 3
            && sid.subauthorities[0] == NFS_SID_SUBAUTH
            && sid.subauthorities[1] == NFS_UID_KIND
        {
            return sid.subauthorities[2];
        }
        self.fallback_uid
    }

    /// Project a native group [`NtfsSid`] to a host `gid`.
    #[must_use]
    pub fn gid_for_sid(&self, sid: &NtfsSid) -> u32 {
        for (&gid, mapped) in &self.gid_to_sid {
            if mapped == sid {
                return gid;
            }
        }
        if self.posix_nfs_sids
            && sid.authority == NFS_SID_AUTHORITY
            && sid.subauthorities.len() == 3
            && sid.subauthorities[0] == NFS_SID_SUBAUTH
            && sid.subauthorities[1] == NFS_GID_KIND
        {
            return sid.subauthorities[2];
        }
        self.fallback_gid
    }

    /// Build an [`NtfsAccessToken`] representing `(uid, gid)` under this SID map.
    pub fn token_for(&self, uid: u32, gid: u32) -> Result<NtfsAccessToken> {
        let user = self.sid_for_uid(uid)?;
        let group = self.sid_for_gid(gid)?;
        Ok(NtfsAccessToken {
            user,
            groups: vec![group],
        })
    }

    /// Project POSIX `0o777` mode bits from a validated MS-DTYP security descriptor.
    #[must_use]
    pub fn project_posix_mode(&self, sd: &NtfsSecurityDescriptor, is_directory: bool) -> u16 {
        let owner = sd.owner.as_ref().unwrap_or(&self.default_owner);
        let group = sd.group.as_ref().unwrap_or(&self.default_group);
        let everyone = NtfsSid::world_everyone();

        let eval_triplet = |sid: &NtfsSid| -> u16 {
            let tok = NtfsAccessToken {
                user: sid.clone(),
                groups: Vec::new(),
            };
            let mut bits = 0_u16;
            if evaluate_dacl_access(sd, &tok, FILE_READ_DATA).unwrap_or(false) {
                bits |= 0o4;
            }
            if evaluate_dacl_access(sd, &tok, FILE_WRITE_DATA).unwrap_or(false) {
                bits |= 0o2;
            }
            if evaluate_dacl_access(sd, &tok, FILE_EXECUTE).unwrap_or(false) {
                bits |= 0o1;
            }
            bits
        };

        let u_bits = eval_triplet(owner);
        let g_bits = eval_triplet(group);
        let o_bits = eval_triplet(&everyone);
        let mode = (u_bits << 6) | (g_bits << 3) | o_bits;
        if is_directory && mode == 0 && !sd.dacl.present {
            0o755
        } else {
            mode
        }
    }
}

/// Host ownership & ACL policy attached to [`crate::NtfsFs`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NtfsSidPolicy {
    /// Default backward-compatible behavior: synthetic `uid`/`gid`, no DACL enforcement.
    Synthetic { uid: u32, gid: u32 },
    /// Explicit SID map & optional MS-DTYP DACL enforcement + POSIX `chmod`/`chown`.
    Mapped {
        caller_uid: u32,
        caller_gid: u32,
        map: NtfsSidMap,
    },
}

impl NtfsSidPolicy {
    #[must_use]
    pub const fn fallback_uid(&self) -> u32 {
        match self {
            Self::Synthetic { uid, .. } => *uid,
            Self::Mapped { map, .. } => map.fallback_uid,
        }
    }

    #[must_use]
    pub const fn fallback_gid(&self) -> u32 {
        match self {
            Self::Synthetic { gid, .. } => *gid,
            Self::Mapped { map, .. } => map.fallback_gid,
        }
    }
}

/// Declarative patch applied to an object's native MS-DTYP security descriptor
/// without dropping its SACL or unrelated non-POSIX ACEs.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NtfsSecurityPatch {
    pub owner: Option<NtfsSid>,
    pub group: Option<NtfsSid>,
    /// Replace the DACL with explicit ACEs (preserving order & DENY entries).
    pub replace_dacl: Option<Vec<NtfsAce>>,
    /// Apply POSIX `0o777` mode bits as canonical DENY+ALLOW owner/group/everyone ACEs
    /// while preserving any SACL and non-trustee ACEs.
    pub posix_mode: Option<(u16, bool)>,
    pub dacl_protected: Option<bool>,
}

/// Build an MS-DTYP ACE helper.
#[must_use]
pub fn build_simple_ace(kind: u8, flags: u8, mask: u32, sid: NtfsSid) -> NtfsAce {
    NtfsAce {
        kind,
        flags,
        size: 0,
        mask: Some(mask),
        sid: Some(sid),
        object_flags: None,
        object_type: None,
        inherited_object_type: None,
        opaque: Vec::new(),
    }
}

fn rwx_to_allow_mask(bits: u16, is_owner: bool, is_directory: bool) -> u32 {
    let mut mask = STANDARD_READ_CONTROL | 0x0010_0000; // READ_CONTROL | SYNCHRONIZE
    if is_owner {
        mask |= STANDARD_WRITE_DAC | STANDARD_WRITE_OWNER;
    }
    if bits & 0o4 != 0 {
        mask |= FILE_GENERIC_READ;
    }
    if bits & 0o2 != 0 {
        mask |= FILE_GENERIC_WRITE | STANDARD_DELETE;
        if is_directory {
            mask |= FILE_DELETE_CHILD;
        }
    }
    if bits & 0o1 != 0 {
        mask |= FILE_GENERIC_EXECUTE;
    }
    if bits == 0o7 && is_owner {
        mask |= FILE_ALL_ACCESS;
    }
    mask
}

fn rwx_to_deny_mask(bits: u16, other_bits: u16) -> u32 {
    let denied = other_bits & !bits;
    let mut mask = 0_u32;
    if denied & 0o4 != 0 {
        mask |= FILE_READ_DATA;
    }
    if denied & 0o2 != 0 {
        mask |= FILE_WRITE_DATA | 0x0000_0004; // WRITE_DATA | APPEND_DATA
    }
    if denied & 0o1 != 0 {
        mask |= FILE_EXECUTE;
    }
    mask
}

/// Apply an [`NtfsSecurityPatch`] onto `base`, returning validated encoded self-relative SD bytes.
pub fn apply_security_patch(
    base: &NtfsSecurityDescriptor,
    patch: &NtfsSecurityPatch,
) -> Result<Vec<u8>> {
    let mut next = base.clone();
    if let Some(ref owner) = patch.owner {
        next.owner = Some(owner.clone());
    }
    if let Some(ref group) = patch.group {
        next.group = Some(group.clone());
    }
    if let Some(protected) = patch.dacl_protected {
        if protected {
            next.control |= ffs_ondisk::ntfs_security::SE_DACL_PROTECTED;
        } else {
            next.control &= !ffs_ondisk::ntfs_security::SE_DACL_PROTECTED;
        }
    }
    if let Some(ref aces) = patch.replace_dacl {
        let has_obj = aces
            .iter()
            .any(|a| matches!(a.kind, 5 | 6 | 7 | 11 | 12 | 15));
        next.control |= SE_SELF_RELATIVE | SE_DACL_PRESENT;
        next.dacl = NtfsAcl {
            present: true,
            offset: 0,
            revision: Some(if has_obj { 4 } else { 2 }),
            ace_count: Some(
                u16::try_from(aces.len())
                    .map_err(|_| FfsError::Format("DACL ACE count exceeds u16".into()))?,
            ),
            size: None,
            aces: aces.clone(),
            padding: Vec::new(),
        };
    } else if let Some((mode, is_directory)) = patch.posix_mode {
        let owner = next
            .owner
            .clone()
            .unwrap_or_else(|| NtfsSidMap::default().default_owner);
        let group = next
            .group
            .clone()
            .unwrap_or_else(|| NtfsSidMap::default().default_group);
        let everyone = NtfsSid::world_everyone();

        let u_bits = (mode >> 6) & 0o7;
        let g_bits = (mode >> 3) & 0o7;
        let o_bits = mode & 0o7;

        let mut new_aces = Vec::new();
        // Canonical POSIX-to-NTFS DACL: explicit DENY for bits withheld from owner/group
        // that a wider principal holds, followed by explicit ALLOW for owner, group, everyone.
        let owner_deny = rwx_to_deny_mask(u_bits, g_bits | o_bits);
        if owner_deny != 0 {
            new_aces.push(build_simple_ace(
                ACE_TYPE_ACCESS_DENIED,
                0,
                owner_deny,
                owner.clone(),
            ));
        }
        new_aces.push(build_simple_ace(
            ACE_TYPE_ACCESS_ALLOWED,
            0,
            rwx_to_allow_mask(u_bits, true, is_directory),
            owner.clone(),
        ));
        let group_deny = rwx_to_deny_mask(g_bits, o_bits);
        if group_deny != 0 && group != owner {
            new_aces.push(build_simple_ace(
                ACE_TYPE_ACCESS_DENIED,
                0,
                group_deny,
                group.clone(),
            ));
        }
        if group != owner {
            new_aces.push(build_simple_ace(
                ACE_TYPE_ACCESS_ALLOWED,
                0,
                rwx_to_allow_mask(g_bits, false, is_directory),
                group.clone(),
            ));
        }
        if o_bits != 0 {
            new_aces.push(build_simple_ace(
                ACE_TYPE_ACCESS_ALLOWED,
                0,
                rwx_to_allow_mask(o_bits, false, is_directory),
                everyone.clone(),
            ));
        }
        // Preserve any unrelated non-POSIX ACEs (e.g. SYSTEM / Administrators / inherited templates).
        for existing in &base.dacl.aces {
            let sid_matches_posix = existing.sid.as_ref().is_some_and(|s| {
                *s == owner
                    || *s == group
                    || *s == everyone
                    || base.owner.as_ref() == Some(s)
                    || base.group.as_ref() == Some(s)
            });
            if !sid_matches_posix {
                new_aces.push(existing.clone());
            }
        }
        let has_obj = new_aces
            .iter()
            .any(|a| matches!(a.kind, 5 | 6 | 7 | 11 | 12 | 15));
        next.control |= SE_SELF_RELATIVE | SE_DACL_PRESENT;
        next.dacl = NtfsAcl {
            present: true,
            offset: 0,
            revision: Some(if has_obj { 4 } else { 2 }),
            ace_count: Some(
                u16::try_from(new_aces.len())
                    .map_err(|_| FfsError::Format("DACL ACE count exceeds u16".into()))?,
            ),
            size: None,
            aces: new_aces,
            padding: Vec::new(),
        };
    }

    next.encode()
        .map_err(|err| FfsError::Format(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_ondisk::ntfs_security::build_default_ntfs_security_descriptor;

    #[test]
    fn posix_mode_patch_enforces_deny_before_allow_and_roundtrips_projection() {
        let base_bytes = build_default_ntfs_security_descriptor();
        let base = NtfsSecurityDescriptor::parse(&base_bytes).unwrap();
        let map = NtfsSidMap::default();
        let owner = map.sid_for_uid(1000).unwrap();
        let group = map.sid_for_gid(2000).unwrap();

        // Mode 0o044: owner is explicitly denied read while group/other can read!
        let patched_bytes = apply_security_patch(
            &base,
            &NtfsSecurityPatch {
                owner: Some(owner.clone()),
                group: Some(group.clone()),
                posix_mode: Some((0o044, false)),
                ..NtfsSecurityPatch::default()
            },
        )
        .unwrap();
        let patched = NtfsSecurityDescriptor::parse(&patched_bytes).unwrap();
        let owner_tok = NtfsAccessToken {
            user: owner,
            groups: vec![group.clone()],
        };
        assert!(!evaluate_dacl_access(&patched, &owner_tok, FILE_READ_DATA).unwrap());

        let group_tok = NtfsAccessToken {
            user: map.sid_for_uid(1001).unwrap(),
            groups: vec![group],
        };
        assert!(evaluate_dacl_access(&patched, &group_tok, FILE_READ_DATA).unwrap());
        assert!(!evaluate_dacl_access(&patched, &group_tok, FILE_WRITE_DATA).unwrap());
        assert_eq!(map.project_posix_mode(&patched, false), 0o044);
    }
}
