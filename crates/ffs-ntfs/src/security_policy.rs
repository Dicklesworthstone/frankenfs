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
    ACE_FLAG_CONTAINER_INHERIT, ACE_FLAG_INHERIT_ONLY, ACE_FLAG_OBJECT_INHERIT,
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
    /// Apply POSIX `0o777` mode bits while retaining native DENYs, inheritance
    /// templates and the SACL. Ambiguous effective ACEs or a mode that conflicts
    /// with retained restrictions are refused; explicit DACL replacement is a
    /// separate operation. An exactly representable POSIX DACL remains editable.
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

fn posix_aces(owner: &NtfsSid, group: &NtfsSid, mode: u16, is_directory: bool) -> Vec<NtfsAce> {
    let u_bits = (mode >> 6) & 0o7;
    let g_bits = (mode >> 3) & 0o7;
    let o_bits = mode & 0o7;
    let mut aces = Vec::new();
    let owner_deny = rwx_to_deny_mask(u_bits, g_bits | o_bits);
    if owner_deny != 0 {
        aces.push(build_simple_ace(
            ACE_TYPE_ACCESS_DENIED,
            0,
            owner_deny,
            owner.clone(),
        ));
    }
    // The owner's grant precedes the group DENY: an owner who belongs to that
    // group still receives the owner's POSIX permissions.
    aces.push(build_simple_ace(
        ACE_TYPE_ACCESS_ALLOWED,
        0,
        rwx_to_allow_mask(u_bits, true, is_directory),
        owner.clone(),
    ));
    let group_deny = rwx_to_deny_mask(g_bits, o_bits);
    if group_deny != 0 && group != owner {
        aces.push(build_simple_ace(
            ACE_TYPE_ACCESS_DENIED,
            0,
            group_deny,
            group.clone(),
        ));
    }
    if group != owner {
        aces.push(build_simple_ace(
            ACE_TYPE_ACCESS_ALLOWED,
            0,
            rwx_to_allow_mask(g_bits, false, is_directory),
            group.clone(),
        ));
    }
    if o_bits != 0 {
        aces.push(build_simple_ace(
            ACE_TYPE_ACCESS_ALLOWED,
            0,
            rwx_to_allow_mask(o_bits, false, is_directory),
            NtfsSid::world_everyone(),
        ));
    }
    aces
}

fn posix_dacl_start(base: &NtfsSecurityDescriptor, is_directory: bool) -> Result<Option<usize>> {
    let (Some(owner), Some(group)) = (&base.owner, &base.group) else {
        return Ok(None);
    };
    let mode = NtfsSidMap::default().project_posix_mode(base, is_directory);
    let canonical = posix_aces(owner, group, mode, is_directory);
    let Some(start) = base.dacl.aces.len().checked_sub(canonical.len()) else {
        return Ok(None);
    };
    for (actual, expected) in base.dacl.aces[start..].iter().zip(&canonical) {
        // Parsed ACEs carry their encoded size; freshly built ACEs do not.
        if actual
            .encode()
            .map_err(|err| FfsError::Format(err.to_string()))?
            != expected
                .encode()
                .map_err(|err| FfsError::Format(err.to_string()))?
        {
            return Ok(None);
        }
    }
    Ok(Some(start))
}

fn validate_effective_ace(ace: &NtfsAce) -> Result<()> {
    if ace.flags & ACE_FLAG_INHERIT_ONLY == 0
        && (!matches!(ace.kind, ACE_TYPE_ACCESS_ALLOWED | ACE_TYPE_ACCESS_DENIED)
            || !ace.opaque.is_empty()
            || ace.mask.is_none()
            || ace.sid.is_none())
    {
        return Err(FfsError::UnsupportedFeature(
            "POSIX mode change cannot preserve an opaque or complex effective NTFS ACE".into(),
        ));
    }
    Ok(())
}

fn retain_native_aces(
    base: &NtfsSecurityDescriptor,
    owner: &NtfsSid,
    group: &NtfsSid,
) -> Result<Vec<NtfsAce>> {
    let everyone = NtfsSid::world_everyone();
    let mut retained = Vec::new();
    let mut saw_effective_allow = false;
    for ace in &base.dacl.aces {
        if ace.flags & ACE_FLAG_INHERIT_ONLY != 0 {
            // Child templates, including opaque/object ACEs, are not current
            // object access decisions. Keep their exact bytes and native order.
            retained.push(ace.clone());
            continue;
        }
        validate_effective_ace(ace)?;
        if ace.kind == ACE_TYPE_ACCESS_DENIED {
            if saw_effective_allow {
                return Err(FfsError::UnsupportedFeature(
                    "POSIX mode change cannot reorder a noncanonical NTFS DENY after ALLOW".into(),
                ));
            }
            retained.push(ace.clone());
        } else {
            saw_effective_allow = true;
            let posix_trustee = ace.sid.as_ref().is_some_and(|sid| {
                sid == owner
                    || sid == group
                    || *sid == everyone
                    || base.owner.as_ref() == Some(sid)
                    || base.group.as_ref() == Some(sid)
            });
            if !posix_trustee {
                retained.push(ace.clone());
            } else if ace.flags & (ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_CONTAINER_INHERIT) != 0 {
                // chmod changes this object's grant, not its children's ACLs.
                // Retain propagation independently of the replacement grant.
                let mut template = ace.clone();
                template.flags |= ACE_FLAG_INHERIT_ONLY;
                retained.push(template);
            }
        }
    }
    Ok(retained)
}

/// Apply an [`NtfsSecurityPatch`] onto `base`, returning validated encoded self-relative SD bytes.
pub fn apply_security_patch(
    base: &NtfsSecurityDescriptor,
    patch: &NtfsSecurityPatch,
) -> Result<Vec<u8>> {
    if patch.replace_dacl.is_some() && patch.posix_mode.is_some() {
        return Err(FfsError::UnsupportedFeature(
            "native DACL replacement and POSIX mode change must be separate operations".into(),
        ));
    }
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
        let (Some(owner), Some(group)) = (&next.owner, &next.group) else {
            return Err(FfsError::UnsupportedFeature(
                "POSIX mode change requires explicit NTFS owner and group SIDs".into(),
            ));
        };
        // Only an exact POSIX DACL authorizes replacing synthetic mode DENYs.
        // Native restrictions must never disappear merely because their SID
        // also happens to be the current or next owner/group/Everyone.
        let mut new_aces = if let Some(start) = posix_dacl_start(base, is_directory)? {
            let retained = base.dacl.aces[..start].to_vec();
            for ace in &retained {
                validate_effective_ace(ace)?;
            }
            retained
        } else {
            retain_native_aces(base, owner, group)?
        };
        new_aces.extend(posix_aces(owner, group, mode, is_directory));
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
            padding: base.dacl.padding.clone(),
        };
        if NtfsSidMap::default().project_posix_mode(&next, is_directory) != mode {
            return Err(FfsError::UnsupportedFeature(
                "requested POSIX mode conflicts with retained NTFS restrictions or SID identities"
                    .into(),
            ));
        }
        // The host owner may also belong to the file's group. A retained
        // group DENY cannot be hidden by projecting an owner-only token.
        let owner_token = NtfsAccessToken {
            user: owner.clone(),
            groups: vec![group.clone()],
        };
        for (bit, mask) in [(4, FILE_READ_DATA), (2, FILE_WRITE_DATA), (1, FILE_EXECUTE)] {
            if evaluate_dacl_access(&next, &owner_token, mask)
                .map_err(|err| FfsError::Format(err.to_string()))?
                != (mode >> 6 & bit != 0)
            {
                return Err(FfsError::UnsupportedFeature(
                    "requested POSIX mode conflicts with the owner's native group restrictions"
                        .into(),
                ));
            }
        }
    }

    next.encode()
        .map_err(|err| FfsError::Format(err.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_ondisk::ntfs_security::{
        ACE_FLAG_INHERITED, ACE_FLAG_NO_PROPAGATE_INHERIT, build_default_ntfs_security_descriptor,
        inherit_security_descriptor,
    };

    fn native_descriptor(aces: Vec<NtfsAce>) -> NtfsSecurityDescriptor {
        let mut sd =
            NtfsSecurityDescriptor::parse(&build_default_ntfs_security_descriptor()).unwrap();
        let map = NtfsSidMap::default();
        sd.owner = Some(map.sid_for_uid(1001).unwrap());
        sd.group = Some(map.sid_for_gid(2000).unwrap());
        sd.dacl.revision = Some(4);
        sd.dacl.aces = aces;
        NtfsSecurityDescriptor::parse(&sd.encode().unwrap()).unwrap()
    }

    fn mode_patch(mode: u16, is_directory: bool) -> NtfsSecurityPatch {
        NtfsSecurityPatch {
            posix_mode: Some((mode, is_directory)),
            ..NtfsSecurityPatch::default()
        }
    }

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

    #[test]
    fn posix_mode_preserves_native_deny_before_new_grants_and_after_owner_change() {
        let map = NtfsSidMap::default();
        let denied = map.sid_for_uid(1002).unwrap();
        let mut base = native_descriptor(vec![
            build_simple_ace(ACE_TYPE_ACCESS_DENIED, 0, FILE_WRITE_DATA, denied.clone()),
            build_simple_ace(
                ACE_TYPE_ACCESS_ALLOWED,
                0,
                FILE_ALL_ACCESS,
                NtfsSid::world_everyone(),
            ),
        ]);
        // Changing ownership must not turn a native restriction into a
        // disposable old-owner ACE.
        base.owner = Some(denied.clone());
        let bytes = apply_security_patch(
            &base,
            &NtfsSecurityPatch {
                owner: Some(map.sid_for_uid(1001).unwrap()),
                ..mode_patch(0o666, false)
            },
        )
        .unwrap();
        let patched = NtfsSecurityDescriptor::parse(&bytes).unwrap();
        assert_eq!(
            patched.dacl.aces[0].encode().unwrap(),
            base.dacl.aces[0].encode().unwrap()
        );
        let token = NtfsAccessToken {
            user: denied,
            groups: Vec::new(),
        };
        assert!(!evaluate_dacl_access(&patched, &token, FILE_WRITE_DATA).unwrap());
        assert!(evaluate_dacl_access(&patched, &token, FILE_READ_DATA).unwrap());

        // A later chmod retains that native restriction too.
        let again = NtfsSecurityDescriptor::parse(
            &apply_security_patch(&patched, &mode_patch(0o777, false)).unwrap(),
        )
        .unwrap();
        assert!(!evaluate_dacl_access(&again, &token, FILE_WRITE_DATA).unwrap());
        assert_eq!(again.dacl.aces[0], patched.dacl.aces[0]);
    }

    #[test]
    fn posix_mode_refuses_to_drop_owner_group_or_everyone_deny() {
        let map = NtfsSidMap::default();
        for sid in [
            map.sid_for_uid(1001).unwrap(),
            map.sid_for_gid(2000).unwrap(),
            NtfsSid::world_everyone(),
        ] {
            let base = native_descriptor(vec![
                build_simple_ace(
                    ACE_TYPE_ACCESS_DENIED,
                    ACE_FLAG_INHERITED,
                    FILE_READ_DATA,
                    sid,
                ),
                build_simple_ace(
                    ACE_TYPE_ACCESS_ALLOWED,
                    0,
                    FILE_ALL_ACCESS,
                    NtfsSid::world_everyone(),
                ),
            ]);
            assert!(matches!(
                apply_security_patch(&base, &mode_patch(0o777, false)),
                Err(FfsError::UnsupportedFeature(_))
            ));
        }
    }

    #[test]
    fn posix_mode_keeps_inheritance_templates_identical_for_children() {
        let map = NtfsSidMap::default();
        let mut aces = Vec::new();
        for sid in [
            map.sid_for_uid(1001).unwrap(),
            map.sid_for_gid(2000).unwrap(),
            NtfsSid::world_everyone(),
        ] {
            aces.push(build_simple_ace(
                ACE_TYPE_ACCESS_ALLOWED,
                ACE_FLAG_OBJECT_INHERIT
                    | ACE_FLAG_CONTAINER_INHERIT
                    | ACE_FLAG_NO_PROPAGATE_INHERIT,
                FILE_ALL_ACCESS,
                sid,
            ));
        }
        let mut object_template = build_simple_ace(
            5,
            ACE_FLAG_OBJECT_INHERIT | ACE_FLAG_INHERIT_ONLY,
            FILE_READ_DATA,
            NtfsSid::world_everyone(),
        );
        object_template.object_flags = Some(1);
        object_template.object_type = Some([0x47; 16]);
        aces.push(object_template);
        let base = native_descriptor(aces);
        let patched = NtfsSecurityDescriptor::parse(
            &apply_security_patch(&base, &mode_patch(0o640, true)).unwrap(),
        )
        .unwrap();
        for (before, after) in base.dacl.aces.iter().zip(&patched.dacl.aces) {
            let mut template = before.clone();
            template.flags |= ACE_FLAG_INHERIT_ONLY;
            assert_eq!(after.encode().unwrap(), template.encode().unwrap());
        }
        let owner = map.sid_for_uid(9001).unwrap();
        let group = map.sid_for_gid(9000).unwrap();
        for directory in [false, true] {
            let expected = inherit_security_descriptor(&base, directory, &owner, &group).unwrap();
            let actual = inherit_security_descriptor(&patched, directory, &owner, &group).unwrap();
            assert_eq!(actual.encode().unwrap(), expected.encode().unwrap());
        }
        // Mode updates must not accumulate templates or make generated DENYs sticky.
        let changed = NtfsSecurityDescriptor::parse(
            &apply_security_patch(&patched, &mode_patch(0o044, true)).unwrap(),
        )
        .unwrap();
        let restored = NtfsSecurityDescriptor::parse(
            &apply_security_patch(&changed, &mode_patch(0o640, true)).unwrap(),
        )
        .unwrap();
        assert_eq!(restored.encode().unwrap(), patched.encode().unwrap());
    }

    #[test]
    fn posix_mode_refuses_ambiguous_effective_aces_and_deny_order() {
        let owner = NtfsSidMap::default().sid_for_uid(1001).unwrap();
        let allow = build_simple_ace(ACE_TYPE_ACCESS_ALLOWED, 0, FILE_ALL_ACCESS, owner.clone());
        let mut opaque_allow = allow.clone();
        opaque_allow.opaque = vec![1, 2, 3, 4];
        let mut object_allow = allow.clone();
        object_allow.kind = 5;
        object_allow.object_flags = Some(0);
        let mut callback_deny = allow.clone();
        callback_deny.kind = 10;
        callback_deny.opaque = vec![0; 4];
        for ace in [opaque_allow, object_allow, callback_deny] {
            let base = native_descriptor(vec![ace]);
            assert!(matches!(
                apply_security_patch(&base, &mode_patch(0o644, false)),
                Err(FfsError::UnsupportedFeature(_))
            ));
        }
        let base = native_descriptor(vec![
            allow,
            build_simple_ace(ACE_TYPE_ACCESS_DENIED, 0, FILE_WRITE_DATA, owner),
        ]);
        assert!(matches!(
            apply_security_patch(&base, &mode_patch(0o644, false)),
            Err(FfsError::UnsupportedFeature(_))
        ));
    }

    #[test]
    fn posix_mode_refuses_missing_or_unrepresentable_owner_group_identities() {
        let base = native_descriptor(Vec::new());
        let mut missing_owner = base.clone();
        missing_owner.owner = None;
        let mut same_owner_group = base.clone();
        same_owner_group.group.clone_from(&base.owner);
        let mut everyone_owner = base;
        everyone_owner.owner = Some(NtfsSid::world_everyone());
        for sd in [missing_owner, same_owner_group, everyone_owner] {
            assert!(matches!(
                apply_security_patch(&sd, &mode_patch(0o640, false)),
                Err(FfsError::UnsupportedFeature(_))
            ));
        }
    }

    #[test]
    fn posix_mode_refuses_conflicting_group_membership_and_combined_dacl_replacement() {
        let map = NtfsSidMap::default();
        let base = native_descriptor(vec![
            build_simple_ace(
                ACE_TYPE_ACCESS_DENIED,
                0,
                FILE_READ_DATA,
                map.sid_for_gid(2000).unwrap(),
            ),
            build_simple_ace(
                ACE_TYPE_ACCESS_ALLOWED,
                0,
                FILE_ALL_ACCESS,
                NtfsSid::world_everyone(),
            ),
        ]);
        assert!(matches!(
            apply_security_patch(&base, &mode_patch(0o400, false)),
            Err(FfsError::UnsupportedFeature(_))
        ));
        assert!(matches!(
            apply_security_patch(
                &base,
                &NtfsSecurityPatch {
                    replace_dacl: Some(Vec::new()),
                    ..mode_patch(0o600, false)
                }
            ),
            Err(FfsError::UnsupportedFeature(_))
        ));
    }

    #[test]
    fn every_representable_posix_mode_remains_editable_with_owner_group_precedence() {
        let base = native_descriptor(Vec::new());
        let map = NtfsSidMap::default();
        let owner = NtfsAccessToken {
            user: base.owner.clone().unwrap(),
            groups: vec![base.group.clone().unwrap()],
        };
        let group = NtfsAccessToken {
            user: map.sid_for_uid(9001).unwrap(),
            groups: owner.groups.clone(),
        };
        let other = NtfsAccessToken {
            user: map.sid_for_uid(9002).unwrap(),
            groups: Vec::new(),
        };
        for is_directory in [false, true] {
            for mode in 0..=0o777 {
                let patched = NtfsSecurityDescriptor::parse(
                    &apply_security_patch(&base, &mode_patch(mode, is_directory)).unwrap(),
                )
                .unwrap();
                assert_eq!(map.project_posix_mode(&patched, is_directory), mode);
                for (token, bits) in [(&owner, mode >> 6), (&group, mode >> 3), (&other, mode)] {
                    for (bit, mask) in
                        [(4, FILE_READ_DATA), (2, FILE_WRITE_DATA), (1, FILE_EXECUTE)]
                    {
                        assert_eq!(
                            evaluate_dacl_access(&patched, token, mask).unwrap(),
                            bits & bit != 0
                        );
                    }
                }
                let restored = NtfsSecurityDescriptor::parse(
                    &apply_security_patch(&patched, &mode_patch(0o777, is_directory)).unwrap(),
                )
                .unwrap();
                assert_eq!(map.project_posix_mode(&restored, is_directory), 0o777);
            }
        }
    }
}
