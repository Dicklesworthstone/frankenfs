//! Native FUID ACL records and ZPL creation/chmod policy.
//!
//! Format and policy oracle: OpenZFS zfs-2.4.0 `zfs_acl.h`,
//! `module/os/linux/zfs/zfs_acl.c` (`zfs_acl_inherit`, `zfs_acl_chmod`,
//! `zfs_mode_compute`, and `ace_trivial_common`). This bounded profile supports
//! ordered ALLOW/DENY entries, including named 64-bit FUIDs. Object, audit, and
//! callback ACEs are rejected rather than replaced with a mode-only ACL.
//! This module preserves native policy; it does not evaluate host credentials.

use super::{Endian, Kind, ParseError, invalid, word16};

pub const FILE_INHERIT: u16 = 0x01;
pub const DIRECTORY_INHERIT: u16 = 0x02;
pub const NO_PROPAGATE: u16 = 0x04;
pub const INHERIT_ONLY: u16 = 0x08;
pub const INHERITED: u16 = 0x80;
const ALL_INHERIT: u16 = FILE_INHERIT | DIRECTORY_INHERIT | NO_PROPAGATE | INHERIT_ONLY;
const PRINCIPAL_FLAGS: u16 = 0x7040;
const MAX_ACES: usize = 1024;

const READ_DATA: u32 = 0x01;
const WRITE_DATA: u32 = 0x02;
const APPEND_DATA: u32 = 0x04;
const READ_NAMED: u32 = 0x08;
const WRITE_NAMED: u32 = 0x10;
const EXECUTE: u32 = 0x20;
const DELETE_CHILD: u32 = 0x40;
const READ_ATTRIBUTES: u32 = 0x80;
const WRITE_ATTRIBUTES: u32 = 0x100;
const DELETE: u32 = 0x1_0000;
const READ_ACL: u32 = 0x2_0000;
const WRITE_ACL: u32 = 0x4_0000;
const WRITE_OWNER: u32 = 0x8_0000;
const SYNCHRONIZE: u32 = 0x10_0000;
const READ_METADATA: u32 = READ_NAMED | READ_ATTRIBUTES | READ_ACL | SYNCHRONIZE;
const WRITE_METADATA: u32 = WRITE_NAMED | WRITE_ATTRIBUTES | WRITE_ACL | WRITE_OWNER;

pub const ZFS_INHERIT_ACE: u64 = 0x02;
pub const ZFS_ACL_TRIVIAL: u64 = 0x04;
pub const ZFS_ACL_AUTO_INHERIT: u64 = 0x40;
pub const ZFS_NO_EXECS_DENIED: u64 = 0x100;
/// Flags recomputed from the supported ACL, excluding protected/defaulted state.
pub const COMPUTED_FLAGS: u64 = ZFS_INHERIT_ACE | ZFS_ACL_TRIVIAL | ZFS_NO_EXECS_DENIED;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclInherit {
    Discard,
    NoAllow,
    Restricted,
    Passthrough,
    PassthroughX,
}

impl AclInherit {
    pub fn from_property(value: u64) -> Result<Self, ParseError> {
        match value {
            0 => Ok(Self::Discard),
            1 => Ok(Self::NoAllow),
            3 => Ok(Self::Passthrough),
            4 => Ok(Self::Restricted),
            5 => Ok(Self::PassthroughX),
            _ => Err(invalid("unsupported native aclinherit property")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AclMode {
    Discard,
    GroupMask,
    Passthrough,
    Restricted,
}

impl AclMode {
    pub fn from_property(value: u64) -> Result<Self, ParseError> {
        match value {
            0 => Ok(Self::Discard),
            2 => Ok(Self::GroupMask),
            3 => Ok(Self::Passthrough),
            4 => Ok(Self::Restricted),
            _ => Err(invalid("unsupported native aclmode property")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AceKind {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Principal {
    Owner,
    OwningGroup,
    Everyone,
    User(u64),
    Group(u64),
}

impl Principal {
    const fn flags(self) -> u16 {
        match self {
            Self::Owner => 0x1000,
            Self::OwningGroup => 0x2040,
            Self::Everyone => 0x4000,
            Self::User(_) => 0,
            Self::Group(_) => 0x0040,
        }
    }

    const fn special(self) -> bool {
        matches!(self, Self::Owner | Self::OwningGroup | Self::Everyone)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ace {
    pub kind: AceKind,
    /// Native flags excluding principal selector bits (which `principal` owns).
    pub flags: u16,
    pub access_mask: u32,
    pub principal: Principal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeAcl {
    aces: Vec<Ace>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedAcl {
    pub acl: NativeAcl,
    pub mode: u64,
    /// Computed ACL hints, plus AUTO_INHERIT for creation requiring chmod.
    pub flags: u64,
}

impl NativeAcl {
    pub fn new(aces: Vec<Ace>) -> Result<Self, ParseError> {
        if aces.len() > MAX_ACES {
            return Err(invalid("native ACL exceeds the 1024-entry writer profile"));
        }
        for ace in &aces {
            if ace.flags & !0x00bf != 0
                || ace.access_mask & !0x001f_01ff != 0
                || (ace.flags & (NO_PROPAGATE | INHERIT_ONLY) != 0
                    && ace.flags & (FILE_INHERIT | DIRECTORY_INHERIT) == 0)
            {
                return Err(invalid(
                    "invalid or unsupported native ACE flags or access mask",
                ));
            }
        }
        Ok(Self { aces })
    }

    pub fn parse_v1(raw: &[u8], count: u64, order: Endian) -> Result<Self, ParseError> {
        let count = usize::try_from(count)
            .ok()
            .filter(|&value| value <= MAX_ACES)
            .ok_or_else(|| invalid("native ACL count exceeds the writer profile"))?;
        if raw.len() < count * 8 || raw.len() > count * 16 {
            return Err(invalid(
                "native ACL byte count disagrees with its ACE count",
            ));
        }
        let mut aces = Vec::with_capacity(count);
        let mut offset = 0;
        for _ in 0..count {
            let kind = match word16(raw, offset, order)? {
                0 => AceKind::Allow,
                1 => AceKind::Deny,
                _ => {
                    return Err(invalid(
                        "native object, audit, or callback ACE is unsupported",
                    ));
                }
            };
            let flags = word16(raw, offset + 2, order)?;
            let mask_bytes: [u8; 4] = raw
                .get(offset + 4..offset + 8)
                .ok_or_else(|| invalid("truncated native ACE access mask"))?
                .try_into()
                .map_err(|_| invalid("truncated native ACE access mask"))?;
            let access_mask = match order {
                Endian::Little => u32::from_le_bytes(mask_bytes),
                Endian::Big => u32::from_be_bytes(mask_bytes),
            };
            let principal = match flags & PRINCIPAL_FLAGS {
                0x1000 => Principal::Owner,
                0x2040 => Principal::OwningGroup,
                0x4000 => Principal::Everyone,
                0 => Principal::User(order.u64(raw, offset + 8)?),
                0x0040 => Principal::Group(order.u64(raw, offset + 8)?),
                _ => return Err(invalid("invalid native ACE principal selector")),
            };
            offset += if principal.special() { 8 } else { 16 };
            aces.push(Ace {
                kind,
                flags: flags & !PRINCIPAL_FLAGS,
                access_mask,
                principal,
            });
        }
        if offset != raw.len() {
            return Err(invalid("trailing bytes after the declared native ACEs"));
        }
        Self::new(aces)
    }

    #[must_use]
    pub fn aces(&self) -> &[Ace] {
        &self.aces
    }

    #[must_use]
    pub fn encode_v1(&self, order: Endian) -> Vec<u8> {
        let mut raw = Vec::with_capacity(self.aces.len() * 16);
        for ace in &self.aces {
            let kind = u16::from(ace.kind == AceKind::Deny);
            let flags = ace.flags | ace.principal.flags();
            match order {
                Endian::Little => {
                    raw.extend_from_slice(&kind.to_le_bytes());
                    raw.extend_from_slice(&flags.to_le_bytes());
                    raw.extend_from_slice(&ace.access_mask.to_le_bytes());
                }
                Endian::Big => {
                    raw.extend_from_slice(&kind.to_be_bytes());
                    raw.extend_from_slice(&flags.to_be_bytes());
                    raw.extend_from_slice(&ace.access_mask.to_be_bytes());
                }
            }
            if let Principal::User(fuid) | Principal::Group(fuid) = ace.principal {
                raw.extend_from_slice(&order.encode(fuid));
            }
        }
        raw
    }

    #[must_use]
    pub fn has_inheritable_aces(&self) -> bool {
        self.aces
            .iter()
            .any(|ace| ace.flags & (FILE_INHERIT | DIRECTORY_INHERIT) != 0)
    }

    /// Native triviality is a structural permission predicate, not a comparison
    /// against one preferred encoding. INHERITED alone does not make it complex.
    #[must_use]
    pub fn is_trivial(&self) -> bool {
        self.aces.iter().all(|ace| {
            ace.principal.special()
                && ace.flags & ALL_INHERIT == 0
                && !(ace.kind == AceKind::Deny
                    && ace.access_mask & (READ_ACL | READ_ATTRIBUTES) != 0)
                && ace.access_mask & DELETE == 0
                && (ace.access_mask & DELETE_CHILD == 0 || ace.access_mask & WRITE_DATA != 0)
                && !(ace.kind == AceKind::Allow
                    && ace.principal != Principal::Owner
                    && ace.access_mask & WRITE_METADATA != 0)
        })
    }

    #[must_use]
    pub fn trivial(mode: u64, directory: bool) -> Self {
        Self {
            aces: mode_aces(mode, directory),
        }
    }

    /// Apply native inheritance to a new regular file or directory. Requested
    /// mode already includes caller/umask policy; passthrough may replace its
    /// permission bits, exactly as native `zfs_acl_ids_create` does.
    #[allow(clippy::too_many_arguments)]
    pub fn inherit(
        &self,
        kind: Kind,
        mode: u64,
        uid: u64,
        gid: u64,
        policy: AclInherit,
        aclmode: AclMode,
    ) -> Result<AppliedAcl, ParseError> {
        if !matches!(kind, Kind::Regular | Kind::Directory) {
            return Err(invalid(
                "native ACL inheritance requires a regular file or directory",
            ));
        }
        let directory = kind == Kind::Directory;
        let mut inherited = Vec::new();
        let mut need_chmod = true;
        if policy != AclInherit::Discard {
            for parent in &self.aces {
                let applies = if directory && parent.flags & DIRECTORY_INHERIT != 0 {
                    true
                } else {
                    parent.flags & FILE_INHERIT != 0
                        && !(directory && parent.flags & NO_PROPAGATE != 0)
                };
                if !applies || (policy == AclInherit::NoAllow && parent.kind == AceKind::Allow) {
                    continue;
                }
                if matches!(policy, AclInherit::Passthrough | AclInherit::PassthroughX)
                    && parent.principal.special()
                    && (!directory || parent.flags & DIRECTORY_INHERIT != 0)
                {
                    need_chmod = false;
                }
                let mut ace = *parent;
                ace.flags |= INHERITED;
                if ace.kind == AceKind::Allow {
                    if policy == AclInherit::Restricted {
                        ace.access_mask &= !(WRITE_ACL | WRITE_OWNER);
                    }
                    if policy == AclInherit::PassthroughX && !directory && mode & 0o111 == 0 {
                        ace.access_mask &= !EXECUTE;
                    }
                }
                if !directory || parent.flags & NO_PROPAGATE != 0 {
                    ace.flags &= !ALL_INHERIT;
                } else if parent.flags & DIRECTORY_INHERIT == 0 {
                    ace.flags |= INHERIT_ONLY;
                } else {
                    ace.flags &= !INHERIT_ONLY;
                }
                inherited.push(ace);
            }
        }
        if aclmode == AclMode::Restricted && !inherited.is_empty() {
            need_chmod = false;
        }
        let mut acl = Self::new(inherited)?;
        if need_chmod {
            let trim = aclmode == AclMode::GroupMask
                && !matches!(policy, AclInherit::Passthrough | AclInherit::PassthroughX);
            acl = acl.with_mode(mode, directory, false, trim)?;
        }
        let (mode, mut flags) = acl.mode_and_flags(mode, uid, gid, directory);
        if need_chmod && directory {
            flags |= ZFS_ACL_AUTO_INHERIT;
        }
        Ok(AppliedAcl { acl, mode, flags })
    }

    /// Apply native chmod without dropping named/inheritable entries under
    /// passthrough/groupmask. Restricted refuses a nontrivial ACL.
    pub fn chmod(
        &self,
        kind: Kind,
        mode: u64,
        uid: u64,
        gid: u64,
        policy: AclMode,
    ) -> Result<AppliedAcl, ParseError> {
        if policy == AclMode::Restricted && !self.is_trivial() {
            return Err(invalid(
                "aclmode=restricted forbids chmod of a nontrivial ACL",
            ));
        }
        let directory = kind == Kind::Directory;
        let acl = if policy == AclMode::Discard {
            Self::trivial(mode, directory)
        } else {
            self.with_mode(mode, directory, true, policy == AclMode::GroupMask)?
        };
        let (mode, flags) = acl.mode_and_flags(mode, uid, gid, directory);
        Ok(AppliedAcl { acl, mode, flags })
    }

    /// Recompute the stored mode/execute shortcut when a named FUID becomes or
    /// ceases to be the object's owner or owning group. ACE bytes are unchanged.
    #[must_use]
    pub fn ownership_mode(&self, kind: Kind, mode: u64, uid: u64, gid: u64) -> (u64, u64) {
        self.mode_and_flags(mode, uid, gid, kind == Kind::Directory)
    }

    fn with_mode(
        &self,
        mode: u64,
        directory: bool,
        split: bool,
        trim: bool,
    ) -> Result<Self, ParseError> {
        let mut result = mode_aces(mode, directory);
        let tail = result.split_off(result.len() - 3);
        let group_mask = tail[1].access_mask;
        for original in &self.aces {
            let mut ace = *original;
            if split && ace.principal.special() {
                if !directory || ace.flags & (FILE_INHERIT | DIRECTORY_INHERIT) == 0 {
                    continue;
                }
                ace.flags |= INHERIT_ONLY;
            }
            if trim && ace.kind == AceKind::Allow && ace.flags & INHERIT_ONLY == 0 {
                ace.access_mask &= group_mask;
            }
            result.push(ace);
        }
        result.extend(tail);
        Self::new(result)
    }

    fn mode_and_flags(&self, mode: u64, uid: u64, gid: u64, directory: bool) -> (u64, u64) {
        let mut computed = mode & !0o777;
        let mut seen = 0;
        let mut named_exec_denial = false;
        for ace in &self.aces {
            if ace.flags & INHERIT_ONLY != 0 {
                continue;
            }
            let classes: &[u32] = match ace.principal {
                Principal::Owner => &[6],
                Principal::User(who) if who == uid => &[6],
                Principal::OwningGroup => &[3],
                Principal::Group(who) if who == gid => &[3],
                Principal::Everyone => &[6, 3, 0],
                _ => {
                    named_exec_denial |=
                        ace.kind == AceKind::Deny && ace.access_mask & EXECUTE != 0;
                    &[]
                }
            };
            for &shift in classes {
                for (access, bit) in [(READ_DATA, 4_u64), (WRITE_DATA, 2), (EXECUTE, 1)] {
                    let permission = bit << shift;
                    if ace.access_mask & access != 0 && seen & permission == 0 {
                        seen |= permission;
                        if ace.kind == AceKind::Allow {
                            computed |= permission;
                        }
                    }
                }
            }
        }
        let mut flags = 0;
        if directory && self.has_inheritable_aces() {
            flags |= ZFS_INHERIT_ACE;
        }
        if self.is_trivial() {
            flags |= ZFS_ACL_TRIVIAL;
        }
        if !named_exec_denial && computed & 0o111 == 0o111 {
            flags |= ZFS_NO_EXECS_DENIED;
        }
        (computed, flags)
    }
}

fn mode_aces(mode: u64, directory: bool) -> Vec<Ace> {
    let permissions = |bits: u64| {
        let mut mask = 0;
        if bits & 4 != 0 {
            mask |= READ_DATA;
        }
        if bits & 2 != 0 {
            mask |= WRITE_DATA | APPEND_DATA;
            if directory {
                mask |= DELETE_CHILD;
            }
        }
        if bits & 1 != 0 {
            mask |= EXECUTE;
        }
        mask
    };
    let owner = permissions((mode >> 6) & 7);
    let group = permissions((mode >> 3) & 7);
    let everyone = permissions(mode & 7);
    [
        (AceKind::Allow, Principal::Owner, owner & everyone & !group),
        (AceKind::Deny, Principal::Owner, (group | everyone) & !owner),
        (AceKind::Deny, Principal::OwningGroup, everyone & !group),
        (
            AceKind::Allow,
            Principal::Owner,
            owner | READ_METADATA | WRITE_METADATA,
        ),
        (
            AceKind::Allow,
            Principal::OwningGroup,
            group | READ_METADATA,
        ),
        (
            AceKind::Allow,
            Principal::Everyone,
            everyone | READ_METADATA,
        ),
    ]
    .into_iter()
    .filter(|(_, _, access_mask)| *access_mask != 0)
    .map(|(kind, principal, access_mask)| Ace {
        kind,
        flags: 0,
        access_mask,
        principal,
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ace(kind: AceKind, principal: Principal, flags: u16, access_mask: u32) -> Ace {
        Ace {
            kind,
            flags,
            access_mask,
            principal,
        }
    }

    #[test]
    fn native_fuid_widths_orders_and_malformed_boundaries() {
        // Independent on-disk bytes: compact OWNER@ followed by a named group.
        for order in [Endian::Little, Endian::Big] {
            let (raw, expected_fuid) = match order {
                Endian::Little => (
                    vec![
                        0, 0, 3, 0x10, 0x21, 0, 0, 0, 1, 0, 0x43, 0, 0x20, 0, 0, 0, 8, 7, 6, 5, 4,
                        3, 2, 1,
                    ],
                    0x0102_0304_0506_0708,
                ),
                Endian::Big => (
                    vec![
                        0, 0, 0x10, 3, 0, 0, 0, 0x21, 0, 1, 0, 0x43, 0, 0, 0, 0x20, 1, 2, 3, 4, 5,
                        6, 7, 8,
                    ],
                    0x0102_0304_0506_0708,
                ),
            };
            let acl = NativeAcl::parse_v1(&raw, 2, order).unwrap();
            assert_eq!(
                acl.aces(),
                &[
                    ace(AceKind::Allow, Principal::Owner, 3, 0x21),
                    ace(AceKind::Deny, Principal::Group(expected_fuid), 3, 0x20),
                ]
            );
            assert_eq!(acl.encode_v1(order), raw);
            assert!(NativeAcl::parse_v1(&raw, 1, order).is_err());
            assert!(NativeAcl::parse_v1(&raw[..23], 2, order).is_err());
            assert!(NativeAcl::parse_v1(&raw, 1025, order).is_err());
            let mut object_ace = raw.clone();
            object_ace[..2].copy_from_slice(&match order {
                Endian::Little => 5_u16.to_le_bytes(),
                Endian::Big => 5_u16.to_be_bytes(),
            });
            assert!(NativeAcl::parse_v1(&object_ace, 2, order).is_err());
        }
        assert!(
            NativeAcl::new(vec![ace(AceKind::Allow, Principal::Owner, INHERIT_ONLY, 1)]).is_err()
        );
        assert!(NativeAcl::new(vec![ace(AceKind::Allow, Principal::Owner, 0x400, 1)]).is_err());
        assert!(
            NativeAcl::new(vec![ace(AceKind::Allow, Principal::Owner, 0, 0x8000_0000)]).is_err()
        );
    }

    #[test]
    fn native_file_directory_and_no_propagate_inheritance() {
        let parent = NativeAcl::new(vec![
            ace(AceKind::Allow, Principal::User(71), FILE_INHERIT, READ_DATA),
            ace(
                AceKind::Deny,
                Principal::Group(72),
                FILE_INHERIT | DIRECTORY_INHERIT | NO_PROPAGATE,
                EXECUTE,
            ),
            ace(
                AceKind::Allow,
                Principal::User(73),
                FILE_INHERIT | NO_PROPAGATE,
                WRITE_DATA,
            ),
            ace(
                AceKind::Allow,
                Principal::Everyone,
                DIRECTORY_INHERIT | INHERIT_ONLY,
                READ_DATA,
            ),
        ])
        .unwrap();
        let child = parent
            .inherit(
                Kind::Directory,
                0o040_777,
                1,
                2,
                AclInherit::Passthrough,
                AclMode::Passthrough,
            )
            .unwrap();
        assert_eq!(
            child.acl.aces(),
            &[
                ace(
                    AceKind::Allow,
                    Principal::User(71),
                    FILE_INHERIT | INHERIT_ONLY | INHERITED,
                    READ_DATA
                ),
                ace(AceKind::Deny, Principal::Group(72), INHERITED, EXECUTE),
                ace(
                    AceKind::Allow,
                    Principal::Everyone,
                    DIRECTORY_INHERIT | INHERITED,
                    READ_DATA
                ),
            ]
        );
        assert_eq!(child.mode, 0o040_444);
        assert_eq!(child.flags, ZFS_INHERIT_ACE);
        let grandchild = child
            .acl
            .inherit(
                Kind::Regular,
                0o100_640,
                1,
                2,
                AclInherit::Passthrough,
                AclMode::Passthrough,
            )
            .unwrap();
        assert_eq!(
            grandchild.acl.aces()[0],
            ace(AceKind::Allow, Principal::User(71), INHERITED, READ_DATA)
        );
        assert_eq!(grandchild.acl.aces().len(), 4); // named entry + mode's three special entries
        assert!(!grandchild.acl.has_inheritable_aces());
        assert!(
            grandchild
                .acl
                .aces()
                .iter()
                .all(|a| !matches!(a.principal, Principal::Group(72) | Principal::User(73)))
        );
        assert_eq!(grandchild.mode, 0o100_640);
    }

    #[test]
    fn native_restricted_noallow_and_groupmask_keep_ordered_denials() {
        let parent = NativeAcl::new(vec![
            ace(
                AceKind::Allow,
                Principal::User(77),
                3,
                READ_DATA | WRITE_DATA | EXECUTE | READ_ACL | WRITE_ACL | WRITE_OWNER,
            ),
            ace(AceKind::Deny, Principal::Group(88), 3, EXECUTE),
            ace(AceKind::Allow, Principal::Everyone, 3, READ_DATA | EXECUTE),
        ])
        .unwrap();
        let restricted = parent
            .inherit(
                Kind::Regular,
                0o100_640,
                1,
                2,
                AclInherit::Restricted,
                AclMode::Discard,
            )
            .unwrap();
        assert_eq!(
            restricted.acl.aces()[0],
            ace(AceKind::Allow, Principal::User(77), INHERITED, 0x0002_0023)
        );
        assert_eq!(
            restricted.acl.aces()[1],
            ace(AceKind::Deny, Principal::Group(88), INHERITED, EXECUTE)
        );
        assert_eq!(restricted.mode, 0o100_755);
        assert_eq!(restricted.flags & ZFS_NO_EXECS_DENIED, 0); // named group denies execute
        let groupmask = parent
            .inherit(
                Kind::Regular,
                0o100_640,
                1,
                2,
                AclInherit::Restricted,
                AclMode::GroupMask,
            )
            .unwrap();
        assert_eq!(groupmask.acl.aces()[0].access_mask, READ_DATA | READ_ACL);
        assert_eq!(groupmask.acl.aces()[1].access_mask, EXECUTE);
        assert_eq!(groupmask.acl.aces()[2].access_mask, READ_DATA);
        assert_eq!(groupmask.mode, 0o100_644);
        let noallow = parent
            .inherit(
                Kind::Regular,
                0o100_640,
                1,
                2,
                AclInherit::NoAllow,
                AclMode::Discard,
            )
            .unwrap();
        assert_eq!(noallow.acl.aces()[0].kind, AceKind::Deny);
        assert_eq!(noallow.acl.aces().len(), 4);
        assert_eq!(noallow.mode, 0o100_640);
        let discard = parent
            .inherit(
                Kind::Directory,
                0o040_750,
                1,
                2,
                AclInherit::Discard,
                AclMode::Restricted,
            )
            .unwrap();
        assert!(discard.acl.is_trivial());
        assert_eq!(discard.mode, 0o040_750);
        assert_eq!(discard.flags, ZFS_ACL_TRIVIAL | ZFS_ACL_AUTO_INHERIT);
    }

    #[test]
    fn passthrough_x_uses_any_requested_execute_and_restricted_mode_skips_chmod() {
        let parent = NativeAcl::new(vec![ace(
            AceKind::Allow,
            Principal::Everyone,
            3,
            READ_DATA | WRITE_DATA | APPEND_DATA | EXECUTE,
        )])
        .unwrap();
        for (kind, mode, expected) in [
            (Kind::Regular, 0o100_644, 0o100_666),
            (Kind::Regular, 0o100_641, 0o100_777),
            (Kind::Directory, 0o040_644, 0o040_777),
        ] {
            let child = parent
                .inherit(
                    kind,
                    mode,
                    1,
                    2,
                    AclInherit::PassthroughX,
                    AclMode::GroupMask,
                )
                .unwrap();
            assert_eq!(child.mode, expected);
            assert_eq!(child.acl.aces().len(), 1);
            assert_eq!(child.flags & ZFS_ACL_AUTO_INHERIT, 0);
        }
        let plain = parent
            .inherit(
                Kind::Regular,
                0o100_600,
                1,
                2,
                AclInherit::Passthrough,
                AclMode::Discard,
            )
            .unwrap();
        assert_eq!(plain.mode, 0o100_777);
        let restricted = parent
            .inherit(
                Kind::Regular,
                0o100_600,
                1,
                2,
                AclInherit::Restricted,
                AclMode::Restricted,
            )
            .unwrap();
        assert_eq!(restricted.acl.aces().len(), 1);
        assert_eq!(restricted.mode, 0o100_777);
    }

    #[test]
    fn chmod_preserves_inherited_template_and_named_principals_under_native_policy() {
        let parent = NativeAcl::new(vec![
            ace(
                AceKind::Allow,
                Principal::Owner,
                3,
                READ_DATA | WRITE_DATA | EXECUTE,
            ),
            ace(
                AceKind::Allow,
                Principal::User(90),
                3,
                READ_DATA | WRITE_DATA | EXECUTE | WRITE_OWNER,
            ),
            ace(AceKind::Deny, Principal::Group(91), 3, EXECUTE),
        ])
        .unwrap();
        let changed = parent
            .chmod(Kind::Directory, 0o040_640, 1, 2, AclMode::GroupMask)
            .unwrap();
        assert_eq!(
            changed.acl.aces()[0],
            ace(AceKind::Allow, Principal::Owner, 3 | INHERIT_ONLY, 0x23)
        );
        assert_eq!(
            changed.acl.aces()[1],
            ace(AceKind::Allow, Principal::User(90), 3, READ_DATA)
        );
        assert_eq!(changed.acl.aces()[2].kind, AceKind::Deny);
        assert_eq!(changed.mode, 0o040_640);
        assert_eq!(changed.flags & ZFS_INHERIT_ACE, ZFS_INHERIT_ACE);
        assert!(
            parent
                .chmod(Kind::Directory, 0o040_640, 1, 2, AclMode::Restricted)
                .is_err()
        );
        let discarded = parent
            .chmod(Kind::Directory, 0o040_640, 1, 2, AclMode::Discard)
            .unwrap();
        assert!(discarded.acl.is_trivial());
        assert!(!discarded.acl.has_inheritable_aces());
        let untouched = parent
            .chmod(Kind::Directory, 0o040_640, 1, 2, AclMode::Passthrough)
            .unwrap();
        assert_eq!(untouched.acl.aces()[1].access_mask, 0x0008_0023);
    }

    #[test]
    fn owner_changes_recompute_named_fuid_mode_and_execute_shortcut() {
        let acl = NativeAcl::new(vec![
            ace(AceKind::Deny, Principal::User(77), 0, WRITE_DATA | EXECUTE),
            ace(
                AceKind::Allow,
                Principal::Everyone,
                0,
                READ_DATA | WRITE_DATA | EXECUTE,
            ),
        ])
        .unwrap();
        assert_eq!(
            acl.ownership_mode(Kind::Regular, 0o104_777, 77, 1),
            (0o104_477, 0)
        );
        assert_eq!(
            acl.ownership_mode(Kind::Regular, 0o104_477, 88, 1),
            (0o104_777, 0)
        );
    }
}
