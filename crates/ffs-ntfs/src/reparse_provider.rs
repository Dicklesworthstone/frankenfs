//! Explicit NTFS reparse-point provider capability classification.
//!
//! Recognizing a reparse tag never authorizes interpreting its `$DATA` stream
//! as an ordinary file or directory. Unknown/opaque tags (such as Cloud Files
//! placeholders, WSL tags, or third-party GUID tags) remain inspectable and
//! metadata-preservable without degrading into empty files.

use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::reparse::{MOUNT_POINT_TAG, NtfsReparseData, NtfsReparsePoint, SYMLINK_TAG};

use crate::reader::wof::TAG as WOF_TAG;

/// Explicit capability granted to a parsed NTFS reparse point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReparseCapability {
    /// Native NTFS symbolic link (`0xA000_000C`): target inspectable via `readlink`.
    Symlink { relative: bool },
    /// Native NTFS directory mount point / junction (`0xA000_0003`): target inspectable,
    /// not automatically traversed into arbitrary host paths.
    MountPoint,
    /// WOF individual-file compression provider (`0x8000_0017`, version 1 file provider).
    WofFileProvider,
    /// Unknown or unimplemented reparse provider (Cloud Files, WIM, WSL, custom GUID):
    /// tag, optional GUID, and exact opaque payload bytes are preserved on metadata/namespace
    /// mutations, while logical `$DATA` / directory traversal fail closed with `UnsupportedFeature`.
    OpaquePreserved { tag: u32 },
}

/// Classify a parsed [`NtfsReparsePoint`] into its explicit provider capability.
#[must_use]
pub fn classify_reparse_point(point: &NtfsReparsePoint) -> ReparseCapability {
    match (point.tag, &point.data) {
        (SYMLINK_TAG, NtfsReparseData::SymbolicLink { relative, .. }) => {
            ReparseCapability::Symlink {
                relative: *relative,
            }
        }
        (MOUNT_POINT_TAG, NtfsReparseData::MountPoint { .. }) => ReparseCapability::MountPoint,
        (WOF_TAG, NtfsReparseData::Opaque(bytes))
            if point.guid.is_none()
                && matches!(bytes.len(), 16 | 20)
                && bytes[0..4] == 1_u32.to_le_bytes()
                && bytes[4..8] == 2_u32.to_le_bytes()
                && bytes[8..12] == 1_u32.to_le_bytes()
                && (bytes.len() == 16 || bytes[16..20] == 0_u32.to_le_bytes())
                && matches!(
                    u32::from_le_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]),
                    0..=3
                ) =>
        {
            ReparseCapability::WofFileProvider
        }
        (tag, _) => ReparseCapability::OpaquePreserved { tag },
    }
}

/// Validate a reparse point before writing it onto a target MFT record.
///
/// Unless `allow_opaque` is explicitly enabled, unknown/opaque reparse providers
/// are rejected rather than silently installed. WOF (`0x8000_0017`) cannot be
/// installed manually through generic reparse creation because it couples tightly
/// to `WofCompressedData`.
pub fn validate_writable_reparse_point(
    point: &NtfsReparsePoint,
    is_directory: bool,
    allow_opaque: bool,
) -> Result<Vec<u8>> {
    let encoded = point
        .encode()
        .map_err(|err| FfsError::Format(err.to_string()))?;
    match classify_reparse_point(point) {
        ReparseCapability::Symlink { .. } => Ok(encoded),
        ReparseCapability::MountPoint => {
            if !is_directory {
                return Err(FfsError::RequestRejected {
                    errno: libc::ENOTDIR,
                    detail: "NTFS mount-point/junction reparse tag requires a directory target"
                        .into(),
                });
            }
            Ok(encoded)
        }
        ReparseCapability::WofFileProvider => Err(FfsError::UnsupportedFeature(
            "WOF reparse metadata cannot be installed directly without WofCompressedData".into(),
        )),
        ReparseCapability::OpaquePreserved { tag } => {
            if !allow_opaque {
                return Err(FfsError::UnsupportedFeature(format!(
                    "reparse tag {tag:#010x} requires explicit opaque-provider admission"
                )));
            }
            Ok(encoded)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_symlink_junction_wof_and_opaque_tags_distinctly() {
        let sym = NtfsReparsePoint {
            tag: SYMLINK_TAG,
            guid: None,
            data: NtfsReparseData::SymbolicLink {
                substitute: "a\\b".encode_utf16().collect(),
                print: "a\\b".encode_utf16().collect(),
                relative: true,
            },
        };
        assert_eq!(
            classify_reparse_point(&sym),
            ReparseCapability::Symlink { relative: true }
        );
        assert!(validate_writable_reparse_point(&sym, false, false).is_ok());

        let mp = NtfsReparsePoint {
            tag: MOUNT_POINT_TAG,
            guid: None,
            data: NtfsReparseData::MountPoint {
                substitute: "\\??\\C:\\vol".encode_utf16().collect(),
                print: "C:\\vol".encode_utf16().collect(),
            },
        };
        assert_eq!(classify_reparse_point(&mp), ReparseCapability::MountPoint);
        assert!(validate_writable_reparse_point(&mp, true, false).is_ok());
        assert!(validate_writable_reparse_point(&mp, false, false).is_err());

        let mut wof_body = Vec::new();
        wof_body.extend_from_slice(&1_u32.to_le_bytes());
        wof_body.extend_from_slice(&2_u32.to_le_bytes());
        wof_body.extend_from_slice(&1_u32.to_le_bytes());
        wof_body.extend_from_slice(&0_u32.to_le_bytes());
        let wof = NtfsReparsePoint {
            tag: WOF_TAG,
            guid: None,
            data: NtfsReparseData::Opaque(wof_body),
        };
        assert_eq!(
            classify_reparse_point(&wof),
            ReparseCapability::WofFileProvider
        );
        assert!(validate_writable_reparse_point(&wof, false, true).is_err());

        let cloud = NtfsReparsePoint {
            tag: 0x9000_101A,
            guid: None,
            data: NtfsReparseData::Opaque(vec![0xFE, 0x01, 0x02, 0x03]),
        };
        assert_eq!(
            classify_reparse_point(&cloud),
            ReparseCapability::OpaquePreserved { tag: 0x9000_101A }
        );
        assert!(validate_writable_reparse_point(&cloud, false, false).is_err());
        assert!(validate_writable_reparse_point(&cloud, false, true).is_ok());
    }
}
