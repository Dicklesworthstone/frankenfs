//! Sequence-bound native directory lookup for the writable filesystem adapter.
//!
//! Reuse the reader's complete `$I30` validation before selecting a mutation
//! target. Exact names take precedence; only Win32 names participate in folded
//! lookup. An ambiguous folded result never grants authority to edit a record.

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::NtfsReference;

use super::{NtfsTransactionEngine, checkpoint, corrupt, validate_ntfs_component_utf16};

impl NtfsTransactionEngine {
    /// Look up one native child, checking both the parent's sequence and the
    /// selected index entry's complete FILE_NAME identity.
    pub fn lookup_reference(
        &self,
        cx: &Cx,
        parent: NtfsReference,
        name: &[u16],
    ) -> Result<NtfsReference> {
        checkpoint(cx)?;
        validate_ntfs_component_utf16(name)?;
        let volume = self.volume_view(cx)?;
        let directory = Self::checked_reference(&volume, cx, parent)?;
        if !directory.is_directory() {
            return Err(FfsError::NotDirectory);
        }
        let entries = volume.list_directory(cx, &directory)?;
        if let Some(entry) = entries.iter().find(|entry| entry.filename.name == name) {
            return Ok(entry.reference);
        }
        let folded = self.fold_upcase(name);
        let mut selected = None;
        for entry in entries {
            checkpoint(cx)?;
            if entry.filename.namespace != 0 && self.fold_upcase(&entry.filename.name) == folded {
                if selected.is_some_and(|previous| previous != entry.reference) {
                    return Err(corrupt(0, "ambiguous folded NTFS mutation target"));
                }
                selected = Some(entry.reference);
            }
        }
        selected.ok_or_else(|| FfsError::NotFound("NTFS directory entry".into()))
    }
}
