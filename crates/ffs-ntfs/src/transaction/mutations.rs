//! Native reference-based operations for the mounted ordinary writer.
//!
//! Every object/parent identity is revalidated before the existing WAL planner
//! runs. These entry points do not grant unsupported stream, alias, extension,
//! or replacement semantics merely because the underlying record is readable.

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::NtfsReference;

use super::ops::FileDataEdit;
use super::{NtfsTransactionEngine, NtfsTxOutcome, unsupported};

/// Objects participating in one completed native rename transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtfsRenameOutcome {
    pub source: NtfsReference,
    pub replaced: Option<NtfsReference>,
}

/// Validate a native filename without normalizing or replacing code units.
pub fn validate_ntfs_component_utf16(name: &[u16]) -> Result<()> {
    if name.len() > 255 {
        return Err(FfsError::NameTooLong);
    }
    if name.is_empty()
        || name == [46]
        || name == [46, 46]
        || name
            .iter()
            .any(|unit| matches!(unit, 0 | 0x2F | 0x5C | 0x3A))
    {
        return Err(FfsError::RequestRejected {
            errno: libc::EINVAL,
            detail: "invalid NTFS native filename component".into(),
        });
    }
    Ok(())
}

/// Validate a DATA attribute name. Empty selects the unnamed DATA stream.
pub fn validate_ntfs_stream_name_utf16(name: &[u16]) -> Result<()> {
    if name.len() > 255 {
        return Err(FfsError::NameTooLong);
    }
    if name
        .iter()
        .any(|unit| matches!(unit, 0 | 0x2F | 0x5C | 0x3A))
    {
        return Err(FfsError::RequestRejected {
            errno: libc::EINVAL,
            detail: "invalid NTFS native stream name".into(),
        });
    }
    Ok(())
}

impl NtfsTransactionEngine {
    /// Create a file relative to a sequence-bound directory reference.
    pub fn create_file_at(
        &mut self,
        cx: &Cx,
        parent: NtfsReference,
        name: &[u16],
        data: &[u8],
    ) -> NtfsTxOutcome<NtfsReference> {
        let admission = (|| {
            let path = self.resolve_reference_path(cx, parent)?;
            validate_ntfs_component_utf16(name)?;
            let name = String::from_utf16(name)
                .map_err(|_| unsupported("NTFS create name is not lossless UTF-8"))?;
            match self.lookup_reference(cx, parent, &name.encode_utf16().collect::<Vec<_>>()) {
                Ok(_) => return Err(FfsError::Exists),
                Err(FfsError::NotFound(_)) => {}
                Err(error) => return Err(error),
            }
            Ok((path, name))
        })();
        match admission {
            Ok((path, name)) => self.create_file(cx, &path, &name, data),
            Err(error) => NtfsTxOutcome::NotCommitted(error),
        }
    }

    /// Create a directory relative to a sequence-bound parent reference.
    pub fn mkdir_at(
        &mut self,
        cx: &Cx,
        parent: NtfsReference,
        name: &[u16],
    ) -> NtfsTxOutcome<NtfsReference> {
        let admission = (|| {
            let path = self.resolve_reference_path(cx, parent)?;
            validate_ntfs_component_utf16(name)?;
            let text = String::from_utf16(name)
                .map_err(|_| unsupported("NTFS directory name is not lossless UTF-8"))?;
            match self.lookup_reference(cx, parent, name) {
                Ok(_) => return Err(FfsError::Exists),
                Err(FfsError::NotFound(_)) => {}
                Err(error) => return Err(error),
            }
            Ok((path, text))
        })();
        match admission {
            Ok((path, name)) => self.mkdir(cx, &path, &name),
            Err(error) => NtfsTxOutcome::NotCommitted(error),
        }
    }

    /// Write an existing plain base-record DATA stream by stable FILE reference
    /// and exact native UTF-16 name. Empty selects unnamed DATA. This preserves
    /// all other streams and admits the same bounded native COW/WAL path as
    /// [`Self::write_file_range`]; extension and transformed streams stay refused.
    pub fn write_stream_range(
        &mut self,
        cx: &Cx,
        reference: NtfsReference,
        stream: &[u16],
        offset: u64,
        data: &[u8],
    ) -> NtfsTxOutcome<NtfsReference> {
        let admission = (|| {
            validate_ntfs_stream_name_utf16(stream)?;
            self.resolve_reference_path(cx, reference)
        })();
        match admission {
            Ok(path) => {
                self.edit_stream_data(cx, &path, stream, FileDataEdit::Write { offset, data })
            }
            Err(error) => NtfsTxOutcome::NotCommitted(error),
        }
    }

    /// Truncate an existing plain base-record DATA stream selected by exact
    /// native name. Growth zero-initializes new bytes before publication, and
    /// a named stream never changes the unnamed sizes in FILE_NAME or $I30.
    pub fn truncate_stream(
        &mut self,
        cx: &Cx,
        reference: NtfsReference,
        stream: &[u16],
        size: u64,
    ) -> NtfsTxOutcome<NtfsReference> {
        let admission = (|| {
            validate_ntfs_stream_name_utf16(stream)?;
            self.resolve_reference_path(cx, reference)
        })();
        match admission {
            Ok(path) => self.edit_stream_data(cx, &path, stream, FileDataEdit::Truncate { size }),
            Err(error) => NtfsTxOutcome::NotCommitted(error),
        }
    }

    /// Remove exactly the selected current directory link. Stale callers cannot
    /// remove a replacement which now occupies the same name.
    pub fn unlink_at(
        &mut self,
        cx: &Cx,
        parent: NtfsReference,
        name: &[u16],
        expected: NtfsReference,
    ) -> NtfsTxOutcome<NtfsReference> {
        let admission = (|| {
            if self.lookup_reference(cx, parent, name)? != expected {
                return Err(stale_target());
            }
            let path = self.child_mutation_path(cx, parent, name)?;
            self.validate_mutation_path_reference(cx, &path, expected)?;
            Ok(path)
        })();
        match admission {
            Ok(path) => self.unlink_file(cx, &path),
            Err(error) => NtfsTxOutcome::NotCommitted(error),
        }
    }

    /// Rename an existing native link without losing its stable FILE identity.
    /// Existing distinct destinations are refused before any write until their
    /// removal and open-handle retention share the same native transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn rename_at(
        &mut self,
        cx: &Cx,
        parent: NtfsReference,
        name: &[u16],
        new_parent: NtfsReference,
        new_name: &[u16],
        expected: NtfsReference,
        no_replace: bool,
    ) -> NtfsTxOutcome<NtfsRenameOutcome> {
        let admission = (|| {
            if self.lookup_reference(cx, parent, name)? != expected {
                return Err(stale_target());
            }
            match self.lookup_reference(cx, new_parent, new_name) {
                Ok(_) if no_replace => return Err(FfsError::Exists),
                Ok(destination) if destination != expected => {
                    return Err(unsupported(
                        "NTFS rename replacement requires atomic destination retirement",
                    ));
                }
                Ok(_) | Err(FfsError::NotFound(_)) => {}
                Err(error) => return Err(error),
            }
            let source = self.child_mutation_path(cx, parent, name)?;
            self.validate_mutation_path_reference(cx, &source, expected)?;
            Ok((source, self.child_mutation_path(cx, new_parent, new_name)?))
        })();
        let (source, destination) = match admission {
            Ok(paths) => paths,
            Err(error) => return NtfsTxOutcome::NotCommitted(error),
        };
        match self.rename_entry(cx, &source, &destination, Some(expected)) {
            NtfsTxOutcome::Committed { value, token } => NtfsTxOutcome::Committed {
                value: NtfsRenameOutcome {
                    source: value,
                    replaced: None,
                },
                token,
            },
            NtfsTxOutcome::NotCommitted(error) => NtfsTxOutcome::NotCommitted(error),
            NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            } => NtfsTxOutcome::Uncertain {
                reason,
                transaction_id,
                commit_lsn,
            },
        }
    }
}

fn stale_target() -> FfsError {
    FfsError::RequestRejected {
        errno: libc::ESTALE,
        detail: "NTFS directory link no longer identifies the requested FILE reference".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_ntfs_component_utf16, validate_ntfs_stream_name_utf16};

    #[test]
    fn component_validation_preserves_native_units_and_rejects_ambiguous_paths() {
        assert!(validate_ntfs_component_utf16(&[0xD800]).is_ok());
        assert!(validate_ntfs_component_utf16(&vec![65; 255]).is_ok());
        assert!(validate_ntfs_component_utf16(&vec![65; 256]).is_err());
        for invalid in [
            vec![],
            vec![46],
            vec![46, 46],
            vec![0],
            vec![47],
            vec![92],
            vec![58],
        ] {
            assert!(
                validate_ntfs_component_utf16(&invalid).is_err(),
                "{invalid:?}"
            );
        }
        assert!(validate_ntfs_stream_name_utf16(&[]).is_ok());
        assert!(validate_ntfs_stream_name_utf16(&[46]).is_ok());
        assert!(validate_ntfs_stream_name_utf16(&[0]).is_err());
        assert!(validate_ntfs_stream_name_utf16(&[58]).is_err());
    }
}
