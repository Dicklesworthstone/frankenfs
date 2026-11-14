//! Reconstruct an admitted mutation path from a sequence-bound native object.
//!
//! Paths are an implementation detail of the existing WAL planners. Callers
//! retain FILE references across rename, and every reconstruction validates
//! the ancestor chain and its index links before passing a path to a planner.

use std::collections::BTreeSet;

use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::index::NtfsFileName;
use ffs_ondisk::ntfs::{ATTRIBUTE_LIST, NtfsFileRecord, NtfsReference, NtfsValue};

use super::{NtfsTransactionEngine, checkpoint, corrupt, parse_err, unsupported};
use crate::NtfsVolume;

impl NtfsTransactionEngine {
    pub(super) fn checked_reference(
        volume: &NtfsVolume,
        cx: &Cx,
        reference: NtfsReference,
    ) -> Result<NtfsFileRecord> {
        if reference.sequence == 0 {
            return Err(stale_reference(reference));
        }
        let record = volume.record(cx, reference.record, None)?;
        if record.sequence != reference.sequence {
            return Err(stale_reference(reference));
        }
        Ok(record)
    }

    /// Resolve a current object reference to a fully validated native path.
    ///
    /// The ordinary writer currently owns base-record name catalogs. An
    /// extension catalog or an unrepresentable UTF-16 component is refused;
    /// neither is shortened or converted with replacement characters.
    pub fn resolve_reference_path(&self, cx: &Cx, reference: NtfsReference) -> Result<String> {
        checkpoint(cx)?;
        let volume = self.volume_view(cx)?;
        let root = volume.record(cx, 5, None)?;
        if !root.is_directory() {
            return Err(corrupt(0, "NTFS root is not a directory"));
        }
        let root_reference = NtfsReference {
            record: 5,
            sequence: root.sequence,
        };
        let mut current = reference;
        let mut visited = BTreeSet::new();
        let mut components = Vec::new();
        let mut path_bytes = 1_usize;
        for _ in 0..=256 {
            checkpoint(cx)?;
            let record = Self::checked_reference(&volume, cx, current)?;
            if current == root_reference {
                components.reverse();
                let path = format!("/{}", components.join("/"));
                // The legacy planners use index-directed traversal. Verify
                // their exact interpretation too, so a POSIX/folded collision
                // cannot redirect a reference-bound request to another file.
                self.validate_mutation_path_reference(cx, &path, reference)?;
                return Ok(path);
            }
            if !visited.insert((current.record, current.sequence)) {
                return Err(corrupt(0, "cycle in NTFS FILE_NAME parent chain"));
            }
            let attributes = record.attributes().map_err(|error| parse_err(&error))?;
            if attributes
                .iter()
                .any(|attribute| attribute.kind == ATTRIBUTE_LIST)
            {
                return Err(unsupported(
                    "NTFS reference mutation requires complete base-record name ownership",
                ));
            }
            let mut names = Vec::new();
            for attribute in attributes.iter().filter(|attribute| attribute.kind == 0x30) {
                let NtfsValue::Resident(value) = attribute.value else {
                    return Err(corrupt(0, "nonresident NTFS FILE_NAME"));
                };
                let name = NtfsFileName::parse(value).map_err(|error| parse_err(&error))?;
                if name.namespace != 2 {
                    names.push(name);
                }
            }
            names.sort_by(|left, right| {
                (left.parent.record, left.parent.sequence, &left.name).cmp(&(
                    right.parent.record,
                    right.parent.sequence,
                    &right.name,
                ))
            });
            let name = names
                .first()
                .ok_or_else(|| corrupt(0, "NTFS object has no ordinary name"))?;
            super::validate_ntfs_component_utf16(&name.name)?;
            let component = String::from_utf16(&name.name)
                .map_err(|_| unsupported("NTFS mutation path is not lossless UTF-8"))?;
            path_bytes = path_bytes
                .checked_add(component.len() + 1)
                .filter(|length| *length <= 65_536)
                .ok_or(FfsError::NameTooLong)?;
            let parent = Self::checked_reference(&volume, cx, name.parent)?;
            if !parent.is_directory() {
                return Err(corrupt(0, "NTFS FILE_NAME parent is not a directory"));
            }
            if !volume
                .list_directory(cx, &parent)?
                .iter()
                .any(|entry| entry.reference == current && entry.filename == *name)
            {
                return Err(corrupt(
                    0,
                    "NTFS FILE_NAME is absent from its parent's index",
                ));
            }
            components.push(component);
            current = name.parent;
        }
        Err(FfsError::NameTooLong)
    }

    pub(super) fn validate_mutation_path_reference(
        &self,
        cx: &Cx,
        path: &str,
        reference: NtfsReference,
    ) -> Result<()> {
        let mft = self.read_mft_record_zero(cx)?;
        let runs = super::extract_plain_nonresident_runs(
            &self.geometry,
            &mft,
            ffs_ondisk::ntfs::DATA,
            &[],
        )?;
        let (number, resolved) = self.resolve_path_raw(cx, &runs, path)?;
        if u64::from(number) != reference.record || resolved.sequence != reference.sequence {
            return Err(corrupt(
                0,
                "NTFS mutation path resolves to a different reference",
            ));
        }
        Ok(())
    }

    pub(super) fn child_mutation_path(
        &self,
        cx: &Cx,
        parent: NtfsReference,
        name: &[u16],
    ) -> Result<String> {
        super::validate_ntfs_component_utf16(name)?;
        let component = String::from_utf16(name)
            .map_err(|_| unsupported("NTFS mutation component is not lossless UTF-8"))?;
        let parent_path = self.resolve_reference_path(cx, parent)?;
        let path = format!("{}/{component}", parent_path.trim_end_matches('/'));
        if path.len() > 65_536 {
            return Err(FfsError::NameTooLong);
        }
        Ok(path)
    }
}

fn stale_reference(reference: NtfsReference) -> FfsError {
    FfsError::RequestRejected {
        errno: libc::ESTALE,
        detail: format!(
            "stale NTFS FILE reference {}:{}",
            reference.record, reference.sequence
        ),
    }
}
