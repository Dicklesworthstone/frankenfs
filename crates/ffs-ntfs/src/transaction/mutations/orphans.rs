//! Durable ownership of files retained for open handles after their last unlink.
//!
//! The ownership record is ordinary resident named DATA, not a second journal.
//! It commits with its sole retained FILE_NAME and $I30 entry through $LogFile.
//! Native readers can inspect that valid file after a crash; only a newly
//! admitted FrankenFS writer interprets this private stream as cleanup intent.
//! This does not implement or claim Windows $Extend/$Deleted recovery.

use super::{
    EditableDataStream, EditableFileName, EditableStreamStorage, FIRST_NON_RESERVED_SLOT,
    I30RawEntry, NtfsTransactionEngine, NtfsTxOutcome, TxWorkspace, checkpoint, corrupt, parse_err,
    read_mft_record_via_runs, remove_link_from_workspace, stale_target, unsupported,
    validate_ntfs_component_utf16,
};
use crate::transaction::{NtfsDurableToken, NtfsStorageIdentity};
use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::index::NtfsFileName;
use ffs_ondisk::ntfs::usn::{
    USN_REASON_CLOSE, USN_REASON_NAMED_DATA_EXTEND, USN_REASON_RENAME_NEW_NAME,
    USN_REASON_RENAME_OLD_NAME, USN_REASON_STREAM_CHANGE,
};
use ffs_ondisk::ntfs::{DATA, NtfsReference, NtfsValue};

pub const ORPHAN_STREAM_NAME: &str = "$FrankenFS.Orphan";
const ORPHAN_NAME_PREFIX: &str = ".ffs-unlinked-";
const ORPHAN_MAGIC: &[u8; 16] = b"FFS_NTFS_ORPHAN\0";
const ORPHAN_VERSION: u64 = 1;
const MAX_RECOVERED_ORPHANS: usize = 4_096;

struct RetainedFile {
    root: NtfsReference,
    target: NtfsReference,
    name: Vec<u16>,
}

fn ownership_record(
    identity: &NtfsStorageIdentity,
    target: NtfsReference,
    root: NtfsReference,
    name: &[u16],
) -> Result<Vec<u8>> {
    let mut name_hash = blake3::Hasher::new();
    for unit in name {
        name_hash.update(&unit.to_le_bytes());
    }
    let mut bytes = Vec::with_capacity(144);
    bytes.extend_from_slice(ORPHAN_MAGIC);
    bytes.extend_from_slice(&ORPHAN_VERSION.to_le_bytes());
    bytes.extend_from_slice(&identity.volume_serial.to_le_bytes());
    bytes.extend_from_slice(&identity.boot_blake3);
    bytes.extend_from_slice(
        &target
            .encode()
            .map_err(|error| parse_err(&error))?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(
        &root
            .encode()
            .map_err(|error| parse_err(&error))?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(name_hash.finalize().as_bytes());
    let checksum = blake3::hash(&bytes);
    bytes.extend_from_slice(checksum.as_bytes());
    Ok(bytes)
}

impl NtfsTransactionEngine {
    /// Move the final visible link into native retained storage, publishing its
    /// ownership record in the same transaction. No marker-only or rename-only
    /// state may become committed, including when catalog growth needs space.
    pub(crate) fn retain_unlinked_at(
        &mut self,
        cx: &Cx,
        parent: NtfsReference,
        name: &[u16],
        expected: NtfsReference,
        retained_name: &[u16],
        now_ticks: u64,
    ) -> NtfsTxOutcome<NtfsReference> {
        let plan = (|| {
            checkpoint(cx)?;
            validate_ntfs_component_utf16(name)?;
            let mut ws = TxWorkspace::load(self, cx)?;
            let matched = ws
                .lookup_in_dir(self, cx, parent, name)?
                .ok_or_else(|| FfsError::NotFound("NTFS unlink source not found".into()))?;
            if matched.reference != expected {
                return Err(stale_target());
            }
            let original = ws.load_catalog(self, cx, expected)?.clone();
            if original.is_directory {
                return Err(FfsError::IsDirectory);
            }
            let remaining = remove_link_from_workspace(
                self,
                cx,
                &mut ws,
                parent,
                expected,
                &matched.file_name,
                now_ticks,
            )?;
            if remaining != 0 {
                return Err(unsupported(
                    "NTFS retention requires the final visible link",
                ));
            }
            ws.push_usn_event_explicit(
                expected,
                parent,
                USN_REASON_RENAME_OLD_NAME,
                original.std_flags(),
                now_ticks,
                matched.file_name.name,
            );
            self.stage_retained_link(cx, &mut ws, expected, retained_name, now_ticks)?;
            let mut digest = blake3::Hasher::new();
            digest.update(b"ntfs.retain_unlinked_at:");
            digest.update(
                &parent
                    .encode()
                    .map_err(|error| parse_err(&error))?
                    .to_le_bytes(),
            );
            digest.update(
                &expected
                    .encode()
                    .map_err(|error| parse_err(&error))?
                    .to_le_bytes(),
            );
            for part in [name, retained_name] {
                digest.update(&(part.len() as u64).to_le_bytes());
                for unit in part {
                    digest.update(&unit.to_le_bytes());
                }
            }
            ws.finalize(
                self,
                cx,
                "retain_unlinked_at",
                *digest.finalize().as_bytes(),
                expected,
            )
        })();
        match plan {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(error) => NtfsTxOutcome::NotCommitted(error),
        }
    }

    /// Add a retained link and its identity-bound marker to the caller's
    /// workspace. Rename-overwrite uses this same planner before its one commit.
    pub(super) fn stage_retained_link(
        &self,
        cx: &Cx,
        ws: &mut TxWorkspace,
        target: NtfsReference,
        name: &[u16],
        now_ticks: u64,
    ) -> Result<()> {
        validate_ntfs_component_utf16(name)?;
        let prefix: Vec<_> = ORPHAN_NAME_PREFIX.encode_utf16().collect();
        if !name.starts_with(&prefix) || target.record < FIRST_NON_RESERVED_SLOT {
            return Err(FfsError::PermissionDenied);
        }
        let root_record =
            read_mft_record_via_runs(&self.device, cx, &self.geometry, &ws.mft_runs, 5)?;
        let root = NtfsReference {
            record: 5,
            sequence: root_record.sequence,
        };
        if ws.lookup_in_dir(self, cx, root, name)?.is_some() {
            return Err(FfsError::Exists);
        }
        let marker_name: Vec<_> = ORPHAN_STREAM_NAME.encode_utf16().collect();
        let marker_folded = self.fold_upcase(&marker_name);
        let marker = ownership_record(self.storage_identity(), target, root, name)?;
        let file_name = NtfsFileName {
            parent: root,
            namespace: 1,
            name: name.to_vec(),
        };
        let (raw_fn_bytes, flags) = {
            let cat = ws.catalog_mut(self, cx, target)?;
            if cat.is_directory || !cat.file_names.is_empty() {
                return Err(unsupported("NTFS retained file still has native links"));
            }
            if cat
                .data_streams
                .iter()
                .any(|stream| self.fold_upcase(&stream.name) == marker_folded)
            {
                return Err(unsupported(
                    "NTFS retention marker collides with an existing stream",
                ));
            }
            cat.data_streams.push(EditableDataStream {
                name: marker_name,
                storage: EditableStreamStorage::Resident(marker),
            });
            cat.file_names.push(EditableFileName {
                file_name: file_name.clone(),
                ctime: 0,
                mtime: 0,
                mft_time: 0,
                atime: 0,
                allocated_size: 0,
                data_size: 0,
                flags: 0,
                reparse: 0,
            });
            cat.set_std_times(None, None, Some(now_ticks), None);
            cat.sync_filename_duplicated_fields(self.geometry.cluster_bytes());
            (cat.file_names[0].encode()?, cat.std_flags())
        };
        ws.dir_entries_mut(self, cx, root)?.push(I30RawEntry {
            reference: target,
            file_name,
            raw_fn_bytes,
        });
        ws.catalog_mut(self, cx, root)?
            .set_std_times(None, Some(now_ticks), Some(now_ticks), None);
        ws.push_usn_event_explicit(
            target,
            root,
            USN_REASON_RENAME_NEW_NAME
                | USN_REASON_NAMED_DATA_EXTEND
                | USN_REASON_STREAM_CHANGE
                | USN_REASON_CLOSE,
            flags,
            now_ticks,
            name.to_vec(),
        );
        Ok(())
    }

    /// Called only when adopting a fresh writable mount, before any namespace
    /// or handles are exposed. Validate the complete bounded candidate set
    /// before starting a deletion; a late malformed marker must not consume an
    /// earlier valid file. Prefix-only files, including legacy survivors, stay.
    pub(crate) fn recover_retained_files(&mut self, cx: &Cx) -> Result<Option<NtfsDurableToken>> {
        checkpoint(cx)?;
        self.require_clean_writer()?;
        self.check_clean_consistency(cx)?;
        let retained = self.validated_retained_files(cx)?;
        let mut last_token = None;
        for file in retained {
            checkpoint(cx)?;
            self.device.begin_durability_commit(cx)?;
            match self.unlink_at(cx, file.root, &file.name, file.target) {
                NtfsTxOutcome::Committed { token, .. } => {
                    if !token.matches_engine(self) {
                        self.device.abort_durability_commit();
                        return Err(corrupt(0, "NTFS orphan cleanup changed storage identity"));
                    }
                    self.device.complete_durability_commit();
                    last_token = Some(token);
                }
                NtfsTxOutcome::NotCommitted(error)
                | NtfsTxOutcome::Uncertain { reason: error, .. } => {
                    self.device.abort_durability_commit();
                    return Err(error);
                }
            }
        }
        Ok(last_token)
    }

    fn validated_retained_files(&self, cx: &Cx) -> Result<Vec<RetainedFile>> {
        let volume = self.volume_view(cx)?;
        let root_record = volume.record(cx, 5, None)?;
        let root = NtfsReference {
            record: 5,
            sequence: root_record.sequence,
        };
        let prefix: Vec<_> = ORPHAN_NAME_PREFIX.encode_utf16().collect();
        let prefix_folded = self.fold_upcase(&prefix);
        let marker_name: Vec<_> = ORPHAN_STREAM_NAME.encode_utf16().collect();
        let marker_folded = self.fold_upcase(&marker_name);
        let ws = TxWorkspace::load(self, cx)?;
        let mut retained = Vec::new();
        for entry in volume.list_directory(cx, &root_record)? {
            checkpoint(cx)?;
            if !self
                .fold_upcase(&entry.filename.name)
                .starts_with(&prefix_folded)
            {
                continue;
            }
            let record =
                volume.record(cx, entry.reference.record, Some(entry.reference.sequence))?;
            let marked = {
                let catalog = volume.attributes(cx, &record)?;
                let mut marked = false;
                for attribute in catalog.all()? {
                    if attribute.kind != DATA || self.fold_upcase(&attribute.name) != marker_folded
                    {
                        continue;
                    }
                    if marked || attribute.name != marker_name || attribute.flags != 0 {
                        return Err(corrupt(0, "ambiguous NTFS retained-file ownership stream"));
                    }
                    let NtfsValue::Resident(bytes) = attribute.value else {
                        return Err(corrupt(0, "NTFS retained-file ownership must be resident"));
                    };
                    let expected = ownership_record(
                        self.storage_identity(),
                        entry.reference,
                        root,
                        &entry.filename.name,
                    )?;
                    if bytes != expected {
                        return Err(corrupt(
                            0,
                            "NTFS retained-file identity or checksum mismatch",
                        ));
                    }
                    marked = true;
                }
                marked
            };
            if !marked {
                continue;
            }
            // Check the full native mutation catalog too, before any other
            // candidate is reaped. Drop it each iteration rather than retaining
            // all of the candidates' DATA and extension catalogs in memory.
            let cat = self.load_editable_catalog(cx, &ws.mft_runs, entry.reference)?;
            if entry.reference.record < FIRST_NON_RESERVED_SLOT
                || cat.is_directory
                || cat.file_names.len() != 1
                || cat.file_names[0].file_name != entry.filename
                || entry.filename.parent != root
                || entry.filename.namespace != 1
            {
                return Err(corrupt(
                    0,
                    "NTFS retained-file ownership has unexpected native links",
                ));
            }
            if retained.len() >= MAX_RECOVERED_ORPHANS {
                return Err(unsupported("NTFS retained-file recovery budget exceeded"));
            }
            retained.push(RetainedFile {
                root,
                target: entry.reference,
                name: entry.filename.name,
            });
        }
        checkpoint(cx)?;
        Ok(retained)
    }
}
