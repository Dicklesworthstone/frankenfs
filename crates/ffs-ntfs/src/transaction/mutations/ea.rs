//! Native EA catalog mutations, published with their allocation and every
//! FILE_NAME / parent-index packed-size copy in one logged transaction.

use super::{
    NtfsTransactionEngine, NtfsTxOutcome, PreparedTxPlan, TxWorkspace, checkpoint,
    physical_spans_of_runs,
};
use crate::transaction::catalog::{PreservedAttribute, PreservedValue};
use crate::transaction::parse_err;
use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_ondisk::ntfs::ea::{FILE_NEED_EA, MAX_EA_NAME_BYTES, NtfsEa, encode_extended_attributes};
use ffs_ondisk::ntfs::usn::{USN_REASON_CLOSE, USN_REASON_EA_CHANGE};
use ffs_ondisk::ntfs::{EA, EA_INFORMATION, NtfsReference, decode_mapping_pairs};

/// How a native EA set operation treats an existing exact eight-bit name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NtfsEaSetMode {
    /// Create a missing entry or replace an existing entry.
    Set,
    /// Refuse with EEXIST when the entry already exists.
    Create,
    /// Refuse with ENODATA when the entry does not exist.
    Replace,
}

fn rejected(errno: i32, detail: &'static str) -> FfsError {
    FfsError::RequestRejected {
        errno,
        detail: detail.into(),
    }
}

fn validate_name(name: &[u8]) -> Result<()> {
    if name.len() > MAX_EA_NAME_BYTES {
        return Err(FfsError::NameTooLong);
    }
    if name.is_empty() || name.contains(&0) {
        return Err(rejected(libc::EINVAL, "invalid native NTFS EA name"));
    }
    Ok(())
}

impl NtfsTransactionEngine {
    /// Create, replace, or upsert one native extended attribute.
    ///
    /// Names and binary values retain their exact bytes; no filename UpCase or
    /// host ACL translation is applied. The entire EA catalog is validated and
    /// bounded to 64 KiB before publication. Other entries, including NEED_EA
    /// flags, remain intact. Large values use initialized COW clusters; their
    /// mappings, EA_INFORMATION and all hard-link packed-size copies commit
    /// together through the existing native journal.
    pub fn set_extended_attribute(
        &mut self,
        cx: &Cx,
        target: NtfsReference,
        entry: &NtfsEa,
        mode: NtfsEaSetMode,
        now_ticks: u64,
    ) -> NtfsTxOutcome<()> {
        let plan = (|| {
            checkpoint(cx)?;
            self.require_clean_writer()?;
            validate_name(&entry.name)?;
            if entry.flags & !FILE_NEED_EA != 0 {
                return Err(rejected(libc::EINVAL, "invalid native NTFS EA flags"));
            }
            if entry.value.len() > usize::from(u16::MAX) {
                return Err(rejected(libc::E2BIG, "native NTFS EA value is too large"));
            }
            let mut ws = TxWorkspace::load(self, cx)?;
            let mut entries = self.editable_extended_attributes(cx, &mut ws, target)?;
            let index = entries.iter().position(|old| old.name == entry.name);
            match (mode, index) {
                (NtfsEaSetMode::Create, Some(_)) => return Err(FfsError::Exists),
                (NtfsEaSetMode::Replace, None) => {
                    return Err(rejected(libc::ENODATA, "native NTFS EA does not exist"));
                }
                (_, Some(index)) => entries[index] = entry.clone(),
                (_, None) => entries.push(entry.clone()),
            }
            self.plan_extended_attributes(cx, ws, target, &entries, now_ticks, "set_ea")
        })();
        match plan {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(error) => NtfsTxOutcome::NotCommitted(error),
        }
    }

    /// Remove one exact native EA, refusing an absent entry with ENODATA.
    /// Removing the last entry retires both native attributes and their storage
    /// in the same transaction. Unrelated DATA, security and other EAs remain.
    pub fn remove_extended_attribute(
        &mut self,
        cx: &Cx,
        target: NtfsReference,
        name: &[u8],
        now_ticks: u64,
    ) -> NtfsTxOutcome<()> {
        let plan = (|| {
            checkpoint(cx)?;
            self.require_clean_writer()?;
            validate_name(name)?;
            let mut ws = TxWorkspace::load(self, cx)?;
            let mut entries = self.editable_extended_attributes(cx, &mut ws, target)?;
            let index = entries
                .iter()
                .position(|entry| entry.name == name)
                .ok_or_else(|| rejected(libc::ENODATA, "native NTFS EA does not exist"))?;
            entries.remove(index);
            self.plan_extended_attributes(cx, ws, target, &entries, now_ticks, "remove_ea")
        })();
        match plan {
            Ok(plan) => self.execute_logged_tx(cx, plan),
            Err(error) => NtfsTxOutcome::NotCommitted(error),
        }
    }

    fn editable_extended_attributes(
        &self,
        cx: &Cx,
        ws: &mut TxWorkspace,
        target: NtfsReference,
    ) -> Result<Vec<NtfsEa>> {
        // Root is ordinary namespace metadata; all other reserved system FILEs
        // retain their own dedicated mutation/admission protocols.
        if target.record < super::MIN_USER_MFT_SLOT && target.record != 5 {
            return Err(FfsError::PermissionDenied);
        }
        ws.load_catalog(self, cx, target)?;
        let volume = self.volume_view(cx)?;
        let record = volume.record(cx, target.record, Some(target.sequence))?;
        Ok(volume.extended_attributes(cx, &record)?.entries)
    }

    fn plan_extended_attributes(
        &self,
        cx: &Cx,
        mut ws: TxWorkspace,
        target: NtfsReference,
        entries: &[NtfsEa],
        now_ticks: u64,
        operation: &'static str,
    ) -> Result<PreparedTxPlan<()>> {
        let (information, bytes) = encode_extended_attributes(entries).map_err(|_| {
            rejected(
                libc::E2BIG,
                "native NTFS EA catalog exceeds its size budget",
            )
        })?;
        let mut digest = blake3::Hasher::new();
        digest.update(b"ntfs.extended_attributes:");
        digest.update(operation.as_bytes());
        digest.update(&target.record.to_le_bytes());
        digest.update(&target.sequence.to_le_bytes());
        digest.update(&now_ticks.to_le_bytes());
        digest.update(&information.encode());
        digest.update(&bytes);

        let mut retired_runs = Vec::new();
        let cluster_count = self.geometry.cluster_count();
        let cat = ws.catalog_mut(self, cx, target)?;
        for attribute in &cat.preserved {
            if attribute.kind == EA
                && let PreservedValue::NonResident {
                    first_vcn,
                    last_vcn,
                    mapping_pairs,
                    ..
                } = &attribute.raw_without_id
            {
                retired_runs.extend(
                    decode_mapping_pairs(mapping_pairs, *first_vcn, *last_vcn, cluster_count)
                        .map_err(|error| parse_err(&error))?,
                );
            }
        }
        cat.preserved
            .retain(|attribute| !matches!(attribute.kind, EA | EA_INFORMATION));
        if !entries.is_empty() {
            for (kind, bytes) in [(EA_INFORMATION, information.encode().to_vec()), (EA, bytes)] {
                cat.preserved.push(PreservedAttribute {
                    kind,
                    flags: 0,
                    name: Vec::new(),
                    raw_without_id: PreservedValue::Resident {
                        indexed: false,
                        bytes,
                    },
                });
            }
        }
        // Offset 60 is the packed EA size on ordinary FILE_NAME values, and a
        // reparse tag only on reparse records.
        let usn_snap = {
            if cat.reparse_point.is_none() {
                for name in &mut cat.file_names {
                    name.reparse = u32::from(information.packed_bytes);
                }
            }
            cat.set_std_times(None, None, Some(now_ticks), None);
            cat.clone()
        };
        ws.push_usn_event_for_catalog(
            &usn_snap,
            USN_REASON_EA_CHANGE | USN_REASON_CLOSE,
            now_ticks,
        );
        ws.free_clusters_deferred(&physical_spans_of_runs(&retired_runs));
        ws.sync_target_into_parent_dirs(self, cx, target)?;
        ws.finalize(self, cx, operation, *digest.finalize().as_bytes(), ())
    }
}
