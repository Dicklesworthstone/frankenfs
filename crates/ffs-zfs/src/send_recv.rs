//! ZFS native send and receive (`DMU_BACKUP_STREAM`) with full, incremental (`-i`/`-I`),
//! bookmark-based, compressed (`-c`), embedded (`-e`), large-block (`-L`), raw encrypted (`-w`),
//! and resumable (`-s`, `%recv`, `receive_resume_token`) semantics across ZPL and ZVOL.
//!
//! Security boundary: untrusted stream metadata (`drr_toname`, embedded XDR nvlists,
//! resume-token `toname`) NEVER selects host paths, devices, pools, key files, or
//! import/mount authority.

pub mod send;

pub use crate::transaction::{
    ZfsRecvReport, ZfsRecvRequest, ZfsResumeState, inspect_receive_resume_state_in_mos,
};
pub use send::{ZfsSendFrom, ZfsSendReport, ZfsSendRequest, send_stream};

/// OpenZFS `dsl_dataset` zapified resume checkpoint keys (exact `include/sys/dsl_dataset.h` names).
pub(crate) const DS_FIELD_RESUME_FROMGUID: &[u8] = b"com.delphix:resume_fromguid";
pub(crate) const DS_FIELD_RESUME_TOGUID: &[u8] = b"com.delphix:resume_toguid";
pub(crate) const DS_FIELD_RESUME_TONAME: &[u8] = b"com.delphix:resume_toname";
pub(crate) const DS_FIELD_RESUME_OBJECT: &[u8] = b"com.delphix:resume_object";
pub(crate) const DS_FIELD_RESUME_OFFSET: &[u8] = b"com.delphix:resume_offset";
pub(crate) const DS_FIELD_RESUME_BYTES: &[u8] = b"com.delphix:resume_bytes";
pub(crate) const DS_FIELD_RESUME_COMPRESSOK: &[u8] = b"com.delphix:resume_compressok";
pub(crate) const DS_FIELD_RESUME_EMBEDOK: &[u8] = b"com.delphix:resume_embedok";
pub(crate) const DS_FIELD_RESUME_LARGEBLOCKOK: &[u8] = b"com.delphix:resume_largeblockok";
pub(crate) const DS_FIELD_RESUME_RAWOK: &[u8] = b"com.datto:resume_rawok";
pub(crate) const DS_FIELD_RESUME_IVSET_GUID: &[u8] = b"com.datto:resume_ivset_guid";

/// `DS_FLAG_INCONSISTENT` (bit 0 of `dsl_dataset_phys_t.ds_flags`).
pub(crate) const DS_FLAG_INCONSISTENT: u64 = 1 << 0;
