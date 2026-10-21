//! Explicit index-directed FsOps lookup; no path reconstruction or new parser.

use super::{
    Cx, FfsError, FileType, InodeAttr, InodeNumber, NtfsFs, OsStr, ROOT, Result,
    checkpoint, corrupt, unsupported,
};

impl NtfsFs {
    pub(super) fn lookup_indexed(
        &self,
        cx: &Cx,
        parent: InodeNumber,
        name: &OsStr,
    ) -> Result<InodeAttr> {
        checkpoint(cx)?;
        if self.describe(cx, parent)?.kind != FileType::Directory {
            return Err(FfsError::NotDirectory);
        }
        if name == OsStr::new(".") {
            return self.describe(cx, parent);
        }
        let directory = self.record(cx, parent)?;
        if name == OsStr::new("..") {
            let ancestor = self.parent(cx, &directory)?;
            return self.describe(cx, ancestor);
        }
        let name = name
            .to_str()
            .ok_or_else(|| unsupported("NTFS lookup requires lossless UTF-8"))?;
        if name.is_empty() || name.contains(['/', '\\', '\0']) {
            return Err(FfsError::Format("invalid NTFS path component".into()));
        }
        if name.len() > 255 {
            return Err(FfsError::NameTooLong);
        }
        let units: Vec<_> = name.encode_utf16().collect();
        let entry = self
            .volume
            .lookup_indexed_entry(cx, &directory, &units, &self.upcase)?
            .ok_or_else(|| FfsError::NotFound(format!("NTFS name {name}")))?;
        // A native fold can select a different spelling. Check that stored
        // spelling too: a valid requested UTF-8 name does not make an unpaired
        // surrogate or overlong native name representable on this mount.
        let native_name = String::from_utf16(&entry.filename.name)
            .map_err(|_| unsupported("NTFS name cannot be represented losslessly as UTF-8"))?;
        if native_name.len() > 255 {
            return Err(FfsError::NameTooLong);
        }
        let target = self.inode(entry.reference)?;
        let attr = self.describe(cx, target)?;
        // The index search validates the selected FILE_NAME but not every
        // directory parent alias. Retain the mount's stronger ancestry rule.
        if attr.kind == FileType::Directory {
            if target == parent || target == ROOT {
                return Err(corrupt(
                    0,
                    "NTFS directory entry aliases itself or the mount root",
                ));
            }
            let child = self.record(cx, target)?;
            if self.parent(cx, &child)? != parent {
                return Err(corrupt(0, "NTFS directory parent differs from its lookup"));
            }
        }
        // No selected-name or negative result enters the complete-directory
        // cache. READDIR must still validate every native entry and target.
        checkpoint(cx)?;
        Ok(attr)
    }
}

#[cfg(test)]
mod tests;
