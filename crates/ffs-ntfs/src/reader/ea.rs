//! Read native extended attributes through the complete validated catalog.
//! EA metadata does not select DATA or reinterpret security/WSL payloads.

use super::{Cx, NtfsFileRecord, NtfsValue, NtfsVolume, Result, checkpoint, corrupt, parse};
use ffs_ondisk::ntfs::ea::{NtfsEa, NtfsEaInformation, parse_extended_attributes};
use ffs_ondisk::ntfs::{EA, EA_INFORMATION};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EaCatalog {
    /// None distinguishes absent native attributes from an empty paired value.
    pub information: Option<NtfsEaInformation>,
    pub entries: Vec<NtfsEa>,
}

impl EaCatalog {
    /// Exact eight-bit identity. Windows code-page conversion and case folding
    /// are intentionally not inferred from the filename UpCase table.
    pub fn find(&self, name: &[u8]) -> Option<&NtfsEa> {
        self.entries.iter().find(|entry| entry.name == name)
    }
}

impl NtfsVolume {
    /// Read and validate every EA before exposing a value or name. The caller
    /// must supply the base FILE record; the shared catalog validates all list
    /// entries, instance IDs, continuation VCNs, sequences and extension owners.
    /// EA inspection remains available independently of DATA provider admission.
    pub fn extended_attributes(&self, cx: &Cx, record: &NtfsFileRecord) -> Result<EaCatalog> {
        checkpoint(cx)?;
        let catalog = self.attributes(cx, record)?;
        let mut information = None;
        let mut has_ea = false;
        for attribute in catalog.all()? {
            checkpoint(cx)?;
            if !matches!(attribute.kind, EA_INFORMATION | EA) {
                continue;
            }
            if !attribute.name.is_empty() || attribute.flags != 0 {
                return Err(corrupt(0, "named or transformed native EA metadata"));
            }
            if attribute.kind == EA_INFORMATION {
                let NtfsValue::Resident(bytes) = attribute.value else {
                    return Err(corrupt(0, "EA_INFORMATION must be resident"));
                };
                if information.is_some() {
                    return Err(corrupt(0, "duplicate EA_INFORMATION"));
                }
                information = Some(NtfsEaInformation::parse(bytes).map_err(|error| parse(&error))?);
            } else {
                has_ea = true;
            }
        }
        let information = match (information, has_ea) {
            (None, false) => {
                checkpoint(cx)?;
                return Ok(EaCatalog {
                    information: None,
                    entries: Vec::new(),
                });
            }
            (Some(information), true) => information,
            _ => return Err(corrupt(0, "EA and EA_INFORMATION must occur together")),
        };
        let stream = catalog.select(&self.geometry, EA, &[])?;
        if stream.size != u64::from(information.unpacked_bytes) || stream.initialized != stream.size
        {
            return Err(corrupt(
                0,
                "EA logical or initialized size disagrees with EA_INFORMATION",
            ));
        }
        // The eight-byte information record was bounded before the stream is
        // read, and ordinary extent assembly refuses sparse holes and aliases.
        let bytes = self.read(cx, &stream, 0, information.unpacked_bytes as usize)?;
        let entries =
            parse_extended_attributes(&information, &bytes).map_err(|error| parse(&error))?;
        checkpoint(cx)?;
        Ok(EaCatalog {
            information: Some(information),
            entries,
        })
    }
}
