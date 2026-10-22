//! Bounded native directory traversal shared by listing and name lookup.
//! A complete chain is validated before yielding records, including allocation
//! after the end marker. Decoding then retains one physical buffer, not all names.

use super::{
    Cx, Directory, Entry, FatDirectoryDecoder, FatVolume, FfsError, MAX_DIRECTORY_SLOTS, Result,
    allocate, checkpoint, corrupt,
};

enum Storage {
    Fixed { start: u64, length: u64 },
    Chain(Vec<u32>),
}

/// A forward-only directory cursor tied to one unchanged native volume.
///
/// The caller must keep the backing and metadata immutable for the entire
/// cursor lifetime. A shared borrow or advisory lock is not a snapshot. Drop
/// this cursor before native mutation; mounted callers must hold their gate.
///
/// Opening validates the complete allocation chain, not all directory records
/// or global ownership. Entries are delivered incrementally; only `Ok(None)`
/// certifies that the namespace scan finished. A later error does not retract
/// earlier entries. `FatVolume::list` and `lookup` retain their all-or-error
/// results by consuming this cursor to completion before returning success.
/// Any error, including cancellation, permanently stops this cursor: reopen it
/// instead of accidentally treating the remaining suffix as a complete listing.
/// No method writes or synchronizes the backing device.
pub struct DirectoryReader<'a> {
    volume: &'a FatVolume,
    storage: Storage,
    decoder: FatDirectoryDecoder,
    bytes: Vec<u8>,
    group: usize,
    offset: u64,
    within: usize,
    slots: usize,
    finished: bool,
    failed: bool,
}

impl FatVolume {
    /// Open a bounded native cursor for a fixed root or cluster-backed directory.
    /// Long names retain their raw UTF-16 units, OEM aliases and short-slot offsets.
    pub fn open_directory_reader(
        &self,
        cx: &Cx,
        directory: Directory,
    ) -> Result<DirectoryReader<'_>> {
        checkpoint(cx)?;
        let fixed = match directory {
            Directory::Root => self.geometry.fixed_root(),
            Directory::Cluster(_) => None,
        };
        let (storage, size) = if let Some((start, length)) = fixed {
            (
                Storage::Fixed { start, length },
                self.geometry.sector_bytes() as usize,
            )
        } else {
            let first = match directory {
                Directory::Root => self.geometry.root_cluster(),
                Directory::Cluster(cluster) => cluster,
            };
            let size = self.geometry.cluster_bytes() as usize;
            let clusters = self.allocation_chain(
                cx,
                first,
                1,
                self.cluster_offset(first)?,
                (MAX_DIRECTORY_SLOTS * 32).div_ceil(size),
            )?;
            (Storage::Chain(clusters), size)
        };
        let bytes = allocate(size)?;
        checkpoint(cx)?;
        Ok(DirectoryReader {
            volume: self,
            storage,
            decoder: FatDirectoryDecoder::default(),
            bytes,
            group: 0,
            offset: 0,
            within: size,
            slots: 0,
            finished: false,
            failed: false,
        })
    }
}

impl DirectoryReader<'_> {
    /// Return the next live, non-dot entry or the validated end of the scan.
    /// Deleted records and volume labels are consumed by the native decoder.
    /// Malformed long names retain the existing decoder's short-name fallback;
    /// this is not a substitute for `check` or its explicit repair authority.
    pub fn next_entry(&mut self, cx: &Cx) -> Result<Option<Entry>> {
        if self.failed {
            return Err(FfsError::Io(std::io::Error::other(
                "FAT directory cursor failed; reopen before continuing",
            )));
        }
        let result = self.advance(cx).and_then(|entry| {
            checkpoint(cx)?;
            Ok(entry)
        });
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn advance(&mut self, cx: &Cx) -> Result<Option<Entry>> {
        loop {
            // Also bounds latency while scanning only deleted/LFN/label slots,
            // and observes cancellation between calls that share one buffer.
            checkpoint(cx)?;
            if self.finished || self.decoder.ended() {
                self.finished = true;
                return Ok(None);
            }
            if self.within == self.bytes.len() {
                let offset = match &self.storage {
                    Storage::Fixed { start, length } => {
                        let relative = self.group as u64 * self.bytes.len() as u64;
                        (relative < *length).then_some(*start + relative)
                    }
                    Storage::Chain(clusters) => clusters
                        .get(self.group)
                        .map(|&cluster| self.volume.cluster_offset(cluster))
                        .transpose()?,
                };
                let Some(offset) = offset else {
                    self.decoder.finish();
                    self.finished = true;
                    return Ok(None);
                };
                // Publish no buffer progress until the entire physical read and
                // its cancellation checkpoint succeed. Failed buffers never yield.
                self.volume.read_exact(cx, offset, &mut self.bytes)?;
                self.offset = offset;
                self.group += 1;
                self.within = 0;
            }
            if self.slots == MAX_DIRECTORY_SLOTS {
                return Err(FfsError::UnsupportedFeature(
                    "FAT directory exceeds 65536 slots".into(),
                ));
            }
            let position = self.offset + self.within as u64;
            let slot: &[u8; 32] = self.bytes[self.within..self.within + 32]
                .try_into()
                .expect("sector-aligned directory buffer");
            self.within += 32;
            self.slots += 1;
            let Some(native) = self
                .decoder
                .push(slot, self.volume.geometry.kind())
                .map_err(|error| corrupt(position, error.to_string()))?
            else {
                continue;
            };
            if native.short_name == *b".          " || native.short_name == *b"..         " {
                continue;
            }
            if native.is_directory() || native.first_cluster != 0 {
                self.volume.cluster_offset(native.first_cluster)?;
            } else if native.size != 0 {
                return Err(corrupt(position, "nonempty FAT file has no first cluster"));
            }
            return Ok(Some(Entry {
                offset: position,
                native,
                oem_code_page: self.volume.oem_code_page,
            }));
        }
    }
}

#[cfg(test)]
mod tests;
