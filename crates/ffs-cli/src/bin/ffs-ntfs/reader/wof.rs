//! WOF individual-file provider: bounded, independent XPRESS and LZX chunks.
//!
//! Native layout sources: Microsoft WOF_EXTERNAL_INFO / FILE_PROVIDER_EXTERNAL_INFO,
//! and Linux v6.17 fs/ntfs3/frecord.c plus ntfs-3g-system-compression v1.0
//! src/system_compression.c. The unnamed sparse DATA is only a size/VDL
//! placeholder. Explicit named DATA reads retain their own stored bytes.

use super::attributes::AttributeSet;
use super::{
    Cx, DATA, NtfsGeometry, NtfsReparseData, NtfsReparsePoint, NtfsVolume, Result, SPARSE, Source,
    Storage, Stream, checkpoint, corrupt, parse, unsupported,
};
use ffs_ondisk::{lzx, xpress};

pub(super) const TAG: u32 = 0x8000_0017;
const BACKING_NAME: &[u16] = &[
    87, 111, 102, 67, 111, 109, 112, 114, 101, 115, 115, 101, 100, 68, 97, 116, 97,
];

#[derive(Debug, Clone, Copy)]
pub(super) struct FileProvider {
    algorithm: u32,
}

impl FileProvider {
    /// Recognition alone does not admit logical DATA. Unknown versions,
    /// providers and flags retain the existing explicit provider refusal.
    pub(super) fn parse(point: &NtfsReparsePoint) -> Result<Self> {
        if point.tag != TAG || point.guid.is_some() {
            return Err(unsupported(
                "NTFS reparse DATA requires an implemented provider",
            ));
        }
        let NtfsReparseData::Opaque(bytes) = &point.data else {
            return Err(corrupt(0, "WOF tag has an incompatible reparse layout"));
        };
        if !matches!(bytes.len(), 16 | 20) {
            return Err(unsupported(
                "WOF reparse file-provider metadata requires a supported exact layout",
            ));
        }
        let word =
            |at| u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
        if word(0) != 1 || word(4) != 2 || word(8) != 1 {
            return Err(unsupported(
                "WOF version or provider is unsupported; WIM backing is not implemented",
            ));
        }
        if bytes.len() == 20 && word(16) != 0 {
            return Err(unsupported("WOF file-provider flags are unsupported"));
        }
        Ok(Self {
            algorithm: word(12),
        })
    }

    fn chunk_bytes(self) -> Result<usize> {
        match self.algorithm {
            0 => Ok(4096),
            1 => Ok(lzx::MAX_OUTPUT_BYTES),
            2 => Ok(8192),
            3 => Ok(16_384),
            other => Err(unsupported(format!(
                "WOF file compression algorithm {other} is unsupported; select a named stream for raw bytes",
            ))),
        }
    }
}

/// Construct logical DATA only after file-level provider and EFS admission.
/// The constructor reads no chunk offsets or compressed file payload.
pub(super) fn open(
    volume: &NtfsVolume,
    cx: &Cx,
    catalog: &AttributeSet<'_>,
    provider: FileProvider,
) -> Result<Stream> {
    checkpoint(cx)?;
    let chunk_bytes = provider.chunk_bytes()?;
    let attributes = catalog.all()?;
    let logical = catalog.select(&volume.geometry, DATA, &[])?;
    let empty_resident = matches!(&logical.storage, Storage::Resident(bytes) if bytes.is_empty());
    if !empty_resident {
        if attributes
            .iter()
            .any(|attr| attr.kind == DATA && attr.name.is_empty() && attr.flags != SPARSE)
        {
            return Err(corrupt(
                0,
                "WOF unnamed DATA must be a native sparse placeholder",
            ));
        }
        if !matches!(&logical.storage, Storage::Mapped(runs) if runs.iter().all(|run| run.lcn.is_none()))
        {
            return Err(corrupt(
                0,
                "WOF unnamed DATA contains physical storage instead of a sparse placeholder",
            ));
        }
    }
    if attributes
        .iter()
        .any(|attr| attr.kind == DATA && attr.name == BACKING_NAME && attr.flags != 0)
    {
        return Err(unsupported(
            "WofCompressedData must not be encrypted, sparse or recursively compressed",
        ));
    }
    let backing = catalog.select(&volume.geometry, DATA, BACKING_NAME)?;
    if backing.initialized != backing.size {
        return Err(corrupt(0, "WofCompressedData is not fully initialized"));
    }
    if !matches!(&backing.storage, Storage::Resident(_) | Storage::Mapped(_)) {
        return Err(corrupt(
            0,
            "WofCompressedData uses recursive provider storage",
        ));
    }
    let layout = ChunkLayout::new(logical.size, backing.size, chunk_bytes)?;
    let allocated = if backing.resident() {
        0
    } else {
        backing.allocated
    };
    checkpoint(cx)?;
    Ok(Stream {
        size: logical.size,
        initialized: logical.initialized,
        allocated,
        storage: Storage::Wof(WofStorage {
            backing: Box::new(backing),
            layout,
        }),
    })
}

#[derive(Debug)]
pub(super) struct WofStorage {
    backing: Box<Stream>,
    layout: ChunkLayout,
}

/// The offset table stays on the image. At most two adjacent entries and one
/// 32 KiB chunk are staged, even when the logical file requires 64-bit offsets.
#[derive(Debug)]
struct ChunkLayout {
    logical_bytes: u64,
    chunk_bytes: usize,
    chunks: u64,
    offset_bytes: usize,
    table_bytes: u64,
    payload_bytes: u64,
}

impl ChunkLayout {
    fn new(logical_bytes: u64, stored_bytes: u64, chunk_bytes: usize) -> Result<Self> {
        if !matches!(chunk_bytes, 4096 | 8192 | 16_384 | 32_768) {
            return Err(unsupported("unsupported WOF chunk size"));
        }
        let chunks = logical_bytes.div_ceil(chunk_bytes as u64);
        let offset_bytes = if logical_bytes > u64::from(u32::MAX) {
            8
        } else {
            4
        };
        let table_bytes = chunks
            .saturating_sub(1)
            .checked_mul(offset_bytes as u64)
            .ok_or_else(|| corrupt(0, "WOF chunk table size overflow"))?;
        let payload_bytes = stored_bytes
            .checked_sub(table_bytes)
            .ok_or_else(|| corrupt(0, "WofCompressedData is shorter than its chunk table"))?;
        if payload_bytes > logical_bytes || payload_bytes < chunks {
            return Err(corrupt(
                0,
                "WOF payload length cannot describe its logical chunks",
            ));
        }
        Ok(Self {
            logical_bytes,
            chunk_bytes,
            chunks,
            offset_bytes,
            table_bytes,
            payload_bytes,
        })
    }

    fn table_window(&self, chunk: u64) -> Result<(u64, usize)> {
        if chunk >= self.chunks {
            return Err(corrupt(0, "WOF chunk index exceeds logical file size"));
        }
        let first = chunk.saturating_sub(1);
        let end = (chunk + 1).min(self.chunks - 1);
        Ok((
            first * self.offset_bytes as u64,
            (end - first) as usize * self.offset_bytes,
        ))
    }

    fn chunk_range(&self, chunk: u64, offsets: &[u8]) -> Result<(u64, usize, usize)> {
        let (_, expected_table) = self.table_window(chunk)?;
        if offsets.len() != expected_table {
            return Err(corrupt(0, "truncated WOF chunk offset pair"));
        }
        let mut at = 0;
        let mut next = || {
            let mut bytes = [0_u8; 8];
            bytes[..self.offset_bytes].copy_from_slice(&offsets[at..at + self.offset_bytes]);
            at += self.offset_bytes;
            u64::from_le_bytes(bytes)
        };
        let start = if chunk == 0 { 0 } else { next() };
        let end = if chunk + 1 == self.chunks {
            self.payload_bytes
        } else {
            next()
        };
        let expected = (self.logical_bytes - chunk * self.chunk_bytes as u64)
            .min(self.chunk_bytes as u64) as usize;
        let size = end
            .checked_sub(start)
            .filter(|size| *size != 0 && *size <= expected as u64 && end <= self.payload_bytes)
            .ok_or_else(|| {
                corrupt(
                    0,
                    "WOF chunk offsets are reversed, empty or outside their payload bounds",
                )
            })?;
        Ok((self.table_bytes + start, size as usize, expected))
    }
}

impl WofStorage {
    pub(super) fn read_into(
        &self,
        source: &Source,
        geometry: &NtfsGeometry,
        cx: &Cx,
        initialized: u64,
        offset: u64,
        output: &mut [u8],
    ) -> Result<()> {
        checkpoint(cx)?;
        output.fill(0);
        let count = initialized.saturating_sub(offset).min(output.len() as u64) as usize;
        let mut done = 0;
        while done < count {
            checkpoint(cx)?;
            let logical = offset + done as u64;
            let chunk = logical / self.layout.chunk_bytes as u64;
            let within = (logical % self.layout.chunk_bytes as u64) as usize;
            let (table_offset, table_length) = self.layout.table_window(chunk)?;
            let offsets = self
                .backing
                .read(source, geometry, cx, table_offset, table_length)?;
            let (payload_offset, stored, expected) = self.layout.chunk_range(chunk, &offsets)?;
            let available = expected
                .checked_sub(within)
                .filter(|bytes| *bytes != 0)
                .ok_or_else(|| corrupt(logical, "WOF read starts past its logical chunk"))?;
            let length = (count - done).min(available);
            let destination = &mut output[done..done + length];
            if stored == expected {
                // A raw chunk is identified by its exact native stored size,
                // never by bytes that happen to resemble a compression header.
                let bytes = self.backing.read(
                    source,
                    geometry,
                    cx,
                    payload_offset + within as u64,
                    length,
                )?;
                if bytes.len() != length {
                    return Err(corrupt(payload_offset, "short WOF logical chunk read"));
                }
                destination.copy_from_slice(&bytes);
            } else {
                let packed = self
                    .backing
                    .read(source, geometry, cx, payload_offset, stored)?;
                if packed.len() != stored {
                    return Err(corrupt(payload_offset, "short WOF compressed chunk read"));
                }
                checkpoint(cx)?;
                let decoded = if self.layout.chunk_bytes == lzx::MAX_OUTPUT_BYTES {
                    lzx::decompress_chunk(&packed, expected)
                } else {
                    xpress::decompress_chunk(&packed, expected)
                }
                .map_err(|error| parse(&error))?;
                checkpoint(cx)?;
                destination.copy_from_slice(&decoded[within..within + length]);
            }
            done += length;
        }
        checkpoint(cx)
    }
}

#[cfg(test)]
mod tests;
