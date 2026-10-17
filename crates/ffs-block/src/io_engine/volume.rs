//! Explicit, byte-bounded views of an existing device.
//!
//! A view translates volume-relative offsets exactly once and validates an
//! entire request before forwarding it. It neither detects partitions nor
//! changes native filesystem geometry. A caller that has already selected a
//! partition can pass this device to a native parser with base offset zero.
//!
//! Read-only views reject writes and discard, and do not forward `sync`.
//! This restricts calls through the view; it cannot stop a different owner of
//! the backing device, or turn a repair-on-read implementation into a pure
//! reader. Use [`VolumeDevice::open_read_only`] for an OS read-only file handle.
//! Images still need to remain offline and immutable when required by a reader.

use crate::{ByteDevice, FileByteDevice, cx_checkpoint};
use asupersync::Cx;
use ffs_error::{FfsError, Result};
use ffs_types::ByteOffset;
use std::fmt;
use std::io::IoSliceMut;
use std::path::Path;
use std::sync::Arc;

/// Operations this view is allowed to forward to its backing device.
///
/// `ReadWrite` grants no additional rights on the underlying handle. Its own
/// permission, alignment, storage and cancellation errors remain authoritative.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum VolumeAccess {
    /// Never forward a write, discard or backing synchronization request.
    #[default]
    ReadOnly,
    /// Forward bounded mutations and whole-device synchronization.
    ReadWrite,
}

/// An owned, fixed-length window into another [`ByteDevice`].
///
/// Clones retain the same backing handle and selection; they do not reopen a
/// pathname. Offsets, including zero-length requests, must lie inside the
/// selected interval or exactly at its end. No sector alignment is imposed by
/// this byte adapter: native admission and the underlying device enforce any
/// format-specific constraints.
///
/// The selected length never grows with the backing. If the backing reports
/// that it has shrunk below the selected end, subsequent requests fail before
/// I/O. This is not live-image coherence: a device can cache its reported length
/// and an unrelated writer can change bytes concurrently.
#[derive(Clone)]
pub struct VolumeDevice {
    inner: Arc<dyn ByteDevice>,
    base: ByteOffset,
    length: u64,
    end: u64,
    access: VolumeAccess,
}

impl fmt::Debug for VolumeDevice {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VolumeDevice")
            .field("base", &self.base)
            .field("length", &self.length)
            .field("access", &self.access)
            .finish_non_exhaustive()
    }
}

impl VolumeDevice {
    /// Select exactly `[base, base + length)` without performing backing I/O.
    ///
    /// Empty volumes are representable. A native filesystem parser can reject
    /// them with its own minimum-size requirement. Invalid or overflowing
    /// selections return [`FfsError::InvalidGeometry`].
    pub fn new(
        inner: Arc<dyn ByteDevice>,
        base: ByteOffset,
        length: u64,
        access: VolumeAccess,
    ) -> Result<Self> {
        let end = base.0.checked_add(length).ok_or_else(|| {
            FfsError::InvalidGeometry("selected volume range overflows u64".to_owned())
        })?;
        let backing_length = inner.as_ref().len_bytes();
        if end > backing_length {
            return Err(FfsError::InvalidGeometry(format!(
                "selected volume exceeds backing: base={} length={length} backing_length={backing_length}",
                base.0
            )));
        }
        Ok(Self {
            inner,
            base,
            length,
            end,
            access,
        })
    }

    /// Open through the existing OS read-only device path and select a volume.
    ///
    /// A missing length selects the remaining bytes **at open time**, not an
    /// unbounded window. No writable open or writable fallback is attempted.
    /// Like `FileByteDevice`, this accepts files and supported block devices;
    /// it does not establish advisory locking, quiescence or native validity.
    pub fn open_read_only(
        cx: &Cx,
        path: impl AsRef<Path>,
        base: ByteOffset,
        length: Option<u64>,
    ) -> Result<Self> {
        cx_checkpoint(cx)?;
        let inner: Arc<dyn ByteDevice> = Arc::new(FileByteDevice::open_read_only(path)?);
        cx_checkpoint(cx)?;
        let length = match length {
            Some(length) => length,
            None => inner.as_ref().len_bytes().checked_sub(base.0).ok_or_else(|| {
                FfsError::InvalidGeometry("volume base exceeds backing length".to_owned())
            })?,
        };
        Self::new(inner, base, length, VolumeAccess::ReadOnly)
    }

    /// Return the start relative to this view's immediate backing device.
    #[must_use]
    pub fn base_offset(&self) -> ByteOffset {
        self.base
    }

    /// Return this view's mutation policy, not the backing handle's rights.
    #[must_use]
    pub fn access(&self) -> VolumeAccess {
        self.access
    }

    /// Select a smaller view without reopening the backing or granting rights.
    ///
    /// `base` is relative to this volume. Attempting to make a writable child
    /// of a read-only parent is refused even if both happen to be empty.
    pub fn subvolume(
        &self,
        base: ByteOffset,
        length: u64,
        access: VolumeAccess,
    ) -> Result<Self> {
        if self.access == VolumeAccess::ReadOnly && access == VolumeAccess::ReadWrite {
            return Err(FfsError::ReadOnly);
        }
        Self::new(Arc::new(self.clone()), base, length, access)
    }

    fn physical_range(&self, cx: &Cx, offset: ByteOffset, count: u64) -> Result<ByteOffset> {
        cx_checkpoint(cx)?;
        let end = offset.0.checked_add(count).ok_or_else(|| {
            FfsError::Format("volume-relative request overflows u64".to_owned())
        })?;
        if end > self.length {
            return Err(FfsError::Format(format!(
                "request exceeds selected volume: offset={} length={count} volume_length={}",
                offset.0, self.length
            )));
        }
        if self.end > self.inner.as_ref().len_bytes() {
            return Err(FfsError::Format(
                "backing length no longer covers the selected volume".to_owned(),
            ));
        }
        // Constructor and request checks prove both translated endpoints fit.
        // Keep the addition checked rather than relying on that proof silently.
        self.base
            .0
            .checked_add(offset.0)
            .map(ByteOffset)
            .ok_or_else(|| FfsError::Format("translated volume offset overflows u64".to_owned()))
    }

    fn require_write(&self, cx: &Cx) -> Result<()> {
        cx_checkpoint(cx)?;
        if self.access == VolumeAccess::ReadOnly {
            return Err(FfsError::ReadOnly);
        }
        Ok(())
    }
}

/// Sum the entire request before forwarding even its first nonempty buffer.
/// This allocates nothing and also checks conversion on wider pointer targets.
fn total_bytes(cx: &Cx, lengths: impl Iterator<Item = usize>) -> Result<u64> {
    let mut total = 0_u64;
    for (index, length) in lengths.enumerate() {
        // Vector metadata can be large even when every buffer is empty.
        if index.is_multiple_of(256) {
            cx_checkpoint(cx)?;
        }
        let length = u64::try_from(length)
            .map_err(|_| FfsError::Format("volume buffer length overflows u64".to_owned()))?;
        total = total
            .checked_add(length)
            .ok_or_else(|| FfsError::Format("volume request length overflows u64".to_owned()))?;
    }
    cx_checkpoint(cx)?;
    Ok(total)
}

impl ByteDevice for VolumeDevice {
    fn len_bytes(&self) -> u64 {
        self.length
    }

    fn supports_vectored_reads(&self) -> bool {
        self.inner.as_ref().supports_vectored_reads()
    }

    fn preserves_read_exact_at_destination_on_error(&self) -> bool {
        self.inner.as_ref().preserves_read_exact_at_destination_on_error()
    }

    fn preserves_read_vectored_destinations_on_error(&self) -> bool {
        self.inner.as_ref().preserves_read_vectored_destinations_on_error()
    }

    fn read_exact_at(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        let physical = self.physical_range(cx, offset, total_bytes(cx, std::iter::once(buf.len()))?)?;
        if buf.is_empty() {
            return Ok(());
        }
        // No fallible post-read checkpoint: it would turn an inner success
        // into Err after changing the destination, violating advertised flags.
        self.inner.as_ref().read_exact_at(cx, physical, buf)
    }

    fn read_exact_at_volatile(&self, cx: &Cx, offset: ByteOffset, buf: &mut [u8]) -> Result<()> {
        let physical = self.physical_range(cx, offset, total_bytes(cx, std::iter::once(buf.len()))?)?;
        if buf.is_empty() {
            return Ok(());
        }
        self.inner.as_ref().read_exact_at_volatile(cx, physical, buf)
    }

    fn read_vectored_exact_at(
        &self,
        cx: &Cx,
        offset: ByteOffset,
        bufs: &mut [IoSliceMut<'_>],
    ) -> Result<()> {
        cx_checkpoint(cx)?;
        let count = total_bytes(cx, bufs.iter().map(|buf| buf.len()))?;
        let physical = self.physical_range(cx, offset, count)?;
        if count == 0 {
            return Ok(());
        }
        // Dispatch through the underlying trait object, not an Arc forwarder.
        // Preserve the native scatter path and its whole-request error policy;
        // do not flatten the buffers or silently fall back to scalar reads.
        self.inner.as_ref().read_vectored_exact_at(cx, physical, bufs)
    }

    fn write_all_at(&self, cx: &Cx, offset: ByteOffset, buf: &[u8]) -> Result<()> {
        self.require_write(cx)?;
        let physical = self.physical_range(cx, offset, total_bytes(cx, std::iter::once(buf.len()))?)?;
        if buf.is_empty() {
            return Ok(());
        }
        self.inner.as_ref().write_all_at(cx, physical, buf)
    }

    fn write_vectored_all_at(&self, cx: &Cx, offset: ByteOffset, bufs: &[&[u8]]) -> Result<()> {
        self.require_write(cx)?;
        let count = total_bytes(cx, bufs.iter().map(|buf| buf.len()))?;
        let physical = self.physical_range(cx, offset, count)?;
        if count == 0 {
            return Ok(());
        }
        // Keep the existing gather implementation, without a payload-sized copy.
        self.inner.as_ref().write_vectored_all_at(cx, physical, bufs)
    }

    fn sync(&self, cx: &Cx) -> Result<()> {
        self.physical_range(cx, ByteOffset(0), 0)?;
        if self.access == VolumeAccess::ReadOnly {
            return Ok(());
        }
        // ByteDevice has no range-sync operation. This is a backing-wide
        // persistence barrier, not a promise to flush only the selected bytes.
        self.inner.as_ref().sync(cx)
    }

    fn supports_discard(&self) -> bool {
        self.access == VolumeAccess::ReadWrite && self.inner.as_ref().supports_discard()
    }

    fn discard(&self, cx: &Cx, offset: ByteOffset, length: u64) -> Result<()> {
        self.require_write(cx)?;
        let physical = self.physical_range(cx, offset, length)?;
        if length == 0 {
            return Ok(());
        }
        self.inner.as_ref().discard(cx, physical, length)
    }
}

#[cfg(test)]
mod tests;
