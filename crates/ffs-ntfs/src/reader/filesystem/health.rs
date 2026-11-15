//! Fail-closed mount health and read/write operation serialization for [`super::NtfsFs`].
//!
//! No-write preflight refusals (`NtfsTxOutcome::NotCommitted`) leave the mount
//! healthy. Any `NtfsTxOutcome::Uncertain`, post-commit view/cache refresh error,
//! device sync failure, or panic while holding the writer gate latches `failed`
//! before releasing the gate so all subsequent operations fail closed with `EIO`.

use super::{Cx, FfsError, Result, checkpoint};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

pub(super) struct MountHealth {
    epoch: Arc<AtomicU64>,
    failed: AtomicBool,
}

impl MountHealth {
    pub(super) fn new() -> Self {
        Self {
            epoch: Arc::new(AtomicU64::new(0)),
            failed: AtomicBool::new(false),
        }
    }

    pub(super) fn bump_epoch(&self) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
    }

    pub(super) fn latch_failed(&self) {
        self.epoch.fetch_add(1, Ordering::AcqRel);
        self.failed.store(true, Ordering::Release);
    }

    fn check(&self) -> Result<()> {
        if self.failed.load(Ordering::Acquire) {
            return Err(FfsError::Io(std::io::Error::other(
                "NTFS mutation outcome or cache publication is uncertain; unmount and recover the image before reopening",
            )));
        }
        Ok(())
    }

    pub(super) fn operation<'a>(
        &'a self,
        cx: &Cx,
        operations: &'a RwLock<()>,
        mutation: bool,
    ) -> Result<OperationGuard<'a>> {
        checkpoint(cx)?;
        self.check()?;
        let poisoned = || {
            FfsError::Io(std::io::Error::other(
                "NTFS operation lock poisoned; unmount and recover the image",
            ))
        };
        let (reader, writer) = if mutation {
            (None, Some(operations.write().map_err(|_| poisoned())?))
        } else {
            (Some(operations.read().map_err(|_| poisoned())?), None)
        };
        self.check()?;
        checkpoint(cx)?;
        Ok(OperationGuard {
            _reader: reader,
            writer,
            health: self,
            initial_epoch: self.epoch.load(Ordering::Acquire),
            completed: false,
        })
    }
}

pub(super) struct OperationGuard<'a> {
    _reader: Option<RwLockReadGuard<'a, ()>>,
    writer: Option<RwLockWriteGuard<'a, ()>>,
    health: &'a MountHealth,
    initial_epoch: u64,
    completed: bool,
}

impl OperationGuard<'_> {
    pub(super) fn complete<T>(mut self, value: T) -> Result<T> {
        self.health.check()?;
        self.completed = true;
        Ok(value)
    }
}

impl Drop for OperationGuard<'_> {
    fn drop(&mut self) {
        if self.writer.is_some()
            && !self.completed
            && (std::thread::panicking()
                || self.health.epoch.load(Ordering::Acquire) != self.initial_epoch)
        {
            self.health.failed.store(true, Ordering::Release);
        }
    }
}
