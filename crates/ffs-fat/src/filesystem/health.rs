//! A mount can continue after a no-write preflight refusal, but not after an
//! unsuccessful request attempted native mutation or synchronization. Keep the
//! failure latch inside the operation gate, including cache publication.

use super::{Cx, FfsError, Result, checkpoint};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard};

pub(super) struct MountHealth {
    epoch: Arc<AtomicU64>,
    failed: AtomicBool,
}

impl MountHealth {
    pub(super) fn new(epoch: Arc<AtomicU64>) -> Self {
        Self {
            epoch,
            failed: AtomicBool::new(false),
        }
    }

    fn check(&self) -> Result<()> {
        if self.failed.load(Ordering::Acquire) {
            return Err(FfsError::Io(std::io::Error::other(
                "FAT mutation outcome or cache publication is uncertain; unmount and check/recover the image before reopening",
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
                "FAT operation lock poisoned; reopen and check the image",
            ))
        };
        let (reader, writer) = if mutation {
            (None, Some(operations.write().map_err(|_| poisoned())?))
        } else {
            (Some(operations.read().map_err(|_| poisoned())?), None)
        };
        // A waiter must see the preceding writer's failure before touching
        // cached nodes or the device. Epoch sampling also belongs inside the
        // gate, never before a different request's native writes finish.
        self.check()?;
        checkpoint(cx)?;
        Ok(OperationGuard {
            _reader: reader,
            writer,
            deferral: None,
            health: self,
            initial_epoch: self.epoch.load(Ordering::Acquire),
            completed: false,
        })
    }
}

pub(super) struct OperationGuard<'a> {
    _reader: Option<RwLockReadGuard<'a, ()>>,
    writer: Option<RwLockWriteGuard<'a, ()>>,
    deferral: Option<ffs_block::DurabilityCommitDeferral<'a>>,
    health: &'a MountHealth,
    initial_epoch: u64,
    completed: bool,
}

impl<'a> OperationGuard<'a> {
    pub(super) fn attach_deferral(&mut self, deferral: ffs_block::DurabilityCommitDeferral<'a>) {
        self.deferral = Some(deferral);
    }

    /// Finish only the cache and reply work following a successful native
    /// mutation. Cancellation cannot turn that committed result into EINTR;
    /// real publication errors still drop this guard and fence the mount.
    pub(super) fn publish_committed<T>(
        self,
        cx: &Cx,
        publish: impl FnOnce() -> Result<T>,
    ) -> Result<T> {
        cx.masked(|| self.complete(publish()?))
    }

    /// Call only after native durability, cache publication and fallible reply
    /// preparation have all succeeded. A later FUSE transport failure is not
    /// an unsuccessful native operation and cannot roll it back.
    pub(super) fn complete<T>(mut self, value: T) -> Result<T> {
        self.health.check()?;
        if let Some(mut deferral) = self.deferral.take() {
            deferral.complete();
        }
        self.completed = true;
        Ok(value)
    }
}

impl Drop for OperationGuard<'_> {
    fn drop(&mut self) {
        if let Some(deferral) = self.deferral.take() {
            drop(deferral);
        }
        if self.writer.is_some()
            && !self.completed
            && self.health.epoch.load(Ordering::Acquire) != self.initial_epoch
        {
            // This runs before the writer guard field is dropped. Waiting
            // readers/writers therefore cannot race with the failure latch.
            self.health.failed.store(true, Ordering::Release);
        }
    }
}

companion_bin_tests! {
    #[cfg(test)]
    mod tests;
}
