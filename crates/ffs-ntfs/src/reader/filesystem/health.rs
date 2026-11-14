//! Serialize native publication with readers and refuse a mount whose last
//! mutation has no verified outcome. Expected preflight errors do not poison it.

use super::{Cx, FfsError, Result, checkpoint};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

pub(super) struct MountHealth {
    dirty: AtomicBool,
    failed: AtomicBool,
}

impl MountHealth {
    pub(super) const fn new() -> Self {
        Self {
            dirty: AtomicBool::new(false),
            failed: AtomicBool::new(false),
        }
    }

    /// The caller owns the exclusive operation gate and is about to invoke a
    /// native writer or a durability barrier. Set this before any backing I/O.
    pub(super) fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::Release);
    }

    /// Clear only after a proven no-write rejection, or after native commitment
    /// and replacement of every cached view. This never clears a failure latch.
    pub(super) fn mark_clean(&self) {
        self.dirty.store(false, Ordering::Release);
    }

    pub(super) fn fail(&self) {
        self.failed.store(true, Ordering::Release);
    }

    fn check(&self) -> Result<()> {
        if self.failed.load(Ordering::Acquire) {
            return Err(FfsError::Io(std::io::Error::other(
                "NTFS mutation outcome or cached view is uncertain; unmount and recover the image before reopening",
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
        // Both checks belong inside the gate too: a queued request must not
        // consume a stale cache after the preceding writer failed.
        self.check()?;
        checkpoint(cx)?;
        Ok(OperationGuard {
            _reader: reader,
            writer,
            health: self,
        })
    }
}

pub(super) struct OperationGuard<'a> {
    _reader: Option<RwLockReadGuard<'a, ()>>,
    writer: Option<RwLockWriteGuard<'a, ()>>,
    health: &'a MountHealth,
}

impl OperationGuard<'_> {
    /// A durable result remains successful if cancellation arrives while its
    /// reply is being formed. No cancellation checkpoint belongs here.
    pub(super) fn complete<T>(self, value: T) -> Result<T> {
        if self.writer.is_some() && self.health.dirty.load(Ordering::Acquire) {
            self.health.fail();
        }
        self.health.check()?;
        Ok(value)
    }
}

impl Drop for OperationGuard<'_> {
    fn drop(&mut self) {
        if self.writer.is_some() && self.health.dirty.load(Ordering::Acquire) {
            // Drop runs before the writer-lock field is released. No waiting
            // read or mutation can race ahead of this latch, including unwind.
            self.health.fail();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preflight_refusal_and_clean_rejection_leave_mount_usable() {
        let cx = Cx::for_testing();
        let health = MountHealth::new();
        let gate = RwLock::new(());
        drop(health.operation(&cx, &gate, true).unwrap());
        let operation = health.operation(&cx, &gate, true).unwrap();
        health.mark_dirty();
        health.mark_clean();
        drop(operation);
        assert!(health.operation(&cx, &gate, false).is_ok());
        assert!(health.operation(&cx, &gate, true).is_ok());
    }

    #[test]
    fn failed_publication_latches_before_gate_release() {
        let cx = Cx::for_testing();
        let health = MountHealth::new();
        let gate = RwLock::new(());
        let operation = health.operation(&cx, &gate, true).unwrap();
        health.mark_dirty();
        drop(operation);
        assert!(gate.try_write().is_ok(), "failure is independent of poison");
        assert!(health.operation(&cx, &gate, false).is_err());
        health.mark_clean();
        assert!(health.operation(&cx, &gate, true).is_err());
    }

    #[test]
    fn cannot_complete_an_unpublished_mutation() {
        let cx = Cx::for_testing();
        let health = MountHealth::new();
        let gate = RwLock::new(());
        let operation = health.operation(&cx, &gate, true).unwrap();
        health.mark_dirty();
        assert!(operation.complete(42).is_err());
        assert!(health.operation(&cx, &gate, false).is_err());
    }

    #[test]
    fn cancellation_before_gate_is_noop_and_after_commit_preserves_success() {
        let cx = Cx::for_testing();
        let health = MountHealth::new();
        let gate = RwLock::new(());
        cx.set_cancel_requested(true);
        assert!(matches!(
            health.operation(&cx, &gate, true),
            Err(FfsError::Cancelled)
        ));
        let cx = Cx::for_testing();
        let operation = health.operation(&cx, &gate, true).unwrap();
        health.mark_dirty();
        health.mark_clean();
        cx.set_cancel_requested(true);
        assert_eq!(operation.complete(42).unwrap(), 42);
        assert!(health.operation(&Cx::for_testing(), &gate, false).is_ok());
    }

    #[test]
    fn waiting_reader_observes_failed_writer() {
        let health = MountHealth::new();
        let gate = RwLock::new(());
        let operation = health.operation(&Cx::for_testing(), &gate, true).unwrap();
        health.mark_dirty();
        std::thread::scope(|scope| {
            let reader =
                scope.spawn(|| health.operation(&Cx::for_testing(), &gate, false).is_err());
            drop(operation);
            assert!(reader.join().unwrap());
        });
    }
}
