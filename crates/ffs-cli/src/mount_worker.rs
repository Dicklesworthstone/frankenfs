//! CLI-owned workers that drain synchronous I/O before releasing mount resources.

use anyhow::{Context, Result, bail};
use asupersync::Cx;
use ffs_core::{FsFlavor, OpenFs};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// CLI-owned runtime for the two synchronous background I/O workers. The core
/// filesystem continues to receive contexts from its caller (bd-11a8t).
pub fn mount_background_runtime() -> Result<Arc<asupersync::runtime::Runtime>> {
    asupersync::runtime::RuntimeBuilder::multi_thread()
        .worker_threads(1)
        .blocking_threads(0, 2)
        .build()
        .map(Arc::new)
        .context("failed to create mount background runtime")
}

pub trait PeriodicCommitTarget: Send + Sync + 'static {
    fn default_commit_interval(&self) -> Option<Duration>;
    fn periodic_commit(&self, cx: &Cx) -> ffs_error::Result<bool>;
}

impl PeriodicCommitTarget for OpenFs {
    fn default_commit_interval(&self) -> Option<Duration> {
        Some(Duration::from_secs(match &self.flavor {
            FsFlavor::Ext4(_) => 5,
            FsFlavor::Btrfs(_) => 30,
        }))
    }

    fn periodic_commit(&self, cx: &Cx) -> ffs_error::Result<bool> {
        Self::periodic_commit(self, cx)
    }
}

/// Use the same periodic filesystem durability boundary for ordinary and
/// sidecar-protected mounts. A protected device's sync also publishes current
/// repair coverage. Zero explicitly disables the timer; fsync still works.
pub fn start_periodic_commit<F: PeriodicCommitTarget>(
    cx: &Cx,
    runtime: &Arc<asupersync::runtime::Runtime>,
    open_fs: &Arc<F>,
    interval: Option<Duration>,
    operation_id: &str,
) -> Result<Option<MountIoWorker<()>>> {
    let Some(interval) = interval.or_else(|| open_fs.default_commit_interval()) else {
        return Ok(None);
    };
    if interval.is_zero() {
        info!(
            target: "ffs::cli::mount",
            operation_id,
            "periodic_commit_disabled"
        );
        return Ok(None);
    }
    let fs = Arc::clone(open_fs);
    let operation_id = operation_id.to_owned();
    let worker = MountIoWorker::start(cx, runtime, move |cx| {
        info!(
            target: "ffs::cli::mount",
            operation_id = %operation_id,
            interval_secs = interval.as_secs(),
            "periodic_commit_started"
        );
        let tick = Duration::from_millis(100);
        let mut previous = cx.now();
        while cx.checkpoint().is_ok() {
            let now = cx.now();
            let elapsed = Duration::from_nanos(now.duration_since(previous));
            let remaining = interval.saturating_sub(elapsed);
            if !remaining.is_zero() {
                std::thread::sleep(remaining.min(tick));
                continue;
            }
            if cx.checkpoint().is_err() {
                break;
            }
            // Count scheduling delays and commit time, using the clock inherited
            // from the mount runtime. Skip missed ticks rather than replaying them.
            previous = now;
            match fs.periodic_commit(cx) {
                Ok(true) => debug!(
                    target: "ffs::cli::mount",
                    operation_id = %operation_id,
                    "periodic_commit_applied"
                ),
                Ok(false) => debug!(
                    target: "ffs::cli::mount",
                    operation_id = %operation_id,
                    "periodic_commit_idle"
                ),
                Err(error) => warn!(
                    target: "ffs::cli::mount",
                    operation_id = %operation_id,
                    error = %error,
                    "periodic_commit_failed"
                ),
            }
        }
        Ok(())
    })?;
    Ok(Some(worker))
}

/// A child region plus an independent completion receipt for its blocking I/O.
/// Task cancellation must not authorize releasing the image lock: the receipt
/// establishes that all worker I/O and cleanup have finished and preserves the
/// actual result even when the wrapper classifies completion as cancellation.
pub struct MountIoWorker<T> {
    runtime: Arc<asupersync::runtime::Runtime>,
    region: Option<asupersync::cx::ChildRegion>,
    task: Option<asupersync::runtime::TaskHandle<()>>,
    completion: asupersync::channel::oneshot::Receiver<Result<T>>,
    cleanup_cx: Cx,
}

impl<T: Send + 'static> MountIoWorker<T> {
    pub fn start(
        cx: &Cx,
        runtime: &Arc<asupersync::runtime::Runtime>,
        work: impl FnOnce(&Cx) -> Result<T> + Send + 'static,
    ) -> Result<Self> {
        let region = runtime
            .block_on(cx.open_child_region(asupersync::cx::ChildRegionSpec::inherit()))
            .context("failed to open mount worker region")?;
        // Cleanup must remain waitable after cancellation of the work subtree.
        let cleanup_cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let completion_cx = cleanup_cx.clone();
        let (sender, completion) = asupersync::channel::oneshot::channel();
        let task = region
            .cx()
            .spawn_blocking(move |worker_cx| {
                // A cancelled pool job can remain queued until a slot opens.
                // Refuse user work when cancellation won before execution.
                if worker_cx.checkpoint().is_err() {
                    return;
                }
                // Reserve before work, then publish without a cancellation point.
                // Before admission the sender can be dropped safely: no I/O ran.
                let Ok(permit) = sender.reserve(&completion_cx) else {
                    return;
                };
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(&worker_cx)))
                        .unwrap_or_else(|_| {
                            Err(anyhow::anyhow!("mount background I/O worker panicked"))
                        });
                let _ = permit.send(result);
            })
            .context("failed to admit mount background I/O worker")?;
        Ok(Self {
            runtime: Arc::clone(runtime),
            region: Some(region),
            task: Some(task),
            completion,
            cleanup_cx,
        })
    }
}

impl<T> MountIoWorker<T> {
    pub fn request_stop(&self) -> Result<()> {
        if let Some(region) = self.region.as_ref() {
            region
                .cancel(asupersync::types::CancelReason::user("mount stopping"))
                .context("failed to cancel mount worker region")?;
        }
        Ok(())
    }

    pub fn stop(&mut self) -> Result<Option<T>> {
        let Some(region) = self.region.take() else {
            return Ok(None);
        };
        let cancel = region.cancel(asupersync::types::CancelReason::user("mount stopping"));
        let mut task = self.task.take().expect("worker region has a task");
        let joined = self.runtime.block_on(task.join(&self.cleanup_cx));
        let closed = self.runtime.block_on(region.close());
        // Never return early on a wrapper error: the closure may still own the
        // device. Also do not replace this drain with shutdown_timeout, which
        // may detach a still-running blocking writer.
        let completed = self
            .runtime
            .block_on(self.completion.recv(&self.cleanup_cx));
        cancel.context("failed to cancel mount worker region")?;
        closed.context("failed to close mount worker region")?;
        match completed {
            Ok(result) => result.map(Some),
            Err(_) if matches!(joined, Err(asupersync::runtime::JoinError::Cancelled(_))) => {
                // Cancellation won before user work started; no I/O ran.
                Ok(None)
            }
            Err(error) => {
                bail!("mount worker lost its completion receipt: {error}; join={joined:?}")
            }
        }
    }
}

impl<T> Drop for MountIoWorker<T> {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            error!(target: "ffs::cli::mount", %error, "mount_background_cleanup_failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    struct CommitTarget {
        commits: AtomicUsize,
    }

    impl PeriodicCommitTarget for CommitTarget {
        fn default_commit_interval(&self) -> Option<Duration> {
            Some(Duration::from_secs(30))
        }

        fn periodic_commit(&self, _cx: &Cx) -> ffs_error::Result<bool> {
            self.commits.fetch_add(1, Ordering::SeqCst);
            Ok(true)
        }
    }

    #[test]
    fn periodic_commit_uses_elapsed_context_time_bd_dj725() {
        let clock = Arc::new(asupersync::time::VirtualClock::new());
        let runtime = Arc::new(
            asupersync::runtime::RuntimeBuilder::multi_thread()
                .worker_threads(1)
                .blocking_threads(0, 1)
                .with_timer_driver(asupersync::time::TimerDriverHandle::with_virtual_clock(
                    Arc::clone(&clock),
                ))
                .build()
                .unwrap(),
        );
        let cx = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let target = Arc::new(CommitTarget {
            commits: AtomicUsize::new(0),
        });
        let mut worker = start_periodic_commit(&cx, &runtime, &target, None, "elapsed-time-test")
            .unwrap()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        while target.commits.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < deadline, "elapsed commit interval ignored");
            // Repeated advances also cover a worker admitted after the first
            // advance. Counting requested sleeps would take 30 real seconds.
            clock.advance(31_000_000_000);
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(Instant::now() < deadline, "commit arrived after watchdog");
        assert_eq!(worker.stop().unwrap(), Some(()));
    }
}
