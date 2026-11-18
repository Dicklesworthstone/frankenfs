//! CLI-owned workers that drain synchronous I/O before releasing mount resources.

use anyhow::{Context, Result, bail};
use asupersync::Cx;
use ffs_core::{FsFlavor, OpenFs};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// CLI-owned runtime for synchronous and async mount background workers. The core
/// filesystem continues to receive contexts from its caller (`bd-11a8t`, `bd-in31y`).
pub fn mount_background_runtime() -> Result<Arc<asupersync::runtime::Runtime>> {
    asupersync::runtime::RuntimeBuilder::multi_thread()
        .worker_threads(2)
        .blocking_threads(0, 16)
        .build()
        .map(Arc::new)
        .context("failed to create mount background runtime")
}

/// Sleep up to `duration` on `cx`'s timer driver while waking immediately on
/// cancellation, falling back to `park_timeout` only if `cx` has no timer driver.
pub fn sleep_with_cx(cx: &Cx, duration: Duration) {
    if duration.is_zero() || cx.checkpoint().is_err() {
        return;
    }
    if cx.timer_driver().is_some() {
        let _ambient = Cx::set_current(Some(cx.clone()));
        let (_keep_tx, mut cancel_rx) = asupersync::channel::oneshot::channel::<()>();
        let _ = ffs_block::block_on_park(asupersync::time::timeout(
            cx.now(),
            duration,
            cancel_rx.recv(cx),
        ));
    } else {
        std::thread::park_timeout(duration);
    }
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
                sleep_with_cx(cx, remaining.min(tick));
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

const WORKER_QUEUED: u8 = 0;
const WORKER_CLAIMED: u8 = 1;
const WORKER_CANCELLED: u8 = 2;

/// A child region plus an independent completion receipt for its blocking I/O.
/// Task cancellation must not authorize releasing the image lock: `sender` lives
/// inside the blocking closure so awaiting `completion` joins actual closure and
/// capture retirement, skips queued closures cancelled before pool claim, and
/// preserves post-commit results across late cancellation.
pub struct MountIoWorker<T> {
    region: Option<ffs_block::OwnedChildRegion>,
    task: Option<asupersync::runtime::TaskHandle<()>>,
    completion: asupersync::channel::oneshot::Receiver<Option<Result<T>>>,
    claim_gate: Arc<std::sync::atomic::AtomicU8>,
    worker_cx: Cx,
}

impl<T: Send + 'static> MountIoWorker<T> {
    pub fn start(
        cx: &Cx,
        _runtime: &Arc<asupersync::runtime::Runtime>,
        work: impl FnOnce(&Cx) -> Result<T> + Send + 'static,
    ) -> Result<Self> {
        let region = ffs_block::OwnedChildRegion::open_sync(cx)
            .context("failed to open mount worker region")?;
        let worker_principal_cx = region.cx().clone();
        let claim_gate = Arc::new(std::sync::atomic::AtomicU8::new(WORKER_QUEUED));
        let worker_gate = Arc::clone(&claim_gate);
        let (sender, completion) = asupersync::channel::oneshot::channel();
        let task = match region.spawn(move |worker_cx| async move {
            asupersync::runtime::spawn_blocking(move || {
                if worker_cx.checkpoint().is_err()
                    || worker_gate
                        .compare_exchange(
                            WORKER_QUEUED,
                            WORKER_CLAIMED,
                            std::sync::atomic::Ordering::AcqRel,
                            std::sync::atomic::Ordering::Acquire,
                        )
                        .is_err()
                {
                    if let Ok(permit) = worker_cx.masked(|| sender.reserve(&worker_cx)) {
                        let _ = permit.send(None);
                    }
                    return;
                }
                let Ok(permit) = worker_cx.masked(|| sender.reserve(&worker_cx)) else {
                    return;
                };
                let result =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(&worker_cx)))
                        .unwrap_or_else(|_| {
                            Err(anyhow::anyhow!("mount background I/O worker panicked"))
                        });
                let _ = permit.send(Some(result));
            })
            .await;
        }) {
            Ok(task) => task,
            Err(error) => {
                region.close_sync();
                return Err(error).context("failed to admit mount background I/O worker");
            }
        };
        Ok(Self {
            region: Some(region),
            task: Some(task),
            completion,
            claim_gate,
            worker_cx: worker_principal_cx,
        })
    }
}

impl<T> MountIoWorker<T> {
    pub fn request_stop(&self) -> Result<()> {
        let _ = self.claim_gate.compare_exchange(
            WORKER_QUEUED,
            WORKER_CANCELLED,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        );
        if let Some(region) = self.region.as_ref() {
            region
                .try_cancel(asupersync::types::CancelReason::user("mount stopping"))
                .context("failed to cancel mount worker region")?;
        }
        Ok(())
    }

    pub fn stop(&mut self) -> Result<Option<T>> {
        let Some(region) = self.region.take() else {
            return Ok(None);
        };
        let _ = self.claim_gate.compare_exchange(
            WORKER_QUEUED,
            WORKER_CANCELLED,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        );
        let cancel_res = region
            .try_cancel(asupersync::types::CancelReason::user("mount stopping"))
            .context("failed to cancel mount worker region");
        let mut task = self.task.take().expect("worker region has a task");
        let (joined, completed) = ffs_block::block_on_park(async {
            let completed =
                ffs_block::poll_masked(&self.worker_cx, self.completion.recv(&self.worker_cx))
                    .await;
            let joined = ffs_block::join_task_uninterruptible(&mut task).await;
            region.close_async().await;
            (joined, completed)
        });
        cancel_res?;
        match completed {
            Ok(Some(result)) => result.map(Some),
            Ok(None) => Ok(None),
            Err(_)
                if self.claim_gate.load(std::sync::atomic::Ordering::Acquire) != WORKER_CLAIMED =>
            {
                // Cancelled before the blocking closure claimed execution; no I/O ran.
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

    #[test]
    fn mount_io_worker_parent_cancellation_skips_queued_interrupts_running_and_preserves_post_commit_bd_in31y()
     {
        use std::sync::atomic::AtomicBool;

        let runtime = mount_background_runtime().unwrap();

        // 1. Pre-cancelled parent Cx refuses worker startup without running work.
        let pre_cancelled = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        pre_cancelled.cancel_with(
            asupersync::types::CancelKind::User,
            Some("pre-cancelled parent"),
        );
        let ran_queued = Arc::new(AtomicBool::new(false));
        let ran_queued_clone = Arc::clone(&ran_queued);
        assert!(
            MountIoWorker::start(&pre_cancelled, &runtime, move |_cx| {
                ran_queued_clone.store(true, Ordering::SeqCst);
                Ok(())
            })
            .is_err(),
            "pre-cancelled parent Cx must fail MountIoWorker::start closed"
        );
        assert!(!ran_queued.load(Ordering::SeqCst));

        // 2. Running worker wakes immediately when its parent Cx is cancelled
        //    without mutating a sibling mount's worker on the same runtime.
        let parent_a = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let parent_b = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let entered_a = Arc::new(AtomicBool::new(false));
        let entered_a_worker = Arc::clone(&entered_a);
        let mut worker_a = MountIoWorker::start(&parent_a, &runtime, move |cx| {
            entered_a_worker.store(true, Ordering::Release);
            sleep_with_cx(cx, Duration::from_secs(60));
            Ok(cx.checkpoint().is_err())
        })
        .unwrap();
        let mut worker_b = MountIoWorker::start(&parent_b, &runtime, move |cx| {
            assert!(cx.checkpoint().is_ok());
            Ok(99_u32)
        })
        .unwrap();

        while !entered_a.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        let started_cancel = Instant::now();
        parent_a.cancel_with(
            asupersync::types::CancelKind::User,
            Some("cancel mount A only"),
        );
        assert_eq!(
            worker_a.stop().unwrap(),
            Some(true),
            "running worker A must observe parent cancellation"
        );
        assert!(
            started_cancel.elapsed() < Duration::from_secs(2),
            "sleep_with_cx must wake promptly on parent cancellation"
        );
        assert_eq!(
            worker_b.stop().unwrap(),
            Some(99),
            "sibling mount B worker on the same runtime must be unaffected"
        );

        // 3. Post-commit result preservation: once durable work has claimed its
        //    pool slot and committed, concurrent parent cancellation AND stop
        //    requests preserve Some(value) and wait for actual closure retirement.
        let parent_c = runtime.request_cx_with_budget(asupersync::Budget::INFINITE);
        let committed_c = Arc::new(AtomicBool::new(false));
        let committed_c_worker = Arc::clone(&committed_c);
        let release_c = Arc::new(AtomicBool::new(false));
        let release_c_worker = Arc::clone(&release_c);
        let parent_c_worker = parent_c.clone();
        let mut worker_c = MountIoWorker::start(&parent_c, &runtime, move |_cx| {
            committed_c_worker.store(true, Ordering::Release);
            parent_c_worker.cancel_with(
                asupersync::types::CancelKind::User,
                Some("late cancel after commit"),
            );
            while !release_c_worker.load(Ordering::Acquire) {
                std::thread::yield_now();
            }
            Ok(42_u64)
        })
        .unwrap();
        while !committed_c.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        worker_c.request_stop().unwrap();
        release_c.store(true, Ordering::Release);
        assert_eq!(
            worker_c.stop().unwrap(),
            Some(42),
            "post-commit worker result must be preserved across late cancellation"
        );

        // 4. Queued cancellation before pool claim skips user work and returns None.
        let single_pool_rt = Arc::new(
            asupersync::runtime::RuntimeBuilder::multi_thread()
                .worker_threads(1)
                .blocking_threads(0, 1)
                .build()
                .unwrap(),
        );
        let blocker_cx = single_pool_rt.request_cx_with_budget(asupersync::Budget::INFINITE);
        let blocker_in = Arc::new(AtomicBool::new(false));
        let blocker_in_worker = Arc::clone(&blocker_in);
        let blocker_out = Arc::new(AtomicBool::new(false));
        let blocker_out_worker = Arc::clone(&blocker_out);
        let mut blocker = MountIoWorker::start(&blocker_cx, &single_pool_rt, move |_cx| {
            blocker_in_worker.store(true, Ordering::Release);
            while !blocker_out_worker.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_millis(2));
            }
            Ok(())
        })
        .unwrap();
        while !blocker_in.load(Ordering::Acquire) {
            std::thread::yield_now();
        }
        let queued_cx = single_pool_rt.request_cx_with_budget(asupersync::Budget::INFINITE);
        let ran_d = Arc::new(AtomicBool::new(false));
        let ran_d_worker = Arc::clone(&ran_d);
        let mut worker_d = MountIoWorker::start(&queued_cx, &single_pool_rt, move |_cx| {
            ran_d_worker.store(true, Ordering::Release);
            Ok(7_u64)
        })
        .unwrap();
        worker_d.request_stop().unwrap();
        blocker_out.store(true, Ordering::Release);
        assert_eq!(blocker.stop().unwrap(), Some(()));
        assert_eq!(
            worker_d.stop().unwrap(),
            None,
            "queued worker cancelled before pool claim must skip work and return None"
        );
        assert!(!ran_d.load(Ordering::Acquire));
    }
}
