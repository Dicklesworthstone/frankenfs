//! Mount-owned source and optional parity scrubbing through the admitted device.
//!
//! Never calls `sync`, writes caller data, or opens the image independently.
//! Each read verifies the device's current intended bytes and may perform its
//! existing generation-checked repair. Optional parity maintenance uses clean,
//! resumable device steps; it never publishes outstanding filesystem writes.
//! Reports describe source reads or protection-group observations, not snapshots.

use crate::mount_worker::MountIoWorker;
use anyhow::{Context, Result, bail};
use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_repair::sidecar::live::{
    ProtectionScrubCursor, ProtectionScrubReport, ProtectionScrubStep, SidecarImageDevice,
};
use ffs_types::ByteOffset;
use serde::Serialize;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

const READ_BYTES: usize = 64 * 1024;
const STOP_POLL: Duration = Duration::from_millis(20);
const BETWEEN_READS: Duration = Duration::from_millis(1);
// Yield/check cancellation between groups and cap each scheduling batch. A
// cycle additionally limits total attempts using the admitted image geometry.
const PROTECTION_STEPS_PER_BATCH: usize = 64;

#[derive(Debug, Default, clap::Args)]
pub struct Options {
    /// Scan protected source bytes in the background; seconds between full passes.
    #[arg(
        long = "scrub-interval-secs",
        conflicts_with = "check",
        value_parser = clap::value_parser!(u64).range(1..=86_400)
    )]
    pub(super) interval_secs: Option<u64>,
    /// Also check and replenish repair symbols at clean device boundaries.
    #[arg(
        long = "scrub-parity",
        requires = "interval_secs",
        conflicts_with = "check"
    )]
    pub(super) parity: bool,
}

impl Options {
    pub(super) fn validate(&self, check: bool) -> Result<()> {
        if self.parity && self.interval_secs.is_none() {
            bail!("--scrub-parity requires --scrub-interval-secs");
        }
        if let Some(seconds) = self.interval_secs {
            if check {
                bail!("--scrub-interval-secs requires a mount, not --check");
            }
            if !(1..=86_400).contains(&seconds) {
                bail!("--scrub-interval-secs must be between 1 and 86400");
            }
        }
        Ok(())
    }
}

struct SourcePass {
    image_bytes: u64,
    verified_bytes: u64,
    buffer: Vec<u8>,
}

impl SourcePass {
    fn new(image_bytes: u64) -> Result<Self> {
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(READ_BYTES)?;
        buffer.resize(READ_BYTES, 0);
        Ok(Self {
            image_bytes,
            verified_bytes: 0,
            buffer,
        })
    }

    /// Advance only after a successful complete read and cancellation check.
    /// The device releases its serialization lock between these bounded reads.
    fn step(&mut self, cx: &Cx, device: &dyn ByteDevice) -> Result<bool> {
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        if device.len_bytes() != self.image_bytes {
            bail!("protected source geometry changed during scrub");
        }
        let remaining = self.image_bytes - self.verified_bytes;
        if remaining == 0 {
            return Ok(false);
        }
        let count = usize::try_from(remaining.min(u64::try_from(READ_BYTES)?))?;
        device
            .read_exact_at(
                cx,
                ByteOffset(self.verified_bytes),
                &mut self.buffer[..count],
            )
            .with_context(|| format!("protected source scrub at byte {}", self.verified_bytes))?;
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        self.verified_bytes += u64::try_from(count)?;
        Ok(true)
    }
}

#[derive(Debug, Serialize)]
struct PassReport {
    event: &'static str,
    completed_passes: u64,
    source_bytes_verified: u64,
    consistency: &'static str,
}

fn emit(report: &impl Serialize) -> Result<()> {
    // Keep mount lifecycle events on stdout; scrub evidence is JSONL on stderr.
    let mut out = std::io::stderr().lock();
    serde_json::to_writer(&mut out, report)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

#[derive(Debug, Serialize)]
struct ProtectionPassReport {
    event: &'static str,
    completed_passes: u64,
    groups_verified: u32,
    source_bytes_verified: u64,
    source_blocks_recovered_during_steps: u64,
    invalid_repair_symbols_observed: u64,
    archive_rebuilt: bool,
    consistency: &'static str,
}

impl ProtectionPassReport {
    const fn new(completed_passes: u64, report: ProtectionScrubReport) -> Self {
        Self {
            event: "protected_parity_scrub_pass",
            completed_passes,
            groups_verified: report.groups_verified,
            source_bytes_verified: report.source_bytes_verified,
            source_blocks_recovered_during_steps: report.source_blocks_recovered,
            invalid_repair_symbols_observed: report.invalid_repair_symbols,
            archive_rebuilt: report.archive_rebuilt,
            consistency: "per_group_not_snapshot",
        }
    }
}

#[derive(Default)]
struct ProtectionMaintenance {
    cursor: ProtectionScrubCursor,
    completed_passes: u64,
}

impl ProtectionMaintenance {
    /// Attempt one full protection pass after a source scan, without waiting
    /// another source interval after each batch. Even continuous epoch changes
    /// cannot consume more than a geometry-sized budget, rounded to one batch.
    fn cycle(
        &mut self,
        cx: &Cx,
        shutdown: &AtomicBool,
        groups: u32,
        mut step: impl FnMut(&mut ProtectionScrubCursor) -> ffs_error::Result<ProtectionScrubStep>,
        mut report: impl FnMut(&ProtectionPassReport) -> Result<()>,
    ) -> Result<()> {
        // One step per group plus the final verification/publication step.
        let batches = (u64::from(groups) + 1).div_ceil(PROTECTION_STEPS_PER_BATCH as u64);
        for _ in 0..batches {
            if !self.batch(cx, shutdown, &mut step, &mut report)? {
                break;
            }
        }
        Ok(())
    }

    /// Resume one bounded batch after a complete source scan. Deferral retains
    /// the cursor but does not count as a completed parity pass. The library
    /// restarts this private cursor if a foreground sync publishes a new epoch.
    /// Returns true only when all batch attempts made progress without finishing.
    fn batch(
        &mut self,
        cx: &Cx,
        shutdown: &AtomicBool,
        mut step: impl FnMut(&mut ProtectionScrubCursor) -> ffs_error::Result<ProtectionScrubStep>,
        mut report: impl FnMut(&ProtectionPassReport) -> Result<()>,
    ) -> Result<bool> {
        // The worker's stop() cancels this same Cx. Managed/external unmount
        // sets shutdown; no independent unjoined task or cleanup Cx is used.
        let never_stopped = AtomicBool::new(false);
        for _ in 0..PROTECTION_STEPS_PER_BATCH {
            if shutdown.load(Ordering::Acquire) {
                return Ok(false);
            }
            cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
            match step(&mut self.cursor).context("protected parity scrub")? {
                ProtectionScrubStep::Busy | ProtectionScrubStep::PendingWrites => return Ok(false),
                ProtectionScrubStep::GroupVerified { .. } => {
                    if !wait(cx, &never_stopped, shutdown, BETWEEN_READS)? {
                        return Ok(false);
                    }
                }
                ProtectionScrubStep::Complete(observed) => {
                    self.completed_passes = self.completed_passes.saturating_add(1);
                    report(&ProtectionPassReport::new(self.completed_passes, observed))?;
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}

/// A mount-owned child region whose blocking I/O is drained before cleanup.
/// Local stop cancels only this worker; parent cancellation also stops it.
/// Final filesystem cleanup uses a separate, uncancelled context.
pub struct ScrubGuard {
    stop: Arc<AtomicBool>,
    worker: MountIoWorker<()>,
}

impl ScrubGuard {
    pub(super) fn start(
        cx: &Cx,
        runtime: &Arc<asupersync::runtime::Runtime>,
        device: Arc<SidecarImageDevice>,
        shutdown: Arc<AtomicBool>,
        interval: Duration,
        parity: bool,
    ) -> Result<Self> {
        Self::start_with_reports(
            cx,
            runtime,
            device,
            shutdown,
            interval,
            parity,
            (emit, emit),
        )
    }

    // Both production and worker tests use this exact integration. Report
    // failure stays inside the existing unmount-on-failure and joined lifetime.
    fn start_with_reports(
        cx: &Cx,
        runtime: &Arc<asupersync::runtime::Runtime>,
        device: Arc<SidecarImageDevice>,
        shutdown: Arc<AtomicBool>,
        interval: Duration,
        parity: bool,
        reports: (
            impl FnMut(&PassReport) -> Result<()> + Send + 'static,
            impl FnMut(&ProtectionPassReport) -> Result<()> + Send + 'static,
        ),
    ) -> Result<Self> {
        let (mut source_report, mut parity_report) = reports;
        let maintenance_device = Arc::clone(&device);
        let maintenance_shutdown = Arc::clone(&shutdown);
        let mut maintenance = ProtectionMaintenance::default();
        Self::spawn(
            cx,
            runtime,
            device,
            shutdown,
            interval,
            move |worker_cx, source| {
                source_report(source)?;
                if parity {
                    maintenance.cycle(
                        worker_cx,
                        &maintenance_shutdown,
                        maintenance_device.protection_group_count(),
                        |cursor| maintenance_device.scrub_step(worker_cx, cursor),
                        &mut parity_report,
                    )?;
                }
                Ok(())
            },
        )
    }

    fn spawn(
        cx: &Cx,
        runtime: &Arc<asupersync::runtime::Runtime>,
        device: Arc<dyn ByteDevice>,
        shutdown: Arc<AtomicBool>,
        interval: Duration,
        report: impl FnMut(&Cx, &PassReport) -> Result<()> + Send + 'static,
    ) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        // Capture before admission: a cancelled queued closure can be dropped
        // without ever entering run(), but must still wake managed unmount.
        let failure = UnmountOnFailure {
            shutdown,
            stop: Arc::clone(&stop),
            started: false,
            armed: true,
        };
        let worker = MountIoWorker::start(cx, runtime, move |worker_cx| {
            let mut failure = failure;
            failure.started = true;
            let result = run(
                worker_cx,
                device.as_ref(),
                &failure.stop,
                &failure.shutdown,
                interval,
                report,
            );
            if result.is_ok() {
                failure.armed = false;
            }
            result
        })
        .context("start protected source scrub worker")?;
        Ok(Self { stop, worker })
    }

    pub(super) fn request_stop(&self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        self.worker.request_stop()
    }

    pub(super) fn stop(&mut self) -> Result<()> {
        let cancel = self.request_stop();
        // A failed cancellation request never authorizes early device release.
        let drained = self.worker.stop();
        cancel.and(drained).map(|_| ())
    }
}

impl Drop for ScrubGuard {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!("protected source scrub shutdown failed: {error:#}");
        }
    }
}

struct UnmountOnFailure {
    shutdown: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    started: bool,
    armed: bool,
}

impl Drop for UnmountOnFailure {
    fn drop(&mut self) {
        // A local stop before admission is normal. Once work starts, an I/O
        // error or panic must request unmount even if it races that local stop.
        if self.armed && (self.started || !self.stop.load(Ordering::Acquire)) {
            self.shutdown.store(true, Ordering::Release);
        }
    }
}

fn stopping(stop: &AtomicBool, shutdown: &AtomicBool) -> bool {
    stop.load(Ordering::Acquire) || shutdown.load(Ordering::Acquire)
}

/// Bounded polling also handles external unmount, which only changes the
/// managed shutdown flag. Spurious unparks cannot shorten the configured wait.
fn wait(cx: &Cx, stop: &AtomicBool, shutdown: &AtomicBool, duration: Duration) -> Result<bool> {
    let start = Instant::now();
    loop {
        if stopping(stop, shutdown) {
            return Ok(false);
        }
        cx.checkpoint().map_err(|_| FfsError::Cancelled)?;
        let remaining = duration.saturating_sub(start.elapsed());
        if remaining.is_zero() {
            return Ok(true);
        }
        thread::park_timeout(remaining.min(STOP_POLL));
    }
}

fn run(
    cx: &Cx,
    device: &dyn ByteDevice,
    stop: &AtomicBool,
    shutdown: &AtomicBool,
    interval: Duration,
    mut report: impl FnMut(&Cx, &PassReport) -> Result<()>,
) -> Result<()> {
    let result: Result<()> = (|| {
        let mut pass = SourcePass::new(device.len_bytes())?;
        let mut completed_passes = 0_u64;
        loop {
            if stopping(stop, shutdown) {
                return Ok(());
            }
            if pass.step(cx, device)? {
                if !wait(cx, stop, shutdown, BETWEEN_READS)? {
                    return Ok(());
                }
                continue;
            }
            completed_passes = completed_passes.saturating_add(1);
            report(
                cx,
                &PassReport {
                    event: "protected_source_scrub_pass",
                    completed_passes,
                    source_bytes_verified: pass.verified_bytes,
                    consistency: "per_read_not_snapshot",
                },
            )?;
            if !wait(cx, stop, shutdown, interval)? {
                return Ok(());
            }
            pass.verified_bytes = 0;
        }
    })();
    match result {
        // Only cancellation requested for shutdown is a normal stop. In
        // particular, an I/O or corruption error racing shutdown stays an error.
        Err(error)
            if stopping(stop, shutdown)
                && error.chain().any(|cause| {
                    matches!(cause.downcast_ref::<FfsError>(), Some(FfsError::Cancelled))
                }) =>
        {
            Ok(())
        }
        other => other,
    }
}

#[cfg(test)]
mod tests;
