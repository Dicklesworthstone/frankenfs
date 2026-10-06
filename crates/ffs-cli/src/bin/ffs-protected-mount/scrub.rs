//! Mount-owned source scrubbing through the admitted repair device.
//!
//! Never calls `sync`, writes caller data, or opens the image independently.
//! Each read verifies the device's current intended bytes and may perform its
//! existing generation-checked repair. A pass is not a filesystem snapshot and
//! does not attest parity health or publish outstanding filesystem writes.

use anyhow::{Context, Result, bail};
use asupersync::Cx;
use ffs_block::ByteDevice;
use ffs_error::FfsError;
use ffs_repair::sidecar::live::SidecarImageDevice;
use ffs_types::ByteOffset;
use serde::Serialize;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const READ_BYTES: usize = 64 * 1024;
const STOP_POLL: Duration = Duration::from_millis(20);
const BETWEEN_READS: Duration = Duration::from_millis(1);

#[derive(Debug, Default, clap::Args)]
pub(super) struct Options {
    /// Scan protected source bytes in the background; seconds between full passes.
    #[arg(
        long = "scrub-interval-secs",
        conflicts_with = "check",
        value_parser = clap::value_parser!(u64).range(1..=86_400)
    )]
    pub(super) interval_secs: Option<u64>,
}

impl Options {
    pub(super) fn validate(&self, check: bool) -> Result<()> {
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

fn emit(report: &PassReport) -> Result<()> {
    // Keep mount lifecycle events on stdout; scrub evidence is JSONL on stderr.
    let mut out = std::io::stderr().lock();
    serde_json::to_writer(&mut out, report)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

/// A joined blocking-I/O worker with the same Cx cancellation authority as
/// startup. As in the ordinary mount's scrub guard, drop requests cancellation
/// and joins; the worker releases its device ownership before stop returns.
/// Final filesystem cleanup uses its separate, uncancelled context.
pub(super) struct ScrubGuard {
    cx: Cx,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<Result<()>>>,
}

impl ScrubGuard {
    pub(super) fn start(
        cx: &Cx,
        device: Arc<SidecarImageDevice>,
        shutdown: Arc<AtomicBool>,
        interval: Duration,
    ) -> Result<Self> {
        Self::spawn(cx, device, shutdown, interval, emit)
    }

    fn spawn(
        cx: &Cx,
        device: Arc<dyn ByteDevice>,
        shutdown: Arc<AtomicBool>,
        interval: Duration,
        report: impl FnMut(&PassReport) -> Result<()> + Send + 'static,
    ) -> Result<Self> {
        let stop = Arc::new(AtomicBool::new(false));
        let worker_cx = cx.clone();
        let worker_stop = Arc::clone(&stop);
        let handle = thread::Builder::new()
            .name("ffs-protected-scrub".to_owned())
            .spawn(move || {
                // This guard also runs on panic: otherwise the main thread could
                // remain blocked in managed wait after losing its scrub worker.
                let mut failure = UnmountOnFailure {
                    shutdown: &shutdown,
                    armed: true,
                };
                let result = run(
                    &worker_cx,
                    device.as_ref(),
                    &worker_stop,
                    &shutdown,
                    interval,
                    report,
                );
                if result.is_ok() {
                    failure.armed = false;
                }
                result
            })
            .context("start protected source scrub worker")?;
        Ok(Self {
            cx: cx.clone(),
            stop,
            handle: Some(handle),
        })
    }

    pub(super) fn stop(&mut self) -> Result<()> {
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };
        self.stop.store(true, Ordering::Release);
        self.cx.set_cancel_requested(true);
        handle.thread().unpark();
        handle
            .join()
            .map_err(|_| anyhow::anyhow!("protected source scrub worker panicked"))?
    }
}

impl Drop for ScrubGuard {
    fn drop(&mut self) {
        if let Err(error) = self.stop() {
            eprintln!("protected source scrub shutdown failed: {error:#}");
        }
    }
}

struct UnmountOnFailure<'a> {
    shutdown: &'a AtomicBool,
    armed: bool,
}

impl Drop for UnmountOnFailure<'_> {
    fn drop(&mut self) {
        if self.armed {
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
    mut report: impl FnMut(&PassReport) -> Result<()>,
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
            report(&PassReport {
                event: "protected_source_scrub_pass",
                completed_passes,
                source_bytes_verified: pass.verified_bytes,
                consistency: "per_read_not_snapshot",
            })?;
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
