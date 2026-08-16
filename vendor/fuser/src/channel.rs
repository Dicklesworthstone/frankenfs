use std::{
    fs::File,
    io,
    os::{
        fd::{AsFd, BorrowedFd},
        unix::prelude::AsRawFd,
    },
    sync::Arc,
};

use libc::{c_int, c_void, size_t};

#[cfg(feature = "abi-7-40")]
use crate::passthrough::BackingId;
use crate::reply::ReplySender;

/// A raw communication channel to the FUSE kernel driver
#[derive(Clone, Debug)]
pub struct Channel(Arc<File>);

impl AsFd for Channel {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

/// Upper bound on `FFS_FUSE_RECEIVE_SPIN`, so a misconfigured knob cannot pin a
/// core for the life of the mount.
const MAX_RECEIVE_SPIN: u32 = 100_000;

impl Channel {
    /// Create a new communication channel to the kernel driver by mounting the
    /// given path. The kernel driver will delegate filesystem operations of
    /// the given path to the channel.
    pub(crate) fn new(device: Arc<File>) -> Self {
        Self(device)
    }

    /// Receives data up to the capacity of the given buffer (can block).
    /// Bounded spin before blocking, from `FFS_FUSE_RECEIVE_SPIN` (default 0 = off).
    ///
    /// Resolved once per call rather than cached because `receive` is not the hot
    /// instruction-count path — it is about to make a syscall either way — and a
    /// cached value would have to be threaded through `Session` construction,
    /// which is a much larger change to make while the build is frozen.
    fn spin_iterations() -> u32 {
        Self::spin_iterations_from_value(std::env::var("FFS_FUSE_RECEIVE_SPIN").ok().as_deref())
    }

    /// Pure half, so the parsing is testable without mutating process-global
    /// environment (racy under a parallel harness, `unsafe` from edition 2024).
    ///
    /// Defaults to 0 and fails CLOSED to 0 on anything unparseable: 0 means the
    /// blocking `read` happens immediately, which is byte-for-byte the behaviour
    /// every banked measurement was taken with.
    ///
    /// Clamped to `MAX_RECEIVE_SPIN`. The clamp is load-bearing rather than
    /// defensive: each iteration is a non-blocking `poll`, so an unbounded value
    /// would pin a core at 100% for the life of the mount, and on this shared
    /// measurement host that would corrupt every other pane's timings as well as
    /// our own.
    fn spin_iterations_from_value(raw: Option<&str>) -> u32 {
        raw.and_then(|r| r.trim().parse::<u32>().ok())
            .unwrap_or(0)
            .min(MAX_RECEIVE_SPIN)
    }

    /// Receive the next request, optionally spinning first.
    ///
    /// # Why this might matter
    ///
    /// `receive` blocks in `read(2)` on `/dev/fuse`, so every request costs a
    /// sleep and a scheduler wakeup. Warm stat's crossing measures 8.674 us
    /// against a kernel-ext4 stat's 2.284 us, and a syscall pair does not cost
    /// 8 us — that gap is dominated by sleep/wake, not by the transfer. In a
    /// SERIAL workload the daemon sleeps between requests it can be confident are
    /// coming, which is precisely the regime a short spin removes.
    ///
    /// # Why it is off by default
    ///
    /// Spinning trades CPU for latency. It is a loss whenever requests are sparse,
    /// and on a shared box an always-spinning daemon degrades every other tenant.
    /// This is an A/B handle for a latency-bound serial workload, not a default.
    pub fn receive(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let spins = Self::spin_iterations();
        if spins > 0 {
            let mut pfd = libc::pollfd {
                fd: self.0.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            for _ in 0..spins {
                // Zero timeout: ask whether a request is already queued, never
                // sleep here. If one is, fall through to the read below and skip
                // the block entirely.
                let ready = unsafe { libc::poll(&mut pfd, 1, 0) };
                if ready > 0 {
                    break;
                }
                if ready < 0 {
                    // Any poll error: abandon spinning and let the blocking read
                    // report the real condition. Spinning is an optimisation and
                    // must never be the thing that surfaces an error.
                    break;
                }
                std::hint::spin_loop();
            }
        }
        let rc = unsafe {
            libc::read(
                self.0.as_raw_fd(),
                buffer.as_ptr() as *mut c_void,
                buffer.len() as size_t,
            )
        };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc as usize)
        }
    }

    /// Returns a sender object for this channel. The sender object can be
    /// used to send to the channel. Multiple sender objects can be used
    /// and they can safely be sent to other threads.
    pub fn sender(&self) -> ChannelSender {
        // Since write/writev syscalls are threadsafe, we can simply create
        // a sender by using the same file and use it in other threads.
        ChannelSender(self.0.clone())
    }
}

#[derive(Clone, Debug)]
pub struct ChannelSender(Arc<File>);

impl ReplySender for ChannelSender {
    fn send(&self, bufs: &[io::IoSlice<'_>]) -> io::Result<()> {
        let rc = unsafe {
            libc::writev(
                self.0.as_raw_fd(),
                bufs.as_ptr() as *const libc::iovec,
                bufs.len() as c_int,
            )
        };
        if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            debug_assert_eq!(bufs.iter().map(|b| b.len()).sum::<usize>(), rc as usize);
            Ok(())
        }
    }

    #[cfg(feature = "abi-7-40")]
    fn open_backing(&self, fd: BorrowedFd<'_>) -> std::io::Result<BackingId> {
        BackingId::create(&self.0, fd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE NEGATIVE CASE: the default must be 0, and anything unrecognised must
    /// fail CLOSED to 0.
    ///
    /// 0 means the blocking `read` happens immediately, which is byte-for-byte
    /// the behaviour every banked mounted measurement was taken with. If this
    /// knob defaulted to spinning — or if junk fell through to spinning — the
    /// shipping daemon would burn a core per mount and every previously banked
    /// ratio would describe a configuration that no longer ships, with nothing
    /// announcing the change.
    #[test]
    fn receive_spin_defaults_to_zero_and_junk_fails_closed() {
        assert_eq!(
            Channel::spin_iterations_from_value(None),
            0,
            "unset MUST mean block immediately — the behaviour every banked row \
             was measured with"
        );
        for junk in ["", "  ", "yes", "on", "true", "-1", "1.5", "1e6", "0x10"] {
            assert_eq!(
                Channel::spin_iterations_from_value(Some(junk)),
                0,
                "{junk:?} must fail CLOSED to 0; a spin knob that engages on \
                 unrecognised input would silently pin a core"
            );
        }
    }

    /// The clamp is load-bearing, not defensive.
    ///
    /// Each iteration is a non-blocking `poll`, so an unbounded value pins a core
    /// at 100% for the life of the mount. On the shared measurement host that
    /// corrupts every other tenant's timings as well as our own — it would show
    /// up as `external_load_during_run ... CONTENDED` in somebody else's run,
    /// which is a very expensive way to discover a typo.
    #[test]
    fn receive_spin_is_clamped_so_a_typo_cannot_pin_a_core() {
        assert_eq!(
            Channel::spin_iterations_from_value(Some("4294967295")),
            MAX_RECEIVE_SPIN,
            "u32::MAX must clamp"
        );
        assert_eq!(
            Channel::spin_iterations_from_value(Some("999999999")),
            MAX_RECEIVE_SPIN
        );
        assert!(
            MAX_RECEIVE_SPIN < u32::MAX,
            "the ceiling must actually bound something"
        );
        // Sane values are honoured, or the knob is useless as an A/B handle.
        assert_eq!(Channel::spin_iterations_from_value(Some("64")), 64);
        assert_eq!(Channel::spin_iterations_from_value(Some(" 2048 ")), 2048);
    }
}
