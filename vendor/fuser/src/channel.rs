use std::{
    fs::File,
    io,
    os::{
        fd::{AsFd, BorrowedFd},
        unix::prelude::AsRawFd,
    },
    sync::Arc,
    sync::atomic::{AtomicU32, Ordering},
};

use libc::{c_int, c_void, size_t};

#[cfg(feature = "abi-7-40")]
use crate::passthrough::BackingId;
use crate::reply::ReplySender;

/// A raw communication channel to the FUSE kernel driver
#[derive(Debug)]
pub struct Channel {
    device: Arc<File>,
    /// Live spin budget for adaptive mode (bd-warm-stat-is-the-fuse-floor-4wxw9).
    /// Relaxed ordering is sufficient: this is a hint that self-corrects within a
    /// few requests, never a correctness invariant, and contending workers racing
    /// on it can only cost each other one mis-sized spin.
    spin_budget: AtomicU32,
}

/// Hand-written because the spin budget is per-clone state, not shared: each
/// worker adapts to the request rate IT observes. Sharing one atomic across
/// workers would let a busy worker keep a starved one spinning, which is the
/// exact CPU burn the adaptive budget exists to avoid.
impl Clone for Channel {
    fn clone(&self) -> Self {
        Self {
            device: self.device.clone(),
            spin_budget: AtomicU32::new(self.spin_budget.load(Ordering::Relaxed)),
        }
    }
}

impl AsFd for Channel {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.device.as_fd()
    }
}

/// Upper bound on `FFS_FUSE_RECEIVE_SPIN`, so a misconfigured knob cannot pin a
/// core for the life of the mount.
pub const MAX_RECEIVE_SPIN: u32 = 100_000;

impl Channel {
    /// Create a new communication channel to the kernel driver by mounting the
    /// given path. The kernel driver will delegate filesystem operations of
    /// the given path to the channel.
    pub(crate) fn new(device: Arc<File>) -> Self {
        Self {
            device,
            spin_budget: AtomicU32::new(0),
        }
    }

    /// Receives data up to the capacity of the given buffer (can block).
    /// Bounded spin before blocking, from `FFS_FUSE_RECEIVE_SPIN` (default 0 = off).
    ///
    /// Resolved once per call rather than cached because `receive` is not the hot
    /// instruction-count path — it is about to make a syscall either way — and a
    /// cached value would have to be threaded through `Session` construction,
    /// which is a much larger change to make while the build is frozen.
    /// Cached for the life of the process. `std::env::var` takes a global lock
    /// and allocates a `String`; doing that twice per request on the path this
    /// lever exists to shorten would spend part of the win paying for the knob
    /// that produces it. Both knobs are read once, at the first request.
    fn spin_iterations() -> u32 {
        static CACHED: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
        *CACHED.get_or_init(|| {
            Self::spin_iterations_from_value(std::env::var("FFS_FUSE_RECEIVE_SPIN").ok().as_deref())
        })
    }

    /// Whether the spin budget adapts to the observed request rate. Cached for
    /// the same reason as [`Self::spin_iterations`].
    fn spin_is_adaptive() -> bool {
        static CACHED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *CACHED.get_or_init(|| {
            Self::adaptive_from_value(
                std::env::var("FFS_FUSE_RECEIVE_SPIN_ADAPTIVE").ok().as_deref(),
            )
        })
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
    pub fn spin_iterations_from_value(raw: Option<&str>) -> u32 {
        raw.and_then(|r| r.trim().parse::<u32>().ok())
            .unwrap_or(0)
            .min(MAX_RECEIVE_SPIN)
    }

    /// Is adaptive spinning enabled? Opt-in for now: it changes when the daemon
    /// burns CPU, which is a behaviour change, and the fixed mode is what the
    /// certified >= 1.119968x measurement used.
    pub fn adaptive_from_value(raw: Option<&str>) -> bool {
        match raw {
            None => false,
            Some(v) => {
                let v = v.trim();
                v == "1" || v.eq_ignore_ascii_case("true") || v.eq_ignore_ascii_case("on")
            }
        }
    }

    /// Next spin budget, given the current one and whether the last spin PAID.
    ///
    /// The certified win (>= 1.119968x on warm stat) could not be defaulted on,
    /// because a fixed spin is a pure loss whenever requests are sparse and on a
    /// shared box it degrades every other tenant. That objection is about the
    /// FIXED budget, not about spinning: a daemon that stops spinning as soon as
    /// spinning stops paying has no such cost.
    ///
    /// A spin "paid" when `poll` found a request already queued, meaning the
    /// blocking read and its wakeup were avoided. Additive increase on a hit,
    /// halving on a miss: climbing slowly bounds how much CPU a
    /// briefly-busy period can claim, while halving abandons a dead regime in a
    /// handful of requests rather than a hundred.
    ///
    /// Pure and total so it can be tested without a FUSE device, which is the
    /// only way this logic gets tested at all.
    pub fn next_spin_budget(current: u32, paid: bool, max: u32) -> u32 {
        if max == 0 {
            return 0;
        }
        if paid {
            current.saturating_add(max / 8).max(1).min(max)
        } else {
            current / 2
        }
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
        let configured = Self::spin_iterations();
        // Adaptive mode: the configured value is a CEILING, not a fixed cost. The
        // budget starts there and follows whether spinning is actually paying, so
        // a sparse or concurrent regime drives it to zero on its own and the
        // daemon stops burning CPU without anyone having to set a flag.
        let adaptive = Self::spin_is_adaptive();
        let spins = if adaptive && configured > 0 {
            let b = self.spin_budget.load(Ordering::Relaxed);
            if b == 0 { configured / 8 } else { b }.max(1)
        } else {
            configured
        };
        let mut paid = false;
        if spins > 0 {
            let mut pfd = libc::pollfd {
                fd: self.device.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            for _ in 0..spins {
                // Zero timeout: ask whether a request is already queued, never
                // sleep here. If one is, fall through to the read below and skip
                // the block entirely.
                let ready = unsafe { libc::poll(&mut pfd, 1, 0) };
                if ready > 0 {
                    paid = true;
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
        if adaptive && configured > 0 {
            let b = self.spin_budget.load(Ordering::Relaxed);
            self.spin_budget
                .store(Self::next_spin_budget(b, paid, configured), Ordering::Relaxed);
        }
        let rc = unsafe {
            libc::read(
                self.device.as_raw_fd(),
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
        ChannelSender(self.device.clone())
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
mod adaptive_spin_tests {
    use super::Channel;

    /// bd-warm-stat-is-the-fuse-floor-4wxw9: the budget must climb while spinning
    /// pays and collapse when it stops, so a sparse or concurrent regime disables
    /// spinning without anyone setting a flag. That is the property that makes the
    /// certified >= 1.119968x warm-stat win safe to enable by default; a FIXED
    /// budget is a pure loss when requests are sparse, which is why it is not.
    #[test]
    fn budget_climbs_while_spinning_pays_and_collapses_when_it_stops() {
        let max = 2000;
        // A serial workload -- every spin finds a request already queued -- must
        // reach the ceiling and stay there rather than oscillating.
        let mut b = 0;
        for _ in 0..64 {
            b = Channel::next_spin_budget(b, true, max);
        }
        assert_eq!(b, max, "sustained hits must reach the ceiling");
        b = Channel::next_spin_budget(b, true, max);
        assert_eq!(b, max, "and must not exceed it");

        // A regime where spinning never pays must reach zero QUICKLY. Halving
        // gets there in ~11 requests from the ceiling; additive decay would take
        // hundreds and burn CPU the whole way.
        let mut steps = 0;
        while b > 0 {
            b = Channel::next_spin_budget(b, false, max);
            steps += 1;
            assert!(steps < 32, "decay must be geometric, not linear");
        }
        assert_eq!(b, 0, "a dead regime must switch spinning off entirely");
    }

    /// Once off, a single paying request must be able to switch it back on --
    /// otherwise a momentary lull permanently disables the lever.
    #[test]
    fn a_single_hit_revives_a_collapsed_budget() {
        let b = Channel::next_spin_budget(0, true, 2000);
        assert!(b >= 1, "a hit from zero must produce a usable budget, got {b}");
    }

    /// Degenerate ceilings must not produce a spinning daemon or panic.
    #[test]
    fn zero_ceiling_never_spins() {
        assert_eq!(Channel::next_spin_budget(0, true, 0), 0);
        assert_eq!(Channel::next_spin_budget(1000, true, 0), 0);
        // saturating arithmetic: a huge current budget must not overflow.
        assert_eq!(Channel::next_spin_budget(u32::MAX, true, 2000), 2000);
    }

    /// The adaptive knob is opt-in and typo-safe: only an explicit 1/true/on
    /// enables it, so a mistyped value cannot silently change when the daemon
    /// burns CPU.
    #[test]
    fn adaptive_knob_is_opt_in_and_typo_safe() {
        assert!(!Channel::adaptive_from_value(None));
        for off in ["0", "false", "off", "", "yes", "maybe", "ON!"] {
            assert!(!Channel::adaptive_from_value(Some(off)), "{off:?} must not enable");
        }
        for on in ["1", "true", "on", "TRUE", " 1 "] {
            assert!(Channel::adaptive_from_value(Some(on)), "{on:?} must enable");
        }
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
