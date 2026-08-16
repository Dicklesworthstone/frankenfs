//! Thread CPU-affinity primitive for the FUSE session loop.
//!
//! This lives here rather than in `ffs-fuse` because that crate is
//! `#![forbid(unsafe_code)]` — a `forbid` cannot be locally overridden, so the
//! `sched_getaffinity`/`sched_setaffinity` calls have no legal home there.

/// Restrict the CALLING thread to a single CPU, chosen as the lowest-numbered
/// CPU already in its affinity mask.
///
/// Returns `Some(cpu)` if the thread was narrowed, `None` if it was left alone
/// (already single-CPU, mask unreadable, or the set failed). Best-effort by
/// design: a mount must never fail because a determinism aid did.
#[cfg(target_os = "linux")]
pub fn pin_current_thread_to_one_cpu() -> Option<usize> {
    // SAFETY: `sched_getaffinity`/`sched_setaffinity` on the calling thread
    // (pid 0), with a correctly sized `cpu_set_t` allocated here and read or
    // written only through libc's own accessors.
    unsafe {
        let mut current: libc::cpu_set_t = std::mem::zeroed();
        let size = std::mem::size_of::<libc::cpu_set_t>();
        if libc::sched_getaffinity(0, size, std::ptr::addr_of_mut!(current)) != 0 {
            return None;
        }
        let width = 8 * size;
        let allowed: Vec<usize> = (0..width).filter(|cpu| libc::CPU_ISSET(*cpu, &current)).collect();
        // Already single-CPU, or nothing readable: leave it alone. Pinning a
        // one-CPU set is a no-op, and pinning an empty one would be a bug.
        if allowed.len() <= 1 {
            return None;
        }
        let chosen = allowed[0];
        let mut only: libc::cpu_set_t = std::mem::zeroed();
        libc::CPU_ZERO(&mut only);
        libc::CPU_SET(chosen, &mut only);
        if libc::sched_setaffinity(0, size, std::ptr::addr_of!(only)) == 0 {
            Some(chosen)
        } else {
            None
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub fn pin_current_thread_to_one_cpu() -> Option<usize> {
    None
}

#[cfg(test)]
mod tests {
    use super::pin_current_thread_to_one_cpu;

    /// The contract that matters to callers: it never panics, and whatever it
    /// reports it must have actually done. Running it twice must be idempotent
    /// -- the second call sees a one-CPU mask and declines.
    #[test]
    fn pinning_is_best_effort_and_idempotent() {
        std::thread::spawn(|| {
            let first = pin_current_thread_to_one_cpu();
            let second = pin_current_thread_to_one_cpu();
            assert_eq!(second, None, "a thread already on one CPU must not be re-pinned");
            if let Some(cpu) = first {
                assert!(cpu < 8 * std::mem::size_of::<libc::cpu_set_t>());
            }
        })
        .join()
        .expect("pinning must never panic");
    }
}
