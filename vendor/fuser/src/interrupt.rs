//! Cooperative cancellation for one FUSE connection.
//!
//! An interrupt targets the original request, not its own message ID. Tracking
//! lasts until the original reply is sent (including deferred replies), and a
//! cancellation notification never manufactures or replaces that reply.

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::{Arc, Mutex, Weak};

type Callback = Box<dyn FnOnce() + Send + 'static>;

#[derive(Default)]
struct State {
    interrupted: bool,
    complete: bool,
    callbacks: Vec<Callback>,
}

struct ActiveRequest {
    unique: u64,
    registry: Weak<InterruptRegistry>,
    state: Mutex<State>,
}

impl ActiveRequest {
    fn unregister(&self) {
        let Some(registry) = self.registry.upgrade() else {
            return;
        };
        let mut requests = registry
            .requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // A surviving token for a completed request must not remove a later
        // registration, even when a test or another transport reuses its ID.
        if requests
            .get(&self.unique)
            .is_some_and(|request| std::ptr::eq(request.as_ptr(), self))
        {
            requests.remove(&self.unique);
        }
    }
}

impl Drop for ActiveRequest {
    fn drop(&mut self) {
        self.unregister();
    }
}

/// An original request's cooperative cancellation notification.
///
/// A handler opts in with [`Self::on_interrupt`], or polls
/// [`Self::is_interrupted`]. The handler still owns its reply and must only
/// return `EINTR` when abandoning the operation is safe. Completed mutations
/// must retain their actual result. Callbacks must not block; they execute on
/// the thread receiving the interrupt, without any registry/state lock held.
#[derive(Clone)]
pub struct RequestInterrupt(Arc<ActiveRequest>);

impl fmt::Debug for RequestInterrupt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestInterrupt")
            .field("unique", &self.0.unique)
            .finish_non_exhaustive()
    }
}

impl RequestInterrupt {
    /// Original kernel request ID, scoped to this connection.
    #[must_use]
    pub fn unique(&self) -> u64 {
        self.0.unique
    }

    /// Whether an interrupt was received before this request completed.
    #[must_use]
    pub fn is_interrupted(&self) -> bool {
        self.0
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .interrupted
    }

    /// Register a nonblocking observer, invoked at most once.
    ///
    /// Registration racing an interrupt cannot miss it: a late observer runs
    /// immediately. Registration after the original reply completes is ignored.
    /// An observer already taken by the interrupt thread may finish after a
    /// concurrent reply; it must not change the reply or perform a rollback.
    pub fn on_interrupt(&self, callback: impl FnOnce() + Send + 'static) {
        let callback: Callback = Box::new(callback);
        let mut state = self
            .0
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.complete {
            drop(state);
            drop(callback);
        } else if state.interrupted {
            drop(state);
            notify(callback);
        } else {
            state.callbacks.push(callback);
        }
    }

    fn interrupt(&self) -> bool {
        let callbacks = {
            let mut state = self
                .0
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if state.complete {
                return false;
            }
            state.interrupted = true;
            std::mem::take(&mut state.callbacks)
        };
        for callback in callbacks {
            notify(callback);
        }
        true
    }

    pub(crate) fn complete(&self) {
        let callbacks = {
            let mut state = self
                .0
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            state.complete = true;
            std::mem::take(&mut state.callbacks)
        };
        self.0.unregister();
        // Dropping a captured context may itself acquire locks or release the
        // final token. Never drop observers while holding either internal lock.
        drop(callbacks);
    }
}

fn notify(callback: Callback) {
    // A faulty observer must not unwind the control receiver and strand other
    // requests. No protected state is borrowed while user code runs.
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(callback)).is_err() {
        log::error!("FUSE interrupt observer panicked");
    }
}

/// Shared only by workers belonging to the same mounted connection.
#[derive(Default)]
pub(crate) struct InterruptRegistry {
    requests: Mutex<HashMap<u64, Weak<ActiveRequest>>>,
}

impl fmt::Debug for InterruptRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InterruptRegistry").finish_non_exhaustive()
    }
}

impl InterruptRegistry {
    pub(crate) fn register(self: &Arc<Self>, unique: u64) -> Option<RequestInterrupt> {
        let mut requests = self
            .requests
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if requests
            .get(&unique)
            .is_some_and(|request| request.strong_count() != 0)
        {
            return None;
        }
        let request = Arc::new(ActiveRequest {
            unique,
            registry: Arc::downgrade(self),
            state: Mutex::new(State::default()),
        });
        requests.insert(unique, Arc::downgrade(&request));
        Some(RequestInterrupt(request))
    }

    pub(crate) fn interrupt(&self, unique: u64) -> bool {
        let request = {
            let requests = self
                .requests
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            requests.get(&unique).and_then(Weak::upgrade)
        };
        // Both callbacks and destruction of the last strong token can acquire
        // the registry again. The registry guard must be gone before either.
        request.is_some_and(|request| RequestInterrupt(request).interrupt())
    }
}

thread_local! {
    static CURRENT_READ: RefCell<Option<RequestInterrupt>> = const { RefCell::new(None) };
}

/// Read-only request currently executing on this dispatch thread, if any.
///
/// This scoped bridge lets an adapter's context factory inherit cancellation
/// without ambient process-global request IDs. The dispatcher explicitly masks
/// it for mutations, handle lifecycle operations and arbitrary ioctls. Code
/// moving work to another thread must capture the token/context explicitly.
/// Outside request dispatch this returns `None`.
#[must_use]
pub fn current_read_request_interrupt() -> Option<RequestInterrupt> {
    CURRENT_READ.with(|current| current.borrow().clone())
}

#[derive(Debug)]
pub(crate) struct DispatchInterruptScope {
    previous: Option<RequestInterrupt>,
    // A scope must restore the same thread-local slot on which it was entered.
    _not_send: PhantomData<Rc<()>>,
}

impl DispatchInterruptScope {
    pub(crate) fn enter(request: Option<RequestInterrupt>) -> Self {
        let previous = CURRENT_READ.with(|current| current.replace(request));
        Self {
            previous,
            _not_send: PhantomData,
        }
    }
}

impl Drop for DispatchInterruptScope {
    fn drop(&mut self) {
        let previous = self.previous.take();
        CURRENT_READ.with(|current| {
            current.replace(previous);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn notification_is_latched_and_each_observer_runs_once() {
        let registry = Arc::new(InterruptRegistry::default());
        let request = registry.register(7).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let before = Arc::clone(&calls);
        request.on_interrupt(move || {
            before.fetch_add(1, Ordering::SeqCst);
        });
        assert!(registry.interrupt(7));
        assert!(request.is_interrupted());
        assert!(registry.interrupt(7));
        let after = Arc::clone(&calls);
        request.on_interrupt(move || {
            after.fetch_add(1, Ordering::SeqCst);
        });
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        request.complete();
        let completed = Arc::clone(&calls);
        request.on_interrupt(move || {
            completed.fetch_add(1, Ordering::SeqCst);
        });
        assert!(!registry.interrupt(7));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn connections_and_original_request_ids_are_isolated() {
        let first = Arc::new(InterruptRegistry::default());
        let second = Arc::new(InterruptRegistry::default());
        let a = first.register(7).unwrap();
        let b = first.register(8).unwrap();
        let c = second.register(7).unwrap();
        assert!(first.interrupt(7));
        assert!(a.is_interrupted());
        assert!(!b.is_interrupted());
        assert!(!c.is_interrupted());
        assert!(!first.interrupt(99));
    }

    #[test]
    fn duplicate_registration_does_not_replace_an_outstanding_request() {
        let registry = Arc::new(InterruptRegistry::default());
        let original = registry.register(7).unwrap();
        assert!(registry.register(7).is_none());
        assert!(registry.interrupt(7));
        assert!(original.is_interrupted());
    }

    #[test]
    fn old_tokens_cannot_remove_a_new_registration() {
        let registry = Arc::new(InterruptRegistry::default());
        let old = registry.register(7).unwrap();
        old.complete();
        let current = registry.register(7).unwrap();
        old.complete();
        drop(old);
        assert!(registry.interrupt(7));
        assert!(current.is_interrupted());
    }

    #[test]
    fn last_token_drop_releases_tracking_but_clones_keep_it_alive() {
        let registry = Arc::new(InterruptRegistry::default());
        let original = registry.register(7).unwrap();
        let deferred = original.clone();
        drop(original);
        assert!(registry.interrupt(7));
        drop(deferred);
        assert!(registry.requests.lock().unwrap().is_empty());
        assert!(!registry.interrupt(7));
    }

    #[test]
    fn callbacks_run_outside_both_locks_and_can_complete_the_request() {
        let registry = Arc::new(InterruptRegistry::default());
        let request = registry.register(7).unwrap();
        let callback_registry = Arc::clone(&registry);
        let callback_request = request.clone();
        request.on_interrupt(move || {
            assert!(callback_request.is_interrupted());
            assert!(callback_registry.register(8).is_some());
            callback_request.complete();
        });
        assert!(registry.interrupt(7));
        assert!(!registry.interrupt(7));
    }

    #[test]
    fn callback_panic_does_not_strand_other_observers() {
        let registry = Arc::new(InterruptRegistry::default());
        let request = registry.register(7).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        request.on_interrupt(|| panic!("injected observer panic"));
        let observer = Arc::clone(&calls);
        request.on_interrupt(move || {
            observer.fetch_add(1, Ordering::SeqCst);
        });
        assert!(registry.interrupt(7));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        request.complete();
        assert!(!registry.interrupt(7));
    }

    #[test]
    fn registration_racing_interrupt_never_loses_notification() {
        for unique in 0..128 {
            let registry = Arc::new(InterruptRegistry::default());
            let request = registry.register(unique).unwrap();
            let calls = Arc::new(AtomicUsize::new(0));
            let barrier = Arc::new(Barrier::new(2));
            std::thread::scope(|scope| {
                let worker_barrier = Arc::clone(&barrier);
                let worker_calls = Arc::clone(&calls);
                let worker_request = request.clone();
                scope.spawn(move || {
                    worker_barrier.wait();
                    worker_request.on_interrupt(move || {
                        worker_calls.fetch_add(1, Ordering::SeqCst);
                    });
                });
                barrier.wait();
                assert!(registry.interrupt(unique));
            });
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn scoped_context_masks_mutations_and_restores_nested_reads() {
        let registry = Arc::new(InterruptRegistry::default());
        let first = registry.register(1).unwrap();
        let second = registry.register(2).unwrap();
        assert!(current_read_request_interrupt().is_none());
        let outer = DispatchInterruptScope::enter(Some(first));
        assert_eq!(current_read_request_interrupt().unwrap().unique(), 1);
        {
            let _mutation = DispatchInterruptScope::enter(None);
            assert!(current_read_request_interrupt().is_none());
            {
                let _inner = DispatchInterruptScope::enter(Some(second));
                assert_eq!(current_read_request_interrupt().unwrap().unique(), 2);
            }
            assert!(current_read_request_interrupt().is_none());
        }
        assert_eq!(current_read_request_interrupt().unwrap().unique(), 1);
        drop(outer);
        assert!(current_read_request_interrupt().is_none());
    }

    #[test]
    fn scope_is_restored_when_a_handler_panics() {
        let registry = Arc::new(InterruptRegistry::default());
        let request = registry.register(1).unwrap();
        let result = std::panic::catch_unwind(|| {
            let _scope = DispatchInterruptScope::enter(Some(request));
            panic!("injected handler panic");
        });
        assert!(result.is_err());
        assert!(current_read_request_interrupt().is_none());
        assert!(!registry.interrupt(1));
    }
}
