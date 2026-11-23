//! One reserved completion result with independently owned callback retirement.
use std::{
    mem,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

/// The callback either published its result or released its last original owner.
pub(crate) enum Outcome<T> {
    /// The actual callback supplied this owned result.
    Published(T),
    /// The callback owner disappeared without publishing a result.
    /// This establishes no operation success or remote delivery.
    CallbackDropped,
}

enum Status<T> {
    Pending,
    Ready(Outcome<T>),
    Taken,
}
struct State<T> {
    status: Status<T>,
    waker: Option<Waker>,
}

/// Unique poll owner; dropping it does not release the callback's slot reference.
pub(crate) struct Completion<T> {
    state: Arc<Mutex<State<T>>>,
}
/// Unique callback publication authority, retained by the native callback block.
/// Its result must already satisfy the native operation's data/allocation bounds.
pub(crate) struct Publisher<T> {
    state: Option<Arc<Mutex<State<T>>>>,
}

/// Reserve one fixed result slot before submitting the original native operation.
/// Publication moves an already owned result into this allocation; it allocates
/// no queue, node or replacement operation. Native buffer loans stay owned by
/// the callback context until its actual retirement, independently of this slot.
pub(crate) fn pair<T>() -> (Completion<T>, Publisher<T>) {
    let state = Arc::new(Mutex::new(State {
        status: Status::Pending,
        waker: None,
    }));
    (
        Completion {
            state: Arc::clone(&state),
        },
        Publisher { state: Some(state) },
    )
}

impl<T> Completion<T> {
    /// Return the original outcome exactly once, then `Ready(None)`.
    /// Checking the result and installing the waker share the publication lock;
    /// publication before or during registration therefore cannot lose a wake.
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Option<Outcome<T>>> {
        // Raw waker implementations may execute code when cloned or dropped.
        // Keep both operations outside the state lock to permit reentrancy.
        let candidate = cx.waker().clone();
        let (result, previous) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match mem::replace(&mut state.status, Status::Taken) {
                Status::Pending => {
                    state.status = Status::Pending;
                    (Poll::Pending, state.waker.replace(candidate))
                }
                Status::Ready(result) => (Poll::Ready(Some(result)), state.waker.take()),
                Status::Taken => (Poll::Ready(None), state.waker.take()),
            }
        };
        drop(previous);
        result
    }
}
impl<T> Drop for Completion<T> {
    fn drop(&mut self) {
        let (result, waker) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            (
                mem::replace(&mut state.status, Status::Taken),
                state.waker.take(),
            )
        };
        // No user destructor executes while the callback needs this lock.
        drop(waker);
        drop(result);
    }
}
impl<T> Publisher<T> {
    /// Publish the one actual result, consuming the original callback authority.
    /// Publication remains valid after admission closes or the poll owner drops.
    /// The SDK callback boundary must also contain panics from user result drops.
    pub(crate) fn publish(mut self, result: T) {
        if let Some(state) = self.state.take() {
            publish(&state, Outcome::Published(result));
        }
    }
}
impl<T> Drop for Publisher<T> {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            publish(&state, Outcome::CallbackDropped);
        }
    }
}
fn publish<T>(state: &Mutex<State<T>>, result: Outcome<T>) {
    let wake = {
        let mut state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if matches!(state.status, Status::Pending) {
            state.status = Status::Ready(result);
            state.waker.take()
        } else {
            // The only other reachable state is a dropped receiver. Release its
            // result after unlocking, never while holding the callback lock.
            drop(state);
            drop(result);
            None
        }
    };
    if let Some(waker) = wake {
        wake_callback(waker);
    }
}
fn wake_callback(waker: Waker) {
    if let Err(payload) = catch_unwind(AssertUnwindSafe(|| waker.wake())) {
        dispose_panic(payload);
    }
}
pub(super) fn dispose_panic(payload: Box<dyn std::any::Any + Send>) {
    // Release the original payload; leaking one on every faulty wake would
    // create unbounded history. A second panic cannot cross an SDK boundary.
    if let Err(_second) = catch_unwind(AssertUnwindSafe(|| drop(payload))) {
        std::process::abort();
    }
}

#[cfg(test)]
mod tests {
    use super::{Completion, Outcome, pair};
    use std::{
        sync::{
            Arc, Barrier,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
        thread,
    };

    #[derive(Default)]
    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn poll<T>(slot: &mut Completion<T>, waker: &Waker) -> Poll<Option<Outcome<T>>> {
        slot.poll(&mut Context::from_waker(waker))
    }

    #[test]
    fn result_before_registration_is_owned_and_consumed_once() {
        let (mut slot, callback) = pair();
        callback.publish(vec![1, 2, 3]);
        let waker = Waker::noop();
        assert!(
            matches!(poll(&mut slot, waker), Poll::Ready(Some(Outcome::Published(data))) if data == [1, 2, 3])
        );
        assert!(matches!(poll(&mut slot, waker), Poll::Ready(None)));
    }

    #[test]
    fn current_waiter_is_notified_and_callback_drop_is_distinct() {
        let (mut slot, callback) = pair::<()>();
        let first = Arc::new(Counter::default());
        let latest = Arc::new(Counter::default());
        assert!(poll(&mut slot, &Waker::from(Arc::clone(&first))).is_pending());
        assert!(poll(&mut slot, &Waker::from(Arc::clone(&latest))).is_pending());
        drop(callback);
        assert_eq!(first.0.load(Ordering::SeqCst), 0);
        assert_eq!(latest.0.load(Ordering::SeqCst), 1);
        assert!(matches!(
            poll(&mut slot, Waker::noop()),
            Poll::Ready(Some(Outcome::CallbackDropped))
        ));
        assert!(matches!(poll(&mut slot, Waker::noop()), Poll::Ready(None)));
    }

    #[test]
    fn registration_and_publication_on_real_threads_do_not_lose_wakes() {
        for expected in 0..128 {
            let (mut slot, callback) = pair();
            let wake = Arc::new(Counter::default());
            let waker = Waker::from(Arc::clone(&wake));
            let barrier = Arc::new(Barrier::new(2));
            let callback_barrier = Arc::clone(&barrier);
            let worker = thread::spawn(move || {
                callback_barrier.wait();
                callback.publish(expected);
            });
            barrier.wait();
            let first = poll(&mut slot, &waker);
            assert!(worker.join().is_ok());
            match first {
                Poll::Pending => {
                    assert_eq!(wake.0.load(Ordering::SeqCst), 1);
                    assert!(
                        matches!(poll(&mut slot, &waker), Poll::Ready(Some(Outcome::Published(value))) if value == expected)
                    );
                }
                Poll::Ready(outcome) => {
                    assert!(
                        matches!(outcome, Some(Outcome::Published(value)) if value == expected)
                    );
                }
            }
            assert!(matches!(poll(&mut slot, &waker), Poll::Ready(None)));
        }
    }

    struct DropCount(Arc<AtomicUsize>);
    impl Drop for DropCount {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    #[test]
    fn dropping_poll_owner_retains_the_callback_slot_until_native_owner_releases_it() {
        let (slot, callback) = pair::<DropCount>();
        let weak = Arc::downgrade(&slot.state);
        drop(slot);
        assert!(weak.upgrade().is_some());
        let drops = Arc::new(AtomicUsize::new(0));
        callback.publish(DropCount(Arc::clone(&drops)));
        assert!(weak.upgrade().is_none());
        assert_eq!(drops.load(Ordering::SeqCst), 1);

        let (slot, callback) = pair::<()>();
        let weak = Arc::downgrade(&slot.state);
        drop(slot);
        assert!(weak.upgrade().is_some());
        drop(callback);
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn poisoned_state_and_panicking_waker_do_not_escape_callback_retirement() {
        let (mut slot, callback) = pair::<()>();
        let state = Arc::clone(&slot.state);
        let poison = thread::spawn(move || {
            let _guard = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::panic::resume_unwind(Box::new("Deliberately poisoned test lock"));
        });
        assert!(poison.join().is_err());
        struct PanickingWake(Arc<AtomicUsize>);
        impl Wake for PanickingWake {
            fn wake(self: Arc<Self>) {
                std::panic::resume_unwind(Box::new(DropCount(Arc::clone(&self.0))));
            }
        }
        let panic_drops = Arc::new(AtomicUsize::new(0));
        assert!(
            poll(
                &mut slot,
                &Waker::from(Arc::new(PanickingWake(Arc::clone(&panic_drops))))
            )
            .is_pending()
        );
        drop(callback);
        assert_eq!(panic_drops.load(Ordering::SeqCst), 1);
        assert!(matches!(
            poll(&mut slot, Waker::noop()),
            Poll::Ready(Some(Outcome::CallbackDropped))
        ));
        assert!(matches!(poll(&mut slot, Waker::noop()), Poll::Ready(None)));
    }
}
