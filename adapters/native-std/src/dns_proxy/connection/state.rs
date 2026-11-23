//! Reusable readiness notifications and independent final registration disposal.
use super::{Loans, sdk};
use crate::dns_proxy::completion::{self, Completion, Outcome, Publisher};
use block2::RcBlock;
use std::{
    io,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

struct Snapshot {
    value: u32,
    error: Option<sdk::Failure>,
    failed: bool,
    waker: Option<Waker>,
}
pub(super) struct State(Mutex<Snapshot>);
pub(super) struct Watches {
    pub state: Arc<State>,
    cancelled: Completion<()>,
    disposed: Completion<()>,
    cancellation: Option<bool>,
    registration_released: bool,
}
struct Registration {
    cancelled: Mutex<Option<Publisher<()>>>,
    state: Arc<State>,
    loans: Loans,
    _disposed: Publisher<()>,
    // The provider debt must outlive native arguments and their disposal gate.
    _provider: Option<super::ProviderLease>,
}
impl State {
    fn new() -> Self {
        Self(Mutex::new(Snapshot {
            value: 0,
            error: None,
            failed: false,
            waker: None,
        }))
    }
    pub(super) fn ready(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .value
            == 3
    }
    pub(super) fn error(&self) -> Option<io::Error> {
        let error = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .error;
        error.map(sdk::Failure::into_error)
    }
    pub(super) fn ended(&self) -> bool {
        matches!(
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .value,
            4 | 5
        )
    }
    pub(super) fn failed(&self) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .failed
    }
    fn publish(&self, value: u32, error: Option<sdk::Failure>) {
        let wake = {
            let mut state = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.value = value;
            state.error = error;
            state.failed |= value == 4;
            state.waker.take()
        };
        // A custom waker must neither run under the state lock nor prevent
        // final cancellation publication and native registration removal.
        if let Some(waker) = wake {
            contain(|| waker.wake());
        }
    }
    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let candidate = cx.waker().clone();
        let (value, error, previous) = {
            let mut state = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            // Ready is reusable: retain the current observer so a later
            // Ready-to-Waiting transition can start its bounded recovery.
            let previous = if matches!(state.value, 4 | 5) {
                state.waker.take()
            } else {
                state.waker.replace(candidate)
            };
            (state.value, state.error, previous)
        };
        drop(previous);
        match value {
            3 => Poll::Ready(Ok(())),
            4 | 5 => Poll::Ready(Err(error.map_or_else(
                || io::ErrorKind::NotConnected.into(),
                sdk::Failure::into_error,
            ))),
            _ => Poll::Pending,
        }
    }
}
pub(super) fn register(loans: Loans) -> Watches {
    let (cancelled, cancel_publisher) = completion::pair();
    let (disposed, disposed_publisher) = completion::pair();
    let state = Arc::new(State::new());
    let registration = Registration {
        cancelled: Mutex::new(Some(cancel_publisher)),
        state: Arc::clone(&state),
        loans: loans.clone(),
        _disposed: disposed_publisher,
        _provider: loans._provider.clone(),
    };
    let block = RcBlock::new(crate::dns_proxy::callback::thread_safe(
        move |value: u32, error| {
            contain(|| {
                registration.state.publish(value, sdk::failure(error));
                if value == 5 {
                    let cancelled = registration
                        .cancelled
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .take();
                    if let Some(cancelled) = cancelled {
                        cancelled.publish(());
                    }
                    sdk::clear_state(&registration.loans.connection);
                }
            });
        },
    ));
    sdk::state(&loans.connection, &block);
    Watches {
        state,
        cancelled,
        disposed,
        cancellation: None,
        registration_released: false,
    }
}
impl Watches {
    pub(super) fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.state.poll_ready(cx)
    }
    pub(super) fn poll_retirement(&mut self, cx: &mut Context<'_>) -> Poll<bool> {
        if self.cancellation.is_none() {
            match self.cancelled.poll(cx) {
                Poll::Ready(Some(Outcome::Published(()))) => self.cancellation = Some(true),
                Poll::Ready(Some(Outcome::CallbackDropped) | None) => {
                    self.cancellation = Some(false)
                }
                Poll::Pending => {}
            }
        }
        if !self.registration_released && self.disposed.poll(cx).is_ready() {
            self.registration_released = true;
        }
        match self.cancellation {
            Some(cancelled) if self.registration_released => Poll::Ready(cancelled),
            _ => Poll::Pending,
        }
    }
}
fn contain(body: impl FnOnce()) {
    if let Err(payload) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        completion::dispose_panic(payload);
    }
}

#[cfg(test)]
mod tests {
    use super::State;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Wake, Waker},
    };
    struct Counter(AtomicUsize);
    impl Wake for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    #[test]
    fn readiness_recovery_registers_each_wait_without_losing_notifications() {
        let state = State::new();
        let count = Arc::new(Counter(AtomicUsize::new(0)));
        let waker = Waker::from(Arc::clone(&count));
        let mut cx = Context::from_waker(&waker);
        assert!(state.poll_ready(&mut cx).is_pending());
        state.publish(3, None);
        assert_eq!(count.0.load(Ordering::SeqCst), 1);
        assert!(matches!(
            state.poll_ready(&mut cx),
            std::task::Poll::Ready(Ok(()))
        ));
        state.publish(1, None);
        assert_eq!(count.0.load(Ordering::SeqCst), 2);
        assert!(state.poll_ready(&mut cx).is_pending());
        state.publish(3, None);
        assert_eq!(count.0.load(Ordering::SeqCst), 3);
        assert!(matches!(
            state.poll_ready(&mut cx),
            std::task::Poll::Ready(Ok(()))
        ));
        assert!(!state.failed());
        state.publish(4, None);
        assert_eq!(count.0.load(Ordering::SeqCst), 4);
        assert!(matches!(
            state.poll_ready(&mut cx),
            std::task::Poll::Ready(Err(_))
        ));
        state.publish(5, None);
        assert_eq!(count.0.load(Ordering::SeqCst), 4);
        assert!(state.failed());
        assert!(matches!(
            state.poll_ready(&mut cx),
            std::task::Poll::Ready(Err(_))
        ));
    }
    #[test]
    fn panicking_wake_does_not_escape_state_publication() {
        struct Bad;
        impl Wake for Bad {
            fn wake(self: Arc<Self>) {
                std::panic::resume_unwind(Box::new("test wake"));
            }
        }
        let state = State::new();
        let waker = Waker::from(Arc::new(Bad));
        let mut cx = Context::from_waker(&waker);
        assert!(state.poll_ready(&mut cx).is_pending());
        state.publish(5, None);
        assert!(state.ended());
    }
}
