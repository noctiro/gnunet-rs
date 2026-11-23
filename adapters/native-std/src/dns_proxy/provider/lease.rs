//! One original provider session's bounded resource groups and final release.
use std::{
    fmt, io,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};

pub(super) struct Counter {
    state: Mutex<State>,
}
struct State {
    accepting: bool,
    live: usize,
    limit: usize,
    waker: Option<Waker>,
}
impl Counter {
    pub(super) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State {
                accepting: false,
                live: 0,
                limit,
                waker: None,
            }),
        })
    }
    pub(super) fn open(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .accepting = true;
    }
    pub(super) fn close(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .accepting = false;
    }
    pub(super) fn poll_drained(&self, cx: &mut Context<'_>) -> Poll<()> {
        let candidate = cx.waker().clone();
        let (ready, previous) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.live == 0 {
                (true, state.waker.take())
            } else {
                (false, state.waker.replace(candidate))
            }
        };
        drop(previous);
        if ready {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

/// Original startup-session authority to create bounded native resource loans.
/// Closing admission prevents new loans; existing ones remain independently held.
#[derive(Clone)]
pub struct Session {
    pub(super) counter: Arc<Counter>,
}
impl Session {
    /// Reserve one flow or connection group before its native operation starts.
    /// Cloning the returned keeper retains that same group for callback loans.
    /// # Errors
    /// Refuses stopping sessions and exhausted native resource capacity.
    pub fn lease(&self) -> io::Result<ProviderLease> {
        {
            let mut state = self
                .counter
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !state.accepting {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "DNS provider session is stopping",
                ));
            }
            if state.live >= state.limit {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "DNS provider resource bound reached",
                ));
            }
            state.live += 1;
        }
        Ok(ProviderLease {
            record: Arc::new(Record {
                counter: Arc::clone(&self.counter),
            }),
        })
    }
}
impl fmt::Debug for Session {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProviderSession")
    }
}

/// Keeper for one original native resource, shared only with its callback guards.
/// Its last clone releases the original session's retirement debt.
#[derive(Clone)]
pub struct ProviderLease {
    record: Arc<Record>,
}
impl fmt::Debug for ProviderLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderLease")
            .field("holders", &Arc::strong_count(&self.record))
            .finish()
    }
}
struct Record {
    counter: Arc<Counter>,
}
impl Drop for Record {
    fn drop(&mut self) {
        let wake = {
            let mut state = self
                .counter
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.live -= 1;
            if state.live == 0 {
                state.waker.take()
            } else {
                None
            }
        };
        if let Some(waker) = wake {
            super::native::contain(|| waker.wake());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Counter, Session};
    use crate::dns_proxy::{callback::Callback, lifetime};
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll, Wake, Waker},
    };

    struct DisposalObserver {
        counter: Arc<Counter>,
        awakened: AtomicBool,
        provider_still_held: AtomicBool,
    }
    impl Wake for DisposalObserver {
        fn wake(self: Arc<Self>) {
            let mut cx = Context::from_waker(Waker::noop());
            self.provider_still_held.store(
                self.counter.poll_drained(&mut cx).is_pending(),
                Ordering::Relaxed,
            );
            self.awakened.store(true, Ordering::Release);
        }
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "The production callback's field-drop ordering must keep provider retirement behind disposal publication"
    )]
    fn callback_disposal_keeps_provider_alive_until_final_keeper_drop() -> std::io::Result<()> {
        let session = Session {
            counter: Counter::new(1),
        };
        session.counter.open();
        let keeper = session.lease()?;
        let (mut pending, publish, disposed) = lifetime::reserve::<usize>();
        let callback = Callback::new(publish, (), disposed, None, ()).keep_provider(Some(keeper));
        callback.invoke(|| Ok(42));
        session.counter.close();

        let observer = Arc::new(DisposalObserver {
            counter: Arc::clone(&session.counter),
            awakened: AtomicBool::new(false),
            provider_still_held: AtomicBool::new(false),
        });
        let waker = Waker::from(Arc::clone(&observer));
        let mut cx = Context::from_waker(&waker);
        assert!(pending.poll(&mut cx).is_pending());
        drop(callback);

        assert!(observer.awakened.load(Ordering::Acquire));
        assert!(observer.provider_still_held.load(Ordering::Relaxed));
        let mut cx = Context::from_waker(Waker::noop());
        assert!(session.counter.poll_drained(&mut cx).is_ready());
        assert!(matches!(pending.poll(&mut cx), Poll::Ready(Some(Ok(42)))));
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Lifecycle regression asserts independent callback keepers and uses fallible reservation"
    )]
    fn closed_session_waits_for_every_resource_keeper() -> std::io::Result<()> {
        let session = Session {
            counter: Counter::new(1),
        };
        session.counter.open();
        let lease = session.lease()?;
        let callback = lease.clone();
        assert!(session.lease().is_err());
        session.counter.close();
        assert!(session.lease().is_err());
        let mut cx = Context::from_waker(Waker::noop());
        drop(lease);
        assert!(session.counter.poll_drained(&mut cx).is_pending());
        drop(callback);
        assert!(session.counter.poll_drained(&mut cx).is_ready());
        Ok(())
    }
}
