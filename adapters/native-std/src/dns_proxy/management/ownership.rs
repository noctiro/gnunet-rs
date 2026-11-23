//! Unique process ownership extending through original native callback disposal.
use super::super::callback::Callback;
use std::{
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

static OWNED: AtomicBool = AtomicBool::new(false);
pub(super) struct Exclusive;
impl Exclusive {
    pub(super) fn acquire() -> io::Result<Arc<Self>> {
        OWNED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "DNS proxy manager or its original callback is still owned",
                )
            })?;
        Ok(Arc::new(Self))
    }
}
impl Drop for Exclusive {
    fn drop(&mut self) {
        OWNED.store(false, Ordering::Release);
    }
}

pub(super) struct OperationGuard<T, D> {
    pub(super) context: Callback<T, D, ()>,
    // Last: reentrant disposal wakes must not reacquire the singleton while
    // original SDK references and their callback context are still dropping.
    pub(super) _exclusive: Arc<Exclusive>,
}
impl<T, D> OperationGuard<T, D> {
    pub(super) fn invoke(&self, result: impl FnOnce() -> io::Result<T>) {
        self.context.invoke(result);
    }
    pub(super) fn data(&self) -> &D {
        self.context.data()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_proxy::lifetime;
    use std::{
        sync::atomic::AtomicBool,
        task::{Context, Poll, Wake, Waker},
    };

    struct DisposalWake(AtomicBool);
    impl Wake for DisposalWake {
        fn wake(self: Arc<Self>) {
            self.wake_by_ref();
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(
                Exclusive::acquire().is_err_and(|error| error.kind() == io::ErrorKind::WouldBlock),
                Ordering::Release,
            );
        }
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Regression assertions report invariant failures; Result propagates fallible test setup without unwrap"
    )]
    fn original_callback_disposal_keeps_singleton_reserved() -> io::Result<()> {
        let exclusive = Exclusive::acquire()?;
        let (mut pending, publish, disposed) = lifetime::reserve::<()>();
        let guard = OperationGuard {
            context: Callback::new(publish, (), disposed, None, ()),
            _exclusive: exclusive.clone(),
        };
        drop(exclusive);
        guard.invoke(|| Ok(()));
        let observed = Arc::new(DisposalWake(AtomicBool::new(false)));
        let waker = Waker::from(observed.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(
            pending.poll(&mut cx).is_pending(),
            "completed callback still owns native loans"
        );
        drop(guard);
        assert!(
            observed.0.load(Ordering::Acquire),
            "disposal wake must not release exclusive ownership early"
        );
        assert!(matches!(pending.poll(&mut cx), Poll::Ready(Some(Ok(())))));
        assert!(
            Exclusive::acquire().is_ok(),
            "new owner becomes available after original context disposal"
        );
        Ok(())
    }
}
