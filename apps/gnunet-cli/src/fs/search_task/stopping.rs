//! Cooperative stop observation without dropping the original durable run.
use std::{
    cell::Cell,
    future::{Future, poll_fn},
    task::Context,
};

pub(super) async fn drive<F: Future>(
    stopped: &Cell<bool>,
    mut observe: impl FnMut(&mut Context<'_>) -> bool,
    original: F,
) -> F::Output {
    let mut original = std::pin::pin!(original);
    poll_fn(|cx| {
        if !stopped.get() && observe(cx) {
            stopped.set(true);
        }
        // The task's own checkpoint persists pause intent and retires its
        // original work. A stop never selects away from that original future.
        original.as_mut().poll(cx)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{pin::Pin, task::Poll};

    struct Original<'a> {
        stopped: &'a Cell<bool>,
        polls: &'a Cell<usize>,
        disposed: &'a Cell<usize>,
    }

    impl Future for Original<'_> {
        type Output = &'static str;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let polls = self.polls.get() + 1;
            self.polls.set(polls);
            if self.stopped.get() && polls == 3 {
                Poll::Ready("settled original pause")
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    impl Drop for Original<'_> {
        fn drop(&mut self) {
            self.disposed.set(self.disposed.get() + 1);
        }
    }

    #[test]
    fn stop_keeps_the_same_original_future_until_its_settled_result() {
        let stopped = Cell::new(false);
        let polls = Cell::new(0);
        let disposed = Cell::new(0);
        let observations = Cell::new(0);
        let original = Original {
            stopped: &stopped,
            polls: &polls,
            disposed: &disposed,
        };
        let mut running = std::pin::pin!(drive(
            &stopped,
            |_| {
                observations.set(observations.get() + 1);
                observations.get() == 2
            },
            original,
        ));
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(running.as_mut().poll(&mut cx).is_pending());
        assert!(!stopped.get());
        assert_eq!(disposed.get(), 0);
        assert!(running.as_mut().poll(&mut cx).is_pending());
        assert!(stopped.get());
        assert_eq!(disposed.get(), 0);
        assert_eq!(
            running.as_mut().poll(&mut cx),
            Poll::Ready("settled original pause")
        );
        assert_eq!(observations.get(), 2);
        assert_eq!(polls.get(), 3);
        assert_eq!(disposed.get(), 1);
    }

    #[test]
    fn stop_is_latched_before_the_original_run_can_begin_work() {
        let stopped = Cell::new(false);
        let original = async {
            assert!(stopped.get());
            "paused before native admission"
        };
        let mut running = std::pin::pin!(drive(&stopped, |_| true, original));
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert_eq!(
            running.as_mut().poll(&mut cx),
            Poll::Ready("paused before native admission")
        );
    }
}
