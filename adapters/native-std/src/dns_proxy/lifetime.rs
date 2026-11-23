//! Results become observable only after original callback argument loans retire.
use super::completion::{self, Completion, Outcome, Publisher};
use std::{
    io,
    task::{Context, Poll},
};

pub(super) struct Pending<T> {
    completion: Completion<io::Result<T>>,
    disposal: Completion<()>,
    result: Option<io::Result<T>>,
}
pub(super) fn reserve<T>() -> (Pending<T>, Publisher<io::Result<T>>, Publisher<()>) {
    let (completion, publish) = completion::pair();
    let (disposal, disposed) = completion::pair();
    (
        Pending {
            completion,
            disposal,
            result: None,
        },
        publish,
        disposed,
    )
}
impl<T> Pending<T> {
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<T>>> {
        if self.result.is_none() {
            match self.completion.poll(cx) {
                Poll::Ready(Some(Outcome::Published(result))) => self.result = Some(result),
                Poll::Ready(Some(Outcome::CallbackDropped)) => {
                    self.result = Some(Err(io::Error::other(
                        "native callback released without a result",
                    )));
                }
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
        match self.disposal.poll(cx) {
            // The unique disposal publisher is the callback context's last
            // field. Its Drop runs after retained SDK arguments and Rust bytes.
            Poll::Ready(Some(_) | None) => Poll::Ready(self.result.take()),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::reserve;
    use std::task::{Context, Poll, Waker};

    #[test]
    fn completion_waits_for_independent_disposal() {
        let (mut pending, publish, disposed) = reserve::<usize>();
        let mut cx = Context::from_waker(Waker::noop());
        publish.publish(Ok(7));
        assert!(pending.poll(&mut cx).is_pending());
        drop(disposed);
        assert!(matches!(pending.poll(&mut cx), Poll::Ready(Some(Ok(7)))));
        assert!(matches!(pending.poll(&mut cx), Poll::Ready(None)));
    }
    #[test]
    fn absent_callback_is_failure_after_disposal() {
        let (mut pending, publish, disposed) = reserve::<()>();
        let mut cx = Context::from_waker(Waker::noop());
        drop(publish);
        assert!(pending.poll(&mut cx).is_pending());
        drop(disposed);
        assert!(matches!(pending.poll(&mut cx), Poll::Ready(Some(Err(_)))));
    }
}
