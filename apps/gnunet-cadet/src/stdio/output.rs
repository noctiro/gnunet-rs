//! One copied original output prefix; a canceled wait never resubmits it.
use super::{Retry, temporary};
use gnunet_program_host::binary_io;
use std::{
    future::Future,
    io,
    task::{Context, Poll},
};
pub(super) struct Output {
    owner: Option<binary_io::Output>,
    pending: bool,
    retry: Retry,
}
impl Output {
    pub(super) fn new() -> Self {
        Self {
            owner: None,
            pending: false,
            retry: Retry::new(),
        }
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        if !self.pending && !self.retry.ready(cx) {
            return Poll::Pending;
        }
        if self.owner.is_none() {
            self.owner = Some(binary_io::Output::stdout(512).map_err(io::Error::other)?);
        }
        let owner = self
            .owner
            .as_mut()
            .ok_or_else(|| io::Error::other("missing original stdout"))?;
        if !self.pending {
            owner.begin(bytes)?;
            self.pending = true;
        }
        let step = {
            let completion = owner.complete();
            let mut completion = std::pin::pin!(completion);
            completion.as_mut().poll(cx)
        };
        match step {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending = false;
                if result.as_ref().is_err_and(temporary) {
                    self.retry.pause(cx);
                    return Poll::Pending;
                }
                Poll::Ready(result)
            }
        }
    }
    pub(super) fn retire(self) -> Option<binary_io::Retirement> {
        self.owner.map(binary_io::Output::retire)
    }
}
