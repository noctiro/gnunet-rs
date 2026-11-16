//! One original read; no data is supplied to the protocol until completion.
use super::{Retry, temporary};
use gnunet_program_host::binary_io;
use std::{
    future::Future,
    io,
    task::{Context, Poll},
};
pub(super) struct Input {
    owner: Option<binary_io::Input>,
    chunk: usize,
    pending: bool,
    retry: Retry,
}
impl Input {
    pub(super) fn new(chunk: usize) -> Self {
        Self {
            owner: None,
            chunk,
            pending: false,
            retry: Retry::new(),
        }
    }
    pub(super) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if !self.pending && !self.retry.ready(cx) {
            return Poll::Pending;
        }
        if !self.pending && !binary_io::Input::stdin_ready()? {
            self.retry.pause(cx);
            return Poll::Pending;
        }
        if self.owner.is_none() {
            self.owner = Some(binary_io::Input::stdin(self.chunk).map_err(io::Error::other)?);
        }
        let owner = self
            .owner
            .as_mut()
            .ok_or_else(|| io::Error::other("missing original stdin"))?;
        if !self.pending {
            owner.begin(bytes.len().min(self.chunk))?;
            self.pending = true;
        }
        let step = {
            let completion = owner.complete();
            let mut completion = std::pin::pin!(completion);
            match completion.as_mut().poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(input)) => {
                    if input.len() > bytes.len() {
                        Poll::Ready(Err(io::ErrorKind::InvalidData.into()))
                    } else {
                        bytes[..input.len()].copy_from_slice(input);
                        Poll::Ready(Ok(input.len()))
                    }
                }
            }
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
        self.owner.map(binary_io::Input::retire)
    }
}
