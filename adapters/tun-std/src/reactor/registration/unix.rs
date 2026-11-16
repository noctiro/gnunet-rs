//! Unix reactor registration preserves the original descriptor through retirement.
use super::{Input, Refusal};
use crate::OwnedTun;
use std::{
    io,
    task::{Context, Poll},
};
use tokio::io::unix::AsyncFd;
pub(in crate::reactor) struct Registered(AsyncFd<OwnedTun>);
impl Registered {
    #[expect(
        unsafe_code,
        reason = "This private owner retains the verified original descriptor until into_inner deregisters it before close; mutable replacement is never exposed"
    )]
    pub(in crate::reactor) fn new(tun: OwnedTun) -> Result<Self, Box<Refusal>> {
        // SAFETY: unique verified descriptor; no close/replacement escapes this owner.
        match unsafe { AsyncFd::register(tun) } {
            Ok(io) => Ok(Self(io)),
            Err(error) => {
                let (tun, cause) = error.into_parts();
                Err(Box::new(Refusal { tun, cause }))
            }
        }
    }
    pub(in crate::reactor) fn get_ref(&self) -> &OwnedTun {
        self.0.get_ref()
    }
    pub(in crate::reactor) fn get_mut(&mut self) -> &mut OwnedTun {
        self.0.get_mut()
    }
    pub(in crate::reactor) fn into_inner(self) -> OwnedTun {
        self.0.into_inner()
    }
    pub(in crate::reactor) fn reset_write_wait(&mut self) {}
    pub(in crate::reactor) fn read(
        &mut self,
        cx: &mut Context<'_>,
        bytes: &mut [u8],
    ) -> Poll<io::Result<Input>> {
        read_once(&self.0, cx, bytes).map(|result| result.map(Input::Data))
    }
    pub(in crate::reactor) fn write(
        &mut self,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        write_once(&self.0, cx, bytes)
    }
}
fn read_once(
    io: &AsyncFd<OwnedTun>,
    cx: &mut Context<'_>,
    bytes: &mut [u8],
) -> Poll<io::Result<usize>> {
    let mut ready = match io.poll_read_ready(cx) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
        Poll::Ready(Ok(ready)) => ready,
    };
    match ready
        .try_io(|io| nix::unistd::read(io.get_ref().descriptor()?, bytes).map_err(io::Error::from))
    {
        Err(_) => {
            // Cached Ready may not have stored a waker before try_io cleared it.
            // Re-poll to register it without repeating the operation here.
            cx.waker().wake_by_ref();
            Poll::Pending
        }
        Ok(value) => Poll::Ready(value),
    }
}
fn write_once(
    io: &AsyncFd<OwnedTun>,
    cx: &mut Context<'_>,
    bytes: &[u8],
) -> Poll<io::Result<usize>> {
    let mut ready = match io.poll_write_ready(cx) {
        Poll::Pending => return Poll::Pending,
        Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
        Poll::Ready(Ok(ready)) => ready,
    };
    match ready
        .try_io(|io| nix::unistd::write(io.get_ref().descriptor()?, bytes).map_err(io::Error::from))
    {
        Err(_) => {
            // Cached Ready may not have stored a waker before try_io cleared it.
            // Re-poll to register it without repeating the operation here.
            cx.waker().wake_by_ref();
            Poll::Pending
        }
        Ok(value) => Poll::Ready(value),
    }
}
