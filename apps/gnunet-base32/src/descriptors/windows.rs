//! Capacity-one native binary workers; cancellation retains original work.
use gnunet_program_host::binary_io::{self, Input, Output};
use std::{
    future::Future,
    io,
    task::{Context, Poll},
};

enum Role {
    Input(Option<Input>),
    Output(Option<Output>),
}
pub(crate) struct Descriptor {
    role: Role,
    pending: bool,
}
impl Descriptor {
    // Capturing each original route is deferred until its first operation.
    // Malformed decode never acquires or submits a stdout worker.
    #[expect(
        clippy::unnecessary_wraps,
        reason = "Shares the fallible Unix descriptor acquisition interface; Windows defers native acquisition to its first byte operation"
    )]
    pub fn pair() -> io::Result<(Self, Self)> {
        Ok((
            Self {
                role: Role::Input(None),
                pending: false,
            },
            Self {
                role: Role::Output(None),
                pending: false,
            },
        ))
    }
    pub fn read(&mut self, cx: &mut Context<'_>, bytes: &mut [u8]) -> Poll<io::Result<usize>> {
        let Role::Input(owner) = &mut self.role else {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        };
        if owner.is_none() {
            *owner = Some(Input::stdin(super::super::transform::INPUT).map_err(io::Error::other)?);
        }
        let owner = owner
            .as_mut()
            .ok_or_else(|| io::Error::other("missing original stdin"))?;
        if !self.pending {
            owner.begin(bytes.len())?;
            self.pending = true;
        }
        let completion = owner.complete();
        let mut completion = std::pin::pin!(completion);
        match completion.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending = false;
                let read = result?;
                let out = bytes
                    .get_mut(..read.len())
                    .ok_or_else(|| io::Error::other("invalid original stdin count"))?;
                out.copy_from_slice(read);
                Poll::Ready(Ok(read.len()))
            }
        }
    }
    pub fn write(&mut self, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let Role::Output(owner) = &mut self.role else {
            return Poll::Ready(Err(io::ErrorKind::InvalidInput.into()));
        };
        if owner.is_none() {
            *owner =
                Some(Output::stdout(super::super::transform::OUTPUT).map_err(io::Error::other)?);
        }
        let owner = owner
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
        if step.is_ready() {
            self.pending = false;
        }
        step
    }
    pub fn retire(&mut self) -> Option<binary_io::Retirement> {
        match &mut self.role {
            Role::Input(owner) => owner.take().map(Input::retire),
            Role::Output(owner) => owner.take().map(Output::retire),
        }
    }
}
