//! Actual callback bytes copied before returning their borrowed delivery lease.
mod retirement;
use crate::Cause;
use gnunet_program_host::binary_io;
use gnunet_resolver_broker::{Completion, Hostname, Reply};
pub(super) use retirement::Retired;
use std::{
    future::Future,
    io::{self, Write},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use zeroize::Zeroizing;
pub(super) struct Line {
    bytes: Zeroizing<Vec<u8>>,
    offset: usize,
}
impl Line {
    pub(super) fn len(&self) -> usize {
        self.bytes.len()
    }
    pub(super) fn offset(&self) -> usize {
        self.offset
    }
    pub(super) fn finished(&self) -> bool {
        self.offset == self.bytes.len()
    }
    pub(super) fn written(&mut self, count: usize) -> io::Result<()> {
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "stdout wrote zero bytes",
            ));
        }
        if count > self.bytes.len() - self.offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid original stdout write count",
            ));
        }
        self.offset += count;
        Ok(())
    }
}
pub(super) enum Callback {
    Line(Line),
    Complete(Completion),
}
pub(super) fn copy(reply: Reply<'_>, reverse: bool) -> Result<Callback, Cause> {
    let mut bytes = Vec::new();
    match reply {
        Reply::Complete(reason) => return Ok(Callback::Complete(reason)),
        Reply::Address(value) if !reverse => {
            bytes.try_reserve_exact(64)?;
            writeln!(bytes, "{value}")?;
        }
        Reply::Hostname(Hostname::Numeric(value)) if reverse => {
            bytes.try_reserve_exact(64)?;
            writeln!(bytes, "{value}")?;
        }
        Reply::Hostname(Hostname::Resolved(value)) if reverse => {
            if value.len() > 65535 {
                return Err("Resolver hostname exceeds bounded native frame".into());
            }
            bytes.try_reserve_exact(value.len() + 1)?;
            bytes.extend_from_slice(value);
            bytes.push(b'\n');
        }
        _ => return Err("Resolver callback role does not match the original query".into()),
    }
    Ok(Callback::Line(Line {
        bytes: Zeroizing::new(bytes),
        offset: 0,
    }))
}
/// One capacity-one native writer; dropping a wait never resubmits its bytes.
pub(super) struct Output {
    owner: binary_io::Output,
    pending: Option<(usize, usize)>,
    retry: Pin<Box<tokio::time::Sleep>>,
}
impl Output {
    pub(super) fn new() -> Result<Self, binary_io::StartError> {
        Ok(Self {
            owner: binary_io::Output::stdout(512)?,
            pending: None,
            retry: Box::pin(tokio::time::sleep(Duration::ZERO)),
        })
    }
    pub(super) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        line: &mut Line,
    ) -> Poll<io::Result<usize>> {
        if let Some((offset, _)) = self.pending {
            if offset != line.offset {
                return Poll::Ready(Err(io::Error::other(
                    "stdout lost its original line cursor",
                )));
            }
        } else {
            if self.retry.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            let end = line.bytes.len().min(line.offset + 512);
            self.owner.begin(&line.bytes[line.offset..end])?;
            self.pending = Some((line.offset, end - line.offset));
        }
        let result = {
            let completion = self.owner.complete();
            let mut completion = std::pin::pin!(completion);
            completion.as_mut().poll(cx)
        };
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending = None;
                let count = match result {
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                        ) =>
                    {
                        // These original native calls wrote no bytes. Back off
                        // without changing the line cursor or command deadline.
                        self.retry
                            .as_mut()
                            .reset(tokio::time::Instant::now() + Duration::from_millis(25));
                        let _registered = self.retry.as_mut().poll(cx);
                        return Poll::Pending;
                    }
                    result => result?,
                };
                line.written(count)?;
                Poll::Ready(Ok(count))
            }
        }
    }
    /// End admission and observe only original native work during fixed grace.
    pub(super) async fn retire(self) -> Retired {
        retirement::retire(self.owner, self.pending.is_some()).await
    }
}
