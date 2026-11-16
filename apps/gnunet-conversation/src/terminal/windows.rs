//! Capacity-one Unicode console I/O with retained original-worker retirement.
use crate::Failure;
use gnunet_program_host::binary_io::{self, Input, Output, RetiredSet};
use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

enum Port {
    Input(Input),
    Output(Output),
}
/// Retains original transfer/close observations, including debt at the fixed
/// shutdown deadline. No blocked worker is replaced or counted as closed.
pub(crate) struct Retirement {
    wait: Option<Pin<Box<dyn Future<Output = RetiredSet<1>>>>>,
    result: Option<RetiredSet<1>>,
}
impl fmt::Debug for Retirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TerminalRetirement")
            .field("pending", &self.wait.is_some())
            .field("result", &self.result)
            .finish()
    }
}
impl Retirement {
    pub(super) fn successful(&self) -> bool {
        self.result.as_ref().is_some_and(RetiredSet::successful)
    }
}
pub(super) struct Descriptor {
    port: Option<Port>,
    pending: bool,
    retirement: Option<Retirement>,
}
impl Descriptor {
    pub fn standard_pair() -> Result<(Self, Self), Failure> {
        // Capture both original routes before admitting worker requests. Console
        // input uses ReadConsoleW; redirection stays a lossless byte stream.
        let input = gnunet_native::stdio::stdin_file()?;
        let output = Output::stdout_text(16384)?;
        let input = Input::text(input, 4096)?;
        let descriptor = |port| Self {
            port: Some(port),
            pending: false,
            retirement: None,
        };
        Ok((
            descriptor(Port::Input(input)),
            descriptor(Port::Output(output)),
        ))
    }
    pub fn read(&mut self, cx: &mut Context<'_>, bytes: &mut [u8]) -> Poll<io::Result<usize>> {
        let Some(Port::Input(input)) = self.port.as_mut() else {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        };
        if !self.pending {
            input.begin(bytes.len())?;
            self.pending = true;
        }
        let result = {
            let mut complete = std::pin::pin!(input.complete());
            match complete.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => Err(error),
                Poll::Ready(Ok(read)) => {
                    if read.len() > bytes.len() {
                        Err(io::ErrorKind::InvalidData.into())
                    } else {
                        bytes[..read.len()].copy_from_slice(read);
                        Ok(read.len())
                    }
                }
            }
        };
        self.pending = false;
        Poll::Ready(result)
    }
    pub fn write(&mut self, cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        let Some(Port::Output(output)) = self.port.as_mut() else {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        };
        if !self.pending {
            output.begin(bytes)?;
            self.pending = true;
        }
        let result = {
            let mut complete = std::pin::pin!(output.complete());
            match complete.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(result) => result,
            }
        };
        self.pending = false;
        Poll::Ready(result)
    }
    pub fn retire(&mut self, hard: Instant) -> Option<io::Error> {
        if let Some(port) = self.port.take() {
            let owner = match port {
                Port::Input(input) => input.retire(),
                Port::Output(output) => output.retire(),
            };
            self.retirement = Some(Retirement {
                wait: Some(Box::pin(binary_io::settle([Some(owner)], hard))),
                result: None,
            });
        }
        None
    }
    pub fn poll_closed(&mut self, cx: &mut Context<'_>, error: &mut Option<io::Error>) -> bool {
        let Some(retirement) = self.retirement.as_mut() else {
            return false;
        };
        if let Some(wait) = retirement.wait.as_mut() {
            let Poll::Ready(result) = wait.as_mut().poll(cx) else {
                return false;
            };
            if !result.successful() {
                error.get_or_insert_with(|| io::Error::other(format!("{result}")));
            }
            retirement.result = Some(result);
            retirement.wait = None;
        }
        true
    }
    pub fn closed(&self) -> bool {
        self.retirement.as_ref().is_some_and(|r| r.wait.is_none())
    }
    pub fn close(&mut self) -> Option<io::Error> {
        let _requested = self.retire(Instant::now());
        if self.closed() {
            None
        } else {
            Some(io::Error::new(
                io::ErrorKind::TimedOut,
                "original terminal worker transfer/close remains unobserved",
            ))
        }
    }
    pub fn take_retirement(&mut self) -> Option<Retirement> {
        self.retirement.take()
    }
}
