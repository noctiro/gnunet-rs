//! Bounded synchronous standard IO. These handles neither duplicate inherited
//! descriptors nor change their file status flags. Accepted stdio bytes are not
//! kernel-exposure/flush receipts; synchronous OS latency is not forcibly bounded
//! by a network deadline and no hidden blocking worker is created.
use crate::lifecycle::Cleanup;
use std::{
    io::{self, Read, Write},
    task::{Context, Poll},
};
pub(super) enum Io {
    Input(io::Stdin),
    Output {
        owner: io::Stdout,
        unflushed: usize,
        cleanup: Cleanup,
    },
}
impl Io {
    pub fn input() -> Self {
        Self::Input(io::stdin())
    }
    pub fn output(cleanup: Cleanup) -> Self {
        Self::Output {
            owner: io::stdout(),
            unflushed: 0,
            cleanup,
        }
    }
    pub fn read(&mut self, _cx: &mut Context<'_>, bytes: &mut [u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(match self {
            Self::Input(input) => input.read(bytes),
            Self::Output { .. } => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot read output stdio",
            )),
        })
    }
    pub fn write(&mut self, _cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(match self {
            Self::Output {
                owner, unflushed, ..
            } => {
                if unflushed.checked_add(bytes.len()).is_none() {
                    return Poll::Ready(Err(io::Error::other("public output byte count overflow")));
                }
                owner.write(bytes).and_then(|written| {
                    if written > bytes.len() {
                        return Err(io::Error::other(
                            "public output returned an invalid byte count",
                        ));
                    }
                    *unflushed += written;
                    Ok(written)
                })
            }
            Self::Input(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot write input stdio",
            )),
        })
    }
    pub fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Input(_) => Ok(()),
            Self::Output {
                owner, unflushed, ..
            } => {
                owner.flush()?;
                *unflushed = 0;
                Ok(())
            }
        }
    }
}
impl Drop for Io {
    fn drop(&mut self) {
        if let Self::Output {
            unflushed, cleanup, ..
        } = self
            && *unflushed != 0
        {
            cleanup.output(*unflushed);
        }
    }
}
