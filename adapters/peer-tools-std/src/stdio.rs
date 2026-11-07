//! Bounded synchronous standard IO. These handles neither duplicate inherited
//! descriptors nor change their file status flags. Accepted stdio bytes are not
//! kernel-exposure/flush receipts; synchronous OS latency is not forcibly bounded
//! by a network deadline and no hidden blocking worker is created.
use std::{
    io::{self, Read, Write},
    task::{Context, Poll},
};
pub(super) enum Io {
    Input(io::Stdin),
    Output(io::Stdout),
}
impl Io {
    pub fn input() -> Self {
        Self::Input(io::stdin())
    }
    pub fn output() -> Self {
        Self::Output(io::stdout())
    }
    pub fn read(&mut self, _cx: &mut Context<'_>, bytes: &mut [u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(match self {
            Self::Input(input) => input.read(bytes),
            Self::Output(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot read output stdio",
            )),
        })
    }
    pub fn write(&mut self, _cx: &mut Context<'_>, bytes: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(match self {
            Self::Output(output) => output.write(bytes),
            Self::Input(_) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot write input stdio",
            )),
        })
    }
    pub fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Input(_) => Ok(()),
            Self::Output(output) => output.flush(),
        }
    }
}
impl Drop for Io {
    fn drop(&mut self) {
        // Explicit normal/error cleanup returns its flush error separately. This
        // fallback also attempts flushing after outer future cancellation; Drop
        // cannot return a receipt, so preserve any independent error diagnostically.
        if let Self::Output(output) = self
            && let Err(error) = output.flush()
        {
            let _diagnostic = writeln!(
                io::stderr().lock(),
                "public peer independent stdio Drop flush failed: {error}"
            );
        }
    }
}
