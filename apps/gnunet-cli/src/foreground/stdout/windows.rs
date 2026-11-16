//! One bounded original-handle write worker and actual completion receipts.
use gnunet_native::stdio::Output;
use std::{
    future::Future,
    io::{self, Write},
    pin::Pin,
    task::{Context, Poll, Waker},
};
use tokio::task::JoinHandle;
type Completion = (Output, Vec<u8>, io::Result<()>);
enum State {
    Idle(Output),
    Writing(JoinHandle<Completion>),
    Failed,
}
pub(crate) struct Stdout {
    state: State,
    buffer: Vec<u8>,
    completed: Option<usize>,
}
impl Stdout {
    pub(crate) fn new() -> io::Result<Self> {
        tokio::runtime::Handle::try_current().map_err(io::Error::other)?;
        let output = Output::stdout()?;
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(4096).map_err(io::Error::other)?;
        Ok(Self {
            state: State::Idle(output),
            buffer,
            completed: None,
        })
    }
    fn settle(&mut self) -> io::Result<Option<usize>> {
        let State::Writing(work) = &mut self.state else {
            return Ok(None);
        };
        // The foreground driver retains its cadence timer. This probe never
        // starts another task while the original job owns its handle/buffer.
        let mut context = Context::from_waker(Waker::noop());
        match Pin::new(work).poll(&mut context) {
            Poll::Pending => Ok(None),
            Poll::Ready(Err(error)) => {
                self.state = State::Failed;
                Err(io::Error::other(error))
            }
            Poll::Ready(Ok((output, bytes, result))) => {
                let written = bytes.len();
                self.buffer = bytes;
                self.buffer.clear();
                match result {
                    Ok(()) => {
                        self.state = State::Idle(output);
                        Ok(Some(written))
                    }
                    Err(error) => {
                        self.state = State::Failed;
                        Err(error)
                    }
                }
            }
        }
    }
    pub(crate) fn write(&mut self, bytes: &[u8]) -> io::Result<Option<usize>> {
        if let Some(n) = self.completed.take() {
            return Ok(Some(n));
        }
        if matches!(self.state, State::Failed) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if matches!(self.state, State::Idle(_)) {
            // JSON is UTF-8; do not cut a console scalar at the chunk boundary.
            let text = std::str::from_utf8(bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
            let end = text.floor_char_boundary(4096);
            self.buffer.extend_from_slice(&bytes[..end]);
            if let State::Idle(mut output) = std::mem::replace(&mut self.state, State::Failed) {
                let buffer = std::mem::take(&mut self.buffer);
                self.state = State::Writing(tokio::task::spawn_blocking(move || {
                    let result = output.write_all(&buffer).and_then(|()| output.flush());
                    (output, buffer, result)
                }));
            }
        }
        self.settle()
    }
    pub(crate) fn flush(&mut self) -> io::Result<()> {
        if matches!(self.state, State::Failed) {
            return Err(io::ErrorKind::BrokenPipe.into());
        }
        if let State::Writing(_) = self.state {
            match self.settle()? {
                Some(n) => self.completed = Some(n),
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::WouldBlock,
                        "original stdout operation remains outstanding",
                    ));
                }
            }
        }
        Ok(())
    }
}
