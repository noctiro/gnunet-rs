//! Capacity-one binary file/stdio I/O with explicit original-work retirement.
//! One bounded worker owns a captured file. Canceling a completion wait leaves
//! that same request with the port; it never starts a second native operation.
mod owner;
mod retirement;
pub use retirement::{Retired, RetiredSet, settle};
#[cfg(test)]
mod tests;
mod worker;
use owner::{Owner, Pending};
use std::{
    fmt,
    fs::File,
    io,
    path::Path,
    task::{Context, Poll},
    thread::JoinHandle,
    time::Instant,
};
use tokio::sync::oneshot;
use zeroize::Zeroizing;

/// Maximum caller-selected scratch capacity for one original I/O owner.
pub const MAX_CHUNK: usize = 64 * 1024;
/// Native role of one original file owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    /// A native read.
    Input,
    /// A native write.
    Output,
}
/// Independent setup and consuming-close diagnostics before worker admission.
#[derive(Debug)]
pub struct StartError {
    /// Original preparation or thread-admission error.
    pub cause: io::Error,
    /// Independent failure closing a file that was never handed to a worker.
    pub close: Option<io::Error>,
}
impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "binary I/O setup: {}", self.cause)?;
        if let Some(error) = &self.close {
            write!(f, "; independent close: {error}")?;
        }
        Ok(())
    }
}
impl std::error::Error for StartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
impl From<io::Error> for StartError {
    fn from(cause: io::Error) -> Self {
        Self { cause, close: None }
    }
}
/// Actual native flush/close receipt, separate from any pending transfer result.
#[derive(Debug)]
pub struct Closed {
    /// Write flush error; no durability or downstream-delivery guarantee is added.
    pub flush: Option<io::Error>,
    /// Original consuming native close error, without a retry.
    pub close: Option<io::Error>,
    /// Native monotonic instant after the actual close attempt returned.
    pub observed_at: Instant,
    /// An original transfer receipt was lost, independently of flush/close facts.
    pub transfer_lost: bool,
}
impl Closed {
    /// Whether flush/close succeeded and no original transfer receipt was lost.
    pub fn successful(&self) -> bool {
        self.flush.is_none() && self.close.is_none() && !self.transfer_lost
    }
}
/// One original transfer's result and zeroizing scratch, retained on retirement.
pub struct Transfer {
    direction: Direction,
    requested: usize,
    result: io::Result<usize>,
    buffer: Zeroizing<Vec<u8>>,
}
impl Transfer {
    /// Actual native Windows cancellation status of this original read.
    /// It grants no write, close or cancellation-request acknowledgement.
    #[cfg(windows)]
    pub fn read_cancelled(&self) -> bool {
        self.direction == Direction::Input
            && self
                .result
                .as_ref()
                .is_err_and(gnunet_native::stdio::is_cancelled_read)
    }
    /// Original read/write role.
    pub fn direction(&self) -> Direction {
        self.direction
    }
    /// Requested prefix length, bounded by the owner's capacity.
    pub fn requested(&self) -> usize {
        self.requested
    }
    /// Original native byte count or error. An error does not prove that a
    /// kernel call made no partial changes.
    pub fn result(&self) -> &io::Result<usize> {
        &self.result
    }
    /// Consume the native result, zeroizing the associated scratch.
    pub fn into_result(self) -> io::Result<usize> {
        self.result
    }
    /// Borrow bytes only from a successful original read completion.
    pub fn read_bytes(&self) -> Option<&[u8]> {
        if self.direction != Direction::Input {
            return None;
        }
        let count = *self.result.as_ref().ok()?;
        self.buffer.get(..count)
    }
}
impl fmt::Debug for Transfer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Transfer")
            .field("direction", &self.direction)
            .field("requested", &self.requested)
            .field("result", &self.result)
            .finish_non_exhaustive()
    }
}
/// A bounded original binary reader. Drop closes admission without waiting;
/// use [`Self::retire`] to keep observing outstanding work and actual close.
pub struct Input(Owner);
impl Input {
    /// Observe stdin without consuming bytes or changing shared file flags.
    /// Exclude route changes/other readers across this observation and capture.
    /// This does not make subsequent native reading preemptible.
    pub fn stdin_ready() -> io::Result<bool> {
        gnunet_native::stdio::stdin_ready()
    }
    /// Transfer a file into one worker with fixed zeroizing scratch capacity.
    pub fn new(file: File, capacity: usize) -> Result<Self, StartError> {
        Owner::new(file, Direction::Input, capacity).map(Self)
    }
    /// Open an input path synchronously, then transfer the resulting original.
    pub fn open(path: &Path, capacity: usize) -> Result<Self, StartError> {
        Self::new(File::open(path)?, capacity)
    }
    /// Capture the original binary stdin route before buffered stdin use.
    pub fn stdin(capacity: usize) -> Result<Self, StartError> {
        Self::new(gnunet_native::stdio::stdin_file()?, capacity)
    }
    /// Retain text input on the same capacity-one worker. Windows console input
    /// is converted from UTF-16 to UTF-8; redirected/native Unix bytes are exact.
    /// Cancellation and close receipts use the same original-worker policy.
    pub fn text(file: File, capacity: usize) -> Result<Self, StartError> {
        Owner::resource(
            worker::Resource::TextInput(gnunet_native::stdio::TextInput::new(file)),
            Direction::Input,
            capacity,
        )
        .map(Self)
    }
    /// Admit one read. A pending request must be completed or retired first.
    pub fn begin(&mut self, maximum: usize) -> io::Result<()> {
        self.0.begin(maximum, None)
    }
    /// Await the same original read across canceled waits; never submits work.
    pub async fn complete(&mut self) -> io::Result<&[u8]> {
        let count = self.0.complete().await?;
        self.0.bytes(count)
    }
    /// End admission while retaining native completion and close observations.
    pub fn retire(self) -> Retirement {
        self.0.retire()
    }
}
/// A bounded raw-byte writer; no Unicode or newline conversion is applied.
pub struct Output(Owner);
impl Output {
    /// Transfer an original file into a capacity-one native writer.
    pub fn new(file: File, capacity: usize) -> Result<Self, StartError> {
        Owner::new(file, Direction::Output, capacity).map(Self)
    }
    /// Open/truncate output. New files get native private creation permissions;
    /// existing files retain their permissions/ACL. Opening is synchronous.
    pub fn open(path: &Path, capacity: usize) -> Result<Self, StartError> {
        Self::new(worker::output_file(path)?, capacity)
    }
    /// Retain original stdout for raw bytes, without a global formatting lock.
    pub fn stdout(capacity: usize) -> Result<Self, StartError> {
        Self::new(gnunet_native::stdio::stdout_file()?, capacity)
    }
    /// Capture stdout for text. Windows consoles require complete valid UTF-8
    /// chunks and receive Unicode; redirected bytes are preserved exactly.
    pub fn stdout_text(capacity: usize) -> Result<Self, StartError> {
        Owner::resource(
            worker::Resource::Text(gnunet_native::stdio::Output::stdout()?),
            Direction::Output,
            capacity,
        )
        .map(Self)
    }
    /// Copy/admit one bounded prefix; no second call is allowed while pending.
    pub fn begin(&mut self, bytes: &[u8]) -> io::Result<()> {
        self.0.begin(bytes.len(), Some(bytes))
    }
    /// Observe the original native write count/error without submitting again.
    pub async fn complete(&mut self) -> io::Result<usize> {
        self.0.complete().await
    }
    /// End admission, observing flush/close after already admitted work returns.
    pub fn retire(self) -> Retirement {
        self.0.retire()
    }
}
/// Original outstanding transfer and close receivers. Dropping this owner never
/// joins or claims cancellation of a blocked kernel call. The worker retains its
/// file and zeroizing buffer until native execution actually returns.
#[must_use = "Retain the original work to observe native transfer and close completion"]
pub struct Retirement {
    direction: Direction,
    pending: Option<Pending>,
    completion: Option<Transfer>,
    closed: Option<oneshot::Receiver<Closed>>,
    thread: Option<JoinHandle<()>>,
    receipt_lost: bool,
}
impl fmt::Debug for Retirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Retirement")
            .field("direction", &self.direction)
            .field("pending", &self.pending.is_some())
            .field("completion", &self.completion)
            .field("receipt_lost", &self.receipt_lost)
            .finish_non_exhaustive()
    }
}
impl Retirement {
    /// Request cancellation of this original outstanding Windows read after
    /// admission has closed. A successful request is not a completion receipt;
    /// ERROR_NOT_FOUND permits a later request for the same not-yet-issued read.
    /// This never cancels writes, a replacement thread or another owner's I/O.
    #[cfg(windows)]
    pub fn request_read_cancel(&mut self) -> io::Result<bool> {
        if self.direction != Direction::Input {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if self.pending.is_none() {
            return Ok(false);
        }
        let thread = self
            .thread
            .as_ref()
            .ok_or_else(|| io::Error::other("missing original read worker"))?;
        gnunet_native::stdio::cancel_synchronous_read(thread)
    }
    /// Poll actual flush/close. Readiness does not imply a thread join or kernel
    /// cancellation; a completed transfer stays available separately.
    pub fn poll_closed(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Closed>> {
        if let Some(pending) = &mut self.pending {
            match std::pin::Pin::new(&mut pending.reply).poll(cx) {
                Poll::Pending => {}
                Poll::Ready(result) => {
                    let requested = pending.requested;
                    self.pending = None;
                    match result {
                        Ok(reply) => {
                            self.completion = Some(Transfer {
                                direction: self.direction,
                                requested,
                                result: reply.result,
                                buffer: reply.buffer,
                            })
                        }
                        Err(_) => self.receipt_lost = true,
                    }
                }
            }
        }
        let Some(closed) = &mut self.closed else {
            return Poll::Ready(Err(io::Error::other(
                "original close receipt already consumed",
            )));
        };
        match std::pin::Pin::new(closed).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.closed = None;
                if let Some(pending) = &mut self.pending {
                    let requested = pending.requested;
                    match std::pin::Pin::new(&mut pending.reply).poll(cx) {
                        Poll::Ready(Ok(reply)) => {
                            self.completion = Some(Transfer {
                                direction: self.direction,
                                requested,
                                result: reply.result,
                                buffer: reply.buffer,
                            });
                            self.pending = None;
                        }
                        Poll::Ready(Err(_)) => {
                            self.receipt_lost = true;
                            self.pending = None;
                        }
                        Poll::Pending => {}
                    }
                }
                Poll::Ready(match result {
                    Ok(mut report) => {
                        report.transfer_lost = self.receipt_lost || self.pending.is_some();
                        Ok(report)
                    }
                    Err(_) => Err(io::Error::other(
                        "binary owner ended without its original close receipt",
                    )),
                })
            }
        }
    }
    /// Consume the original outstanding transfer once, including read bytes.
    pub fn take_transfer(&mut self) -> Option<Transfer> {
        self.completion.take()
    }
    /// Observe worker completion without a join, PID lookup or waiting.
    pub fn worker_finished(&self) -> bool {
        self.thread.as_ref().is_none_or(JoinHandle::is_finished)
    }
}
