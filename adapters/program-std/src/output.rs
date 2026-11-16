//! Bounded synchronous text/binary output with independently driven native I/O.
//!
//! Encoding and domain errors stay on the caller's thread. One supervisor and
//! at most one blocking job own the original output route. A timeout or native
//! stop ends waiting, never asserts that a blocking kernel call was cancelled.
//! Failed owners retain their original pending job and receipt receiver.
mod actor;
mod state;
#[cfg(test)]
mod tests;
use state::{Cause, Counts};
pub use state::{Failure, Snapshot};
use std::{
    cell::Cell,
    io::{self, Write},
    rc::Rc,
    sync::{Arc, mpsc},
    thread::JoinHandle,
    time::{Duration, Instant},
};

const CAPACITY: usize = 64 * 1024;
const CHUNK: usize = 4096;
/// Encoding contract for native output. Binary routes never reinterpret bytes.
#[derive(Clone, Copy, Debug)]
enum Encoding {
    /// Validate UTF-8 and preserve complete scalar boundaries for consoles.
    Utf8,
    /// Preserve arbitrary bytes, including local file content.
    Bytes,
}

#[derive(Clone, Copy)]
enum Phase {
    Work(Option<Instant>),
    Cleanup(Instant),
}
/// Explicit operation bounds shared only with the command's encoding thread.
/// Cloning this capability does not create a worker or renew a deadline.
#[derive(Clone)]
pub struct Control(Rc<Cell<Phase>>);
impl Default for Control {
    fn default() -> Self {
        Self(Rc::new(Cell::new(Phase::Work(None))))
    }
}
impl Control {
    /// Constrain subsequent work writes to the original operation deadline.
    /// Repeated bindings can only shorten the bound.
    pub fn deadline(&self, hard: Instant) {
        if let Phase::Work(old) = self.0.get() {
            self.0
                .set(Phase::Work(Some(old.map_or(hard, |old| old.min(hard)))));
        }
    }
    /// Start one fixed cleanup grace. Repeated calls never renew it.
    ///
    /// # Errors
    /// Refuses zero or unrepresentable intervals before changing phase.
    pub fn cleanup(&self, grace: Duration) -> io::Result<()> {
        if matches!(self.0.get(), Phase::Work(_)) {
            let until = Instant::now()
                .checked_add(grace)
                .filter(|_| !grace.is_zero())
                .ok_or(io::ErrorKind::InvalidInput)?;
            self.0.set(Phase::Cleanup(until));
        }
        Ok(())
    }
}

/// A capacity-one output writer. Successful `write` admits bytes into a bounded
/// buffer; only `flush` acknowledges their actual native write and flush.
/// The handle must have exclusive output use while this owner is live.
pub struct BoundedOutput {
    encoding: Encoding,
    control: Control,
    stall: Duration,
    buffer: Vec<u8>,
    sender: tokio::sync::mpsc::Sender<actor::Work>,
    supervisor: Option<JoinHandle<()>>,
    receipt: Option<mpsc::Receiver<actor::Reply>>,
    pending: Option<tokio::task::JoinHandle<actor::Completed>>,
    cause: Option<Arc<Cause>>,
    counts: Arc<Counts>,
    discarded: u64,
    uncertain: bool,
}
impl BoundedOutput {
    /// Retain the original stdout route and start its bounded owner.
    ///
    /// # Errors
    /// Preserves route capture, allocation, thread and runtime setup errors.
    pub fn stdout(stall: Duration) -> io::Result<Self> {
        Self::start(
            gnunet_native::stdio::Output::stdout()?,
            Encoding::Utf8,
            stall,
        )
    }
    /// Retain the original stderr route, independently of stdout retirement.
    ///
    /// # Errors
    /// Preserves the same setup errors as [`Self::stdout`].
    pub fn stderr(stall: Duration) -> io::Result<Self> {
        Self::start(
            gnunet_native::stdio::Output::stderr()?,
            Encoding::Utf8,
            stall,
        )
    }
    /// Retain stdout for arbitrary bytes without Unicode conversion.
    ///
    /// # Errors
    /// Preserves the same setup errors as [`Self::stdout`].
    pub fn stdout_bytes(stall: Duration) -> io::Result<Self> {
        Self::start(
            gnunet_native::stdio::Output::stdout_bytes()?,
            Encoding::Bytes,
            stall,
        )
    }
    fn start(
        output: impl Write + Send + 'static,
        encoding: Encoding,
        stall: Duration,
    ) -> io::Result<Self> {
        if stall.is_zero() || Instant::now().checked_add(stall).is_none() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(CAPACITY)
            .map_err(io::Error::other)?;
        let runtime = actor::Background(Some(
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .max_blocking_threads(1)
                .thread_stack_size(256 * 1024)
                .build()?,
        ));
        let counts = Arc::new(Counts::default());
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        let observed = Arc::clone(&counts);
        let supervisor = std::thread::Builder::new()
            .name("gnunet-output".into())
            .stack_size(256 * 1024)
            .spawn(move || {
                if let Some(runtime) = &runtime.0 {
                    runtime.block_on(actor::run(output, receiver, observed));
                }
                // Pending blocking calls keep their original route and buffer;
                // runtime shutdown must not wait forever for an undrained pipe.
                drop(runtime);
            })?;
        Ok(Self {
            encoding,
            control: Control::default(),
            stall,
            buffer,
            sender,
            supervisor: Some(supervisor),
            receipt: None,
            pending: None,
            cause: None,
            counts,
            discarded: 0,
            uncertain: false,
        })
    }
    /// Borrow the explicit deadline/cleanup capability for this command.
    pub fn control(&self) -> Control {
        self.control.clone()
    }
    /// Lower-bound native receipts, distinct from bytes buffered by `write`.
    /// Pending retirement never implies an interrupted kernel write.
    pub fn snapshot(&self) -> Snapshot {
        self.counts.snapshot(
            self.buffer.len(),
            self.discarded,
            self.uncertain
                || self.receipt.is_some()
                || self.pending.as_ref().is_some_and(|job| !job.is_finished()),
        )
    }
    /// Discard only the unsubmitted tail after an independent domain error.
    /// Already submitted bytes may still be written by their original job.
    pub fn discard_buffer(&mut self) {
        self.discarded = self.discarded.saturating_add(self.buffer.len() as u64);
        self.buffer.clear();
    }
    fn refuse(&mut self, cause: Cause) -> io::Error {
        let cause = self.cause.get_or_insert_with(|| Arc::new(cause));
        io::Error::new(cause.kind(), Arc::clone(cause))
    }
    fn settle(&mut self, length: usize) -> io::Result<()> {
        if let Some(cause) = &self.cause {
            return Err(io::Error::new(cause.kind(), Arc::clone(cause)));
        }
        let now = Instant::now();
        let until = now
            .checked_add(self.stall)
            .ok_or_else(|| self.refuse(Cause::Deadline))?;
        let (deadline, observe_stop) = match self.control.0.get() {
            Phase::Work(hard) => (hard.map_or(until, |hard| hard.min(until)), true),
            Phase::Cleanup(hard) => (hard.min(until), false),
        };
        if now >= deadline {
            return Err(self.refuse(Cause::Deadline));
        }
        let tail = self.buffer.len() - length;
        let mut suffix = [0; 3];
        suffix[..tail].copy_from_slice(&self.buffer[length..]);
        self.buffer.truncate(length);
        let (done, receipt) = mpsc::sync_channel(1);
        let work = actor::Work {
            bytes: std::mem::take(&mut self.buffer),
            encoding: self.encoding,
            deadline,
            observe_stop,
            done,
        };
        match self.sender.try_send(work) {
            Ok(()) => {}
            Err(error) => {
                self.buffer = error.into_inner().bytes;
                self.buffer.extend_from_slice(&suffix[..tail]);
                self.uncertain = true;
                return Err(self.refuse(Cause::Supervisor));
            }
        }
        self.counts.submit(length as u64);
        match receipt.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(actor::Reply::Done(done)) => {
                self.buffer = done.bytes;
                self.buffer.clear();
                self.buffer.extend_from_slice(&suffix[..tail]);
                if let Err(error) = done.result {
                    return Err(self.refuse(Cause::Native(error)));
                }
                Ok(())
            }
            Ok(actor::Reply::Refused { cause, pending }) => {
                self.pending = pending;
                self.discarded = self.discarded.saturating_add(tail as u64);
                Err(self.refuse(cause))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.receipt = Some(receipt);
                self.discarded = self.discarded.saturating_add(tail as u64);
                Err(self.refuse(Cause::Deadline))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                self.uncertain = true;
                Err(self.refuse(Cause::Supervisor))
            }
        }
    }
    /// Flush and retire this owner. Failure retains the original outstanding
    /// job/receiver; inspecting it does not retry or append more output.
    ///
    /// # Errors
    /// Preserves the first native, stop, deadline or supervisor refusal.
    pub fn finish(mut self) -> Result<Snapshot, Failure> {
        let result = self.flush();
        if let Some(receipt) = &self.receipt {
            match receipt.try_recv() {
                Ok(actor::Reply::Refused { pending, .. }) => {
                    self.pending = pending;
                    self.receipt = None;
                }
                Ok(actor::Reply::Done(_)) => self.receipt = None,
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.uncertain = true;
                    self.receipt = None;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if result.is_err() {
            return Err(Failure {
                owner: Box::new(self),
            });
        }
        Ok(self.snapshot())
    }
}
impl Write for BoundedOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if let Some(cause) = &self.cause {
            return Err(io::Error::new(cause.kind(), Arc::clone(cause)));
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.buffer.len() == CAPACITY {
            let length = match (self.encoding, std::str::from_utf8(&self.buffer)) {
                (Encoding::Bytes, _) | (_, Ok(_)) => self.buffer.len(),
                (_, Err(error)) if error.error_len().is_none() => error.valid_up_to(),
                (_, Err(error)) => {
                    return Err(self.refuse(Cause::Native(io::Error::new(
                        io::ErrorKind::InvalidData,
                        error,
                    ))));
                }
            };
            self.settle(length)?;
        }
        let count = bytes.len().min(CAPACITY - self.buffer.len());
        self.buffer.extend_from_slice(&bytes[..count]);
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        if matches!(self.encoding, Encoding::Utf8)
            && let Err(error) = std::str::from_utf8(&self.buffer)
        {
            return Err(self.refuse(Cause::Native(io::Error::new(
                io::ErrorKind::InvalidData,
                error,
            ))));
        }
        // Even an empty flush goes to the actual original writer.
        self.settle(self.buffer.len())
    }
}
impl Drop for BoundedOutput {
    fn drop(&mut self) {
        // Drop closes admission. A still-pending original job is detached,
        // never joined implicitly or described as quiescent.
        if self
            .supervisor
            .as_ref()
            .is_some_and(JoinHandle::is_finished)
            && let Some(supervisor) = self.supervisor.take()
        {
            let _outcome = supervisor.join();
        }
    }
}
