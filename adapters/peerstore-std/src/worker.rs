//! Explicit one-thread bounded storage worker. The foreground calls start and
//! owns stop/drain/join; constructing the socket Server never creates a thread.
use crate::backend::{Failure, Wal};
use gnunet_peerstore::{Envelope, Request, Response, Storage};
use gnunet_types::Error;
use std::{
    sync::{
        Arc,
        mpsc::{self, SyncSender},
    },
    task::{Context, Poll},
    thread::{self, JoinHandle},
};
use tokio::sync::mpsc as async_mpsc;
/// Original job in this explicit worker domain, never encoded on the wire.
#[derive(Clone, Debug)]
pub struct Job {
    domain: Arc<()>,
    number: u64,
}
impl PartialEq for Job {
    fn eq(&self, o: &Self) -> bool {
        Arc::ptr_eq(&self.domain, &o.domain) && self.number == o.number
    }
}
impl Eq for Job {}
impl Job {
    /// Local diagnostic serial, not reconstructed authority.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.number
    }
}
pub(crate) enum Command {
    Store(Vec<u8>),
    Scan { query: Vec<u8>, after: u64 },
    Expire(u64),
}
struct Submitted {
    job: Job,
    command: Command,
}
pub(crate) struct OwnedRow {
    pub sequence: u64,
    pub frame: Vec<u8>,
}
pub(crate) enum ResultData {
    Store {
        request: Vec<u8>,
        result: Result<u64, Error>,
    },
    Scan(Result<Option<OwnedRow>, Error>),
    Expire(Result<u64, Error>),
}
/// Private actual thread completion. No public arbitrary-success constructor.
pub struct Completion {
    job: Job,
    pub(crate) data: ResultData,
}
impl Completion {
    /// Exact original worker job; only actual receive mints Completion.
    #[must_use]
    pub fn job(&self) -> &Job {
        &self.job
    }
}
/// Original final worker report, only available after real thread termination.
#[derive(Debug)]
pub struct Stopped {
    /// Original WAL uncertainty cause, independently retained.
    pub failure: Option<Failure>,
    /// Rows in the last known committed view; failure retains uncertainty.
    pub records: usize,
    /// Last known committed sequence, without resolving a retained failure.
    pub sequence: u64,
    /// Actual commands completed by the worker, including known refusals.
    pub completed: u64,
}
fn record_frame(record: gnunet_peerstore::Record<'_>) -> Result<Vec<u8>, Error> {
    let response = Response::Record(Envelope {
        rid: 0,
        options: 0,
        reserved: 0,
        record,
    });
    let n = response.encoded_len()?;
    let mut b = Vec::new();
    b.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    b.resize(n, 0);
    response.encode(&mut b)?;
    Ok(b)
}
fn execute(wal: &mut Wal, command: Command) -> ResultData {
    let unavailable = wal.poisoned();
    match command {
        Command::Store(request) => {
            let result = if unavailable {
                Err(Error::Cancelled)
            } else {
                match Request::decode(&request) {
                    Ok(Request::Store(e)) => wal.store(e.record, e.options == 1),
                    Ok(_) => Err(Error::InvalidInput),
                    Err(e) => Err(e),
                }
            };
            ResultData::Store { request, result }
        }
        Command::Scan { query, after } => {
            let result = if unavailable {
                Err(Error::Cancelled)
            } else {
                (|| {
                    let Request::IterateStart(i) = Request::decode(&query)? else {
                        return Err(Error::InvalidInput);
                    };
                    wal.next(i.filter, after)?
                        .map(|r| {
                            record_frame(r.record).map(|frame| OwnedRow {
                                sequence: r.sequence,
                                frame,
                            })
                        })
                        .transpose()
                })()
            };
            ResultData::Scan(result)
        }
        Command::Expire(now) => ResultData::Expire(if unavailable {
            Err(Error::Cancelled)
        } else {
            wal.expire(now)
        }),
    }
}
/// Explicit actual worker ownership, one bounded command/result channel pair.
/// Dropping this owner is not a quiescence receipt; call request_stop, keep
/// polling original completions, and join the original thread before exit.
#[must_use = "Drain and join the explicitly started original storage worker."]
pub struct Worker {
    domain: Arc<()>,
    sender: Option<SyncSender<Submitted>>,
    receiver: async_mpsc::Receiver<Completion>,
    thread: Option<JoinHandle<Stopped>>,
    capacity: usize,
    inflight: usize,
    next: u64,
    ended: bool,
}
impl Worker {
    /// Explicitly start exactly one storage thread for the whole service. Both
    /// queue capacities are fixed; no per-client worker or runtime task exists.
    pub fn start(mut wal: Wal, capacity: usize) -> Result<Self, std::io::Error> {
        if !(1..=4096).contains(&capacity) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "worker capacity must be from 1 through 4096",
            ));
        }
        let (sender, commands) = mpsc::sync_channel::<Submitted>(capacity);
        let (results, receiver) = async_mpsc::channel(capacity);
        let domain = Arc::new(());
        let thread = thread::Builder::new()
            .name("gnunet-peerstore-storage".into())
            .spawn(move || {
                let mut completed = 0_u64;
                while let Ok(submitted) = commands.recv() {
                    let data = execute(&mut wal, submitted.command);
                    completed = completed.saturating_add(1);
                    if results
                        .blocking_send(Completion {
                            job: submitted.job,
                            data,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                Stopped {
                    records: wal.records(),
                    sequence: wal.sequence(),
                    failure: wal.take_failure(),
                    completed,
                }
            })?;
        Ok(Self {
            domain,
            sender: Some(sender),
            receiver,
            thread: Some(thread),
            capacity,
            inflight: 0,
            next: 0,
            ended: false,
        })
    }
    /// Original fixed admitted-job budget, including results not yet observed.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }
    /// Whether another original command may be admitted without waiting.
    #[must_use]
    pub fn available(&self) -> bool {
        self.sender.is_some() && self.inflight < self.capacity
    }
    pub(crate) fn submit(&mut self, command: Command) -> Result<Job, Error> {
        if !self.available() {
            return Err(if self.sender.is_none() {
                Error::Closed
            } else {
                Error::WouldBlock
            });
        }
        let number = self.next.checked_add(1).ok_or(Error::Overflow)?;
        let job = Job {
            domain: self.domain.clone(),
            number,
        };
        self.sender
            .as_ref()
            .ok_or(Error::Closed)?
            .try_send(Submitted {
                job: job.clone(),
                command,
            })
            .map_err(|e| match e {
                mpsc::TrySendError::Full(_) => Error::WouldBlock,
                mpsc::TrySendError::Disconnected(_) => Error::Closed,
            })?;
        self.next = number;
        self.inflight += 1;
        Ok(job)
    }
    /// Poll only actual private completions. Cancellation keeps them queued.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Completion>, Error>> {
        match self.receiver.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(c)) => {
                if !Arc::ptr_eq(&self.domain, &c.job.domain) || self.inflight == 0 {
                    return Poll::Ready(Err(Error::StaleGeneration));
                }
                self.inflight -= 1;
                let unknown = match &c.data {
                    ResultData::Store { result, .. } => result == &Err(Error::OutcomeUnknown),
                    ResultData::Scan(result) => matches!(result, Err(Error::OutcomeUnknown)),
                    ResultData::Expire(result) => result == &Err(Error::OutcomeUnknown),
                };
                if unknown {
                    self.request_stop()
                }
                Poll::Ready(Ok(Some(c)))
            }
            Poll::Ready(None) => {
                self.ended = true;
                if self.inflight != 0 {
                    self.inflight = 0;
                    Poll::Ready(Err(Error::OutcomeUnknown))
                } else {
                    Poll::Ready(Ok(None))
                }
            }
        }
    }
    /// Refuse new admission, then let the original worker drain every already
    /// admitted command. Closing a client alone never cancels committed disk IO.
    pub fn request_stop(&mut self) {
        drop(self.sender.take())
    }
    /// Whether the original thread still needs its explicit actual join.
    #[must_use]
    pub fn needs_join(&self) -> bool {
        self.thread.is_some()
    }
    /// Explicit startup-error cleanup. Every actually received original receipt
    /// is returned to the supplied observer before the original thread is joined.
    pub async fn shutdown(
        &mut self,
        mut observe: impl FnMut(Completion),
    ) -> Result<Stopped, Error> {
        self.request_stop();
        let mut failure = None;
        while !self.ended {
            match core::future::poll_fn(|cx| self.poll(cx)).await {
                Ok(Some(c)) => observe(c),
                Ok(None) => {}
                Err(e) => {
                    if failure.is_none() {
                        failure = Some(e)
                    }
                }
            }
        }
        let stopped = core::future::poll_fn(|cx| self.poll_join(cx)).await?;
        match failure {
            Some(e) => Err(e),
            None => Ok(stopped),
        }
    }
    /// Join only the original actual thread after result-channel quiescence.
    /// Before then this returns WouldBlock and retains the original JoinHandle.
    pub fn poll_join(&mut self, cx: &mut Context<'_>) -> Poll<Result<Stopped, Error>> {
        if !self.ended || self.inflight != 0 || self.sender.is_some() {
            return Poll::Ready(Err(Error::WouldBlock));
        }
        let Some(thread) = self.thread.as_ref() else {
            return Poll::Ready(Err(Error::StaleGeneration));
        };
        if !thread.is_finished() {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let thread = self.thread.take().ok_or(Error::StaleGeneration)?;
        Poll::Ready(thread.join().map_err(|_| Error::OutcomeUnknown))
    }
}
