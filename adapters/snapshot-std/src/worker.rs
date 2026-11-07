//! Exactly one explicit bounded disk worker. The caller owns start/drain/join.
//! Canonical secret state stays in the pure service; only one zeroizing owned
//! serialized snapshot crosses this original worker's channel.
use crate::backend::{Committed, Failure, Namespace, Store};
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
use zeroize::Zeroizing;
/// One actual original worker admission, private domain and checked serial.
#[derive(Clone, Debug)]
pub struct Job {
    namespace: Namespace,
    domain: Arc<()>,
    serial: u64,
}
impl PartialEq for Job {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.domain, &other.domain)
            && self.serial == other.serial
            && self.namespace == other.namespace
    }
}
impl Eq for Job {}
impl Job {
    /// Original qualified worker namespace, diagnostic metadata only.
    #[must_use]
    pub const fn namespace(&self) -> Namespace {
        self.namespace
    }

    /// Diagnostic only; cannot reconstruct actual completion authority.
    #[must_use]
    pub const fn value(&self) -> u64 {
        self.serial
    }
}
struct Command {
    job: Job,
    expected: u64,
    body: Zeroizing<Vec<u8>>,
}
/// A private actual worker result. No arbitrary successful constructor is exposed.
pub struct Completion {
    job: Job,
    result: Result<Committed, Arc<Failure>>,
}
impl Completion {
    /// Actual original job from the one owned worker channel.
    #[must_use]
    pub fn job(&self) -> &Job {
        &self.job
    }
    /// Consume original physical persistence outcome, with no secret payload.
    pub fn into_parts(self) -> (Job, Result<Committed, Arc<Failure>>) {
        (self.job, self.result)
    }
}
/// Only actual thread join yields this report; it contains public metadata only.
#[derive(Debug)]
pub struct Stopped {
    /// Namespace of the actual joined original writer.
    pub namespace: Namespace,
    /// Last definitely committed generation, not an attempted-write counter.
    pub generation: u64,
    /// Actual disk worker commands finished.
    pub completed: u64,
    /// Original independent store failure when present.
    pub failure: Option<Arc<Failure>>,
}
/// One explicit storage thread, one admitted job, one bounded completion. There
/// is no per-client worker, ambient thread creation or late detached publisher.
pub struct Worker {
    namespace: Namespace,
    domain: Arc<()>,
    sender: Option<SyncSender<Command>>,
    receiver: async_mpsc::Receiver<Completion>,
    thread: Option<JoinHandle<Stopped>>,
    next: u64,
    inflight: bool,
    ended: bool,
}
impl Worker {
    /// Explicitly start the sole disk thread after configured UID/GID setup.
    pub fn start(mut store: Store) -> Result<Self, std::io::Error> {
        let namespace = store.namespace();
        let (sender, requests) = mpsc::sync_channel::<Command>(1);
        let (results, receiver) = async_mpsc::channel(1);
        let domain = Arc::new(());
        let thread = thread::Builder::new()
            .name(namespace.thread_name().into())
            .spawn(move || {
                let mut completed = 0u64;
                while let Ok(command) = requests.recv() {
                    let result = store.commit(command.expected, command.body);
                    completed = completed.saturating_add(1);
                    let failed = result.is_err();
                    if results
                        .blocking_send(Completion {
                            job: command.job,
                            result,
                        })
                        .is_err()
                        || failed
                    {
                        break;
                    }
                }
                Stopped {
                    namespace,
                    generation: store.generation(),
                    completed,
                    failure: store.failure().cloned(),
                }
            })?;
        Ok(Self {
            namespace,
            domain,
            sender: Some(sender),
            receiver,
            thread: Some(thread),
            next: 0,
            inflight: false,
            ended: false,
        })
    }
    /// Original immutable qualified namespace of this explicit worker.
    #[must_use]
    pub const fn namespace(&self) -> Namespace {
        self.namespace
    }
    /// Actual original single-command admission capacity, including unobserved result.
    #[must_use]
    pub fn available(&self) -> bool {
        self.sender.is_some() && !self.inflight && !self.ended
    }
    /// Reserve actual owned body into the original queue. Admission failure
    /// returns the original zeroizing bytes unchanged; no successful job is minted.
    pub fn submit(
        &mut self,
        expected: u64,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<Job, (Error, Zeroizing<Vec<u8>>)> {
        if !self.available() {
            return Err((
                if self.sender.is_some() {
                    Error::WouldBlock
                } else {
                    Error::Closed
                },
                body,
            ));
        }
        let Some(serial) = self.next.checked_add(1) else {
            return Err((Error::Overflow, body));
        };
        let job = Job {
            namespace: self.namespace,
            domain: self.domain.clone(),
            serial,
        };
        let Some(sender) = &self.sender else {
            return Err((Error::Closed, body));
        };
        if let Err(e) = sender.try_send(Command {
            job: job.clone(),
            expected,
            body,
        }) {
            return Err(match e {
                mpsc::TrySendError::Full(c) => (Error::WouldBlock, c.body),
                mpsc::TrySendError::Disconnected(c) => (Error::Closed, c.body),
            });
        }
        self.next = serial;
        self.inflight = true;
        Ok(job)
    }
    /// Poll only an actual private completion. Waiting future cancellation keeps
    /// the same channel/result/job and cannot replay or abandon the admitted write.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Completion>, Error>> {
        match self.receiver.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(completion)) => {
                if !self.inflight
                    || !Arc::ptr_eq(&completion.job.domain, &self.domain)
                    || completion.job.namespace != self.namespace
                {
                    return Poll::Ready(Err(Error::Stale));
                }
                self.inflight = false;
                if completion.result.is_err() {
                    self.request_stop();
                }
                Poll::Ready(Ok(Some(completion)))
            }
            Poll::Ready(None) => {
                self.ended = true;
                if self.inflight {
                    self.inflight = false;
                    Poll::Ready(Err(Error::OutcomeUnknown))
                } else {
                    Poll::Ready(Ok(None))
                }
            }
        }
    }
    /// Refuse new jobs while preserving the original admitted IO until its actual outcome.
    pub fn request_stop(&mut self) {
        drop(self.sender.take());
    }
    /// Close admission, consume every original actual completion, then join the
    /// real original thread. OS filesystem calls can block: a socket deadline is
    /// not a claimed cancellation of an in-progress fsync/rename.
    pub async fn shutdown(
        &mut self,
        mut observe: impl FnMut(Completion),
    ) -> Result<Stopped, Error> {
        self.request_stop();
        let mut first = None;
        while !self.ended {
            match std::future::poll_fn(|cx| self.poll(cx)).await {
                Ok(Some(c)) => observe(c),
                Ok(None) => {}
                Err(e) => {
                    if first.is_none() {
                        first = Some(e);
                    }
                }
            }
        }
        let stopped = std::future::poll_fn(|cx| self.poll_join(cx)).await?;
        match first {
            Some(e) => Err(e),
            None => Ok(stopped),
        }
    }
    /// Join only after actual result-channel termination; no guessed quiescence.
    pub fn poll_join(&mut self, cx: &mut Context<'_>) -> Poll<Result<Stopped, Error>> {
        if !self.ended || self.inflight || self.sender.is_some() {
            return Poll::Ready(Err(Error::WouldBlock));
        }
        let Some(thread) = &self.thread else {
            return Poll::Ready(Err(Error::Stale));
        };
        if !thread.is_finished() {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let thread = self.thread.take().ok_or(Error::Stale)?;
        Poll::Ready(thread.join().map_err(|_| Error::OutcomeUnknown))
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.request_stop();
        self.receiver.close(); // Wake a blocked result sender before joining.
        if let Some(thread) = self.thread.take() {
            // No detached filesystem writer can outlive the original store/fence
            // owner. This emergency fallback may wait for actual OS IO progress.
            let _joined = thread.join();
        }
    }
}
