//! One explicit verifier worker with exactly one reusable1MiB scratch allocation.
//! Certificates are public; no signing key, self-reference or per-job scratch.
use gnunet_revocation::{Certificate, Check, CheckedCertificate, RevocationConfig, pow};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::{Error, Rejected};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
    },
    task::{Context, Poll},
    thread::{self, JoinHandle},
};
use tokio::{
    sync::mpsc as async_mpsc,
    time::{Instant, Sleep},
};
/// Exact original worker request. Canceling this token cannot cancel another job.
#[derive(Clone, Debug)]
pub struct Job {
    domain: Arc<()>,
    serial: u64,
    cancel: Arc<AtomicBool>,
}
impl PartialEq for Job {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.domain, &other.domain)
            && self.serial == other.serial
            && Arc::ptr_eq(&self.cancel, &other.cancel)
    }
}
impl Eq for Job {}
impl Job {
    /// Diagnostic serial, not receipt authority.
    pub const fn diagnostic(&self) -> u64 {
        self.serial
    }
}
/// Original actual work outcome; invalid/canceled is never a checked receipt.
#[derive(Debug)]
pub enum Outcome {
    /// Actual signature/order/current-work/lifetime rejection.
    Invalid,
    /// Original host request canceled between bounded steps.
    Cancelled,
    /// Original logical/native deadline.
    Deadline,
    /// Original clock failure.
    Clock(Error),
    /// Actual primitive/resource failure.
    Fault(Error),
    /// Actual32hash/signature/lifetime receipt.
    Checked(Box<CheckedCertificate>),
}
/// Only the original worker channel creates a completion.
#[derive(Debug)]
pub struct Completion {
    job: Job,
    outcome: Outcome,
}
impl Completion {
    /// Observe original identity without consuming the result.
    pub fn job(&self) -> &Job {
        &self.job
    }
    /// Consume the actual result once; no work or acknowledgement is invented.
    pub fn into_parts(self) -> (Job, Outcome) {
        (self.job, self.outcome)
    }
}
struct Command {
    job: Job,
    certificate: Certificate,
    until: u64,
    hard: Instant,
}
/// Actual original thread join report.
#[derive(Debug)]
pub struct Stopped {
    /// Actual completed commands, including canceled/invalid checks.
    pub completed: u64,
}
/// One fixed native worker; constructor performs the explicit allocation/spawn.
pub struct Worker {
    domain: Arc<()>,
    sender: Option<SyncSender<Command>>,
    receiver: async_mpsc::Receiver<Completion>,
    thread: Option<JoinHandle<Stopped>>,
    active: Option<Job>,
    next: u64,
    ended: bool,
    join_alarm: Option<Pin<Box<Sleep>>>,
}
fn guard(command: &Command, clock: &dyn RuntimeClock) -> Result<u64, Outcome> {
    if command.job.cancel.load(Ordering::Acquire) {
        return Err(Outcome::Cancelled);
    }
    if Instant::now() >= command.hard {
        return Err(Outcome::Deadline);
    }
    let now = clock.sample().map_err(Outcome::Clock)?.now.as_micros();
    if now >= command.until {
        return Err(Outcome::Deadline);
    }
    Ok(now)
}
fn run(
    command: &Command,
    clock: &dyn RuntimeClock,
    policy: RevocationConfig,
    memory: &mut [pow::Block],
) -> Outcome {
    if let Err(outcome) = guard(command, clock) {
        return outcome;
    }
    let mut check = match Check::new(&command.certificate, policy) {
        Ok(Some(check)) => check,
        Ok(None) => return Outcome::Invalid,
        Err(e) => return Outcome::Fault(e),
    };
    while check.completed_hashes() < 32 {
        if let Err(outcome) = guard(command, clock) {
            return outcome;
        }
        if let Err(e) = check.step(memory) {
            return Outcome::Fault(e);
        }
    }
    let now = match guard(command, clock) {
        Ok(now) => now,
        Err(outcome) => return outcome,
    };
    match check.finish_at(now) {
        Ok(Some(receipt)) => Outcome::Checked(Box::new(receipt)),
        Ok(None) => Outcome::Invalid,
        Err(e) => Outcome::Fault(e),
    }
}
impl Worker {
    /// Explicit spawn, after privileges and shared-clock construction. One scratch
    /// is allocated before spawn; no native operation is performed by Limits.
    pub fn start(
        clock: Arc<dyn RuntimeClock>,
        policy: RevocationConfig,
    ) -> Result<Self, std::io::Error> {
        if policy.matching_bits >= 512 || policy.epoch_duration == 0 {
            return Err(std::io::ErrorKind::InvalidInput.into());
        }
        let mut memory = Vec::new();
        memory
            .try_reserve_exact(pow::MEMORY_BLOCKS)
            .map_err(std::io::Error::other)?;
        memory.resize_with(pow::MEMORY_BLOCKS, pow::Block::default);
        let (sender, commands) = mpsc::sync_channel::<Command>(1);
        let (results, receiver) = async_mpsc::channel(1);
        let domain = Arc::new(());
        let thread = thread::Builder::new()
            .name("gnunet-revocation-verify".into())
            .spawn(move || {
                let mut completed = 0u64;
                while let Ok(command) = commands.recv() {
                    let outcome = run(&command, clock.as_ref(), policy, &mut memory);
                    completed = completed.saturating_add(1);
                    if results
                        .blocking_send(Completion {
                            job: command.job,
                            outcome,
                        })
                        .is_err()
                    {
                        break;
                    }
                }
                Stopped { completed }
            })?;
        Ok(Self {
            domain,
            sender: Some(sender),
            receiver,
            thread: Some(thread),
            active: None,
            next: 0,
            ended: false,
            join_alarm: None,
        })
    }
    /// Actual one-job admission availability, including unobserved completion.
    pub fn available(&self) -> bool {
        self.sender.is_some() && self.active.is_none() && !self.ended
    }
    /// Admit exactly one public certificate into the original queue. Refusal
    /// returns it intact and creates no job or validation assertion.
    pub fn submit(
        &mut self,
        certificate: Certificate,
        until: u64,
        hard: Instant,
    ) -> Result<Job, Box<Rejected<Certificate>>> {
        let refuse = |reason, value| Box::new(Rejected { reason, value });
        if !self.available() {
            return Err(refuse(Error::WouldBlock, certificate));
        }
        let Some(serial) = self.next.checked_add(1) else {
            return Err(refuse(Error::Overflow, certificate));
        };
        let job = Job {
            domain: self.domain.clone(),
            serial,
            cancel: Arc::new(AtomicBool::new(false)),
        };
        let Some(sender) = &self.sender else {
            return Err(refuse(Error::Closed, certificate));
        };
        if let Err(e) = sender.try_send(Command {
            job: job.clone(),
            certificate,
            until,
            hard,
        }) {
            let (reason, command) = match e {
                mpsc::TrySendError::Full(c) => (Error::WouldBlock, c),
                mpsc::TrySendError::Disconnected(c) => (Error::Closed, c),
            };
            return Err(refuse(reason, command.certificate));
        }
        self.next = serial;
        self.active = Some(job.clone());
        Ok(job)
    }
    /// Signal only the exact original job; no clock/IO is required. A hash already
    /// running may finish, then the original guard suppresses a checked receipt.
    pub fn cancel(&self, job: &Job) -> Result<(), Error> {
        if self.active.as_ref() != Some(job) {
            return Err(Error::Stale);
        }
        job.cancel.store(true, Ordering::Release);
        Ok(())
    }
    /// Observe only the actual bounded worker channel.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Completion>, Error>> {
        match self.receiver.poll_recv(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(c)) => {
                if self.active.as_ref() != Some(&c.job) {
                    return Poll::Ready(Err(Error::Stale));
                }
                self.active = None;
                Poll::Ready(Ok(Some(c)))
            }
            Poll::Ready(None) => {
                self.ended = true;
                if self.active.take().is_some() {
                    Poll::Ready(Err(Error::OutcomeUnknown))
                } else {
                    Poll::Ready(Ok(None))
                }
            }
        }
    }
    /// Stop new work and request bounded-step cancellation of the original check.
    pub fn request_stop(&mut self) {
        if let Some(job) = &self.active {
            job.cancel.store(true, Ordering::Release)
        }
        drop(self.sender.take());
    }
    /// Drain actual completions and physically join the original worker. No
    /// background verifier survives this owner. CPU/OS progress is still required.
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
                        first = Some(e)
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
    /// Join only after the original channel actually ended. A retained1ms timer
    /// observes thread completion without a busy wake loop or forged quiescence.
    pub fn poll_join(&mut self, cx: &mut Context<'_>) -> Poll<Result<Stopped, Error>> {
        if !self.ended || self.active.is_some() || self.sender.is_some() {
            return Poll::Ready(Err(Error::WouldBlock));
        }
        let Some(thread) = &self.thread else {
            return Poll::Ready(Err(Error::Closed));
        };
        if !thread.is_finished() {
            let timer = self.join_alarm.get_or_insert_with(|| {
                Box::pin(tokio::time::sleep(std::time::Duration::from_millis(1)))
            });
            if timer.as_mut().poll(cx).is_ready() {
                self.join_alarm = None;
                cx.waker().wake_by_ref()
            }
            return Poll::Pending;
        }
        let Some(thread) = self.thread.take() else {
            return Poll::Ready(Err(Error::Closed));
        };
        Poll::Ready(thread.join().map_err(|_| Error::OutcomeUnknown))
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.request_stop();
        self.receiver.close();
        if let Some(thread) = self.thread.take() {
            let _joined = thread.join();
        }
    }
}
