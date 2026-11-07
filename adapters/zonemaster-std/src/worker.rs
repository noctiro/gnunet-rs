//! Actual bounded workers: durable expiration reservation, then Rust crypto.
//! No key file, entropy, native crypto actor, network or detached task is used.
use crate::{Failure, nonce};
use gnunet_types::{Error as Fault, Rejected};
use gnunet_zonemaster::{
    material::Sealed,
    schedule::{Job, Sealing},
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender, TrySendError},
    },
    task::{Context, Poll},
    thread::{self, JoinHandle},
};
use tokio::{sync::mpsc as results, time::Instant};
struct Input {
    sealing: Sealing,
    hard: Instant,
    cancel: Arc<AtomicBool>,
}
/// Original admitted worker interest. Cancel is local; only an actual completion
/// or joined worker proves input crypto/key ownership has retired.
pub struct Ticket {
    job: Job,
    cancel: Arc<AtomicBool>,
}
impl Ticket {
    /// Original private binding, never a wire identity or secret hash.
    pub const fn job(&self) -> Job {
        self.job
    }
    /// Signal original interest cancellation without reading key material.
    pub fn cancel(&self) {
        self.cancel.store(true, Ordering::Release)
    }
}
/// One actual worker return. Fields cannot be forged by a port caller.
pub struct Completion {
    job: Job,
    expires: u64,
    result: Result<Sealed, Fault>,
    cause: Option<Arc<nonce::Failure>>,
    reservation: Option<nonce::Receipt>,
}
/// Consumed original completion observations. Constructing this projection does
/// not construct Completion or an input/assignment authority.
pub struct Returned {
    /// Original admitted job.
    pub job: Job,
    /// Original logical target, never renewed by reservation IO.
    pub expires: u64,
    /// Actual ciphertext or original pure failure classification.
    pub result: Result<Sealed, Fault>,
    /// Independent actual persistent authority failure.
    pub cause: Option<Arc<nonce::Failure>>,
    /// Actual local durable allocation even when the later job was canceled.
    pub reservation: Option<nonce::Receipt>,
}
impl Completion {
    /// Consume the actual original binding and independent output/IO facts.
    pub fn into_parts(self) -> Returned {
        Returned {
            job: self.job,
            expires: self.expires,
            result: self.result,
            cause: self.cause,
            reservation: self.reservation,
        }
    }
}
enum RetiredFailure {
    Nonce(Arc<nonce::Failure>),
    Pure(Fault),
}
impl RetiredFailure {
    fn from_completion(completion: Completion) -> Option<Self> {
        if let Some(error) = completion.cause {
            Some(Self::Nonce(error))
        } else if let Err(error) = completion.result
            && !matches!(error, Fault::Cancelled | Fault::Deadline)
        {
            Some(Self::Pure(error))
        } else {
            None
        }
    }
}
/// Bounded owned worker group. No actual worker is started until new is called.
/// Its production lifecycle has not been executed in the candidate workflow.
pub struct Pool {
    input: Option<SyncSender<Input>>,
    output: Option<results::Receiver<Completion>>,
    threads: Vec<Option<JoinHandle<Result<(), Fault>>>>,
    stop: Arc<AtomicBool>,
    authority: Arc<nonce::Authority>,
    // A failed completion send ends that worker immediately, so each worker
    // contributes at most one terminal failure. No plaintext/ciphertext stays.
    undelivered: Arc<Mutex<[Option<RetiredFailure>; 64]>>,
}
impl Pool {
    /// Start bounded reservation/crypto workers without opening a store yet.
    /// Partial startup failure closes/wakes/joins every original worker.
    pub fn new(count: usize, queued: usize, nonce: nonce::Config) -> Result<Self, Failure> {
        if count == 0 || count > 64 || queued == 0 || queued > 50000 {
            return Err(Fault::Capacity.into());
        }
        let (input, receiver) = mpsc::sync_channel::<Input>(queued);
        let receiver = Arc::new(Mutex::new(receiver));
        let (sender, output) = results::channel(queued);
        let stop = Arc::new(AtomicBool::new(false));
        let mut threads = Vec::new();
        threads
            .try_reserve_exact(count)
            .map_err(|_| Fault::Capacity)?;
        let mut pool = Self {
            input: Some(input),
            output: Some(output),
            threads,
            stop,
            authority: Arc::new(nonce::Authority::new(nonce)),
            undelivered: Arc::new(Mutex::new(std::array::from_fn(|_| None))),
        };
        for index in 0..count {
            let receiver = receiver.clone();
            let sender = sender.clone();
            let stopped = pool.stop.clone();
            let authority = pool.authority.clone();
            let undelivered = pool.undelivered.clone();
            let created = thread::Builder::new()
                .name(format!("gnunet-zonemaster-{index}"))
                .spawn(move || -> Result<(), Fault> {
                    loop {
                        if stopped.load(Ordering::Acquire) {
                            return Ok(());
                        }
                        let input = {
                            let locked = receiver.lock().map_err(|_| Fault::Io)?;
                            match locked.recv() {
                                Ok(input) => input,
                                Err(_) => return Ok(()),
                            }
                        };
                        let Input {
                            sealing,
                            hard,
                            cancel,
                        } = input;
                        let Sealing {
                            job,
                            expires,
                            input: prepared,
                        } = sealing;
                        let mut cause = None;
                        let mut reservation = None;
                        let result = if stopped.load(Ordering::Acquire)
                            || cancel.load(Ordering::Acquire)
                        {
                            Err(Fault::Cancelled)
                        } else if Instant::now() >= hard {
                            Err(Fault::Deadline)
                        } else if let Some(error) = authority.failure() {
                            let reason = error.reason();
                            cause = Some(error);
                            Err(reason)
                        } else {
                            let attempted =
                                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                    let mut plan = prepared.into_sealing()?;
                                    let request = plan.request()?;
                                    let granted = match authority
                                        .reserve(request, &stopped, &cancel, hard)
                                    {
                                        Ok(granted) => granted,
                                        Err(error) => {
                                            let reason = error.reason();
                                            if !matches!(reason, Fault::Cancelled | Fault::Deadline)
                                                || error.has_original()
                                            {
                                                cause = Some(error);
                                            }
                                            return Err(reason);
                                        }
                                    };
                                    reservation = Some(granted.receipt);
                                    // Reservation is already durably consumed. A late
                                    // interest now drops its assignment and never seals.
                                    if stopped.load(Ordering::Acquire)
                                        || cancel.load(Ordering::Acquire)
                                    {
                                        return Err(Fault::Cancelled);
                                    }
                                    if Instant::now() >= hard {
                                        return Err(Fault::Deadline);
                                    }
                                    plan.seal(granted.expirations)
                                }));
                            match attempted {
                                Ok(result) => result,
                                Err(_) => {
                                    let error = authority.panicked();
                                    let reason = error.reason();
                                    cause = Some(error);
                                    Err(reason)
                                }
                            }
                        };
                        // Never replace an original IO/crypto failure with a late
                        // cancellation. Only a successful ciphertext is discarded.
                        let result = if result.is_ok() {
                            if stopped.load(Ordering::Acquire) || cancel.load(Ordering::Acquire) {
                                drop(result);
                                Err(Fault::Cancelled)
                            } else if Instant::now() >= hard {
                                drop(result);
                                Err(Fault::Deadline)
                            } else {
                                result
                            }
                        } else {
                            result
                        };
                        if let Err(rejected) = sender.blocking_send(Completion {
                            job,
                            expires,
                            result,
                            cause,
                            reservation,
                        }) {
                            if let Some(error) = RetiredFailure::from_completion(rejected.0) {
                                let mut slots =
                                    undelivered.lock().unwrap_or_else(|p| p.into_inner());
                                // count <=64; index is this thread's private creation
                                // index, and this exact worker exits after setting it.
                                slots[index] = Some(error);
                            }
                            return Ok(());
                        }
                    }
                });
            match created {
                Ok(thread) => pool.threads.push(Some(thread)),
                Err(original) => {
                    pool.begin_stop();
                    let cleanup = pool.join_all().err().into_iter().collect::<Vec<_>>();
                    return Err(format!(
                        "zonemaster worker start: {original}; independent joins: {cleanup:?}"
                    )
                    .into());
                }
            }
        }
        Ok(pool)
    }
    /// Mark one actual first failure observed before dropping any late result.
    pub(crate) fn observe_nonce_failure(&self, error: &Arc<nonce::Failure>) -> bool {
        self.authority.observe_failure(error)
    }
    /// Drain original terminal causes only after actual workers have joined.
    /// Closing the output never drops its queued completions; failed sends use
    /// one fixed slot per retiring worker. The first global cause is deduplicated.
    pub(crate) fn take_retired_failure(&mut self) -> Option<Failure> {
        loop {
            let queued = self
                .output
                .as_mut()
                .and_then(|output| output.try_recv().ok());
            let had_queued = queued.is_some();
            let next = if let Some(completion) = queued {
                RetiredFailure::from_completion(completion)
            } else {
                self.undelivered
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .iter_mut()
                    .find_map(Option::take)
            };
            match next {
                Some(RetiredFailure::Nonce(error)) => {
                    if self.authority.observe_failure(&error) {
                        return Some(Box::new(error));
                    }
                }
                Some(RetiredFailure::Pure(error)) => return Some(Box::new(error)),
                None if had_queued => continue,
                None => {
                    return self
                        .authority
                        .take_failure()
                        .map(|error| Box::new(error) as Failure);
                }
            }
        }
    }
    /// Latest actual local reservation metadata, after real worker retirement.
    pub(crate) fn take_last_reservation(&self) -> Option<nonce::Receipt> {
        self.authority.take_latest()
    }
    /// Actual bounded admission, returning the unchanged original input on
    /// refusal. Neither this Ticket nor queue success proves sealing occurred.
    #[expect(
        clippy::result_large_err,
        reason = "Refused worker admission returns the exact bounded zeroizing original material without a further allocation to report the error."
    )]
    pub fn submit(&mut self, sealing: Sealing, hard: Instant) -> Result<Ticket, Rejected<Sealing>> {
        let Some(sender) = &self.input else {
            return Err(Rejected {
                value: sealing,
                reason: Fault::Closed,
            });
        };
        if Instant::now() >= hard {
            return Err(Rejected {
                value: sealing,
                reason: Fault::Deadline,
            });
        }
        if let Some(error) = self.authority.failure() {
            return Err(Rejected {
                value: sealing,
                reason: error.reason(),
            });
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let job = sealing.job;
        match sender.try_send(Input {
            sealing,
            hard,
            cancel: cancel.clone(),
        }) {
            Ok(()) => Ok(Ticket { job, cancel }),
            Err(TrySendError::Full(input)) => Err(Rejected {
                value: input.sealing,
                reason: Fault::WouldBlock,
            }),
            Err(TrySendError::Disconnected(input)) => Err(Rejected {
                value: input.sealing,
                reason: Fault::Closed,
            }),
        }
    }
    /// Poll one real original worker completion. Canceling this wait cannot
    /// rerun a seal or lose an already admitted original task.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Option<Completion>> {
        match &mut self.output {
            Some(output) => output.poll_recv(cx),
            None => Poll::Ready(None),
        }
    }
    /// Close channels and signal workers without a clock/crypto call. Closing
    /// the result receiver unblocks senders while retaining its bounded original
    /// queued facts for transfer after joins; each failed sender then exits.
    pub fn begin_stop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.input = None;
        if let Some(output) = self.output.as_mut() {
            output.close();
        }
    }
    /// True only after actual OS threads report finished. No optimistic token.
    pub fn finished(&self) -> bool {
        self.threads
            .iter()
            .all(|h| h.as_ref().is_none_or(JoinHandle::is_finished))
    }
    /// Join only actual finished workers; caller can drive a finite native
    /// shutdown alarm without blocking live DNS/NAMESTORE/cache/publication IO.
    pub fn try_join(&mut self) -> Result<bool, Failure> {
        let mut failure = None;
        for slot in &mut self.threads {
            if slot.as_ref().is_some_and(JoinHandle::is_finished)
                && let Some(thread) = slot.take()
            {
                match thread.join() {
                    Ok(Ok(())) => {}
                    Ok(Err(e)) => failure = Some(e),
                    Err(_) => failure = Some(Fault::Io),
                }
            }
        }
        if let Some(e) = failure {
            return Err(e.into());
        }
        Ok(self.threads.iter().all(Option::is_none))
    }
    /// Physical final CPU retirement. Call only after all external native owners
    /// are stopped, or finished() proves this cannot block the foreground.
    pub fn join_all(&mut self) -> Result<(), Failure> {
        self.begin_stop();
        let mut failures = 0usize;
        for thread in &mut self.threads {
            if let Some(thread) = thread.take()
                && !matches!(thread.join(), Ok(Ok(())))
            {
                failures = failures.saturating_add(1);
            }
        }
        if failures != 0 {
            return Err(format!("{failures} zonemaster workers failed during actual join").into());
        }
        Ok(())
    }
}
impl Drop for Pool {
    fn drop(&mut self) {
        self.begin_stop();
        let _actual = self.join_all();
    }
}
