//! Original-open DHT discovery. A validated public path is only a routing hint;
//! the normal Book CREATE and authenticated tunnel still establish the channel.
use gnunet_cadet_host::{node::Discovery, time::Timebase};
use gnunet_client_host::EndpointSource;
use gnunet_dht_client_host::{self as dht, Action, Cancel, Event, GetId, Progress};
use gnunet_hello::{AbsoluteTime, Hello, SignatureProfile};
use gnunet_types::Error as Fault;
use std::{
    error::Error,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};

// Fixed C cadet_dht.c GCD_search: typed public HELLO and these public options.
const HELLO: u32 = 13;
const RECORD_ROUTE: u32 = 2;
const DEMULTIPLEX: u32 = 1;
type Result<T> = std::result::Result<T, Box<dyn Error>>;
#[cfg(test)]
mod profile_tests;
pub(super) struct Policy {
    pub maximum: usize,
    pub path_peers: usize,
    pub replication: u32,
    pub signature_profile: SignatureProfile,
}
struct Candidate {
    path: Vec<[u8; 32]>,
    expires: u64,
}
struct Job<'dht, 'app> {
    original: Discovery<'app>,
    get: GetId<'dht>,
    key: [u8; 64],
    hard: Instant,
    stopping: bool,
    candidate: Option<Candidate>,
    candidate_source: Option<dht::Epoch<'dht>>,
}
#[derive(Debug, Default)]
pub(super) struct Report<'dht> {
    pub started: u64,
    pub stop_requested: u64,
    pub stop_unissued: u64,
    pub stop_written: u64,
    pub stopped_by_retirement: u64,
    pub admitted_paths: u64,
    pub rejected_paths: u64,
    pub expired_opens: u64,
    pub source_losses: u64,
    pub first_loss: Option<Arc<dht::LossCause>>,
    pub last_epoch: Option<dht::Epoch<'dht>>,
    pub last_loss: Option<Arc<dht::LossCause>>,
    pub retry_attempts: u64,
    pub first_retry: Option<Arc<std::io::Error>>,
    pub last_rejection: Option<Fault>,
    pub last_candidate_source: Option<dht::Epoch<'dht>>,
    pub last_admitted_source: Option<dht::Epoch<'dht>>,
    pub closed: bool,
}
pub(super) struct Path<'a, 'app> {
    pub original: Discovery<'app>,
    pub peers: &'a [[u8; 32]],
    pub observed: gnunet_types::MonoInstant,
}
pub(super) struct Driver<'dht, 'app> {
    client: dht::Client<'dht>,
    timebase: Timebase,
    local: [u8; 32],
    policy: Policy,
    jobs: Vec<Job<'dht, 'app>>,
    scratch: Vec<u8>,
    timer: Option<(Instant, Pin<Box<Sleep>>)>,
    report: Report<'dht>,
}
impl<'dht, 'app> Driver<'dht, 'app> {
    pub(super) fn new(
        instance: &'dht mut dht::Instance,
        source: EndpointSource,
        timebase: Timebase,
        local: [u8; 32],
        policy: Policy,
    ) -> Result<Self> {
        let maximum = policy.maximum;
        let path_peers = policy.path_peers;
        if maximum == 0 || path_peers < 2 {
            return Err(Fault::InvalidInput.into());
        }
        if !Arc::ptr_eq(&source.clock(), &timebase.source()) {
            return Err(Fault::Conflict.into());
        }
        let mut limits = dht::Limits::default();
        limits.protocol.gets = maximum;
        limits.protocol.monitors = 0;
        limits.protocol.hellos = 0;
        limits.protocol.operations = 0;
        limits.protocol.known_per_get = 0; // A new path for the same HELLO remains useful.
        limits.protocol.source_bytes = maximum.checked_mul(256).ok_or(Fault::Overflow)?;
        let client = dht::Client::new(instance, source, limits)?;
        let mut jobs = Vec::new();
        jobs.try_reserve_exact(maximum)?;
        let mut scratch = Vec::new();
        scratch.try_reserve_exact(65535)?;
        scratch.resize(65535, 0);
        Ok(Self {
            client,
            timebase,
            local,
            policy,
            jobs,
            scratch,
            timer: None,
            report: Report::default(),
        })
    }
    pub(super) fn report(&self) -> &Report<'dht> {
        &self.report
    }
    pub(super) fn contains(&self, original: Discovery<'app>) -> bool {
        self.jobs.iter().any(|job| job.original == original)
    }
    pub(super) fn start(&mut self, original: Discovery<'app>, hard: Instant) -> Result<()> {
        if self.report.closed {
            return Err(Fault::Closed.into());
        }
        if self.contains(original) {
            return Ok(());
        }
        if self.jobs.len() == self.policy.maximum {
            return Err(Fault::WouldBlock.into());
        }
        let hard = hard.min(self.timebase.native_bound(original.expires)?);
        let now = self.timebase.sample()?.monotonic;
        if now >= original.expires || Instant::now() >= hard {
            return Err(Fault::Deadline.into());
        }
        let mut key = [0; 64];
        key[..32].copy_from_slice(&original.peer);
        let get = self.client.get(dht::Get {
            key: &key,
            block_type: HELLO,
            options: RECORD_ROUTE | DEMULTIPLEX,
            replication: self.policy.replication,
            extended_query: &[],
        })?;
        self.jobs.push(Job {
            original,
            get,
            key,
            hard,
            stopping: false,
            candidate: None,
            candidate_source: None,
        });
        self.report.started = self.report.started.saturating_add(1);
        Ok(())
    }
    fn stop(&mut self, index: usize) -> Result<()> {
        if self.jobs[index].stopping {
            return Ok(());
        }
        let cancel = self.client.stop(self.jobs[index].get)?;
        self.report.stop_requested = self.report.stop_requested.saturating_add(1);
        self.jobs[index].candidate = None;
        match cancel {
            Cancel::BeforeIssue => {
                self.jobs.remove(index);
                self.report.stop_unissued = self.report.stop_unissued.saturating_add(1);
            }
            Cancel::Draining => self.jobs[index].stopping = true,
        }
        Ok(())
    }
    fn lost(&mut self, epoch: dht::Epoch<'dht>, cause: dht::LossCause) {
        self.report.source_losses = self.report.source_losses.saturating_add(1);
        self.report.last_epoch = Some(epoch);
        let cause = Arc::new(cause);
        self.report
            .first_loss
            .get_or_insert_with(|| Arc::clone(&cause));
        self.report.last_loss = Some(cause);
        let before = self.jobs.len();
        // The real client has physically retired this MQ and removed cancelled GETs.
        self.jobs.retain(|job| !job.stopping);
        self.report.stopped_by_retirement = self
            .report
            .stopped_by_retirement
            .saturating_add((before - self.jobs.len()) as u64);
    }
    fn retire(&mut self) -> Result<()> {
        if let Some(Progress::Lost { epoch, cause, .. }) = self.client.retire_io()? {
            self.lost(epoch, cause);
        } else {
            let before = self.jobs.len();
            self.jobs.retain(|job| !job.stopping);
            self.report.stopped_by_retirement = self
                .report
                .stopped_by_retirement
                .saturating_add((before - self.jobs.len()) as u64);
        }
        Ok(())
    }
    /// Run before any discovery IO. Expiry returns the exact original open for
    /// clock-free local cancellation. Other live GETs retain their original IDs,
    /// hard targets and logical intents when the shared MQ must be retired.
    pub(super) fn maintain(
        &mut self,
        mut current: impl FnMut(Discovery<'app>) -> bool,
    ) -> Result<Option<Discovery<'app>>> {
        let native = Instant::now();
        if let Some(index) = self.jobs.iter().position(|job| native >= job.hard) {
            let original = self.jobs[index].original;
            let was_current = current(original);
            self.stop(index)?;
            self.retire()?;
            if was_current {
                self.report.expired_opens = self.report.expired_opens.saturating_add(1);
                return Ok(Some(original));
            }
        }
        let now = self.timebase.sample()?.monotonic;
        let mut index = 0;
        while index < self.jobs.len() {
            if !self.jobs[index].stopping
                && (now >= self.jobs[index].original.expires || !current(self.jobs[index].original))
            {
                let original = self.jobs[index].original;
                let expired = now >= original.expires && current(original);
                let before = self.jobs.len();
                self.stop(index)?;
                if expired {
                    self.report.expired_opens = self.report.expired_opens.saturating_add(1);
                    return Ok(Some(original));
                }
                if self.jobs.len() < before {
                    continue;
                }
            }
            index += 1;
        }
        Ok(None)
    }
    pub(super) fn candidate(&mut self) -> Result<Option<Path<'_, 'app>>> {
        let sample = self.timebase.sample()?;
        let absolute = sample.absolute.as_micros();
        for job in &mut self.jobs {
            if job
                .candidate
                .as_ref()
                .is_some_and(|path| absolute >= path.expires)
            {
                job.candidate = None;
                self.report.rejected_paths = self.report.rejected_paths.saturating_add(1);
            }
        }
        Ok(self.jobs.iter().find_map(|job| {
            if job.stopping
                || Instant::now() >= job.hard
                || sample.monotonic >= job.original.expires
            {
                return None;
            }
            job.candidate.as_ref().map(|path| Path {
                original: job.original,
                peers: &path.path,
                observed: sample.monotonic,
            })
        }))
    }
    /// Node acknowledged actual Book route-opening admission, not a ready tunnel.
    pub(super) fn admitted(&mut self, original: Discovery<'app>) -> Result<()> {
        let index = self
            .jobs
            .iter()
            .position(|job| job.original == original)
            .ok_or(Fault::StaleGeneration)?;
        self.report.admitted_paths = self.report.admitted_paths.saturating_add(1);
        self.report.last_admitted_source = self.jobs[index].candidate_source;
        self.stop(index)
    }
    pub(super) fn reject(&mut self, original: Discovery<'app>, reason: Fault) {
        if let Some(job) = self.jobs.iter_mut().find(|job| job.original == original) {
            job.candidate = None;
        }
        self.report.rejected_paths = self.report.rejected_paths.saturating_add(1);
        self.report.last_rejection = Some(reason);
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if self.report.closed || self.jobs.is_empty() {
            self.timer = None;
            return Poll::Pending;
        }
        let target = self.jobs.iter().map(|job| job.hard).min();
        if let Some(target) = target {
            if self.timer.as_ref().is_none_or(|(old, _)| *old != target) {
                self.timer = Some((target, Box::pin(tokio::time::sleep_until(target))));
            }
            if let Some((_, timer)) = &mut self.timer
                && timer.as_mut().poll(cx).is_ready()
            {
                return Poll::Ready(Ok(())); // caller maintain physically retires before more IO
            }
        } else {
            self.timer = None;
        }
        let progress = match self.client.poll_with_input(cx, target, true) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(result) => match result {
                Ok(p) => p,
                Err(error) => return Poll::Ready(Err(error.into())),
            },
        };
        let result = match progress {
            Progress::Inbound(received) => {
                if let Event::Result { get, .. } = received.event()
                    && let Some(index) = self
                        .jobs
                        .iter()
                        .position(|job| job.get == *get && !job.stopping)
                {
                    let sample = self.timebase.sample()?;
                    let job = &self.jobs[index];
                    if Instant::now() < job.hard && sample.monotonic < job.original.expires {
                        let result = received.result()?;
                        if result.key != &job.key
                            || result.block_type != HELLO
                            || result.id != self.client.request_id(job.get)?
                        {
                            return Poll::Ready(Err(Fault::Malformed.into()));
                        }
                        match validate(
                            result,
                            job.original.peer,
                            self.local,
                            sample.absolute.as_micros(),
                            self.policy.path_peers,
                            self.policy.signature_profile,
                            &mut self.scratch,
                        ) {
                            Ok(path) => {
                                self.jobs[index].candidate = Some(path);
                                self.jobs[index].candidate_source = Some(received.epoch());
                                self.report.last_candidate_source = Some(received.epoch());
                            }
                            Err(
                                reason @ (Fault::Authentication
                                | Fault::Malformed
                                | Fault::InvalidInput
                                | Fault::Unsupported
                                | Fault::Truncated
                                | Fault::TooLarge
                                | Fault::Stale
                                | Fault::Timeout
                                | Fault::Deadline),
                            ) => {
                                self.report.rejected_paths =
                                    self.report.rejected_paths.saturating_add(1);
                                self.report.last_rejection = Some(reason);
                            }
                            Err(reason) => return Poll::Ready(Err(reason.into())),
                        }
                    }
                }
                Ok(())
            }
            Progress::Written {
                action: Action::Stop(get),
                ..
            } => {
                let index = self
                    .jobs
                    .iter()
                    .position(|job| job.get == get && job.stopping)
                    .ok_or(Fault::StaleGeneration)?;
                self.jobs.remove(index);
                self.report.stop_written = self.report.stop_written.saturating_add(1);
                Ok(())
            }
            Progress::Lost { epoch, cause, .. } => {
                self.lost(epoch, cause);
                Ok(())
            }
            Progress::ConnectRetry { error, .. } => {
                self.report.retry_attempts = self.report.retry_attempts.saturating_add(1);
                self.report
                    .first_retry
                    .get_or_insert_with(|| Arc::new(error));
                Ok(())
            }
            Progress::Capacity(_) => Err(Fault::Capacity.into()),
            Progress::Completed(_) => Err(Fault::Conflict.into()),
            Progress::Unavailable(error) => Err(error.into()),
            Progress::Closed => Err(Fault::Closed.into()),
            _ => Ok(()),
        };
        Poll::Ready(result)
    }
    pub(super) fn close(&mut self) -> Result<()> {
        if self.report.closed {
            return Ok(());
        }
        let mut first = None;
        let mut index = 0;
        while index < self.jobs.len() {
            let before = self.jobs.len();
            if let Err(error) = self.stop(index) {
                first.get_or_insert(error);
                // The actual physical close below still retires this original.
                self.jobs[index].stopping = true;
            }
            if self.jobs.len() == before {
                index += 1;
            }
        }
        if let Some(Progress::Lost { epoch, cause, .. }) = self.client.close() {
            self.lost(epoch, cause);
        }
        self.report.stopped_by_retirement = self
            .report
            .stopped_by_retirement
            .saturating_add(self.jobs.len() as u64);
        self.jobs.clear();
        self.report.closed = true;
        self.timer = None;
        first.map_or(Ok(()), Err)
    }
}
fn validate(
    result: dht::ipc::ResultMessage<'_>,
    expected: [u8; 32],
    local: [u8; 32],
    now: u64,
    maximum: usize,
    signature_profile: SignatureProfile,
    scratch: &mut [u8],
) -> std::result::Result<Candidate, Fault> {
    if result.options & RECORD_ROUTE == 0 || result.expiration.as_micros() < now {
        return Err(Fault::Stale);
    }
    let hello = Hello::parse_block(
        result.payload,
        scratch,
        gnunet_hello::Limits {
            maximum_input_bytes: 65535,
            maximum_address_bytes: 65535,
            maximum_addresses: 128,
        },
    )?;
    hello.verify_at(signature_profile, AbsoluteTime::from_micros(now))?;
    if hello.peer().as_bytes() != &expected || hello.expiration().as_micros() <= now {
        return Err(Fault::Authentication);
    }
    gnunet_dht::path::verify(
        result.payload,
        result.expiration.as_micros(),
        result.truncated_peer,
        result.put_path,
        result.get_path,
        &local,
    )
    .map_err(|failure| failure.reason)?;
    // Fixed GCPP_try_path_from_dht: reverse GET then PUT, erase a cycle at the
    // last occurrence. No absent endpoint or first-hop neighbor is fabricated.
    let count = result
        .get_path
        .len()
        .checked_add(result.put_path.len())
        .and_then(|n| n.checked_add(1))
        .ok_or(Fault::Overflow)?;
    let mut path = Vec::new();
    path.try_reserve_exact(count).map_err(|_| Fault::Capacity)?;
    path.push(local);
    for element in result
        .get_path
        .elements()
        .rev()
        .chain(result.put_path.elements().rev())
    {
        let peer: [u8; 32] = element
            .predecessor()
            .try_into()
            .map_err(|_| Fault::Malformed)?;
        if let Some(index) = path.iter().position(|p| *p == peer) {
            path.truncate(index + 1);
        } else {
            path.push(peer);
        }
    }
    if path.len() < 2
        || path.len() > maximum
        || path.first() != Some(&local)
        || path.last() != Some(&expected)
    {
        return Err(Fault::Authentication);
    }
    // Do not retain the capacity of a long cyclic input as a tiny accepted path.
    let mut retained = Vec::new();
    retained
        .try_reserve_exact(path.len())
        .map_err(|_| Fault::Capacity)?;
    retained.extend_from_slice(&path);
    Ok(Candidate {
        path: retained,
        expires: result
            .expiration
            .as_micros()
            .min(hello.expiration().as_micros()),
    })
}
