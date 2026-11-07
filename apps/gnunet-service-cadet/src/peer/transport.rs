//! Real TRANSPORT application demand: one MQ/peer and one 1300 per MQ.
//! Attachment/Written never grant a CORE neighbor or authenticated tunnel.
use gnunet_cadet_host::{node::TransportDemand, time::Timebase};
use gnunet_client_host::{ConnectGuard, EndpointSource, resolution::PortError};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_transport_application_host::{Application, Bounds, Error, Retired, Step};
use gnunet_types::Error as Fault;
use std::{
    error::Error as StdError,
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::time::Sleep;
type Result<T> = std::result::Result<T, Box<dyn StdError>>;
#[derive(Clone, Copy)]
struct Live {
    peer: [u8; 32],
    opening: Option<Instant>,
}
struct Job {
    peer: [u8; 32],
    source: Option<Application>,
    bounds: Option<Bounds>,
    serial: u64,
    submitted: bool,
    whole: bool,
    retry: Instant,
}
/// Physical-source facts; a full 1300 is a local write, never a service ACK.
pub(super) struct Retirement {
    pub source: u64,
    pub epoch: u64,
    pub submitted: bool,
    pub written: usize,
    pub remaining: usize,
    pub suggestion_written: bool,
}
impl std::fmt::Debug for Retirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Retirement")
            .field("source", &self.source)
            .field("epoch", &self.epoch)
            .field("submitted", &self.submitted)
            .field("written", &self.written)
            .field("remaining", &self.remaining)
            .field("suggestion_written", &self.suggestion_written)
            .finish()
    }
}
#[derive(Debug, Default)]
pub(super) struct Report {
    pub sources: u64,
    pub suggestions_written: u64,
    pub source_losses: u64,
    pub clean_eof_losses: u64,
    pub last_loss_was_eof: bool,
    pub retry_attempts: u64,
    pub demand_retirements: u64,
    pub lease_retirements: u64,
    pub physical_retirements: u64,
    pub first_cause: Option<Arc<Error>>,
    pub last_cause: Option<Arc<Error>>,
    pub last_retired: Option<Retirement>,
    pub closed: bool,
}
impl Report {
    fn retire(&mut self, source: u64, whole: bool, facts: Retired) {
        self.physical_retirements = self.physical_retirements.saturating_add(1);
        self.last_retired = Some(Retirement {
            source,
            epoch: facts.epoch,
            submitted: facts.submitted,
            written: facts.written,
            remaining: facts.remaining,
            suggestion_written: whole,
        });
    }
    fn cause(&mut self, error: Error) {
        let error = Arc::new(error);
        self.first_cause.get_or_insert_with(|| error.clone());
        self.last_cause = Some(error);
    }
}
// Only public peer and original native/absolute bounds enter this Send gate.
// The foreground retains the original non-Send domain/channel capabilities.
fn check(
    live: &Mutex<Vec<Live>>,
    clock: &dyn RuntimeClock,
    peer: [u8; 32],
    source: Bounds,
) -> io::Result<()> {
    if Instant::now() >= source.hard {
        return Err(io::Error::other(Fault::Deadline));
    }
    let now = clock.sample().map_err(io::Error::other)?.now.as_micros();
    let native = Instant::now();
    if native >= source.hard || now >= source.expires {
        return Err(io::Error::other(Fault::Deadline));
    }
    let live = live.lock().map_err(|_| io::Error::other(Fault::Conflict))?;
    let mut present = false;
    for demand in live.iter().filter(|d| d.peer == peer) {
        present = true;
        if demand.opening.is_none_or(|hard| native < hard) {
            return Ok(());
        }
    }
    Err(io::Error::other(if present {
        Fault::Deadline
    } else {
        Fault::Cancelled
    }))
}
fn same_owner(a: TransportDemand<'_, '_>, b: TransportDemand<'_, '_>) -> bool {
    a.scope == b.scope && (a.channel == b.channel || a.channel.is_none() || b.channel.is_none())
}
// With only original openings, cap the entire physical epoch by their
// intersection. The SDK's final sample therefore covers every authorizing
// opening even if a preceding external gate/provider consumed time. A real
// established channel/confirmed tunnel independently authorizes its peer lease.
fn capped(
    demands: &[TransportDemand<'_, '_>],
    timebase: &Timebase,
    peer: [u8; 32],
    mut bounds: Bounds,
) -> Result<Bounds> {
    if demands
        .iter()
        .any(|d| d.scope.peer() == peer && d.opening.is_none())
    {
        return Ok(bounds);
    }
    let mut present = false;
    for demand in demands.iter().filter(|d| d.scope.peer() == peer) {
        let (original, hard) = demand.opening.ok_or(Fault::Stale)?;
        present = true;
        // Opening targets belong to the shared native epoch. CLIENT's Unix
        // target remains unchanged; no elapsed value may truncate it.
        bounds.hard = bounds
            .hard
            .min(hard)
            .min(timebase.native_bound(original.expires)?.into_std());
    }
    if !present {
        return Err(Fault::Stale.into());
    }
    Ok(bounds)
}

pub(super) struct Driver<'node, 'app> {
    endpoint: EndpointSource,
    clock: Arc<dyn RuntimeClock>,
    timebase: Timebase,
    live: Arc<Mutex<Vec<Live>>>,
    original: Vec<TransportDemand<'node, 'app>>,
    next: Vec<TransportDemand<'node, 'app>>,
    jobs: Vec<Job>,
    maximum: usize,
    references: usize,
    io: usize,
    lease: Duration,
    cursor: usize,
    timer: Option<(Instant, Pin<Box<Sleep>>)>,
    report: Report,
}
impl<'node, 'app> Driver<'node, 'app> {
    pub(super) fn new(
        endpoint: EndpointSource,
        timebase: Timebase,
        maximum: usize,
        references: usize,
        io: usize,
        lease: Duration,
    ) -> Result<Self> {
        let clock = timebase.source();
        if maximum == 0
            || references < maximum
            || io == 0
            || lease.is_zero()
            || !Arc::ptr_eq(&endpoint.clock(), &clock)
        {
            return Err(Fault::InvalidInput.into());
        }
        let endpoint = endpoint.fixed_endpoint()?;
        let mut jobs = Vec::new();
        jobs.try_reserve_exact(maximum)?;
        let mut original = Vec::new();
        original.try_reserve_exact(references)?;
        let mut next = Vec::new();
        next.try_reserve_exact(references)?;
        let mut live = Vec::new();
        live.try_reserve_exact(references)?;
        Ok(Self {
            endpoint,
            clock,
            timebase,
            live: Arc::new(Mutex::new(live)),
            original,
            next,
            jobs,
            maximum,
            references,
            io,
            lease,
            cursor: 0,
            timer: None,
            report: Report::default(),
        })
    }
    pub(super) fn report(&self) -> &Report {
        &self.report
    }
    /// Run before every subsequent source poll, including after any Node event.
    /// Old channel generations cannot carry a source into replacement opens.
    pub(super) fn maintain(
        &mut self,
        mut demand: impl FnMut(usize) -> Option<(usize, TransportDemand<'node, 'app>)>,
    ) -> Result<()> {
        if self.report.closed {
            return Err(Fault::Closed.into());
        }
        self.next.clear();
        let mut cursor = 0;
        while let Some((after, original)) = demand(cursor) {
            if after <= cursor || self.next.len() == self.references {
                return Err(Fault::Capacity.into());
            }
            self.next.push(original);
            cursor = after;
        }
        {
            let mut live = self.live.lock().map_err(|_| Fault::Conflict)?;
            live.clear();
            for d in &self.next {
                live.push(Live {
                    peer: d.scope.peer(),
                    opening: d
                        .opening
                        .map(|(open, hard)| {
                            self.timebase
                                .native_bound(open.expires)
                                .map(|at| hard.min(at.into_std()))
                        })
                        .transpose()?,
                });
            }
        }
        let mut index = 0;
        while index < self.jobs.len() {
            let peer = self.jobs[index].peer;
            let continuing = self
                .original
                .iter()
                .filter(|d| d.scope.peer() == peer)
                .any(|old| self.next.iter().any(|new| same_owner(*old, *new)));
            if !continuing {
                self.retire(index);
                self.jobs.swap_remove(index);
                self.report.demand_retirements = self.report.demand_retirements.saturating_add(1);
            } else {
                if let Some(bounds) = self.jobs[index].bounds {
                    let cap = capped(&self.next, &self.timebase, peer, bounds)?;
                    if cap.expires < bounds.expires || cap.hard < bounds.hard {
                        // An established authorizer may have retired, leaving
                        // shorter original openings. Retire before any later IO;
                        // never silently retag its already admitted old frame.
                        self.retire(index);
                        self.jobs[index].retry = Instant::now();
                        self.report.demand_retirements =
                            self.report.demand_retirements.saturating_add(1);
                    }
                }
                index += 1;
            }
        }
        for d in &self.next {
            let peer = d.scope.peer();
            if self.jobs.iter().any(|j| j.peer == peer) {
                continue;
            }
            if self.jobs.len() == self.maximum {
                return Err(Fault::Capacity.into());
            }
            self.jobs.push(Job {
                peer,
                source: None,
                bounds: None,
                serial: 0,
                submitted: false,
                whole: false,
                retry: Instant::now(),
            });
        }
        std::mem::swap(&mut self.original, &mut self.next);
        self.next.clear();
        Ok(())
    }
    fn retire(&mut self, index: usize) {
        let job = &mut self.jobs[index];
        if let Some(mut source) = job.source.take() {
            self.report.retire(job.serial, job.whole, source.close());
        }
        job.bounds = None;
        job.submitted = false;
        job.whole = false;
    }
    fn lost(&mut self, index: usize, error: Option<Error>, facts: Option<Retired>) -> Result<()> {
        if let Some(facts) = facts {
            self.jobs[index].source = None; // SDK has already physically retired it.
            self.report
                .retire(self.jobs[index].serial, self.jobs[index].whole, facts);
            self.jobs[index].bounds = None;
            self.jobs[index].submitted = false;
            self.jobs[index].whole = false;
        } else {
            self.retire(index);
        }
        self.report.source_losses = self.report.source_losses.saturating_add(1);
        let fatal = error.as_ref().is_some_and(|e| match e {
            Error::Configuration(_) => true,
            Error::Protocol(p) => !matches!(p, Fault::Deadline | Fault::Cancelled),
            Error::Io(e) => {
                PortError::from_io(e).is_some()
                    || e.get_ref()
                        .and_then(|e| e.downcast_ref::<Fault>())
                        .is_some_and(|p| !matches!(p, Fault::Deadline | Fault::Cancelled))
            }
        });
        self.report.last_loss_was_eof = error.is_none();
        if let Some(error) = error {
            self.report.cause(error);
        } else {
            self.report.clean_eof_losses = self.report.clean_eof_losses.saturating_add(1);
            self.report.last_cause = None;
        }
        self.jobs[index].retry = Instant::now()
            .checked_add(Duration::from_secs(1))
            .ok_or(Fault::Overflow)?;
        if fatal {
            return Err(self
                .report
                .last_cause
                .as_ref()
                .ok_or(Fault::Stale)?
                .clone()
                .into());
        }
        Ok(())
    }
    fn poll_one(&mut self, index: usize, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if self.jobs[index].source.is_none() {
            if Instant::now() < self.jobs[index].retry {
                return Poll::Pending;
            }
            let peer = self.jobs[index].peer;
            let bounds = capped(
                &self.original,
                &self.timebase,
                peer,
                Bounds::new(self.clock.as_ref(), self.lease)?,
            )?;
            let live = self.live.clone();
            let clock = self.clock.clone();
            let guard: ConnectGuard = Arc::new(move || check(&live, clock.as_ref(), peer, bounds));
            match Application::new_bounded_guarded(
                self.endpoint.duplicate()?,
                self.io,
                bounds,
                guard,
            ) {
                Ok(source) => {
                    self.report.sources =
                        self.report.sources.checked_add(1).ok_or(Fault::Overflow)?;
                    let job = &mut self.jobs[index];
                    job.serial = self.report.sources;
                    job.bounds = Some(bounds);
                    job.source = Some(source);
                }
                Err(error) => {
                    self.lost(index, Some(error), None)?;
                    return Poll::Ready(Ok(()));
                }
            }
        }
        let job = &mut self.jobs[index];
        let source = job.source.as_mut().ok_or(Fault::Stale)?;
        if let Some(facts) = source.poll_native_guard(cx) {
            self.report.lease_retirements = self.report.lease_retirements.saturating_add(1);
            self.lost(index, Some(Fault::Deadline.into()), Some(facts))?;
            return Poll::Ready(Ok(()));
        }
        if source.idle() && !job.submitted {
            if let Err(error) = source.preference(job.peer, false, job.bounds.ok_or(Fault::Stale)?)
            {
                self.lost(index, Some(error), None)?;
                return Poll::Ready(Ok(()));
            }
            job.submitted = true; // Admission, not a whole/native receipt.
        }
        match source.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.lost(index, Some(error), None)?;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(Step::Lost { report, cause })) => {
                self.lost(index, cause.map(Error::Io), Some(report))?;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(Step::Written { .. })) => {
                job.whole = true;
                self.report.suggestions_written = self.report.suggestions_written.saturating_add(1);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(Step::Retry(error))) => {
                self.report.retry_attempts = self.report.retry_attempts.saturating_add(1);
                self.report.cause(Error::Io(error));
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(Step::Attached(_) | Step::Activity)) => Poll::Ready(Ok(())),
        }
    }
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        if self.report.closed {
            return Poll::Pending;
        }
        for _ in 0..self.jobs.len() {
            let index = self.cursor % self.jobs.len();
            self.cursor = (index + 1) % self.jobs.len();
            if let Poll::Ready(result) = self.poll_one(index, cx) {
                return Poll::Ready(result);
            }
        }
        let next = self
            .jobs
            .iter()
            .map(|j| j.bounds.map_or(j.retry, |b| b.hard))
            .min();
        if let Some(next) = next {
            if self.timer.as_ref().is_none_or(|(at, _)| *at != next) {
                self.timer = Some((next, Box::pin(tokio::time::sleep_until(next.into()))));
            }
            if self
                .timer
                .as_mut()
                .is_some_and(|(_, timer)| timer.as_mut().poll(cx).is_ready())
            {
                self.timer = None;
                cx.waker().wake_by_ref();
                return Poll::Ready(Ok(()));
            }
        } else {
            self.timer = None;
        }
        Poll::Pending
    }
    /// Disable guards before retiring every physical source. C disconnect
    /// removes only this MQ's request; no cancel is sent on a fresh connection.
    pub(super) fn close(&mut self) -> Result<()> {
        let clear = match self.live.lock() {
            Ok(mut live) => {
                live.clear();
                Ok(())
            }
            Err(_) => Err(Fault::Conflict),
        };
        for index in 0..self.jobs.len() {
            self.retire(index);
        }
        self.jobs.clear();
        self.original.clear();
        self.next.clear();
        self.timer = None;
        self.report.closed = true;
        clear.map_err(Into::into)
    }
}
impl Drop for Driver<'_, '_> {
    fn drop(&mut self) {
        drop(self.close());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnunet_service_runtime::clock::{ClockSample, ClockSubscription};
    use gnunet_types::AbsoluteTime;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    struct Adjustable {
        now: AtomicU64,
        failed: AtomicBool,
    }
    impl RuntimeClock for Adjustable {
        fn sample(&self) -> std::result::Result<ClockSample, Fault> {
            if self.failed.load(Ordering::SeqCst) {
                return Err(Fault::Unavailable);
            }
            Ok(ClockSample {
                now: AbsoluteTime::from_micros(self.now.load(Ordering::SeqCst)),
                revision: 0,
            })
        }
        fn subscribe(&self) -> std::result::Result<Box<dyn ClockSubscription>, Fault> {
            Err(Fault::Unsupported)
        }
    }
    fn require(value: bool) -> Result<()> {
        value
            .then_some(())
            .ok_or_else(|| Fault::InvalidInput.into())
    }

    #[test]
    fn original_open_native_bound_survives_logical_rollback_and_keeps_source_failures() -> Result<()>
    {
        let clock = Adjustable {
            now: AtomicU64::new(6_000_000),
            failed: AtomicBool::new(false),
        };
        let hard = Instant::now()
            .checked_add(Duration::from_secs(3600))
            .ok_or(Fault::Overflow)?;
        let bounds = Bounds {
            expires: 10_000_000,
            hard,
        };
        let live = Mutex::new(vec![Live {
            peer: [7; 32],
            opening: Some(hard),
        }]);
        check(&live, &clock, [7; 32], bounds)?;
        clock.now.store(1, Ordering::SeqCst);
        check(&live, &clock, [7; 32], bounds)?;
        clock.failed.store(true, Ordering::SeqCst);
        let error = check(&live, &clock, [7; 32], bounds)
            .err()
            .ok_or(Fault::InvalidInput)?;
        require(
            error.get_ref().and_then(|e| e.downcast_ref::<Fault>()) == Some(&Fault::Unavailable),
        )?;
        clock.failed.store(false, Ordering::SeqCst);
        let expired = Instant::now()
            .checked_sub(Duration::from_secs(1))
            .ok_or(Fault::Overflow)?;
        live.lock().map_err(|_| Fault::Conflict)?[0].opening = Some(expired);
        let error = check(&live, &clock, [7; 32], bounds)
            .err()
            .ok_or(Fault::InvalidInput)?;
        require(error.get_ref().and_then(|e| e.downcast_ref::<Fault>()) == Some(&Fault::Deadline))
    }
}
