//! Actual public DNS exit advertisement: one original PILS signature and DHT PUT.
//! Local PUT writing is not publication/availability. Failure returns to the
//! ordinary bounded publisher; retry creates a new epoch/expiry/signature.
use crate::Failure;
use gnunet_client_host::EndpointSource;
use gnunet_dht_client_host as dht;
use gnunet_pils::{
    Profile,
    client::{self as pc, Completion, Identity, Inbound, KeyTarget},
};
use gnunet_pils_host::client as pils;
use gnunet_pt::exit::{self as wire, Advertisement};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use gnunet_wire::official::AbsoluteTime;
use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
const REFRESH: Duration = Duration::from_secs(15 * 60);
const VALIDITY: u64 = 3 * 60 * 60 * 1_000_000;
const OPERATION: Duration = Duration::from_secs(30);
const BACKOFF: Duration = Duration::from_secs(1);
/// Retained bounded local facts; no field is a DHT publication acknowledgement.
#[derive(Default)]
pub(super) struct Report {
    pub signatures: u64,
    pub local_put_writes: u64,
    pub uncertain_puts: u64,
    pub cancelled_before_issue: u64,
    pub signing_interrupted: bool,
    pub last_put: Option<dht::Outcome>,
    pub last_expiration: Option<u64>,
    pub retry_failures: u64,
    pub last_retry: Option<std::io::Error>,
    pub failed_intents: u64,
    pub first_failure: Option<FailedIntent>,
    pub last_failure: Option<FailedIntent>,
    pub sources_closed: bool,
}
/// One bounded original failure observation; an absent PUT result never means
/// that asking for cancellation acquired a receipt or withdrew an old public ad.
pub(super) struct FailedIntent {
    pub intent: Option<u64>,
    pub expiration: Option<u64>,
    pub put_outcome: Option<dht::Outcome>,
    pub put_cancel: Option<dht::Cancel>,
    pub cause: Failure,
}
impl fmt::Debug for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsAdvertisement")
            .field("signatures", &self.signatures)
            .field("local_put_writes", &self.local_put_writes)
            .field("uncertain_puts", &self.uncertain_puts)
            .field("cancelled_before_issue", &self.cancelled_before_issue)
            .field("signing_interrupted", &self.signing_interrupted)
            .field("last_put", &self.last_put)
            .field("last_expiration", &self.last_expiration)
            .field("retry_failures", &self.retry_failures)
            .field("last_retry", &self.last_retry)
            .field("failed_intents", &self.failed_intents)
            .field("first_failure", &self.first_failure)
            .field("last_failure", &self.last_failure)
            .field("sources_closed", &self.sources_closed)
            .finish()
    }
}
impl fmt::Debug for FailedIntent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FailedIntent")
            .field("intent", &self.intent)
            .field("expiration", &self.expiration)
            .field("put_outcome", &self.put_outcome)
            .field("put_cancel", &self.put_cancel)
            .field("cause", &self.cause)
            .finish()
    }
}
#[derive(Debug)]
struct PilsLost(pils::LossCause);
impl fmt::Display for PilsLost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EXIT DNS advertisement original PILS source: {:?}",
            self.0
        )
    }
}
impl std::error::Error for PilsLost {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            pils::LossCause::Io(e) => Some(e),
            pils::LossCause::Protocol(e) | pils::LossCause::Resource(e) => Some(e),
            pils::LossCause::Setup(e) => Some(e),
            _ => None,
        }
    }
}
#[derive(Debug)]
struct DhtLost(dht::LossCause);
impl fmt::Display for DhtLost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EXIT DNS advertisement original DHT source: {:?}",
            self.0
        )
    }
}
impl std::error::Error for DhtLost {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            dht::LossCause::Io(e) => Some(e),
            dht::LossCause::Protocol(e) | dht::LossCause::Resource(e) => Some(e),
            _ => None,
        }
    }
}
#[derive(Debug)]
struct SignFailure(pc::Failure);
impl fmt::Display for SignFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EXIT DNS advertisement actual PILS refusal: {:?}",
            self.0
        )
    }
}
impl std::error::Error for SignFailure {}
#[derive(Clone, Copy)]
enum Phase<'id> {
    Identity,
    Signing(pc::OperationId<'id>, Identity<'id>),
    ConnectingDht(Identity<'id>),
    Settled(dht::Outcome),
    Writing(dht::OperationId<'id>, Identity<'id>),
}
struct Job<'id> {
    generation: u64,
    phase: Phase<'id>,
    hard: Instant,
    until: u64,
    expiration: u64,
}
/// Native owners are polled by the same normal foreground/Resolver. There is no
/// local key, hidden worker, private RPC, restored mutation or self-hosted DHT.
pub(super) struct Owner<'id> {
    pils: pils::Client<'id, 1>,
    dht: dht::Client<'id>,
    clock: Arc<dyn RuntimeClock>,
    job: Option<Job<'id>>,
    next: Option<(Instant, u64)>,
    block: [u8; wire::ADVERTISEMENT_BYTES],
    enabled: bool,
    closed: bool,
    report: Report,
    alarm: Option<Pin<Box<Sleep>>>,
    alarm_at: Option<Instant>,
    generation: u64,
}
impl<'id> Owner<'id> {
    /// Constructors reserve finite metadata only. The original startup hard
    /// target is not renewed by port readiness, identity receipt or signing.
    pub fn new(
        pils_id: &'id mut pc::Instance,
        dht_id: &'id mut dht::Instance,
        pils_source: EndpointSource,
        dht_source: EndpointSource,
        startup: Instant,
        profile: Profile,
    ) -> Result<Self, Failure> {
        let [pils_source, dht_source] = EndpointSource::snapshot_all([&pils_source, &dht_source])?;
        let clock = pils_source.clock();
        let now = clock.sample()?.now.as_micros();
        let remaining = startup
            .checked_duration_since(Instant::now())
            .ok_or(Fault::Deadline)?;
        let until = now
            .checked_add(u64::try_from(remaining.as_micros())?)
            .ok_or(Fault::Overflow)?;
        let pils = pils::Client::new(
            pils_id,
            pils_source,
            profile,
            pils::Limits {
                pending_operations: 1,
                ..pils::Limits::default()
            },
            gnunet_pils::HelloLimits {
                maximum_input_bytes: 65535,
                maximum_address_bytes: 65535,
                maximum_addresses: 128,
            },
        )?;
        let mut limits = dht::Limits::default();
        limits.protocol.gets = 0;
        limits.protocol.monitors = 0;
        limits.protocol.hellos = 0;
        limits.protocol.operations = 1;
        limits.protocol.attempts = 1;
        limits.protocol.source_bytes = 512;
        limits.protocol.known_per_get = 0;
        limits.protocol.frame_bytes = 256;
        limits.output.frames = 1;
        limits.output.bytes = 256;
        limits.io_slice_bytes = 256;
        limits.hello.maximum_address_bytes = 0;
        let dht = dht::Client::new(dht_id, dht_source, limits)?;
        Ok(Self {
            pils,
            dht,
            clock,
            job: Some(Job {
                generation: 1,
                phase: Phase::Identity,
                hard: startup,
                until,
                expiration: 0,
            }),
            next: None,
            block: [0; wire::ADVERTISEMENT_BYTES],
            enabled: false,
            closed: false,
            report: Report::default(),
            alarm: None,
            alarm_at: None,
            generation: 1,
        })
    }
    /// A lost current DNS port pauses this advertiser and retires old bytes.
    /// New IO waits for the ordinary CADET owner to reannounce its real port.
    pub fn readiness(&mut self, ready: bool) -> Result<(), Failure> {
        if self.closed {
            return Err(Fault::Closed.into());
        }
        if self.enabled && !ready {
            let now = self.clock.sample()?.now.as_micros();
            self.failed(Fault::NotReady.into(), now)?;
        }
        self.enabled = ready;
        Ok(())
    }
    pub fn report(&self) -> &Report {
        &self.report
    }
    fn current(&self, identity: Identity<'id>, now: u64) -> bool {
        self.pils.identity().is_some_and(|current| {
            current.epoch() == identity.epoch()
                && current.peer() == identity.peer()
                && current.expiration().as_micros() > now
        })
    }
    fn terminal(&mut self) -> Option<dht::Completion<'id>> {
        let mut original = None;
        while let Some(terminal) = self.dht.take_completion() {
            original = Some(terminal);
            self.report.last_put = Some(terminal.outcome);
            match terminal.outcome {
                dht::Outcome::Written | dht::Outcome::CanceledWritten => {
                    self.report.local_put_writes = self.report.local_put_writes.saturating_add(1);
                }
                dht::Outcome::Lost | dht::Outcome::CanceledLost => {
                    self.report.uncertain_puts = self.report.uncertain_puts.saturating_add(1);
                }
            }
        }
        original
    }
    /// Physically retire old sources before any future independent intent. The
    /// clients' reconnect methods may retain crypto/one-shots, so cancel/drain
    /// the exact old operation explicitly before allowing a replacement epoch.
    fn retire(&mut self) -> Result<(Option<dht::Outcome>, Option<dht::Cancel>), Failure> {
        let old = self.job.take();
        let terminal = self.terminal();
        let mut cancel = None;
        let mut outcome = old.as_ref().and_then(|job| match job.phase {
            Phase::Settled(outcome) => Some(outcome),
            Phase::Writing(operation, _) => terminal
                .filter(|t| t.operation == operation)
                .map(|t| t.outcome),
            _ => None,
        });
        if let Some(Job {
            phase: Phase::Signing(op, _),
            ..
        }) = &old
            && !self.pils.operation_quiescent(*op)?
        {
            self.report.signing_interrupted = true;
            self.pils.cancel(*op)?;
        }
        if self.pils.epoch().is_some() {
            let _physical = self.pils.reconnect()?;
        }
        if let Some(Job {
            phase: Phase::Writing(op, _),
            ..
        }) = old
            && terminal.is_none_or(|t| t.operation != op)
        {
            let observed = self.dht.cancel(op)?;
            cancel = Some(observed);
            match observed {
                dht::Cancel::BeforeIssue => {
                    self.report.cancelled_before_issue =
                        self.report.cancelled_before_issue.saturating_add(1)
                }
                dht::Cancel::Draining => {}
            }
        }
        let _physical = self.dht.retire_io()?;
        if let Some(terminal) = self.terminal() {
            outcome = Some(terminal.outcome);
        }
        self.block.fill(0);
        Ok((outcome, cancel))
    }
    fn failed(&mut self, cause: Failure, now: u64) -> Result<(), Failure> {
        self.report.failed_intents = self.report.failed_intents.saturating_add(1);
        let had_put = self
            .job
            .as_ref()
            .is_some_and(|j| matches!(j.phase, Phase::Writing(..) | Phase::Settled(_)));
        let first = self.report.first_failure.is_none();
        let failed = FailedIntent {
            intent: self.job.as_ref().map(|j| j.generation),
            expiration: self
                .job
                .as_ref()
                .and_then(|j| (j.expiration != 0).then_some(j.expiration)),
            put_outcome: None,
            put_cancel: None,
            cause,
        };
        if first {
            self.report.first_failure = Some(failed);
        } else {
            self.report.last_failure = Some(failed);
        }
        let (outcome, cancel) = self.retire()?;
        if had_put {
            let entry = if first {
                &mut self.report.first_failure
            } else {
                &mut self.report.last_failure
            };
            if let Some(entry) = entry {
                entry.put_outcome = outcome;
                entry.put_cancel = cancel;
            }
        }
        self.next = Some((
            Instant::now().checked_add(BACKOFF).ok_or(Fault::Overflow)?,
            now.checked_add(u64::try_from(BACKOFF.as_micros())?)
                .ok_or(Fault::Overflow)?,
        ));
        self.alarm = None;
        self.alarm_at = None;
        Ok(())
    }
    fn guard(&mut self) -> Result<u64, Failure> {
        let now = self.clock.sample()?.now.as_micros();
        if let Some(job) = &self.job {
            let expired = Instant::now() >= job.hard || now >= job.until;
            let changed = match job.phase {
                Phase::Signing(_, id) | Phase::ConnectingDht(id) | Phase::Writing(_, id) => {
                    !self.current(id, now) || job.expiration <= now
                }
                Phase::Identity | Phase::Settled(_) => false,
            };
            if expired {
                self.failed(Fault::Deadline.into(), now)?;
            } else if changed {
                self.failed(Box::new(SignFailure(pc::Failure::KeyChanged)), now)?;
            }
        } else if let Some((hard, until)) = self.next
            && (Instant::now() >= hard || now >= until)
        {
            self.generation = self.generation.checked_add(1).ok_or(Fault::Overflow)?;
            self.job = Some(Job {
                generation: self.generation,
                phase: Phase::Identity,
                hard: Instant::now()
                    .checked_add(OPERATION)
                    .ok_or(Fault::Overflow)?,
                until: now
                    .checked_add(u64::try_from(OPERATION.as_micros())?)
                    .ok_or(Fault::Overflow)?,
                expiration: 0,
            });
            self.next = None;
            self.alarm = None;
            self.alarm_at = None;
        }
        Ok(now)
    }
    fn wait(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, Failure>> {
        let Some((target, _)) = self.next else {
            return Poll::Ready(Err(Fault::Conflict.into()));
        };
        if self.alarm_at != Some(target) {
            self.alarm = Some(Box::pin(tokio::time::sleep_until(target)));
            self.alarm_at = Some(target);
        }
        match self
            .alarm
            .as_mut()
            .ok_or(Fault::Conflict)?
            .as_mut()
            .poll(cx)
        {
            Poll::Ready(()) => Poll::Ready(Ok(true)),
            Poll::Pending => Poll::Pending,
        }
    }
    fn sign(&mut self, now: u64) -> Result<bool, Failure> {
        if !self
            .job
            .as_ref()
            .is_some_and(|j| matches!(j.phase, Phase::Identity))
        {
            return Ok(false);
        }
        let Some(identity) = self.pils.identity() else {
            return Ok(false);
        };
        if !self.current(identity, now) {
            return Ok(false);
        }
        let expiration = now
            .checked_add(VALIDITY)
            .filter(|n| *n != u64::MAX)
            .ok_or(Fault::Overflow)?;
        // A replacement intent never resubmits the old signed bytes, even if a
        // testing/skewed canonical UTC clock has not yet advanced. Its original
        // job hard bound still expires; no synthetic clock value is invented.
        if self
            .report
            .last_expiration
            .is_some_and(|old| expiration <= old)
        {
            return Ok(false);
        }
        let region = Advertisement::signed_region(*identity.peer().as_bytes(), expiration);
        let operation = self.pils.sign(&region, KeyTarget::Exact(identity))?;
        let job = self.job.as_mut().ok_or(Fault::Conflict)?;
        job.phase = Phase::Signing(operation, identity);
        job.expiration = expiration;
        self.report.last_expiration = Some(expiration);
        Ok(true)
    }
    fn signature(&mut self, completion: Completion<'id>, now: u64) -> Result<(), Failure> {
        let job = self.job.as_ref().ok_or(Fault::Stale)?;
        let Phase::Signing(operation, identity) = job.phase else {
            return Err(Fault::Conflict.into());
        };
        if completion.operation() != operation {
            return Err(Fault::Stale.into());
        }
        let timely = Instant::now() < job.hard && now < job.until && job.expiration > now;
        let expiration = job.expiration;
        match completion {
            Completion::Signature {
                peer,
                signature,
                announced,
                ..
            } => {
                let current = self.current(identity, now)
                    && peer == identity.peer()
                    && announced.is_some_and(|a| a.epoch() == identity.epoch() && a.peer() == peer);
                if !timely || !current {
                    // Real completion already consumed this operation. Retire
                    // only its actual sources; never cancel a fabricated token.
                    self.job.as_mut().ok_or(Fault::Conflict)?.phase = Phase::Identity;
                    return self.failed(
                        if !timely {
                            Fault::Deadline.into()
                        } else {
                            Box::new(SignFailure(pc::Failure::KeyChanged))
                        },
                        now,
                    );
                }
                self.block = Advertisement::encode_signed(
                    *peer.as_bytes(),
                    expiration,
                    signature.as_bytes(),
                    now,
                )?;
                self.report.signatures = self.report.signatures.saturating_add(1);
                self.report.last_expiration = Some(expiration);
                self.job.as_mut().ok_or(Fault::Conflict)?.phase = Phase::ConnectingDht(identity);
                Ok(())
            }
            Completion::Failed {
                reason: reason @ (pc::Failure::KeyChanged | pc::Failure::IdentityUnavailable),
                ..
            } => {
                self.job.as_mut().ok_or(Fault::Conflict)?.phase = Phase::Identity;
                self.failed(Box::new(SignFailure(reason)), now)
            }
            Completion::Failed { reason, .. } => Err(Box::new(SignFailure(reason))),
            _ => Err(Fault::Authentication.into()),
        }
    }
    fn completion(&mut self, completion: dht::Completion<'id>, now: u64) -> Result<(), Failure> {
        let job = self.job.as_ref().ok_or(Fault::Stale)?;
        let Phase::Writing(operation, identity) = job.phase else {
            return Err(Fault::Conflict.into());
        };
        if completion.operation != operation {
            return Err(Fault::Stale.into());
        }
        let timely = Instant::now() < job.hard
            && now < job.until
            && self.current(identity, now)
            && job.expiration > now;
        self.report.last_put = Some(completion.outcome);
        // The original terminal notice was consumed. Clearing only that phase
        // prevents retire() from canceling a no-longer-live native operation.
        self.job.as_mut().ok_or(Fault::Conflict)?.phase = Phase::Settled(completion.outcome);
        match completion.outcome {
            dht::Outcome::Written | dht::Outcome::CanceledWritten => {
                self.report.local_put_writes = self.report.local_put_writes.saturating_add(1)
            }
            dht::Outcome::Lost | dht::Outcome::CanceledLost => {
                self.report.uncertain_puts = self.report.uncertain_puts.saturating_add(1)
            }
        }
        if completion.outcome != dht::Outcome::Written {
            return self.failed(Fault::OutcomeUnknown.into(), now);
        }
        if !timely {
            return self.failed(Fault::Deadline.into(), now);
        }
        self.job = None;
        self.next = Some((
            Instant::now().checked_add(REFRESH).ok_or(Fault::Overflow)?,
            now.checked_add(u64::try_from(REFRESH.as_micros())?)
                .ok_or(Fault::Overflow)?,
        ));
        Ok(())
    }
    fn put(&mut self, now: u64) -> Result<(), Failure> {
        let job = self.job.as_ref().ok_or(Fault::Conflict)?;
        let Phase::ConnectingDht(identity) = job.phase else {
            return Err(Fault::Conflict.into());
        };
        if !self.current(identity, now) || self.dht.epoch().is_none() {
            return Err(Fault::NotReady.into());
        }
        let put = self.dht.put(dht::ipc::Put {
            block_type: wire::BLOCK_TYPE,
            options: 0, // Official GNUNET_DHT_RO_NONE.
            replication: 1,
            expiration: AbsoluteTime::from_micros(job.expiration),
            key: &wire::discovery_key(),
            payload: &self.block,
        })?;
        self.job.as_mut().ok_or(Fault::Conflict)?.phase = Phase::Writing(put, identity);
        Ok(())
    }
    /// One bounded foreground turn. PILS is observed before DHT IO, so an
    /// observed key/source change retires old publication bytes before retry.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<bool, Failure>> {
        if self.closed || !self.enabled {
            return Poll::Pending;
        }
        let now = self.guard()?;
        if self.job.is_none() {
            return self.wait(cx);
        }
        if self.sign(now)? {
            return Poll::Ready(Ok(true));
        }
        let target = self.job.as_ref().map(|j| j.hard);
        let progress = {
            let mut driving = std::pin::pin!(self.pils.drive(target));
            driving.as_mut().poll(cx)
        };
        let mut activity = false;
        match progress {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(progress)) => {
                activity = true;
                match progress {
                    pils::Progress::Inbound(Inbound::Complete(c)) => {
                        let now = self.clock.sample()?.now.as_micros();
                        self.signature(c, now)?;
                    }
                    pils::Progress::Lost { cause, .. } => {
                        let transient =
                            matches!(cause, pils::LossCause::Eof | pils::LossCause::Io(_));
                        if !transient {
                            return Poll::Ready(Err(Box::new(PilsLost(cause))));
                        }
                        let now = self.clock.sample()?.now.as_micros();
                        self.failed(Box::new(PilsLost(cause)), now)?;
                        return Poll::Ready(Ok(true));
                    }
                    pils::Progress::Unavailable(e) => return Poll::Ready(Err(e.into())),
                    pils::Progress::Closed => return Poll::Ready(Err(Fault::Closed.into())),
                    pils::Progress::ConnectRetry { error, .. } => {
                        self.report.retry_failures = self.report.retry_failures.saturating_add(1);
                        self.report.last_retry = Some(error);
                    }
                    pils::Progress::WaitDeadline => {
                        self.guard()?;
                    }
                    _ => {}
                }
            }
            Poll::Pending => {}
        }
        let now = self.guard()?;
        if self.job.is_none() {
            return Poll::Ready(Ok(true));
        }
        if self
            .job
            .as_ref()
            .is_some_and(|j| matches!(j.phase, Phase::ConnectingDht(_)))
            && self.dht.epoch().is_some()
        {
            self.put(now)?;
        }
        if self
            .job
            .as_ref()
            .is_some_and(|j| matches!(j.phase, Phase::ConnectingDht(_) | Phase::Writing(..)))
        {
            match self.dht.poll_with_input(cx, target, true) {
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(progress)) => {
                    activity = true;
                    match progress {
                        dht::Progress::Connected(_) => {
                            let now = self.guard()?;
                            if self.job.is_some() {
                                self.put(now)?;
                            }
                        }
                        dht::Progress::Completed(c) => {
                            let now = self.clock.sample()?.now.as_micros();
                            self.completion(c, now)?;
                        }
                        dht::Progress::Lost { cause, .. } => {
                            let transient =
                                matches!(cause, dht::LossCause::Eof | dht::LossCause::Io(_));
                            if !transient {
                                return Poll::Ready(Err(Box::new(DhtLost(cause))));
                            }
                            let now = self.clock.sample()?.now.as_micros();
                            self.failed(Box::new(DhtLost(cause)), now)?;
                        }
                        dht::Progress::ConnectRetry { error, .. } => {
                            self.report.retry_failures =
                                self.report.retry_failures.saturating_add(1);
                            self.report.last_retry = Some(error);
                        }
                        dht::Progress::Unavailable(e) => return Poll::Ready(Err(e.into())),
                        dht::Progress::Capacity(_) => {
                            return Poll::Ready(Err(Fault::Capacity.into()));
                        }
                        dht::Progress::Closed => return Poll::Ready(Err(Fault::Closed.into())),
                        dht::Progress::WaitDeadline => {
                            self.guard()?;
                        }
                        _ => {}
                    }
                }
                Poll::Pending => {}
            }
        }
        if activity {
            Poll::Ready(Ok(true))
        } else {
            Poll::Pending
        }
    }
    /// Actual physical retirement and retained terminal notices. Neither a
    /// cancel request nor an exposed old public advertisement can be retracted.
    pub fn close(&mut self) -> (Option<Report>, Option<Failure>) {
        if self.closed {
            return (None, None);
        }
        self.closed = true;
        self.enabled = false;
        let error = self.retire().err();
        let _signatures_retired = self.pils.close();
        let _physical = self.dht.close();
        self.terminal();
        self.job = None;
        self.next = None;
        self.alarm = None;
        self.alarm_at = None;
        self.report.sources_closed = true;
        (Some(std::mem::take(&mut self.report)), error)
    }
}
impl Drop for Owner<'_> {
    fn drop(&mut self) {
        let _retired = self.close();
    }
}
