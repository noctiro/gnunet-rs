//! Actual PILS source/signature/FEED ownership. No local key loading, key
//! export, private-seed fallback, fake crypto result or cross-MQ replay.
use crate::{Failure, time::Bounds};
use gnunet_client_host::EndpointSource;
use gnunet_crypto::{EddsaPublicKey, EddsaSignature};
use gnunet_hello::{HelloBuilder, Limits as HelloLimits};
use gnunet_pils::{
    Profile,
    client::{
        self as pc, Completion, Epoch, FeedDisposition, Identity, Inbound, KeyTarget, OperationId,
        OperationKind,
    },
};
use gnunet_pils_host::client::{self as native, Client};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::{Error as Fault, Rejected};
use std::{
    collections::VecDeque,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
/// Original failure of an actual matched task, not a wire cancel acknowledgement.
#[derive(Clone, Copy, Debug)]
pub enum Reason {
    /// Logical caller interest stopped; no remote rollback inferred.
    Cancelled,
    /// Original deadline expired.
    Deadline,
    /// Actual source retired; FEED's actual known exposure is retained.
    Lost(Option<FeedDisposition>),
    /// Real PILS response failed validation/refused.
    Refused(pc::Failure),
}
/// Caller-owned bounded metadata is returned only under its original operation.
pub enum Event<'id, J> {
    /// Actual physical source attached, before identity is available.
    Connected(Epoch<'id>),
    /// Real verified public announcement from that original source.
    Identity {
        /// Source-matching observation.
        identity: Identity<'id>,
        /// Actual public key changed.
        changed: bool,
    },
    /// Real signature already checked by the existing pure PILS client.
    Signature {
        /// Original caller metadata.
        origin: J,
        /// Actual returned signer, checked against original expected key.
        peer: EddsaPublicKey,
        /// Exact real signature.
        signature: EddsaSignature,
    },
    /// Original complete FEED write only; no ACK/application/remote availability.
    FeedWritten(J),
    /// Original local/real failure, returning original metadata once.
    Failed {
        /// Same original task.
        origin: J,
        /// Exact local/actual reason.
        reason: Reason,
    },
    /// Actual original MQ is physically retired before this event; all old
    /// jobs fail separately and no pending crypto is replayed to another source.
    SourceLost {
        /// Original physical identity when one attached.
        epoch: Option<Epoch<'id>>,
        /// Actual original cause.
        cause: Failure,
    },
    /// Positive byte/protocol progress without a domain result.
    Activity,
}
#[derive(Clone, Copy)]
enum Kind {
    Sign(EddsaPublicKey),
    Feed,
}
struct Row<'id, J> {
    operation: OperationId<'id>,
    epoch: Epoch<'id>,
    origin: J,
    kind: Kind,
    bounds: Bounds,
    cancelled: bool,
    retire: Option<Instant>,
}
/// Explicit bounded native/phase resources; actual PILS source profile supplied.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Actual existing client budgets.
    pub client: native::Limits,
    /// Complete source lifetime.
    pub source: Duration,
    /// Attachment/identity initial budget.
    pub initial: Duration,
    /// First partial input frame bound.
    pub input: Duration,
    /// Original cancelled suffix retirement maximum.
    pub retire: Duration,
    /// Actual caller metadata slots, at most32.
    pub jobs: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            client: Default::default(),
            source: Duration::from_secs(86400),
            initial: Duration::from_secs(30),
            input: Duration::from_secs(10),
            retire: Duration::from_secs(2),
            jobs: 24,
        }
    }
}
#[derive(Debug)]
struct Cause(native::LossCause);
impl std::fmt::Display for Cause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PILS original native source: {:?}", self.0)
    }
}
impl std::error::Error for Cause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            native::LossCause::Io(e) => Some(e),
            native::LossCause::Setup(e) => Some(e),
            _ => None,
        }
    }
}
#[derive(Debug)]
struct SourceFailure {
    original: Failure,
    cleanup: Failure,
}
impl std::fmt::Display for SourceFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}; independent cleanup: {}",
            self.original, self.cleanup
        )
    }
}
impl std::error::Error for SourceFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.original.as_ref())
    }
}
/// One explicitly polled real source. J is bounded caller metadata (typed
/// original engine/ADD/HELLO tokens), never arbitrary private bytes or authority.
pub struct Pils<'id, J> {
    client: Client<'id, 32>,
    clock: Arc<dyn RuntimeClock>,
    epoch: Option<Epoch<'id>>,
    identity: Option<Identity<'id>>,
    source: Bounds,
    initial: Option<Instant>,
    input: Option<Instant>,
    rows: Vec<Row<'id, J>>,
    events: VecDeque<Event<'id, J>>,
    limits: Limits,
    alarm: Option<Pin<Box<Sleep>>>,
    closed: bool,
}
impl<'id, J> Pils<'id, J> {
    /// Reserve real client and fixed metadata only; never enable_local_key.
    pub fn new(
        instance: &'id mut pc::Instance,
        source: EndpointSource,
        profile: Profile,
        hello: HelloLimits,
        limits: Limits,
    ) -> Result<Self, Failure> {
        if limits.jobs == 0 || limits.jobs > 32 {
            return Err(Fault::Capacity.into());
        }
        for d in [limits.source, limits.initial, limits.input, limits.retire] {
            if d.is_zero() || Instant::now().checked_add(d).is_none() {
                return Err(Fault::InvalidInput.into());
            }
        }
        let clock = source.clock();
        let bounds = Bounds::after(clock.sample()?.now.as_micros(), limits.source)?;
        let initial = Some(
            Instant::now()
                .checked_add(limits.initial)
                .ok_or(Fault::Overflow)?
                .min(bounds.hard),
        );
        let mut rows = Vec::new();
        rows.try_reserve_exact(limits.jobs)
            .map_err(|_| Fault::Capacity)?;
        let mut events = VecDeque::new();
        events
            .try_reserve_exact(limits.jobs + 4)
            .map_err(|_| Fault::Capacity)?;
        let client = Client::new(instance, source, profile, limits.client, hello)?;
        Ok(Self {
            client,
            clock,
            epoch: None,
            identity: None,
            source: bounds,
            initial,
            input: None,
            rows,
            events,
            limits,
            alarm: None,
            closed: false,
        })
    }
    /// Cancel this original epoch's admitted jobs without replacing its healthy
    /// physical PILS source or its actual ordered identity observations. Copied
    /// suffixes remain under the original bounds until real quiescence/loss.
    pub fn cancel_all(&mut self) -> Result<(), Failure> {
        for i in 0..self.rows.len() {
            if !self.rows[i].cancelled {
                let operation = self.rows[i].operation;
                self.cancel(operation)?;
            }
        }
        Ok(())
    }
    /// Original native job metadata still awaiting a terminal observation.
    pub fn pending_jobs(&self) -> usize {
        self.rows.len()
    }
    /// A genuine source failure cannot be cleared by a core epoch rotation.
    pub fn reusable(&self) -> bool {
        !self.closed
    }
    /// Real actual-current public observation only.
    pub fn identity(&self) -> Option<Identity<'id>> {
        self.identity
    }
    /// Exact current public HELLO; not a stronger address-authentication claim.
    pub fn announcement(&self) -> Option<&[u8]> {
        self.client.announcement()
    }
    /// Same canonical source for provider composition.
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    fn reserve(&self, bounds: Bounds) -> Result<Epoch<'id>, Fault> {
        if self.closed {
            return Err(Fault::Closed);
        }
        if self.rows.len() >= self.limits.jobs {
            return Err(Fault::Capacity);
        }
        if !bounds.live(self.clock.sample()?.now.as_micros()) {
            return Err(Fault::Deadline);
        }
        self.epoch.ok_or(Fault::NotReady)
    }
    /// Admit a real signature over the immutable exact purpose region, keeping
    /// original metadata on refusal. Actual result must match this physical MQ
    /// and expected signer; same wire RID on another source cannot satisfy it.
    pub fn sign(
        &mut self,
        origin: J,
        expected: EddsaPublicKey,
        region: &[u8],
        bounds: Bounds,
    ) -> Result<OperationId<'id>, Rejected<J>> {
        let epoch = match self.reserve(bounds) {
            Ok(e) => e,
            Err(reason) => {
                return Err(Rejected {
                    value: origin,
                    reason,
                });
            }
        };
        let identity = match self.identity {
            Some(i) if i.epoch() == epoch && i.peer() == expected => i,
            _ => {
                return Err(Rejected {
                    value: origin,
                    reason: Fault::NotReady,
                });
            }
        };
        let operation = match self.client.sign(region, KeyTarget::Exact(identity)) {
            Ok(op) => op,
            Err(error) => {
                let reason = match error {
                    native::Error::Protocol(reason) => reason,
                    other => {
                        self.stop(Box::new(other), None);
                        Fault::Io
                    }
                };
                return Err(Rejected {
                    value: origin,
                    reason,
                });
            }
        };
        self.rows.push(Row {
            operation,
            epoch,
            origin,
            kind: Kind::Sign(expected),
            bounds,
            cancelled: false,
            retire: None,
        });
        Ok(operation)
    }
    /// Actual unsigned FEED on a physically attached MQ. Empty actual address
    /// sets are valid, including bootstrap before a first public identity.
    pub fn feed(
        &mut self,
        origin: J,
        builder: &HelloBuilder<'_>,
        bounds: Bounds,
    ) -> Result<OperationId<'id>, Rejected<J>> {
        let epoch = match self.reserve(bounds) {
            Ok(e) => e,
            Err(reason) => {
                return Err(Rejected {
                    value: origin,
                    reason,
                });
            }
        };
        let operation = match self.client.feed_addresses(builder) {
            Ok(op) => op,
            Err(error) => {
                let reason = match error {
                    native::Error::Protocol(reason) => reason,
                    other => {
                        self.stop(Box::new(other), None);
                        Fault::Io
                    }
                };
                return Err(Rejected {
                    value: origin,
                    reason,
                });
            }
        };
        self.rows.push(Row {
            operation,
            epoch,
            origin,
            kind: Kind::Feed,
            bounds,
            cancelled: false,
            retire: None,
        });
        Ok(operation)
    }
    /// Actual logical cancellation preserves the immutable copied suffix until
    /// operation_quiescent or original physical source retirement. No wire ACK.
    pub fn cancel(&mut self, operation: OperationId<'id>) -> Result<(), Failure> {
        let Some(index) = self.rows.iter().position(|r| r.operation == operation) else {
            if self.client.operation_quiescent(operation)? {
                return Ok(());
            }
            return Err(Fault::Stale.into());
        };
        let row = &mut self.rows[index];
        if !row.cancelled {
            self.client.cancel(operation)?;
            row.cancelled = true;
            row.retire = Some(
                Instant::now()
                    .checked_add(self.limits.retire)
                    .ok_or(Fault::Overflow)?
                    .min(row.bounds.hard),
            );
        }
        Ok(())
    }
    fn stop(&mut self, cause: Failure, report: Option<&pc::LossReport<'id, 32>>) {
        if self.closed {
            return;
        }
        self.closed = true;
        let mut owned_report = None;
        let mut cleanup = None;
        if report.is_none() && self.client.epoch().is_some() {
            match self.client.reconnect() {
                Ok(native::Progress::Lost { report, .. }) => owned_report = Some(report),
                Ok(_) => cleanup = Some(Box::new(Fault::Stale) as Failure),
                Err(error) => cleanup = Some(Box::new(error) as Failure),
            }
        }
        let cause = if let Some(cleanup) = cleanup {
            Box::new(SourceFailure {
                original: cause,
                cleanup,
            }) as Failure
        } else {
            cause
        };
        let report = report.or(owned_report.as_ref());
        let epoch = self.epoch.take();
        let _originals = self.client.close();
        self.identity = None;
        self.initial = None;
        self.input = None;
        self.alarm = None;
        for row in self.rows.drain(..) {
            let feed = if matches!(row.kind, Kind::Feed) {
                report.and_then(|r| {
                    r.feeds()
                        .find(|f| f.operation == row.operation)
                        .map(|f| f.disposition)
                })
            } else {
                None
            };
            self.events.push_back(Event::Failed {
                origin: row.origin,
                reason: if row.cancelled {
                    Reason::Cancelled
                } else {
                    Reason::Lost(feed)
                },
            });
        }
        self.events.push_back(Event::SourceLost { epoch, cause });
    }
    /// Actual no-clock physical retirement, returning every original metadata
    /// item through subsequent poll. This is not a new authority or remote erase.
    pub fn close(&mut self) {
        self.stop(Box::new(Fault::Closed), None);
    }
    /// Native guard before any enclosing canonical wait; no IO/decode/crypto.
    pub fn native_guard(&mut self, cx: &mut Context<'_>) -> Result<(), Failure> {
        if self.closed {
            return Ok(());
        }
        let now = Instant::now();
        if now >= self.source.hard
            || self.initial.is_some_and(|at| now >= at)
            || self.input.is_some_and(|at| now >= at)
            || self
                .rows
                .iter()
                .any(|r| now >= r.bounds.hard || r.retire.is_some_and(|at| now >= at))
        {
            self.stop(Box::new(Fault::Deadline), None);
            return Ok(());
        }
        let mut i = 0;
        while i < self.rows.len() {
            if self.rows[i].cancelled && self.client.operation_quiescent(self.rows[i].operation)? {
                let row = self.rows.remove(i);
                self.events.push_back(Event::Failed {
                    origin: row.origin,
                    reason: Reason::Cancelled,
                });
            } else {
                i += 1;
            }
        }
        let due = Some(self.source.hard)
            .into_iter()
            .chain(self.initial)
            .chain(self.input)
            .chain(
                self.rows
                    .iter()
                    .flat_map(|r| Some(r.bounds.hard).into_iter().chain(r.retire)),
            )
            .min();
        if let Some(at) = due {
            let alarm = self
                .alarm
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
            alarm.as_mut().reset(at);
            if alarm.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        Ok(())
    }
    fn progress(&mut self, p: native::Progress<'id, 32>) -> Result<(), Failure> {
        match p {
            native::Progress::Connected(epoch) => {
                if self.epoch.is_some() {
                    return Err(Fault::Stale.into());
                }
                self.epoch = Some(epoch);
                self.events.push_back(Event::Connected(epoch));
            }
            native::Progress::Inbound(Inbound::Identity {
                identity,
                identity_changed,
                ..
            }) => {
                self.input = None;
                if self.epoch != Some(identity.epoch()) {
                    return Err(Fault::Stale.into());
                }
                self.identity = Some(identity);
                self.initial = None;
                self.events.push_back(Event::Identity {
                    identity,
                    changed: identity_changed,
                });
            }
            native::Progress::Inbound(Inbound::Complete(completion)) => {
                self.input = None;
                let operation = completion.operation();
                let Some(i) = self.rows.iter().position(|r| r.operation == operation) else {
                    return Ok(());
                };
                if Some(self.rows[i].epoch) != self.epoch {
                    return Err(Fault::Stale.into());
                }
                if !self.rows[i].cancelled {
                    match &completion {
                        Completion::Signature { peer, .. } if matches!(self.rows[i].kind,Kind::Sign(expected) if expected==*peer) =>
                            {}
                        Completion::Failed { .. } => {}
                        _ => return Err(Fault::Authentication.into()),
                    }
                }
                let row = self.rows.remove(i);
                if row.cancelled {
                    self.events.push_back(Event::Failed {
                        origin: row.origin,
                        reason: Reason::Cancelled,
                    });
                    return Ok(());
                }
                match completion {
                    Completion::Signature {
                        peer, signature, ..
                    } => {
                        self.events.push_back(Event::Signature {
                            origin: row.origin,
                            peer,
                            signature,
                        });
                    }
                    Completion::Failed { reason, .. } => self.events.push_back(Event::Failed {
                        origin: row.origin,
                        reason: Reason::Refused(reason),
                    }),
                    Completion::Decapsulated { .. } | Completion::Ecdh { .. } => {
                        return Err(Fault::Malformed.into());
                    }
                }
            }
            native::Progress::Inbound(Inbound::Ignored) => self.input = None,
            native::Progress::Written(written) => {
                if written.kind == OperationKind::Feed
                    && let Some(i) = self
                        .rows
                        .iter()
                        .position(|r| r.operation == written.operation)
                {
                    if Some(self.rows[i].epoch) != self.epoch
                        || !matches!(self.rows[i].kind, Kind::Feed)
                    {
                        return Err(Fault::Stale.into());
                    }
                    let row = self.rows.remove(i);
                    self.events.push_back(if row.cancelled || written.canceled {
                        Event::Failed {
                            origin: row.origin,
                            reason: Reason::Cancelled,
                        }
                    } else {
                        Event::FeedWritten(row.origin)
                    });
                }
            }
            native::Progress::Lost { cause, report, .. } => {
                self.stop(Box::new(Cause(cause)), Some(&report))
            }
            native::Progress::Activity { read_bytes, .. } => {
                if read_bytes > 0 && self.input.is_none() {
                    self.input = Some(
                        Instant::now()
                            .checked_add(self.limits.input)
                            .ok_or(Fault::Overflow)?,
                    );
                }
            }
            native::Progress::ConnectRetry { .. } => {}
            native::Progress::Unavailable(error) => return Err(Box::new(error)),
            native::Progress::WaitDeadline => {}
            native::Progress::Closed => self.stop(Box::new(Fault::Closed), None),
        }
        Ok(())
    }
    /// Drive one real source event. Queueing/writing are not fabricated signature
    /// completion. Any fatal result first closes all original native debt.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Event<'id, J>, Failure>> {
        if let Err(error) = self.native_guard(cx) {
            self.stop(error, None);
        }
        if let Some(event) = self.events.pop_front() {
            return Poll::Ready(Ok(event));
        }
        if self.closed {
            return Poll::Pending;
        }
        let now = match self.clock.sample() {
            Ok(s) => s.now.as_micros(),
            Err(error) => {
                self.stop(Box::new(error), None);
                return Poll::Ready(Ok(self.events.pop_front().ok_or(Fault::NotReady)?));
            }
        };
        if now >= self.source.expires || self.rows.iter().any(|r| now >= r.bounds.expires) {
            self.stop(Box::new(Fault::Deadline), None);
            return Poll::Ready(Ok(self.events.pop_front().ok_or(Fault::NotReady)?));
        }
        let result = {
            let mut driving = std::pin::pin!(self.client.drive(None));
            driving.as_mut().poll(cx)
        };
        match result {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => {
                self.stop(Box::new(error), None);
                Poll::Ready(Ok(self.events.pop_front().ok_or(Fault::NotReady)?))
            }
            Poll::Ready(Ok(p)) => {
                if let Err(error) = self.progress(p) {
                    self.stop(error, None);
                }
                self.native_guard(cx)?;
                Poll::Ready(Ok(self.events.pop_front().unwrap_or(Event::Activity)))
            }
        }
    }
}
impl<J> Drop for Pils<'_, J> {
    fn drop(&mut self) {
        let _originals = self.client.close();
    }
}
