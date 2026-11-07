pub mod burst;
pub mod dv_bridge;
mod retirement;
use crate::framed::Framed;
use gnunet_crypto::Entropy;
use gnunet_service_runtime::service::Listener;
use gnunet_service_runtime::{connection::Connection, framing::OwnedFrame};
use gnunet_transport::{
    ClientId, Engine, Output, PeerId, QueueRejection, ReceiveOutcome, Signer, Times, WorkDeferral,
    WorkStatus,
};
use gnunet_types::{Error, MonoInstant};
use gnunet_wire::official::AbsoluteTime;
pub use retirement::{DvRetirementWork, NativeGuardEvent, NativeRetirement, RetirementCause};
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
/// Authenticated-address storage-result port; an error stops later domain output.
pub trait AddressStore {
    /// Store the validated address and its authenticated peer binding. A native
    /// service result carries only that service's processing assurance; no MQ
    /// response is itself a filesystem/fsync proof.
    fn validated(&mut self, peer: PeerId, address: &[u8], until: u64) -> Result<(), Error>;
    /// Poll the same original persistence effect until its actual terminal
    /// result. Pending is not admission or completion; retain its original
    /// STORE operation/source/targets and do not re-enqueue on subsequent polls.
    /// A synchronous actual store keeps its existing semantics through Ready.
    fn poll_validated(
        &mut self,
        _cx: &mut Context<'_>,
        peer: PeerId,
        address: &[u8],
        until: u64,
    ) -> Poll<Result<(), Error>> {
        Poll::Ready(self.validated(peer, address, until))
    }
}
/// One fair physical/protocol step, including observable nonfatal input refusal.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Step {
    /// Actual admission, IO or protocol progress; no delivery is inferred.
    Progress,
    /// Exact slow observation MQ was physically retired; no gap or END is fabricated.
    MonitorRetired(gnunet_transport::monitor::Retirement),
    /// Original known queue refused a numeric update and remains available.
    InputRejected(QueueRejection),
    /// One complete original address ADD refused local quota; owner stays live.
    AddressRejected(gnunet_transport::addresses::AddressRejection),
    /// Input/timer progress committed; this original TX needs explicit retry.
    WorkDeferred(WorkDeferral),
}
/// Finite original accepted-source, partial-input and output-head bounds.
#[derive(Clone, Copy, Debug)]
pub struct NativeLimits {
    /// Whole accepted IPC source lease.
    pub lifetime: Duration,
    /// First positive input byte through complete frame.
    pub input: Duration,
    /// Each original queued head through whole write; progress cannot renew it.
    pub output: Duration,
}
impl Default for NativeLimits {
    fn default() -> Self {
        Self {
            lifetime: Duration::from_secs(86400),
            input: Duration::from_secs(10),
            output: Duration::from_secs(10),
        }
    }
}
impl NativeLimits {
    fn validate(self) -> Result<(), Error> {
        for d in [self.lifetime, self.input, self.output] {
            if d.is_zero() || Instant::now().checked_add(d).is_none() {
                return Err(Error::InvalidInput);
            }
        }
        Ok(())
    }
}
struct Validated {
    peer: PeerId,
    address: Vec<u8>,
    until: AbsoluteTime,
}
/// Output FIFO readiness is independent of already admitted physical IO.
#[derive(Clone, Copy, Eq, PartialEq)]
enum OutputState {
    Ready,
    Deferred,
    // Yield to the Bridge's exact original cancellation before any old write.
    Retiring,
}
struct Client {
    id: ClientId,
    io: Framed,
    lease: Instant,
    input: Option<Instant>,
    output: Option<Instant>,
    monitor: bool,
    // First positive RX byte fixes the original local DV source. Native retire
    // closes retained old-source partial/complete RX before any new source.
    dv_rx_source: Option<gnunet_transport::dv_bridge::Source>,
}
/// Caller-driven process-level TRANSPORT IPC host, with fair socket directions.
/// Dropped step futures retain all original buffers/cursors/connection owners.
pub struct Server {
    native_retirement: Option<NativeRetirement>,
    dv_deadlines: Vec<dv_bridge::Deadline>,
    burst_deadline: Option<burst::Guard>,
    discovery: crate::discovery::Pending,
    engine: Engine,
    clients: Vec<Client>,
    cursor: usize,
    maximum: usize,
    pending_bytes: usize,
    pending_frame: Option<(ClientId, OwnedFrame)>,
    pending_validated: Option<Validated>,
    settled_step: Option<Step>,
    monitor_retirements: std::collections::VecDeque<gnunet_transport::monitor::Retirement>,
    timer_step: Option<Step>,
    native: NativeLimits,
    tolerant: bool,
    alarm: Option<Pin<Box<Sleep>>>,
}
impl Server {
    /// Construct a host around its already-reserved pure engine.
    pub fn new(engine: Engine, maximum: usize, pending_bytes: usize) -> Result<Self, Error> {
        Self::new_with_native(engine, maximum, pending_bytes, NativeLimits::default())
    }
    /// Reserve actual finite native resources; creates no socket/task/timer.
    pub fn new_with_native(
        engine: Engine,
        maximum: usize,
        pending_bytes: usize,
        native: NativeLimits,
    ) -> Result<Self, Error> {
        native.validate()?;
        if maximum == 0 || pending_bytes < 65535 {
            return Err(Error::InvalidInput);
        }
        let mut clients = Vec::new();
        clients
            .try_reserve_exact(maximum)
            .map_err(|_| Error::Capacity)?;
        let mut monitor_retirements = std::collections::VecDeque::new();
        monitor_retirements
            .try_reserve_exact(maximum)
            .map_err(|_| Error::Capacity)?;
        Ok(Self {
            native_retirement: None,
            dv_deadlines: Vec::new(),
            burst_deadline: None,
            discovery: crate::discovery::Pending::default(),
            engine,
            clients,
            cursor: 0,
            maximum,
            pending_bytes,
            pending_frame: None,
            pending_validated: None,
            settled_step: None,
            monitor_retirements,
            timer_step: None,
            native,
            tolerant: false,
            alarm: None,
        })
    }
    /// Standard SERVICE tolerance applies only to unknown IPC types, never to
    /// malformed known messages, role/credit errors or unsupported peer bodies.
    pub fn set_tolerant(&mut self, tolerant: bool) {
        self.tolerant = tolerant;
    }
    /// An original authenticated persistence effect still owns the domain
    /// output barrier. Native guards/IO/retirement must continue while Pending.
    pub fn persistence_pending(&self) -> bool {
        self.pending_validated.is_some()
    }
    /// Drive one due original1300 connection demand against a candidate source.
    /// Call this along with native steps/ticks. The bounded source operation
    /// retains its original lease on failure; it never grants peer authenticity.
    /// `now` is engine logical time, `utc` is actual expiry-checking UTC.
    pub fn discover(
        &mut self,
        now: u64,
        utc: u64,
        source: &mut impl crate::discovery::AddressSource,
        quantum: core::num::NonZeroUsize,
    ) -> Result<crate::discovery::DiscoveryStep, Error> {
        self.discover_at(
            Times::new(MonoInstant(now), AbsoluteTime::from_micros(utc)),
            source,
            quantum,
        )
    }
    /// Drive an original demand with independent scheduling/record-expiry
    /// coordinates. Candidate source expiry uses this sample's actual absolute.
    pub fn discover_at(
        &mut self,
        times: Times,
        source: &mut impl crate::discovery::AddressSource,
        quantum: core::num::NonZeroUsize,
    ) -> Result<crate::discovery::DiscoveryStep, Error> {
        self.discovery
            .drive_at(&mut self.engine, times, source, quantum)
    }
    /// Borrow actual protocol/resource state for observation.
    pub fn engine(&self) -> &Engine {
        &self.engine
    }
    /// Borrow the original aggregate while the real PILS port prepares its copy.
    pub fn address_publication(
        &self,
    ) -> Result<Option<gnunet_transport::addresses::Publication<'_>>, Error> {
        self.engine.address_publication()
    }
    /// Current original ADDs independently of the aggregate FEED write state.
    pub fn local_addresses(
        &self,
    ) -> impl Iterator<Item = gnunet_transport::addresses::LocalAddress<'_>> {
        self.engine.local_addresses()
    }
    /// Check an original admitted ADD before handing its certificate to storage.
    pub fn owns_local_address(&self, lease: &gnunet_transport::addresses::AddressLease) -> bool {
        self.engine.owns_local_address(lease)
    }
    /// Original FLOW provider demand; it carries no durable receipt by itself.
    pub fn monotime_demand(&self) -> Option<&gnunet_transport::monotime::Demand> {
        self.engine.monotime_demand()
    }
    /// Supply an actual committed original range without rebinding its Engine.
    pub fn supply_monotime(
        &mut self,
        id: &gnunet_transport::monotime::DemandId,
        span: gnunet_transport::monotime::Span,
        times: Times,
    ) -> Result<(), Error> {
        self.engine.supply_monotime(id, span, times)
    }
    /// Retire an exact original demand without extending its targets.
    pub fn retire_monotime(
        &mut self,
        id: &gnunet_transport::monotime::DemandId,
    ) -> Result<(), Error> {
        self.engine.retire_monotime(id)
    }
    /// Record an actual unusable commit as burnt, without authorizing output.
    pub fn burn_monotime(
        &mut self,
        id: &gnunet_transport::monotime::DemandId,
        span: gnunet_transport::monotime::Span,
    ) -> Result<(), Error> {
        self.engine.burn_monotime(id, span)
    }
    /// Original aggregate view even after its FEED write is settled.
    pub fn address_snapshot(&self) -> Result<gnunet_transport::addresses::Publication<'_>, Error> {
        self.engine.address_snapshot()
    }
    /// Compare an observed public HELLO's claims with this original resource set.
    pub fn addresses_match(&self, hello: gnunet_hello::Hello<'_>) -> bool {
        self.engine.addresses_match(hello)
    }
    /// Create a new current-resource publication, never replay an old FEED body.
    pub fn refresh_address_publication(&mut self) -> Result<(), Error> {
        self.engine.refresh_address_publication()
    }
    /// Claim only after the actual current-PILS FEED operation was admitted.
    pub fn claim_address_publication(
        &mut self,
        id: &gnunet_transport::addresses::PublicationId,
    ) -> Result<(), Error> {
        self.engine.claim_address_publication(id)
    }
    /// Record the original local full write; this does not acknowledge application.
    pub fn address_publication_written(
        &mut self,
        id: &gnunet_transport::addresses::PublicationId,
    ) -> Result<(), Error> {
        self.engine.address_publication_written(id)
    }
    /// Borrow the original unclaimed purpose35 signing effect.
    pub fn validation_request(&self) -> Option<&gnunet_transport::signing::ValidationRequest> {
        self.engine.validation_request()
    }
    /// Claim only after the real signing-service owner admitted its operation.
    pub fn claim_validation(
        &mut self,
        id: &gnunet_transport::signing::ValidationId,
    ) -> Result<(), Error> {
        self.engine.claim_validation(id)
    }
    /// Query retirement without granting authority to a replacement owner.
    #[must_use]
    pub fn validation_live(&self, id: &gnunet_transport::signing::ValidationId) -> bool {
        self.engine.validation_live(id)
    }
    /// Cancel the pure original while original handed native bytes still drain.
    pub fn cancel_validation(
        &mut self,
        id: &gnunet_transport::signing::ValidationId,
    ) -> Result<(), Error> {
        self.engine.cancel_validation(id)
    }
    /// Validate the actual signer/snapshot and enqueue the exact original route.
    /// Local resource rejection retains the pure effect; no IPC input is replayed.
    pub fn complete_validation(
        &mut self,
        id: &gnunet_transport::signing::ValidationId,
        signer: PeerId,
        signature: [u8; 64],
        now: u64,
    ) -> Result<(), Error> {
        self.complete_validation_at(id, signer, signature, Times::shared_coordinate(now))
    }
    /// Complete the exact original signed effect with actual independent clocks;
    /// retained signature TTL and original route checks use only local mono.
    pub fn complete_validation_at(
        &mut self,
        id: &gnunet_transport::signing::ValidationId,
        signer: PeerId,
        signature: [u8; 64],
        times: Times,
    ) -> Result<(), Error> {
        self.engine
            .complete_validation_at(id, signer, signature, times)
    }
    /// Admit an already owned canonical connection; listener/ACL selection is external.
    /// Official applications may remain completely idle without an INIT. Their
    /// original source lease and accepted-source cap apply immediately; the
    /// partial-input bound begins only with actual positive input bytes.
    pub fn admit(&mut self, connection: Connection) -> Result<ClientId, Error> {
        if self
            .clients
            .len()
            .checked_add(self.monitor_retirements.len())
            .is_none_or(|n| n >= self.maximum)
        {
            return Err(Error::Capacity);
        }
        let now = Instant::now();
        let lease = now
            .checked_add(self.native.lifetime)
            .ok_or(Error::Overflow)?;
        let io = Framed::new(connection, self.pending_bytes)?;
        let id = self.engine.accept()?;
        self.clients.push(Client {
            id: id.clone(),
            io,
            lease,
            input: None,
            output: None,
            monitor: false,
            dv_rx_source: None,
        });
        Ok(id)
    }
    fn close(&mut self, index: usize) -> Result<(), Error> {
        let client = self.clients.remove(index);
        if self
            .pending_frame
            .as_ref()
            .is_some_and(|(id, _)| *id == client.id)
        {
            drop(self.pending_frame.take());
        }
        let Client { id, io, .. } = client;
        drop(io);
        self.burst_native_closed(&id);
        self.engine.close(&id)
    }
    /// Soft shutdown drains actual non-monitor sources. Monitor-only sockets
    /// never keep a standard SOFT_SHUTDOWN service alive by themselves.
    pub fn draining_complete(&self) -> bool {
        self.clients.iter().all(|c| c.monitor)
    }
    /// Physical accepted-source retirement; no clock sample or fake callback.
    pub fn close_client(&mut self, id: &ClientId) -> Result<(), Error> {
        let index = self
            .clients
            .iter()
            .position(|c| c.id == *id)
            .ok_or(Error::Stale)?;
        self.close(index)
    }
    /// Physically retire one exact failed observer before any old source IO.
    fn retire_monitor(&mut self) -> Result<Option<ClientId>, Error> {
        if self.monitor_retirements.len() >= self.maximum {
            return Ok(None);
        }
        let Some(original) = self.engine.take_monitor_retirement() else {
            return Ok(None);
        };
        let id = original.client.clone();
        let index = self.clients.iter().position(|c| c.id == id);
        self.monitor_retirements.push_back(original);
        if let Some(index) = index {
            self.close(index)?;
        }
        Ok(Some(id))
    }
    /// Check/register original native bounds while persistence or canonical time
    /// is pending. Reclaim fully local transfers; retire original MQs for native
    /// or uncertain debt. The returned action distinguishes those two facts.
    pub fn poll_native_guard(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Result<Option<NativeGuardEvent>, Error> {
        if let Some(id) = self.retire_monitor()? {
            return Ok(Some(NativeGuardEvent::SourceRetired(id)));
        }
        let now = Instant::now();
        if let Some(id) = self.burst_expired(now)? {
            self.close_client(&id)?;
            return Ok(Some(NativeGuardEvent::SourceRetired(id)));
        }
        if let Some((id, cause)) = self.dv_expired(now) {
            if let RetirementCause::DvDeadline {
                work: DvRetirementWork::Transfer { id: transfer, .. },
                ..
            } = &cause
            {
                if matches!(
                    self.dv_cancel_transfer_pre_native(transfer)?,
                    gnunet_transport::dv_bridge::TransferCancellation::Unsent { .. }
                ) {
                    return Ok(Some(NativeGuardEvent::TransferUnsent(transfer.clone())));
                }
                // The same native target ends this original logical Job even
                // when canonical tick has not run yet. Known packet results
                // and an unsent suffix are not unknown physical source debt.
                self.engine.dv_cancel_transfer(transfer)?;
                if let Some(outcome) = self.dv_finish_settled_transfer(transfer)? {
                    return Ok(Some(NativeGuardEvent::TransferSettled {
                        id: transfer.clone(),
                        outcome,
                    }));
                }
            }
            let index = self
                .clients
                .iter()
                .position(|c| c.id == id)
                .ok_or(Error::Stale)?;
            self.close_observed(index, cause)?;
            return Ok(Some(NativeGuardEvent::SourceRetired(id)));
        }
        if let Some(i) = self.clients.iter().position(|c| {
            now >= c.lease
                || c.input.is_some_and(|at| now >= at)
                || c.output.is_some_and(|at| now >= at)
        }) {
            let id = self.clients[i].id.clone();
            self.close_observed(i, RetirementCause::NativeDeadline)?;
            return Ok(Some(NativeGuardEvent::SourceRetired(id)));
        }
        let due = self
            .clients
            .iter()
            .flat_map(|c| Some(c.lease).into_iter().chain(c.input).chain(c.output))
            .chain(self.dv_next_deadline())
            .chain(self.burst_next_deadline())
            .min();
        if let Some(at) = due {
            let alarm = self
                .alarm
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
            alarm.as_mut().reset(at);
            if alarm.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        } else {
            self.alarm = None;
        }
        Ok(None)
    }
    fn outputs(&mut self, store: &mut impl AddressStore) -> Result<(), Error> {
        if self.outputs_inner(None, store, &mut dv_bridge::NoObserver)? == OutputState::Ready {
            Ok(())
        } else {
            Err(Error::WouldBlock)
        }
    }
    fn poll_outputs(
        &mut self,
        cx: &mut Context<'_>,
        store: &mut impl AddressStore,
    ) -> Poll<Result<(), Error>> {
        self.poll_outputs_observed(cx, store, &mut dv_bridge::NoObserver)
    }
    fn poll_outputs_observed(
        &mut self,
        cx: &mut Context<'_>,
        store: &mut impl AddressStore,
        observer: &mut dyn dv_bridge::NativeObserver,
    ) -> Poll<Result<(), Error>> {
        match self.outputs_inner(Some(cx), store, observer) {
            Ok(OutputState::Ready) => Poll::Ready(Ok(())),
            Ok(OutputState::Deferred | OutputState::Retiring) => Poll::Pending,
            Err(error) => Poll::Ready(Err(error)),
        }
    }
    fn outputs_inner(
        &mut self,
        mut cx: Option<&mut Context<'_>>,
        store: &mut impl AddressStore,
        observer: &mut dyn dv_bridge::NativeObserver,
    ) -> Result<OutputState, Error> {
        loop {
            while self.retire_monitor()?.is_some() {}
            if let Some(original) = &self.pending_validated {
                let result = match cx.as_deref_mut() {
                    Some(cx) => store.poll_validated(
                        cx,
                        original.peer,
                        &original.address,
                        original.until.as_micros(),
                    ),
                    None => Poll::Ready(store.validated(
                        original.peer,
                        &original.address,
                        original.until.as_micros(),
                    )),
                };
                match result {
                    Poll::Pending => return Ok(OutputState::Deferred),
                    Poll::Ready(Err(error)) => return Err(error),
                    Poll::Ready(Ok(())) => {
                        self.pending_validated = None;
                        continue;
                    }
                }
            }

            if self.pending_frame.is_none() {
                match self.engine.output() {
                    Some(Output::Frame { client, bytes }) => {
                        self.pending_frame = Some((client, OwnedFrame::new(bytes)))
                    }
                    Some(Output::Validated {
                        peer,
                        address,
                        until,
                    }) => {
                        self.pending_validated = Some(Validated {
                            peer,
                            address,
                            until: AbsoluteTime::from_micros(until),
                        });
                        continue;
                    }
                    None => break,
                }
            }
            let Some((client, frame)) = self.pending_frame.as_ref() else {
                break;
            };
            let Some(index) = self.clients.iter().position(|c| c.id == *client) else {
                drop(self.pending_frame.take());
                continue;
            };
            let tag = self.engine.dv_frame_tag(client, frame.bytes());
            let parent = tag.as_ref().and_then(|id| self.engine.dv_chunk_parent(id));
            if let Some(parent) = &parent {
                match observer.ready(parent, &self.engine) {
                    Ok(dv_bridge::NativeAdmission::Admit) => {}
                    Ok(dv_bridge::NativeAdmission::Deferred) => return Ok(OutputState::Deferred),
                    Ok(dv_bridge::NativeAdmission::Retiring) => return Ok(OutputState::Retiring),
                    Err(error) => {
                        if let Err(cleanup) =
                            self.close_observed(index, RetirementCause::ObserverRefusal(error))
                        {
                            observer.cleanup(cleanup);
                        }
                        return Err(error);
                    }
                }
            }
            let reserved = if tag.is_some() {
                self.clients[index].io.reserve_tagged(frame.len())
            } else {
                self.clients[index].io.reserve(frame.len())
            };
            match reserved {
                Ok(()) => {}
                Err(Error::WouldBlock) => {
                    if gnunet_wire::official::Frame::decode(frame.bytes()).is_ok_and(|f| {
                        matches!(f.header().message_type().value(), 1251 | 1252 | 1256 | 1257)
                    }) {
                        self.monitor_retirements
                            .push_back(gnunet_transport::monitor::Retirement {
                                client: client.clone(),
                                reason: Error::WouldBlock,
                            });
                    }
                    drop(self.pending_frame.take());
                    self.close_observed(index, RetirementCause::OutputPressure)?;
                    continue;
                }
                // Retain the exact original effect and bytes on a metadata
                // allocation refusal. No engine replay or false delivery occurs.
                Err(error) => return Err(error),
            }
            let output = match self.clients[index].output {
                Some(at) => Some(at),
                None => Some(
                    Instant::now()
                        .checked_add(self.native.output)
                        .ok_or(Error::Overflow)?,
                ),
            };
            let command = gnunet_wire::official::Frame::decode(frame.bytes())?
                .header()
                .message_type()
                == gnunet_wire::official::message_type::TRANSPORT_START_BURST;
            if command && !self.burst_queue_allowed(client) {
                return Err(Error::NotReady);
            }
            let Some((client, frame)) = self.pending_frame.take() else {
                return Err(Error::Stale);
            };
            if let Err(rejected) = self.clients[index].io.queue_tagged(frame, tag.clone()) {
                self.pending_frame = Some((client, rejected.value));
                return Err(rejected.reason);
            }
            if command {
                let end = self.clients[index].io.queued_cursor();
                self.burst_queued(&client, end)?;
            }
            self.clients[index].output = output;
            if let Some(tag) = &tag
                && let Some(parent) = self.engine.dv_chunk_queued(tag)?
                && let Err(error) = observer.queued(&parent)
            {
                if let Err(cleanup) =
                    self.close_observed(index, RetirementCause::ObserverRefusal(error))
                {
                    observer.cleanup(cleanup);
                }
                return Err(error);
            }
        }
        Ok(OutputState::Ready)
    }
    /// Advance timers exactly once per caller's scheduled tick, never in an idle spin.
    pub fn tick(
        &mut self,
        now: u64,
        entropy: &mut impl Entropy,
        store: &mut impl AddressStore,
    ) -> Result<Step, Error> {
        self.tick_at(Times::shared_coordinate(now), entropy, store)
    }
    /// Advance only the local mono schedule, preserving true absolute output
    /// expiration and the same original persistence effect.
    pub fn tick_at(
        &mut self,
        times: Times,
        entropy: &mut impl Entropy,
        store: &mut impl AddressStore,
    ) -> Result<Step, Error> {
        let status = self.engine.tick_at(times, entropy)?;
        self.outputs(store)?;
        Ok(Self::work_step(status))
    }
    /// Poll a scheduled timer advance exactly once through a possibly pending
    /// real persistence barrier. Its original Step is retained until Ready.
    pub fn poll_tick(
        &mut self,
        cx: &mut Context<'_>,
        now: u64,
        entropy: &mut impl Entropy,
        store: &mut impl AddressStore,
    ) -> Poll<Result<Step, Error>> {
        self.poll_tick_at(cx, Times::shared_coordinate(now), entropy, store)
    }
    /// Actual scheduled common Job progress with synchronous native DV receipt
    /// dispatch. Original timer/sample is captured once through storage Pending.
    pub fn poll_tick_observed_at(
        &mut self,
        cx: &mut Context<'_>,
        times: Times,
        entropy: &mut impl Entropy,
        store: &mut impl AddressStore,
        observer: &mut dyn dv_bridge::NativeObserver,
    ) -> Poll<Result<Step, Error>> {
        self.engine.validate_times(times)?;
        if self.timer_step.is_none() {
            self.timer_step = Some(Self::work_step(self.engine.tick_at(times, entropy)?));
        }
        match self.poll_outputs_observed(cx, store, observer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Poll::Ready(self.timer_step.take().ok_or(Error::NotReady)),
        }
    }
    /// Capture a scheduled typed-clock tick once. Re-polling while its actual
    /// STORE barrier waits never replays it or remints output expiry/deadlines.
    pub fn poll_tick_at(
        &mut self,
        cx: &mut Context<'_>,
        times: Times,
        entropy: &mut impl Entropy,
        store: &mut impl AddressStore,
    ) -> Poll<Result<Step, Error>> {
        self.engine.validate_times(times)?;
        if self.timer_step.is_none() {
            self.timer_step = Some(Self::work_step(self.engine.tick_at(times, entropy)?));
        }
        match self.poll_outputs(cx, store) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Poll::Ready(self.timer_step.take().ok_or(Error::NotReady)),
        }
    }
    /// Explicit retry of the same retained original common jobs, with actual
    /// native DV receipts. Uses the original timer_step barrier, not a new tick.
    pub fn poll_retry_observed_at(
        &mut self,
        cx: &mut Context<'_>,
        times: Times,
        entropy: &mut impl Entropy,
        store: &mut impl AddressStore,
        observer: &mut dyn dv_bridge::NativeObserver,
    ) -> Poll<Result<Step, Error>> {
        self.engine.validate_times(times)?;
        if self.timer_step.is_none() {
            self.timer_step = Some(Self::work_step(
                self.engine.retry_deferred_at(times, entropy)?,
            ));
        }
        match self.poll_outputs_observed(cx, store, observer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => Poll::Ready(self.timer_step.take().ok_or(Error::NotReady)),
        }
    }
    /// Same original retry gate as retry_deferred, with an actual asynchronous
    /// persistence receipt instead of a false queued-success return.
    pub fn poll_retry_deferred(
        &mut self,
        cx: &mut Context<'_>,
        now: u64,
        entropy: &mut impl Entropy,
        store: &mut impl AddressStore,
    ) -> Poll<Result<Step, Error>> {
        self.poll_retry_deferred_at(cx, Times::shared_coordinate(now), entropy, store)
    }
    /// Retry retained preflight once using actual mono. A new absolute sample
    /// does not replay the original retry or replace an admitted STORE target.
    pub fn poll_retry_deferred_at(
        &mut self,
        cx: &mut Context<'_>,
        times: Times,
        entropy: &mut impl Entropy,
        store: &mut impl AddressStore,
    ) -> Poll<Result<Step, Error>> {
        self.engine.validate_times(times)?;
        if self.timer_step.is_none() {
            self.timer_step = Some(Self::work_step(
                self.engine.retry_deferred_at(times, entropy)?,
            ));
        }
        match self.poll_outputs(cx, store) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => Poll::Ready(self.timer_step.take().ok_or(Error::NotReady)),
        }
    }
    /// Explicit resource-policy retry; no accepted IPC request is replayed.
    /// Ordinary poll/tick keep blocked originals dormant so other peers can progress.
    pub fn retry_deferred(
        &mut self,
        now: u64,
        entropy: &mut impl Entropy,
        store: &mut impl AddressStore,
    ) -> Result<Step, Error> {
        self.retry_deferred_at(Times::shared_coordinate(now), entropy, store)
    }
    /// Explicit retained-work retry with separate actual clock coordinates.
    pub fn retry_deferred_at(
        &mut self,
        times: Times,
        entropy: &mut impl Entropy,
        store: &mut impl AddressStore,
    ) -> Result<Step, Error> {
        let status = self.engine.retry_deferred_at(times, entropy)?;
        self.outputs(store)?;
        Ok(Self::work_step(status))
    }
    fn work_step(status: WorkStatus) -> Step {
        match status {
            WorkStatus::Ready => Step::Progress,
            WorkStatus::Deferred(reason) => Step::WorkDeferred(reason),
        }
    }
    /// Consume a complete head once, or retain a business head behind the
    /// domain barrier. Maintenance uses the same bounded communicator handlers
    /// without pumping new business Jobs; it never overwrites a settled result.
    fn receive_frame<S: Signer, E: Entropy>(
        &mut self,
        index: usize,
        times: Times,
        signer: &mut S,
        entropy: &mut E,
        observer: &mut dyn dv_bridge::NativeObserver,
        maintenance: bool,
    ) -> Result<Option<Step>, Error> {
        let frame = self.clients[index].io.frame().ok_or(Error::NotReady)?;
        let dv_bound = if self.engine.dv_source_active() && dv_bridge::is_dv(frame) {
            // A complete raw DV head may be waiting on Actor slots
            // that themselves owe SEND_ACKs later on this same MQ.
            // Move it to the existing bounded Engine inbox, retaining
            // its original first-byte/source bounds, so control input
            // can continue. Retirement still fences all old bytes.
            if !self.engine.dv_source_accepting() {
                return Ok(None);
            }
            let Some(source) = self.clients[index].dv_rx_source.clone() else {
                self.close_observed(index, RetirementCause::DvSourceRetired)?;
                return Ok(Some(Step::Progress));
            };
            if self.engine.dv_current_source() != Some(&source) {
                self.close_observed(index, RetirementCause::DvSourceRetired)?;
                return Ok(Some(Step::Progress));
            }
            let hard = self.clients[index]
                .input
                .unwrap_or(self.clients[index].lease)
                .min(self.clients[index].lease);
            let native = Instant::now();
            if native >= hard {
                self.close_observed(index, RetirementCause::NativeDeadline)?;
                return Ok(Some(Step::Progress));
            }
            let remaining = u64::try_from(hard.duration_since(native).as_micros())
                .map_err(|_| Error::Overflow)?;
            let until = MonoInstant(
                times
                    .monotonic()
                    .0
                    .checked_add(remaining)
                    .filter(|value| *value != u64::MAX && remaining != 0)
                    .ok_or(Error::Deadline)?,
            );
            let absolute = times
                .absolute_after(gnunet_wire::official::RelativeTime::from_micros(remaining))?;
            Some((source, until, absolute))
        } else {
            None
        };
        let id = self.clients[index].id.clone();
        let message_type = gnunet_wire::official::Frame::decode(frame)?
            .header()
            .message_type();
        if !maintenance && self.tolerant && !known_ipc(message_type) {
            self.clients[index].io.release();
            self.clients[index].input = None;
            self.clients[index].dv_rx_source = None;
            return Ok(Some(Step::Progress));
        }
        if message_type == gnunet_wire::official::message_type::TRANSPORT_BURST_FINISHED
            && !self.burst_callback_allowed(&id)
        {
            self.clients[index].io.release();
            self.clients[index].input = None;
            self.clients[index].dv_rx_source = None;
            return Ok(Some(Step::Progress));
        }
        let monitor = message_type == gnunet_wire::official::message_type::TRANSPORT_MONITOR_START;
        let result = if !maintenance
            && message_type == gnunet_wire::official::message_type::TRANSPORT_LINK_LIST_REQUEST
        {
            Some(
                self.engine
                    .check_link_request(&id, frame, times, signer)
                    .and_then(|peer| observer.links(&self.engine, peer))
                    .and_then(|links| {
                        self.engine
                            .receive_links_at(&id, frame, times, signer, links)
                    }),
            )
        } else if let Some((source, until, absolute_until)) = dv_bound {
            let input = gnunet_transport::dv_bridge::NativeInput {
                source: &source,
                owner: &id,
                bytes: frame,
                until,
                absolute_until,
            };
            if maintenance {
                self.engine
                    .receive_dv_maintenance_at(input, times, signer, entropy)
                    .transpose()
            } else {
                Some(self.engine.receive_dv_at(input, times, signer, entropy))
            }
        } else if maintenance {
            self.engine
                .receive_maintenance_at(&id, frame, times, signer, entropy)
                .transpose()
        } else {
            Some(self.engine.receive_at(&id, frame, times, signer, entropy))
        };
        let Some(result) = result else {
            return Ok(None);
        };
        self.clients[index].io.release();
        self.clients[index].input = None;
        self.clients[index].dv_rx_source = None;
        let step = match result {
            Ok(ReceiveOutcome::Accepted) => {
                if monitor {
                    self.clients[index].monitor = true;
                }
                Step::Progress
            }
            Ok(ReceiveOutcome::Rejected(rejection)) => Step::InputRejected(rejection),
            Ok(ReceiveOutcome::AddressRejected(rejection)) => Step::AddressRejected(rejection),
            Ok(ReceiveOutcome::WorkDeferred(reason)) => Step::WorkDeferred(reason),
            Err(reason) if matches!(message_type.value(), 1250 | 1255) => {
                self.close(index)?;
                Step::MonitorRetired(gnunet_transport::monitor::Retirement {
                    client: id.clone(),
                    reason,
                })
            }
            // The complete input has been consumed once. These local
            // failures are supervision causes, never malformed-peer
            // evidence. Do not replay it or retire a shared MQ here.
            Err(error @ (Error::Capacity | Error::Entropy | Error::TimeUncertain | Error::Io)) => {
                return Err(error);
            }
            Err(_) => {
                self.close(index)?;
                Step::Progress
            }
        };
        Ok(Some(step))
    }
    /// Poll one fair native/protocol step. No tasks or background writers are spawned.
    /// Local resource/storage failure is returned unchanged; it may follow input
    /// commit, so callers must not replay input. A failed socket/role closes its owner.
    pub fn poll_step(
        &mut self,
        cx: &mut Context<'_>,
        listener: Option<Listener<'_>>,
        now: u64,
        signer: &mut impl Signer,
        entropy: &mut impl Entropy,
        store: &mut impl AddressStore,
    ) -> Poll<Result<Step, Error>> {
        self.poll_step_at(
            cx,
            listener,
            Times::shared_coordinate(now),
            signer,
            entropy,
            store,
        )
    }
    /// Poll actual original IO with a fresh independent sample supplied by the
    /// caller. Native hard guards run before logical validation; source/input
    /// ownership and partial cursors remain unchanged across Pending.
    pub fn poll_step_at(
        &mut self,
        cx: &mut Context<'_>,
        listener: Option<Listener<'_>>,
        times: Times,
        signer: &mut impl Signer,
        entropy: &mut impl Entropy,
        store: &mut impl AddressStore,
    ) -> Poll<Result<Step, Error>> {
        self.poll_step_observed_at(
            cx,
            listener,
            times,
            dv_bridge::Ports {
                signer,
                entropy,
                store,
            },
            &mut dv_bridge::NoObserver,
        )
    }
    /// Same original actual IO, with synchronous DV admission/exposure receipts.
    /// Default poll_step_at retains DV-native frames until this real port drives.
    pub fn poll_step_observed_at<S: Signer, E: Entropy, A: AddressStore>(
        &mut self,
        cx: &mut Context<'_>,
        listener: Option<Listener<'_>>,
        times: Times,
        ports: dv_bridge::Ports<'_, S, E, A>,
        observer: &mut dyn dv_bridge::NativeObserver,
    ) -> Poll<Result<Step, Error>> {
        let dv_bridge::Ports {
            signer,
            entropy,
            store,
        } = ports;
        if self.poll_native_guard(cx)?.is_some() {
            return Poll::Ready(Ok(Step::Progress));
        }
        self.engine.validate_times(times)?;
        self.retire_monitor()?;
        if let Some(original) = self.monitor_retirements.pop_front() {
            return Poll::Ready(Ok(Step::MonitorRetired(original)));
        }
        let mut maintenance = match self.outputs_inner(Some(cx), store, observer)? {
            OutputState::Ready => false,
            OutputState::Deferred => true,
            OutputState::Retiring => return Poll::Pending,
        };
        // Engine output preparation can discover a bounded observer failure.
        // Retire it before entering any native read/write iteration.
        while self.retire_monitor()?.is_some() {}
        if let Some(original) = self.monitor_retirements.pop_front() {
            return Poll::Ready(Ok(Step::MonitorRetired(original)));
        }
        if !maintenance && let Some(step) = self.settled_step.take() {
            return Poll::Ready(Ok(step));
        }
        let directions = self.clients.len() * 2 + 1;
        for _ in 0..directions {
            if let Some(id) = self.burst_expired(Instant::now())? {
                self.close_client(&id)?;
                return Poll::Ready(Ok(Step::Progress));
            }
            let slot = self.cursor % directions;
            self.cursor = (self.cursor + 1) % directions;
            if slot == 0 {
                if !maintenance
                    && self.clients.len() < self.maximum
                    && let Some(listener) = listener
                {
                    match listener.poll_canonical_connection(cx) {
                        Poll::Ready(Ok(accepted)) => {
                            let (connection, _, _) = accepted.into_parts();
                            self.admit(connection)?;
                            return Poll::Ready(Ok(Step::Progress));
                        }
                        Poll::Ready(Err(_)) => return Poll::Ready(Err(Error::Io)),
                        Poll::Pending => {}
                    }
                }
                continue;
            }
            let index = (slot - 1) / 2;
            if index >= self.clients.len() {
                continue;
            }
            if slot % 2 == 1 {
                if self.clients[index].io.frame().is_some() {
                    let Some(step) =
                        self.receive_frame(index, times, signer, entropy, observer, maintenance)?
                    else {
                        continue;
                    };
                    if maintenance {
                        // Report only this real callback/control progress. The
                        // earlier business result still owns settled_step.
                        return Poll::Ready(Ok(step));
                    }
                    self.settled_step = Some(step);
                    match self.outputs_inner(Some(cx), store, observer)? {
                        OutputState::Ready => {
                            return Poll::Ready(self.settled_step.take().ok_or(Error::NotReady));
                        }
                        OutputState::Deferred => {
                            maintenance = true;
                            // This input just committed. If its slot ended the
                            // rotation, arrange one further maintenance pass;
                            // stable barriers do not wake themselves.
                            cx.waker().wake_by_ref();
                        }
                        OutputState::Retiring => return Poll::Pending,
                    }
                    // The newly discovered barrier must not starve IO in this
                    // same bounded rotation. No new business head is consumed.
                    continue;
                }
                match self.clients[index].io.poll_read_status(cx) {
                    Poll::Ready(Ok(gnunet_service_runtime::framing::ReadStep::Progress {
                        bytes,
                        complete,
                    })) => {
                        if bytes > 0 && self.clients[index].input.is_none() {
                            self.clients[index].dv_rx_source =
                                self.engine.dv_current_source().cloned();
                        }
                        let held_dv = complete
                            && self.engine.dv_source_active()
                            && self.clients[index].io.frame().is_some_and(dv_bridge::is_dv);
                        if complete && !held_dv {
                            self.clients[index].input = None;
                        } else if bytes > 0 && self.clients[index].input.is_none() {
                            self.clients[index].input = Some(
                                Instant::now()
                                    .checked_add(self.native.input)
                                    .ok_or(Error::Overflow)?,
                            );
                        }
                        self.poll_native_guard(cx)?;
                        return Poll::Ready(Ok(Step::Progress));
                    }
                    Poll::Ready(Ok(gnunet_service_runtime::framing::ReadStep::Eof)) => {
                        self.close(index)?;
                        return Poll::Ready(Ok(Step::Progress));
                    }
                    Poll::Ready(Err(_)) => {
                        self.close(index)?;
                        return Poll::Ready(Ok(Step::Progress));
                    }
                    Poll::Pending => {}
                }
            } else {
                let engine = &mut self.engine;
                let mut progress_error = None;
                let actual =
                    self.clients[index]
                        .io
                        .poll_write_observed(cx, |id, bytes, complete| {
                            let parent = engine.dv_chunk_parent(id);
                            if let Err(error) = engine.dv_ipc_progress(id, bytes, complete) {
                                progress_error.get_or_insert(error);
                            }
                            if let Some(parent) = parent
                                && let Err(error) = observer.exposed(&parent, bytes)
                            {
                                progress_error.get_or_insert(error);
                            }
                        });
                if let Some(error) = progress_error {
                    if let Err(cleanup) = self.close(index) {
                        observer.cleanup(cleanup);
                    }
                    return Poll::Ready(Err(error));
                }
                match actual {
                    Poll::Ready(Ok(progress)) => {
                        if self.clients[index].io.queued_frames() == 0 {
                            self.clients[index].output = None;
                        } else if progress.completed_frames > 0 {
                            self.clients[index].output = Some(
                                Instant::now()
                                    .checked_add(self.native.output)
                                    .ok_or(Error::Overflow)?,
                            );
                        }
                        self.poll_native_guard(cx)?;
                        return Poll::Ready(Ok(Step::Progress));
                    }
                    Poll::Ready(Err(_)) => {
                        self.close(index)?;
                        return Poll::Ready(Ok(Step::Progress));
                    }
                    Poll::Pending => {}
                }
            }
        }
        Poll::Pending
    }
    /// Await a step; cancellation preserves every retained owner and partial cursor.
    pub async fn step(
        &mut self,
        listener: Option<Listener<'_>>,
        now: u64,
        signer: &mut impl Signer,
        entropy: &mut impl Entropy,
        store: &mut impl AddressStore,
    ) -> Result<Step, Error> {
        self.step_at(
            listener,
            Times::shared_coordinate(now),
            signer,
            entropy,
            store,
        )
        .await
    }
    /// Cancellation-safe explicit-sample wrapper. It retains the supplied pair;
    /// real coordinators should call poll_step_at with fresh samples each turn.
    pub async fn step_at(
        &mut self,
        listener: Option<Listener<'_>>,
        times: Times,
        signer: &mut impl Signer,
        entropy: &mut impl Entropy,
        store: &mut impl AddressStore,
    ) -> Result<Step, Error> {
        poll_fn(|cx| self.poll_step_at(cx, listener, times, signer, entropy, store)).await
    }
    /// Drop all physical clients after applying their real protocol close effects.
    /// Take one original observation refusal after physical retirement,
    /// including when an enclosing owner is already stopping.
    pub fn take_monitor_retirement(&mut self) -> Option<gnunet_transport::monitor::Retirement> {
        self.monitor_retirements.pop_front()
    }
    /// Physically retire every original owned source, preserving pending
    /// observation causes for the enclosing owner's explicit cleanup reporting.
    pub fn shutdown(&mut self) -> Result<(), Error> {
        let mut first = None;
        loop {
            match self.retire_monitor() {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(e) => {
                    first.get_or_insert(e);
                }
            }
        }
        drop(self.pending_frame.take());
        self.pending_validated = None;
        self.settled_step = None;
        self.timer_step = None;
        self.alarm = None;
        self.discovery.0 = None;
        while !self.clients.is_empty() {
            if let Err(error) = self.close(self.clients.len() - 1) {
                first.get_or_insert(error);
            }
        }
        first.map_or(Ok(()), Err)
    }
}

fn known_ipc(kind: gnunet_wire::official::MessageType) -> bool {
    use gnunet_wire::official::message_type::*;
    [
        TRANSPORT_SUGGEST,
        TRANSPORT_SUGGEST_CANCEL,
        TRANSPORT_REQUEST_HELLO_VALIDATION,
        TRANSPORT_START,
        TRANSPORT_SEND,
        TRANSPORT_RECV_OK,
        TRANSPORT_NEW_COMMUNICATOR,
        TRANSPORT_COMMUNICATOR_BACKCHANNEL,
        TRANSPORT_ADD_ADDRESS,
        TRANSPORT_DEL_ADDRESS,
        TRANSPORT_INCOMING_MSG,
        TRANSPORT_QUEUE_CREATE_OK,
        TRANSPORT_QUEUE_CREATE_FAIL,
        TRANSPORT_QUEUE_SETUP,
        TRANSPORT_QUEUE_UPDATE,
        TRANSPORT_QUEUE_TEARDOWN,
        TRANSPORT_SEND_MSG_ACK,
        TRANSPORT_BURST_FINISHED,
        TRANSPORT_MONITOR_START,
        TRANSPORT_LINK_LIST_REQUEST,
    ]
    .contains(&kind)
}

#[cfg(test)]
mod framing_resource_tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Actual retained-effect and physical-close assertions with fallible setup"
    )]
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    #[tokio::test(flavor = "current_thread")]
    async fn pending_original_effect_is_wiped_on_matching_close_and_shutdown_without_ack()
    -> Result<(), Box<dyn std::error::Error>> {
        let engine = Engine::new(PeerId([0x21; 32]), gnunet_transport::Limits::default())?;
        let mut server = Server::new(engine, 2, 65535)?;
        let (a, mut pa) = tokio::net::UnixStream::pair()?;
        let (b, mut pb) = tokio::net::UnixStream::pair()?;
        let first = server.admit(Connection::from_unix(a))?;
        let second = server.admit(Connection::from_unix(b))?;
        server.pending_frame = Some((
            second.clone(),
            OwnedFrame::new(vec![0, 8, 0, 99, 0x71, 0x71, 0x71, 0x71]),
        ));
        server.close(0)?;
        assert!(
            server
                .pending_frame
                .as_ref()
                .is_some_and(|(id, _)| *id == second)
        );
        let mut bytes = Vec::new();
        pa.read_to_end(&mut bytes).await?;
        assert!(bytes.is_empty());
        server.shutdown()?;
        assert!(server.pending_frame.is_none());
        let mut bytes = Vec::new();
        pb.read_to_end(&mut bytes).await?;
        assert!(bytes.is_empty());
        assert_eq!(server.engine().snapshot().clients, 0);
        assert_ne!(first, second);
        Ok(())
    }

    struct MaintenanceSigner(PeerId);
    impl Signer for MaintenanceSigner {
        fn identity(&self) -> PeerId {
            self.0
        }
        fn sign_validation(&mut self, _: &[u8; 48]) -> Result<[u8; 64], Error> {
            Err(Error::PermissionDenied)
        }
    }
    struct MaintenanceEntropy;
    impl Entropy for MaintenanceEntropy {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), Error> {
            Err(Error::Entropy)
        }
    }
    struct StoreGate {
        ready: bool,
        waker: Option<std::task::Waker>,
    }
    impl AddressStore for StoreGate {
        fn validated(&mut self, _: PeerId, _: &[u8], _: u64) -> Result<(), Error> {
            Err(Error::Conflict)
        }
        fn poll_validated(
            &mut self,
            cx: &mut Context<'_>,
            _: PeerId,
            _: &[u8],
            _: u64,
        ) -> Poll<Result<(), Error>> {
            if self.ready {
                Poll::Ready(Ok(()))
            } else {
                self.waker = Some(cx.waker().clone());
                Poll::Pending
            }
        }
    }
    /// The private barrier/result markers deliberately isolate host ownership;
    /// the real Unix callback below must neither replace nor prematurely take
    /// either marker. This is not authenticated-address acceptance evidence.
    #[tokio::test(flavor = "current_thread")]
    async fn maintenance_callback_preserves_original_settled_and_timer_results()
    -> Result<(), Box<dyn std::error::Error>> {
        let local = PeerId([0x45; 32]);
        let mut signer = MaintenanceSigner(local);
        let mut entropy = MaintenanceEntropy;
        let mut gate = StoreGate {
            ready: false,
            waker: None,
        };
        let mut server = Server::new(
            Engine::new(local, gnunet_transport::Limits::default())?,
            1,
            65535,
        )?;
        let (native, mut remote) = tokio::net::UnixStream::pair()?;
        let id = server.admit(Connection::from_unix(native))?;
        let mut register = [0; 16];
        register[..2].copy_from_slice(&16u16.to_be_bytes());
        register[2..4].copy_from_slice(&1211u16.to_be_bytes());
        register[4..8].copy_from_slice(&1u32.to_be_bytes());
        register[12..].copy_from_slice(b"tcp\0");
        assert_eq!(
            server
                .engine
                .receive(&id, &register, 100, &mut signer, &mut entropy)?,
            ReceiveOutcome::Accepted
        );
        let settled = Step::InputRejected(QueueRejection {
            client: id,
            peer: PeerId([0x46; 32]),
            queue: 7,
            reason: Error::Overflow,
        });
        let timer = Step::WorkDeferred(WorkDeferral {
            operation: 42,
            peer: local,
            reason: Error::WouldBlock,
        });
        server.settled_step = Some(settled.clone());
        server.timer_step = Some(timer.clone());
        server.pending_validated = Some(Validated {
            peer: local,
            address: b"tcp-private-marker".to_vec(),
            until: AbsoluteTime::from_micros(1000),
        });
        // A whole-write-gated1254 remains gated while STORE is pending.
        // First retain its actual complete Unix frame, then consume that head.
        remote.write_all(&[0, 4, 4, 230]).await?;
        tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| {
                let result = server.poll_step_at(
                    cx,
                    None,
                    Times::shared_coordinate(100),
                    &mut signer,
                    &mut entropy,
                    &mut gate,
                );
                match result {
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Ready(Ok(_)) if server.clients[0].io.frame().is_some() => {
                        Poll::Ready(Ok(()))
                    }
                    Poll::Ready(Ok(_)) => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Poll::Pending => Poll::Pending,
                }
            }),
        )
        .await??;
        assert_eq!(
            poll_fn(|cx| server.poll_step_at(
                cx,
                None,
                Times::shared_coordinate(100),
                &mut signer,
                &mut entropy,
                &mut gate
            ))
            .await?,
            Step::Progress
        );
        assert!(server.clients[0].io.frame().is_none());
        assert_eq!(server.engine.snapshot().ignored_local_callbacks, 0);
        let mut callback = [0; 52];
        callback[..2].copy_from_slice(&52u16.to_be_bytes());
        callback[2..4].copy_from_slice(&1210u16.to_be_bytes());
        callback[4..8].copy_from_slice(&1u32.to_be_bytes());
        remote.write_all(&callback).await?;
        tokio::time::timeout(
            Duration::from_secs(2),
            poll_fn(|cx| {
                let result = server.poll_step_at(
                    cx,
                    None,
                    Times::shared_coordinate(100),
                    &mut signer,
                    &mut entropy,
                    &mut gate,
                );
                match result {
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Ready(Ok(_)) if server.engine.snapshot().ignored_local_callbacks == 1 => {
                        Poll::Ready(Ok(()))
                    }
                    Poll::Ready(Ok(_)) => {
                        cx.waker().wake_by_ref();
                        Poll::Pending
                    }
                    Poll::Pending => Poll::Pending,
                }
            }),
        )
        .await??;
        assert_eq!(server.settled_step, Some(settled.clone()));
        assert_eq!(server.timer_step, Some(timer.clone()));
        assert!(server.persistence_pending());
        gate.ready = true;
        if let Some(waker) = gate.waker.take() {
            waker.wake();
        }
        assert_eq!(
            poll_fn(|cx| server.poll_step_at(
                cx,
                None,
                Times::shared_coordinate(100),
                &mut signer,
                &mut entropy,
                &mut gate
            ))
            .await?,
            settled
        );
        assert!(server.settled_step.is_none());
        assert_eq!(server.timer_step, Some(timer.clone()));
        assert_eq!(
            poll_fn(|cx| server.poll_tick_at(
                cx,
                Times::shared_coordinate(100),
                &mut entropy,
                &mut gate
            ))
            .await?,
            timer
        );
        server.shutdown()?;
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn idle_application_has_no_first_frame_deadline_but_partial_progress_keeps_original_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let local = PeerId([0x45; 32]);
        let mut signer = MaintenanceSigner(local);
        let mut entropy = MaintenanceEntropy;
        let mut store = StoreGate {
            ready: true,
            waker: None,
        };
        let native = NativeLimits {
            lifetime: Duration::from_secs(2),
            input: Duration::from_millis(120),
            output: Duration::from_secs(1),
        };
        let mut server = Server::new_with_native(
            Engine::new(local, gnunet_transport::Limits::default())?,
            2,
            65535,
            native,
        )?;
        let (connection, mut application) = tokio::net::UnixStream::pair()?;
        let application_id = server.admit(Connection::from_unix(connection))?;
        let application_lease = server.clients[0].lease;
        // Drive the actual empty Unix MQ beyond the configured partial-input
        // interval. Neither an INIT nor fabricated role declaration is sent.
        assert!(
            tokio::time::timeout(
                native.input * 2,
                server.step(None, 100, &mut signer, &mut entropy, &mut store)
            )
            .await
            .is_err()
        );
        assert_eq!(server.engine.snapshot().clients, 1);
        assert_eq!(server.clients[0].lease, application_lease);
        assert!(server.clients[0].input.is_none());
        assert!(server.take_native_retirement().is_none());
        let mut preference = [0; 44];
        gnunet_transport::application::Preference {
            peer: PeerId([0x46; 32]),
            priority: 0,
            bandwidth: 0,
        }
        .encode(false, &mut preference)?;
        application.write_all(&preference).await?;
        tokio::time::timeout(Duration::from_secs(1), async {
            while server.engine.snapshot().application_suggestions == 0 {
                server
                    .step(None, 100, &mut signer, &mut entropy, &mut store)
                    .await?;
            }
            Ok::<_, Error>(())
        })
        .await??;
        assert_eq!(server.engine.snapshot().application_suggestions, 1);
        assert_eq!(server.clients[0].id, application_id);
        assert_eq!(server.clients[0].lease, application_lease);
        assert!(server.clients[0].input.is_none());

        let (connection, mut partial) = tokio::net::UnixStream::pair()?;
        let partial_id = server.admit(Connection::from_unix(connection))?;
        let partial_lease = server.clients[1].lease;
        partial.write_all(&preference[..1]).await?;
        server
            .step(None, 100, &mut signer, &mut entropy, &mut store)
            .await?;
        let original = server.clients[1].input.ok_or(Error::NotReady)?;
        tokio::time::sleep_until(
            original
                .checked_sub(native.input / 2)
                .ok_or(Error::Overflow)?,
        )
        .await;
        partial.write_all(&preference[1..2]).await?;
        server
            .step(None, 100, &mut signer, &mut entropy, &mut store)
            .await?;
        assert_eq!(server.clients[1].input, Some(original));
        assert_eq!(server.clients[1].lease, partial_lease);
        // Actual header progress is not a new timeout. The old native target
        // closes only that physical source, retaining the valid application.
        tokio::time::sleep_until(original).await;
        server
            .step(None, 100, &mut signer, &mut entropy, &mut store)
            .await?;
        let retired = server.take_native_retirement().ok_or(Error::NotReady)?;
        assert_eq!(retired.client, partial_id);
        assert!(matches!(retired.cause, RetirementCause::NativeDeadline));
        assert_eq!(retired.input, Some(original));
        assert_eq!(retired.lease, partial_lease);
        assert!(retired.observed >= original && retired.observed < partial_lease);
        let mut byte = [0; 1];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), partial.read(&mut byte)).await??,
            0
        );
        assert_eq!(server.engine.snapshot().clients, 1);
        assert_eq!(server.engine.snapshot().application_suggestions, 1);
        assert_eq!(server.clients[0].id, application_id);
        assert_eq!(server.clients[0].lease, application_lease);
        server.shutdown()?;
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), application.read(&mut byte)).await??,
            0
        );
        Ok(())
    }
}

// Exact active gnunet-service-transport.c SERVICE_MAIN handler table. Unknown
// tolerance is determined before domain decoding; it cannot swallow Unsupported
// from an active handler or a malformed encapsulated peer message.
