//! Bounded caller-driven native CADET direct-neighbor coordinator.
//! Actual CORE, PILS, KX, reliable channels and application MQs have distinct
//! original effects; no discovery backend, task, thread or fake ACK is created.
mod loose;
mod observations;
mod state;
mod types;
use crate::{connection, identity_dh, server, signing, time::Timebase};
use gnunet_cadet::{connection::Book, service, tunnel::controller};
use gnunet_crypto::Entropy;
use gnunet_service_runtime::{
    clock::{ClockSubscription, RuntimeClock},
    service::{Listener, ShutdownMode},
};
use gnunet_types::{Error as ProtocolError, MonoInstant};
pub use observations::{AckInput, ChannelInputOutcome, ChannelObservations, DataInput, FirstLast};
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
pub use types::{
    ChannelBuffers, Close, Discovery, Error, Limits, NativeStage, Parts, PeerClose, Refusal,
    Report, Signing, Step, Storage, TransportDemand,
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum Applications {
    Serving,
    Paused,
    Released,
    Stopped,
}

/// Movable peer-generation owner borrowing the longer-lived application server.
/// Domains, instances and slabs are caller-owned; no field borrows another field.
/// Failed or unretired destruction still closes application MQs as a safety fence.
pub struct Node<
    'node,
    'core,
    'book,
    'pils,
    'server,
    'app,
    'appstore,
    'appbytes,
    'store,
    'bytes,
    E: Entropy,
    const C: usize = 64,
    const S: usize = 32,
    const O: usize = 32,
    const P: usize = 16,
> {
    state: state::State<'node, 'book, 'server, 'app, 'appstore, 'appbytes, 'store, 'bytes, E>,
    book: Book<'book, 'store, 'bytes, P>,
    bridge: connection::Bridge<'core, 'book, 'store, C, S>,
    dh: identity_dh::Port<'node, 'pils, 'store, O>,
    clock: Arc<dyn RuntimeClock>,
    timebase: Timebase,
    listener: Box<dyn ClockSubscription>,
    revision: u64,
    last_now: MonoInstant,
    timer: Pin<Box<Sleep>>,
    wake: Option<Waker>,
    class: u8,
    dh_cursor: usize,
    core_ready: bool,
    core_stopped: bool,
    applications: Applications,
    dh_stopped: bool,
}
impl<
    'node,
    'core,
    'book,
    'pils,
    'server,
    'app,
    'appstore,
    'appbytes,
    'store,
    'bytes,
    E: Entropy,
    const C: usize,
    const S: usize,
    const O: usize,
    const P: usize,
>
    Node<
        'node,
        'core,
        'book,
        'pils,
        'server,
        'app,
        'appstore,
        'appbytes,
        'store,
        'bytes,
        E,
        C,
        S,
        O,
        P,
    >
{
    /// Consume independently constructed actual owners and fixed free pools.
    /// Allocation, pool/source/clock/frame validation completes before Node IO.
    pub fn new(
        parts: Parts<
            'node,
            'core,
            'book,
            'pils,
            'server,
            'app,
            'appstore,
            'appbytes,
            'store,
            'bytes,
            C,
            S,
            O,
            P,
        >,
        storage: Storage<'node, 'store, 'bytes>,
        limits: Limits,
        entropy: E,
    ) -> Result<Self, Error> {
        if limits.pending_frames == 0
            || limits.used_channels == 0
            || limits.opening_micros == 0
            || limits.idle_micros == 0
            || limits.route_tick_micros == 0
            || limits.ratchet_messages == 0
            || limits.ratchet_micros == 0
            || storage.tunnels.is_empty()
            || storage.channels.is_empty()
            || !(1..=4).contains(&limits.channel.window)
            || !(4..=64348).contains(&limits.channel.payload_bytes)
            || limits.channel.retry_micros == 0
            || limits.channel.maximum_retry_micros < limits.channel.retry_micros
            || limits.tunnel.retry_micros == 0
            || limits.tunnel.maximum_retry_micros < limits.tunnel.retry_micros
            || limits.tunnel.negotiation_micros == 0
            || limits.tunnel.maximum_transmissions == 0
            || limits.tunnel.maximum_unverified_attempts == 0
        {
            return Err(ProtocolError::InvalidInput.into());
        }
        let plain = limits
            .channel
            .payload_bytes
            .checked_add(12)
            .ok_or(ProtocolError::Overflow)?;
        let frame = plain.checked_add(112).ok_or(ProtocolError::Overflow)?;
        let staging = plain
            .checked_mul(2)
            .and_then(|p| p.checked_add(112))
            .ok_or(ProtocolError::Overflow)?;
        if frame > parts.book.frame_capacity()
            || frame > connection::MAX_PEER_FRAME
            || limits.tunnel.crypto.plaintext_bytes < plain
            || storage.plaintext.len() < plain
            || storage.ciphertext.len() < staging
        {
            return Err(ProtocolError::TooLarge.into());
        }
        for store in &storage.tunnels {
            store.validate(limits.tunnel.crypto)?;
        }
        for buffers in &storage.channels {
            buffers.validate(limits.channel)?;
        }
        let clock = parts.server.clock();
        let timebase = parts.bridge.timebase().clone();
        if !Arc::ptr_eq(&clock, &parts.bridge.clock())
            || !Arc::ptr_eq(&clock, &parts.identity_dh.clock())
            || !Arc::ptr_eq(&clock, &timebase.source())
            || !timebase.same_epoch(parts.identity_dh.timebase())
        {
            return Err(ProtocolError::InvalidInput.into());
        }
        let source = parts.identity_dh.source();
        if !source.is_live()
            || source.local() != parts.server.local_peer()
            || parts.book.reset_authority().local() != source.local()
        {
            return Err(ProtocolError::Authentication.into());
        }
        let listener = clock.subscribe()?;
        let sample = timebase.sample()?;
        parts.server.enable_management(limits.management)?;
        let state = state::State::new(
            parts.server,
            storage,
            source,
            limits,
            entropy,
            sample.monotonic,
        )?;
        Ok(Self {
            state,
            book: parts.book,
            bridge: parts.bridge,
            dh: parts.identity_dh,
            clock,
            timebase,
            listener,
            revision: sample.revision,
            last_now: sample.monotonic,
            timer: Box::pin(tokio::time::sleep(Duration::from_secs(1))),
            wake: None,
            class: 0,
            dh_cursor: 0,
            core_ready: false,
            core_stopped: false,
            applications: Applications::Serving,
            dh_stopped: false,
        })
    }
    /// Actual common canonical clock; cloning creates no listener.
    #[must_use]
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Shared native epoch for this Node, Book and its actual peer providers.
    #[must_use]
    pub fn timebase(&self) -> &Timebase {
        &self.timebase
    }
    /// Originally verified local PILS/application identity.
    #[must_use]
    pub fn local_peer(&self) -> [u8; 32] {
        self.state.server.local_peer()
    }
    /// Actual CORE INIT_REPLY matched the already bound local identity.
    #[must_use]
    pub fn ready(&self) -> bool {
        self.core_ready
            && !self.core_stopped
            && !self.dh_stopped
            && self.applications == Applications::Serving
            && !self.state.closing
    }
    /// Bounded peer/crypto/channel observations, without application delivery claims.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.state.report
    }
    /// First/last authenticated DATA/ACK facts for each fixed slot's last
    /// original channel occupant, retained after its owner returns the slab.
    /// Read-only and allocation-free; this is not a complete packet history.
    pub fn channel_observations(&self) -> impl Iterator<Item = &ChannelObservations> + '_ {
        self.state.channel_observations()
    }
    /// Aggregate the four disjoint original domains once. Historical counters
    /// survive owner/row retirement; current resource gauges come from live rows.
    #[must_use]
    pub fn statistics(&self) -> gnunet_cadet::statistics::Snapshot {
        let mut snapshot = self.state.server.statistics();
        snapshot.merge(&self.peer_statistics());
        snapshot
    }
    /// Disjoint peer-generation observations, excluding the long-lived
    /// application domain. Retired generations can retain counters once.
    #[must_use]
    pub fn peer_statistics(&self) -> gnunet_cadet::statistics::Snapshot {
        let mut snapshot = self.state.peer_statistics();
        snapshot.merge(&self.book.statistics());
        snapshot
    }
    /// Actual original accepted application MQ/report counters.
    #[must_use]
    pub fn server_report(&self) -> &server::Report {
        self.state.server.report()
    }
    /// Physically close this exact original application MQ after its poll
    /// callback returned. Node never reenters a caller's diagnostics callback.
    pub fn close_client(
        &mut self,
        client: service::Client<'app>,
        cause: server::CloseCause,
        observe: &mut impl FnMut(server::Event<'app>),
    ) -> Result<service::Loss<'app>, server::Error> {
        self.state.server.close(client, cause, observe)
    }
    /// Apply the official local soft/immediate policy. Soft retains all existing
    /// MQs and peer traffic until callers close them or choose actual hard stop.
    pub fn request_shutdown(&mut self, mode: ShutdownMode) {
        self.state.server.request_shutdown(mode);
        if let Some(w) = &self.wake {
            w.wake_by_ref()
        }
    }
    /// Strong independent actual source stops, valid even when clock sampling
    /// refuses. Original metadata still drains through poll/poll_signing.
    pub fn close(
        &mut self,
        observe: &mut impl FnMut(server::Event<'app>),
    ) -> Close<'core, 'book, 'pils, O> {
        let core = self.bridge.close(&mut self.book, &mut self.state);
        let identity_dh = self.dh.close();
        self.dh_stopped = true;
        self.core_ready = false;
        let applications = self.state.server.close_all(observe);
        self.applications = if applications.is_ok() {
            Applications::Stopped
        } else {
            Applications::Serving
        };
        self.state.begin_close();
        if let Some(w) = &self.wake {
            w.wake_by_ref()
        }
        Close {
            core,
            identity_dh,
            applications,
        }
    }
    /// Actual local-source/Book/peer retirement only. An external signer MQ is
    /// separately closed/drained by its caller; a grace timeout is not success.
    #[must_use]
    pub fn quiescent(&self) -> bool {
        self.applications == Applications::Stopped && self.peers_retired()
    }
    /// Actual peer-generation retirement. Application MQs may remain alive;
    /// their frozen original native cursors have not been completed or renewed.
    #[must_use]
    pub fn peers_retired(&self) -> bool {
        self.state.closing
            && self.core_stopped
            && self.dh_stopped
            && self.state.quiescent()
            && !self.book.has_work()
            && self.state.server.identity_channels_retired()
    }
    /// Physically stop this peer generation and retire its original application
    /// effects, preserving MQs, ports, established loop pairs and native bytes.
    /// Application IO pauses until the caller installs a new generation.
    pub fn retire_peers(&mut self) -> PeerClose<'core, 'book, 'pils, O> {
        self.applications = Applications::Paused;
        let applications = self.state.server.retire_identity_channels();
        self.state.begin_close();
        let core = self.bridge.close(&mut self.book, &mut self.state);
        let identity_dh = self.dh.close();
        self.dh_stopped = true;
        self.core_ready = false;
        if let Some(wake) = &self.wake {
            wake.wake_by_ref();
        }
        PeerClose {
            core,
            identity_dh,
            applications,
        }
    }
    /// Release this borrow only after all tracked original peer effects retire.
    /// The caller must also retire its separately owned signer. Further polling
    /// this Node refuses; Drop no longer closes the retained application MQs.
    pub fn release_applications(&mut self) -> Result<(), ProtocolError> {
        if self.applications != Applications::Paused || !self.peers_retired() {
            return Err(ProtocolError::NotReady);
        }
        self.applications = Applications::Released;
        Ok(())
    }
    /// Enumerate bounded actual channel/tunnel demand using an observation
    /// cursor only. The returned original handles carry generation authority;
    /// the numeric cursor grants none. Opening targets are never renewed.
    #[must_use]
    pub fn transport_after(&self, cursor: usize) -> Option<(usize, TransportDemand<'node, 'app>)> {
        self.state.transport_after(cursor)
    }
    /// Original pending open that needs caller-supplied discovery/transport
    /// work. This starts no lookup and creates no neighbor/route/authentication.
    #[must_use]
    pub fn discovery_needed(&self) -> Option<Discovery<'app>> {
        self.state.discovery_needed(&self.book, None)
    }
    /// Next original pending discovery in bounded slot order; no lookup or route is created.
    #[must_use]
    pub fn discovery_after(
        &self,
        after: Option<gnunet_cadet::service::Open<'app>>,
    ) -> Option<Discovery<'app>> {
        self.state.discovery_needed(&self.book, after)
    }
    /// Original native opening target, minted when this exact application open was admitted.
    pub fn discovery_hard(&self, wanted: Discovery<'app>) -> Result<Instant, Error> {
        self.state
            .discovery_hard(wanted)
            .ok_or(ProtocolError::StaleGeneration.into())
    }
    /// Whether this exact original open remains pending, independent of route readiness.
    #[must_use]
    pub fn discovery_current(&self, wanted: Discovery<'app>) -> bool {
        self.state.discovery_hard(wanted).is_some()
    }
    /// Expire only this original open without creating a clock/IO or peer-success receipt.
    pub fn expire_discovery(&mut self, wanted: Discovery<'app>) -> Result<(), Error> {
        Ok(self.state.expire_discovery(wanted)?)
    }
    /// Admit a caller-verified public DHT routing candidate. Book still requires a
    /// current real first-hop neighbor and performs the normal CREATE/signing/KX.
    /// true means an actual route opening was admitted, never an established channel.
    /// `now` must be sampled from this Node's shared native timebase.
    pub fn admit_discovery(
        &mut self,
        wanted: Discovery<'app>,
        path: &[[u8; 32]],
        now: MonoInstant,
    ) -> Result<bool, Error> {
        let admitted = self
            .state
            .admit_discovery(wanted, path, &mut self.book, now)?;
        if admitted && let Some(wake) = &self.wake {
            wake.wake_by_ref();
        }
        Ok(admitted)
    }
    /// A persisted monotime refill is required; caller reserves outside poll.
    #[must_use]
    pub fn needs_monotime_range(&self) -> bool {
        self.state.monotime_needed
    }
    /// Install an already fsynced, exact-local-peer monotime reservation. No
    /// disk work, hidden refill or wall-clock fallback happens in socket poll.
    pub fn install_monotime_range(
        &mut self,
        range: signing::monotime::Range,
    ) -> Result<(), ProtocolError> {
        if range.local() != self.local_peer() {
            return Err(ProtocolError::Authentication);
        }
        if range.remaining() == 0 {
            return Err(ProtocolError::NotReady);
        }
        self.state.monotime = Some(range);
        self.state.monotime_notice = false;
        self.state.monotime_needed = false;
        if let Some(w) = &self.wake {
            w.wake_by_ref()
        }
        Ok(())
    }
    fn now(&mut self, cx: &mut Context<'_>) -> Result<MonoInstant, ProtocolError> {
        match self.listener.poll_changed(cx, self.revision) {
            Poll::Ready(Err(e)) => return Err(e),
            Poll::Ready(Ok(s)) => self.revision = s.revision,
            Poll::Pending => {}
        }
        let sample = self.timebase.sample()?;
        if sample.monotonic < self.last_now {
            return Err(ProtocolError::TimeUncertain);
        }
        self.revision = sample.revision;
        self.last_now = sample.monotonic;
        Ok(sample.monotonic)
    }
    /// Capture an actual bounded Node directory without IO or state mutation.
    /// Empty output is legitimate only after this actual capture succeeds.
    pub fn management_snapshot(
        &self,
        kind: crate::management::Kind,
    ) -> Result<crate::management::Snapshot, ProtocolError> {
        self.state.management_snapshot(&self.book, kind)
    }
    fn management(&mut self, observe: &mut impl FnMut(server::Event<'app>)) -> Result<bool, Error> {
        let Some(query) = self.state.server.pending_management() else {
            return Ok(false);
        };
        match self.management_snapshot(query.kind()) {
            Ok(snapshot) => self.state.server.bind_management(query, snapshot)?,
            Err(reason) => {
                self.state.server.close(
                    query.client(),
                    server::CloseCause::Fault(reason.into()),
                    observe,
                )?;
            }
        }
        Ok(true)
    }
    fn advance_dh(&mut self, now: MonoInstant) -> Result<bool, ProtocolError> {
        for n in 0..self.state.tunnels.len() {
            let i = (self.dh_cursor + n) % self.state.tunnels.len();
            let Some(owner) = self.state.tunnels[i].owner.as_mut() else {
                continue;
            };
            if owner.pending_identity_dh().is_none() {
                continue;
            }
            let peer = owner.scope().peer();
            let event = match owner.advance_identity_dh(owner.scope(), &mut self.dh, now) {
                Ok(event) => event,
                Err(ProtocolError::Capacity | ProtocolError::WouldBlock) => return Ok(false),
                Err(
                    reason @ (ProtocolError::Authentication
                    | ProtocolError::Deadline
                    | ProtocolError::Cancelled),
                ) => {
                    self.state.refusal = Some(Refusal {
                        peer,
                        channel: None,
                        reason,
                    });
                    return Ok(true);
                }
                Err(reason) => return Err(reason),
            };
            self.dh_cursor = (i + 1) % self.state.tunnels.len();
            return Ok(!matches!(
                event,
                controller::Event::Idle | controller::Event::IdentityDhRetiring
            ));
        }
        Ok(false)
    }
    /// Poll one bounded actual IO/pure effect. Canceled waits retain original
    /// partial native cursors, peer MIDs, ciphertexts and complete held packets.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        deadline: Option<Instant>,
        observe: &mut impl FnMut(server::Event<'app>),
    ) -> Poll<Result<Step<'node, 'core, 'book, 'pils, O>, Error>> {
        if self.applications == Applications::Released {
            return Poll::Ready(Err(ProtocolError::Closed.into()));
        }
        self.wake = Some(cx.waker().clone());
        if let Some(error) = self.state.error.take() {
            return Poll::Ready(Err(error.into()));
        }
        if let Some(refusal) = self.state.refusal.take() {
            return Poll::Ready(Ok(Step::Refused(refusal)));
        }
        if self.quiescent() {
            return Poll::Ready(Ok(Step::Quiescent));
        }
        if self.applications == Applications::Paused && self.peers_retired() {
            return Poll::Ready(Ok(Step::PeersRetired));
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            return Poll::Ready(Ok(Step::WaitDeadline));
        }
        let now = self.now(cx)?;
        for n in 0..5 {
            let class = (self.class + n) % 5;
            let result = match class {
                0 => {
                    if self.advance_dh(now)? || self.state.maintain(&mut self.book, now)? {
                        cx.waker().wake_by_ref();
                        Poll::Ready(Ok(Step::Progress))
                    } else if self.state.monotime_notice && self.state.monotime.is_none() {
                        self.state.monotime_notice = false;
                        Poll::Ready(Ok(Step::MonotimeRequired))
                    } else {
                        Poll::Pending
                    }
                }
                1 if self.applications == Applications::Serving => {
                    match self.state.server.poll(cx, listeners, deadline, observe) {
                        Poll::Ready(Ok(progress)) => {
                            if progress == server::Progress::Stopped {
                                self.applications = Applications::Stopped;
                            }
                            Poll::Ready(Ok(Step::Application(progress)))
                        }
                        Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
                        Poll::Pending => Poll::Pending,
                    }
                }
                2 if !self.core_stopped => {
                    match self
                        .bridge
                        .poll(&mut *cx, &mut self.book, &mut self.state, deadline)
                    {
                        Poll::Ready(Ok(step)) => {
                            match &step {
                                connection::Step::Identity(_) => self.core_ready = true,
                                connection::Step::StartRefused { frame, .. } => {
                                    self.state.native_deferred(*frame)
                                }
                                connection::Step::IdentityMismatch { .. }
                                | connection::Step::Lost { .. } => self.core_ready = false,
                                connection::Step::Core(
                                    gnunet_core_client_host::Progress::Closed,
                                ) => {
                                    self.core_stopped = true;
                                    self.core_ready = false;
                                }
                                _ => {}
                            }
                            Poll::Ready(Ok(Step::Core(step)))
                        }
                        Poll::Ready(Err(cause)) => Poll::Ready(Err(Error::NativeAt {
                            stage: NativeStage::CoreBridge,
                            core_context: self.bridge.native_failure_context(),
                            cause,
                        })),
                        Poll::Pending => Poll::Pending,
                    }
                }
                3 if !self.dh_stopped => match self.dh.poll(cx, deadline) {
                    Poll::Ready(Ok(step)) => {
                        if let identity_dh::Step::Result { request, .. } = &step
                            && let Some(index) = self.state.tunnels.iter().position(|t| {
                                t.owner
                                    .as_ref()
                                    .is_some_and(|o| o.pending_identity_dh() == Some(*request))
                            })
                        {
                            self.dh_cursor = index;
                            self.advance_dh(now)?;
                        }
                        if matches!(
                            step,
                            identity_dh::Step::Lost { .. }
                                | identity_dh::Step::IdentityChanged { .. }
                                | identity_dh::Step::KeyChanged { .. }
                                | identity_dh::Step::Closed(_)
                        ) {
                            self.dh_stopped = true;
                            self.state.begin_close();
                        }
                        Poll::Ready(Ok(Step::IdentityDh(step)))
                    }
                    Poll::Ready(Err(cause)) => Poll::Ready(Err(Error::NativeAt {
                        stage: NativeStage::IdentityDh,
                        core_context: None,
                        cause,
                    })),
                    Poll::Pending => Poll::Pending,
                },
                4 if self.applications == Applications::Serving => {
                    if self.management(observe)? {
                        cx.waker().wake_by_ref();
                        Poll::Ready(Ok(Step::Progress))
                    } else {
                        Poll::Pending
                    }
                }
                _ => Poll::Pending,
            };
            if result.is_ready() {
                self.class = (class + 1) % 5;
                return result;
            }
        }
        let target = self
            .state
            .next_deadline()
            .into_iter()
            .chain(self.dh.next_deadline())
            .chain(self.bridge.next_deadline())
            .filter(|target| *target > now)
            .min();
        let mut wake = deadline;
        if let Some(hard) = self.state.native_deadline() {
            wake = Some(wake.map_or(hard, |old| old.min(hard)));
        }
        if let Some(target) = target {
            let at = self.timebase.native_bound(target)?;
            wake = Some(wake.map_or(at, |old| old.min(at)));
        }
        if let Some(at) = wake {
            self.timer.as_mut().reset(at);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
                return Poll::Ready(Ok(Step::Progress));
            }
        }
        Poll::Pending
    }
    /// Cancellation-safe foreground wait; it creates no background scheduler.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        deadline: Option<Instant>,
        mut observe: impl FnMut(server::Event<'app>),
    ) -> Result<Step<'node, 'core, 'book, 'pils, O>, Error> {
        poll_fn(|cx| self.poll(cx, listeners, deadline, &mut observe)).await
    }
    /// Drive the separately owned one-node purpose38 signer. Disk reservation
    /// is deliberately external. Original jobs remain actual signer capabilities.
    pub fn poll_signing<'sig, 'sigstore, const SO: usize>(
        &mut self,
        cx: &mut Context<'_>,
        signer: &mut signing::Signer<'book, 'sig, 'sigstore, SO>,
        deadline: Option<Instant>,
    ) -> Poll<Result<SigningProgress<'book, 'sig, SO>, Error>> {
        if self.applications == Applications::Released {
            return Poll::Ready(Err(ProtocolError::Closed.into()));
        }
        if !Arc::ptr_eq(&self.clock, &signer.clock())
            || !self.timebase.same_epoch(signer.timebase())
            || signer.authority() != self.book.reset_authority()
        {
            return Poll::Ready(Err(ProtocolError::Authentication.into()));
        }
        let now = self.now(cx)?;
        for i in 0..self.state.signs.len() {
            let Some(task) = self.state.signs[i] else {
                continue;
            };
            if now >= task.expires
                || self.state.closing
                || self.book.signing_local(task.request).is_err()
            {
                if self.book.signing_local(task.request).is_ok() {
                    let _closed = self.book.close_route(task.request.route());
                }
                if let Some(job) = signer.job_for(task.request) {
                    if signer.retire(job)? {
                        self.state.signs[i] = None;
                        return Poll::Ready(Ok(SigningProgress::Progress));
                    }
                } else {
                    self.state.signs[i] = None;
                    return Poll::Ready(Ok(SigningProgress::Progress));
                }
            } else if let Some(job) = signer.job_for(task.request) {
                match signer.finish(&mut self.book, job)? {
                    signing::Completion::Pending | signing::Completion::Blocked(_) => {}
                    signing::Completion::Signed { .. } => {
                        self.state.signs[i] = None;
                        return Poll::Ready(Ok(SigningProgress::Progress));
                    }
                    signing::Completion::Failed(reason) => {
                        let _closed = self.book.close_route(task.request.route());
                        self.state.signs[i] = None;
                        return Poll::Ready(Err(reason.into()));
                    }
                }
            } else {
                match signer.submit(&self.book, task.request, task.expires) {
                    Ok(_) => return Poll::Ready(Ok(SigningProgress::Progress)),
                    Err(crate::Error::Protocol(
                        ProtocolError::Capacity | ProtocolError::WouldBlock,
                    )) => {}
                    Err(e) => return Poll::Ready(Err(e.into())),
                }
            }
        }
        if signer.jobs_retired() {
            return Poll::Pending;
        }
        match signer.poll_book(cx, &self.book, deadline) {
            Poll::Ready(Ok(step)) => Poll::Ready(Ok(SigningProgress::Native(step))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}
/// Actual separate signing progress. A private result is accepted only inside
/// poll_signing through the original signer's Book-bound finish operation.
#[expect(
    clippy::large_enum_variant,
    reason = "Return the bounded original source observation directly without a fallible allocation on each native signing step"
)]
pub enum SigningProgress<'book, 'sig, const O: usize = 32> {
    /// One genuine original admission/Book acceptance/retirement step.
    Progress,
    /// Original real native source observation, without a public signature.
    Native(signing::Step<'book, 'sig, O>),
}

impl<E: Entropy, const C: usize, const S: usize, const O: usize, const P: usize> Drop
    for Node<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_, E, C, S, O, P>
{
    fn drop(&mut self) {
        if self.applications == Applications::Released {
            return;
        }
        // Fallback physical safety only. Use explicit close/poll for original
        // Loss/outcome reports; Drop cannot claim application/peer quiescence.
        let _core = self.bridge.close(&mut self.book, &mut self.state);
        let _dh = self.dh.close();
        let _apps = self.state.server.close_all(&mut |_event| {});
        self.state.begin_close();
    }
}
