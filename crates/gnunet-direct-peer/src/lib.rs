//! An allocation-free CORE peer on the original GNUnet direct TCP carrier.
#![no_std]
#![forbid(unsafe_code)]

use core::num::NonZeroU64;
use gnunet_core::{
    direct_peer::{Local, Peer as CorePeer, Submission},
    record::ReceiveError,
    session::Monitor,
    wire::{MAX_RECORD_BYTES, RECORD_PREFIX},
};
use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey, Entropy};
use gnunet_tcp_communicator_core::{
    firmware::{Delivery, Outgoing, Sample, Transport, TransportContext, TransportDeadlines},
    session::Role,
};
use gnunet_transport::direct::{self, Link, Reassembled, Received, RoutingFrame, Scope, Status};
use gnunet_types::{AbsoluteTime, Error, MonoInstant};
use zeroize::Zeroize;

#[cfg(test)]
mod tests;

mod hello;
use hello::Discovery;
pub use hello::{DiscoveryBuffers, DiscoveryChange};
mod routing;
use routing::Routing;
pub use routing::{RoutingOffer, RoutingReceipt};

/// Original TRANSPORT validation lease for the provisioned direct peer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reachability {
    /// Identity admitted by this carrier's validation.
    pub peer: EddsaPublicKey,
    /// This proof is live strictly before its elapsed deadline.
    pub until: MonoInstant,
}

/// Read-only direct TRANSPORT link facts owned by the original carrier.
pub struct LinkObservation {
    /// Current independent validation lease.
    pub confirmed: bool,
    /// Last actual validation proof, including an expired proof's history.
    pub last_validation: Option<gnunet_transport::direct_validation::ValidationObservation>,
    /// Original local probe or renewal target.
    pub next_validation: Option<MonoInstant>,
    /// Current FLOW credit and byte accounting.
    pub flow: gnunet_transport::direct_flow::Observation,
    /// One basic CORE receiver slot, occupied while an original frame waits.
    pub core_receive_window: i32,
    /// Original application output awaiting local admission.
    pub application_pending: bool,
}

/// Application port for one original CORE peer. Callbacks are synchronous.
pub trait Application {
    /// Observe a change in explicit CAKE association confirmation.
    fn readiness(&mut self, confirmed: bool);
    /// Observe the confirmed peer class, including loss or a confirmed class change.
    fn association(&mut self, _class: Option<u16>) {}
    /// Observe real CAKE phase and idle expiry, or retirement of its original owner.
    fn key_exchange(&mut self, _original: Option<Monitor>) {}
    /// Observe original TRANSPORT validation, renewal or loss. This lease is
    /// independent of the CORE association.
    fn reachability(&mut self, _lease: Option<Reachability>) {}
    /// Consume one complete authenticated application frame during this call.
    fn received(&mut self, message: &[u8]);
    /// Consume a frame using the same time sample as the authenticated CORE turn.
    fn received_at(&mut self, message: &[u8], _sample: Sample) {
        self.received(message);
    }
    /// Observe the authenticated sender's own HELLO addresses and freshness.
    /// Copy bytes needed after the call.
    fn discovered(&mut self, _change: DiscoveryChange<'_>) {}
    /// Receive a DV envelope from this peer's validated direct carrier.
    /// Implementations with a router must verify DV's own signature and replay
    /// state before using it. The frame is borrowed for this call.
    fn routed(&mut self, _frame: RoutingFrame<'_>, _sample: Sample) -> Delivery {
        Delivery::Dropped
    }
    /// Borrow one original DV offer. Preserve its identity, receipt mode and
    /// exact bytes across retries until `routing_admitted` settles it.
    /// Use the current carrier turn's elapsed sample to check its ownership.
    fn routing_offer(&mut self, _now: MonoInstant) -> Result<Option<RoutingOffer<'_>>, Error> {
        Ok(None)
    }
    /// Recheck an outstanding DV original before advancing the native stream.
    /// Errors fence the original carrier, before any further bytes are written.
    fn before_routing_write(&mut self, _now: MonoInstant) -> Result<(), Error> {
        Ok(())
    }
    /// Release one offered DV frame. A successful result means its final BOX
    /// entered the ordered local queue. A failed offer has no written receipt.
    fn routing_admitted(&mut self, _id: NonZeroU64, _outcome: Result<(), Error>) {}
    /// Settle one admitted `NativeWrite` request, using the actual write turn's
    /// elapsed clock on success. The receipt does not grant remote delivery.
    fn routing_written(
        &mut self,
        _id: NonZeroU64,
        _outcome: Result<(), Error>,
        _elapsed: MonoInstant,
    ) {
    }
    /// Borrow the current local input until its original completion.
    fn outgoing(&mut self) -> Option<&[u8]>;
    /// Borrow local input using the current authenticated carrier turn's time.
    /// The default drives ordinary application output without a timer.
    fn outgoing_at(&mut self, _sample: Sample) -> Result<Option<&[u8]>, Error> {
        Ok(self.outgoing())
    }
    /// Next scheduled opportunity to produce one local input on a confirmed
    /// CORE association.
    fn outgoing_deadlines(&self) -> TransportDeadlines {
        TransportDeadlines::default()
    }
    /// Release explicit ownership of that input. Success is original local
    /// TCP BOX admission. Physical delivery is a separate observation.
    fn outgoing_complete(&mut self, outcome: Result<(), Error>);
}

/// Publish a real change from one original CORE observation to another.
pub fn notify_core_transition(
    application: &mut impl Application,
    before: Option<Monitor>,
    after: Option<Monitor>,
) {
    let previous_class = before.and_then(|snapshot| snapshot.class);
    let class = after.and_then(|snapshot| snapshot.class);
    if previous_class.is_some() != class.is_some() {
        application.readiness(class.is_some());
    }
    if previous_class != class {
        application.association(class);
    }
    if before != after {
        application.key_exchange(after);
    }
}

/// Expected peers and policy for one provisioned carrier.
pub struct Settings<'key> {
    /// Local TRANSPORT signing key. Both it and CORE must match the TCP identity.
    pub transport_signing: &'key EddsaPrivateKey,
    /// CORE identity and handshake settings.
    pub core: Local<'key>,
    /// Expected authenticated remote identity.
    pub remote: EddsaPublicKey,
    /// Direct TRANSPORT receive, timing and validity bounds.
    pub link: direct::Limits,
}

/// Exclusive caller-owned storage for one connection.
pub struct Buffers<'buf, const N: usize = { direct::DEFAULT_REASSEMBLIES }> {
    /// Exact CORE record retained across lower backpressure.
    /// Capacity covers the smaller of the carrier and the CORE record limit.
    pub outbound: &'buf mut [u8],
    /// Decryption storage for one incoming CORE record's plaintext.
    pub plaintext: &'buf mut [u8],
    /// Space for one original incoming CORE record while a reply is staged.
    pub pending_input: &'buf mut [u8],
    /// Original TRANSPORT fragment and coverage storage.
    pub fragments: direct::FragmentBuffers<'buf, N>,
    /// Retained and temporary storage for the authenticated peer's HELLO.
    pub discovery: DiscoveryBuffers<'buf>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    WaitingForTcp,
    Validating,
    Validated,
    Closed,
}

struct Pending<'buf> {
    len: usize,
    delivery: direct::Delivery<'buf>,
}

/// Binds one configured peer across TCP, direct TRANSPORT and CORE. The
/// TCP firmware driver supplies the physical queue and its actual admissions.
/// Reconnection uses a fresh `Peer` and flow scope.
pub struct Peer<
    'key,
    'buf,
    A: Application,
    const F: usize = 1024,
    const N: usize = { direct::DEFAULT_REASSEMBLIES },
> {
    signer: &'key EddsaPrivateKey,
    local: EddsaPublicKey,
    remote: EddsaPublicKey,
    link: Link<'buf, N>,
    core: CorePeer<'key, 'buf, F>,
    discovery: Discovery<'buf>,
    control: [u8; direct::MAX_CONTROL_SIZE],
    pending_input: &'buf mut [u8],
    held: Option<Pending<'buf>>,
    application: A,
    application_pending: bool,
    routing: Routing,
    prefer_routing: bool,
    reached_until: Option<MonoInstant>,
    last_elapsed: MonoInstant,
    phase: Phase,
}

impl<'key, 'buf, A: Application, const F: usize, const N: usize> Peer<'key, 'buf, A, F, N> {
    /// Reserve storage for one original direct peer before TCP admission.
    ///
    /// # Errors
    /// Refuses differing local identities or storage smaller than the
    /// selected CORE and transport limits and supported handshake.
    pub fn new(
        scope: &'buf mut Scope,
        settings: Settings<'key>,
        buffers: Buffers<'buf, N>,
        application: A,
    ) -> Result<Self, Error> {
        let local = settings.transport_signing.public_key();
        if settings.core.identity.public_key() != local {
            return Err(Error::Authentication);
        }
        let core_size = usize::from(settings.link.max_payload.get()).min(MAX_RECORD_BYTES);
        let outbound = buffers
            .outbound
            .get_mut(..core_size)
            .ok_or(Error::Capacity)?;
        let plaintext = buffers
            .plaintext
            .get_mut(..core_size.saturating_sub(RECORD_PREFIX))
            .ok_or(Error::Capacity)?;
        let pending_input = buffers
            .pending_input
            .get_mut(..core_size)
            .ok_or(Error::Capacity)?;
        Ok(Self {
            signer: settings.transport_signing,
            local,
            remote: settings.remote,
            link: Link::new(
                scope,
                local,
                settings.remote,
                settings.link,
                buffers.fragments,
            )?,
            core: CorePeer::new(settings.core, outbound, plaintext)?,
            discovery: Discovery::new(settings.remote, buffers.discovery)?,
            control: [0; direct::MAX_CONTROL_SIZE],
            pending_input,
            held: None,
            application,
            application_pending: false,
            routing: Routing::default(),
            prefer_routing: false,
            reached_until: None,
            last_elapsed: MonoInstant(0),
            phase: Phase::WaitingForTcp,
        })
    }

    /// Observe actual explicit CORE confirmation on this original carrier.
    #[must_use]
    pub fn established(&self) -> bool {
        self.phase == Phase::Validated && self.core.established()
    }

    /// Observe the original direct link without changing its timers or credit.
    #[must_use]
    pub fn link_observation(&self) -> LinkObservation {
        let (last_validation, next_validation) = self.link.observe_validation();
        LinkObservation {
            confirmed: self.phase == Phase::Validated,
            last_validation,
            next_validation,
            flow: self.link.observe_flow(),
            core_receive_window: i32::from(self.held.is_none()),
            application_pending: self.application_pending,
        }
    }

    fn update_validation(&mut self, now: MonoInstant) -> Result<(), Error> {
        match self.phase {
            Phase::WaitingForTcp => return Err(Error::NotReady),
            Phase::Closed => return Err(Error::Closed),
            Phase::Validating | Phase::Validated => {}
        }
        let status = self.link.status(now)?;
        self.last_elapsed = now;
        match (self.phase, status) {
            (Phase::Validating, Status::Ready(_)) => {
                self.core.activate_validated(self.remote)?;
                self.phase = Phase::Validated;
                notify_core_transition(&mut self.application, None, self.core.monitor());
            }
            (Phase::Validated, Status::Unvalidated) => {
                if self.routing.active() {
                    self.retire_carrier();
                    return Err(Error::Deadline);
                }
                self.retire_core();
                self.phase = Phase::Validating;
                if let Some(held) = self.held.take() {
                    self.pending_input[..held.len].zeroize();
                    self.link.release(held.delivery).map_err(|e| e.reason)?;
                }
            }
            (_, Status::Closed) => return Err(Error::Closed),
            _ => {}
        }
        self.set_reachability(match status {
            Status::Ready(until) => Some(until),
            Status::Unvalidated | Status::Closed => None,
        });
        Ok(())
    }

    fn set_reachability(&mut self, until: Option<MonoInstant>) {
        if self.reached_until != until {
            self.reached_until = until;
            self.application
                .reachability(until.map(|until| Reachability {
                    peer: self.remote,
                    until,
                }));
        }
    }

    fn retire_core(&mut self) {
        let before = self.core.monitor();
        self.core.carrier_lost();
        notify_core_transition(&mut self.application, before, self.core.monitor());
        if core::mem::take(&mut self.application_pending) {
            self.application.outgoing_complete(Err(Error::Closed));
        }
    }

    fn retire_carrier(&mut self) {
        if self.phase != Phase::Closed {
            self.routing.close(&mut self.application, self.last_elapsed);
            self.set_reachability(None);
            self.retire_core();
            self.link.cancel();
            if let Some(held) = self.held.take() {
                self.pending_input[..held.len].zeroize();
            }
            self.phase = Phase::Closed;
        }
    }

    fn drive_core(
        &mut self,
        context: &mut TransportContext<'_, impl Entropy>,
    ) -> Result<(), Error> {
        if self.core.has_pending() {
            return Ok(());
        }
        if let Some(held) = self.held.take() {
            let frame = &mut self.pending_input[..held.len];
            let outcome = consume(
                &mut self.core,
                &mut self.application,
                &mut self.discovery,
                frame,
                context,
            );
            frame.zeroize();
            self.link.release(held.delivery).map_err(|e| e.reason)?;
            let _delivery = outcome?;
            return Ok(());
        }
        if self.drain_reassembled(context)?.is_some() {
            return Ok(());
        }
        let now = context.sample.absolute.as_micros();
        let before = self.core.monitor();
        let result = self.core.tick(now, context.entropy);
        notify_core_transition(&mut self.application, before, self.core.monitor());
        result?;
        let application_limit = self.pending_input.len() - RECORD_PREFIX;
        if self.core.established()
            && !self.core.has_pending()
            && let Some(message) = self.application.outgoing_at(context.sample)?
        {
            let staged = if message.len() <= application_limit {
                self.core.send(now, message)
            } else {
                Err(Error::TooLarge)
            };
            match staged {
                Ok(()) => self.application_pending = true,
                Err(error) => {
                    self.application.outgoing_complete(Err(error));
                    if !matches!(
                        error,
                        Error::InvalidInput | Error::Malformed | Error::Capacity | Error::TooLarge
                    ) {
                        return Err(error);
                    }
                }
            }
        }
        Ok(())
    }

    fn drain_reassembled(
        &mut self,
        context: &mut TransportContext<'_, impl Entropy>,
    ) -> Result<Option<Delivery>, Error> {
        if self.core.has_pending() || self.held.is_some() {
            return Ok(None);
        }
        let core_limit = self.pending_input.len();
        self.link.deliver_reassembled(|frame| match frame {
            Reassembled::Core(frame) if frame.len() > core_limit => Ok(Delivery::Dropped),
            Reassembled::Core(frame) => consume(
                &mut self.core,
                &mut self.application,
                &mut self.discovery,
                frame,
                context,
            ),
            Reassembled::Routed(frame) => Ok(self.application.routed(frame, context.sample)),
        })
    }
}

impl<A: Application, const F: usize, const N: usize> Drop for Peer<'_, '_, A, F, N> {
    fn drop(&mut self) {
        self.retire_carrier();
    }
}

impl<A: Application, const F: usize, const N: usize> Transport for Peer<'_, '_, A, F, N> {
    fn add_queue(
        &mut self,
        local: EddsaPublicKey,
        peer: EddsaPublicKey,
        _role: Role,
    ) -> Result<(), Error> {
        if self.phase != Phase::WaitingForTcp {
            return Err(Error::Conflict);
        }
        if (local, peer) != (self.local, self.remote) {
            return Err(Error::Authentication);
        }
        self.phase = Phase::Validating;
        Ok(())
    }

    fn remove_queue(&mut self) {
        self.retire_carrier();
    }

    fn receive(
        &mut self,
        peer: EddsaPublicKey,
        message: &[u8],
        context: &mut TransportContext<'_, impl Entropy>,
    ) -> Result<Delivery, Error> {
        if peer != self.remote {
            return Err(Error::Authentication);
        }
        let now = context.sample.elapsed;
        self.maintain(context.sample)?;
        match self.link.receive(now, message, self.signer) {
            Ok(Received::Control) => {
                self.update_validation(now)?;
                Ok(self
                    .drain_reassembled(context)?
                    .unwrap_or(Delivery::Consumed))
            }
            Ok(Received::Payload { frame, delivery }) if frame.len() > self.pending_input.len() => {
                self.link.release(delivery).map_err(|e| e.reason)?;
                Ok(Delivery::Dropped)
            }
            Ok(Received::Payload { frame, delivery }) if self.core.has_pending() => {
                self.pending_input[..frame.len()].copy_from_slice(frame);
                self.held = Some(Pending {
                    len: frame.len(),
                    delivery,
                });
                Ok(Delivery::Consumed)
            }
            Ok(Received::Payload { frame, delivery }) => {
                let outcome = consume(
                    &mut self.core,
                    &mut self.application,
                    &mut self.discovery,
                    frame,
                    context,
                );
                self.link.release(delivery).map_err(|e| e.reason)?;
                outcome
            }
            Ok(Received::Routed { frame, delivery }) => {
                let outcome = self.application.routed(frame, context.sample);
                if let Some(delivery) = delivery {
                    self.link.release(delivery).map_err(|e| e.reason)?;
                }
                Ok(outcome)
            }
            // A full original receive slot keeps its charge. A subsequent
            // frame can be discarded while later control messages still flow.
            Err(
                Error::NotReady
                | Error::WouldBlock
                | Error::Capacity
                | Error::Unsupported
                | Error::Malformed
                | Error::Truncated
                | Error::InvalidInput
                | Error::TooLarge
                | Error::Replay
                | Error::Authentication,
            ) => Ok(Delivery::Dropped),
            Err(error) => Err(error),
        }
    }

    fn poll_send(
        &mut self,
        context: &mut TransportContext<'_, impl Entropy>,
        admit: impl FnOnce(Outgoing<'_>) -> Result<(), Error>,
    ) -> Result<(), Error> {
        let now = context.sample.elapsed;
        self.maintain(context.sample)?;
        let mut admit = Some(admit);
        if self
            .link
            .send_control(
                now,
                &mut self.control,
                context.entropy,
                || Ok(context.signed),
                |bytes| admit.take().ok_or(Error::Conflict)?(Outgoing::Buffered(bytes)),
            )?
            .is_some()
            || self.phase != Phase::Validated
        {
            return Ok(());
        }
        self.drive_core(context)?;
        if self.routing.fragmented() {
            return self
                .routing
                .poll(
                    &mut self.link,
                    &mut self.application,
                    now,
                    context.entropy,
                    &mut admit,
                )
                .map(|_| ());
        }
        if !self.link.fragmented_send_pending() && (self.prefer_routing || !self.core.has_pending())
        {
            self.prefer_routing = false;
            if self.routing.poll(
                &mut self.link,
                &mut self.application,
                now,
                context.entropy,
                &mut admit,
            )? {
                return Ok(());
            }
        }
        if self.core.has_pending() {
            self.prefer_routing = true;
        }
        let before = self.core.monitor();
        let admitted = self.core.submit_progress(|frame| {
            self.link
                .send_payload(now, frame, context.entropy, |bytes| {
                    admit.take().ok_or(Error::Conflict)?(Outgoing::Buffered(bytes))
                })
                .map(|progress| match progress {
                    direct::SendProgress::Partial(()) => Submission::Pending,
                    direct::SendProgress::Complete(()) => Submission::Complete(()),
                })
        });
        notify_core_transition(&mut self.application, before, self.core.monitor());
        if admitted?.is_some() && core::mem::take(&mut self.application_pending) {
            self.application.outgoing_complete(Ok(()));
        }
        Ok(())
    }

    fn outgoing_complete(&mut self, result: Result<(), Error>) {
        if result.is_err() {
            self.retire_carrier();
        }
    }

    fn outgoing_written(
        &mut self,
        id: NonZeroU64,
        result: Result<(), Error>,
        elapsed: MonoInstant,
    ) {
        self.routing
            .written(&mut self.application, id, result, elapsed);
    }

    fn before_write(&mut self, sample: Sample) -> Result<(), Error> {
        if self.routing.active() {
            self.application.before_routing_write(sample.elapsed)?;
        }
        Ok(())
    }

    fn deadlines(&self) -> Result<TransportDeadlines, Error> {
        if matches!(self.phase, Phase::WaitingForTcp | Phase::Closed) {
            return Ok(TransportDeadlines::default());
        }
        let elapsed =
            if !self.core.has_pending() && (self.held.is_some() || self.link.has_reassembled()) {
                Some(MonoInstant(0))
            } else {
                self.link.next_deadline()?
            };
        let app = if self.established() && !self.core.has_pending() {
            self.application.outgoing_deadlines()
        } else {
            TransportDeadlines::default()
        };
        Ok(TransportDeadlines {
            absolute: [
                self.core.next_deadline().map(AbsoluteTime::from_micros),
                app.absolute,
            ]
            .into_iter()
            .flatten()
            .min(),
            elapsed: [elapsed, app.elapsed].into_iter().flatten().min(),
        })
    }

    fn maintenance_deadlines(&self) -> TransportDeadlines {
        if !matches!(self.phase, Phase::Validating | Phase::Validated) {
            return TransportDeadlines::default();
        }
        TransportDeadlines {
            absolute: [
                self.core
                    .association_expiry()
                    .map(AbsoluteTime::from_micros),
                self.discovery.next_expiration(),
            ]
            .into_iter()
            .flatten()
            .min(),
            elapsed: self.link.maintenance_deadline(),
        }
    }

    fn maintain(&mut self, sample: Sample) -> Result<(), Error> {
        self.update_validation(sample.elapsed)?;
        self.discovery
            .expire(sample.absolute, &mut self.application)?;
        let before = self.core.monitor();
        if self.core.expire_association(sample.absolute.as_micros()) {
            notify_core_transition(&mut self.application, before, self.core.monitor());
            if core::mem::take(&mut self.application_pending) {
                self.application.outgoing_complete(Err(Error::Deadline));
            }
            if self.link.fragmented_send_pending() && !self.routing.fragmented() {
                self.retire_carrier();
                return Err(Error::Deadline);
            }
        }
        Ok(())
    }
}

fn consume<const F: usize>(
    core: &mut CorePeer<'_, '_, F>,
    application: &mut impl Application,
    discovery: &mut Discovery<'_>,
    frame: &[u8],
    context: &mut TransportContext<'_, impl Entropy>,
) -> Result<Delivery, Error> {
    let before = core.monitor();
    let sample = context.sample;
    let now = sample.absolute;
    let event = core.receive(now.as_micros(), frame, context.entropy, |message| {
        discovery.receive(now, message, application);
        application.received_at(message, sample);
    });
    notify_core_transition(application, before, core.monitor());
    match event {
        Ok(_) => Ok(Delivery::Consumed),
        Err(ReceiveError::RejectedEpoch(_)) => Ok(Delivery::Dropped),
        Err(ReceiveError::Failed(error)) => Err(error),
    }
}
