//! Caller-driven native underlays, PILS signing and local IPC ownership.
//! Direct IP binds its configured UDP sockets; all work remains caller-driven.
use crate::{
    budget::{Anchor, Bound},
    discovery::{self, Discovery},
    neighbours,
    signer::{self, Signer},
    *,
};
use application::Application;
use gnunet_block::plugins::{Context as BlockContext, Plugin, Work as BlockWork};
use gnunet_core_client_host as core;
use gnunet_crypto::{EddsaPublicKey, Entropy};
use gnunet_dht::{
    network::{self, Job, JobKind, NetworkOwner, PutId, Work},
    service::{BuiltinBlocks, ClientId, LocalOwner, Output},
};
use gnunet_nse_client_host as nse;
use gnunet_peerstore_client_host as ps;
use gnunet_pils_host::client as pils;
use gnunet_service_runtime::{
    accepted::{AcceptState, AcceptedConnection},
    clock::{ClockSubscription, RuntimeClock},
    framing::{Accounting, Budget, Class, Framed, Limits as FrameLimits, OwnedFrame, ReadStep},
    service::Listener,
};
use gnunet_transport_application_host as application;
use gnunet_types::Error as Fault;
use gnunet_wire::official::{
    AbsoluteTime, Frame,
    dht::{CoreEnvelope, ipc},
    message_type as mt,
};
use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};
mod core_source;
use core_source::{CorePhase, CoreSource};
mod identity;
mod outgoing;
#[cfg(test)]
mod tests;
mod transport_preferences;
mod underlays;
static TYPES: [u16; 1] = [158];
#[derive(Clone, Copy)]
struct Origin<'id> {
    client: ClientId<'id>,
}
struct Local<'id> {
    token: ClientId<'id>,
    io: Framed<Origin<'id>>,
    input: Option<Bound>,
    output: Option<Bound>,
    first: Option<Bound>,
    read_first: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativePeer<'id> {
    Core(core::Peer<'id>),
    Ip(crate::ip::Peer<'id>),
}
impl NativePeer<'_> {
    fn identity(self) -> gnunet_wire::official::core::PeerId {
        match self {
            Self::Core(peer) => peer.identity(),
            Self::Ip(peer) => peer.identity(),
        }
    }
    fn provider(self) -> Provider {
        match self {
            Self::Core(_) => Provider::Core,
            Self::Ip(_) => Provider::Ip,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NativeSend<'id> {
    Core(core::SendId<'id>),
    Ip(crate::ip::SendId<'id>),
}
struct Peer<'id> {
    native: NativePeer<'id>,
    token: network::Peer<'id>,
    hello_pending: bool,
    ip_preferred: bool,
}
struct NativeJob<'id> {
    job: Job<'id>,
    bound: Bound,
    cancelled: bool,
    target: Option<NativePeer<'id>>,
}
fn native_job_index<'id>(jobs: &[NativeJob<'id>], job: Job<'id>) -> Result<usize, Error> {
    let index = jobs
        .binary_search_by_key(&job.diagnostic(), |row| row.job.diagnostic())
        .map_err(|_| Fault::Stale)?;
    // Diagnostic serials locate metadata; the original branded token alone
    // authorizes access to its fixed target, deadline and cancellation state.
    if jobs[index].job != job {
        return Err(Fault::InvalidInput.into());
    }
    Ok(index)
}
struct NativePut<'id> {
    put: PutId<'id>,
    bound: Bound,
}
struct Send<'id> {
    id: NativeSend<'id>,
    peer: NativePeer<'id>,
    job: Option<Job<'id>>,
    bound: Bound,
    cancelled: bool,
    retirement: Option<(Instant, Pin<Box<Sleep>>)>,
    payload: Option<(usize, usize)>,
    frame_bytes: usize,
}
/// Actual native original sources and their one volatile DHT business owner.
pub struct Server<'id> {
    owner: Option<NetworkOwner<'id>>,
    local: Option<LocalOwner<'id>>,
    core: Option<CoreSource<'id>>,
    ip: Option<crate::ip::Client<'id>>,
    ip_input: Option<crate::ip::Packet<'id>>,
    hello_refresh: bool,
    own_hello: crate::own_hello::OwnHello<'id>,
    core_estimate: Option<f64>,
    ip_addresses_observed: Option<(u64, bool)>,
    signer: Signer<'id>,
    nse: Option<nse::Subscription<'id>>,
    discovery: Discovery<'id>,
    neighbours: neighbours::Controller,
    transport: Option<Application>,
    clock: Arc<dyn RuntimeClock>,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    options: gnunet_service_runtime::service::ServiceOptions,
    unix: gnunet_service_runtime::credentials::UnixAccess,
    limits: Limits,
    blocks: Blocks,
    hello_scratch: Vec<u8>,
    pow: Vec<gnunet_crypto::pow::Block>,
    peers: Vec<Peer<'id>>,
    locals: Vec<Option<Local<'id>>>,
    // Sorted by original serial; every hit also compares the complete token.
    jobs: Vec<NativeJob<'id>>,
    // Sorted by original serial; every hit also compares the complete token.
    puts: Vec<NativePut<'id>>,
    sends: Vec<Send<'id>>,
    preferences: transport_preferences::Preferences,
    output: Option<Output<'id>>,
    events: VecDeque<Event>,
    initial: Option<Bound>,
    routing_identity: Option<[u8; 32]>,
    // Only actual PILS Identity observations can update the own-HELLO slot.
    own_hello_pending: bool,
    closing: bool,
    closed: bool,
    accept: AcceptState,
    cursor: usize,
    local_cursor: usize,
    listener_cursor: usize,
    yield_due: bool,
    timer: Pin<Box<Sleep>>,
    report: Report,
}
impl<'id> Server<'id> {
    /// Reserve bounded metadata and configured native sources. Direct IP binds
    /// actual UDP sockets and samples interfaces; CLIENT sources retain the
    /// caller's single Resolver/clock, listener FDs and stop authority.
    pub fn new(
        instances: &'id mut Instances,
        ports: Ports,
        mut limits: Limits,
        blocks: Blocks,
    ) -> Result<Self, Error> {
        if blocks.hello_profile != limits.pils_profile.hello() {
            return Err(Fault::Conflict.into());
        }
        if !limits.underlays.gnunet && limits.underlays.ip.is_none() {
            return Err(Fault::InvalidInput.into());
        }
        // Admission uses the largest configured carrier; selection below checks
        // the original concrete endpoint's individual limit before issuing IO.
        let carrier_limit = if limits.underlays.gnunet {
            network::PutFrameLimit::from_core_frame_bytes(limits.core.frame_bytes)?
        } else {
            network::PutFrameLimit::new(crate::ip::MAX_FRAME_BYTES)?
        };
        let carrier_limit = if limits.underlays.ip.is_some() {
            carrier_limit.max(network::PutFrameLimit::new(crate::ip::MAX_FRAME_BYTES)?)
        } else {
            carrier_limit
        };
        limits.network.put_frame_limit = limits.network.put_frame_limit.min(carrier_limit);
        for source in [
            &ports.core,
            &ports.pils,
            &ports.nse,
            &ports.peerstore,
            &ports.transport,
        ] {
            if !Arc::ptr_eq(&ports.clock, &source.clock()) {
                return Err(Fault::Conflict.into());
            }
        }
        if limits.local.clients == 0
            || limits.network.peers > 256
            || limits.core.sends > 64
            || !(1..=64).contains(&limits.native_sends)
            || limits.client_frames == 0
            || limits.client_bytes < 65535
            || limits.addresses == 0
            || limits.network.unrouted_puts == 0
            || limits.network.unrouted_puts > 65_535
            || limits.network.unrouted_put_bytes == 0
        {
            return Err(Fault::Capacity.into());
        }
        for d in [
            limits.initial,
            limits.source_lifetime,
            limits.input_lifetime,
            limits.output_lifetime,
            limits.retirement,
            limits.discovery_lifetime,
        ] {
            crate::budget::duration(d)?;
        }
        let initial = Bound::new(ports.clock.as_ref(), limits.initial)?;
        let mut core_initial = limits
            .underlays
            .gnunet
            .then(|| Bound::new(ports.clock.as_ref(), limits.initial))
            .transpose()?;
        let subscription = ports.clock.subscribe()?;
        let revision = ports.clock.sample()?.revision;
        let local = LocalOwner::new(&mut instances.dht, limits.local)?;
        let core_result = if limits.underlays.gnunet {
            core::Client::new(
                &mut instances.core,
                ports.core,
                limits.core_order,
                4,
                &TYPES,
                limits.core,
            )
            .map(Some)
        } else {
            Ok(None)
        };
        let ip_result = limits
            .underlays
            .ip
            .map(|config| crate::ip::Client::new(&mut instances.ip, config))
            .transpose();
        let mut core_failure = None;
        let mut ip_failure = None;
        let core = match core_result {
            Ok(core) => core,
            Err(error) => {
                core_failure = Some(error);
                None
            }
        };
        let ip = match ip_result {
            Ok(ip) => ip,
            Err(error) => {
                ip_failure = Some(error);
                None
            }
        };
        if core.is_none() && ip.is_none() {
            return Err(Error(Arc::new(Cause::UnderlayInitialization {
                core: core_failure.map(Box::new),
                ip: ip_failure.map(Box::new),
            })));
        }
        let mut report = Report::default();
        if let Some(error) = core_failure {
            report.record(Cause::Port(error));
        }
        if let Some(error) = ip_failure {
            report.record(Cause::Ip(error));
        }
        let core = match core {
            Some(client) => Some(CoreSource {
                client,
                phase: CorePhase::Connecting(core_initial.take().ok_or(Fault::NotReady)?),
                input: None,
            }),
            None => None,
        };
        let actual_limit = if core.is_some() {
            network::PutFrameLimit::from_core_frame_bytes(limits.core.frame_bytes)?
        } else {
            network::PutFrameLimit::new(ip.as_ref().ok_or(Fault::NotReady)?.frame_limit())?
        };
        let actual_limit = if let Some(ip) = ip.as_ref() {
            actual_limit.max(network::PutFrameLimit::new(ip.frame_limit())?)
        } else {
            actual_limit
        };
        limits.network.put_frame_limit = limits.network.put_frame_limit.min(actual_limit);
        let mut own_limits = limits.hello;
        if let Some(ip) = ip.as_ref() {
            own_limits.maximum_input_bytes = own_limits.maximum_input_bytes.min(ip.frame_limit());
        }
        let own_hello = crate::own_hello::OwnHello::new(
            own_limits,
            blocks.hello_profile,
            limits.address_bytes,
        )?;
        let signer = Signer::new(
            &mut instances.pils,
            ports.pils,
            limits.pils_profile,
            limits.pils,
            limits.hello,
            limits.retirement,
            limits.input_lifetime,
        )?;
        let nse = if core.is_some() {
            Some(nse::Subscription::new(
                &mut instances.nse,
                ports.nse,
                None,
                limits.nse,
            )?)
        } else {
            None
        };
        let discovery = Discovery::new(
            &mut instances.peerstore,
            &mut instances.peerstore_writer,
            ports.peerstore,
            ports.clock.clone(),
            limits,
            core.is_some(),
        )?;
        let transport = if core.is_some() {
            Some(Application::new(
                ports.transport,
                limits.io_slice_bytes,
                limits.initial,
                limits.source_lifetime,
            )?)
        } else {
            None
        };
        let hello_scratch = discovery::buffer(limits.hello.maximum_address_bytes)?;
        let mut pow = Vec::new();
        if blocks
            .plugins
            .iter()
            .any(|p| matches!(p, Plugin::Revocation(_)))
        {
            pow.try_reserve_exact(gnunet_crypto::pow::MEMORY_BLOCKS)
                .map_err(|_| Fault::Capacity)?;
            pow.resize_with(gnunet_crypto::pow::MEMORY_BLOCKS, Default::default);
        }
        let core_capacity = core.as_ref().map_or(0, |_| limits.network.peers);
        let ip_capacity = ip.as_ref().map_or(0, |_| {
            limits.underlays.ip.map_or(0, |config| config.targets)
        });
        let peers = reserve(
            core_capacity
                .checked_add(ip_capacity)
                .ok_or(Fault::Overflow)?,
        )?;
        let jobs = reserve(limits.network.output_frames)?;
        // Fixed metadata only, never 1024 maximum payload allocations. Actual
        // queue payloads are fallibly allocated before local frame acceptance.
        let puts = reserve(limits.network.unrouted_puts)?;
        let sends = reserve(limits.native_sends)?;
        let preferences = transport_preferences::Preferences::new(core_capacity)?;
        let mut locals = reserve(limits.local.clients)?;
        locals.resize_with(limits.local.clients, || None);
        Ok(Self {
            owner: None,
            local: Some(local),
            core,
            ip,
            ip_input: None,
            hello_refresh: false,
            own_hello,
            core_estimate: None,
            ip_addresses_observed: None,
            signer,
            nse,
            discovery,
            neighbours: neighbours::Controller::new(limits.try_connect),
            transport,
            clock: ports.clock,
            subscription,
            revision,
            options: ports.options,
            unix: ports.unix,
            limits,
            blocks,
            hello_scratch,
            pow,
            peers,
            locals,
            jobs,
            puts,
            sends,
            preferences,
            output: None,
            events: VecDeque::new(),
            initial: Some(initial),
            routing_identity: None,
            own_hello_pending: false,
            closing: false,
            closed: false,
            accept: AcceptState::default(),
            cursor: 0,
            local_cursor: 0,
            listener_cursor: 0,
            yield_due: false,
            timer: Box::pin(tokio::time::sleep(std::time::Duration::ZERO)),
            report,
        })
    }
    /// Actual owned diagnostic facts, without packet, private key or payload data.
    pub fn report(&self) -> &Report {
        &self.report
    }
    /// True only after the original local/provider source owners physically retire
    /// and all retained CORE source-return observations have actually drained.
    pub fn is_closed(&self) -> bool {
        self.closed
    }
    /// The actual PILS identity and at least one enabled native underlay are
    /// ready. Tracked frames and own HELLOs additionally require the selected
    /// carrier's actual local identity to match the applied PILS routing identity.
    pub fn is_ready(&self) -> bool {
        self.report.ready && !self.closing
    }
    fn error(&mut self, provider: Provider, cause: Cause) -> Event {
        Event::Error {
            provider,
            cause: self.report.record(cause),
        }
    }
    fn framing(&self) -> FrameLimits {
        FrameLimits {
            frame_bytes: 65535,
            ordinary: Budget {
                frames: self.limits.client_frames,
                bytes: self.limits.client_bytes,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.limits.io_slice_bytes,
        }
    }
    fn anchor(&self) -> Result<Anchor, Error> {
        let native = Instant::now();
        let hard = native
            .checked_add(self.limits.output_lifetime)
            .ok_or(Fault::Overflow)?;
        let now = self.clock.sample()?.now.as_micros();
        if Instant::now() >= hard {
            return Err(Fault::Deadline.into());
        }
        Ok(Anchor { now, native, hard })
    }
    fn sync_jobs(&mut self, anchor: Anchor) -> Result<(), Error> {
        let Some(owner) = self.owner.as_ref() else {
            return Ok(());
        };
        self.jobs.retain(|j| owner.owns_job(j.job));
        self.puts
            .retain(|native| owner.owns_unrouted_put(native.put));
        for info in owner.unrouted_puts() {
            match self
                .puts
                .binary_search_by_key(&info.put.diagnostic(), |p| p.put.diagnostic())
            {
                Ok(index) => {
                    // The serial locates metadata, never creates or replaces
                    // an original intent from another service instance.
                    if self.puts[index].put != info.put {
                        return Err(Fault::InvalidInput.into());
                    }
                }
                Err(index) => {
                    if self.puts.len() == self.limits.network.unrouted_puts {
                        return Err(Fault::Capacity.into());
                    }
                    let remaining = info.until.checked_sub(anchor.now).ok_or(Fault::Deadline)?;
                    let hard = anchor
                        .native
                        .checked_add(std::time::Duration::from_micros(remaining))
                        .ok_or(Fault::Overflow)?;
                    self.puts.insert(
                        index,
                        NativePut {
                            put: info.put,
                            bound: Bound::targets(info.until, hard),
                        },
                    );
                }
            }
        }
        self.report.unrouted_puts = owner.put_stats();
        for info in owner.jobs() {
            match self
                .jobs
                .binary_search_by_key(&info.job.diagnostic(), |row| row.job.diagnostic())
            {
                Ok(index) => {
                    if self.jobs[index].job != info.job {
                        return Err(Fault::InvalidInput.into());
                    }
                }
                Err(index) => {
                    if self.jobs.len() == self.limits.network.output_frames {
                        return Err(Fault::Capacity.into());
                    }
                    let mut bound = Bound::for_job(info.until, anchor)?;
                    if let Some(put) = info.put {
                        let index = self
                            .puts
                            .binary_search_by_key(&put.diagnostic(), |p| p.put.diagnostic())
                            .map_err(|_| Fault::Stale)?;
                        let original = &self.puts[index];
                        if original.put != put {
                            return Err(Fault::Stale.into());
                        }
                        // A rollback/new retry must not extend the original PUT's
                        // native hard even though this is a new unsubmitted frame.
                        bound = Bound::targets(info.until, bound.hard.min(original.bound.hard));
                    }
                    self.jobs.insert(
                        index,
                        NativeJob {
                            job: info.job,
                            bound,
                            cancelled: false,
                            target: None,
                        },
                    );
                }
            }
        }
        Ok(())
    }
    fn ready(&mut self) -> Result<Option<Event>, Error> {
        if self.owner.is_some()
            || (!self
                .core
                .as_ref()
                .is_some_and(|source| source.phase.ready())
                && self.ip.is_none())
        {
            return Ok(None);
        }
        let Some(identity) = self.signer.identity() else {
            return Ok(None);
        };
        let peer = *identity.peer().as_bytes();
        self.routing_identity = Some(peer);
        if let Some(ip) = self.ip.as_mut() {
            ip.set_identity(peer)?;
        }
        let owner = NetworkOwner::new(
            self.local.take().ok_or(Fault::Stale)?,
            peer,
            self.limits.network,
            network::Policy {
                estimate: gnunet_dht::routing::Estimate::new(0.5)?,
            },
        )?;
        self.owner = Some(owner);
        self.update_estimate()?;
        self.initial = None;
        self.report.ready = true;
        Ok(Some(Event::Ready { peer }))
    }
    fn core_event(
        &mut self,
        event: core::Progress<'id>,
        anchor: Option<Anchor>,
        entropy: &mut impl Entropy,
    ) -> Result<Event, Error> {
        match event {
            core::Progress::Inbound { event, .. } => {
                self.core.as_mut().ok_or(Fault::Stale)?.input = None;
                match event {
                    core::Inbound::Ready { local, .. } => {
                        // INIT_REPLY identifies this actual CORE MQ, not the
                        // current canonical PILS routing identity.
                        self.core.as_mut().ok_or(Fault::Stale)?.phase = CorePhase::Ready {
                            bound: Bound::new(self.clock.as_ref(), self.limits.source_lifetime)?,
                            local,
                        };
                        if let Some(event) = self.ready()? {
                            return Ok(event);
                        }
                    }
                    core::Inbound::Connected(native) => {
                        self.connect_native(NativePeer::Core(native))?;
                    }
                    core::Inbound::Disconnected(peer) => {
                        self.disconnect_native(NativePeer::Core(peer))?
                    }
                    core::Inbound::Traffic {
                        connection: Some(native),
                        direction: core::Direction::Inbound,
                        traffic: core::OwnedTraffic::Full(frame),
                        ..
                    } => {
                        let wire = match CoreEnvelope::decode(frame.as_ref()) {
                            Ok(envelope) => envelope.inner(),
                            Err(error) => {
                                return Ok(self.error(Provider::Core, Cause::Protocol(error)));
                            }
                        };
                        if let Err(error) = self.ingest_native(
                            NativePeer::Core(native),
                            wire,
                            anchor.ok_or(Fault::NotReady)?,
                            entropy,
                        ) {
                            return Ok(Event::Error {
                                provider: Provider::Core,
                                cause: self.record_error(error),
                            });
                        }
                    }
                    _ => {}
                }
                Ok(Event::Activity(Provider::Core))
            }
            core::Progress::Finished {
                peer,
                send,
                payload,
                completion,
                ..
            } => {
                let i = self
                    .sends
                    .iter()
                    .position(|s| {
                        s.id == NativeSend::Core(send) && s.peer == NativePeer::Core(peer)
                    })
                    .ok_or(Fault::Stale)?;
                let s = self.sends.remove(i);
                let fact = SendFact {
                    job: s.job.map_or(0, Job::diagnostic),
                    peer: peer.identity().0,
                    provider: Provider::Core,
                    outcome: crate::SendOutcome::Core(completion.outcome),
                    written: payload.written(),
                    frame_bytes: payload.frame_bytes(),
                };
                if matches!(
                    fact.outcome,
                    crate::SendOutcome::Core(core::SendOutcome::Written)
                ) {
                    self.report.core_written = self.report.core_written.saturating_add(1);
                } else if payload.exposed() {
                    self.report.core_uncertain = self.report.core_uncertain.saturating_add(1);
                }
                // The returned original source erases here; metadata above is not a replay permit.
                drop(completion.source);
                Ok(Event::Send(fact))
            }
            core::Progress::PeerLost { peer, .. } => {
                self.disconnect_native(NativePeer::Core(peer))?;
                Ok(Event::Activity(Provider::Core))
            }
            core::Progress::Lost { cause, .. } => {
                self.core.as_mut().ok_or(Fault::Stale)?.retire();
                self.disconnect_core_peers()?;
                self.core_estimate = None;
                self.update_estimate()?;
                Ok(self.error(Provider::Core, Cause::Core(cause)))
            }
            core::Progress::Connected(_) => {
                self.core.as_mut().ok_or(Fault::Stale)?.phase =
                    CorePhase::Connecting(Bound::new(self.clock.as_ref(), self.limits.initial)?);
                Ok(Event::Activity(Provider::Core))
            }
            core::Progress::Capacity(_) => {
                let source = self.core.as_mut().ok_or(Fault::Stale)?;
                if source.input.is_none() {
                    source.input =
                        Some(Bound::new(self.clock.as_ref(), self.limits.input_lifetime)?);
                }
                Ok(self.error(Provider::Core, Cause::Protocol(Fault::Capacity)))
            }
            core::Progress::ConnectRetry { error, .. } => {
                Ok(self.error(Provider::Core, Cause::Io(error)))
            }
            core::Progress::Unavailable(error) => {
                if self.ip.is_none() {
                    return Err(error.into());
                }
                self.disable_core()?;
                Ok(self.error(Provider::Core, Cause::Port(error)))
            }
            core::Progress::Activity {
                read_bytes,
                payload,
                ..
            } => {
                if let Some(progress) = payload {
                    let actual = progress.state();
                    if let Some(send) = self.sends.iter_mut().find(|s| {
                        s.id == NativeSend::Core(actual.send())
                            && s.peer == NativePeer::Core(actual.peer())
                    }) {
                        send.payload = Some((actual.written(), actual.frame_bytes()));
                    }
                }
                let source = self.core.as_mut().ok_or(Fault::Stale)?;
                if read_bytes > 0 && source.input.is_none() {
                    source.input =
                        Some(Bound::new(self.clock.as_ref(), self.limits.input_lifetime)?);
                }
                Ok(Event::Activity(Provider::Core))
            }
            core::Progress::Closed => {
                self.core = None;
                Ok(Event::Activity(Provider::Core))
            }
            _ => Ok(Event::Activity(Provider::Core)),
        }
    }
    fn ps_event(&mut self, event: ps::Progress<'id>) -> Event {
        match event {
            ps::Progress::Lost { cause, .. } => {
                self.error(Provider::Peerstore, Cause::Peerstore(cause))
            }
            ps::Progress::ConnectRetry { error, .. } => {
                self.error(Provider::Peerstore, Cause::Io(error))
            }
            ps::Progress::Unavailable(e) => self.error(Provider::Peerstore, Cause::Port(e)),
            ps::Progress::Completed { outcome, kind, .. } => {
                match outcome {
                    ps::Outcome::StoreResult(code) => {
                        self.report.peerstore_results =
                            self.report.peerstore_results.saturating_add(1);
                        self.report.peerstore_result = Some(code);
                    }
                    ps::Outcome::Local {
                        submission: ps::Submission::Unknown,
                        ..
                    } if kind == ps::Kind::Store => {
                        self.report.peerstore_unknown =
                            self.report.peerstore_unknown.saturating_add(1)
                    }
                    _ => {}
                }
                Event::Activity(Provider::Peerstore)
            }
            _ => Event::Activity(Provider::Peerstore),
        }
    }
    fn transport_retired(&mut self, r: application::Retired) -> Result<(), Error> {
        // Positive prefix remains Unknown even if the full local hint had not written.
        if r.written > 0 {
            self.report.transport_unknown = self.report.transport_unknown.saturating_add(1);
        }
        self.preferences.retired(r.epoch)?;
        let _original = (r.submitted, r.remaining);
        Ok(())
    }
    /// Clock-free physical stop of each original provider. CORE's returned
    /// messages still drain through poll_close; no timeout is called completion.
    pub fn begin_close(&mut self) {
        if self.closing {
            return;
        }
        self.closing = true;
        self.ip_input = None;
        self.neighbours.empty();
        // Retire original local tokens before closing the business owner.
        for i in 0..self.locals.len() {
            self.close_local(i);
        }
        if let Some(owner) = self.owner.as_mut() {
            owner.close();
            self.report.unrouted_puts = owner.put_stats();
            self.puts.clear();
        }
        if let Some(failure) = self
            .owner
            .as_mut()
            .and_then(NetworkOwner::take_unrouted_failure)
        {
            let event = self.put_failure(failure);
            self.events.push_back(event);
        }
        if let Some(local) = self.local.as_mut() {
            local.close();
        }
        if let Some(target) = self.signer.close()
            && let Err(error) = self.cancel_sign_target(target, true)
        {
            self.record_error(error);
        }
        if let Some(nse) = self.nse.as_mut() {
            let actual_nse = nse.close();
            self.report.nse_start_bytes = actual_nse.start_bytes;
            self.report.nse_start_written = actual_nse.start_written;
        }
        for result in self.discovery.close() {
            match result {
                Ok(Some(event)) => {
                    let e = self.ps_event(event);
                    self.events.push_back(e);
                }
                Ok(None) => {}
                Err(e) => {
                    let e = self.error(Provider::Peerstore, Cause::Port(e));
                    self.events.push_back(e);
                }
            }
        }
        if let Some(transport) = self.transport.as_mut() {
            let retired = transport.close();
            if let Err(error) = self.transport_retired(retired) {
                let event = self.record_error(error);
                self.events.push_back(Event::Error {
                    provider: Provider::Transport,
                    cause: event,
                });
            }
        }
        if let Some(ip) = self.ip.as_mut() {
            ip.close();
        }
        match self
            .core
            .as_mut()
            .map(|source| {
                source.retire();
                source.client.close()
            })
            .transpose()
        {
            Ok(Some(Some(event))) => self.close_core_event(event),
            Ok(Some(None) | None) => {}
            Err(e) => {
                let e = self.error(Provider::Core, Cause::Port(e));
                self.events.push_back(e);
            }
        }
        self.output = None;
        self.jobs.clear();
    }
    fn close_core_event(&mut self, event: core::Progress<'id>) {
        match event {
            core::Progress::Finished {
                peer,
                send,
                payload,
                completion,
                ..
            } => {
                if let Some(i) = self.sends.iter().position(|s| {
                    s.id == NativeSend::Core(send) && s.peer == NativePeer::Core(peer)
                }) {
                    let s = self.sends.remove(i);
                    let fact = SendFact {
                        job: s.job.map_or(0, Job::diagnostic),
                        peer: peer.identity().0,
                        provider: Provider::Core,
                        outcome: crate::SendOutcome::Core(completion.outcome),
                        written: payload.written(),
                        frame_bytes: payload.frame_bytes(),
                    };
                    if payload.exposed() && completion.outcome != core::SendOutcome::Written {
                        self.report.core_uncertain = self.report.core_uncertain.saturating_add(1);
                    }
                    if completion.outcome == core::SendOutcome::Written {
                        self.report.core_written = self.report.core_written.saturating_add(1);
                    }
                    self.events.push_back(Event::Send(fact));
                } else {
                    self.report.record(Cause::Protocol(Fault::Stale));
                }
                drop(completion.source);
            }
            core::Progress::Lost { cause, .. } => {
                let e = self.error(Provider::Core, Cause::Core(cause));
                self.events.push_back(e);
            }
            core::Progress::Closed => {
                self.core = None;
            }
            _ => {}
        }
    }
    /// Continue original return queues without sampling a failed clock/Resolver.
    pub fn poll_close(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if self.closed {
            return Poll::Ready(Ok(Progress::Closed));
        }
        self.begin_close();
        if let Some(event) = self.events.pop_front() {
            observe(event);
            return Poll::Ready(Ok(Progress::Activity));
        }
        if let Some(event) = self.discovery.take_event() {
            let e = self.ps_event(event);
            observe(e);
            return Poll::Ready(Ok(Progress::Activity));
        }
        if let Some(source) = self.core.as_mut() {
            match source.client.poll(cx, None) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(e)) => {
                    let event = self.error(Provider::Core, Cause::Port(e));
                    observe(event);
                    return Poll::Ready(Ok(Progress::Activity));
                }
                Poll::Ready(Ok(event)) => {
                    self.close_core_event(event);
                    cx.waker().wake_by_ref();
                    return Poll::Ready(Ok(Progress::Activity));
                }
            }
        }
        if let Some(ip) = self.ip.as_mut() {
            let event = match ip.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(event) => event?,
            };
            if let Some(event) = self.ip_close_event(event)? {
                observe(event);
            }
            return Poll::Ready(Ok(Progress::Activity));
        }
        self.closed = true;
        self.report.unresolved = self.sends.len()
            + self.discovery.pending()
            + self.owner.as_ref().map_or(0, |o| o.snapshot().jobs);
        self.report.quiescent = self.report.unresolved == 0;
        observe(Event::Closed);
        Poll::Ready(Ok(Progress::Closed))
    }
    /// Consume the same report. Forced consuming close remains honestly unresolved
    /// until original return queues were observed, even though Drop closes FDs.
    pub fn into_report(mut self) -> Report {
        self.begin_close();
        while let Some(event) = self.discovery.take_event() {
            let _original = self.ps_event(event);
        }
        for (slot, send) in self.report.unsettled.iter_mut().zip(&self.sends) {
            *slot = Some(PendingSendFact {
                job: send.job.map_or(0, Job::diagnostic),
                peer: send.peer.identity().0,
                provider: send.peer.provider(),
                written: send.payload.map_or(0, |(written, _)| written),
                frame_bytes: send.frame_bytes,
            });
        }
        if !self.closed {
            self.report.unresolved = self.sends.len()
                + self.discovery.pending()
                + usize::from(self.core.is_some())
                + usize::from(self.ip.is_some())
                + self.owner.as_ref().map_or(0, |o| o.snapshot().jobs);
            self.report.quiescent = false;
        }
        std::mem::take(&mut self.report)
    }
    fn close_local(&mut self, i: usize) {
        if let Some(p) = self.locals[i].take() {
            if let Some(owner) = self.owner.as_mut()
                && let Err(e) = owner.disconnect_client(p.token)
            {
                self.report.record(Cause::Protocol(e));
            }
            drop(p);
            self.accept.client_closed();
        }
    }
    fn admit(&mut self, accepted: AcceptedConnection) -> Result<Event, Error> {
        let (connection, address, diagnostics) = accepted.into_parts();
        for d in diagnostics {
            self.events.push_back(Event::Socket(
                gnunet_service_runtime::accepted::SocketEvent::Diagnostic(d),
            ));
        }
        let allowed = match address {
            gnunet_service_runtime::service::PeerAddress::Tcp(a) => {
                self.options.access.allows(a.ip())
            }
            gnunet_service_runtime::service::PeerAddress::Unix => self
                .unix
                .allows(&connection)
                .map_err(|e| Error(Arc::new(Cause::Io(e))))?,
        };
        if !allowed {
            return Err(Fault::PermissionDenied.into());
        }
        let i = self
            .locals
            .iter()
            .position(Option::is_none)
            .ok_or(Fault::Capacity)?;
        let first = Bound::new(self.clock.as_ref(), self.limits.input_lifetime)?;
        let io = Framed::new(connection, self.framing())?;
        if Instant::now() >= first.hard {
            return Err(Fault::Deadline.into());
        }
        let token = self
            .owner
            .as_mut()
            .ok_or(Fault::NotReady)?
            .connect_client()?;
        self.locals[i] = Some(Local {
            token,
            io,
            input: None,
            output: None,
            first: Some(first),
            read_first: false,
        });
        self.report.clients = self.report.clients.saturating_add(1);
        Ok(Event::Client {
            client: token.diagnostic(),
            address,
        })
    }
    fn accept(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
    ) -> Poll<Result<Event, Error>> {
        if !self.accept.ready() || listeners.is_empty() || !self.is_ready() {
            return Poll::Pending;
        }
        for n in 0..listeners.len() {
            let i = (self.listener_cursor + n) % listeners.len();
            match listeners[i].poll_canonical_connection(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => {
                    return Poll::Ready(Ok(Event::Socket(self.accept.failed(e))));
                }
                Poll::Ready(Ok(c)) => {
                    self.listener_cursor = (i + 1) % listeners.len();
                    return Poll::Ready(Ok(match self.admit(c) {
                        Ok(event) => event,
                        Err(error) => Event::Error {
                            provider: Provider::Local,
                            cause: self.record_error(error),
                        },
                    }));
                }
            }
        }
        Poll::Pending
    }

    fn hello_frame(&mut self, url: bool, now: u64) -> Result<Vec<u8>, Error> {
        let block = if self.ip.is_some() {
            if self.ip.as_ref().is_some_and(|ip| ip.addresses_current()) {
                self.own_hello.block()
            } else {
                None
            }
        } else {
            self.signer
                .announcement()
                .map(gnunet_wire::official::pils::PeerUpdate::decode)
                .transpose()?
                .map(|update| update.block)
        };
        let Some(block) = block else {
            if url {
                let mut frame = discovery::buffer(4)?;
                ipc::encode_hello(None, false, &mut frame)?;
                return Ok(frame);
            }
            return Err(Fault::NotReady.into());
        };
        let hello =
            gnunet_hello::Hello::parse_block(block, &mut self.hello_scratch, self.limits.hello)?;
        if Some(*hello.peer().as_bytes()) != self.routing_identity {
            return Err(Error(Arc::new(Cause::Identity)));
        }
        match hello.verify_at(self.blocks.hello_profile, AbsoluteTime::from_micros(now)) {
            Ok(_) => {}
            Err(Fault::Deadline) => {
                if url {
                    let mut frame = discovery::buffer(4)?;
                    ipc::encode_hello(None, false, &mut frame)?;
                    return Ok(frame);
                }
                return Err(Fault::NotReady.into());
            }
            Err(e) => return Err(e.into()),
        }
        if url {
            let mut text = discovery::buffer(hello.url_len()?)?;
            hello.write_url(&mut text)?;
            let mut frame = discovery::buffer(text.len().checked_add(5).ok_or(Fault::Overflow)?)?;
            ipc::encode_hello(Some(&text), false, &mut frame)?;
            Ok(frame)
        } else if self.ip.is_some() {
            self.own_hello
                .message()?
                .ok_or_else(|| Fault::NotReady.into())
        } else {
            let mut frame = discovery::buffer(hello.dht_message_len()?)?;
            hello.encode_dht_message(&mut frame)?;
            Ok(frame)
        }
    }
    fn process_local(
        &mut self,
        i: usize,
        anchor: Anchor,
        entropy: &mut impl Entropy,
    ) -> Result<bool, Error> {
        let Some(p) = self.locals[i].as_mut() else {
            return Ok(false);
        };
        let Some(frame) = p.io.frame() else {
            return Ok(false);
        };
        if p.input.as_ref().is_some_and(|b| Instant::now() >= b.hard) {
            return Err(Fault::Deadline.into());
        }
        match ipc::Request::decode(frame)? {
            ipc::Request::HelloGet => {
                let reply = self.hello_frame(true, anchor.now)?;
                let p = self.locals[i].as_mut().ok_or(Fault::Stale)?;
                if !p.io.capacity(reply.len(), Class::Ordinary) {
                    return Ok(false);
                }
                let bound = if p.output.is_none() {
                    Some(Bound::new(
                        self.clock.as_ref(),
                        self.limits.output_lifetime,
                    )?)
                } else {
                    None
                };
                p.io.reserve(reply.len(), Class::Ordinary)?;
                p.io.enqueue_owned(
                    OwnedFrame::new(reply),
                    Origin { client: p.token },
                    Class::Ordinary,
                )
                .map_err(|e| e.reason)?;
                if let Some(bound) = bound {
                    p.output = Some(bound);
                }
            }
            ipc::Request::HelloUrl(Some(url)) => {
                let hello = gnunet_hello::Hello::parse_url(
                    url,
                    &mut self.hello_scratch,
                    self.limits.hello,
                )?;
                hello.verify_at(
                    self.blocks.hello_profile,
                    AbsoluteTime::from_micros(anchor.now),
                )?;
                let mut bytes = discovery::buffer(hello.message_len()?)?;
                hello.encode_message(&mut bytes)?;
                self.discovery.observe(&bytes, None, anchor.now, true)?;
                self.report.hello_observations = self.report.hello_observations.saturating_add(1);
            }
            ipc::Request::HelloUrl(None) => return Err(Fault::InvalidInput.into()),
            _ => {
                let p = self.locals[i].as_ref().ok_or(Fault::Stale)?;
                let mut blocks = BuiltinBlocks {
                    context: BlockContext::new(&self.blocks.plugins, self.blocks.group_profile),
                    work: BlockWork {
                        hello: &mut self.hello_scratch,
                        hello_limits: self.limits.hello,
                        hello_profile: self.blocks.hello_profile,
                        pow: &mut self.pow,
                    },
                };
                match self.owner.as_mut().ok_or(Fault::NotReady)?.ingest_client(
                    p.token,
                    p.io.frame().ok_or(Fault::NotReady)?,
                    anchor.now,
                    &mut blocks,
                    entropy,
                ) {
                    Ok(_) => {}
                    Err(Fault::Capacity | Fault::WouldBlock) => return Ok(false),
                    Err(e) => return Err(e.into()),
                }
                self.sync_jobs(anchor)?;
            }
        }
        let p = self.locals[i].as_mut().ok_or(Fault::Stale)?;
        p.io.release_frame();
        p.input = None;
        p.first = None;
        self.report.requests = self.report.requests.saturating_add(1);
        Ok(true)
    }
    fn local_poll(
        &mut self,
        cx: &mut Context<'_>,
        anchor: Anchor,
        entropy: &mut impl Entropy,
    ) -> Poll<Result<Event, Error>> {
        for n in 0..self.locals.len() {
            let i = (self.local_cursor + n) % self.locals.len();
            if self.locals[i].is_none() {
                continue;
            }
            match self.process_local(i, anchor, entropy) {
                Ok(true) => {
                    self.local_cursor = (i + 1) % self.locals.len();
                    return Poll::Ready(Ok(Event::Activity(Provider::Local)));
                }
                Err(e) => {
                    self.close_local(i);
                    return Poll::Ready(Ok(Event::Error {
                        provider: Provider::Local,
                        cause: self.record_error(e),
                    }));
                }
                Ok(false) => {}
            }
            for offset in 0..2 {
                let p = self.locals[i].as_mut().ok_or(Fault::Stale)?;
                let read = (offset == 0) == p.read_first;
                if read {
                    if p.io.frame().is_some() {
                        continue;
                    }
                    let started = Instant::now();
                    match p.io.poll_read(cx) {
                        Poll::Pending => {}
                        Poll::Ready(Ok(ReadStep::Eof)) => {
                            self.close_local(i);
                            return Poll::Ready(Ok(Event::Activity(Provider::Local)));
                        }
                        Poll::Ready(Err(e)) => {
                            self.close_local(i);
                            return Poll::Ready(Ok(self.error(Provider::Local, Cause::Io(e))));
                        }
                        Poll::Ready(Ok(ReadStep::Progress { bytes, .. })) => {
                            if bytes > 0 && p.input.is_none() {
                                let hard = started
                                    .checked_add(self.limits.input_lifetime)
                                    .ok_or(Fault::Overflow)?;
                                let until = anchor
                                    .now
                                    .checked_add(crate::budget::duration(
                                        self.limits.input_lifetime,
                                    )?)
                                    .filter(|n| *n != u64::MAX)
                                    .ok_or(Fault::Overflow)?;
                                p.input = Some(Bound::targets(until, hard));
                            }
                            p.read_first = false;
                            self.local_cursor = (i + 1) % self.locals.len();
                            return Poll::Ready(Ok(Event::Activity(Provider::Local)));
                        }
                    }
                } else if p.io.queued_frames() > 0 {
                    match p.io.poll_write(cx) {
                        Poll::Pending => {}
                        Poll::Ready(Err(e)) => {
                            self.close_local(i);
                            return Poll::Ready(Ok(self.error(Provider::Local, Cause::Io(e))));
                        }
                        Poll::Ready(Ok(progress)) => {
                            if progress.origin.client != p.token {
                                return Poll::Ready(Err(Fault::Stale.into()));
                            }
                            self.report.local_written = self
                                .report
                                .local_written
                                .saturating_add(progress.bytes as u64);
                            if p.io.queued_frames() == 0 {
                                p.output = None;
                            }
                            p.read_first = true;
                            self.local_cursor = (i + 1) % self.locals.len();
                            return Poll::Ready(Ok(Event::Activity(Provider::Local)));
                        }
                    }
                }
            }
        }
        Poll::Pending
    }
    fn record_error(&mut self, error: Error) -> Arc<Cause> {
        let cause = error.0;
        if let Some(s) = self.report.errors.iter_mut().find(|s| s.is_none()) {
            *s = Some(cause.clone());
        } else {
            self.report.omitted_errors = self.report.omitted_errors.saturating_add(1);
        }
        cause
    }
    fn local_output(&mut self) -> Result<bool, Error> {
        if self.output.is_none() {
            self.output = self.owner.as_mut().and_then(NetworkOwner::take_output);
        }
        let Some(output) = self.output.as_ref() else {
            return Ok(false);
        };
        let Some(i) = self
            .locals
            .iter()
            .position(|p| p.as_ref().is_some_and(|p| p.token == output.client()))
        else {
            self.output = None;
            return Ok(true);
        };
        let p = self.locals[i].as_mut().ok_or(Fault::Stale)?;
        if !p.io.capacity(output.bytes().len(), Class::Ordinary) {
            return Ok(false);
        }
        let bound = if p.output.is_none() {
            Some(Bound::new(
                self.clock.as_ref(),
                self.limits.output_lifetime,
            )?)
        } else {
            None
        };
        p.io.reserve(output.bytes().len(), Class::Ordinary)?;
        let (client, _, bytes) = self.output.take().ok_or(Fault::Stale)?.into_parts();
        p.io.enqueue_owned(OwnedFrame::new(bytes), Origin { client }, Class::Ordinary)
            .map_err(|e| e.reason)?;
        if let Some(bound) = bound {
            p.output = Some(bound);
        }
        Ok(true)
    }
    fn send_frame(
        &mut self,
        native: NativePeer<'id>,
        job: Option<(Job<'id>, JobKind)>,
        frame: &[u8],
        bound: Bound,
    ) -> Result<bool, Error> {
        outgoing::Outgoing::new(
            &mut self.core,
            &mut self.ip,
            &mut self.sends,
            self.clock.as_ref(),
            &mut self.report,
            self.limits.native_sends,
        )
        .send(native, job, frame, bound)
    }
    fn work(&mut self) -> Result<bool, Error> {
        enum Selected<'id> {
            Sign(Job<'id>, [u8; 144]),
            Admitted(Job<'id>, network::Peer<'id>),
            Expired(Job<'id>),
        }
        let Some(owner) = self.owner.as_ref() else {
            return Ok(false);
        };
        let mut selected = None;
        for work in owner.work() {
            let job = match &work {
                Work::Sign {
                    job,
                    peer,
                    frame_bytes,
                    ..
                } => {
                    let Some(target) = self.target_for(*job, *peer, *frame_bytes, true)? else {
                        continue;
                    };
                    // Freeze the exact matching carrier before asking PILS to
                    // sign its successor. A mismatched CORE must not hide IP.
                    let index = native_job_index(&self.jobs, *job)?;
                    self.jobs[index].target = Some(target);
                    if !self.signer.idle() {
                        continue;
                    }
                    *job
                }
                Work::Send {
                    job, peer, frame, ..
                } => {
                    if self.sends.len() == self.send_limit() {
                        continue;
                    }
                    let Some(target) =
                        self.target_for(*job, *peer, frame.len(), identity::tracked(frame)?)?
                    else {
                        continue;
                    };
                    // Freeze this original endpoint before waiting for its credit.
                    let index = native_job_index(&self.jobs, *job)?;
                    self.jobs[index].target = Some(target);
                    if !self.request_available(target, frame.len())? {
                        continue;
                    }
                    *job
                }
                Work::Retire { job, .. } => {
                    self.signer.cancel(signer::Target::Path(*job))?;
                    continue;
                }
            };
            let original = &self.jobs[native_job_index(&self.jobs, job)?];
            if Instant::now() >= original.bound.hard
                || self.clock.sample()?.now.as_micros() >= original.bound.until
            {
                selected = Some(Selected::Expired(job));
                break;
            }
            selected = Some(match work {
                Work::Sign { job, material, .. } => Selected::Sign(job, *material),
                Work::Send {
                    job,
                    peer,
                    kind,
                    frame,
                    ..
                } => {
                    let target = original.target.ok_or(Fault::Stale)?;
                    let bound = Bound::targets(original.bound.until, original.bound.hard);
                    // Split only carrier fields away from the borrowed pure
                    // owner. Its original frame is copied directly into the
                    // actual native FIFO, never an intermediate payload owner.
                    if !outgoing::Outgoing::new(
                        &mut self.core,
                        &mut self.ip,
                        &mut self.sends,
                        self.clock.as_ref(),
                        &mut self.report,
                        self.limits.native_sends,
                    )
                    .send(target, Some((job, kind)), frame, bound)?
                    {
                        return Ok(false);
                    }
                    Selected::Admitted(job, peer)
                }
                Work::Retire { .. } => continue,
            });
            break;
        }
        let Some(work) = selected else {
            return Ok(false);
        };
        match work {
            Selected::Expired(job) => {
                self.owner
                    .as_mut()
                    .ok_or(Fault::NotReady)?
                    .cancel_job(job)?;
                self.jobs.retain(|original| original.job != job);
                self.report.record(Cause::Protocol(Fault::Deadline));
                Ok(true)
            }
            Selected::Sign(job, material) => {
                let original = &self.jobs[native_job_index(&self.jobs, job)?];
                original.bound.check(self.clock.as_ref())?;
                let peer =
                    EddsaPublicKey::from_bytes(self.routing_identity.ok_or(Fault::NotReady)?);
                self.signer
                    .start(job, peer, &material, original.bound.hard)?;
                self.owner
                    .as_mut()
                    .ok_or(Fault::NotReady)?
                    .sign_started(job)?;
                Ok(true)
            }
            Selected::Admitted(job, peer) => {
                self.owner
                    .as_mut()
                    .ok_or(Fault::NotReady)?
                    .admitted(job, peer)?;
                self.jobs.retain(|original| original.job != job);
                if let Some(owner) = self.owner.as_ref() {
                    self.puts.retain(|put| owner.owns_unrouted_put(put.put));
                    self.report.unrouted_puts = owner.put_stats();
                }
                Ok(true)
            }
        }
    }
    fn hints(&mut self, anchor: Anchor) -> Result<bool, Error> {
        let desired = self.peers.iter().filter_map(|peer| match peer.native {
            NativePeer::Core(peer) => Some(peer.identity().0),
            NativePeer::Ip(_) => None,
        });
        if let Some(change) = self.preferences.next(desired)
            && let Some(transport) = self.transport.as_mut()
            && transport.idle()
        {
            let bound = Bound::new(self.clock.as_ref(), self.limits.output_lifetime)?;
            transport.preference(change.peer, change.cancel, transport_bounds(bound))?;
            self.preferences.admitted(change)?;
            return Ok(true);
        }
        for index in 0..self.peers.len() {
            if self.peers[index].ip_preferred {
                continue;
            }
            match self.peers[index].native {
                NativePeer::Core(_) => continue,
                NativePeer::Ip(peer) => self
                    .ip
                    .as_mut()
                    .ok_or(Fault::Closed)?
                    .set_preference(peer, true)?,
            }
            self.peers[index].ip_preferred = true;
            return Ok(true);
        }
        self.discovery.expire(anchor.now);
        if !self.limits.try_connect {
            return Ok(false);
        }
        for offset in 0..2 {
            let block = (offset == 0) == self.discovery.hint_first;
            if block {
                if let Some(hint) = self.discovery.hints.first() {
                    let until = anchor
                        .now
                        .checked_add(crate::budget::duration(self.limits.output_lifetime)?)
                        .filter(|n| *n != u64::MAX)
                        .ok_or(Fault::Overflow)?
                        .min(hint.expiration);
                    let bound = Bound::for_job(until, anchor)?;
                    if underlays::hint(
                        &mut self.ip,
                        &mut self.transport,
                        &mut self.report,
                        hint.peer,
                        &hint.uri,
                        bound,
                    )? {
                        self.discovery.hints.remove(0);
                        self.discovery.hint_first = false;
                        return Ok(true);
                    }
                }
            } else {
                for index in 0..self.discovery.records.len() {
                    let expires = self.discovery.records[index].expiration;
                    if expires <= anchor.now {
                        continue;
                    }
                    if let Some((peer, address)) = self.discovery.address(index)? {
                        let until = anchor
                            .now
                            .checked_add(crate::budget::duration(self.limits.output_lifetime)?)
                            .filter(|n| *n != u64::MAX)
                            .ok_or(Fault::Overflow)?
                            .min(expires);
                        let bound = Bound::for_job(until, anchor)?;
                        if underlays::hint(
                            &mut self.ip,
                            &mut self.transport,
                            &mut self.report,
                            peer,
                            address,
                            bound,
                        )? {
                            self.discovery.records[index].next_address += 1;
                            self.discovery.hint_first = true;
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
    }
    fn local_hello_work(&mut self, anchor: Anchor) -> Result<bool, Error> {
        if !self.own_hello_pending {
            return Ok(false);
        }
        let block = if self.ip.is_some() {
            if self.signer.idle() && self.ip.as_ref().is_some_and(|ip| ip.addresses_current()) {
                let bound = Bound::new(self.clock.as_ref(), self.limits.output_lifetime)?;
                if let Some(request) = self.own_hello.request(
                    &mut self.hello_scratch,
                    AbsoluteTime::from_micros(anchor.now),
                )? {
                    bound.check(self.clock.as_ref())?;
                    self.signer.start_hello(
                        request.revision,
                        request.identity,
                        &request.builder,
                        request.expiration,
                        bound.hard,
                    )?;
                    self.own_hello.started(request.revision)?;
                    return Ok(true);
                }
            }
            let Some(block) = self.own_hello.block() else {
                return Ok(false);
            };
            block
        } else {
            // The actual PILS observation remains the source for CORE-only HELLO.
            let bytes = self.signer.announcement().ok_or(Fault::NotReady)?;
            gnunet_wire::official::pils::PeerUpdate::decode(bytes)?.block
        };
        let hello =
            gnunet_hello::Hello::parse_block(block, &mut self.hello_scratch, self.limits.hello)?;
        if Some(*hello.peer().as_bytes()) != self.routing_identity {
            return Err(Error(Arc::new(Cause::Identity)));
        }
        hello.verify_at(
            self.blocks.hello_profile,
            AbsoluteTime::from_micros(anchor.now),
        )?;
        let mut block = discovery::buffer(hello.block_len()?)?;
        hello.encode_block(&mut block)?;
        let mut blocks = BuiltinBlocks {
            context: BlockContext::new(&self.blocks.plugins, self.blocks.group_profile),
            work: BlockWork {
                hello: &mut self.hello_scratch,
                hello_limits: self.limits.hello,
                hello_profile: self.blocks.hello_profile,
                pow: &mut self.pow,
            },
        };
        match self
            .owner
            .as_mut()
            .ok_or(Fault::NotReady)?
            .observe_local_hello(&block, anchor.now, &mut blocks)
        {
            Ok(()) => self.own_hello_pending = false,
            Err(Fault::Capacity | Fault::WouldBlock) => return Ok(false),
            Err(e) => return Err(e.into()),
        }
        Ok(true)
    }
    fn hello_work(&mut self, anchor: Anchor) -> Result<bool, Error> {
        // Cache actual complete verified remote HELLOs without a synthetic PUT
        // client. Failure/backpressure leaves the original candidate pending.
        if let Some(i) = self.discovery.records.iter().position(|r| r.cache_pending) {
            let r = &self.discovery.records[i];
            let mut blocks = BuiltinBlocks {
                context: BlockContext::new(&self.blocks.plugins, self.blocks.group_profile),
                work: BlockWork {
                    hello: &mut self.hello_scratch,
                    hello_limits: self.limits.hello,
                    hello_profile: self.blocks.hello_profile,
                    pow: &mut self.pow,
                },
            };
            match self.owner.as_mut().ok_or(Fault::NotReady)?.observe_hello(
                &r.block,
                anchor.now,
                &mut blocks,
            ) {
                Ok(()) => self.discovery.records[i].cache_pending = false,
                Err(Fault::Capacity | Fault::WouldBlock) => return Ok(false),
                Err(e) => return Err(e.into()),
            }
            return Ok(true);
        }
        let mut frame = None;
        for index in 0..self.peers.len() {
            if !self.peers[index].hello_pending {
                continue;
            }
            if frame.is_none() {
                frame = Some(match self.hello_frame(false, anchor.now) {
                    Ok(frame) => frame,
                    Err(Error(cause))
                        if matches!(cause.as_ref(), Cause::Protocol(Fault::NotReady)) =>
                    {
                        return Ok(false);
                    }
                    Err(error) => return Err(error),
                });
            }
            let bytes = frame.as_ref().ok_or(Fault::Stale)?;
            let native = self.peers[index].native;
            // P2P HELLO omits its public key: the receiver supplies the
            // actual carrier sender identity when verifying purpose7.
            if !self.native_identity_matches(native) {
                continue;
            }
            if !self.frame_fits(native, bytes.len())? {
                self.peers[index].hello_pending = false;
                self.report.record(Cause::Protocol(Fault::TooLarge));
                return Ok(true);
            }
            let bound = Bound::new(self.clock.as_ref(), self.limits.output_lifetime)?;
            if self.send_frame(native, None, bytes, bound)? {
                self.peers[index].hello_pending = false;
                return Ok(true);
            }
        }
        Ok(false)
    }
    fn put_failure(&mut self, actual: network::PutFailure<'id>) -> Event {
        if self.report.first_unrouted_put_failure.is_none() {
            self.report.first_unrouted_put_failure = Some(UnroutedPutFailure {
                put: actual.info.put.diagnostic(),
                client: actual.info.client.diagnostic(),
                accepted: actual.info.accepted,
                expiration: actual.info.expiration,
                until: actual.info.until,
                reason: actual.reason,
            });
        }
        self.error(Provider::Local, Cause::Protocol(actual.reason))
    }
    fn expire_put_native(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        let Some(owner) = self.owner.as_mut() else {
            return Ok(false);
        };
        self.puts.retain(|p| owner.owns_unrouted_put(p.put));
        let Some(index) = self.puts.iter_mut().position(|p| p.bound.poll_native(cx)) else {
            return Ok(false);
        };
        let original = self.puts.remove(index);
        owner.expire_unrouted_put(original.put)?;
        for native in &mut self.jobs {
            if !native.cancelled
                && owner.job_info(native.job).is_some_and(|info| {
                    info.put == Some(original.put) && info.issued && info.retiring
                })
            {
                self.signer.cancel(signer::Target::Path(native.job))?;
                native.cancelled = true;
            }
        }
        self.report.unrouted_puts = owner.put_stats();
        Ok(true)
    }
    /// Register and enforce original native budgets before any canonical sample
    /// or provider poll. Native expiry fences the same operation/source only.
    pub fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Result<Option<Event>, Error> {
        if self.closing {
            return Ok(None);
        }
        if let Some(owner) = self.owner.as_ref() {
            self.jobs.retain(|j| owner.owns_job(j.job));
        }
        if self.expire_put_native(cx)? {
            return Ok(Some(
                self.error(Provider::Local, Cause::Protocol(Fault::Deadline)),
            ));
        }
        if self.neighbours.poll_native_guard(cx) {
            self.report.find_peer_expired = self.report.find_peer_expired.saturating_add(1);
            return Ok(Some(Event::Activity(Provider::Core)));
        }
        if self.initial.as_mut().is_some_and(|b| b.poll_native(cx)) {
            self.begin_close();
            return Err(Fault::Deadline.into());
        }
        if self
            .core
            .as_mut()
            .is_some_and(|source| source.poll_native_guard(cx))
        {
            let source = self.core.as_mut().ok_or(Fault::Stale)?;
            source.retire();
            let event = source.client.reconnect()?;
            self.disconnect_core_peers()?;
            self.core_estimate = None;
            self.update_estimate()?;
            self.close_core_event(event);
            return Ok(Some(
                self.error(Provider::Core, Cause::Protocol(Fault::Deadline)),
            ));
        }
        for i in 0..self.jobs.len() {
            if !self.jobs[i].cancelled && self.jobs[i].bound.poll_native(cx) {
                let job = self.jobs[i].job;
                self.owner
                    .as_mut()
                    .ok_or(Fault::NotReady)?
                    .cancel_job(job)?;
                if self
                    .owner
                    .as_ref()
                    .and_then(|o| o.job_info(job))
                    .is_some_and(|info| info.issued)
                {
                    self.signer.cancel(signer::Target::Path(job))?;
                }
                self.jobs[i].cancelled = true;
                return Ok(Some(
                    self.error(Provider::Core, Cause::Protocol(Fault::Deadline)),
                ));
            }
        }
        if let Some(guard) = self.signer.poll_native_guard(cx) {
            match guard {
                signer::Guard::Cancel(target) => {
                    self.cancel_sign_target(target, false)?;
                    self.signer.cancel(target)?;
                    if let signer::Target::Path(job) = target
                        && let Ok(index) = self
                            .jobs
                            .binary_search_by_key(&job.diagnostic(), |row| row.job.diagnostic())
                        && self.jobs[index].job == job
                    {
                        self.jobs[index].cancelled = true;
                    }
                    return Ok(Some(
                        self.error(Provider::Pils, Cause::Protocol(Fault::Deadline)),
                    ));
                }
                signer::Guard::SourceEnd(target) => {
                    if let Some(target) = target {
                        self.cancel_sign_target(target, false)?;
                        self.cancel_sign_target(target, true)?;
                    }
                    self.begin_close();
                    return Err(Fault::Deadline.into());
                }
                signer::Guard::Retired(target) => {
                    self.cancel_sign_target(target, true)?;
                    self.begin_close();
                    return Err(Fault::Deadline.into());
                }
            }
        }
        for i in 0..self.sends.len() {
            if self.sends[i]
                .payload
                .is_some_and(|(written, total)| written == total)
            {
                continue;
            }
            if !self.sends[i].cancelled && self.sends[i].bound.poll_native(cx) {
                let id = self.sends[i].id;
                let provider = self.sends[i].peer.provider();
                self.sends[i].cancelled = true;
                let until = Instant::now()
                    .checked_add(self.limits.retirement)
                    .ok_or(Fault::Overflow)?;
                self.sends[i].retirement = Some((until, Box::pin(tokio::time::sleep_until(until))));
                match id {
                    NativeSend::Core(id) => {
                        if let Some(completion) =
                            self.core.as_mut().ok_or(Fault::Closed)?.client.cancel(id)?
                        {
                            let send = self.sends.remove(i);
                            self.events.push_back(Event::Send(SendFact {
                                job: send.job.map_or(0, Job::diagnostic),
                                peer: send.peer.identity().0,
                                provider: Provider::Core,
                                outcome: crate::SendOutcome::Core(completion.outcome),
                                written: 0,
                                frame_bytes: completion.source.as_ref().len() + 48,
                            }));
                            drop(completion.source);
                        }
                    }
                    NativeSend::Ip(id) => self.ip.as_mut().ok_or(Fault::Closed)?.cancel(id)?,
                }
                return Ok(Some(self.error(provider, Cause::Protocol(Fault::Deadline))));
            }
            if matches!(self.sends[i].id, NativeSend::Core(_))
                && self
                    .core
                    .as_ref()
                    .is_some_and(|source| !source.phase.retiring())
                && self.sends[i]
                    .retirement
                    .as_mut()
                    .is_some_and(|(hard, alarm)| {
                        Instant::now() >= *hard || alarm.as_mut().poll(cx).is_ready()
                    })
            {
                let source = self.core.as_mut().ok_or(Fault::Stale)?;
                let event = source.client.reconnect()?;
                source.retire();
                self.disconnect_core_peers()?;
                self.core_estimate = None;
                self.update_estimate()?;
                self.close_core_event(event);
                return Ok(Some(
                    self.error(Provider::Core, Cause::Protocol(Fault::Deadline)),
                ));
            }
        }
        for i in 0..self.locals.len() {
            let expired = self.locals[i].as_mut().is_some_and(|p| {
                p.first.as_mut().is_some_and(|b| b.poll_native(cx))
                    || p.input.as_mut().is_some_and(|b| b.poll_native(cx))
                    || p.output.as_mut().is_some_and(|b| b.poll_native(cx))
            });
            if expired {
                self.close_local(i);
                return Ok(Some(
                    self.error(Provider::Local, Cause::Protocol(Fault::Deadline)),
                ));
            }
        }
        if self.discovery.poll_native_guard(cx)? {
            return Ok(Some(
                self.error(Provider::Peerstore, Cause::Protocol(Fault::Deadline)),
            ));
        }
        if let Some(retired) = self
            .transport
            .as_mut()
            .and_then(|transport| transport.poll_native_guard(cx))
        {
            let event = self.error(Provider::Transport, Cause::Protocol(Fault::Deadline));
            self.transport_retired(retired)?;
            self.transport
                .as_mut()
                .ok_or(Fault::Stale)?
                .restart(self.limits.initial)?;
            return Ok(Some(event));
        }
        if let Some(nse) = self.nse.as_mut()
            && let Some(result) = nse.poll_native_guard(cx)
        {
            return Ok(Some(self.nse_event(result?)?));
        }
        if let Some(ip) = self.ip.as_mut()
            && let Some(event) = ip.poll_native_guard(cx)?
        {
            return self.ip_event(event).map(Some);
        }
        Ok(None)
    }
    fn nse_event(&mut self, progress: nse::Progress<'id>) -> Result<Event, Error> {
        Ok(match progress {
            nse::Progress::Estimate(o) => {
                let estimate = o.estimate.log2_size.value();
                gnunet_dht::routing::Estimate::new(estimate)?;
                self.core_estimate = Some(estimate.max(0.5));
                self.update_estimate()?;
                Event::Activity(Provider::Nse)
            }
            nse::Progress::Lost { cause, report } => {
                self.report.nse_start_bytes = report.start_bytes;
                self.report.nse_start_written = report.start_written;
                self.error(Provider::Nse, Cause::Nse(cause))
            }
            nse::Progress::Retry { error, .. } => self.error(Provider::Nse, Cause::Io(error)),
            nse::Progress::Unavailable(error) => {
                if self.ip.is_none() {
                    return Err(error.into());
                }
                self.disable_core()?;
                self.error(Provider::Nse, Cause::Port(error))
            }
            _ => Event::Activity(Provider::Nse),
        })
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        entropy: &mut impl Entropy,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if self.closing {
            return self.poll_close(cx, observe);
        }
        if let Some(event) = self.events.pop_front() {
            observe(event);
            return Poll::Ready(Ok(Progress::Activity));
        }
        if let Some(event) = self.poll_native_guard(cx)? {
            observe(event);
            return Poll::Ready(Ok(Progress::Activity));
        }
        match self.subscription.poll_changed(cx, self.revision) {
            Poll::Ready(r) => {
                self.revision = r?.revision;
            }
            Poll::Pending => {}
        }
        let anchor = self.anchor()?;
        self.prepare_ip_addresses(anchor.now)?;
        if self.expire_put_native(cx)? {
            let event = self.error(Provider::Local, Cause::Protocol(Fault::Deadline));
            observe(event);
            return Poll::Ready(Ok(Progress::Activity));
        }
        if let Some(initial) = self.initial.as_ref() {
            initial.check(self.clock.as_ref())?;
        }
        if let Some(bound) = self.core.as_ref().and_then(|source| source.phase.bound()) {
            bound.check(self.clock.as_ref())?;
        }
        for i in 0..self.locals.len() {
            let expired = self.locals[i].as_ref().is_some_and(|p| {
                p.first.as_ref().is_some_and(|b| anchor.now >= b.until)
                    || p.input.as_ref().is_some_and(|b| anchor.now >= b.until)
                    || p.output.as_ref().is_some_and(|b| anchor.now >= b.until)
            });
            if expired {
                self.close_local(i);
                observe(self.error(Provider::Local, Cause::Protocol(Fault::Deadline)));
                return Poll::Ready(Ok(Progress::Activity));
            }
        }
        self.discovery.expire(anchor.now);
        if let Some(event) = self.discovery.canonical_guard(anchor.now)? {
            let event = self.ps_event(event);
            observe(event);
            return Poll::Ready(Ok(Progress::Activity));
        }
        if let Some(owner) = self.owner.as_mut() {
            let mut blocks = BuiltinBlocks {
                context: BlockContext::new(&self.blocks.plugins, self.blocks.group_profile),
                work: BlockWork {
                    hello: &mut self.hello_scratch,
                    hello_limits: self.limits.hello,
                    hello_profile: self.blocks.hello_profile,
                    pow: &mut self.pow,
                },
            };
            owner.tick(anchor.now, &mut blocks, entropy)?;
            self.sync_jobs(anchor)?;
        }
        if let Some(failure) = self
            .owner
            .as_mut()
            .and_then(NetworkOwner::take_unrouted_failure)
        {
            let event = self.put_failure(failure);
            observe(event);
            return Poll::Ready(Ok(Progress::Activity));
        }
        for offset in 0..12 {
            let class = (self.cursor + offset) % 12;
            let result = match class {
                0 if self
                    .core
                    .as_ref()
                    .is_some_and(|source| !source.phase.ready() || self.owner.is_some()) =>
                {
                    match self
                        .core
                        .as_mut()
                        .ok_or(Fault::Stale)?
                        .client
                        .poll(cx, wait)
                    {
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
                        Poll::Ready(Ok(p)) => {
                            Poll::Ready(self.core_event(p, Some(anchor), entropy))
                        }
                    }
                }
                1 => match self.signer.poll(cx, wait) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
                    Poll::Ready(Ok(event)) => {
                        let event = match event {
                            signer::Event::Identity { identity } => {
                                self.observe_identity(*identity.peer().as_bytes(), anchor)?;
                                if self.signer.announcement().is_some() {
                                    self.hello_refresh = self.ip.is_some();
                                    self.prepare_ip_addresses(anchor.now)?;
                                    for peer in &mut self.peers {
                                        peer.hello_pending = true;
                                    }
                                    self.own_hello_pending = true;
                                    self.report.hello_observations =
                                        self.report.hello_observations.saturating_add(1);
                                }
                                self.ready()?.unwrap_or(Event::Activity(Provider::Pils))
                            }
                            signer::Event::Complete {
                                target,
                                operation,
                                identity,
                                result,
                            } => {
                                let _original_operation = operation;
                                match target {
                                    signer::Target::Path(job) => {
                                        if let Some(cause) = self.complete_path_signature(
                                            job,
                                            identity.peer(),
                                            result,
                                        )? {
                                            let event = self.error(Provider::Pils, cause);
                                            observe(event);
                                            return Poll::Ready(Ok(Progress::Activity));
                                        }
                                    }
                                    signer::Target::OwnHello(revision) => match result {
                                        Ok((peer, signature)) => {
                                            if !self
                                                .ip
                                                .as_ref()
                                                .is_some_and(|ip| ip.addresses_current())
                                            {
                                                self.own_hello.abandon(revision)?;
                                                return Poll::Ready(Ok(Progress::Activity));
                                            }
                                            if self.own_hello.complete(
                                                revision,
                                                identity,
                                                peer,
                                                signature,
                                                AbsoluteTime::from_micros(anchor.now),
                                            )? {
                                                self.own_hello_pending = true;
                                                for peer in &mut self.peers {
                                                    peer.hello_pending = true;
                                                }
                                            }
                                        }
                                        Err(cause) => {
                                            self.own_hello.abandon(revision)?;
                                            let event =
                                                self.error(Provider::Pils, Cause::Signature(cause));
                                            observe(event);
                                            return Poll::Ready(Ok(Progress::Activity));
                                        }
                                    },
                                }
                                Event::Activity(Provider::Pils)
                            }
                            signer::Event::Retired(target) => {
                                self.cancel_sign_target(target, true)?;
                                Event::Activity(Provider::Pils)
                            }
                            signer::Event::Source(pils::Progress::Lost { cause, .. }) => {
                                // A lost signer may retain copied original debt; explicitly
                                // close that source, retire its exact job, then fail this host.
                                let event = self.error(Provider::Pils, Cause::Pils(cause));
                                self.begin_close();
                                event
                            }
                            signer::Event::Source(pils::Progress::ConnectRetry {
                                error, ..
                            }) => self.error(Provider::Pils, Cause::Io(error)),
                            signer::Event::Source(pils::Progress::Unavailable(e)) => {
                                return Poll::Ready(Err(e.into()));
                            }
                            _ => Event::Activity(Provider::Pils),
                        };
                        Poll::Ready(Ok(event))
                    }
                },
                2 if self.nse.is_some() => {
                    match self.nse.as_mut().ok_or(Fault::Stale)?.poll(cx, wait) {
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
                        Poll::Ready(Ok(p)) => Poll::Ready(self.nse_event(p)),
                    }
                }
                3 => match self.discovery.poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Ready(Ok(discovery::Step::Invalid(error))) => {
                        Poll::Ready(Ok(Event::Error {
                            provider: Provider::Peerstore,
                            cause: self.record_error(error),
                        }))
                    }
                    Poll::Ready(Ok(discovery::Step::Observed)) => {
                        self.report.hello_observations =
                            self.report.hello_observations.saturating_add(1);
                        Poll::Ready(Ok(Event::Activity(Provider::Peerstore)))
                    }
                    Poll::Ready(Ok(discovery::Step::Monitor(p) | discovery::Step::Store(p))) => {
                        Poll::Ready(Ok(self.ps_event(p)))
                    }
                },
                4 if self.transport.is_some() => {
                    match self.transport.as_mut().ok_or(Fault::Stale)?.poll(cx) {
                        Poll::Pending => Poll::Pending,
                        Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
                        Poll::Ready(Ok(p)) => {
                            let event = match p {
                                application::Step::Written { epoch, bytes } => {
                                    let _original_bytes = bytes;
                                    self.report.transport_written =
                                        self.report.transport_written.saturating_add(1);
                                    self.preferences.written(epoch)?;
                                    Event::Activity(Provider::Transport)
                                }
                                application::Step::Lost { report, cause } => {
                                    // This original source already closed. A
                                    // later replacement refusal must not erase
                                    // its actual failure or clean EOF fact.
                                    let event = match cause {
                                        Some(e) => self.error(Provider::Transport, Cause::Io(e)),
                                        None => self.error(
                                            Provider::Transport,
                                            Cause::Protocol(Fault::Closed),
                                        ),
                                    };
                                    self.transport_retired(report)?;
                                    self.transport
                                        .as_mut()
                                        .ok_or(Fault::Stale)?
                                        .restart(self.limits.initial)?;
                                    event
                                }
                                application::Step::Retry(e) => {
                                    self.error(Provider::Transport, Cause::Io(e))
                                }
                                application::Step::Attached(epoch) => {
                                    self.preferences.attached(epoch)?;
                                    Event::Activity(Provider::Transport)
                                }
                                application::Step::Activity => Event::Activity(Provider::Transport),
                            };
                            Poll::Ready(Ok(event))
                        }
                    }
                }
                5 if self.owner.is_some() => self.local_poll(cx, anchor, entropy),
                6 => self.accept(cx, listeners),
                7 if self.owner.is_some() => {
                    if self.local_output()? {
                        Poll::Ready(Ok(Event::Activity(Provider::Local)))
                    } else {
                        Poll::Pending
                    }
                }
                8 if self.owner.is_some() => {
                    if self.work()? {
                        Poll::Ready(Ok(Event::Activity(Provider::Core)))
                    } else {
                        Poll::Pending
                    }
                }
                9 if self.owner.is_some() => {
                    if self.local_hello_work(anchor)?
                        || self.hints(anchor)?
                        || self.hello_work(anchor)?
                    {
                        Poll::Ready(Ok(Event::Activity(Provider::Transport)))
                    } else {
                        Poll::Pending
                    }
                }
                10 if self.owner.is_some() => {
                    let mut blocks = BuiltinBlocks {
                        context: BlockContext::new(&self.blocks.plugins, self.blocks.group_profile),
                        work: BlockWork {
                            hello: &mut self.hello_scratch,
                            hello_limits: self.limits.hello,
                            hello_profile: self.blocks.hello_profile,
                            pow: &mut self.pow,
                        },
                    };
                    let step = self.neighbours.step(
                        self.owner.as_mut().ok_or(Fault::NotReady)?,
                        self.clock.as_ref(),
                        &self.limits,
                        anchor.now,
                        &mut blocks,
                        entropy,
                    )?;
                    // A newly created alarm must register this original task
                    // even if a fully unadmitted round encounters backpressure
                    // and every native source is otherwise Pending this turn.
                    if self.neighbours.poll_native_guard(cx) {
                        self.report.find_peer_expired =
                            self.report.find_peer_expired.saturating_add(1);
                    }
                    match step {
                        neighbours::Step::Idle => Poll::Pending,
                        neighbours::Step::Expired => {
                            self.report.find_peer_expired =
                                self.report.find_peer_expired.saturating_add(1);
                            Poll::Ready(Ok(Event::Activity(Provider::Core)))
                        }
                        neighbours::Step::Skipped => {
                            Poll::Ready(Ok(Event::Activity(Provider::Core)))
                        }
                        neighbours::Step::Prepared {
                            frames,
                            anchor: original,
                        } => {
                            self.sync_jobs(original)?;
                            self.report.find_peer_rounds =
                                self.report.find_peer_rounds.saturating_add(1);
                            self.report.find_peer_prepared =
                                self.report.find_peer_prepared.saturating_add(frames as u64);
                            Poll::Ready(Ok(Event::Activity(Provider::Core)))
                        }
                    }
                }
                11 if self.owner.is_some() => self.poll_ip(cx, anchor, entropy),
                _ => Poll::Pending,
            };
            if let Poll::Ready(result) = result {
                self.cursor = (class + 1) % 12;
                let event = result?;
                let progress = if matches!(event, Event::Ready { .. }) {
                    Progress::Ready
                } else {
                    Progress::Activity
                };
                observe(event);
                return Poll::Ready(Ok(progress));
            }
        }
        let mut due = wait;
        if let Some(target) = self.owner.as_ref().and_then(NetworkOwner::next_wakeup) {
            let native = anchor
                .native
                .checked_add(std::time::Duration::from_micros(
                    target.saturating_sub(anchor.now),
                ))
                .ok_or(Fault::Overflow)?;
            due = Some(due.map_or(native, |old| old.min(native)));
        }
        if let Some(due) = due {
            self.timer.as_mut().reset(due);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        Poll::Pending
    }
    /// One fair bounded turn; an observable event ends the turn so a permanent
    /// selected Logger failure gates the next provider/effect in the caller.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        entropy: &mut impl Entropy,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<Progress, Error>> {
        if self.yield_due {
            self.yield_due = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        let result = self.poll_inner(cx, listeners, wait, entropy, observe);
        if result.is_ready() {
            self.yield_due = true;
        }
        if let Poll::Ready(Err(e)) = &result {
            self.record_error(e.clone());
            self.begin_close();
        }
        result
    }
    /// Retain this exact owner across scheduler waits; dropping only this future
    /// never replaces/cancels its original provider sources or immutable frames.
    pub async fn drive(
        &mut self,
        listeners: &[Listener<'_>],
        wait: Option<Instant>,
        entropy: &mut impl Entropy,
        mut observe: impl FnMut(Event),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, listeners, wait, entropy, &mut observe)).await
    }
}
fn reserve<T>(n: usize) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    v.try_reserve_exact(n).map_err(|_| Fault::Capacity)?;
    Ok(v)
}

fn transport_bounds(bound: Bound) -> application::Bounds {
    application::Bounds {
        expires: bound.until,
        hard: bound.hard.into_std(),
    }
}

impl Drop for Server<'_> {
    fn drop(&mut self) {
        self.begin_close();
    }
}
