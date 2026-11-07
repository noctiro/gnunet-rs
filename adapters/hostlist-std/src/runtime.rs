//! Caller-driven production composition. No global tasks, default DNS, private
//! protocol, replayed mutation, synthetic store result or inferred peer connection.
use crate::{
    Core, Durable, DurableEvent, Error, Fault, Fetch, HelloFrame, Job, Uri,
    gate::Gate,
    http::{DownloadJob, HttpLimits, Proxy, Tls, WireReport},
    peerstore::{AddStatus, PeerstoreEvent, Port},
    publication::{PublicationLimits, Publisher},
    server::{HttpEvent, Server},
    statistics::{Metric, Statistics, StatisticsEvent},
};
use gnunet_client_host::{EndpointSource, resolution::SharedResolution};
use gnunet_core_client_host as core;
use gnunet_peerstore_client_host as ps;
use gnunet_service_runtime::clock::RuntimeClock;
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    net::TcpListener,
    time::{Instant, Sleep},
};
use zeroize::Zeroizing;
const TYPES: [u16; 1] = [160];
const AD_PRIORITY: u32 = 16 | 64; // Actual public GNUNET_MQ_PREF_UNRELIABLE|CORK_ALLOWED.
/// Caller-owned stable native allocation domains; never leaked or self-referential.
pub struct Instances<'id> {
    /// CORE application source.
    pub core: &'id mut core::Instance,
    /// General PEERSTORE source.
    pub peerstore: &'id mut ps::Instance,
    /// Dedicated monitor source.
    pub monitor: &'id mut ps::Instance,
}
/// Explicit source selectors, fixed together from one live config revision.
pub struct Sources {
    /// Actual CORE service.
    pub core: EndpointSource,
    /// Actual PEERSTORE service.
    pub peerstore: EndpointSource,
    /// Actual STATISTICS service.
    pub statistics: EndpointSource,
}
/// Native caller input; binding and TLS config creation are explicit foreground effects.
pub struct Options {
    /// Actual bound public listeners (none for client-only mode).
    pub listeners: Vec<TcpListener>,
    /// Explicit configured external claim, never reachability proof.
    pub advertised: Option<Uri>,
    /// Caller-owned verified TLS configuration.
    pub tls: Tls,
    /// Explicit proxy only; environment proxies are never consulted.
    pub proxy: Option<Arc<Proxy>>,
}
/// Native memory/work/time profile. Pure state limits belong to the supplied Core.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum tracked non-self CORE links (at most 63).
    pub peers: usize,
    /// Exact original HELLO parsing capacities.
    pub hello: gnunet_hello::Limits,
    /// Actual selected official signature profile.
    pub profile: gnunet_hello::SignatureProfile,
    /// Native CORE class enum order.
    pub core_order: core::ClassOrder,
    /// Mature HTTP transport/work bounds.
    pub http: HttpLimits,
    /// Current/historical publication body bounds.
    pub publication: PublicationLimits,
    /// Maximum active accepted HTTP sources.
    pub connections: usize,
    /// Maximum accepted sources per actual IP.
    pub per_ip: usize,
    /// Original individual HTTP source lifetime.
    pub http_lifetime: Duration,
    /// Original general metadata/provider operation bound.
    pub operation: Duration,
    /// Original partial cancellation drain bound.
    pub grace: Duration,
    /// Finite original daemon intent; fresh restart is explicit.
    pub lifetime: Duration,
    /// Native scheduler/temporary-capacity wake interval.
    pub tick: Duration,
    /// Batching interval for actual publication rebuilds.
    pub rebuild: Duration,
    /// Actual learned-metadata checkpoint interval.
    pub save_interval: Duration,
    /// Maximum native IPC syscall slice bytes.
    pub io_slice: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            peers: 63,
            hello: gnunet_hello::Limits {
                maximum_input_bytes: 65535,
                maximum_address_bytes: 65535,
                maximum_addresses: 256,
            },
            profile: gnunet_hello::SignatureProfile::Gnunet029,
            core_order: if cfg!(target_endian = "little") {
                core::ClassOrder::Little
            } else {
                core::ClassOrder::Big
            },
            http: HttpLimits::default(),
            publication: PublicationLimits::default(),
            connections: 64,
            per_ip: 32,
            http_lifetime: Duration::from_secs(60),
            operation: Duration::from_secs(60),
            grace: Duration::from_secs(5),
            lifetime: Duration::from_secs(8 * 3600),
            tick: Duration::from_millis(100),
            rebuild: Duration::from_secs(1),
            save_interval: Duration::from_secs(1800),
            io_slice: 65535,
        }
    }
}
/// Actual original CORE advertisement provenance, retained as history rather than
/// reassigned to a new connection when a download outlives that peer generation.
#[derive(Clone, Copy, Debug)]
pub struct AdOrigin<'id> {
    /// Actual original CORE MQ.
    pub epoch: core::ConnectionEpoch<'id>,
    /// Actual original current peer token.
    pub peer: core::Peer<'id>,
}
/// Actual bounded foreground observations. URI/authentication bytes are not printed.
#[derive(Debug)]
pub enum Event<'id> {
    /// Actual CORE init reply and public local identity.
    CoreReady {
        /// Actual original source.
        epoch: core::ConnectionEpoch<'id>,
        /// Actual local token.
        local: core::Peer<'id>,
    },
    /// Actual remote link up/down.
    Peer {
        /// Original token.
        peer: core::Peer<'id>,
        /// Actual notification direction.
        connected: bool,
    },
    /// Actual CORE source loss.
    CoreLost {
        /// Original source.
        epoch: core::ConnectionEpoch<'id>,
        /// Original actual cause.
        cause: core::LossCause,
    },
    /// Actual untrusted input rejection.
    AdvertisementRejected {
        /// Original source.
        epoch: core::ConnectionEpoch<'id>,
        /// Finite classification.
        reason: Fault,
    },
    /// Actual original advertisement queue admission.
    AdvertisementQueued {
        /// Original source.
        epoch: core::ConnectionEpoch<'id>,
        /// Original current peer.
        peer: core::Peer<'id>,
        /// Original immutable send.
        send: core::SendId<'id>,
    },
    /// Actual whole/partial original CORE send outcome.
    AdvertisementFinished {
        /// Actual original source.
        epoch: core::ConnectionEpoch<'id>,
        /// Actual original peer.
        peer: core::Peer<'id>,
        /// Original send.
        send: core::SendId<'id>,
        /// Exact physical payload state, including prefix bytes.
        payload: core::PayloadState<'id>,
        /// Actual local outcome, never remote ACK.
        outcome: core::SendOutcome,
    },
    /// Actual cancellation before any payload exposure.
    AdvertisementCancelled {
        /// Original send.
        send: core::SendId<'id>,
        /// Exact local outcome.
        outcome: core::SendOutcome,
    },
    /// Actual original native attempt failure.
    CoreRetry(std::io::Error),
    /// Actual local HTTP provider admission, no network ACK.
    DownloadQueued {
        /// Original fresh job.
        job: Job,
        /// Actual original CORE origin when this is a newly advertised test.
        origin: Option<AdOrigin<'id>>,
    },
    /// Actual bounded complete HTTP body received.
    DownloadBody {
        /// Original job.
        job: Job,
        /// Actual status.
        status: u16,
        /// Actual complete body bytes.
        bytes: usize,
        /// Actual wire counters.
        wire: WireReport,
    },
    /// Actual original nonfatal native connection setup warning.
    SocketDiagnostic {
        /// Original HTTP job.
        job: Job,
        /// Actual probe-correlated native warning.
        diagnostic: crate::http::SocketDiagnostic,
    },
    /// Actual bounded downloaded HELLO rejection; raw bytes are never printed.
    HelloRejected {
        /// Original HTTP job.
        job: Job,
        /// Original frame index.
        index: u32,
        /// Actual parser/signature/expiry/capacity cause.
        reason: Fault,
    },
    /// Actual original round observations and errors.
    DownloadFinished {
        /// Original job.
        job: Job,
        /// Original actual CORE origin, if applicable.
        origin: Option<AdOrigin<'id>>,
        /// Actual verification/storage observations.
        outcome: crate::DownloadOutcome,
        /// Actual wire exposure.
        wire: WireReport,
        /// Actual error or finite local cancellation.
        failure: Option<Error>,
    },
    /// Actual PEERSTORE source/result.
    Peerstore(PeerstoreEvent<'id>),
    /// Actual public HTTP source.
    Http(HttpEvent),
    /// Actual STATISTICS local action.
    Statistics(StatisticsEvent),
    /// Actual original snapshot worker receipt.
    Durable(DurableEvent),
    /// Explicit finite source/capacity pressure.
    Capacity(&'static str),
    /// Independent cleanup error alongside original cause.
    Cleanup(&'static str, Error),
}
/// Foreground progress, with no fabricated completion for a result-less stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Progress {
    /// Actual bounded action or state transition.
    Activity,
    /// Caller-native wait ended; original owners remain intact.
    WaitDeadline,
    /// All network owners are physically stopped; durable join is separate.
    Stopped,
}
struct Link<'id> {
    peer: core::Peer<'id>,
    attempted: bool,
}
struct Send<'id> {
    send: core::SendId<'id>,
    hard: Instant,
    drain: Option<Instant>,
}
struct Round<'id> {
    fetch: Fetch,
    origin: Option<AdOrigin<'id>>,
    hard: Instant,
    network: Option<DownloadJob>,
    body: Option<Zeroizing<Vec<u8>>>,
    offset: usize,
    index: u32,
    waiting: bool,
    pending: Option<HelloFrame>,
    outcome: crate::DownloadOutcome,
    failure: Option<Error>,
    wire: WireReport,
    retiring: bool,
}
/// Actual production composition; caller owns and polls the shared Resolver driver.
pub struct Runtime<'id> {
    core: Core,
    client: core::Client<'id>,
    port: Port<'id>,
    stats: Statistics,
    publisher: Publisher,
    server: Option<Server>,
    durable: Option<Durable>,
    resolution: SharedResolution,
    tls: Tls,
    proxy: Option<Arc<Proxy>>,
    advertised: Option<Uri>,
    clock: Arc<dyn RuntimeClock>,
    gate: Gate,
    limits: Limits,
    links: Vec<Link<'id>>,
    sends: Vec<Send<'id>>,
    epoch: Option<core::ConnectionEpoch<'id>>,
    local: Option<core::PeerId>,
    ready: bool,
    candidate_origin: Option<AdOrigin<'id>>,
    round: Option<Round<'id>>,
    scratch: Vec<u8>,
    rebuild_at: u64,
    save_at: Instant,
    pause: Option<Instant>,
    alarm: Option<Pin<Box<Sleep>>>,
    wait: Option<Pin<Box<Sleep>>>,
    turn: usize,
    stopping: bool,
    closed: bool,
    yield_due: bool,
}
fn micros(duration: Duration) -> Result<u64, Error> {
    u64::try_from(duration.as_micros()).map_err(|_| Fault::Overflow.into())
}
fn temporary(error: &Error) -> bool {
    matches!(
        error,
        Error::Fault(Fault::Capacity | Fault::WouldBlock | Fault::NotReady)
            | Error::Native(gnunet_client_host::ConnectError::Protocol(
                Fault::Capacity | Fault::WouldBlock | Fault::NotReady
            ))
    )
}
impl<'id> Runtime<'id> {
    /// Fix every source selector before any admission. Instances/pools remain in
    /// the outer caller; all actual sockets and immutable queues stay in owners.
    pub fn new(
        instances: Instances<'id>,
        sources: Sources,
        resolution: SharedResolution,
        core: Core,
        options: Options,
        limits: Limits,
        durable: Option<Durable>,
    ) -> Result<Self, Error> {
        let native_start = Instant::now();
        limits.http.validate()?;
        if limits.http.body_bytes > core.body_limit() {
            return Err(Fault::Capacity.into());
        }
        if limits.peers == 0
            || limits.peers > 63
            || limits.tick.is_zero()
            || limits.grace.is_zero()
            || limits.lifetime.is_zero()
            || limits.operation.is_zero()
            || limits.save_interval.is_zero()
            || limits.io_slice == 0
        {
            return Err(Fault::InvalidInput.into());
        }
        let [core_source, peer_source, statistics_source] =
            EndpointSource::snapshot_all([&sources.core, &sources.peerstore, &sources.statistics])?;
        let clock = resolution.clock();
        for source in [&core_source, &peer_source, &statistics_source] {
            if !Arc::ptr_eq(&clock, &source.clock()) {
                return Err(Fault::Conflict.into());
            }
        }
        let now = clock.sample().map_err(Error::Clock)?.now.as_micros();
        let until = now
            .checked_add(micros(limits.lifetime)?)
            .filter(|n| *n < u64::MAX)
            .ok_or(Fault::Overflow)?;
        let mut gate = Gate::new(clock.clone(), until)?;
        gate.hard = gate.hard.min(
            native_start
                .checked_add(limits.lifetime)
                .ok_or(Fault::Overflow)?,
        );
        let modes = core.modes();
        if modes.provide && options.listeners.is_empty()
            || !modes.provide && !options.listeners.is_empty()
        {
            return Err(Fault::InvalidInput.into());
        }
        if let Some(uri) = &options.advertised {
            crate::http::validate_uri(uri.bytes())?;
        }
        let mut links = Vec::new();
        links
            .try_reserve_exact(limits.peers)
            .map_err(|_| Fault::Capacity)?;
        let mut sends = Vec::new();
        sends.try_reserve_exact(32).map_err(|_| Fault::Capacity)?;
        let mut scratch = Vec::new();
        scratch
            .try_reserve_exact(limits.hello.maximum_address_bytes)
            .map_err(|_| Fault::Capacity)?;
        scratch.resize(limits.hello.maximum_address_bytes, 0);
        let client = core::Client::new(
            instances.core,
            core_source,
            limits.core_order,
            0,
            if modes.learning { &TYPES } else { &[] },
            core::Limits {
                sends: 32,
                source_bytes: 65535,
                frame_bytes: 65535,
                output: gnunet_service_runtime::framing::Budget {
                    frames: 64,
                    bytes: 64 * 65535,
                },
                io_slice_bytes: limits.io_slice,
            },
        )?;
        let native = ps::Limits {
            operations: 1,
            source_bytes: 2 * 65535,
            output: gnunet_service_runtime::framing::Budget {
                frames: 4,
                bytes: 4 * 65535,
            },
            io_slice_bytes: limits.io_slice,
            retirement_grace_micros: micros(limits.grace)?,
            ..Default::default()
        };
        let mut port = Port::new(
            instances.peerstore,
            instances.monitor,
            peer_source,
            crate::peerstore::Options {
                native,
                hello_limits: limits.hello,
                profile: limits.profile,
                grace: limits.grace,
                retry: limits.tick,
            },
        )?;
        if modes.provide {
            port.start_monitor(until)?
        }
        let publisher = Publisher::new(limits.publication)?;
        let server = if modes.provide {
            Some(Server::new(
                options.listeners,
                publisher.view.clone(),
                clock.clone(),
                crate::server::Options {
                    limits: limits.http,
                    connections: limits.connections,
                    per_ip: limits.per_ip,
                    lifetime: limits.http_lifetime,
                },
                (until, gate.hard),
            )?)
        } else {
            None
        };
        let stats = Statistics::new(
            statistics_source,
            until,
            gate.hard,
            limits.operation,
            limits.io_slice,
        )?;
        let save_at = native_start
            .checked_add(limits.save_interval)
            .ok_or(Fault::Overflow)?;
        Ok(Self {
            core,
            client,
            port,
            stats,
            publisher,
            server,
            durable,
            resolution,
            tls: options.tls,
            proxy: options.proxy,
            advertised: options.advertised,
            clock,
            gate,
            limits,
            links,
            sends,
            epoch: None,
            local: None,
            ready: false,
            candidate_origin: None,
            round: None,
            scratch,
            rebuild_at: now,
            save_at,
            pause: None,
            alarm: None,
            wait: None,
            turn: 0,
            stopping: false,
            closed: false,
            yield_due: false,
        })
    }
    /// The same original operation clock used by the shared Resolver and MQs.
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Read-only actual pure state; mutating the native owner is caller-driven.
    pub fn core(&self) -> &Core {
        &self.core
    }
    /// Whether an actual original qualified worker is retained for final join.
    pub fn has_durable(&self) -> bool {
        self.durable.is_some()
    }
    /// Actual readiness observations, not a bootstrap/transport-connectivity claim.
    pub fn readiness(&self) -> Readiness {
        Readiness {
            core: self.ready,
            peerstore: self.port.connected(),
            monitor: !self.core.modes().provide || self.port.synced(),
            http_listeners: self.server.as_ref().map_or(0, Server::listeners),
        }
    }
    fn ps_event(
        round: &mut Option<Round<'id>>,
        stats: &mut Statistics,
        event: PeerstoreEvent<'id>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        if let PeerstoreEvent::Add(completion) = &event {
            let round = round.as_mut().ok_or(Fault::Stale)?;
            if round.fetch.job != completion.job
                || round.index != completion.index
                || !round.waiting
            {
                return Err(Fault::Stale.into());
            }
            round.waiting = false;
            round.index = round.index.checked_add(1).ok_or(Fault::Overflow)?;
            match completion.status {
                AddStatus::Store(1) => {
                    round.outcome.stored = round.outcome.stored.saturating_add(1);
                    stats.add(Metric::Stored, 1)
                }
                AddStatus::ExistingNewer(_) => {
                    round.outcome.existing_newer = round.outcome.existing_newer.saturating_add(1)
                }
                _ => round.outcome.indeterminate = round.outcome.indeterminate.saturating_add(1),
            }
        }
        observe(Event::Peerstore(event));
        Ok(())
    }
    fn expire(
        &mut self,
        now: Option<u64>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        let mut fault = None;
        {
            let round = &mut self.round;
            let stats = &mut self.stats;
            self.port.expire(now, &mut |event| {
                if let Err(error) = Self::ps_event(round, stats, event, observe) {
                    fault = Some(error)
                }
            })?;
        }
        if let Some(error) = fault {
            return Err(error);
        }
        if let Some(round) = &mut self.round
            && (!round.retiring
                && (Instant::now() >= round.hard || now.is_some_and(|n| n >= round.fetch.until)))
        {
            if let Some(network) = &mut round.network {
                round.wire = network.wire();
                network.cancel();
                match network.take_diagnostics() {
                    Ok(list) => {
                        for diagnostic in list {
                            observe(Event::SocketDiagnostic {
                                job: round.fetch.job.clone(),
                                diagnostic,
                            })
                        }
                    }
                    Err(cleanup) => observe(Event::Cleanup("HTTP native diagnostics", cleanup)),
                }
            }
            round.network = None;
            round.body = None;
            round.pending = None;
            round.retiring = true;
            round.outcome.complete = false;
            if round.failure.is_none() {
                round.failure = Some(Fault::Deadline.into())
            }
        }
        if self
            .round
            .as_ref()
            .is_some_and(|r| r.retiring && !r.waiting)
        {
            let round = self.round.take().ok_or(Fault::Stale)?;
            self.core.retire_without_time(&round.fetch.job)?;
            self.stats.add(Metric::Failures, 1);
            observe(Event::DownloadFinished {
                job: round.fetch.job,
                origin: round.origin,
                outcome: round.outcome,
                wire: round.wire,
                failure: round.failure,
            });
        }
        let mut index = 0;
        while index < self.sends.len() {
            if self.sends[index].drain.is_some_and(|d| Instant::now() >= d) {
                return Err(Fault::Deadline.into());
            }
            if self.sends[index].drain.is_none() && Instant::now() >= self.sends[index].hard {
                let send = self.sends[index].send;
                match self.client.cancel(send) {
                    Ok(Some(completion)) => {
                        observe(Event::AdvertisementCancelled {
                            send,
                            outcome: completion.outcome,
                        });
                        self.sends.swap_remove(index);
                        continue;
                    }
                    Ok(None)
                    | Err(gnunet_client_host::ConnectError::Protocol(
                        Fault::Stale | Fault::StaleGeneration,
                    )) => {
                        self.sends[index].drain = Some(
                            Instant::now()
                                .min(self.sends[index].hard)
                                .checked_add(self.limits.grace)
                                .ok_or(Fault::Overflow)?,
                        )
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            index += 1;
        }
        Ok(())
    }
    fn core_event(
        &mut self,
        event: core::Progress<'id>,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        match event {
            core::Progress::Connected(epoch) => {
                self.epoch = Some(epoch);
                self.ready = false;
                self.links.clear();
                self.stats.set(Metric::Connections, 0)
            }
            core::Progress::Inbound { epoch, event } => {
                if Some(epoch) != self.epoch {
                    return Err(Fault::Stale.into());
                }
                match event {
                    core::Inbound::Ready { local, .. } => {
                        self.ready = true;
                        self.local = Some(local.identity());
                        observe(Event::CoreReady { epoch, local })
                    }
                    core::Inbound::Connected(peer) => {
                        if Some(peer.identity()) != self.local
                            && !self.links.iter().any(|l| l.peer == peer)
                        {
                            if self.links.len() >= self.limits.peers {
                                observe(Event::Capacity("CORE links"))
                            } else {
                                self.links.push(Link {
                                    peer,
                                    attempted: false,
                                });
                                self.stats.set(Metric::Connections, self.links.len() as u64);
                                observe(Event::Peer {
                                    peer,
                                    connected: true,
                                })
                            }
                        }
                    }
                    core::Inbound::Disconnected(peer) => {
                        self.links.retain(|l| l.peer != peer);
                        self.stats.set(Metric::Connections, self.links.len() as u64);
                        observe(Event::Peer {
                            peer,
                            connected: false,
                        })
                    }
                    core::Inbound::Traffic {
                        peer,
                        connection: Some(connection),
                        direction: core::Direction::Inbound,
                        traffic: core::OwnedTraffic::Full(message),
                    } if !self.stopping && self.core.modes().learning => {
                        if Some(peer) == self.local || self.client.peer(peer) != Some(connection) {
                            observe(Event::AdvertisementRejected {
                                epoch,
                                reason: Fault::Stale,
                            });
                            return Ok(());
                        }
                        let advertisement =
                            match gnunet_hostlist::Advertisement::decode(message.as_ref()) {
                                Ok(ad) => ad,
                                Err(reason) => {
                                    observe(Event::AdvertisementRejected { epoch, reason });
                                    return Ok(());
                                }
                            };
                        let parsed = match crate::http::validate_uri(advertisement.uri()) {
                            Ok(url) => url,
                            Err(_) => {
                                observe(Event::AdvertisementRejected {
                                    epoch,
                                    reason: Fault::InvalidInput,
                                });
                                return Ok(());
                            }
                        };
                        let persist = parsed.username().is_empty() && parsed.password().is_none();
                        let uri = Uri::copy_from(advertisement.uri())?;
                        let origin = AdOrigin {
                            epoch,
                            peer: connection,
                        };
                        if self.core.advertise(
                            uri,
                            gnunet_hostlist::Advertiser {
                                source: epoch.value(),
                                peer: peer.0,
                            },
                            persist,
                            now,
                        )? {
                            self.candidate_origin = Some(origin)
                        }
                    }
                    _ => {}
                }
            }
            core::Progress::Finished {
                epoch,
                peer,
                send,
                payload,
                completion,
            } => {
                if let Some(index) = self.sends.iter().position(|p| p.send == send) {
                    self.sends.swap_remove(index);
                }
                if completion.outcome == core::SendOutcome::Written {
                    self.stats.add(Metric::Advertisements, 1)
                }
                observe(Event::AdvertisementFinished {
                    epoch,
                    peer,
                    send,
                    payload,
                    outcome: completion.outcome,
                });
            }
            core::Progress::Lost { epoch, cause } => {
                self.ready = false;
                self.epoch = None;
                self.links.clear();
                self.stats.set(Metric::Connections, 0);
                observe(Event::CoreLost { epoch, cause })
            }
            core::Progress::PeerLost { peer, .. } => {
                self.links.retain(|l| l.peer != peer);
                self.stats.set(Metric::Connections, self.links.len() as u64)
            }
            core::Progress::Capacity(_) => {
                self.pause = Some(
                    Instant::now()
                        .checked_add(self.limits.tick)
                        .ok_or(Fault::Overflow)?,
                );
                observe(Event::Capacity("CORE original full input"))
            }
            core::Progress::ConnectRetry { error, .. } => observe(Event::CoreRetry(error)),
            core::Progress::Unavailable(error) => return Err(error.into()),
            _ => {}
        }
        Ok(())
    }
    fn prepare(&mut self, now: u64, observe: &mut impl FnMut(Event<'id>)) -> Result<bool, Error> {
        if self.core.expire(now)? {
            self.rebuild_at = now;
        }
        if self.core.modes().provide
            && self.port.synced()
            && now >= self.rebuild_at
            && self.publisher.revision() != Some(self.core.revision())
        {
            match self.publisher.publish(&self.core, now) {
                Ok(true) => {
                    self.rebuild_at = now.saturating_add(micros(self.limits.rebuild)?);
                    let bytes = self
                        .publisher
                        .view
                        .borrow()
                        .as_ref()
                        .map_or(0, |p| p.binary.len());
                    self.stats.set(Metric::PublishedBytes, bytes as u64);
                    return Ok(true);
                }
                Ok(false) => {}
                Err(error) if temporary(&error) => {
                    observe(Event::Capacity("retained historical HTTP publications"));
                    self.rebuild_at = now.saturating_add(micros(self.limits.tick)?);
                }
                Err(error) => return Err(error),
            }
        }
        if self.stopping {
            return Ok(false);
        }
        if self.core.modes().provide {
            self.port.start_monitor(self.gate.until)?;
        }
        if self.core.modes().advertise
            && self.server.as_ref().is_some_and(|s| s.listeners() != 0)
            && self.publisher.view.borrow().is_some()
            && self.sends.len() < 32
            && self.ready
            && let Some(index) = self.links.iter().position(|l| !l.attempted)
            && let Some(uri) = &self.advertised
        {
            let peer = self.links[index].peer;
            if self.client.peer(peer.identity()) != Some(peer) {
                self.links[index].attempted = true;
                return Ok(true);
            }
            let ad = gnunet_hostlist::Advertisement::new(uri.bytes())?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(ad.encoded_len()?)
                .map_err(|_| Fault::Capacity)?;
            bytes.resize(ad.encoded_len()?, 0);
            ad.encode(&mut bytes)?;
            let duration = Duration::from_secs(300);
            let hard = Instant::now()
                .checked_add(duration)
                .ok_or(Fault::Overflow)?
                .min(self.gate.hard);
            let until = now.saturating_add(300_000_000).min(self.gate.until);
            match self.client.send(
                peer,
                AD_PRIORITY,
                until,
                core::Message::try_from_owned(bytes).map_err(|e| e.reason)?,
            ) {
                Ok(send) => {
                    let epoch = self.epoch.ok_or(Fault::Stale)?;
                    self.links[index].attempted = true;
                    self.sends.push(Send {
                        send,
                        hard,
                        drain: None,
                    });
                    observe(Event::AdvertisementQueued { epoch, peer, send });
                    return Ok(true);
                }
                Err(rejected)
                    if matches!(
                        rejected.reason,
                        Fault::Capacity | Fault::WouldBlock | Fault::NotReady
                    ) => {}
                Err(rejected) => return Err(rejected.reason.into()),
            }
        }
        if self.round.is_none() {
            let hard = Instant::now()
                .checked_add(self.limits.operation)
                .ok_or(Fault::Overflow)?
                .min(self.gate.hard);
            if let Some(fetch) = self.core.next(now, self.links.len(), self.gate.until)? {
                let origin = if fetch.advertiser.is_some() {
                    self.candidate_origin
                } else {
                    None
                };
                match DownloadJob::new(
                    fetch.clone(),
                    self.resolution.clone(),
                    self.tls.clone(),
                    self.proxy.clone(),
                    self.limits.http,
                    hard,
                ) {
                    Ok(network) => {
                        if fetch.advertiser.is_some() {
                            self.candidate_origin = None;
                        }
                        let hard = network.hard_deadline();
                        self.stats.add(Metric::Downloads, 1);
                        observe(Event::DownloadQueued {
                            job: fetch.job.clone(),
                            origin,
                        });
                        self.round = Some(Round {
                            fetch,
                            origin,
                            hard,
                            network: Some(network),
                            body: None,
                            offset: 0,
                            index: 0,
                            waiting: false,
                            pending: None,
                            outcome: Default::default(),
                            failure: None,
                            wire: Default::default(),
                            retiring: false,
                        });
                        return Ok(true);
                    }
                    Err(error) if temporary(&error) => {
                        self.core.abandon(&fetch.job)?;
                        self.pause = Some(
                            Instant::now()
                                .checked_add(self.limits.tick)
                                .ok_or(Fault::Overflow)?,
                        );
                        observe(Event::Capacity("HTTP original admission"));
                    }
                    Err(error) => {
                        self.core.abandon(&fetch.job)?;
                        return Err(error);
                    }
                }
            }
        }
        self.stats
            .set(Metric::RetryMillis, self.core.retry_delay() / 1000);
        self.stats
            .set(Metric::Learned, self.core.learned().count() as u64);
        if Instant::now() >= self.save_at
            && let Some(durable) = &mut self.durable
        {
            if durable.save(&self.core, false, &mut |event| {
                observe(Event::Durable(event))
            })? {
                self.save_at = Instant::now()
                    .checked_add(self.limits.save_interval)
                    .ok_or(Fault::Overflow)?;
                return Ok(true);
            }
            self.save_at = Instant::now()
                .checked_add(self.limits.tick)
                .ok_or(Fault::Overflow)?;
        }
        Ok(false)
    }
    fn download(
        &mut self,
        cx: &mut Context<'_>,
        now: u64,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<(), Error>> {
        let Some(round) = &mut self.round else {
            return Poll::Pending;
        };
        if let Some(network) = &mut round.network {
            match network.poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(download)) => {
                    for diagnostic in download.diagnostics {
                        observe(Event::SocketDiagnostic {
                            job: round.fetch.job.clone(),
                            diagnostic,
                        })
                    }
                    round.wire = download.wire;
                    self.stats.add(Metric::Bytes, download.body.len() as u64);
                    observe(Event::DownloadBody {
                        job: round.fetch.job.clone(),
                        status: download.status,
                        bytes: download.body.len(),
                        wire: download.wire,
                    });
                    round.body = Some(download.body);
                    round.network = None;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Err(Error::Clock(error))) => {
                    match network.take_diagnostics() {
                        Ok(list) => {
                            for diagnostic in list {
                                observe(Event::SocketDiagnostic {
                                    job: round.fetch.job.clone(),
                                    diagnostic,
                                })
                            }
                        }
                        Err(cleanup) => observe(Event::Cleanup("HTTP native diagnostics", cleanup)),
                    }
                    return Poll::Ready(Err(Error::Clock(error)));
                }
                Poll::Ready(Err(error)) => {
                    round.wire = network.wire();
                    match network.take_diagnostics() {
                        Ok(list) => {
                            for diagnostic in list {
                                observe(Event::SocketDiagnostic {
                                    job: round.fetch.job.clone(),
                                    diagnostic,
                                })
                            }
                        }
                        Err(cleanup) => observe(Event::Cleanup("HTTP native diagnostics", cleanup)),
                    }
                    round.network = None;
                    round.failure = Some(error);
                    round.body = None;
                }
            }
        }
        if round.waiting {
            return Poll::Pending;
        }
        if let Some(frame) = round.pending.take() {
            if now < frame.checked_at() {
                round.pending = Some(frame);
                return Poll::Pending;
            }
            if now >= frame.expires() {
                round.outcome.invalid = round.outcome.invalid.saturating_add(1);
                self.stats.add(Metric::Invalid, 1);
                round.index = round.index.checked_add(1).ok_or(Fault::Overflow)?;
                return Poll::Ready(Ok(()));
            }
            let until = round.fetch.until.min(frame.expires());
            let hard = round.hard.min(
                Instant::now()
                    .checked_add(Duration::from_micros(frame.expires().saturating_sub(now)))
                    .ok_or(Fault::Overflow)?,
            );
            match self
                .port
                .start(round.fetch.job.clone(), round.index, frame, until, hard)
            {
                Ok(()) => {
                    round.waiting = true;
                    return Poll::Ready(Ok(()));
                }
                Err(rejected) => {
                    let (error, frame) = *rejected;
                    round.pending = Some(frame);
                    if temporary(&error) {
                        self.pause = Some(
                            Instant::now()
                                .checked_add(self.limits.tick)
                                .ok_or(Fault::Overflow)?,
                        );
                        return Poll::Pending;
                    }
                    return Poll::Ready(Err(error));
                }
            }
        }
        if let Some(body) = &round.body
            && round.offset < body.len()
        {
            let rest = &body[round.offset..];
            let frame =
                match gnunet_hostlist::Frames::new(rest, self.limits.http.body_bytes)?.next() {
                    Some(Ok(frame)) => frame,
                    Some(Err(error)) => {
                        round.outcome.invalid = round.outcome.invalid.saturating_add(1);
                        self.stats.add(Metric::Invalid, 1);
                        round.failure = Some(error.into());
                        round.body = None;
                        return Poll::Ready(Ok(()));
                    }
                    None => return Poll::Ready(Err(Fault::Malformed.into())),
                };
            let length = frame.len();
            match HelloFrame::verify(
                frame,
                &mut self.scratch,
                self.limits.hello,
                self.limits.profile,
                now,
            ) {
                Ok(hello) => {
                    round.outcome.verified = round.outcome.verified.saturating_add(1);
                    self.stats.add(Metric::Verified, 1);
                    if gnunet_hello::message_expiration(hello.bytes())?.as_micros() != 0 {
                        round.pending = Some(hello)
                    } else {
                        round.index = round.index.checked_add(1).ok_or(Fault::Overflow)?
                    }
                }
                Err(reason) => {
                    observe(Event::HelloRejected {
                        job: round.fetch.job.clone(),
                        index: round.index,
                        reason,
                    });
                    round.outcome.invalid = round.outcome.invalid.saturating_add(1);
                    self.stats.add(Metric::Invalid, 1);
                    round.index = round.index.checked_add(1).ok_or(Fault::Overflow)?;
                    if reason == Fault::Capacity {
                        observe(Event::Capacity("bounded HELLO parser"))
                    }
                }
            }
            round.offset = round.offset.checked_add(length).ok_or(Fault::Overflow)?;
            return Poll::Ready(Ok(()));
        }
        let mut round = self.round.take().ok_or(Fault::Stale)?;
        round.outcome.complete = round.failure.is_none() && !round.retiring;
        self.core.finish(&round.fetch.job, round.outcome, now)?;
        if !round.outcome.complete || round.outcome.invalid != 0 {
            self.stats.add(Metric::Failures, 1)
        }
        observe(Event::DownloadFinished {
            job: round.fetch.job,
            origin: round.origin,
            outcome: round.outcome,
            wire: round.wire,
            failure: round.failure,
        });
        Poll::Ready(Ok(()))
    }
    fn alarm(&mut self, cx: &mut Context<'_>) -> Result<(), Error> {
        let mut at = Instant::now()
            .checked_add(self.limits.tick)
            .ok_or(Fault::Overflow)?
            .min(self.gate.hard);
        if let Some(next) = self.port.next_native() {
            at = at.min(next)
        }
        if let Some(round) = &self.round
            && !round.retiring
        {
            at = at.min(round.hard)
        }
        for send in &self.sends {
            at = at.min(send.drain.unwrap_or(send.hard))
        }
        if let Some(pause) = self.pause
            && Instant::now() < pause
        {
            at = at.min(pause)
        }
        if let Some(alarm) = &mut self.alarm {
            alarm.as_mut().reset(at)
        } else {
            self.alarm = Some(Box::pin(tokio::time::sleep_until(at)))
        }
        if let Some(alarm) = &mut self.alarm
            && alarm.as_mut().poll(cx).is_ready()
        {
            cx.waker().wake_by_ref()
        }
        Ok(())
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        if self.closed {
            return Poll::Ready(Ok(Progress::Stopped));
        }
        if let Some(durable) = &mut self.durable {
            durable.report_load(&mut |event| observe(Event::Durable(event)));
        }
        self.expire(None, observe)?;
        self.alarm(cx)?;
        let sample = match self.gate.poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Ready(Ok(sample)) => sample,
        };
        let now = sample.now.as_micros();
        self.expire(Some(now), observe)?;
        if let Some(until) = wait {
            if Instant::now() >= until {
                return Poll::Ready(Ok(Progress::WaitDeadline));
            }
            if let Some(timer) = &mut self.wait {
                timer.as_mut().reset(until)
            } else {
                self.wait = Some(Box::pin(tokio::time::sleep_until(until)))
            }
            if let Some(timer) = &mut self.wait
                && timer.as_mut().poll(cx).is_ready()
            {
                return Poll::Ready(Ok(Progress::WaitDeadline));
            }
        } else {
            self.wait = None
        }
        if self.yield_due {
            self.yield_due = false;
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if self.stopping
            && self.round.is_none()
            && self.sends.is_empty()
            && self.server.as_ref().is_none_or(Server::idle)
        {
            self.close(observe)?;
            return Poll::Ready(Ok(Progress::Stopped));
        }
        for offset in 0..7 {
            let direction = (self.turn + offset) % 7;
            let result = match direction {
                0 => {
                    if self.pause.is_some_and(|at| Instant::now() < at) {
                        Poll::Pending
                    } else {
                        match self.client.poll(cx, None) {
                            Poll::Pending => Poll::Pending,
                            Poll::Ready(event) => {
                                self.core_event(event?, now, observe)?;
                                Poll::Ready(Ok(()))
                            }
                        }
                    }
                }
                1 => {
                    let mut fault = None;
                    let round = &mut self.round;
                    let stats = &mut self.stats;
                    let result = self.port.poll(cx, &mut self.core, now, &mut |event| {
                        if let Err(error) = Self::ps_event(round, stats, event, observe) {
                            fault = Some(error)
                        }
                    });
                    if let Some(error) = fault {
                        return Poll::Ready(Err(error));
                    }
                    result
                }
                2 => self.download(cx, now, observe),
                3 => match &mut self.server {
                    Some(server) => {
                        let stats = &mut self.stats;
                        server.poll(cx, &mut |event| {
                            if matches!(
                                event,
                                HttpEvent::Prepared {
                                    revision: Some(_),
                                    status: 200,
                                    ..
                                }
                            ) {
                                stats.add(Metric::Requests, 1)
                            }
                            observe(Event::Http(event))
                        })
                    }
                    None => Poll::Pending,
                },
                4 => self
                    .stats
                    .poll(cx, now, &mut |event| observe(Event::Statistics(event))),
                5 => match &mut self.durable {
                    Some(durable) => {
                        match durable.poll(cx, &mut |event| observe(Event::Durable(event))) {
                            Poll::Ready(Ok(true)) => Poll::Ready(Ok(())),
                            Poll::Ready(Ok(false)) | Poll::Pending => Poll::Pending,
                            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                        }
                    }
                    None => Poll::Pending,
                },
                _ => {
                    if self.pause.is_some_and(|at| Instant::now() < at) {
                        Poll::Pending
                    } else {
                        self.pause = None;
                        if self.prepare(now, observe)? {
                            Poll::Ready(Ok(()))
                        } else {
                            Poll::Pending
                        }
                    }
                }
            };
            if let Poll::Ready(result) = result {
                self.turn = (direction + 1) % 7;
                result?;
                return Poll::Ready(Ok(Progress::Activity));
            }
        }
        Poll::Pending
    }
    /// Foreground poll; every error physically stops all network/MQ owners before
    /// returning. Original persistence jobs remain owned for explicit final join.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<Instant>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<Progress, Error>> {
        let result = self.poll_inner(cx, wait, observe);
        if matches!(result, Poll::Ready(Err(_)))
            && let Err(error) = self.close(observe)
        {
            observe(Event::Cleanup("independent network cleanup", error))
        }
        if matches!(result, Poll::Ready(Ok(Progress::Activity))) {
            self.yield_due = true
        }
        result
    }
    /// Cancellation-safe borrowed future for original retained owners/cursors.
    pub async fn drive(
        &mut self,
        wait: Option<Instant>,
        mut observe: impl FnMut(Event<'id>),
    ) -> Result<Progress, Error> {
        poll_fn(|cx| self.poll(cx, wait, &mut observe)).await
    }
    /// Soft stop: no new advertisements/downloads/accepts. Existing writes retain
    /// original tokens and bounded drains; the outer caller supplies stop grace.
    pub fn request_stop(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Result<(), Error> {
        self.stopping = true;
        if let Some(server) = &mut self.server {
            server.stop_accepting()
        }
        if let Some(round) = &mut self.round {
            if let Some(network) = &mut round.network {
                round.wire = network.wire();
                network.cancel();
                match network.take_diagnostics() {
                    Ok(list) => {
                        for diagnostic in list {
                            observe(Event::SocketDiagnostic {
                                job: round.fetch.job.clone(),
                                diagnostic,
                            })
                        }
                    }
                    Err(cleanup) => observe(Event::Cleanup("HTTP native diagnostics", cleanup)),
                }
            }
            round.network = None;
            round.body = None;
            round.pending = None;
            round.retiring = true;
            round.failure = Some(Fault::Cancelled.into());
            round.outcome.complete = false;
        }
        let round = &mut self.round;
        let stats = &mut self.stats;
        let mut fault = None;
        self.port.cancel(&mut |event| {
            if let Err(error) = Self::ps_event(round, stats, event, observe) {
                fault = Some(error)
            }
        })?;
        if let Some(error) = fault {
            return Err(error);
        }
        let mut index = 0;
        while index < self.sends.len() {
            let send = self.sends[index].send;
            match self.client.cancel(send) {
                Ok(Some(completion)) => {
                    self.sends.swap_remove(index);
                    observe(Event::AdvertisementCancelled {
                        send,
                        outcome: completion.outcome,
                    });
                }
                Ok(None)
                | Err(gnunet_client_host::ConnectError::Protocol(
                    Fault::Stale | Fault::StaleGeneration,
                )) => {
                    if self.sends[index].drain.is_none() {
                        self.sends[index].drain = Some(
                            Instant::now()
                                .min(self.sends[index].hard)
                                .checked_add(self.limits.grace)
                                .ok_or(Fault::Overflow)?,
                        );
                    }
                    index += 1
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
    /// Stop original sockets before metadata retirement, independently of clocks.
    /// Socket destruction exposes no close errno; actual MQ callback errors are
    /// retained and no missing receipt is fabricated as success.
    pub fn close(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Result<(), Error> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        if let Some(round) = &mut self.round
            && let Some(network) = &mut round.network
        {
            round.wire = network.wire();
            network.cancel()
        }
        if let Some(server) = &mut self.server {
            server.close(&mut |event| observe(Event::Http(event)))
        }
        let core_result = self.client.close();
        let mut fault = None;
        let round = &mut self.round;
        let stats = &mut self.stats;
        let peer_result = self.port.close(&mut |event| {
            if let Err(error) = Self::ps_event(round, stats, event, observe) {
                fault = Some(error)
            }
        });
        self.stats
            .close(&mut |event| observe(Event::Statistics(event)));
        self.publisher.clear();
        self.links.clear();
        self.ready = false;
        self.epoch = None;
        self.alarm = None;
        self.wait = None;
        let mut first = core_result.err().map(Error::Native);
        if let Err(error) = peer_result {
            if first.is_none() {
                first = Some(error)
            } else {
                observe(Event::Cleanup("PEERSTORE independent cleanup", error))
            }
        }
        if let Some(error) = fault {
            if first.is_none() {
                first = Some(error)
            } else {
                observe(Event::Cleanup("original peerstore completion", error))
            }
        }
        let mut cx = Context::from_waker(std::task::Waker::noop());
        for _ in 0..128 {
            match self.client.poll(&mut cx, None) {
                Poll::Ready(Ok(core::Progress::Finished {
                    epoch,
                    peer,
                    send,
                    payload,
                    completion,
                })) => {
                    if let Some(index) = self.sends.iter().position(|s| s.send == send) {
                        self.sends.swap_remove(index);
                    }
                    observe(Event::AdvertisementFinished {
                        epoch,
                        peer,
                        send,
                        payload,
                        outcome: completion.outcome,
                    })
                }
                Poll::Ready(Ok(core::Progress::Closed)) => break,
                Poll::Ready(Err(error)) => {
                    if first.is_none() {
                        first = Some(error.into())
                    } else {
                        observe(Event::Cleanup("CORE actual retirement", error.into()))
                    }
                    break;
                }
                Poll::Pending => {
                    if first.is_none() {
                        first = Some(Fault::OutcomeUnknown.into())
                    }
                    break;
                }
                _ => {}
            }
        }
        if !self.sends.is_empty() && first.is_none() {
            first = Some(Fault::OutcomeUnknown.into())
        }
        self.sends.clear();
        if let Some(mut round) = self.round.take() {
            round.outcome.complete = false;
            if let Err(error) = self.core.retire_without_time(&round.fetch.job) {
                if first.is_none() {
                    first = Some(error.into())
                } else {
                    observe(Event::Cleanup("HTTP metadata retirement", error.into()))
                }
            }
            observe(Event::DownloadFinished {
                job: round.fetch.job,
                origin: round.origin,
                outcome: round.outcome,
                wire: round.wire,
                failure: round.failure.or(Some(Fault::Closed.into())),
            })
        }
        first.map_or(Ok(()), Err)
    }
    /// Only after physical network close, save final public history and join its
    /// original worker. An fsync is not declared canceled by a socket timeout.
    pub async fn shutdown_durable(
        &mut self,
        mut observe: impl FnMut(Event<'id>),
    ) -> Result<(), Error> {
        if !self.closed {
            return Err(Fault::Conflict.into());
        }
        if let Some(durable) = &mut self.durable {
            durable.report_load(&mut |event| observe(Event::Durable(event)));
            durable
                .shutdown(&self.core, |event| observe(Event::Durable(event)))
                .await?
        }
        Ok(())
    }
}
impl Drop for Runtime<'_> {
    fn drop(&mut self) {
        let _closed = self.close(&mut |_| {});
    }
}
/// Actual startup observations; this never asserts an Internet bootstrap succeeded.
#[derive(Clone, Copy, Debug)]
pub struct Readiness {
    /// Actual CORE INIT_REPLY.
    pub core: bool,
    /// Actual general PEERSTORE attach.
    pub peerstore: bool,
    /// Actual current monitor SYNC, or monitoring not requested.
    pub monitor: bool,
    /// Number of real bound HTTP listeners.
    pub http_listeners: usize,
}
impl Readiness {
    /// Critical actual source startup (HTTP role has its own real listeners).
    pub const fn complete(self) -> bool {
        self.core && self.peerstore && self.monitor
    }
}
