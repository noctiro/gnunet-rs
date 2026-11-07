//! Actual caller-polled NAT service business/IO owner. Jobs and mappings retain
//! original Source/Provider/bounds; outcomes are applied only to those originals.
#[cfg(test)]
mod mapping_tests;

use crate::{
    Error,
    deadline::{Bounds, Gate},
    helpers::{Helper, Supervisor},
    interfaces,
    resolve::Lookup,
    settings::{External, Settings},
    upnp::{self, Device, Mapping, Protocol},
};
use gnunet_client_host::resolution::SharedResolution;
use gnunet_config::Configuration;
use gnunet_nat::{
    address::{SocketAddress, parse_ipv4},
    state::{self, Advertised, Core, Provider, ProviderKind, Source},
};
use gnunet_service_runtime::clock::{ClockSubscription, RuntimeClock};
use gnunet_types::Error as Fault;
use gnunet_wire::official::nat::{self, AddressClass};
use std::{
    collections::VecDeque,
    future::{Future, poll_fn},
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpSocket, UdpSocket},
    time::{Instant, Sleep},
};
/// Actual original cause, retaining concrete clock/DNS/IGD/helper failures.
pub type Failure = Box<dyn std::error::Error>;
/// Actual service-side provider/cleanup observations, never fake IPC ACKs.
#[derive(Debug)]
pub enum Event {
    /// Original worker failed; already-performed partial IO is not hidden.
    Failed {
        /// Original local job serial.
        job: u64,
        /// Original registration source when scoped.
        source: Option<Source>,
        /// Actual cause.
        error: Failure,
    },
    /// Actual router mutation may have occurred; real cleanup remains separate.
    MappingUnknown {
        /// Original mapping source, never the next reconnect.
        source: Source,
        /// Original mapped external port.
        port: u16,
    },
    /// Actual SOAP-confirmed delete/absent snapshot on the original mapping.
    /// An absent snapshot can accompany MappingUnknown when an earlier exposed
    /// Add may still apply later; it does not itself settle that original debt.
    MappingRemoved {
        /// Original source (possibly already physically retired).
        source: Source,
        /// Original external port.
        port: u16,
    },
    /// Actual local test send/helper completion, not remote receipt.
    TestWritten {
        /// Original test requester.
        source: Source,
    },
    /// Actual original child observation/loss/wait error.
    Helper(crate::helpers::Event),
}
#[derive(Clone, Copy)]
struct Due {
    absolute: u64,
    native: Instant,
}
impl Due {
    fn after(clock: &dyn RuntimeClock, d: Duration) -> Result<Self, Error> {
        let b = Bounds::after(clock, d)?;
        Ok(Self {
            absolute: b.expires,
            native: b.hard,
        })
    }
    fn reached(self, now: u64) -> bool {
        now >= self.absolute || Instant::now() >= self.native
    }
}
struct Client {
    source: Source,
    external: External,
    dns: Option<Provider>,
    next_dns: Option<Due>,
    next_mapping: Option<Due>,
}
struct Interface {
    local: [u8; 4],
    helper: Option<Helper>,
    retry: Option<Instant>,
    backoff: Duration,
}
#[derive(Clone)]
struct Intent {
    source: Source,
    provider: Provider,
    device: Device,
    internal: Ipv4Addr,
    port: u16,
    protocol: Protocol,
}
struct Lease {
    id: u64,
    intent: Intent,
    mapping: Mapping,
    next: Due,
    valid_until: Due,
    valid: bool,
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum CleanupOrigin {
    Committed,
    ExposedUnknown,
}
impl CleanupOrigin {
    fn from_add(outcome: upnp::AddOutcome) -> Option<Self> {
        match outcome {
            upnp::AddOutcome::Committed => Some(Self::Committed),
            upnp::AddOutcome::ExposedUnknown => Some(Self::ExposedUnknown),
            upnp::AddOutcome::Unexposed | upnp::AddOutcome::KnownRejected => None,
        }
    }
}
fn observe_cleanup(
    intent: &Intent,
    origin: CleanupOrigin,
    removal: Option<upnp::Removal>,
    observe: &mut impl FnMut(Event),
) -> bool {
    if matches!(
        removal,
        Some(upnp::Removal::Removed | upnp::Removal::Absent | upnp::Removal::OwnedThenAbsent)
    ) {
        observe(Event::MappingRemoved {
            source: intent.source,
            port: intent.port,
        });
    }
    let unresolved = match removal {
        Some(upnp::Removal::Removed | upnp::Removal::OwnedThenAbsent) => false,
        Some(upnp::Removal::Absent) => origin == CleanupOrigin::ExposedUnknown,
        Some(upnp::Removal::Unproven) | None => true,
    };
    if unresolved {
        observe(Event::MappingUnknown {
            source: intent.source,
            port: intent.port,
        });
    }
    unresolved
}
#[derive(Clone)]
enum Kind {
    Test {
        source: Source,
    },
    Dns {
        source: Source,
        provider: Provider,
    },
    Discover {
        source: Source,
        provider: Provider,
        internal: Ipv4Addr,
        port: u16,
        protocol: Protocol,
        observations: upnp::ReadObservations,
    },
    Add {
        intent: Intent,
        attempt: upnp::AddAttempt,
    },
    Refresh {
        lease: u64,
        intent: Intent,
    },
    Delete {
        intent: Intent,
        origin: CleanupOrigin,
        attempt: upnp::DeleteAttempt,
    },
    External,
}
impl Kind {
    fn source(&self) -> Option<Source> {
        match self {
            Self::Test { source } | Self::Dns { source, .. } | Self::Discover { source, .. } => {
                Some(*source)
            }
            Self::Add { intent: i, .. }
            | Self::Delete { intent: i, .. }
            | Self::Refresh { intent: i, .. } => Some(i.source),
            Self::External => None,
        }
    }
}
enum Output {
    TestWritten,
    Dns(Vec<Advertised>),
    Selected(Box<upnp::SelectionReport>),
    Mapped {
        mapping: Box<Mapping>,
        external: Result<Ipv4Addr, Arc<upnp::Error>>,
    },
    Refreshed {
        present: bool,
        external: Option<Ipv4Addr>,
    },
    Deleted(upnp::Removal),
    External(Ipv4Addr),
}
type JobFuture = Pin<Box<dyn Future<Output = Result<Output, Failure>>>>;
struct Job {
    id: u64,
    kind: Kind,
    bounds: Bounds,
    future: Option<JobFuture>,
    result: Option<Result<Output, Failure>>,
}
fn retire_reads(row: &mut Job, observe: &mut impl FnMut(Event)) {
    // Stop original IO before exposing/draining its read observations. Each
    // take moves this same Vec once; a previously completed report leaves it empty.
    row.future = None;
    if let Kind::Discover {
        source,
        observations,
        ..
    } = &row.kind
    {
        for failure in observations.take() {
            observe(Event::Failed {
                job: row.id,
                source: Some(*source),
                error: Box::new(failure),
            });
        }
    }
}
fn mapping_class(address: SocketAddress) -> AddressClass {
    if address.is_private() {
        AddressClass::LAN
    } else {
        AddressClass::EXTERN
    }
}
struct Cleanup {
    intent: Intent,
    ownership: upnp::Ownership,
    origin: CleanupOrigin,
    bounds: Bounds,
}
struct SharedUpnp(Arc<upnp::Error>);
impl std::fmt::Debug for SharedUpnp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.0.as_ref(), f)
    }
}
impl std::fmt::Display for SharedUpnp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self.0.as_ref(), f)
    }
}
impl std::error::Error for SharedUpnp {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
struct Fresh {
    provider: Provider,
    until: Due,
}
/// Actual native/committed state owner. Constructor opens no listener or socket.
/// Periodic work creates a fresh job only after its previous original finishes.
pub struct Manager {
    core: Core,
    config: Configuration,
    settings: Settings,
    resolver: SharedResolution,
    clock: Arc<dyn RuntimeClock>,
    interface_provider: Provider,
    external_provider: Provider,
    interfaces: Vec<Interface>,
    addresses: Vec<Advertised>,
    clients: Vec<Client>,
    jobs: Vec<Job>,
    leases: Vec<Lease>,
    fresh: Vec<Fresh>,
    cleanup_queue: VecDeque<Cleanup>,
    unresolved: usize,
    retire_sources: Vec<Source>,
    stun: Vec<(SocketAddress, Provider)>,
    helpers: Supervisor,
    next: u64,
    next_scan: Due,
    next_external: Due,
    subscription: Box<dyn ClockSubscription>,
    revision: u64,
    timer: Pin<Box<Sleep>>,
    cursor: usize,
    stopping: bool,
    helper_first: bool,
}
impl Manager {
    /// Use the exact process-shared Resolver/clock Arc and immutable config snapshot.
    pub fn new(
        config: Configuration,
        settings: Settings,
        limits: state::Limits,
        resolver: SharedResolution,
        clock: Arc<dyn RuntimeClock>,
    ) -> Result<Self, Failure> {
        if !Arc::ptr_eq(&resolver.clock(), &clock) {
            return Err(Fault::InvalidInput.into());
        }
        let mut core = Core::new(limits)?;
        let interface_provider = core.provider_started(ProviderKind::Interface)?;
        let external_provider = core.provider_started(ProviderKind::ExternalIp)?;
        let helpers = Supervisor::new(settings.helper_paths.clone(), settings.helper_limits)?;
        let now = clock.sample()?.now.as_micros();
        let native = Instant::now();
        let subscription = clock.subscribe()?;
        let revision = clock.sample()?.revision;
        let mut cleanup_queue = VecDeque::new();
        cleanup_queue
            .try_reserve_exact(
                settings
                    .jobs
                    .checked_add(settings.mappings)
                    .ok_or(Fault::Overflow)?,
            )
            .map_err(|_| Fault::Capacity)?;
        Ok(Self {
            core,
            config,
            settings,
            resolver,
            clock,
            interface_provider,
            external_provider,
            interfaces: Vec::new(),
            addresses: Vec::new(),
            clients: Vec::new(),
            jobs: Vec::new(),
            leases: Vec::new(),
            fresh: Vec::new(),
            cleanup_queue,
            unresolved: 0,
            retire_sources: Vec::new(),
            stun: Vec::new(),
            helpers,
            next: 1,
            next_scan: Due {
                absolute: now,
                native,
            },
            next_external: Due {
                absolute: now,
                native,
            },
            subscription,
            revision,
            timer: Box::pin(tokio::time::sleep(Duration::ZERO)),
            cursor: 0,
            stopping: false,
            helper_first: false,
        })
    }
    /// Actual core view, never an independent shadow inventory.
    pub fn core(&self) -> &Core {
        &self.core
    }
    /// Actual accepted physical service source, before registration.
    pub fn source_attached(&mut self) -> Result<Source, Failure> {
        Ok(self.core.source_attached()?)
    }
    /// Consume one actual effective-set/reversal notification, preserving Source.
    pub fn take_notification(&mut self) -> Option<state::Event> {
        self.core.take_event()
    }
    /// Current cleanup/child debt; shutdown is complete only when this iszero.
    pub fn pending(&self) -> usize {
        self.jobs.len() + self.helpers.pending() + self.leases.len() + self.cleanup_queue.len()
    }
    /// Actual cleanup attempts which could not establish removal; never reported as clean shutdown.
    pub const fn unresolved(&self) -> usize {
        self.unresolved
    }
    /// Source whose actual local forwarding interface vanished. Native SERVICE must physically close only this original before any further IO on it.
    pub fn take_retirement(&mut self) -> Option<Source> {
        self.retire_sources.pop()
    }
    fn serial(&mut self) -> Result<u64, Failure> {
        let n = self.next;
        self.next = n.checked_add(1).ok_or(Fault::Overflow)?;
        Ok(n)
    }
    fn admit(&mut self, kind: Kind, bounds: Bounds, future: JobFuture) -> Result<u64, Failure> {
        if self.jobs.len() >= self.settings.jobs {
            return Err(Fault::WouldBlock.into());
        }
        bounds.check(&*self.clock)?;
        self.jobs.try_reserve(1).map_err(|_| Fault::Capacity)?;
        let id = self.serial()?;
        self.jobs.push(Job {
            id,
            kind,
            bounds,
            future: Some(future),
            result: None,
        });
        Ok(id)
    }
    fn current(&self, source: Source) -> bool {
        self.core.registration(source).is_ok_and(|r| r.is_some())
    }
    /// Handle the actual original NAT request. There are no wire replies/ACKs.
    /// WouldBlock preserves the input for retry on this same physical source.
    pub fn request(
        &mut self,
        source: Source,
        request: nat::Request<'_>,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Failure> {
        if self.stopping {
            return Err(Fault::Closed.into());
        }
        let now = self.clock.sample()?.now.as_micros();
        match request {
            nat::Request::Register {
                flags,
                protocol,
                addresses,
                section,
            } => {
                let raw = section.split(|&b| b == 0).next().unwrap_or(&[]);
                let reg = self.settings.registration(&self.config, raw)?;
                let mut bindings = Vec::new();
                bindings
                    .try_reserve_exact(addresses.len())
                    .map_err(|_| Fault::Capacity)?;
                for address in addresses.iter() {
                    if let Ok(address) = SocketAddress::from_wire(address.address()) {
                        bindings.push(address);
                    }
                }
                self.clients.try_reserve(1).map_err(|_| Fault::Capacity)?;
                self.core.register(
                    source,
                    state::RegistrationInput {
                        flags,
                        protocol,
                        section,
                        bindings: &bindings,
                        options: reg.options,
                    },
                    now,
                )?;
                let mut client = Client {
                    source,
                    external: reg.external,
                    dns: None,
                    next_dns: None,
                    next_mapping: if self.settings.enable_upnp {
                        Some(Due::after(&*self.clock, self.settings.mapping_interval)?)
                    } else {
                        None
                    },
                };
                match &client.external {
                    External::Literal(address) => {
                        let provider = self.core.provider_started(ProviderKind::Manual(source))?;
                        self.core.publish_snapshot(
                            provider,
                            &[Advertised {
                                address: *address,
                                class: AddressClass(
                                    AddressClass::GLOBAL.0 | AddressClass::MANUAL.0,
                                ),
                            }],
                            None,
                            now,
                        )?;
                        client.dns = Some(provider);
                    }
                    External::Dns { .. } => {
                        client.dns =
                            Some(self.core.provider_started(ProviderKind::Manual(source))?);
                        client.next_dns = Some(Due {
                            absolute: now,
                            native: Instant::now(),
                        });
                    }
                    _ => {}
                }
                self.clients.push(client);
                if self.settings.enable_upnp {
                    for binding in bindings {
                        if let SocketAddress::V4 { ip, port } = binding {
                            if port == 0 {
                                continue;
                            }
                            let proto = match protocol {
                                6 => Protocol::Tcp,
                                17 => Protocol::Udp,
                                _ => continue,
                            };
                            let locals: Vec<[u8; 4]> = if ip == [0; 4] {
                                self.interfaces.iter().map(|i| i.local).collect()
                            } else if binding.is_private() {
                                vec![ip]
                            } else {
                                Vec::new()
                            };
                            for local in locals {
                                if let Err(error) =
                                    self.start_discover(source, Ipv4Addr::from(local), port, proto)
                                {
                                    observe(Event::Failed {
                                        job: 0,
                                        source: Some(source),
                                        error,
                                    });
                                }
                            }
                        }
                    }
                }
            }
            nat::Request::Stun { sender, payload } => {
                let sender = SocketAddress::from_wire(sender.address())?;
                let message = match gnunet_nat::stun::Message::decode(payload) {
                    Ok(m) => m,
                    Err(_) => return Ok(()),
                };
                let Some(address) = message.mapped_address().ok().flatten() else {
                    return Ok(());
                };
                if !matches!(address, SocketAddress::V4 { .. }) {
                    return Ok(());
                }
                let provider = if let Some((_, p)) = self.stun.iter().find(|(s, _)| *s == sender) {
                    *p
                } else {
                    if self.stun.len() >= self.settings.jobs {
                        return Err(Fault::WouldBlock.into());
                    }
                    self.stun.try_reserve(1).map_err(|_| Fault::Capacity)?;
                    let p = self.core.provider_started(ProviderKind::Stun)?;
                    self.stun.push((sender, p));
                    p
                };
                self.publish_fresh(
                    provider,
                    &[Advertised {
                        address: address.with_port(0),
                        class: AddressClass(AddressClass::EXTERN.0 | AddressClass::GLOBAL.0),
                    }],
                    self.settings.stun_stale,
                )?;
            }
            nat::Request::AddGlobal { address } => {
                let ip = match parse_ipv4(address) {
                    Ok(ip) if ip != [0; 4] => ip,
                    _ => return Ok(()),
                };
                let sender = SocketAddress::V4 { ip, port: 0 };
                let provider = if let Some((_, p)) = self.stun.iter().find(|(s, _)| *s == sender) {
                    *p
                } else {
                    if self.stun.len() >= self.settings.jobs {
                        return Err(Fault::WouldBlock.into());
                    }
                    self.stun.try_reserve(1).map_err(|_| Fault::Capacity)?;
                    let p = self.core.provider_started(ProviderKind::Stun)?;
                    self.stun.push((sender, p));
                    p
                };
                self.publish_fresh(
                    provider,
                    &[Advertised {
                        address: sender,
                        class: AddressClass(AddressClass::EXTERN.0 | AddressClass::GLOBAL.0),
                    }],
                    self.settings.stun_stale,
                )?;
            }
            nat::Request::Reverse { local, remote } => {
                let reversal = self.core.request_reversal(
                    source,
                    SocketAddress::from_wire(local.address())?,
                    SocketAddress::from_wire(remote.address())?,
                )?;
                let bounds = Bounds::after(&*self.clock, self.settings.job_timeout)?;
                self.helpers.start_client(reversal, bounds, &*self.clock)?;
            }
        }
        Ok(())
    }
    fn publish_fresh(
        &mut self,
        provider: Provider,
        addresses: &[Advertised],
        lifetime: Duration,
    ) -> Result<(), Failure> {
        let until = Due::after(&*self.clock, lifetime)?;
        if !self.fresh.iter().any(|f| f.provider == provider) {
            self.fresh.try_reserve(1).map_err(|_| Fault::Capacity)?;
        }
        let now = self.clock.sample()?.now.as_micros();
        self.core
            .publish_snapshot(provider, addresses, Some(until.absolute), now)?;
        if let Some(f) = self.fresh.iter_mut().find(|f| f.provider == provider) {
            f.until = until;
        } else {
            self.fresh.push(Fresh { provider, until });
        }
        Ok(())
    }
    fn start_discover(
        &mut self,
        source: Source,
        internal: Ipv4Addr,
        port: u16,
        protocol: Protocol,
    ) -> Result<(), Failure> {
        if self.leases.len()
            + self
                .jobs
                .iter()
                .filter(|j| matches!(j.kind, Kind::Discover { .. } | Kind::Add { .. }))
                .count()
            >= self.settings.mappings
        {
            return Err(Fault::WouldBlock.into());
        }
        if self.leases.iter().any(|l| {
            l.intent.source == source
                && l.intent.internal == internal
                && l.intent.port == port
                && l.intent.protocol == protocol
        }) || self.jobs.iter().any(|j| match &j.kind {
            Kind::Discover {
                source: s,
                internal: i,
                port: p,
                protocol: t,
                ..
            } => *s == source && *i == internal && *p == port && *t == protocol,
            Kind::Add { intent: i, .. } => {
                i.source == source
                    && i.internal == internal
                    && i.port == port
                    && i.protocol == protocol
            }
            _ => false,
        }) {
            return Ok(());
        }
        let observations = upnp::ReadObservations::new(upnp::Limits::default())?;
        let bounds = Bounds::after(&*self.clock, self.settings.job_timeout)?;
        let mut gate = Gate::new(self.clock.clone(), bounds)?;
        let provider = self.core.provider_started(ProviderKind::Mapping {
            source,
            protocol: protocol.number(),
            internal: SocketAddress::V4 {
                ip: internal.octets(),
                port,
            },
        })?;
        let resolver = self.resolver.clone();
        let progress = observations.clone();
        let future = Box::pin(async move {
            Ok(Output::Selected(Box::new(
                upnp::discover(&resolver, &mut gate, Some(internal), progress).await?,
            )))
        });
        match self.admit(
            Kind::Discover {
                source,
                provider,
                internal,
                port,
                protocol,
                observations,
            },
            bounds,
            future,
        ) {
            Ok(_) => Ok(()),
            Err(e) => {
                let now = self.clock.sample()?.now.as_micros();
                let _cleanup = self.core.provider_stopped(provider, now);
                Err(e)
            }
        }
    }
    fn add(&mut self, intent: Intent, bounds: Bounds) -> Result<(), Failure> {
        let mut gate = Gate::new(self.clock.clone(), bounds)?;
        let resolver = self.resolver.clone();
        let i = intent.clone();
        let attempt = upnp::AddAttempt::new()?;
        let progress = attempt.clone();
        let future = Box::pin(async move {
            let mapping = upnp::add_mapping(
                &resolver,
                &mut gate,
                &i.device,
                upnp::MappingRequest {
                    internal: i.internal,
                    internal_port: i.port,
                    external_port: i.port,
                    protocol: i.protocol,
                    lease_seconds: 0,
                },
                &progress,
                upnp::Limits::default(),
            )
            .await?;
            let external =
                upnp::external_ipv4(&resolver, &mut gate, &i.device, upnp::Limits::default())
                    .await
                    .map_err(Arc::new);
            Ok(Output::Mapped {
                mapping: Box::new(mapping),
                external,
            })
        });
        self.admit(Kind::Add { intent, attempt }, bounds, future)?;
        Ok(())
    }
    fn cleanup(
        &mut self,
        intent: Intent,
        ownership: upnp::Ownership,
        origin: CleanupOrigin,
    ) -> Result<(), Failure> {
        let bounds = match Bounds::after(&*self.clock, self.settings.cleanup_timeout) {
            Ok(b) => b,
            Err(e) => {
                self.unresolved = self.unresolved.saturating_add(1);
                return Err(e.into());
            }
        };
        if self.cleanup_queue.len() >= self.settings.jobs + self.settings.mappings {
            self.unresolved = self.unresolved.saturating_add(1);
            return Err(Fault::Capacity.into());
        }
        self.cleanup_queue.push_back(Cleanup {
            intent,
            ownership,
            origin,
            bounds,
        });
        Ok(())
    }
    fn start_cleanup(
        &mut self,
        intent: Intent,
        ownership: upnp::Ownership,
        origin: CleanupOrigin,
        bounds: Bounds,
    ) -> Result<(), Failure> {
        let mut gate = Gate::new(self.clock.clone(), bounds)?;
        let resolver = self.resolver.clone();
        let i = intent.clone();
        let attempt = upnp::DeleteAttempt::default();
        let progress = attempt.clone();
        let future = Box::pin(async move {
            let removal = upnp::delete_mapping(
                &resolver,
                &mut gate,
                &i.device,
                upnp::MappingRequest {
                    internal: i.internal,
                    internal_port: i.port,
                    external_port: i.port,
                    protocol: i.protocol,
                    lease_seconds: 0,
                },
                &ownership,
                &progress,
                upnp::Limits::default(),
            )
            .await?;
            Ok(Output::Deleted(removal))
        });
        self.admit(
            Kind::Delete {
                intent,
                origin,
                attempt,
            },
            bounds,
            future,
        )?;
        Ok(())
    }
    fn refresh(&mut self, index: usize) -> Result<(), Failure> {
        let lease = &self.leases[index];
        let kind = Kind::Refresh {
            lease: lease.id,
            intent: lease.intent.clone(),
        };
        let mapping = lease.mapping.clone();
        let bounds = Bounds::after(&*self.clock, self.settings.job_timeout)?;
        let mut gate = Gate::new(self.clock.clone(), bounds)?;
        let resolver = self.resolver.clone();
        let future = Box::pin(async move {
            let present =
                upnp::query_mapping(&resolver, &mut gate, &mapping, upnp::Limits::default())
                    .await?;
            let external = if present {
                Some(
                    upnp::external_ipv4(
                        &resolver,
                        &mut gate,
                        mapping.device(),
                        upnp::Limits::default(),
                    )
                    .await?,
                )
            } else {
                None
            };
            Ok(Output::Refreshed { present, external })
        });
        self.admit(kind, bounds, future)?;
        Ok(())
    }
    fn dns(&mut self, index: usize) -> Result<(), Failure> {
        let client = &self.clients[index];
        let External::Dns { host, port } = &client.external else {
            return Ok(());
        };
        let source = client.source;
        let provider = client.dns.ok_or(Fault::NotReady)?;
        let port = *port;
        let host = host.clone();
        let bounds = Bounds::after(&*self.clock, self.settings.job_timeout)?;
        let mut gate = Gate::new(self.clock.clone(), bounds)?;
        let mut lookup = Lookup::start(&self.resolver, &gate, &host, 128)?;
        let disable_v6 = self.settings.disable_v6;
        let future = Box::pin(async move {
            loop {
                if poll_fn(|cx| lookup.poll(cx, &mut gate)).await? {
                    break;
                }
            }
            let mut out = Vec::new();
            out.try_reserve_exact(lookup.addresses().len())
                .map_err(|_| Fault::Capacity)?;
            for &ip in lookup.addresses() {
                let address = match ip {
                    IpAddr::V4(ip) => SocketAddress::V4 {
                        ip: ip.octets(),
                        port,
                    },
                    IpAddr::V6(ip) if !disable_v6 => SocketAddress::V6 {
                        ip: ip.octets(),
                        port,
                        scope: 0,
                        flow: 0,
                    },
                    _ => continue,
                };
                out.push(Advertised {
                    address,
                    class: AddressClass(AddressClass::GLOBAL.0 | AddressClass::MANUAL.0),
                });
            }
            Ok(Output::Dns(out))
        });
        self.admit(Kind::Dns { source, provider }, bounds, future)?;
        Ok(())
    }
    fn external(&mut self) -> Result<(), Failure> {
        if !self.settings.use_stun || self.settings.stun_servers.is_empty() {
            return Ok(());
        }
        let bounds = Bounds::after(&*self.clock, self.settings.job_timeout)?;
        let servers = self.settings.stun_servers.clone();
        let max_datagrams = self.settings.stun_datagrams;
        let resolver = self.resolver.clone();
        let clock = self.clock.clone();
        let future = Box::pin(async move {
            let mut last = None;
            for (host, port) in servers {
                match crate::probe::external_ipv4(
                    resolver.clone(),
                    clock.clone(),
                    host,
                    port,
                    bounds,
                    max_datagrams,
                )
                .await
                {
                    Ok(ip) => return Ok(Output::External(ip)),
                    Err(e) => last = Some(e),
                }
            }
            Err(last.map_or_else(
                || Box::new(Fault::NotFound) as Failure,
                |e| Box::new(e) as Failure,
            ))
        });
        self.admit(Kind::External, bounds, future)?;
        Ok(())
    }
    /// Actual remote-test-server output (two opaque challenge bytes). It sends
    /// no invented acknowledgement and remains bound to the original requester.
    pub fn test(&mut self, source: Source, request: nat::TestRequest) -> Result<(), Failure> {
        let bounds = Bounds::after(&*self.clock, self.settings.job_timeout)?;
        if request.port == 0 {
            let port = u16::from_be_bytes(request.data);
            if port == 0 {
                return Err(Fault::InvalidInput.into());
            }
            self.helpers.start_test(
                state::Reversal {
                    source,
                    local: [0; 4],
                    remote: request.destination,
                    port,
                },
                bounds,
                &*self.clock,
            )?;
            return Ok(());
        }
        let target = SocketAddr::from((request.destination, request.port));
        let mut gate = Gate::new(self.clock.clone(), bounds)?;
        let future = Box::pin(async move {
            if request.is_tcp == 1 {
                let socket = TcpSocket::new_v4()?;
                let mut stream = gate.run(socket.connect(target)).await?;
                gate.run(stream.write_all(&request.data)).await?;
            } else {
                let socket = gate
                    .run(UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))))
                    .await?;
                let n = gate.run(socket.send_to(&request.data, target)).await?;
                if n != 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "short NAT test datagram",
                    )
                    .into());
                }
            }
            Ok(Output::TestWritten)
        });
        self.admit(Kind::Test { source }, bounds, future)?;
        Ok(())
    }
    /// Physical source stop: discard its callbacks/partial jobs, preserve actual
    /// mutation uncertainty, and queue separately bounded real deletes.
    pub fn source_stopped(
        &mut self,
        source: Source,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Failure> {
        self.helpers.source_stopped(source);
        if let Some(provider) = self
            .clients
            .iter()
            .find(|c| c.source == source)
            .and_then(|c| c.dns)
        {
            self.fresh.retain(|f| f.provider != provider);
        }
        self.clients.retain(|c| c.source != source);
        self.retire_sources.retain(|s| *s != source);
        // Revoke the original source before any fallible cleanup admission.
        // The queue was reserved at construction; retirement needs no scratch Vec.
        let retired = self.core.source_stopped(source);
        let mut i = 0;
        while i < self.jobs.len() {
            if self.jobs[i].kind.source() == Some(source)
                && !matches!(self.jobs[i].kind, Kind::Delete { .. } | Kind::Test { .. })
            {
                let mut row = self.jobs.swap_remove(i);
                retire_reads(&mut row, observe);
                if let Kind::Add { intent, attempt } = row.kind
                    && let Some(origin) = CleanupOrigin::from_add(attempt.outcome())
                {
                    observe(Event::MappingUnknown {
                        source,
                        port: intent.port,
                    });
                    if let Err(error) = self.cleanup(intent, attempt.ownership(), origin) {
                        observe(Event::Failed {
                            job: 0,
                            source: Some(source),
                            error,
                        });
                    }
                }
            } else {
                i += 1;
            }
        }
        let mut i = 0;
        while i < self.leases.len() {
            if self.leases[i].intent.source == source {
                let lease = self.leases.swap_remove(i);
                if let Err(error) = self.cleanup(
                    lease.intent,
                    lease.mapping.ownership(),
                    CleanupOrigin::Committed,
                ) {
                    observe(Event::Failed {
                        job: 0,
                        source: Some(source),
                        error,
                    });
                }
            } else {
                i += 1;
            }
        }
        retired?;
        Ok(())
    }
    fn scan(&mut self, observe: &mut impl FnMut(Event)) -> Result<(), Failure> {
        let bounds = Bounds::after(&*self.clock, self.settings.job_timeout)?;
        let gate = Gate::new(self.clock.clone(), bounds)?;
        let addresses = interfaces::scan(
            &mut self.core,
            self.interface_provider,
            &gate,
            self.settings.interfaces,
            self.settings.disable_v6,
        )?;
        let mut locals = Vec::new();
        locals
            .try_reserve_exact(addresses.len())
            .map_err(|_| Fault::Capacity)?;
        locals.extend(addresses.iter().filter_map(|a| match a.address {
            SocketAddress::V4 { ip, .. } if a.address.is_private() => Some(ip),
            _ => None,
        }));
        for lease in &self.leases {
            if !locals.contains(&lease.intent.internal.octets())
                && !self.retire_sources.contains(&lease.intent.source)
            {
                self.retire_sources
                    .try_reserve(1)
                    .map_err(|_| Fault::Capacity)?;
                self.retire_sources.push(lease.intent.source);
            }
        }
        for job in &self.jobs {
            let origin = match &job.kind {
                Kind::Discover {
                    source, internal, ..
                } if !locals.contains(&internal.octets()) => Some(*source),
                Kind::Add { intent, .. } if !locals.contains(&intent.internal.octets()) => {
                    Some(intent.source)
                }
                _ => None,
            };
            if let Some(source) = origin
                && !self.retire_sources.contains(&source)
            {
                self.retire_sources
                    .try_reserve(1)
                    .map_err(|_| Fault::Capacity)?;
                self.retire_sources.push(source);
            }
        }
        for i in (0..self.interfaces.len()).rev() {
            if !locals.contains(&self.interfaces[i].local) {
                let old = self.interfaces.swap_remove(i);
                if let Some(helper) = old.helper {
                    self.helpers.stop(helper)?;
                }
            }
        }
        for local in locals {
            if !self.interfaces.iter().any(|i| i.local == local) {
                self.interfaces
                    .try_reserve(1)
                    .map_err(|_| Fault::Capacity)?;
                self.interfaces.push(Interface {
                    local,
                    helper: None,
                    retry: Some(Instant::now()),
                    backoff: Duration::from_millis(100),
                });
            }
        }
        self.addresses = addresses;
        let bindings: Vec<(Source, u8, Vec<SocketAddress>)> = self
            .clients
            .iter()
            .filter_map(|c| {
                self.core
                    .registration(c.source)
                    .ok()
                    .flatten()
                    .map(|r| (c.source, r.protocol, r.bindings.to_vec()))
            })
            .collect();
        if self.settings.enable_upnp {
            for (source, protocol, bindings) in bindings {
                let protocol = match protocol {
                    6 => Protocol::Tcp,
                    17 => Protocol::Udp,
                    _ => continue,
                };
                for b in bindings {
                    if b.port() == 0 {
                        continue;
                    }
                    if b.is_unspecified() {
                        let locals: Vec<_> = self.interfaces.iter().map(|i| i.local).collect();
                        for ip in locals {
                            if let Err(error) =
                                self.start_discover(source, ip.into(), b.port(), protocol)
                            {
                                observe(Event::Failed {
                                    job: 0,
                                    source: Some(source),
                                    error,
                                });
                            }
                        }
                    }
                }
            }
        }
        Ok(())
    }
    fn job_failure(
        &mut self,
        mut row: Job,
        error: Failure,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Failure> {
        retire_reads(&mut row, observe);
        let source = row.kind.source();
        if let Kind::Delete {
            intent,
            origin,
            attempt,
        } = &row.kind
        {
            self.unresolved = self.unresolved.saturating_add(usize::from(observe_cleanup(
                intent,
                *origin,
                attempt.removal(),
                observe,
            )));
        }
        let failed_provider = match &row.kind {
            Kind::Discover { provider, .. } => Some(*provider),
            Kind::Add { intent, .. } => Some(intent.provider),
            _ => None,
        };
        let mut clock_failure = None;
        if let Some(provider) = failed_provider {
            match self.clock.sample() {
                Ok(sample) => {
                    if let Err(cleanup) =
                        self.core.provider_stopped(provider, sample.now.as_micros())
                        && cleanup != Fault::StaleGeneration
                    {
                        observe(Event::Failed {
                            job: row.id,
                            source,
                            error: cleanup.into(),
                        });
                    }
                }
                Err(error) => clock_failure = Some(error),
            }
        }

        if let Kind::Add { intent, attempt } = row.kind
            && let Some(origin) = CleanupOrigin::from_add(attempt.outcome())
        {
            observe(Event::MappingUnknown {
                source: intent.source,
                port: intent.port,
            });
            if clock_failure.is_some() {
                self.unresolved = self.unresolved.saturating_add(1);
            } else if let Err(error) = self.cleanup(intent, attempt.ownership(), origin) {
                observe(Event::Failed {
                    job: row.id,
                    source,
                    error,
                });
            }
        }
        observe(Event::Failed {
            job: row.id,
            source,
            error,
        });
        if let Some(error) = clock_failure {
            self.abort(observe);
            return Err(error.into());
        }
        Ok(())
    }
    fn complete(
        &mut self,
        row: &mut Job,
        now: u64,
        observe: &mut impl FnMut(Event),
    ) -> Result<bool, Failure> {
        let Some(result) = row.result.as_ref() else {
            return Ok(false);
        };
        if result.is_err() {
            return Ok(true);
        }
        if row.bounds.hard <= Instant::now() || now >= row.bounds.expires {
            return Err(Fault::Deadline.into());
        }
        if row.kind.source().is_some_and(|s| !self.current(s))
            && !matches!(row.kind, Kind::Delete { .. } | Kind::Test { .. })
        {
            return Err(Fault::StaleGeneration.into());
        }
        match (&row.kind, result) {
            (Kind::Test { source }, Ok(Output::TestWritten)) => {
                observe(Event::TestWritten { source: *source })
            }
            (Kind::Dns { provider, .. }, Ok(Output::Dns(addresses))) => self.publish_fresh(
                *provider,
                addresses,
                self.settings.dyndns_interval + self.settings.job_timeout,
            )?,
            (
                Kind::Discover {
                    source,
                    provider,
                    internal,
                    port,
                    protocol,
                    ..
                },
                Ok(Output::Selected(_)),
            ) => {
                if self.jobs.len() >= self.settings.jobs {
                    return Err(Fault::WouldBlock.into());
                }
                row.future = None;
                let Some(Ok(Output::Selected(report))) = row.result.take() else {
                    return Err(Fault::Conflict.into());
                };
                let (selected, failures) = report.into_parts();
                for failure in failures {
                    observe(Event::Failed {
                        job: row.id,
                        source: Some(*source),
                        error: Box::new(failure),
                    });
                }
                let selected = selected.map_err(|error| Box::new(SharedUpnp(error)) as Failure)?;
                let device = selected.into_device();
                let intent = Intent {
                    source: *source,
                    provider: *provider,
                    device,
                    internal: *internal,
                    port: *port,
                    protocol: *protocol,
                };
                self.add(intent, row.bounds)?;
            }
            (Kind::Add { intent, .. }, Ok(Output::Mapped { mapping, external })) => {
                if self.leases.len() >= self.settings.mappings {
                    return Err(Fault::Capacity.into());
                }
                self.leases.try_reserve(1).map_err(|_| Fault::Capacity)?;
                let valid_until = Due::after(
                    &*self.clock,
                    self.settings.mapping_interval + self.settings.job_timeout,
                )?;
                if let Ok(ip) = external {
                    self.core.publish_snapshot(
                        intent.provider,
                        &[Advertised {
                            address: SocketAddress::V4 {
                                ip: ip.octets(),
                                port: mapping.external_port(),
                            },
                            class: mapping_class(SocketAddress::V4 {
                                ip: ip.octets(),
                                port: mapping.external_port(),
                            }),
                        }],
                        Some(valid_until.absolute),
                        now,
                    )?;
                } else if let Err(error) = external {
                    observe(Event::Failed {
                        job: row.id,
                        source: Some(intent.source),
                        error: Box::new(SharedUpnp(error.clone())),
                    });
                }
                let id = self.serial()?;
                let next = Due::after(&*self.clock, self.settings.mapping_interval)?;
                let Some(Ok(Output::Mapped { mapping, .. })) = row.result.take() else {
                    return Err(Fault::Conflict.into());
                };
                self.leases.push(Lease {
                    id,
                    intent: intent.clone(),
                    mapping: *mapping,
                    next,
                    valid_until,
                    valid: true,
                });
            }
            (Kind::Refresh { lease, intent, .. }, Ok(Output::Refreshed { present, external })) => {
                let index = self
                    .leases
                    .iter()
                    .position(|l| l.id == *lease)
                    .ok_or(Fault::StaleGeneration)?;
                if *present {
                    let until = Due::after(
                        &*self.clock,
                        self.settings.mapping_interval + self.settings.job_timeout,
                    )?;
                    if let Some(ip) = external {
                        self.core.publish_snapshot(
                            intent.provider,
                            &[Advertised {
                                address: SocketAddress::V4 {
                                    ip: ip.octets(),
                                    port: intent.port,
                                },
                                class: mapping_class(SocketAddress::V4 {
                                    ip: ip.octets(),
                                    port: intent.port,
                                }),
                            }],
                            Some(until.absolute),
                            now,
                        )?;
                    }
                    self.leases[index].valid_until = until;
                    self.leases[index].valid = true;
                    self.leases[index].next =
                        Due::after(&*self.clock, self.settings.mapping_interval)?;
                } else {
                    self.core
                        .publish_snapshot(intent.provider, &[], None, now)?;
                    let old = self.leases.swap_remove(index);
                    self.add(
                        old.intent,
                        Bounds::after(&*self.clock, self.settings.job_timeout)?,
                    )?;
                }
            }
            (Kind::Delete { intent, origin, .. }, Ok(Output::Deleted(removal))) => {
                self.unresolved = self.unresolved.saturating_add(usize::from(observe_cleanup(
                    intent,
                    *origin,
                    Some(*removal),
                    observe,
                )));
            }
            (Kind::External, Ok(Output::External(ip))) => {
                self.publish_fresh(
                    self.external_provider,
                    &[Advertised {
                        address: SocketAddress::V4 {
                            ip: ip.octets(),
                            port: 0,
                        },
                        class: AddressClass::GLOBAL,
                    }],
                    self.settings.stun_stale,
                )?;
            }
            _ => return Err(Fault::Conflict.into()),
        }
        Ok(true)
    }
    fn helper_event(
        &mut self,
        event: crate::helpers::Event,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Failure> {
        match &event {
            crate::helpers::Event::Observation {
                helper,
                local,
                remote,
                port,
            } => {
                if self
                    .interfaces
                    .iter()
                    .any(|i| i.local == *local && i.helper == Some(*helper))
                {
                    self.core
                        .reversal_observed(self.interface_provider, *local, *remote, *port)?;
                }
            }
            crate::helpers::Event::Exited { helper, .. }
            | crate::helpers::Event::RetirementUnknown { helper, .. } => {
                if let Some(i) = self
                    .interfaces
                    .iter_mut()
                    .find(|i| i.helper == Some(*helper))
                {
                    i.helper = None;
                    i.retry = if self.stopping {
                        None
                    } else {
                        Instant::now().checked_add(i.backoff)
                    };
                    i.backoff = (i.backoff * 2).min(Duration::from_secs(60));
                }
            }
            _ => {}
        }
        observe(Event::Helper(event));
        Ok(())
    }
    /// Enforce/arm native job/provider/helper bounds even while canonical source
    /// stabilization is Pending. This never samples a fictitious logical now.
    pub fn poll_native(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event),
    ) -> Result<(), Failure> {
        if let Some(e) = self.helpers.poll_native(cx) {
            self.helper_event(e, observe)?;
        }
        let now = Instant::now();
        let mut i = 0;
        while i < self.jobs.len() {
            if self.jobs[i].bounds.hard <= now {
                let row = self.jobs.swap_remove(i);
                self.job_failure(row, Fault::Deadline.into(), observe)?;
            } else {
                i += 1;
            }
        }
        let mut i = 0;
        while i < self.cleanup_queue.len() {
            if self.cleanup_queue[i].bounds.hard <= now {
                let cleanup = self.cleanup_queue.remove(i).ok_or(Fault::Stale)?;
                self.unresolved = self.unresolved.saturating_add(1);
                observe(Event::MappingUnknown {
                    source: cleanup.intent.source,
                    port: cleanup.intent.port,
                });
                observe(Event::Failed {
                    job: 0,
                    source: Some(cleanup.intent.source),
                    error: Fault::Deadline.into(),
                });
            } else {
                i += 1;
            }
        }
        let mut due: Option<Instant> = None;
        let mut include = |value: Instant| {
            if value > now {
                due = Some(due.map_or(value, |old| old.min(value)));
            }
        };
        for j in &self.jobs {
            include(j.bounds.hard);
        }
        for c in &self.cleanup_queue {
            include(c.bounds.hard);
        }
        for f in &self.fresh {
            include(f.until.native);
        }
        for l in &self.leases {
            if l.valid {
                include(l.valid_until.native);
            }
            if !self.stopping {
                include(l.next.native);
            }
        }
        if !self.stopping {
            if self.settings.enable_ipscan {
                include(self.next_scan.native);
            }
            if self.settings.use_stun && !self.settings.stun_servers.is_empty() {
                include(self.next_external.native);
            }
            for i in &self.interfaces {
                if let Some(t) = i.retry {
                    include(t);
                }
            }
            for c in &self.clients {
                if let Some(t) = c.next_mapping {
                    include(t.native);
                }
                if let Some(t) = c.next_dns {
                    include(t.native);
                }
            }
        }
        if let Some(due) = due {
            self.timer.as_mut().reset(due);
            let _wake = self.timer.as_mut().poll(cx);
        }
        Ok(())
    }
    fn poll_clock(&mut self, cx: &mut Context<'_>) -> Poll<Result<u64, Failure>> {
        match self.subscription.poll_changed(cx, self.revision) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(s)) => self.revision = s.revision,
            Poll::Pending => {}
        }
        let sample = self.clock.sample()?;
        match self.subscription.poll_changed(cx, sample.revision) {
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Ready(Ok(_)) => {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Poll::Pending => {
                self.revision = sample.revision;
                Poll::Ready(Ok(sample.now.as_micros()))
            }
        }
    }
    /// Establish actual freshness removals before native notifications/writes. Queue exhaustion fails closed instead of sending an expired queued address.
    pub fn maintain(&mut self, now: u64) -> Result<(), Failure> {
        let mut i = 0;
        while i < self.fresh.len() {
            if self.fresh[i].until.reached(now) {
                let provider = self.fresh[i].provider;
                self.core.publish_snapshot(provider, &[], None, now)?;
                self.fresh.swap_remove(i);
                if self.stun.iter().any(|(_, p)| *p == provider) {
                    self.core.provider_stopped(provider, now)?;
                    self.stun.retain(|(_, p)| *p != provider);
                }
            } else {
                i += 1;
            }
        }
        for i in 0..self.leases.len() {
            if self.leases[i].valid && self.leases[i].valid_until.reached(now) {
                self.core
                    .publish_snapshot(self.leases[i].intent.provider, &[], None, now)?;
                self.leases[i].valid = false;
            }
        }
        self.core.expire(now)?;
        Ok(())
    }
    /// Whether this exact queued add still belongs to the committed effective set.
    pub fn advertised(&self, source: Source, value: Advertised) -> bool {
        self.core
            .registration(source)
            .ok()
            .flatten()
            .is_some_and(|r| r.advertised.contains(&value))
    }
    /// One finite actual state/IO turn. Nothing spawns in the background.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event),
    ) -> Poll<Result<(), Failure>> {
        self.poll_native(cx, observe)?;
        let now = match self.poll_clock(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(n)) => n,
        };
        self.maintain(now)?;
        if !self.helper_first
            && let Poll::Ready(event) = self.helpers.poll(cx, Some(now))
        {
            self.helper_first = true;
            self.helper_event(event, observe)?;
            return Poll::Ready(Ok(()));
        }

        for n in 0..self.jobs.len() {
            let i = (self.cursor + n) % self.jobs.len();
            if self.jobs[i].result.is_none() {
                let result = self.jobs[i]
                    .future
                    .as_mut()
                    .ok_or(Fault::Stale)?
                    .as_mut()
                    .poll(cx);
                if let Poll::Ready(result) = result {
                    self.jobs[i].future = None;
                    self.jobs[i].result = Some(result);
                }
            }
            if self.jobs[i].result.is_some() {
                let mut row = self.jobs.swap_remove(i);
                match self.complete(&mut row, now, observe) {
                    Err(e) if e.downcast_ref::<Fault>() == Some(&Fault::WouldBlock) => {
                        self.jobs.push(row);
                        return Poll::Pending;
                    }
                    Err(error) => self.job_failure(row, error, observe)?,
                    Ok(false) => self.jobs.push(row),
                    Ok(true) => {
                        if let Some(Err(error)) = row.result.take() {
                            self.job_failure(row, error, observe)?;
                        }
                    }
                }
                self.cursor = if self.jobs.is_empty() {
                    0
                } else {
                    i % self.jobs.len()
                };
                self.helper_first = false;
                return Poll::Ready(Ok(()));
            }
        }
        if !self.cleanup_queue.is_empty() && self.jobs.len() < self.settings.jobs {
            let cleanup = self.cleanup_queue.pop_front().ok_or(Fault::Stale)?;
            let source = cleanup.intent.source;
            let port = cleanup.intent.port;
            if let Err(error) = self.start_cleanup(
                cleanup.intent,
                cleanup.ownership,
                cleanup.origin,
                cleanup.bounds,
            ) {
                self.unresolved = self.unresolved.saturating_add(1);
                observe(Event::MappingUnknown { source, port });
                observe(Event::Failed {
                    job: 0,
                    source: Some(source),
                    error,
                });
            }
            return Poll::Ready(Ok(()));
        }
        if self.stopping {
            return Poll::Pending;
        }
        if self.settings.enable_ipscan && self.next_scan.reached(now) {
            self.next_scan = Due::after(&*self.clock, self.settings.interface_interval)?;
            if let Err(error) = self.scan(observe) {
                observe(Event::Failed {
                    job: 0,
                    source: None,
                    error,
                });
            }
            return Poll::Ready(Ok(()));
        }
        for i in 0..self.interfaces.len() {
            if self.interfaces[i].helper.is_none()
                && self.interfaces[i]
                    .retry
                    .is_some_and(|t| Instant::now() >= t)
            {
                let local = self.interfaces[i].local;
                match self.helpers.start_server(local) {
                    Ok(h) => {
                        self.interfaces[i].helper = Some(h);
                        self.interfaces[i].retry = None;
                    }
                    Err(error) => {
                        self.interfaces[i].retry =
                            Instant::now().checked_add(self.interfaces[i].backoff);
                        self.interfaces[i].backoff =
                            (self.interfaces[i].backoff * 2).min(Duration::from_secs(60));
                        observe(Event::Failed {
                            job: 0,
                            source: None,
                            error: error.into(),
                        });
                    }
                }
                return Poll::Ready(Ok(()));
            }
        }
        for i in 0..self.clients.len() {
            let source = self.clients[i].source;
            if self.clients[i].next_dns.is_some_and(|d| d.reached(now))
                && !self
                    .jobs
                    .iter()
                    .any(|j| matches!(j.kind,Kind::Dns{source:s,..}if s==source))
            {
                self.clients[i].next_dns =
                    Some(Due::after(&*self.clock, self.settings.dyndns_interval)?);
                if let Err(error) = self.dns(i) {
                    observe(Event::Failed {
                        job: 0,
                        source: Some(source),
                        error,
                    });
                }
                return Poll::Ready(Ok(()));
            }
        }
        for i in 0..self.clients.len() {
            if self.clients[i].next_mapping.is_some_and(|d| d.reached(now)) {
                let source = self.clients[i].source;
                self.clients[i].next_mapping =
                    Some(Due::after(&*self.clock, self.settings.mapping_interval)?);
                if let Some(r) = self.core.registration(source)? {
                    let protocol = match r.protocol {
                        6 => Some(Protocol::Tcp),
                        17 => Some(Protocol::Udp),
                        _ => None,
                    };
                    let bindings = r.bindings.to_vec();
                    if let Some(protocol) = protocol {
                        for b in bindings {
                            if let SocketAddress::V4 { ip, port } = b {
                                if port == 0 {
                                    continue;
                                }
                                let locals: Vec<_> = if ip == [0; 4] {
                                    self.interfaces.iter().map(|i| i.local).collect()
                                } else if b.is_private() {
                                    vec![ip]
                                } else {
                                    Vec::new()
                                };
                                for ip in locals {
                                    if let Err(error) =
                                        self.start_discover(source, ip.into(), port, protocol)
                                    {
                                        observe(Event::Failed {
                                            job: 0,
                                            source: Some(source),
                                            error,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
                return Poll::Ready(Ok(()));
            }
        }
        for i in 0..self.leases.len() {
            let id = self.leases[i].id;
            if self.leases[i].next.reached(now)
                && !self
                    .jobs
                    .iter()
                    .any(|j| matches!(j.kind,Kind::Refresh{lease,..}if lease==id))
            {
                self.leases[i].next = Due::after(&*self.clock, self.settings.mapping_interval)?;
                if let Err(error) = self.refresh(i) {
                    observe(Event::Failed {
                        job: 0,
                        source: Some(self.leases[i].intent.source),
                        error,
                    });
                }
                return Poll::Ready(Ok(()));
            }
        }
        if self.settings.use_stun
            && !self.settings.stun_servers.is_empty()
            && self.next_external.reached(now)
            && !self.jobs.iter().any(|j| matches!(j.kind, Kind::External))
        {
            self.next_external = Due::after(&*self.clock, self.settings.stun_interval)?;
            if let Err(error) = self.external() {
                observe(Event::Failed {
                    job: 0,
                    source: None,
                    error,
                });
            }
            return Poll::Ready(Ok(()));
        }
        if let Poll::Ready(event) = self.helpers.poll(cx, Some(now)) {
            self.helper_event(event, observe)?;
            self.helper_first = true;
            return Poll::Ready(Ok(()));
        }
        Poll::Pending
    }
    /// Begin actual shutdown: retire original source ownership, cancel jobs,
    /// queue real deletes and physically stop children. No successful delete or
    /// wait is fabricated; caller keeps polling until pending iszero or hard cap.
    pub fn shutdown(&mut self, observe: &mut impl FnMut(Event)) -> Result<(), Failure> {
        self.stopping = true;
        while let Some(source) = self.clients.last().map(|c| c.source) {
            self.source_stopped(source, observe)?;
        }
        self.helpers.stop_all();
        let mut i = 0;
        while i < self.jobs.len() {
            if matches!(self.jobs[i].kind, Kind::Delete { .. }) {
                i += 1;
            } else {
                let row = self.jobs.swap_remove(i);
                self.job_failure(row, Fault::Cancelled.into(), observe)?;
            }
        }
        Ok(())
    }
    /// Clock/port failure emergency physical stop. It starts no replacement
    /// network cleanup when the clock cannot authorize an original operation.
    pub fn abort(&mut self, observe: &mut impl FnMut(Event)) {
        self.stopping = true;
        self.helpers.stop_all();
        for cleanup in self.cleanup_queue.drain(..) {
            self.unresolved = self.unresolved.saturating_add(1);
            observe(Event::MappingUnknown {
                source: cleanup.intent.source,
                port: cleanup.intent.port,
            });
        }
        for mut row in self.jobs.drain(..) {
            retire_reads(&mut row, observe);
            if let Kind::Delete {
                intent,
                origin,
                attempt,
            } = &row.kind
            {
                self.unresolved = self.unresolved.saturating_add(usize::from(observe_cleanup(
                    intent,
                    *origin,
                    attempt.removal(),
                    observe,
                )));
            }
            if let Kind::Add { intent: i, attempt } = row.kind
                && CleanupOrigin::from_add(attempt.outcome()).is_some()
            {
                self.unresolved = self.unresolved.saturating_add(1);
                observe(Event::MappingUnknown {
                    source: i.source,
                    port: i.port,
                });
            }
        }
        for lease in self.leases.drain(..) {
            self.unresolved = self.unresolved.saturating_add(1);
            observe(Event::MappingUnknown {
                source: lease.intent.source,
                port: lease.intent.port,
            });
        }
    }
}
