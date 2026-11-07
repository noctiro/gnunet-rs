//! Bounded NAT service business state. Providers supply actual interface,
//! resolver, STUN or mapping observations; intent/worker completion alone does
//! not add an address. Notifications are a bounded queue on original sources.
use crate::{
    Error,
    address::{SocketAddress, select},
};
use alloc::{collections::VecDeque, string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use gnunet_wire::official::nat::{self, AddressClass};
static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);
/// Resource bounds include both committed state and a bounded transactional
/// recomputation workspace. No Internet data silently grows these tables.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum accepted original service connections.
    pub sources: usize,
    /// Maximum Internet bindings in each registration.
    pub bindings_per_source: usize,
    /// Maximum UTF-8 configuration section bytes, excluding final NUL.
    pub section_bytes: usize,
    /// Maximum original provider leases (interfaces/STUN/mappings/resolvers).
    pub providers: usize,
    /// Maximum addresses in one real provider snapshot.
    pub addresses_per_provider: usize,
    /// Maximum effective addresses per registration.
    pub advertised_per_source: usize,
    /// Maximum pending notification metadata; no frame payload duplicates.
    pub events: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            sources: 128,
            bindings_per_source: 64,
            section_bytes: 256,
            providers: 256,
            addresses_per_provider: 128,
            advertised_per_source: 512,
            events: 4096,
        }
    }
}
/// An original accepted connection; private fields prevent cross-Core forgery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Source {
    instance: u64,
    serial: u64,
}
impl Source {
    /// Process-local serial for diagnostics, never a wire request id.
    pub const fn serial(self) -> u64 {
        self.serial
    }
}
/// One original address-discovery or mapping provider generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Provider {
    instance: u64,
    serial: u64,
}
impl Provider {
    /// Process-local original provider generation.
    pub const fn serial(self) -> u64 {
        self.serial
    }
}
/// Registration-specific configuration loaded from the real requested section.
#[derive(Clone, Copy, Debug, Default)]
pub struct Options {
    /// Include loopback/link-local addresses for wildcard binds.
    pub return_local_addresses: bool,
    /// Effective DISABLEV6 policy.
    pub disable_v6: bool,
    /// HOLE_EXTERNAL=AUTO port, if explicitly configured.
    pub auto_external_port: Option<u16>,
}
/// Borrowed original registration and its resolved configuration policy.
#[derive(Clone, Copy, Debug)]
pub struct RegistrationInput<'a> {
    /// Original notification flags.
    pub flags: u8,
    /// Original Internet protocol number.
    pub protocol: u8,
    /// Original bounded configuration section bytes.
    pub section: &'a [u8],
    /// Original decoded Internet bindings.
    pub bindings: &'a [SocketAddress],
    /// Actual policy resolved for this registration.
    pub options: Options,
}
/// Actual address plus its advertised classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Advertised {
    /// Actual discovered endpoint.
    pub address: SocketAddress,
    /// Original/provider class bits.
    pub class: AddressClass,
}
/// Which external action supplied a provider. Creating a provider is only
/// a lease: its address set remains empty until publish_snapshot succeeds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderKind {
    /// Actual local interface snapshot. Class is supplied per observation.
    Interface,
    /// Literal or actually resolved HOLE_EXTERNAL addresses for this source.
    Manual(Source),
    /// Actual host external-IP monitor; only AUTO-configured registrations use it.
    ExternalIp,
    /// Actual STUN response/global-IPv4 hint. This is an unauthenticated claim;
    /// official NAT advertises it with port0 to NAT-bound clients of any protocol.
    Stun,
    /// Actually installed mapping, restricted to its original registration,
    /// protocol and internal endpoint. The supplied endpoint has its mapped port.
    Mapping {
        /// Original registration source.
        source: Source,
        /// Original TCP6/UDP17 protocol.
        protocol: u8,
        /// Original internal binding being mapped.
        internal: SocketAddress,
    },
}
/// One address/reversal notification on its original service connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Event {
    /// Original service source; never retarget to a reconnect.
    pub source: Source,
    /// Actual state change or received reversal observation.
    pub kind: EventKind,
}
/// There is no generic ACK or fabricated provider-success notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EventKind {
    /// Exact effective advertised-set delta.
    AddressChange {
        /// True only when the address enters the set.
        added: bool,
        /// Address and class of this exact lease.
        value: Advertised,
    },
    /// Original helper's unauthenticated, nonzero-port reverse-connect observation.
    Reverse {
        /// Actual remote endpoint extracted from ICMP.
        remote: SocketAddress,
    },
}
struct Registration {
    flags: u8,
    protocol: u8,
    section: String,
    bindings: Vec<SocketAddress>,
    options: Options,
    advertised: Vec<Advertised>,
}
struct SourceRow {
    source: Source,
    registration: Option<Registration>,
}
struct ProviderRow {
    provider: Provider,
    kind: ProviderKind,
    addresses: Vec<Advertised>,
    expires: Option<u64>,
}
/// Read-only original registration, including the real committed address set.
#[derive(Clone, Copy, Debug)]
pub struct RegistrationView<'a> {
    /// Original notification flags.
    pub flags: u8,
    /// Original IP protocol.
    pub protocol: u8,
    /// Actual configuration section.
    pub section: &'a str,
    /// Original Internet bindings (Unix bindings cause no Internet discovery).
    pub bindings: &'a [SocketAddress],
    /// Effective loaded registration options.
    pub options: Options,
    /// Last committed effective address set; poll expire before publishing it.
    pub advertised: &'a [Advertised],
}
/// Checked plan for the real outgoing helper. It is not a success/ACK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Reversal {
    /// Original requesting service source.
    pub source: Source,
    /// Caller-supplied local IPv4 for the raw source header.
    pub local: [u8; 4],
    /// Original external IPv4 destination.
    pub remote: [u8; 4],
    /// Original advertised local port.
    pub port: u16,
}
struct Plan {
    sets: Vec<(Source, Vec<Advertised>)>,
    events: Vec<Event>,
}
enum Override<'a> {
    None,
    Replace(Provider, &'a [Advertised], Option<u64>),
    Remove(Provider),
}
/// Pure business owner. Native code must enforce independent finite hard
/// deadlines, accept canonical logical clock adjustments without renewing them,
/// stop original resources on clock failure, and call expire before
/// draining events. This type neither opens sockets nor claims external IO.
pub struct Core {
    instance: u64,
    next: u64,
    limits: Limits,
    sources: Vec<SourceRow>,
    providers: Vec<ProviderRow>,
    events: VecDeque<Event>,
}
fn reserve<T>(v: &mut Vec<T>, n: usize) -> Result<(), Error> {
    v.try_reserve_exact(n).map_err(|_| Error::Capacity)
}
fn owned<T: Copy>(input: &[T]) -> Result<Vec<T>, Error> {
    let mut v = Vec::new();
    reserve(&mut v, input.len())?;
    v.extend_from_slice(input);
    Ok(v)
}
impl Core {
    /// Create an independent bounded owner; instance exhaustion fails closed.
    pub fn new(limits: Limits) -> Result<Self, Error> {
        if limits.sources == 0
            || limits.events == 0
            || limits.providers == 0
            || limits.advertised_per_source == 0
        {
            return Err(Error::InvalidInput);
        }
        let instance = NEXT_INSTANCE
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| Error::Overflow)?;
        Ok(Self {
            instance,
            next: 1,
            limits,
            sources: Vec::new(),
            providers: Vec::new(),
            events: VecDeque::new(),
        })
    }
    fn serial(&mut self) -> Result<u64, Error> {
        let n = self.next;
        self.next = n.checked_add(1).ok_or(Error::Overflow)?;
        Ok(n)
    }
    fn source_index(&self, s: Source) -> Result<usize, Error> {
        if s.instance != self.instance {
            return Err(Error::StaleGeneration);
        }
        self.sources
            .iter()
            .position(|r| r.source == s)
            .ok_or(Error::StaleGeneration)
    }
    fn provider_index(&self, p: Provider) -> Result<usize, Error> {
        if p.instance != self.instance {
            return Err(Error::StaleGeneration);
        }
        self.providers
            .iter()
            .position(|r| r.provider == p)
            .ok_or(Error::StaleGeneration)
    }
    /// Admit only after an actual accepted MQ. No registration/ready is implied.
    pub fn source_attached(&mut self) -> Result<Source, Error> {
        if self.sources.len() >= self.limits.sources {
            return Err(Error::Capacity);
        }
        reserve(&mut self.sources, 1)?;
        let source = Source {
            instance: self.instance,
            serial: self.serial()?,
        };
        self.sources.push(SourceRow {
            source,
            registration: None,
        });
        Ok(source)
    }
    /// Install the original registration exactly once, after the actual section
    /// has been resolved. Caller decodes native sockaddr ABI before this call.
    /// Unix bindings are accepted by IPC but deliberately omitted from Internet
    /// discovery. A zero-address registration remains valid and can receive
    /// explicit reversal observations when requested.
    pub fn register(
        &mut self,
        source: Source,
        input: RegistrationInput<'_>,
        now: u64,
    ) -> Result<(), Error> {
        let RegistrationInput {
            flags,
            protocol,
            section,
            bindings,
            options,
        } = input;
        let i = self.source_index(source)?;
        if self.sources[i].registration.is_some() {
            return Err(Error::Conflict);
        }
        // TRANSPORT uses protocol 0 for its ordinary reversal subscription.
        // Mapping providers select TCP/UDP separately from this metadata.
        if flags & !(nat::ADDRESSES | nat::REVERSAL) != 0
            || bindings.len() > self.limits.bindings_per_source
        {
            return Err(Error::InvalidInput);
        }
        let section = section.split(|&b| b == 0).next().unwrap_or(&[]);
        if section.len() > self.limits.section_bytes {
            return Err(Error::TooLarge);
        }
        let section = core::str::from_utf8(section).map_err(|_| Error::Malformed)?;
        let mut name = String::new();
        name.try_reserve_exact(section.len())
            .map_err(|_| Error::Capacity)?;
        name.push_str(section);
        let mut r = Registration {
            flags,
            protocol,
            section: name,
            bindings: owned(bindings)?,
            options,
            advertised: Vec::new(),
        };
        let desired = self.desired(&r, source, now, &Override::None)?;
        let mut events = Vec::new();
        reserve(&mut events, desired.len())?;
        for &value in &desired {
            events.push(Event {
                source,
                kind: EventKind::AddressChange { added: true, value },
            });
        }
        self.reserve_events(events.len())?;
        r.advertised = desired;
        self.sources[i].registration = Some(r);
        self.events.extend(events);
        Ok(())
    }
    /// Original registration without hidden mutation or a synthetic INIT marker.
    pub fn registration(&self, source: Source) -> Result<Option<RegistrationView<'_>>, Error> {
        let i = self.source_index(source)?;
        Ok(self.sources[i]
            .registration
            .as_ref()
            .map(|r| RegistrationView {
                flags: r.flags,
                protocol: r.protocol,
                section: &r.section,
                bindings: &r.bindings,
                options: r.options,
                advertised: &r.advertised,
            }))
    }
    /// Mint a new original provider lease. Superseded workers must never reuse
    /// this handle for a retry/reconnect; retired results fail generation checks.
    pub fn provider_started(&mut self, kind: ProviderKind) -> Result<Provider, Error> {
        match kind {
            ProviderKind::Manual(source) | ProviderKind::Mapping { source, .. } => {
                let i = self.source_index(source)?;
                if self.sources[i].registration.is_none() {
                    return Err(Error::NotReady);
                }
            }
            _ => {}
        }
        if self.providers.len() >= self.limits.providers {
            return Err(Error::Capacity);
        }
        reserve(&mut self.providers, 1)?;
        let provider = Provider {
            instance: self.instance,
            serial: self.serial()?,
        };
        self.providers.push(ProviderRow {
            provider,
            kind,
            addresses: Vec::new(),
            expires: None,
        });
        Ok(provider)
    }
    /// Atomically replace an original provider's actual observed snapshot and
    /// its original finite freshness deadline. Backpressure leaves committed
    /// provider/address state unchanged; the caller retains the original input.
    pub fn publish_snapshot(
        &mut self,
        provider: Provider,
        addresses: &[Advertised],
        expires: Option<u64>,
        now: u64,
    ) -> Result<(), Error> {
        let index = self.provider_index(provider)?;
        if addresses.len() > self.limits.addresses_per_provider {
            return Err(Error::Capacity);
        }
        if expires.is_some_and(|n| n <= now) {
            return Err(Error::Deadline);
        }
        for a in addresses {
            if a.address.is_unspecified() {
                return Err(Error::InvalidInput);
            }
        }
        let addresses = owned(addresses)?;
        let plan = self.plan(now, Override::Replace(provider, &addresses, expires))?;
        self.reserve_events(plan.events.len())?;
        self.providers[index].addresses = addresses;
        self.providers[index].expires = expires;
        self.commit(plan);
        Ok(())
    }
    /// Retire only the original provider after its real host action/resource is
    /// stopped. Its final removals are committed before this handle is forgotten.
    pub fn provider_stopped(&mut self, provider: Provider, now: u64) -> Result<(), Error> {
        let i = self.provider_index(provider)?;
        let plan = self.plan(now, Override::Remove(provider))?;
        self.reserve_events(plan.events.len())?;
        self.providers.swap_remove(i);
        self.commit(plan);
        Ok(())
    }
    /// Explicit freshness expiration. Never refreshes an original deadline.
    /// If downstream capacity is exhausted, close that actual source and retry;
    /// do not send a stale address or busy-poll this method.
    pub fn expire(&mut self, now: u64) -> Result<(), Error> {
        if !self
            .providers
            .iter()
            .any(|p| p.expires.is_some_and(|n| n <= now))
        {
            return Ok(());
        }
        let plan = self.plan(now, Override::None)?;
        self.reserve_events(plan.events.len())?;
        for p in &mut self.providers {
            if p.expires.is_some_and(|n| n <= now) {
                p.addresses.clear();
                p.expires = None;
            }
        }
        self.commit(plan);
        Ok(())
    }
    /// Earliest committed provider expiry, for one native timer registration.
    pub fn next_deadline(&self) -> Option<u64> {
        self.providers.iter().filter_map(|p| p.expires).min()
    }
    /// Consume one original notification after native expiration preflight.
    pub fn take_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }
    /// Current queued notification metadata count.
    pub fn pending_events(&self) -> usize {
        self.events.len()
    }
    /// True if one committed effective endpoint matches, including port/scope/flow. Native clients retain original padding for the exact C bytewise check.
    pub fn test_address(&self, source: Source, address: SocketAddress) -> Result<bool, Error> {
        Ok(self
            .registration(source)?
            .is_some_and(|r| r.advertised.iter().any(|a| a.address == address)))
    }
    /// Validate the actual one-shot reversal request. It returns only helper
    /// inputs, never an invented wire response or a remote-connect success.
    pub fn request_reversal(
        &self,
        source: Source,
        local: SocketAddress,
        remote: SocketAddress,
    ) -> Result<Reversal, Error> {
        self.registration(source)?.ok_or(Error::NotReady)?;
        let (SocketAddress::V4 { ip: local_ip, port }, SocketAddress::V4 { ip: remote_ip, .. }) =
            (local, remote)
        else {
            return Err(Error::Unsupported);
        };
        if port == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(Reversal {
            source,
            local: local_ip,
            remote: remote_ip,
            port,
        })
    }
    /// Publish a real original helper's nonzero-port observation to interested
    /// NAT registrations on that local IPv4. This remains unauthenticated data.
    pub fn reversal_observed(
        &mut self,
        provider: Provider,
        local: [u8; 4],
        remote: [u8; 4],
        port: u16,
    ) -> Result<(), Error> {
        let p = &self.providers[self.provider_index(provider)?];
        if p.kind != ProviderKind::Interface {
            return Err(Error::PermissionDenied);
        }
        if !p
            .addresses
            .iter()
            .any(|a| matches!(a.address,SocketAddress::V4{ip,..}if ip==local))
        {
            return Err(Error::StaleGeneration);
        }
        if port == 0 {
            return Ok(());
        }
        let mut targets = Vec::new();
        for row in &self.sources {
            let Some(r) = &row.registration else {
                continue;
            };
            if r.flags & nat::REVERSAL == 0 {
                continue;
            }
            if (r.bindings.is_empty()
                || r.bindings
                    .iter()
                    .any(|b| matches!(b,SocketAddress::V4{ip,..}if *ip==[0;4]||*ip==local)))
                && (r.bindings.is_empty()
                    || r.bindings
                        .iter()
                        .any(|b| b.is_unspecified() || b.is_private()))
            {
                reserve(&mut targets, 1)?;
                targets.push(Event {
                    source: row.source,
                    kind: EventKind::Reverse {
                        remote: SocketAddress::V4 { ip: remote, port },
                    },
                });
            }
        }
        self.reserve_events(targets.len())?;
        self.events.extend(targets);
        Ok(())
    }
    /// Physical source loss. Only this connection and its scoped providers are
    /// retired; other registrations and global discovery sources remain valid.
    /// Pending events on the dead original MQ are removed, never rehomed.
    pub fn source_stopped(&mut self, source: Source) -> Result<(), Error> {
        let i = self.source_index(source)?;
        self.sources.swap_remove(i);
        self.providers.retain(|p|!matches!(p.kind,ProviderKind::Manual(s)|ProviderKind::Mapping{source:s,..}if s==source));
        self.events.retain(|e| e.source != source);
        Ok(())
    }
    fn reserve_events(&mut self, n: usize) -> Result<(), Error> {
        if n > self.limits.events.saturating_sub(self.events.len()) {
            return Err(Error::WouldBlock);
        }
        self.events.try_reserve(n).map_err(|_| Error::Capacity)
    }
    fn commit(&mut self, plan: Plan) {
        for (s, set) in plan.sets {
            if let Some(r) = self
                .sources
                .iter_mut()
                .find(|r| r.source == s)
                .and_then(|r| r.registration.as_mut())
            {
                r.advertised = set;
            }
        }
        self.events.extend(plan.events);
    }
    fn plan(&self, now: u64, override_: Override<'_>) -> Result<Plan, Error> {
        let mut sets = Vec::new();
        let mut events = Vec::new();
        reserve(&mut sets, self.sources.len())?;
        for row in &self.sources {
            let Some(r) = &row.registration else {
                continue;
            };
            let desired = self.desired(r, row.source, now, &override_)?;
            for &value in &r.advertised {
                if !desired.contains(&value) {
                    if events.len() >= self.limits.events {
                        return Err(Error::WouldBlock);
                    }
                    reserve(&mut events, 1)?;
                    events.push(Event {
                        source: row.source,
                        kind: EventKind::AddressChange {
                            added: false,
                            value,
                        },
                    });
                }
            }
            for &value in &desired {
                if !r.advertised.contains(&value) {
                    if events.len() >= self.limits.events {
                        return Err(Error::WouldBlock);
                    }
                    reserve(&mut events, 1)?;
                    events.push(Event {
                        source: row.source,
                        kind: EventKind::AddressChange { added: true, value },
                    });
                }
            }
            sets.push((row.source, desired));
        }
        Ok(Plan { sets, events })
    }
    fn desired(
        &self,
        r: &Registration,
        source: Source,
        now: u64,
        override_: &Override<'_>,
    ) -> Result<Vec<Advertised>, Error> {
        let mut out = Vec::new();
        if r.flags & nat::ADDRESSES == 0 {
            return Ok(out);
        }
        for p in &self.providers {
            let (addresses, expires) = match override_ {
                Override::Remove(id) if *id == p.provider => continue,
                Override::Replace(id, a, e) if *id == p.provider => (*a, *e),
                _ => (&p.addresses[..], p.expires),
            };
            if expires.is_some_and(|n| n <= now) {
                continue;
            }
            for &a in addresses {
                if r.options.disable_v6 && matches!(a.address, SocketAddress::V6 { .. }) {
                    continue;
                }
                match p.kind {
                    ProviderKind::Manual(owner) if owner != source => continue,
                    ProviderKind::Mapping {
                        source: owner,
                        protocol,
                        internal,
                    } => {
                        if owner != source
                            || r.protocol != protocol
                            || !r.bindings.iter().any(|b| {
                                b.port() == internal.port()
                                    && (b.is_unspecified() || b.same_ip(internal))
                            })
                        {
                            continue;
                        }
                        self.push(
                            &mut out,
                            Advertised {
                                address: a.address,
                                class: a.class,
                            },
                        )?;
                        continue;
                    }
                    ProviderKind::Stun => {
                        if matches!(a.address, SocketAddress::V4 { .. })
                            && r.bindings.iter().any(|b| {
                                matches!(b, SocketAddress::V4 { .. })
                                    && (b.is_unspecified() || b.is_private())
                            })
                        {
                            self.push(
                                &mut out,
                                Advertised {
                                    address: a.address.with_port(0),
                                    class: AddressClass(
                                        AddressClass::EXTERN.0 | AddressClass::GLOBAL.0,
                                    ),
                                },
                            )?;
                        }
                        continue;
                    }
                    ProviderKind::ExternalIp => {
                        let Some(port) = r.options.auto_external_port else {
                            continue;
                        };
                        if matches!(a.address, SocketAddress::V4 { .. })
                            && r.bindings.iter().any(|b| {
                                matches!(b, SocketAddress::V4 { .. })
                                    && (b.is_unspecified() || b.is_private())
                            })
                        {
                            self.push(
                                &mut out,
                                Advertised {
                                    address: a.address.with_port(port),
                                    class: AddressClass(
                                        AddressClass::GLOBAL.0 | AddressClass::MANUAL.0,
                                    ),
                                },
                            )?;
                        }
                        continue;
                    }
                    _ => {}
                }
                for &binding in &r.bindings {
                    if let Some(address) = select(
                        binding,
                        a.address,
                        a.class,
                        r.options.return_local_addresses,
                    ) {
                        self.push(
                            &mut out,
                            Advertised {
                                address,
                                class: a.class,
                            },
                        )?;
                    }
                }
            }
        }
        Ok(out)
    }
    fn push(&self, out: &mut Vec<Advertised>, value: Advertised) -> Result<(), Error> {
        if out.contains(&value) {
            return Ok(());
        }
        if out.len() >= self.limits.advertised_per_source {
            return Err(Error::Capacity);
        }
        reserve(out, 1)?;
        out.push(value);
        Ok(())
    }
}

#[cfg(test)]
mod mapping_scope {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Pure mapping scope assertions use bounded provider transitions, without native discovery claims"
    )]
    fn mapping_provider_preserves_lan_and_external_scope_in_notifications() -> Result<(), Error> {
        let mut core = Core::new(Limits::default())?;
        let source = core.source_attached()?;
        let internal = SocketAddress::V4 {
            ip: [192, 168, 1, 10],
            port: 2086,
        };
        core.register(
            source,
            RegistrationInput {
                flags: nat::ADDRESSES,
                protocol: 6,
                section: b"scope",
                bindings: &[internal],
                options: Options::default(),
            },
            1,
        )?;
        let provider = core.provider_started(ProviderKind::Mapping {
            source,
            protocol: 6,
            internal,
        })?;
        for (ip, class) in [
            ([100, 64, 1, 2], AddressClass::LAN),
            ([8, 8, 8, 8], AddressClass::EXTERN),
        ] {
            let value = Advertised {
                address: SocketAddress::V4 { ip, port: 2086 },
                class,
            };
            core.publish_snapshot(provider, &[value], None, 2)?;
            assert_eq!(
                core.registration(source)?
                    .ok_or(Error::NotReady)?
                    .advertised,
                &[value]
            );
            let mut added = None;
            while let Some(event) = core.take_event() {
                if let EventKind::AddressChange { added: true, value } = event.kind {
                    added = Some(value);
                }
            }
            assert_eq!(added, Some(value));
        }
        Ok(())
    }
}

#[cfg(test)]
mod clock_model {
    use super::*;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Pure public address metadata assertions with fallible bounded setup"
    )]
    fn logical_rollback_preserves_expiry_and_cannot_revive_removed_addresses() -> Result<(), Error>
    {
        let mut core = Core::new(Limits::default())?;
        // These are mock source/provider observations for the pure state contract.
        // They perform no native I/O and confer no provider or discovery credit.
        let source = core.source_attached()?;
        core.register(
            source,
            RegistrationInput {
                flags: nat::ADDRESSES,
                protocol: 17,
                section: b"example",
                bindings: &[SocketAddress::V4 {
                    ip: [0; 4],
                    port: 42,
                }],
                options: Options::default(),
            },
            100,
        )?;
        let provider = core.provider_started(ProviderKind::Interface)?;
        core.publish_snapshot(
            provider,
            &[Advertised {
                address: SocketAddress::V4 {
                    ip: [192, 0, 2, 7],
                    port: 0,
                },
                class: AddressClass::LAN,
            }],
            Some(200),
            100,
        )?;
        assert!(matches!(
            core.take_event(),
            Some(Event {
                kind: EventKind::AddressChange { added: true, .. },
                ..
            })
        ));
        core.expire(50)?;
        assert_eq!(core.next_deadline(), Some(200));
        assert_eq!(
            core.registration(source)?
                .ok_or(Error::NotReady)?
                .advertised
                .len(),
            1
        );
        assert!(core.take_event().is_none());
        core.expire(200)?;
        assert!(matches!(
            core.take_event(),
            Some(Event {
                kind: EventKind::AddressChange { added: false, .. },
                ..
            })
        ));
        core.expire(40)?;
        assert!(
            core.registration(source)?
                .ok_or(Error::NotReady)?
                .advertised
                .is_empty()
        );
        assert!(core.next_deadline().is_none());
        assert!(core.take_event().is_none());
        core.provider_stopped(provider, 40)?;
        assert_eq!(
            core.publish_snapshot(provider, &[], Some(300), 40),
            Err(Error::StaleGeneration)
        );
        Ok(())
    }
}
