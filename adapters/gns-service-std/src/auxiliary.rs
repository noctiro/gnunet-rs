//! Actual ordinary DNS, shared system Resolver and registry effects.
use crate::{
    Bounds, Close, Operation, Provider, Shared, Value,
    native::{Error, Report},
};
use gnunet_gns::EffectKind;
use gnunet_types::{AbsoluteTime, Error as Fault};
use std::{
    marker::PhantomData,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::Instant;
pub mod dns;
pub mod registry;
pub mod system;

pub(super) fn guard(bounds: Bounds) -> Result<(), Fault> {
    if Instant::now() >= bounds.hard() {
        Err(Fault::Timeout)
    } else {
        Ok(())
    }
}
/// Concrete remaining dependency factory. It shares the foreground's original
/// broker Context; its unique Driver remains explicitly outside this owner.
pub struct Auxiliary<'id, const R: usize, const N: usize> {
    system: system::Factory<R, N>,
    dns: dns::RecursiveDns,
    nameservers: NameserverLookup,
    registry: registry::Source,
    closing: bool,
    // Error/report composition only; real query identity is the broker Token.
    lifetime: PhantomData<&'id ()>,
}
/// Select how to resolve hostnames in GNS2DNS records.
#[derive(Clone, Copy, Debug)]
pub enum NameserverLookup {
    /// Resolve through the shared GNUnet Resolver, using its configured policy.
    Resolver,
    /// Resolve through the numeric bootstrap settings of the wire DNS owner.
    WireDns,
}

impl<'id, const R: usize, const N: usize> Auxiliary<'id, R, N> {
    /// Compose prepared genuine capabilities, never a second broker or fake
    /// successful dependency. Both actual factories must share one clock Arc.
    pub fn new(
        system: system::Factory<R, N>,
        dns: dns::RecursiveDns,
        registry: registry::Files,
    ) -> Result<Self, Fault> {
        Self::with_registry(system, dns, Ok(registry))
    }
    /// Compose the same factories while retaining an unavailable files profile.
    /// A Service effect needing OS data receives that original preparation error.
    /// Published GANA mappings remain independently available; missing OS data is
    /// never converted into a successful registry miss.
    pub fn with_registry(
        system: system::Factory<R, N>,
        dns: dns::RecursiveDns,
        registry: Result<registry::Files, Arc<registry::Error>>,
    ) -> Result<Self, Fault> {
        Self::compose(system, dns, || registry::Source::Prepared(registry))
    }

    /// Compose the ordinary platform protocol/service database as a bounded
    /// native worker. Startup failure remains a per-registry observation.
    pub fn with_system_registry(
        system: system::Factory<R, N>,
        dns: dns::RecursiveDns,
    ) -> Result<Self, Fault> {
        Self::compose(system, dns, registry::Source::native)
    }

    /// Optional registry preparation failure known before lookup admission.
    pub fn registry_preparation_error(&self) -> Option<&Arc<registry::Error>> {
        self.registry.preparation_error()
    }

    fn compose(
        system: system::Factory<R, N>,
        dns: dns::RecursiveDns,
        registry: impl FnOnce() -> registry::Source,
    ) -> Result<Self, Fault> {
        if !Arc::ptr_eq(&system.clock(), &dns.clock()) {
            return Err(Fault::InvalidInput);
        }
        Ok(Self {
            system,
            dns,
            nameservers: NameserverLookup::Resolver,
            registry: registry(),
            closing: false,
            lifetime: PhantomData,
        })
    }

    /// Select the address lookup route without changing delegated DNS traffic.
    pub fn with_nameserver_lookup(mut self, lookup: NameserverLookup) -> Self {
        self.nameservers = lookup;
        self
    }
}
enum Inner<'id, const R: usize, const N: usize> {
    System(system::Query<'id, R, N>),
    Dns(dns::Query<'id>),
    Registry(registry::Lookup),
}
/// Original concrete auxiliary operation. No queue/native completion can be
/// reconstructed from caller scalars; each inner operation keeps its own owner.
pub struct Native<'id, const R: usize, const N: usize> {
    inner: Inner<'id, R, N>,
}
impl<'id, const R: usize, const N: usize> Provider for Auxiliary<'id, R, N> {
    type Operation = Native<'id, R, N>;
    fn start(
        &mut self,
        effect: &EffectKind,
        bounds: Bounds,
    ) -> Result<Self::Operation, Error<'id>> {
        guard(bounds)?;
        if self.closing {
            return Err(Fault::Closed.into());
        }
        let inner = match effect {
            EffectKind::System {
                name,
                record_type,
                remaining_steps,
            } => {
                guard(bounds)?;
                Inner::System(
                    self.system
                        .start(name, *record_type, *remaining_steps, bounds)?,
                )
            }
            EffectKind::Nameserver {
                name,
                remaining_steps,
            } => {
                guard(bounds)?;
                match self.nameservers {
                    NameserverLookup::Resolver => Inner::System(self.system.start_nameserver(
                        name,
                        *remaining_steps,
                        bounds,
                        self.dns.server_limit(),
                    )?),
                    NameserverLookup::WireDns => {
                        Inner::Dns(self.dns.addresses(name, *remaining_steps, bounds)?)
                    }
                }
            }
            EffectKind::Dns {
                name,
                authority,
                record_type,
                server,
                security,
                remaining_steps,
            } => {
                guard(bounds)?;
                Inner::Dns(self.dns.query(
                    dns::Request {
                        name,
                        authority,
                        record_type: *record_type,
                        server: *server,
                        security,
                        remaining_steps: *remaining_steps,
                    },
                    bounds,
                )?)
            }
            EffectKind::Service { service, protocol } => Inner::Registry(
                self.registry
                    .start(service, protocol, bounds)
                    .map_err(Error::Registry)?,
            ),
            // NAMECACHE/REVOCATION/DHT are handled by the enclosing concrete
            // native provider. This is not an unspecified fallback backend.
            _ => return Err(Fault::Unsupported.into()),
        };
        // Return admitted owners even if a synchronous constructor crossed hard;
        // Manager then retires them while preserving their actual facts.
        Ok(Native { inner })
    }
    fn poll_native_guard(&mut self, _cx: &mut Context<'_>) -> Option<Error<'id>> {
        None
    }
    fn poll_shared(&mut self, cx: &mut Context<'_>) -> Poll<Shared<Error<'id>>> {
        self.registry.poll_stopped(cx).map(|result| match result {
            Ok(()) => Shared::Activity,
            Err(error) => Shared::Failed(Error::Registry(Arc::new(error.into()))),
        })
    }
    fn begin_close(&mut self) -> Option<Error<'id>> {
        if !self.closing {
            self.closing = true;
            self.system.begin_close();
            self.dns.begin_close();
            self.registry.begin_close();
        }
        None
    }
    fn is_closed(&self) -> bool {
        // This is the local subscription/socket scope only. Final SERVICE close
        // must additionally disconnect/retire its actual original broker Driver.
        self.closing
            && self.system.is_closed()
            && self.dns.is_closed()
            && self.registry.is_stopped()
    }
}
impl<'id, const R: usize, const N: usize> Operation for Native<'id, R, N> {
    type Error = Error<'id>;
    type Report = Report<'id>;
    fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Self::Error> {
        match &mut self.inner {
            Inner::System(query) => query.poll_native_guard(cx),
            Inner::Dns(query) => query.poll_native_guard(cx),
            Inner::Registry(query) => query.check_deadline().map(Error::from),
        }
    }
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        now: AbsoluteTime,
    ) -> Poll<Result<Value, Self::Error>> {
        if let Some(error) = self.poll_native_guard(cx) {
            return Poll::Ready(Err(error));
        }
        match &mut self.inner {
            Inner::System(query) => query.poll(cx, now),
            Inner::Dns(query) => query.poll(cx, now),
            Inner::Registry(query) => query.poll(cx),
        }
    }
    fn begin_close(&mut self) -> Option<Self::Error> {
        match &mut self.inner {
            Inner::System(query) => query.begin_close(),
            Inner::Dns(query) => query.begin_close(),
            Inner::Registry(query) => {
                query.begin_close();
                None
            }
        }
    }
    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<Close<Self::Report, Self::Error>> {
        match &mut self.inner {
            Inner::System(query) => query.poll_close(cx),
            Inner::Dns(query) => query.poll_close(cx),
            Inner::Registry(query) => query.poll_close(cx),
        }
    }
}
