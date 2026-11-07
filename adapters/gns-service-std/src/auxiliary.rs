//! Actual ordinary DNS, shared system Resolver and prepared registry effects.
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
    registry: Result<registry::Files, Arc<registry::Error>>,
    closing: bool,
    // Error/report composition only; real query identity is the broker Token.
    lifetime: PhantomData<&'id ()>,
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
        if !Arc::ptr_eq(&system.clock(), &dns.clock()) {
            return Err(Fault::InvalidInput);
        }
        Ok(Self {
            system,
            dns,
            registry,
            closing: false,
            lifetime: PhantomData,
        })
    }
}
struct Registry {
    value: Option<Value>,
    mapping: Option<(u16, u16)>,
    bounds: Bounds,
    closing: bool,
    closed: bool,
}
enum Inner<'id, const R: usize, const N: usize> {
    System(system::Query<'id, R, N>),
    Dns(dns::Query<'id>),
    Registry(Registry),
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
                Inner::Dns(self.dns.addresses(name, *remaining_steps, bounds)?)
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
            EffectKind::Service { service, protocol } => {
                guard(bounds)?;
                let mapping = match &self.registry {
                    Ok(files) => files.lookup(service, protocol),
                    Err(error) => Some(
                        registry::assigned(service, protocol)
                            .ok_or_else(|| Error::Registry(error.clone()))?,
                    ),
                };
                Inner::Registry(Registry {
                    value: Some(Value::Service(mapping)),
                    mapping,
                    bounds,
                    closing: false,
                    closed: false,
                })
            }
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
    fn poll_shared(&mut self, _cx: &mut Context<'_>) -> Poll<Shared<Error<'id>>> {
        // The single foreground Driver drives shared Resolver wire debt. DNS
        // futures own their sockets and are polled through original operations.
        Poll::Pending
    }
    fn begin_close(&mut self) -> Option<Error<'id>> {
        if !self.closing {
            self.closing = true;
            self.system.begin_close();
            self.dns.begin_close();
        }
        None
    }
    fn is_closed(&self) -> bool {
        // This is the local subscription/socket scope only. Final SERVICE close
        // must additionally disconnect/retire its actual original broker Driver.
        self.closing && self.system.is_closed() && self.dns.is_closed()
    }
}
impl<'id, const R: usize, const N: usize> Operation for Native<'id, R, N> {
    type Error = Error<'id>;
    type Report = Report<'id>;
    fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Self::Error> {
        match &mut self.inner {
            Inner::System(query) => query.poll_native_guard(cx),
            Inner::Dns(query) => query.poll_native_guard(cx),
            Inner::Registry(query)
                if !query.closing
                    && query.value.is_some()
                    && Instant::now() >= query.bounds.hard() =>
            {
                query.closing = true;
                Some(Fault::Timeout.into())
            }
            Inner::Registry(_) => None,
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
            Inner::Registry(query) if !query.closing => match query.value.take() {
                Some(value) => Poll::Ready(Ok(value)),
                None => Poll::Pending,
            },
            Inner::Registry(_) => Poll::Pending,
        }
    }
    fn begin_close(&mut self) -> Option<Self::Error> {
        match &mut self.inner {
            Inner::System(query) => query.begin_close(),
            Inner::Dns(query) => query.begin_close(),
            Inner::Registry(query) => {
                query.closing = true;
                query.value = None;
                None
            }
        }
    }
    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<Close<Self::Report, Self::Error>> {
        match &mut self.inner {
            Inner::System(query) => query.poll_close(cx),
            Inner::Dns(query) => query.poll_close(cx),
            Inner::Registry(query) if query.closing && !query.closed => {
                query.closed = true;
                Poll::Ready(Close::Closed(Report::Registry {
                    mapping: query.mapping,
                }))
            }
            Inner::Registry(_) => Poll::Pending,
        }
    }
}
