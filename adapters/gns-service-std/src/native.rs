//! Genuine shared NAMECACHE/DHT and dedicated REVOCATION dependency owners.
//! The auxiliary Provider is required for DNS/system/registry effects; it is
//! never replaced by a default successful or unsupported implementation here.
use crate::{Bounds, Close, Operation, Provider, Shared, Value};
use gnunet_client_host::EndpointSource;
use gnunet_dht_client_host as dht;
use gnunet_gns::EffectKind;
use gnunet_namecache_client_host as cache;
use gnunet_revocation_client_host as revocation;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::{AbsoluteTime, Error as Fault};
use std::{
    cell::RefCell,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::Instant;
mod cache_ops;
pub mod diagnostics;
mod error;
mod query;
mod remote;
pub use error::{CacheReport, Error, RemoteEnd, RemoteReport, Report, RevocationReport};

/// Caller-owned native identity domains. They contain no keys or native handles.
/// They outlive the actual clients and must not be replaced while tokens survive.
pub struct Domains {
    cache: cache::Instance,
    revocation: revocation::Instance,
    dht: dht::Instance,
}
impl Domains {
    /// Fresh domains without native work.
    pub const fn new() -> Self {
        Self {
            cache: cache::Instance::new(),
            revocation: revocation::Instance::new(),
            dht: dht::Instance::new(),
        }
    }
}
impl Default for Domains {
    fn default() -> Self {
        Self::new()
    }
}
/// Original endpoint factories, constructed by the foreground with the same
/// configuration, shared Resolver broker and canonical clock.
pub struct Sources {
    /// Actual NAMECACHE endpoint.
    pub namecache: EndpointSource,
    /// Actual REVOCATION endpoint.
    pub revocation: EndpointSource,
    /// Actual DHT endpoint.
    pub dht: EndpointSource,
}
/// Resource caps independent of wire names, no unbounded event/log queues.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Concurrent native effects. Match or exceed the manager's query capacity.
    pub operations: usize,
    /// Maximum copied encrypted DHT candidate.
    pub block_bytes: usize,
    /// Actual shared NAMECACHE client policy.
    pub namecache: cache::Limits,
    /// Actual shared DHT client policy.
    pub dht: dht::Limits,
    /// Actual dedicated REVOCATION client policy.
    pub revocation: revocation::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            operations: 32,
            block_bytes: 64_640,
            namecache: cache::Limits {
                block_bytes: 64_640,
                ..cache::Limits::default()
            },
            dht: dht::Limits::default(),
            revocation: revocation::Limits::default(),
        }
    }
}
/// Actual shared native retirement, independent of query business outcomes.
#[derive(Debug)]
pub struct ProviderReport<'id> {
    /// Actual NAMECACHE physical close, if it was not already closed.
    pub cache_close: Option<cache::Loss<'id>>,
    /// Actual DHT close source and retained snapshot, if attached.
    pub dht_close: Option<(dht::Epoch<'id>, dht::Snapshot)>,
    /// Per-operation report rows still retained by their original owners.
    pub cache_rows: usize,
    /// Per-operation GET report rows still retained by original owners.
    pub dht_rows: usize,
    /// True only after actual shared close and auxiliary retirement.
    pub closed: bool,
}
/// Concrete original dependency owner. Shared caches save connections and
/// allocations; REVOCATION keeps its real one-query, untagged-response MQ.
pub struct NativeProvider<'id, B: Provider> {
    cache: cache_ops::SharedCache<'id>,
    remote: remote::SharedRemote<'id>,
    revocation_domain: &'id revocation::Instance,
    revocation_source: EndpointSource,
    clock: Arc<dyn RuntimeClock>,
    limits: Limits,
    auxiliary: B,
    phase: usize,
    closing: bool,
}
/// One original native operation. Inline variants keep ownership and teardown
/// explicit without a second allocation per ordinary IPC effect.
#[expect(
    clippy::large_enum_variant,
    reason = "one inline native owner; avoid a new heap allocation for every IPC effect"
)]
enum NativeOperation<'id, O: Operation<Error = Error<'id>, Report = Report<'id>>> {
    /// Original shared NAMECACHE row.
    Cache {
        state: cache_ops::SharedCache<'id>,
        token: cache_ops::Token,
    },
    /// Original shared DHT GET.
    Remote {
        state: remote::SharedRemote<'id>,
        token: remote::Token,
    },
    /// Original dedicated REVOCATION MQ.
    Revocation(query::Query<'id>),
    /// Real auxiliary DNS/system/registry operation supplied by the foreground.
    Auxiliary(O),
}
// Keep private row authority behind this concrete owner and expose only the
// Operation methods.
/// Opaque original operation returned by NativeProvider.
pub struct Native<'id, O: Operation<Error = Error<'id>, Report = Report<'id>>> {
    inner: NativeOperation<'id, O>,
}
pub(super) fn guard(bounds: Bounds) -> Result<(), Fault> {
    if Instant::now() >= bounds.hard() {
        Err(Fault::Timeout)
    } else {
        Ok(())
    }
}
impl<'id, B> NativeProvider<'id, B>
where
    B: Provider,
    B::Operation: Operation<Error = Error<'id>, Report = Report<'id>>,
{
    /// Reserve bounded genuine clients without connecting. Auxiliary must be a
    /// real provider for the remaining effects and use this same clock/broker.
    /// No implicit runtime, Resolver, source clone or detached task is made.
    pub fn new(
        domains: &'id mut Domains,
        sources: Sources,
        clock: Arc<dyn RuntimeClock>,
        limits: Limits,
        auxiliary: B,
    ) -> Result<Self, Error<'id>> {
        if limits.operations == 0
            || limits.block_bytes == 0
            || limits.block_bytes > 65_535
            || limits.namecache.operations < limits.operations
            || limits.dht.protocol.gets < limits.operations
            || !Arc::ptr_eq(&clock, &sources.namecache.clock())
            || !Arc::ptr_eq(&clock, &sources.revocation.clock())
            || !Arc::ptr_eq(&clock, &sources.dht.clock())
        {
            return Err(Fault::InvalidInput.into());
        }
        let namecache = cache::Client::new(&domains.cache, sources.namecache, limits.namecache)?;
        let dht = dht::Client::new(&mut domains.dht, sources.dht, limits.dht)?;
        Ok(Self {
            cache: Rc::new(RefCell::new(cache_ops::State::new(
                namecache,
                limits.operations,
            )?)),
            remote: Rc::new(RefCell::new(remote::State::new(
                dht,
                limits.operations,
                limits.block_bytes,
            )?)),
            revocation_domain: &domains.revocation,
            revocation_source: sources.revocation,
            clock,
            limits,
            auxiliary,
            phase: 0,
            closing: false,
        })
    }
    /// The one actual clock shared with all native factories.
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Explicit port recovery after the caller re-established the same clock /
    /// broker capability. Old NAMECACHE operations are not replayed.
    pub fn recover_cache_ports(&mut self) -> Result<(), Error<'id>> {
        if self.closing {
            return Err(Fault::Closed.into());
        }
        self.cache.borrow_mut().recover()
    }
    /// Restore only safe retained DHT read intents, preserving GetId and Bounds.
    pub fn recover_dht_ports(&mut self) -> Result<(), Error<'id>> {
        if self.closing {
            return Err(Fault::Closed.into());
        }
        self.remote.borrow_mut().recover()
    }
    /// Real auxiliary state, for its explicit source recovery controls.
    pub fn auxiliary_mut(&mut self) -> &mut B {
        &mut self.auxiliary
    }
    /// Snapshot actual shared native retirement; does not consume authority.
    pub fn report(&self) -> ProviderReport<'id> {
        let cache = self.cache.borrow();
        let remote = self.remote.borrow();
        ProviderReport {
            cache_close: cache.close_report,
            dht_close: remote.close_report,
            cache_rows: cache.retained(),
            dht_rows: remote.retained(),
            closed: self.closing
                && cache.is_closed()
                && remote.is_closed()
                && self.auxiliary.is_closed(),
        }
    }
}
impl<'id, B> Provider for NativeProvider<'id, B>
where
    B: Provider,
    B::Operation: Operation<Error = Error<'id>, Report = Report<'id>>,
{
    type Operation = Native<'id, B::Operation>;
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
            EffectKind::Cache { key, .. } => {
                guard(bounds)?;
                let token = self.cache.borrow_mut().admit(Some(key), None, bounds)?;
                NativeOperation::Cache {
                    state: self.cache.clone(),
                    token,
                }
            }
            EffectKind::CachePut { block, .. } => {
                guard(bounds)?;
                let token = self.cache.borrow_mut().admit(None, Some(block), bounds)?;
                NativeOperation::Cache {
                    state: self.cache.clone(),
                    token,
                }
            }
            EffectKind::Remote { key, .. } => {
                guard(bounds)?;
                let token = self.remote.borrow_mut().admit(key, bounds)?;
                NativeOperation::Remote {
                    state: self.remote.clone(),
                    token,
                }
            }
            EffectKind::Revocation { zone } => {
                guard(bounds)?;
                let client = revocation::Client::query(
                    self.revocation_domain,
                    self.revocation_source.duplicate()?,
                    *zone,
                    revocation::Deadlines {
                        send_until: bounds.until().as_micros(),
                        until: bounds.until().as_micros(),
                    },
                    self.limits.revocation,
                )?;
                NativeOperation::Revocation(query::Query::new(client, bounds))
            }
            _ => {
                guard(bounds)?;
                NativeOperation::Auxiliary(self.auxiliary.start(effect, bounds)?)
            }
        };
        // Return the admitted owner even if construction crossed hard. Manager
        // retains and closes it, instead of dropping unknown native work on Err.
        Ok(Native { inner })
    }
    fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Error<'id>> {
        if let Some(error) = self.cache.borrow_mut().native_guard(cx) {
            return Some(error);
        }
        if let Some(error) = self.remote.borrow_mut().native_guard(cx) {
            return Some(error);
        }
        self.auxiliary.poll_native_guard(cx)
    }
    fn poll_shared(&mut self, cx: &mut Context<'_>) -> Poll<Shared<Error<'id>>> {
        for _ in 0..3 {
            let phase = self.phase;
            self.phase = (phase + 1) % 3;
            let event = match phase {
                0 => self.cache.borrow_mut().poll(cx),
                1 => self.remote.borrow_mut().poll(cx),
                _ => self.auxiliary.poll_shared(cx),
            };
            if event.is_ready() {
                return event;
            }
        }
        Poll::Pending
    }
    fn begin_close(&mut self) -> Option<Error<'id>> {
        if self.closing {
            return None;
        }
        self.closing = true;
        self.cache.borrow_mut().close();
        self.remote.borrow_mut().close();
        self.auxiliary.begin_close()
    }
    fn is_closed(&self) -> bool {
        self.closing
            && self.cache.borrow().is_closed()
            && self.remote.borrow().is_closed()
            && self.auxiliary.is_closed()
    }
}
impl<'id, O> Operation for Native<'id, O>
where
    O: Operation<Error = Error<'id>, Report = Report<'id>>,
{
    type Error = Error<'id>;
    type Report = Report<'id>;
    fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Self::Error> {
        match &mut self.inner {
            NativeOperation::Revocation(query) => query.poll_native_guard(cx),
            NativeOperation::Auxiliary(operation) => operation.poll_native_guard(cx),
            // Shared guards are checked once by NativeProvider, not once per row.
            _ => None,
        }
    }
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        now: AbsoluteTime,
    ) -> Poll<Result<Value, Self::Error>> {
        match &mut self.inner {
            NativeOperation::Cache { state, token } => state.borrow_mut().value(*token, cx),
            NativeOperation::Remote { state, token } => state.borrow_mut().value(*token, cx),
            NativeOperation::Revocation(query) => query.poll(cx, now),
            NativeOperation::Auxiliary(operation) => operation.poll(cx, now),
        }
    }
    fn begin_close(&mut self) -> Option<Self::Error> {
        match &mut self.inner {
            NativeOperation::Cache { state, token } => state.borrow_mut().cancel(*token),
            NativeOperation::Remote { state, token } => state.borrow_mut().cancel(*token),
            NativeOperation::Revocation(query) => query.begin_close(),
            NativeOperation::Auxiliary(operation) => operation.begin_close(),
        }
    }
    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<Close<Self::Report, Self::Error>> {
        match &mut self.inner {
            NativeOperation::Cache { state, token } => state.borrow_mut().retired(*token, cx),
            NativeOperation::Remote { state, token } => state.borrow_mut().retired(*token, cx),
            NativeOperation::Revocation(query) => query.poll_close(cx),
            NativeOperation::Auxiliary(operation) => operation.poll_close(cx),
        }
    }
}
