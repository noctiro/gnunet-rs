//! Default-system redirection through the foreground's original Resolver broker.
use crate::{
    Bounds, Close, Operation, Value,
    native::{Error, Report},
};
use gnunet_gns::{Origin, Record, RecordFlags, RecordType};
use gnunet_resolver_broker::{self as broker, Completion, Family, Reply};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::{AbsoluteTime, Duration, Error as Fault};
use std::{
    cell::Cell,
    future::Future,
    marker::PhantomData,
    pin::{Pin, pin},
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};

/// Explicit resource and synthesized address-expiration policy. Resolver's
/// address API does not provide a DNS TTL; this value is policy, not a DNS fact.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Simultaneous original subscriptions.
    pub operations: usize,
    /// Actual addresses retained until the original END callback.
    pub records: usize,
    /// Total actual address payload bytes.
    pub bytes: usize,
    /// Synthesized data lifetime. FOREVER is data only, never an IO budget.
    pub lifetime: Duration,
}
/// The actual subscription outcome, separate from shared Driver retirement.
#[derive(Debug)]
pub struct SystemReport {
    /// Original broker capability, not a reconstructed scalar.
    pub token: broker::Token,
    /// Actual address callbacks observed, including a callback rejected by caps.
    pub addresses: usize,
    /// Actual original END/timeout/malformed callback, if observed.
    pub terminal: Option<Completion>,
    /// This original subscription's local callback authority was revoked.
    pub subscription_revoked: bool,
    /// The same foreground Driver owns any shared wire/tombstone/partial IO.
    /// This report grants no claim that those shared resources have retired.
    pub shared_wire_owned_by_driver: bool,
}
struct Permit(Rc<Cell<usize>>);
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.set(self.0.get().saturating_sub(1));
    }
}
/// Clone shares only the actual process broker, resource count and closing gate.
#[derive(Clone)]
pub struct Factory<const R: usize, const N: usize> {
    context: broker::Context<R, N>,
    clock: Arc<dyn RuntimeClock>,
    limits: Limits,
    active: Rc<Cell<usize>>,
    closing: Rc<Cell<bool>>,
}
impl<const R: usize, const N: usize> Factory<R, N> {
    /// No broker or Driver is created here. All endpoint resolution and System
    /// queries remain in the single process domain supplied by the foreground.
    pub fn new(
        context: broker::Context<R, N>,
        clock: Arc<dyn RuntimeClock>,
        limits: Limits,
    ) -> Result<Self, Fault> {
        if limits.operations == 0
            || limits.records == 0
            || limits.records > 65_535
            || limits.bytes < 16
            || limits.bytes > 64_512
            || !Arc::ptr_eq(&clock, &context.resolution_context().clock())
        {
            return Err(Fault::InvalidInput);
        }
        Ok(Self {
            context,
            clock,
            limits,
            active: Rc::new(Cell::new(0)),
            closing: Rc::new(Cell::new(false)),
        })
    }
    /// The exact process clock, without a new listener or native effect.
    pub fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    /// Admit one real forward subscription. Construction/lookup time is charged
    /// to the same original hard; no private Resolver or host-DNS fallback exists.
    pub fn start<'id>(
        &self,
        name: &str,
        kind: RecordType,
        steps: u32,
        bounds: Bounds,
    ) -> Result<Query<'id, R, N>, Error<'id>> {
        super::guard(bounds)?;
        if self.closing.get() {
            return Err(Fault::Closed.into());
        }
        if steps == 0 {
            return Err(Fault::Capacity.into());
        }
        let family = match kind {
            RecordType::A => Family::V4,
            RecordType::AAAA => Family::V6,
            kind if kind.value() == 0 => Family::Any,
            _ => return Err(Fault::Unsupported.into()),
        };
        let active = self.active.get();
        if active == self.limits.operations {
            return Err(Fault::WouldBlock.into());
        }
        let now = self.clock.sample().map_err(Error::Clock)?.now;
        super::guard(bounds)?;
        if now >= bounds.until() {
            return Err(Fault::Timeout.into());
        }
        self.active
            .set(active.checked_add(1).ok_or(Fault::Overflow)?);
        let permit = Permit(self.active.clone());
        super::guard(bounds)?;
        let query = self
            .context
            .ip_get(
                name.as_bytes(),
                family,
                Duration(bounds.until().as_micros() - now.as_micros()),
            )
            .map_err(Error::Resolver)?;
        let token = query.token();
        Ok(Query {
            query: Some(query),
            bounds,
            alarm: None,
            limits: self.limits,
            family,
            records: Vec::new(),
            bytes: 0,
            report: Some(SystemReport {
                token,
                addresses: 0,
                terminal: None,
                subscription_revoked: false,
                shared_wire_owned_by_driver: true,
            }),
            permit: Some(permit),
            closing: false,
            delivered: false,
            lifetime: PhantomData,
        })
    }
    /// Stop new subscriptions only. Actual operations are retained by Manager.
    pub fn begin_close(&self) {
        self.closing.set(true);
    }
    /// Local subscription scope only, never a whole shared-Driver drain proof.
    pub fn is_closed(&self) -> bool {
        self.closing.get() && self.active.get() == 0
    }
}
/// One actual broker Query with its original callback and native-hard boundary.
pub struct Query<'id, const R: usize, const N: usize> {
    query: Option<broker::Query<R, N>>,
    bounds: Bounds,
    alarm: Option<Pin<Box<Sleep>>>,
    limits: Limits,
    family: Family,
    records: Vec<Record>,
    bytes: usize,
    report: Option<SystemReport>,
    permit: Option<Permit>,
    closing: bool,
    delivered: bool,
    // Unifies the enclosing native provider's error/report type; this marker
    // grants no query identity. The real broker Token above supplies identity.
    lifetime: PhantomData<&'id ()>,
}
enum Observation {
    Address(std::net::IpAddr),
    Terminal(Completion),
}
impl<'id, const R: usize, const N: usize> Query<'id, R, N> {
    fn cancel(&mut self) -> Option<Error<'id>> {
        let query = self.query.take()?;
        let mut query = query;
        let result = query.cancel_clock_free();
        // This public method fences only its own receipt even when shared
        // cleanup fails. The actual error and shared Driver debt are separate.
        if let Some(report) = &mut self.report {
            report.subscription_revoked = true;
        }
        drop(query);
        result.err().map(Error::Resolver)
    }
}
impl<'id, const R: usize, const N: usize> Operation for Query<'id, R, N> {
    type Error = Error<'id>;
    type Report = Report<'id>;
    fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Self::Error> {
        if self.closing || self.delivered {
            return None;
        }
        let alarm = self
            .alarm
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(self.bounds.hard())));
        if Instant::now() >= self.bounds.hard() || alarm.as_mut().poll(cx).is_ready() {
            // Retain a distinct cleanup error for begin_close. Do not replace
            // the primary original timeout with that error or fake END.
            self.closing = true;
            self.alarm = None;
            return Some(Fault::Timeout.into());
        }
        None
    }
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
        now: AbsoluteTime,
    ) -> Poll<Result<Value, Self::Error>> {
        if self.closing || self.delivered {
            return Poll::Pending;
        }
        if let Some(error) = self.poll_native_guard(cx) {
            return Poll::Ready(Err(error));
        }
        let Some(query) = &mut self.query else {
            return Poll::Ready(Err(Fault::Closed.into()));
        };
        let observed = {
            let future = query.next();
            let mut future = pin!(future);
            let delivery = match future.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(Error::Resolver(error))),
                Poll::Ready(Ok(None)) => return Poll::Ready(Err(Fault::Closed.into())),
                Poll::Ready(Ok(Some(delivery))) => delivery,
            };
            let observed = match delivery.reply() {
                Ok(Reply::Address(address)) => Ok(Observation::Address(address)),
                Ok(Reply::Complete(terminal)) => Ok(Observation::Terminal(terminal)),
                Ok(Reply::Hostname(_)) => Err(Fault::Malformed),
                Err(error) => Err(error),
            };
            // Return only the actual original callback lease. No socket effect,
            // remote ACK or unrelated broker callback is manufactured here.
            drop(delivery);
            observed?
        };
        match observed {
            Observation::Address(address) => {
                let report = self.report.as_mut().ok_or(Fault::Closed)?;
                report.addresses = report.addresses.checked_add(1).ok_or(Fault::Overflow)?;
                if !self.family.accepts(address) {
                    return Poll::Ready(Err(Fault::Malformed.into()));
                }
                let (kind, slice): (RecordType, Vec<u8>) = match address {
                    std::net::IpAddr::V4(ip) => (RecordType::A, copy(&ip.octets())?),
                    std::net::IpAddr::V6(ip) => (RecordType::AAAA, copy(&ip.octets())?),
                };
                let total = self.bytes.checked_add(slice.len()).ok_or(Fault::Overflow)?;
                if self.records.len() == self.limits.records || total > self.limits.bytes {
                    return Poll::Ready(Err(Fault::Capacity.into()));
                }
                self.records.try_reserve(1).map_err(|_| Fault::Capacity)?;
                self.records.push(Record {
                    origin: Origin::System,
                    expiration_time: now.as_micros().saturating_add(self.limits.lifetime.0),
                    record_type: kind,
                    flags: RecordFlags::NONE,
                    data: slice,
                });
                self.bytes = total;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
            Observation::Terminal(terminal) => {
                self.report.as_mut().ok_or(Fault::Closed)?.terminal = Some(terminal);
                self.delivered = true;
                self.alarm = None;
                match terminal {
                    Completion::End => Poll::Ready(Ok(Value::Records {
                        records: std::mem::take(&mut self.records),
                        spent: 1,
                    })),
                    Completion::Timeout => Poll::Ready(Err(Fault::Timeout.into())),
                    _ => Poll::Ready(Err(Fault::Malformed.into())),
                }
            }
        }
    }
    fn begin_close(&mut self) -> Option<Self::Error> {
        self.closing = true;
        self.alarm = None;
        self.cancel()
    }
    fn poll_close(&mut self, _cx: &mut Context<'_>) -> Poll<Close<Self::Report, Self::Error>> {
        if !self.closing || self.query.is_some() {
            return Poll::Pending;
        }
        match self.report.take() {
            Some(report) => {
                self.permit = None;
                Poll::Ready(Close::Closed(Report::System(report)))
            }
            None => Poll::Pending,
        }
    }
}
fn copy(input: &[u8]) -> Result<Vec<u8>, Fault> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(input.len())
        .map_err(|_| Fault::Capacity)?;
    output.extend_from_slice(input);
    Ok(output)
}
