//! Durable-provider boundary for the official FLOW sender-monotime scalar.
//! Numeric spans are representation, not persistence proofs. A production host
//! supplies only an exact original demand after its real upper-bound commit.
//! Sender scalars are neither local scheduling samples nor remote UTC leases.
use crate::Times;
use alloc::sync::Arc;
use gnunet_types::{Error, MonoInstant};
use gnunet_wire::official::{AbsoluteTime, RelativeTime};
/// Checked finite inclusive numeric interval. It grants no durability or source
/// authenticity by itself; the actual storage provider owns that assurance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Span {
    first: u64,
    last: u64,
}
impl Span {
    /// Check nonzero finite endpoints and inclusive ordering.
    pub const fn checked(first: u64, last: u64) -> Result<Self, Error> {
        if first == 0 || first > last || last == u64::MAX {
            return Err(Error::InvalidInput);
        }
        Ok(Self { first, last })
    }
    /// First durably reserved scalar, inclusive.
    pub const fn first(self) -> u64 {
        self.first
    }
    /// Persisted highwater upper bound, inclusive.
    pub const fn last(self) -> u64 {
        self.last
    }
    /// Test representation membership without granting a commit proof.
    pub const fn contains(self, value: u64) -> bool {
        value >= self.first && value <= self.last
    }
}
/// Finite original provider request policy, independent of the numeric horizon.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    lifetime: RelativeTime,
}
impl Policy {
    /// Set a finite positive original request lifetime.
    pub fn checked(lifetime: RelativeTime) -> Result<Self, Error> {
        if lifetime.is_forever() || lifetime.as_micros() == 0 {
            return Err(Error::InvalidInput);
        }
        Ok(Self { lifetime })
    }
    /// Original request budget in microseconds; never renewed by retries.
    pub const fn lifetime(self) -> RelativeTime {
        self.lifetime
    }
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            lifetime: RelativeTime::from_micros(60_000_000),
        }
    }
}
/// One original Engine demand, scoped independently from a wire number.
#[derive(Clone)]
pub struct DemandId {
    engine: Arc<()>,
    serial: u64,
}
impl PartialEq for DemandId {
    fn eq(&self, other: &Self) -> bool {
        self.serial == other.serial && Arc::ptr_eq(&self.engine, &other.engine)
    }
}
impl Eq for DemandId {}
impl core::fmt::Debug for DemandId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("MonotimeDemand").field(&self.serial).finish()
    }
}
/// Actual pending original resource demand. Captured targets survive queue wait,
/// clock corrections and the storage provider's original native operation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Demand {
    id: DemandId,
    observed: AbsoluteTime,
    until: MonoInstant,
    expires: AbsoluteTime,
}
impl Demand {
    /// Original Engine allocation and checked serial; not a wire request id.
    pub fn id(&self) -> &DemandId {
        &self.id
    }
    /// Real absolute sample at demand creation, only for provenance. The storage
    /// provider uses its actual admission sample for first=max(UTC,oldHighwater+1).
    pub const fn observed(&self) -> AbsoluteTime {
        self.observed
    }
    /// Original local monotonic scheduling deadline.
    pub const fn until(&self) -> MonoInstant {
        self.until
    }
    /// Original GNUnet absolute target, independent of the native hard deadline.
    pub const fn expires(&self) -> AbsoluteTime {
        self.expires
    }
    /// Check original logical targets without changing them.
    pub fn live(&self, times: Times) -> bool {
        times.monotonic() < self.until && times.absolute() < self.expires
    }
}
/// Observable immutable counter state. No snapshot value grants a fresh span.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct State {
    /// Current still-usable numeric range; invalidated ranges never revive.
    pub active: Option<Span>,
    /// Greatest upper bound ever installed/burned in this Engine allocation.
    pub greatest_upper: u64,
    /// Actual original provider demand remains outstanding.
    pub waiting: bool,
}
pub(crate) struct Book {
    engine: Arc<()>,
    policy: Policy,
    serial: u64,
    active: Option<Span>,
    greatest_upper: u64,
    demand: Option<Demand>,
}
impl Book {
    pub(crate) fn new(engine: Arc<()>) -> Self {
        Self {
            engine,
            policy: Policy::default(),
            serial: 0,
            active: None,
            greatest_upper: 0,
            demand: None,
        }
    }
    pub(crate) fn configure(&mut self, policy: Policy) -> Result<(), Error> {
        if self.serial != 0 || self.active.is_some() || self.greatest_upper != 0 {
            return Err(Error::NotReady);
        }
        self.policy = policy;
        Ok(())
    }
    pub(crate) fn demand(&self) -> Option<&Demand> {
        self.demand.as_ref()
    }
    pub(crate) fn state(&self) -> State {
        State {
            active: self.active,
            greatest_upper: self.greatest_upper,
            waiting: self.demand.is_some(),
        }
    }
    fn owns(&self, id: &DemandId) -> bool {
        Arc::ptr_eq(&self.engine, &id.engine)
    }
    pub(crate) fn retire(&mut self, id: &DemandId) -> Result<(), Error> {
        if !self.owns(id) || self.demand.as_ref().is_none_or(|d| d.id != *id) {
            return Err(Error::Stale);
        }
        self.demand = None;
        Ok(())
    }
    pub(crate) fn install(
        &mut self,
        id: &DemandId,
        span: Span,
        times: Times,
        issued: u64,
    ) -> Result<(), Error> {
        times.validate()?;
        if !self.owns(id) || self.demand.as_ref().is_none_or(|d| d.id != *id) {
            return Err(Error::Stale);
        }
        if !self.demand.as_ref().is_some_and(|d| d.live(times)) {
            return Err(Error::Deadline);
        }
        if span.first <= self.greatest_upper || span.first <= issued {
            return Err(Error::Replay);
        }
        if times.absolute().as_micros() > span.last {
            return Err(Error::Deadline);
        }
        self.greatest_upper = span.last;
        self.active = Some(span);
        self.demand = None;
        Ok(())
    }
    /// A genuine but unusable/late commit only burns its numeric interval. It
    /// cannot grant active values or affect another Engine's current demand.
    pub(crate) fn burn(&mut self, id: &DemandId, span: Span) -> Result<(), Error> {
        if !self.owns(id) {
            return Err(Error::Stale);
        }
        self.greatest_upper = self.greatest_upper.max(span.last);
        if self.active.is_some_and(|active| active.first <= span.last) {
            self.active = None;
        }
        if self.demand.as_ref().is_some_and(|d| d.id == *id) {
            self.demand = None;
        }
        Ok(())
    }
    pub(crate) fn next(&mut self, issued: &mut u64, times: Times) -> Result<Option<u64>, Error> {
        times.validate()?;
        let next = issued
            .checked_add(1)
            .filter(|n| *n != u64::MAX)
            .ok_or(Error::Overflow)?
            .max(times.absolute().as_micros());
        if let Some(span) = self.active {
            let value = next.max(span.first);
            if value <= span.last {
                *issued = value;
                return Ok(Some(value));
            }
            // Actual UTC passed the upper bound or numbers were consumed. A
            // later UTC rollback cannot revive this cleared interval.
            self.active = None;
        }
        if self.demand.as_ref().is_some_and(|d| !d.live(times)) {
            self.demand = None;
        }
        if self.demand.is_none() {
            let serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
            let until = times.monotonic_after(self.policy.lifetime)?;
            let expires = times.absolute_after(self.policy.lifetime)?;
            self.demand = Some(Demand {
                id: DemandId {
                    engine: self.engine.clone(),
                    serial,
                },
                observed: times.absolute(),
                until,
                expires,
            });
            self.serial = serial;
        }
        Ok(None)
    }
}
