use crate::{Error, Limits};
use gnunet_service_runtime::{clock::RuntimeClock, framing::OwnedFrame};
use gnunet_types::Error as Fault;
use std::{
    cell::{Cell, RefCell},
    future::poll_fn,
    rc::Rc,
    time::{Duration, Instant},
};
mod query;
mod session;
pub(crate) use session::{Session, session};

pub(crate) struct Control {
    reason: Cell<Option<Fault>>,
}
impl Control {
    pub fn new() -> Self {
        Self {
            reason: Cell::new(None),
        }
    }
    pub fn cancel(&self, cause: Fault) {
        if self.reason.get().is_none() {
            self.reason.set(Some(cause));
        }
    }
    pub fn reason(&self) -> Option<Fault> {
        self.reason.get()
    }
}
pub(crate) struct Registry {
    next: Cell<Option<u64>>,
    queries: Cell<usize>,
    reserved: Cell<usize>,
    failed: Cell<bool>,
    limits: Limits,
}
impl Registry {
    pub fn new(limits: Limits, fixed_bytes: usize) -> Result<Self, Error> {
        if fixed_bytes > limits.total_retained_bytes {
            return Err(Fault::Capacity.into());
        }
        Ok(Self {
            next: Cell::new(Some(1)),
            queries: Cell::new(0),
            reserved: Cell::new(fixed_bytes),
            failed: Cell::new(false),
            limits,
        })
    }
    pub fn reserve_storage(self: &Rc<Self>, bytes: usize) -> Result<StorageLease, Error> {
        if self.failed.get() {
            return Err(Fault::NotReady.into());
        }
        let total = self
            .reserved
            .get()
            .checked_add(bytes)
            .ok_or(Fault::Overflow)?;
        if total > self.limits.total_retained_bytes {
            return Err(Fault::Capacity.into());
        }
        self.reserved.set(total);
        Ok(StorageLease {
            registry: self.clone(),
            bytes,
        })
    }
    pub fn reserve(self: &Rc<Self>) -> Result<Permit, Error> {
        if self.failed.get() {
            return Err(Fault::NotReady.into());
        }
        let queries = self.queries.get().checked_add(1).ok_or(Fault::Overflow)?;
        let reserved = self
            .reserved
            .get()
            .checked_add(self.limits.query_bytes)
            .ok_or(Fault::Overflow)?;
        if queries > self.limits.queries || reserved > self.limits.total_retained_bytes {
            return Err(Fault::Capacity.into());
        }
        let id = self.next.get().ok_or(Fault::Overflow)?;
        self.next.set(id.checked_add(1));
        self.queries.set(queries);
        self.reserved.set(reserved);
        Ok(Permit {
            registry: self.clone(),
            id,
        })
    }
    pub fn healthy(&self) -> bool {
        !self.failed.get()
    }
    pub fn pending(&self) -> usize {
        self.queries.get()
    }
}
pub(crate) struct StorageLease {
    registry: Rc<Registry>,
    bytes: usize,
}
impl StorageLease {
    pub fn resize(&mut self, bytes: usize) -> Result<(), Error> {
        if !self.registry.healthy() {
            return Err(Fault::NotReady.into());
        }
        let base = self
            .registry
            .reserved
            .get()
            .checked_sub(self.bytes)
            .ok_or(Fault::Conflict)?;
        let total = base.checked_add(bytes).ok_or(Fault::Overflow)?;
        if total > self.registry.limits.total_retained_bytes {
            return Err(Fault::Capacity.into());
        }
        self.registry.reserved.set(total);
        self.bytes = bytes;
        Ok(())
    }
}
impl Drop for StorageLease {
    fn drop(&mut self) {
        if let Some(total) = self.registry.reserved.get().checked_sub(self.bytes) {
            self.registry.reserved.set(total);
        } else {
            self.registry.failed.set(true);
        }
    }
}
pub(crate) struct Permit {
    registry: Rc<Registry>,
    pub id: u64,
}
impl Drop for Permit {
    fn drop(&mut self) {
        match (
            self.registry.queries.get().checked_sub(1),
            self.registry
                .reserved
                .get()
                .checked_sub(self.registry.limits.query_bytes),
        ) {
            (Some(q), Some(b)) => {
                self.registry.queries.set(q);
                self.registry.reserved.set(b);
            }
            _ => self.registry.failed.set(true),
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct Targets {
    pub canonical: u64,
    pub hard: Instant,
    pub start: Instant,
}
impl Targets {
    pub fn new(clock: &dyn RuntimeClock, life: Duration) -> Result<Self, Error> {
        let start = Instant::now();
        let hard = start.checked_add(life).ok_or(Fault::Overflow)?;
        if life.is_zero() {
            return Err(Fault::InvalidInput.into());
        }
        let now = clock.sample()?.now.as_micros();
        if Instant::now() >= hard {
            return Err(Fault::Deadline.into());
        }
        let canonical = now
            .checked_add(u64::try_from(life.as_micros()).map_err(|_| Fault::Overflow)?)
            .filter(|v| *v != u64::MAX)
            .ok_or(Fault::Overflow)?;
        Ok(Self {
            canonical,
            hard,
            start,
        })
    }
    pub fn native(self) -> Result<(), Error> {
        if Instant::now() >= self.hard {
            Err(Fault::Deadline.into())
        } else {
            Ok(())
        }
    }
    pub fn check(self, clock: &dyn RuntimeClock) -> Result<(), Error> {
        self.native()?;
        let now = clock.sample()?.now.as_micros();
        self.native()?;
        if now >= self.canonical {
            return Err(Fault::Deadline.into());
        }
        Ok(())
    }
    pub fn observe(
        self,
        clock: &dyn RuntimeClock,
        uncertainty: Duration,
    ) -> Result<gnunet_abd::Time, Error> {
        self.native()?;
        let sample = clock.sample()?.now.as_micros();
        self.native()?;
        if sample >= self.canonical {
            return Err(Fault::Deadline.into());
        }
        let interval = u64::try_from(uncertainty.as_micros()).map_err(|_| Fault::Overflow)?;
        let utc_latest_us = sample.checked_add(interval).ok_or(Fault::TimeUncertain)?;
        let monotonic_us = u64::try_from(Instant::now().duration_since(self.start).as_micros())
            .map_err(|_| Fault::Overflow)?;
        Ok(gnunet_abd::Time {
            monotonic_us,
            utc_earliest_us: sample.saturating_sub(interval),
            utc_latest_us,
        })
    }
}

pub(crate) struct Output {
    pub frame: OwnedFrame,
    pub terminal: bool,
    pub valid_until: Option<u64>,
}
pub(crate) type Mailbox = Rc<RefCell<Option<Output>>>;
pub(crate) async fn publish(
    mailbox: &Mailbox,
    control: &Control,
    output: Output,
) -> Result<(), Error> {
    let mut output = Some(output);
    poll_fn(|_| {
        if let Some(reason) = control.reason() {
            return std::task::Poll::Ready(Err(reason.into()));
        }
        let mut slot = match mailbox.try_borrow_mut() {
            Ok(v) => v,
            Err(_) => return std::task::Poll::Ready(Err(Fault::Conflict.into())),
        };
        if slot.is_some() {
            return std::task::Poll::Pending;
        }
        *slot = output.take();
        std::task::Poll::Ready(Ok(()))
    })
    .await
}
pub(crate) async fn yield_once() {
    let mut yielded = false;
    poll_fn(|cx| {
        if yielded {
            std::task::Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        }
    })
    .await;
}
pub(crate) struct QueryReport {
    pub primary: Option<Error>,
    pub cleanup: Option<Error>,
    pub outcome: Option<gnunet_abd::Outcome>,
    pub lookups: u64,
    pub lookup_writes: u64,
    pub answers: u64,
    pub ignored: u64,
    pub collection_writes: u64,
    pub undrained: usize,
}
impl QueryReport {
    fn new() -> Self {
        Self {
            primary: None,
            cleanup: None,
            outcome: None,
            lookups: 0,
            lookup_writes: 0,
            answers: 0,
            ignored: 0,
            collection_writes: 0,
            undrained: 0,
        }
    }
}
pub(crate) fn expiration(
    record: gnunet_gnsrecord::RecordData<'_>,
    time: gnunet_abd::Time,
) -> Result<u64, Error> {
    let expiration = if record.has_relative_expiration() && record.expiration_time != u64::MAX {
        time.utc_earliest_us
            .checked_add(record.expiration_time)
            .ok_or(Fault::Overflow)?
    } else {
        record.expiration_time
    };
    time.valid_until(expiration)?;
    Ok(expiration)
}
