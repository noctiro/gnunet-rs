use crate::{CallSummary, Error, Limits};
use gnunet_client_host::ConnectGuard;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    rc::Rc,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
mod line;
pub(crate) use line::run;

#[derive(Clone, Copy)]
pub(crate) struct Bounds {
    pub hard: Instant,
    pub canonical: u64,
}
impl Bounds {
    pub fn native(self) -> Result<(), Fault> {
        if Instant::now() >= self.hard {
            Err(Fault::Deadline)
        } else {
            Ok(())
        }
    }
    pub fn check(self, clock: &dyn RuntimeClock) -> Result<(), Fault> {
        self.native()?;
        let now = clock.sample()?.now.as_micros();
        self.native()?;
        if now >= self.canonical {
            Err(Fault::Deadline)
        } else {
            Ok(())
        }
    }
}
#[derive(Clone, Copy)]
pub(crate) struct Origin {
    pub start: Instant,
    pub canonical: u64,
    pub sample_offset: u64,
}
impl Origin {
    pub fn new(clock: &dyn RuntimeClock) -> Result<Self, Error> {
        let start = Instant::now();
        let canonical = clock.sample()?.now.as_micros();
        if canonical == u64::MAX {
            return Err(Fault::TimeUncertain.into());
        }
        let sample_offset = u64::try_from(Instant::now().duration_since(start).as_micros())
            .map_err(|_| Fault::Overflow)?;
        Ok(Self {
            start,
            canonical,
            sample_offset,
        })
    }
    pub fn now(self) -> Result<u64, Fault> {
        u64::try_from(Instant::now().duration_since(self.start).as_micros())
            .map_err(|_| Fault::Overflow)
    }
    pub fn at(self, deadline: u64) -> Result<Bounds, Fault> {
        let canonical = self
            .canonical
            .checked_add(
                deadline
                    .checked_sub(self.sample_offset)
                    .ok_or(Fault::Deadline)?,
            )
            .filter(|v| *v != u64::MAX)
            .ok_or(Fault::Overflow)?;
        let hard = self
            .start
            .checked_add(Duration::from_micros(deadline))
            .ok_or(Fault::Overflow)?;
        Ok(Bounds { hard, canonical })
    }
    pub fn after(self, duration: Duration) -> Result<Bounds, Fault> {
        let delta = u64::try_from(duration.as_micros()).map_err(|_| Fault::Overflow)?;
        self.at(self.now()?.checked_add(delta).ok_or(Fault::Overflow)?)
    }
}
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Known {
    pub peer: [u8; 32],
    pub epoch: u64,
    pub revision: u64,
    pub expiration: u64,
}
#[derive(Clone, Copy)]
struct Gate {
    reason: Option<Fault>,
    known: Option<Known>,
    bounds: Option<Bounds>,
}
pub(crate) struct Control {
    gate: Mutex<Gate>,
    uncertainty: u64,
}
impl Control {
    pub fn new(uncertainty: u64) -> Self {
        Self {
            gate: Mutex::new(Gate {
                reason: None,
                known: None,
                bounds: None,
            }),
            uncertainty,
        }
    }
    fn snapshot(&self) -> Result<Gate, Fault> {
        self.gate.lock().map(|g| *g).map_err(|_| Fault::Unavailable)
    }
    pub fn cancel(&self, reason: Fault) {
        if let Ok(mut g) = self.gate.lock() {
            g.reason.get_or_insert(reason);
        }
    }
    pub fn reason(&self) -> Option<Fault> {
        self.snapshot()
            .map_or(Some(Fault::Unavailable), |g| g.reason)
    }
    pub fn targets(&self, bounds: Option<Bounds>) -> Result<(), Fault> {
        self.gate.lock().map_err(|_| Fault::Unavailable)?.bounds = bounds;
        Ok(())
    }
    /// Replace exactly the observation the Line currently owns. A new peer on
    /// the same verified MQ is allowed; replacing a physical source is not.
    pub fn known(&self, previous: Option<Known>, value: Known) -> Result<(), Fault> {
        let mut g = self.gate.lock().map_err(|_| Fault::Unavailable)?;
        if g.known != previous || previous.is_some_and(|old| old.epoch != value.epoch) {
            g.reason.get_or_insert(Fault::StaleGeneration);
            return Err(Fault::StaleGeneration);
        }
        g.known = Some(value);
        Ok(())
    }
    pub fn check(&self, clock: &dyn RuntimeClock, require_known: bool) -> Result<u64, Fault> {
        let before = self.snapshot()?;
        if let Some(e) = before.reason {
            return Err(e);
        }
        if let Some(b) = before.bounds {
            b.native()?;
        }
        let now = clock.sample()?.now.as_micros();
        let after = self.snapshot()?;
        if let Some(e) = after.reason {
            return Err(e);
        }
        if let Some(b) = after.bounds {
            b.native()?;
            if now >= b.canonical {
                return Err(Fault::Deadline);
            }
        }
        if before.known.is_some_and(|old| {
            after.known.is_none_or(|new| {
                old.peer != new.peer || old.epoch != new.epoch || old.revision != new.revision
            })
        }) {
            return Err(Fault::StaleGeneration);
        }
        let utc = now
            .checked_add(self.uncertainty)
            .filter(|v| *v != u64::MAX)
            .ok_or(Fault::TimeUncertain)?;
        match after.known {
            Some(known) if utc >= known.expiration => Err(Fault::Timeout),
            None if require_known => Err(Fault::NotReady),
            _ => Ok(utc),
        }
    }
    pub fn connect_guard(
        self: &Arc<Self>,
        clock: Arc<dyn RuntimeClock>,
        require_known: bool,
    ) -> ConnectGuard {
        let original = self.clone();
        Arc::new(move || {
            original
                .check(clock.as_ref(), require_known)
                .map(|_| ())
                .map_err(std::io::Error::other)
        })
    }
}

pub(crate) struct Registry {
    lines: Cell<usize>,
    calls: Cell<usize>,
    reserved: Cell<usize>,
    failed: Cell<bool>,
    limits: Limits,
}
impl Registry {
    pub fn new(limits: Limits, fixed: usize) -> Result<Self, Error> {
        if fixed > limits.total_retained_bytes {
            return Err(Fault::Capacity.into());
        }
        Ok(Self {
            lines: Cell::new(0),
            calls: Cell::new(0),
            reserved: Cell::new(fixed),
            failed: Cell::new(false),
            limits,
        })
    }
    pub fn healthy(&self) -> bool {
        !self.failed.get()
    }
    pub fn pending(&self) -> usize {
        self.lines.get().saturating_add(self.calls.get())
    }
    pub fn line(self: &Rc<Self>) -> Result<LineLease, Error> {
        let n = self.lines.get().checked_add(1).ok_or(Fault::Overflow)?;
        let bytes = self
            .reserved
            .get()
            .checked_add(self.limits.line_bytes)
            .ok_or(Fault::Overflow)?;
        if !self.healthy() {
            return Err(Fault::NotReady.into());
        }
        if n > self.limits.clients || bytes > self.limits.total_retained_bytes {
            return Err(Fault::Capacity.into());
        }
        self.lines.set(n);
        self.reserved.set(bytes);
        Ok(LineLease {
            registry: self.clone(),
        })
    }
    pub fn call(self: &Rc<Self>) -> Result<CallLease, Error> {
        let n = self.calls.get().checked_add(1).ok_or(Fault::Overflow)?;
        if !self.healthy() {
            return Err(Fault::NotReady.into());
        }
        if n > self.limits.calls {
            return Err(Fault::Capacity.into());
        }
        self.calls.set(n);
        Ok(CallLease {
            registry: self.clone(),
        })
    }
}
pub(crate) struct LineLease {
    registry: Rc<Registry>,
}
impl Drop for LineLease {
    fn drop(&mut self) {
        match (
            self.registry.lines.get().checked_sub(1),
            self.registry
                .reserved
                .get()
                .checked_sub(self.registry.limits.line_bytes),
        ) {
            (Some(n), Some(b)) => {
                self.registry.lines.set(n);
                self.registry.reserved.set(b);
            }
            _ => self.registry.failed.set(true),
        }
    }
}
pub(crate) struct CallLease {
    registry: Rc<Registry>,
}
impl Drop for CallLease {
    fn drop(&mut self) {
        if let Some(n) = self.registry.calls.get().checked_sub(1) {
            self.registry.calls.set(n);
        } else {
            self.registry.failed.set(true);
        }
    }
}
pub(crate) enum LocalEvent {
    RegistrationAccepted,
    Identity {
        peer: [u8; 32],
        epoch: u64,
    },
    ChannelDestroyed {
        call: u64,
        cid: u32,
        channel: u64,
        epoch: u64,
        mq_current: bool,
    },
    CallClosed(CallSummary),
}
pub(crate) struct Events {
    rows: RefCell<VecDeque<LocalEvent>>,
    activity: Cell<bool>,
    limit: usize,
}
impl Events {
    pub fn new(limit: usize) -> Result<Self, Error> {
        let mut rows = VecDeque::new();
        rows.try_reserve_exact(limit).map_err(|_| Fault::Capacity)?;
        Ok(Self {
            rows: RefCell::new(rows),
            activity: Cell::new(false),
            limit,
        })
    }
    pub fn room(&self) -> Result<bool, Fault> {
        Ok(self.rows.try_borrow().map_err(|_| Fault::Conflict)?.len() < self.limit)
    }
    pub fn emit(&self, event: LocalEvent) -> Result<(), Fault> {
        let mut rows = self.rows.try_borrow_mut().map_err(|_| Fault::Conflict)?;
        if rows.len() >= self.limit {
            return Err(Fault::WouldBlock);
        }
        rows.push_back(event);
        self.activity.set(true);
        Ok(())
    }
    pub fn take(&self) -> Option<LocalEvent> {
        self.rows.borrow_mut().pop_front()
    }
    pub fn progress(&self) {
        self.activity.set(true);
    }
    pub fn take_activity(&self) -> bool {
        self.activity.replace(false)
    }
    pub fn retained(&self) -> Result<usize, Fault> {
        self.rows
            .borrow()
            .capacity()
            .checked_mul(std::mem::size_of::<LocalEvent>())
            .and_then(|n| {
                n.checked_add(std::mem::size_of::<Self>() + 2 * std::mem::size_of::<usize>())
            })
            .ok_or(Fault::Overflow)
    }
}
pub(crate) type Mailbox = Rc<Events>;
pub(crate) async fn yield_once() {
    let mut yielded = false;
    std::future::poll_fn(|cx| {
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

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ClientOrigin(pub u64);
