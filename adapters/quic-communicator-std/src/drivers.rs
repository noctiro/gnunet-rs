//! Pinned Quinn0.11.12 backend drivers remain explicitly caller-owned/polled.
//! Actual spawn sites are endpoint.rs144 and connection.rs61, not arbitrary
//! user tasks. One endpoint plus C retained connection rows requires C+1 slots.
use gnunet_types::Error;
use quinn::{AsyncTimer, AsyncUdpSocket, Runtime};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::Context,
    time::Instant,
};
type Driver = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
#[derive(Clone)]
pub(crate) struct Id {
    domain: Arc<()>,
    index: usize,
    serial: u64,
}
impl PartialEq for Id {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.domain, &other.domain)
            && self.index == other.index
            && self.serial == other.serial
    }
}
impl Eq for Id {}
impl std::fmt::Debug for Id {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("QuinnDriver").field(&self.serial).finish()
    }
}
enum State {
    Vacant,
    Reserved,
    Running(Driver),
    Polling,
    Done { forced: bool },
}
struct Slot {
    serial: u64,
    state: State,
    retire_at: Option<tokio::time::Instant>,
}
struct Book {
    slots: Vec<Slot>,
    armed: Option<Id>,
    next: u64,
    stopped: bool,
}
struct Shared {
    domain: Arc<()>,
    book: Mutex<Book>,
}
impl Shared {
    fn lock(&self) -> MutexGuard<'_, Book> {
        match self.book.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }
}
struct OwnedRuntime {
    shared: Arc<Shared>,
    gate: Arc<crate::socket::Gate>,
}
impl std::fmt::Debug for OwnedRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedQuinnRuntime").finish_non_exhaustive()
    }
}
impl Runtime for OwnedRuntime {
    fn new_timer(&self, at: Instant) -> Pin<Box<dyn AsyncTimer>> {
        quinn::TokioRuntime.new_timer(at)
    }
    fn wrap_udp_socket(&self, socket: std::net::UdpSocket) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let inner = quinn::TokioRuntime.wrap_udp_socket(socket)?;
        Ok(Arc::new(crate::socket::Socket::new(
            inner,
            self.gate.clone(),
        )))
    }
    fn now(&self) -> Instant {
        quinn::TokioRuntime.now()
    }
    // Capacity is NOT handled in this infallible callback. Private admissions
    // reserve a slot before entering either of the two pinned Quinn spawn sites.
    // Neither Endpoint nor this Runtime escapes that owner. A draining driver
    // retains its row, so the C+1 bound includes every original live driver.
    #[expect(
        clippy::panic,
        reason = "Pinned private Quinn constructors synchronously consume exactly one pre-reserved spawn ticket; impossible invariant violations must not masquerade as capacity success or silently discard a driver"
    )]
    fn spawn(&self, future: Driver) {
        let mut book = self.shared.lock();
        let Some(id) = book.armed.take() else {
            panic!("Quinn spawn without original reserved admission")
        };
        let slot = &mut book.slots[id.index];
        if slot.serial != id.serial || !matches!(slot.state, State::Reserved) {
            panic!("Quinn spawn does not match original reserved driver")
        }
        slot.state = State::Running(future);
    }
}
/// Actual backend progress, not a packet, TLS or application success result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Progress {
    Pending,
    Completed(Id),
    Canceled(Id),
}
/// One bounded owned backend pool. It creates no Tokio tasks. Pure application
/// Cell instances live separately in the caller's current-thread application pool.
pub(crate) struct Drivers {
    shared: Arc<Shared>,
    runtime: Arc<OwnedRuntime>,
    cursor: usize,
}
impl Drivers {
    pub(crate) fn new(connections: usize, gate: Arc<crate::socket::Gate>) -> Result<Self, Error> {
        if connections == 0 || connections > 65535 {
            return Err(Error::InvalidInput);
        }
        let capacity = connections.checked_add(1).ok_or(Error::Overflow)?;
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(capacity)
            .map_err(|_| Error::Capacity)?;
        slots.resize_with(capacity, || Slot {
            serial: 0,
            state: State::Vacant,
            retire_at: None,
        });
        let shared = Arc::new(Shared {
            domain: Arc::new(()),
            book: Mutex::new(Book {
                slots,
                armed: None,
                next: 0,
                stopped: false,
            }),
        });
        Ok(Self {
            runtime: Arc::new(OwnedRuntime {
                shared: shared.clone(),
                gate,
            }),
            shared,
            cursor: 0,
        })
    }
    pub(crate) fn reserve(&mut self) -> Result<Id, Error> {
        let mut book = self.shared.lock();
        if book.stopped {
            return Err(Error::Closed);
        }
        let index = book
            .slots
            .iter()
            .position(|s| matches!(s.state, State::Vacant))
            .ok_or(Error::Capacity)?;
        let serial = book.next.checked_add(1).ok_or(Error::Overflow)?;
        book.next = serial;
        book.slots[index] = Slot {
            serial,
            state: State::Reserved,
            retire_at: None,
        };
        Ok(Id {
            domain: self.shared.domain.clone(),
            index,
            serial,
        })
    }
    /// The closure is a private concrete Endpoint/connect/accept constructor,
    /// never a general unbounded task submission port. It must not await/reenter.
    pub(crate) fn construct<T, E>(
        &mut self,
        id: &Id,
        constructor: impl FnOnce(Arc<dyn Runtime>) -> Result<T, E>,
    ) -> Result<T, Construct<E, T>> {
        {
            let mut book = self.shared.lock();
            if !Arc::ptr_eq(&id.domain, &self.shared.domain)
                || book.stopped
                || book.armed.is_some()
                || !book
                    .slots
                    .get(id.index)
                    .is_some_and(|s| s.serial == id.serial && matches!(s.state, State::Reserved))
            {
                return Err(Construct::Protocol(Error::Stale));
            }
            book.armed = Some(id.clone());
        }
        // Runtime.spawn may synchronously acquire the same book; never hold it.
        let result = constructor(self.runtime.clone());
        let mut book = self.shared.lock();
        let no_spawn = book.armed.take().as_ref() == Some(id);
        if no_spawn {
            book.slots[id.index].state = State::Vacant;
            return match result {
                Err(e) => Err(Construct::Backend(e)),
                Ok(value) => Err(Construct::MissingDriver(value)),
            };
        }
        match result {
            Ok(value) => Ok(value),
            Err(error) => Err(Construct::Spawned {
                error,
                id: id.clone(),
            }),
        }
    }
    /// Visit one original slot without holding a Runtime bookkeeping mutex
    /// across future polling. A full endpoint turn visits each slot once.
    pub(crate) fn poll(&mut self, cx: &mut Context<'_>) -> Result<Progress, Error> {
        let selected = {
            let mut book = self.shared.lock();
            let n = book.slots.len();
            let index = self.cursor % n;
            self.cursor = (index + 1) % n;
            // Endpoint visits all C+1 slots once per turn. Vacant/done slots
            // consume their own visit instead of searching back to a live
            // driver and polling it repeatedly in the same endpoint turn.
            let slot = &mut book.slots[index];
            if matches!(slot.state, State::Running(_)) {
                let serial = slot.serial;
                let retire_at = slot.retire_at;
                if let State::Running(future) = core::mem::replace(&mut slot.state, State::Polling)
                {
                    Some((index, serial, future, retire_at))
                } else {
                    return Err(Error::Conflict);
                }
            } else {
                None
            }
        };
        let Some((index, serial, mut future, retire_at)) = selected else {
            return Ok(Progress::Pending);
        };
        // The original connection retirement target is checked immediately
        // before this exact future. It cannot be bypassed by earlier busy
        // drivers or renewed by the next domain polling turn.
        let cancel = retire_at.is_some_and(|at| tokio::time::Instant::now() >= at);
        let completed = cancel || future.as_mut().poll(cx).is_ready();
        let mut book = self.shared.lock();
        let slot = &mut book.slots[index];
        if slot.serial != serial || !matches!(slot.state, State::Polling) {
            return Err(Error::Conflict);
        }
        if completed {
            slot.state = State::Done { forced: cancel };
            drop(book);
            drop(future);
            let id = Id {
                domain: self.shared.domain.clone(),
                index,
                serial,
            };
            Ok(if cancel {
                Progress::Canceled(id)
            } else {
                Progress::Completed(id)
            })
        } else {
            slot.state = State::Running(future);
            Ok(Progress::Pending)
        }
    }
    pub(crate) fn done(&self, id: &Id) -> Result<bool, Error> {
        if !Arc::ptr_eq(&id.domain, &self.shared.domain) {
            return Err(Error::Stale);
        }
        let book = self.shared.lock();
        let s = book.slots.get(id.index).ok_or(Error::Stale)?;
        if s.serial != id.serial {
            return Err(Error::Stale);
        }
        Ok(matches!(s.state, State::Done { .. }))
    }
    pub(crate) fn retire_done(&mut self, id: &Id) -> Result<(), Error> {
        if !Arc::ptr_eq(&id.domain, &self.shared.domain) {
            return Err(Error::Stale);
        }
        let mut book = self.shared.lock();
        let s = book.slots.get_mut(id.index).ok_or(Error::Stale)?;
        if s.serial != id.serial {
            return Err(Error::Stale);
        }
        if !matches!(s.state, State::Done { .. }) {
            return Err(Error::NotReady);
        }
        s.state = State::Vacant;
        s.retire_at = None;
        Ok(())
    }
    pub(crate) fn retire_at(&mut self, id: &Id, at: tokio::time::Instant) -> Result<(), Error> {
        if !Arc::ptr_eq(&id.domain, &self.shared.domain) {
            return Err(Error::Stale);
        }
        let mut book = self.shared.lock();
        let slot = book.slots.get_mut(id.index).ok_or(Error::Stale)?;
        if slot.serial != id.serial
            || matches!(slot.state, State::Vacant | State::Reserved | State::Polling)
        {
            return Err(Error::Stale);
        }
        slot.retire_at = Some(slot.retire_at.map_or(at, |old| old.min(at)));
        Ok(())
    }
    pub(crate) fn was_canceled(&self, id: &Id) -> Result<bool, Error> {
        if !Arc::ptr_eq(&id.domain, &self.shared.domain) {
            return Err(Error::Stale);
        }
        let book = self.shared.lock();
        let slot = book.slots.get(id.index).ok_or(Error::Stale)?;
        if slot.serial != id.serial {
            return Err(Error::Stale);
        }
        match slot.state {
            State::Done { forced } => Ok(forced),
            _ => Err(Error::NotReady),
        }
    }
    pub(crate) fn stop_admission(&mut self) {
        self.shared.lock().stopped = true
    }
    /// Cancel one original closed connection driver, never the endpoint driver.
    /// Its exact future is dropped outside the bookkeeping lock; this is force
    /// cancellation rather than a successful backend completion.
    pub(crate) fn cancel(&mut self, id: &Id) -> Result<bool, Error> {
        if !Arc::ptr_eq(&id.domain, &self.shared.domain) {
            return Err(Error::Stale);
        }
        let original = {
            let mut book = self.shared.lock();
            let slot = book.slots.get_mut(id.index).ok_or(Error::Stale)?;
            if slot.serial != id.serial {
                return Err(Error::Stale);
            }
            match slot.state {
                State::Done { .. } => return Ok(false),
                State::Running(_) => {
                    core::mem::replace(&mut slot.state, State::Done { forced: true })
                }
                State::Polling => return Err(Error::WouldBlock),
                State::Vacant | State::Reserved => return Err(Error::Stale),
            }
        };
        drop(original);
        Ok(true)
    }
    pub(crate) fn slots(&self) -> usize {
        self.shared.lock().slots.len()
    }
    pub(crate) fn pending(&self) -> usize {
        self.shared
            .lock()
            .slots
            .iter()
            .filter(|s| !matches!(s.state, State::Vacant | State::Done { .. }))
            .count()
    }
    /// Use only after original Endpoint/connection handles were physically
    /// retired and fixed drain grace elapsed. Dropping original drivers is a
    /// force-stop observation, never successful task/packet completion.
    pub(crate) fn force_drop(&mut self) -> Result<usize, Error> {
        let mut book = self.shared.lock();
        book.stopped = true;
        if book.slots.iter().any(|s| matches!(s.state, State::Polling)) {
            return Err(Error::WouldBlock);
        }
        book.armed = None;
        drop(book);
        Ok(self.drop_futures())
    }
    fn drop_futures(&self) -> usize {
        let len = self.shared.lock().slots.len();
        let mut count = 0;
        for i in 0..len {
            let original = {
                let mut book = self.shared.lock();
                core::mem::replace(&mut book.slots[i].state, State::Done { forced: true })
            };
            if let State::Running(future) = original {
                count += 1;
                drop(future)
            }
        }
        count
    }
}
impl Drop for Drivers {
    fn drop(&mut self) {
        // Break Shared -> driver -> Quinn Runtime -> Shared cycles even if the
        // caller drops its owner instead of awaiting explicit shutdown. During
        // panic unwind a Polling future is already owned by the unwinding stack;
        // clear its metadata without reporting fictitious completion.
        self.runtime.gate.close();
        {
            let mut book = self.shared.lock();
            book.stopped = true;
            book.armed = None;
        }
        let _actual_stored_drivers = self.drop_futures();
    }
}
pub(crate) enum Construct<E, T = ()> {
    Protocol(Error),
    Backend(E),
    MissingDriver(T),
    Spawned { error: E, id: Id },
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::Waker,
        time::Duration,
    };
    type Test = Result<(), Box<dyn std::error::Error>>;
    struct Dropped(Arc<AtomicUsize>);
    impl Drop for Dropped {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
    fn install(
        drivers: &mut Drivers,
        id: &Id,
        polls: Arc<AtomicUsize>,
        drops: Arc<AtomicUsize>,
    ) -> Test {
        let held = Dropped(drops);
        drivers
            .construct(id, |runtime| {
                runtime.spawn(Box::pin(async move {
                    let _held = held;
                    polls.fetch_add(1, Ordering::Relaxed);
                    std::future::pending::<()>().await;
                }));
                Ok::<(), ()>(())
            })
            .map_err(|_| "original reserved driver admission failed")?;
        Ok(())
    }
    #[test]
    fn sparse_pool_turn_polls_one_live_future_once_instead_of_repeating_vacant_searches() -> Test {
        let mut drivers = Drivers::new(
            128,
            crate::socket::Gate::new((Instant::now() + Duration::from_secs(60)).into()),
        )?;
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let id = drivers.reserve()?;
        install(&mut drivers, &id, polls.clone(), drops)?;
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..drivers.slots() {
            drivers.poll(&mut cx)?;
        }
        if polls.load(Ordering::Relaxed) != 1 {
            return Err("one sparse endpoint turn repeatedly polled the live driver".into());
        }
        drivers.cancel(&id)?;
        drivers.retire_done(&id)?;
        Ok(())
    }
    #[test]
    fn original_expired_driver_is_dropped_without_poll_and_deadline_cannot_cross_ticket_reuse()
    -> Test {
        let mut drivers = Drivers::new(
            1,
            crate::socket::Gate::new((Instant::now() + Duration::from_secs(60)).into()),
        )?;
        let polls = Arc::new(AtomicUsize::new(0));
        let drops = Arc::new(AtomicUsize::new(0));
        let old = drivers.reserve()?;
        install(&mut drivers, &old, polls.clone(), drops.clone())?;
        let expired = tokio::time::Instant::now() - Duration::from_micros(1);
        drivers.retire_at(&old, expired)?;
        drivers.retire_at(&old, tokio::time::Instant::now() + Duration::from_secs(30))?;
        let mut cx = Context::from_waker(Waker::noop());
        if drivers.poll(&mut cx)? != Progress::Canceled(old.clone())
            || polls.load(Ordering::Relaxed) != 0
            || drops.load(Ordering::Relaxed) != 1
            || !drivers.was_canceled(&old)?
        {
            return Err("expired original driver was polled or not dropped".into());
        }
        drivers.retire_done(&old)?;
        let fresh = drivers.reserve()?;
        install(&mut drivers, &fresh, polls.clone(), drops.clone())?;
        if fresh == old || drivers.retire_at(&old, expired).is_ok() {
            return Err("old driver ticket regained authority".into());
        }
        for _ in 0..drivers.slots() {
            if drivers.poll(&mut cx)? != Progress::Pending {
                return Err("fresh original driver completed unexpectedly".into());
            }
        }
        if polls.load(Ordering::Relaxed) != 1 {
            return Err("retired deadline crossed into fresh driver".into());
        }
        drivers.cancel(&fresh)?;
        drivers.retire_done(&fresh)?;
        if drops.load(Ordering::Relaxed) != 2 {
            return Err("original future resources survived actual cancellation".into());
        }
        Ok(())
    }
}
