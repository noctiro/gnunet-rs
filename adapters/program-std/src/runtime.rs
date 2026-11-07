//! Caller-driven PROGRAM task lifecycle and logical timer adapter.
//!
//! This is a scoped Future adapter for PROGRAM's start/main/stop read points,
//! not an implementation claim for all public GNUNET_SCHEDULER fd/driver APIs.
//! No detached task is spawned. The caller supplies and polls the whole run.
use crate::{
    clock::{Start, Ticket},
    program::{Failure, Main, Prepared, ResolverConnect},
    shared_clock::{SharedClock, Subscription},
};
use gnunet_types::{AbsoluteTime, Error, RelativeTime};
use std::{
    cell::{Cell, RefCell},
    future::Future,
    pin::Pin,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);
/// Bounded scoped task identity, unusable after execution/cancellation or reuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskId {
    owner: u64,
    generation: u64,
}
pub(crate) type Work<'a> = Pin<Box<dyn Future<Output = ()> + 'a>>;
struct Entry<'a> {
    id: TaskId,
    work: Work<'a>,
    lifeness: bool,
    priority: u8,
}
struct Slot<'a> {
    entry: Option<Entry<'a>>,
    leased: bool,
}
struct State<'a> {
    owner: u64,
    generation: u64,
    slots: Vec<Slot<'a>>,
    lifeness: bool,
    shutdown: bool,
    closed: bool,
    waker: Option<Waker>,
}
/// Synchronous narrow admission/cancellation context. Capturing a clone shares
/// the same scoped owner; it never starts an independent scheduler.
pub struct Scope<'a> {
    state: Rc<RefCell<State<'a>>>,
    clock: SharedClock,
}
impl Clone for Scope<'_> {
    fn clone(&self) -> Self {
        Self {
            state: Rc::clone(&self.state),
            clock: self.clock.clone(),
        }
    }
}
impl<'a> Scope<'a> {
    /// Admit a future with source inherited lifeness and DEFAULT priority3.
    pub fn spawn(&self, work: impl Future<Output = ()> + 'a) -> Result<TaskId, Error> {
        self.spawn_with(work, None, 3)
    }
    /// Admit with explicit lifeness and priority1..=7. Higher priorities are polled
    /// first; ready futures at equal priority retain original admission order.
    pub fn spawn_with(
        &self,
        work: impl Future<Output = ()> + 'a,
        lifeness: Option<bool>,
        priority: u8,
    ) -> Result<TaskId, Error> {
        if !(1..=7).contains(&priority) {
            return Err(Error::InvalidInput);
        }
        let mut s = self.state.try_borrow_mut().map_err(|_| Error::Conflict)?;
        if s.closed {
            return Err(Error::StaleGeneration);
        }
        let slot = s
            .slots
            .iter()
            .position(|v| v.entry.is_none() && !v.leased)
            .ok_or(Error::Capacity)?;
        let generation = s.generation.checked_add(1).ok_or(Error::Overflow)?;
        let id = TaskId {
            owner: s.owner,
            generation,
        };
        let lifeness = lifeness.unwrap_or(s.lifeness);
        s.slots[slot].entry = Some(Entry {
            id,
            work: Box::pin(work),
            lifeness,
            priority,
        });
        s.generation = generation;
        let waker = s.waker.clone();
        drop(s);
        if let Some(w) = waker {
            w.wake();
        }
        Ok(id)
    }
    pub(crate) fn batch(&self, works: Vec<Work<'a>>) -> Result<Vec<TaskId>, Error> {
        let mut ids = Vec::new();
        ids.try_reserve_exact(works.len())
            .map_err(|_| Error::Capacity)?;
        let mut state = self.state.try_borrow_mut().map_err(|_| Error::Conflict)?;
        if state.closed {
            return Err(Error::StaleGeneration);
        }
        let available = state
            .slots
            .iter()
            .filter(|v| v.entry.is_none() && !v.leased)
            .count();
        if works.len() > available {
            return Err(Error::Capacity);
        }
        let count = u64::try_from(works.len()).map_err(|_| Error::Overflow)?;
        state.generation.checked_add(count).ok_or(Error::Overflow)?;
        let lifeness = state.lifeness;
        for work in works {
            let index = state
                .slots
                .iter()
                .position(|v| v.entry.is_none() && !v.leased)
                .ok_or(Error::Conflict)?;
            state.generation += 1;
            let id = TaskId {
                owner: state.owner,
                generation: state.generation,
            };
            state.slots[index].entry = Some(Entry {
                id,
                work,
                lifeness,
                priority: 3,
            });
            ids.push(id);
        }
        let waker = state.waker.clone();
        drop(state);
        if let Some(waker) = waker {
            waker.wake();
        }
        Ok(ids)
    }
    /// Cancel only an unconsumed original task. Dropping its future suppresses all
    /// later body execution; it is local retirement, never a remote completion.
    pub fn cancel(&self, id: TaskId) -> Result<(), Error> {
        let mut s = self.state.try_borrow_mut().map_err(|_| Error::Conflict)?;
        let i = s
            .slots
            .iter()
            .position(|v| v.entry.as_ref().is_some_and(|v| v.id == id))
            .ok_or(Error::StaleGeneration)?;
        let entry = s.slots[i].entry.take();
        drop(s);
        drop(entry);
        Ok(())
    }
    /// Request the registered PROGRAM shutdown hook. Existing caller futures retain
    /// their own lifeness; callers must cancel/finish their outstanding work.
    pub fn shutdown(&self) -> Result<(), Error> {
        let mut s = self.state.try_borrow_mut().map_err(|_| Error::Conflict)?;
        if s.closed {
            return Err(Error::StaleGeneration);
        }
        s.shutdown = true;
        let w = s.waker.clone();
        drop(s);
        if let Some(w) = w {
            w.wake();
        }
        Ok(())
    }
    /// Reserve an independent logical timer subscription. FOREVER remains
    /// pending without overflow; listener capacity failure is explicit. A finite
    /// deadline already due when registered remains ready across clock rollback.
    pub fn delay_until(&self, target: AbsoluteTime) -> Result<Delay, Error> {
        let subscription = self.clock.subscribe()?;
        // GNUNET_SCHEDULER_add_at checks remaining time during registration
        // and irrevocably queues an already-due finite task as ready.
        let registered_ready = !target.is_never() && self.clock.sample()?.now >= target;
        Ok(Delay::new(
            self.clock.clone(),
            target,
            Some(subscription),
            registered_ready,
        ))
    }
    /// Source saturating logical now+relative, including explicit FOREVER.
    pub fn delay(&self, relative: RelativeTime) -> Result<Delay, Error> {
        let subscription = self.clock.subscribe()?;
        let now = self.clock.sample()?.now;
        let target = if relative.is_forever() {
            AbsoluteTime::NEVER
        } else {
            AbsoluteTime::from_micros(now.as_micros().saturating_add(relative.as_micros()))
        };
        // Relative ZERO enters the ready queue at this registration. A second
        // source read could roll backwards and wrongly revoke that admission.
        let registered_ready = relative == RelativeTime::ZERO && !target.is_never();
        Ok(Delay::new(
            self.clock.clone(),
            target,
            Some(subscription),
            registered_ready,
        ))
    }
}
/// Persistent logical timer. Canceling its await drops no external request;
/// retaining it across polls retains its original logical deadline.
pub struct Delay {
    clock: SharedClock,
    target: AbsoluteTime,
    sleep: Option<Pin<Box<Sleep>>>,
    revision: Option<u64>,
    subscription: Option<Subscription>,
    finished: bool,
    registered_ready: bool,
}
impl Delay {
    fn new(
        clock: SharedClock,
        target: AbsoluteTime,
        subscription: Option<Subscription>,
        registered_ready: bool,
    ) -> Self {
        Self {
            clock,
            target,
            sleep: None,
            revision: None,
            subscription,
            finished: false,
            registered_ready,
        }
    }
    fn finish(&mut self, result: Result<(), Error>) -> Poll<Result<(), Error>> {
        self.subscription = None;
        self.sleep = None;
        self.finished = true;
        Poll::Ready(result)
    }
}
impl Future for Delay {
    type Output = Result<(), Error>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.finished {
            return Poll::Ready(Err(Error::NotReady));
        }
        if this.registered_ready {
            return this.finish(Ok(()));
        }
        if let Some(subscription) = &mut this.subscription {
            match subscription.poll_changed(cx, this.revision.unwrap_or(0)) {
                Poll::Ready(Err(error)) => return this.finish(Err(error)),
                Poll::Ready(Ok(_)) | Poll::Pending => {}
            }
        }
        let sample = match this.clock.sample() {
            Ok(v) => v,
            Err(e) => return this.finish(Err(e)),
        };
        if let Some(subscription) = &mut this.subscription {
            match subscription.poll_changed(cx, sample.revision) {
                Poll::Ready(Err(error)) => return this.finish(Err(error)),
                Poll::Ready(Ok(_)) => {
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }
                Poll::Pending => {}
            }
        }
        if this.target.is_never() {
            return Poll::Pending;
        }
        if sample.now >= this.target {
            return this.finish(Ok(()));
        }
        if this.revision != Some(sample.revision) || this.sleep.is_none() {
            let Some(deadline) = Instant::now().checked_add(Duration::from_micros(
                this.target.as_micros() - sample.now.as_micros(),
            )) else {
                return this.finish(Err(Error::Overflow));
            };
            this.sleep = Some(Box::pin(tokio::time::sleep_until(deadline)));
            this.revision = Some(sample.revision);
        }
        match this.sleep.as_mut() {
            Some(sleep) => match sleep.as_mut().poll(cx) {
                Poll::Pending => Poll::Pending,
                Poll::Ready(()) => {
                    this.sleep = None;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            },
            None => this.finish(Err(Error::Conflict)),
        }
    }
}

struct Stop<'observer> {
    clock: SharedClock,
    ticket: Rc<Cell<Option<Ticket>>>,
    done: Rc<Cell<bool>>,
    observer: Option<gnunet_config::diagnostic::BorrowedObserver<'observer>>,
}
impl Drop for Stop<'_> {
    fn drop(&mut self) {
        if !self.done.replace(true)
            && self
                .clock
                .finish_speedup(self.ticket.take(), self.observer)
                .is_err()
        {
            // A stale ticket cannot retire a replacement. Poison/overflow is
            // already observable to explicit operations; Drop cannot report it.
        }
    }
}
struct Run<'a> {
    scope: Scope<'a>,
    subscription: Subscription,
    observed: u64,
    tick: Option<Ticket>,
    tick_delay: Option<Delay>,
    stop_done: Rc<Cell<bool>>,
    cleanup: Rc<Cell<Option<Ticket>>>,
    speedup_attempt: bool,
    observer: Option<gnunet_config::diagnostic::BorrowedObserver<'a>>,
}
impl Run<'_> {
    fn stop(&mut self) -> Result<(), Error> {
        if !self.stop_done.get() {
            self.tick = None;
            self.tick_delay = None;
            let ticket = self.cleanup.take();
            if self.speedup_attempt {
                self.scope.clock.finish_speedup(ticket, self.observer)?;
            } else if let Some(ticket) = ticket {
                self.scope.clock.stop_ticket(ticket)?;
            }
            self.stop_done.set(true);
        }
        Ok(())
    }
}
impl Drop for Run<'_> {
    fn drop(&mut self) {
        let entries = {
            let mut state = self.scope.state.borrow_mut();
            state.closed = true;
            let slots = std::mem::take(&mut state.slots);
            state.waker = None;
            slots
        };
        // User futures may own Scope clones; drop them outside RefCell borrowing.
        drop(entries);
    }
}
impl Future for Run<'_> {
    type Output = Result<(), Error>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        match this.subscription.poll_changed(cx, this.observed) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(v)) => this.observed = v.revision,
            Poll::Pending => {}
        }
        let sample = match this.subscription.sample() {
            Ok(v) => v,
            Err(e) => return Poll::Ready(Err(e)),
        };
        this.observed = sample.revision;
        this.scope.state.borrow_mut().waker = Some(cx.waker().clone());
        if this.scope.state.borrow().shutdown {
            if let Err(e) = this.stop() {
                return Poll::Ready(Err(e));
            }
            this.scope.state.borrow_mut().shutdown = false;
        }
        let mut order = this
            .scope
            .state
            .borrow()
            .slots
            .iter()
            .filter_map(|v| v.entry.as_ref().map(|v| (v.priority, v.id)))
            .collect::<Vec<_>>();
        order.sort_by_key(|&(priority, id)| (std::cmp::Reverse(priority), id.generation));
        let mut tick_polled = false;
        let mut progressed = false;
        for (priority, id) in order.iter().copied() {
            if !tick_polled && priority <= 3 {
                tick_polled = true;
                match poll_tick(this, cx) {
                    Ok(v) => progressed |= v,
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
            if this.scope.state.borrow().shutdown {
                if let Err(e) = this.stop() {
                    return Poll::Ready(Err(e));
                }
                this.scope.state.borrow_mut().shutdown = false;
            }
            let leased = {
                let mut state = this.scope.state.borrow_mut();
                let found = state
                    .slots
                    .iter()
                    .position(|v| v.entry.as_ref().is_some_and(|v| v.id == id));
                found.and_then(|i| {
                    state.slots[i].entry.take().map(|entry| {
                        state.slots[i].leased = true;
                        state.lifeness = entry.lifeness;
                        (i, entry)
                    })
                })
            };
            let Some((slot, mut entry)) = leased else {
                continue;
            };
            let status = entry.work.as_mut().poll(cx);
            {
                let mut state = this.scope.state.borrow_mut();
                state.slots[slot].leased = false;
                state.lifeness = true;
                if status.is_pending() {
                    state.slots[slot].entry = Some(entry);
                } else {
                    progressed = true;
                    drop(state);
                    drop(entry);
                }
            }
        }
        if this.scope.state.borrow().shutdown {
            if let Err(e) = this.stop() {
                return Poll::Ready(Err(e));
            }
            this.scope.state.borrow_mut().shutdown = false;
        }
        if !tick_polled {
            match poll_tick(this, cx) {
                Ok(v) => progressed |= v,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        let (live, new_task) = {
            let state = this.scope.state.borrow();
            (
                state
                    .slots
                    .iter()
                    .any(|v| v.entry.as_ref().is_some_and(|e| e.lifeness)),
                state.slots.iter().any(|v| {
                    v.entry
                        .as_ref()
                        .is_some_and(|e| !order.iter().any(|&(_, id)| id == e.id))
                }),
            )
        };
        // Every newly admitted future gets an initial ready poll, including
        // non-lifeness descendants. Only pending non-lifeness work may be dropped.
        if !new_task && !live {
            if let Err(e) = this.stop() {
                return Poll::Ready(Err(e));
            }
            return Poll::Ready(Ok(()));
        }
        if progressed || new_task {
            cx.waker().wake_by_ref();
        }
        match this.subscription.poll_changed(cx, this.observed) {
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
            Poll::Pending => {}
        }
        Poll::Pending
    }
}
fn poll_tick(run: &mut Run<'_>, cx: &mut Context<'_>) -> Result<bool, Error> {
    let Some(ticket) = run.tick else {
        return Ok(false);
    };
    if run.tick_delay.is_none() {
        // This private delay is polled only by Run with its already registered waker.
        run.tick_delay = Some(Delay::new(
            run.scope.clock.clone(),
            ticket.at(),
            None,
            ticket.at() == AbsoluteTime::UNIX_EPOCH,
        ));
    }
    let Some(delay) = &mut run.tick_delay else {
        return Err(Error::Conflict);
    };
    match Pin::new(delay).poll(cx) {
        Poll::Pending => Ok(false),
        Poll::Ready(Err(e)) => Err(e),
        Poll::Ready(Ok(())) => match run.scope.clock.tick_observed(ticket, run.observer) {
            Ok(advanced) => {
                run.tick = Some(advanced.next);
                run.cleanup.set(Some(advanced.next));
                run.tick_delay = None;
                Ok(true)
            }
            Err(Error::WouldBlock) => {
                run.tick_delay = None;
                cx.waker().wake_by_ref();
                Ok(false)
            }
            Err(e) => Err(e),
        },
    }
}
impl Prepared {
    /// Run PROGRAM's scheduler path in the caller's active Tokio runtime. The task
    /// is synchronous like GNUNET_PROGRAM_Main, and may admit scoped futures. The
    /// shared Resolver selection and source SPEEDUP startup precede its invocation.
    pub async fn run_scheduled(
        self,
        resolver: &mut impl ResolverConnect,
        clock: SharedClock,
        capacity: usize,
        task: impl for<'a> FnOnce(Main<'a>, Scope<'a>),
    ) -> Result<i32, Failure> {
        self.run_scheduled_observed(resolver, clock, capacity, None, task)
            .await
    }
    /// Same actual scoped run with synchronous CONFIG/SPEEDUP diagnostics. The
    /// future borrows its route until return/cancel; callbacks run outside clock
    /// locks. No diagnostic is a task/remote-processing acknowledgement.
    pub async fn run_scheduled_observed(
        self,
        resolver: &mut impl ResolverConnect,
        clock: SharedClock,
        capacity: usize,
        observer: Option<gnunet_config::diagnostic::BorrowedObserver<'_>>,
        task: impl for<'a> FnOnce(Main<'a>, Scope<'a>),
    ) -> Result<i32, Failure> {
        let mut run = new_run(clock.clone(), capacity)?;
        run.observer = observer;
        run.speedup_attempt = true;
        let tick = match clock.start_observed(self.main().config, observer) {
            Ok(Start::Ready(ticket)) => Some(ticket),
            Ok(Start::Disabled) | Err(Error::InvalidInput) => None,
            Err(e) => return Err(e.into()),
        };
        run.tick = tick;
        run.cleanup.set(tick);
        let cleanup = Rc::clone(&run.cleanup);
        let _stop = Stop {
            clock: clock.clone(),
            ticket: Rc::clone(&cleanup),
            done: Rc::clone(&run.stop_done),
            observer,
        };
        resolver.connect(self.main().config.duplicate()?)?;
        task(self.main(), run.scope.clone());
        run.await?;
        Ok(1)
    }
}

fn new_run<'a>(clock: SharedClock, capacity: usize) -> Result<Run<'a>, Error> {
    let owner = NEXT_OWNER
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_add(1))
        .map_err(|_| Error::Overflow)?;
    let subscription = clock.subscribe()?;
    let observed = subscription.sample()?.revision;
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(capacity)
        .map_err(|_| Error::Capacity)?;
    slots.resize_with(capacity, || Slot {
        entry: None,
        leased: false,
    });
    let scope = Scope {
        state: Rc::new(RefCell::new(State {
            owner,
            generation: 0,
            slots,
            lifeness: true,
            shutdown: false,
            closed: false,
            waker: None,
        })),
        clock,
    };
    Ok(Run {
        scope,
        subscription,
        observed,
        tick: None,
        tick_delay: None,
        stop_done: Rc::new(Cell::new(false)),
        cleanup: Rc::new(Cell::new(None)),
        speedup_attempt: false,
        observer: None,
    })
}
/// Run only the scoped scheduler adapter, without implicitly starting SPEEDUP or
/// selecting Resolver. This corresponds to DAEMON/monolith's distinct entrypoint.
/// The initializer is synchronous and must explicitly admit every future.
pub async fn run_tasks<'a>(
    clock: SharedClock,
    capacity: usize,
    initialize: impl FnOnce(Scope<'a>),
) -> Result<(), Error> {
    run_tasks_fallible(clock, capacity, |scope| {
        initialize(scope);
        Ok(())
    })
    .await
}
/// Fallible initialization counterpart: failed registration drops every admitted
/// future before the first poll, closes this scoped owner and preserves the exact
/// initialization error. It does not roll back external service side effects.
pub async fn run_tasks_fallible<'a, E: From<Error>>(
    clock: SharedClock,
    capacity: usize,
    initialize: impl FnOnce(Scope<'a>) -> Result<(), E>,
) -> Result<(), E> {
    let run = new_run(clock, capacity)?;
    initialize(run.scope.clone())?;
    run.await.map_err(E::from)
}
