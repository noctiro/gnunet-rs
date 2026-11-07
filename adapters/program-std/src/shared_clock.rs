//! Bounded logical-clock subscriptions, for scheduler/broker revision wakeups.
//! No detached task, OS clock mutation or hidden timer is created by this owner.
use crate::clock::{Advanced, Clock, Start, Ticket};
use gnunet_types::{AbsoluteTime, Error};
use std::{
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
    time::{SystemTime, UNIX_EPOCH},
};
/// Explicit wall microsecond port, separate from the adjustable logical offset.
pub trait WallClock: Send + Sync {
    /// Sample raw unshifted wall microseconds using the source unsigned representation.
    fn wall_us(&self) -> Result<u64, Error>;
}
/// Native wall-clock reader. It does not install or adjust any host setting.
pub struct NativeWall;
impl WallClock for NativeWall {
    fn wall_us(&self) -> Result<u64, Error> {
        let value = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => d
                .as_secs()
                .wrapping_mul(1_000_000)
                .wrapping_add(u64::from(d.subsec_micros())),
            Err(e) => {
                let d = e.duration();
                let magnitude = d
                    .as_secs()
                    .wrapping_mul(1_000_000)
                    .wrapping_add(u64::from(d.subsec_micros()))
                    .wrapping_add(u64::from(!d.subsec_nanos().is_multiple_of(1000)));
                0u64.wrapping_sub(magnitude)
            }
        };
        Ok(value)
    }
}
/// Coherent logical value/revision, convertible directly to the broker clock port.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sample {
    /// Logical source timestamp; explicitly allowed to move backwards.
    pub now: AbsoluteTime,
    /// Incremented on every effective logical adjustment.
    pub revision: u64,
}
struct Watch {
    generation: u64,
    waker: Option<Waker>,
}
struct State {
    clock: Clock,
    revision: u64,
    generation: u64,
    slots: Vec<Option<Watch>>,
}
struct Inner {
    state: Mutex<State>,
    wall: Arc<dyn WallClock>,
}
/// Shared offset/speedup authority. Cloning shares this same owner; it does not
/// duplicate a clock, pending tick, callback or revision history.
#[derive(Clone)]
pub struct SharedClock {
    inner: Arc<Inner>,
}
/// One bounded, non-Clone listener identity. Reserve a distinct subscription for
/// each independently polled driver or timer. Arc-cloning cannot fork a waiter.
pub struct Subscription {
    inner: Arc<Inner>,
    slot: usize,
    generation: u64,
}
impl SharedClock {
    /// Allocate caller-selected listener metadata. A zero-listener clock remains
    /// usable but cannot silently pretend to subscribe a driver.
    pub fn new(max_listeners: usize, wall: Arc<dyn WallClock>) -> Result<Self, Error> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(max_listeners)
            .map_err(|_| Error::Capacity)?;
        slots.resize_with(max_listeners, || None);
        Ok(Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    clock: Clock::new()?,
                    revision: 0,
                    generation: 0,
                    slots,
                }),
                wall,
            }),
        })
    }
    /// Native wall reader with explicit finite listener capacity.
    pub fn native(max_listeners: usize) -> Result<Self, Error> {
        Self::new(max_listeners, Arc::new(NativeWall))
    }
    /// Reserve one original listener slot before a driver is constructed.
    pub fn subscribe(&self) -> Result<Subscription, Error> {
        let mut state = self.inner.state.lock().map_err(|_| Error::Io)?;
        let slot = state
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let generation = state.generation.checked_add(1).ok_or(Error::Overflow)?;
        state.slots[slot] = Some(Watch {
            generation,
            waker: None,
        });
        state.generation = generation;
        Ok(Subscription {
            inner: Arc::clone(&self.inner),
            slot,
            generation,
        })
    }
    /// Copy current logical value/revision after sampling the underlying wall clock.
    pub fn sample(&self) -> Result<Sample, Error> {
        sample(&self.inner)
    }
    /// Current source offset; no wall-clock or scheduler read occurs.
    pub fn offset(&self) -> Result<i64, Error> {
        Ok(self
            .inner
            .state
            .lock()
            .map_err(|_| Error::Io)?
            .clock
            .offset())
    }
    /// Source set_offset and a bounded revision broadcast. Registered wakers are
    /// taken under lock, then invoked only after the state lock is released.
    pub fn set_offset(&self, value: i64) -> Result<(), Error> {
        let mut state = self.inner.state.lock().map_err(|_| Error::Io)?;
        if state.clock.offset() == value {
            return Ok(());
        }
        let revision = state.revision.checked_add(1).ok_or(Error::Overflow)?;
        let mut wakes = reserve_wakes(&state)?;
        state.clock.set_offset(value);
        state.revision = revision;
        take_wakes(&mut state, &mut wakes);
        drop(state);
        wake(wakes);
        Ok(())
    }
    /// Apply the source paired testing skew rule without manufacturing a change for
    /// a missing/invalid setting.
    pub fn testing_skew(&self, cfg: &gnunet_config::Configuration) -> Result<(), Error> {
        self.testing_skew_observed(cfg, None)
    }
    /// CONFIG callbacks execute without holding the clock state Mutex.
    pub fn testing_skew_observed(
        &self,
        cfg: &gnunet_config::Configuration,
        observer: Option<gnunet_config::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<(), Error> {
        if let Ok(offset) = cfg.get_number_observed(b"testing", b"skew_offset", observer)
            && let Ok(variance) = cfg.get_number_observed(b"testing", b"skew_variance", observer)
        {
            self.set_offset(offset.wrapping_sub(variance) as i64)?;
        }
        Ok(())
    }
    /// Queue the original speedup ready effect; this does not schedule an OS task.
    pub fn start(&self, cfg: &gnunet_config::Configuration) -> Result<Start, Error> {
        self.start_observed(cfg, None)
    }
    /// CONFIG/source callbacks run outside the state lock. A synchronous callback
    /// that starts a replacement cannot have its authority overwritten.
    pub fn start_observed(
        &self,
        cfg: &gnunet_config::Configuration,
        observer: Option<gnunet_config::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<Start, Error> {
        let attempt = self
            .inner
            .state
            .lock()
            .map_err(|_| Error::Io)?
            .clock
            .start_generation()?;
        let interval = cfg
            .get_time_observed(b"testing", b"SPEEDUP_INTERVAL", observer)
            .map_err(|_| Error::InvalidInput);
        let delta = if interval.is_ok() {
            Some(
                cfg.get_time_observed(b"testing", b"SPEEDUP_DELTA", observer)
                    .map_err(|_| Error::InvalidInput),
            )
        } else {
            None
        };
        let (result, settings) = {
            let mut state = self.inner.state.lock().map_err(|_| Error::Io)?;
            let result = state.clock.commit_start(attempt, interval, delta);
            (result, state.clock.settings())
        };
        if let Ok(start) = result {
            match start {
                Start::Disabled => speedup_notice(
                    observer,
                    "speedup.start.disabled",
                    b"GNUNET_SPEEDUP_start_",
                    80,
                    b"Speed up disabled\n",
                    None,
                ),
                Start::Ready(_) => {
                    speedup_notice(
                        observer,
                        "speedup.start.delta",
                        b"GNUNET_SPEEDUP_start_",
                        85,
                        b"Speed up execution by %s\n",
                        Some(settings.1),
                    );
                    speedup_notice(
                        observer,
                        "speedup.start.interval",
                        b"GNUNET_SPEEDUP_start_",
                        88,
                        b"Speed up executed every %s\n",
                        Some(settings.0),
                    );
                }
            }
        }
        result
    }
    /// Commit an actually delivered speedup task and broadcast its new offset.
    /// Revision exhaustion is preflighted before a tick that changes the offset.
    pub fn tick(&self, ticket: Ticket) -> Result<Advanced, Error> {
        self.tick_observed(ticket, None)
    }
    /// Publish the actual offset/revision and wakeups before its source notice.
    pub fn tick_observed(
        &self,
        ticket: Ticket,
        observer: Option<gnunet_config::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<Advanced, Error> {
        let wall = self.inner.wall.wall_us()?;
        let mut state = self.inner.state.lock().map_err(|_| Error::Io)?;
        let plan = state.clock.plan_tick(ticket, wall)?;
        let changed = plan.offset != state.clock.offset();
        let revision = if changed {
            state.revision.checked_add(1).ok_or(Error::Overflow)?
        } else {
            state.revision
        };
        let mut wakes = reserve_wakes(&state)?;
        let delta = state.clock.settings().1;
        let advanced = state.clock.commit_tick(plan);
        state.revision = revision;
        if changed {
            take_wakes(&mut state, &mut wakes);
        }
        drop(state);
        wake(wakes);
        speedup_notice(
            observer,
            "speedup.tick",
            b"do_speedup",
            52,
            b"Speeding up execution time by %s\n",
            Some(delta),
        );
        Ok(advanced)
    }
    /// Retire the logical timer without changing process offset or waking unrelated
    /// request deadlines. The runtime must cancel this returned original task.
    pub fn stop(&self) -> Result<Option<Ticket>, Error> {
        Ok(self.inner.state.lock().map_err(|_| Error::Io)?.clock.stop())
    }
    /// Retire only this original speedup ticket. A stale run's Drop cannot
    /// cancel a replacement installed through another explicit owner.
    pub fn stop_ticket(&self, ticket: Ticket) -> Result<Option<Ticket>, Error> {
        let mut state = self.inner.state.lock().map_err(|_| Error::Io)?;
        if state.clock.pending() != Some(ticket) {
            return Err(Error::StaleGeneration);
        }
        Ok(state.clock.stop())
    }
    #[cfg(feature = "runtime")]
    pub(crate) fn finish_speedup(
        &self,
        ticket: Option<Ticket>,
        observer: Option<gnunet_config::diagnostic::BorrowedObserver<'_>>,
    ) -> Result<(), Error> {
        let notice = {
            let mut state = self.inner.state.lock().map_err(|_| Error::Io)?;
            if let Some(ticket) = ticket {
                if state.clock.pending() != Some(ticket) {
                    return Err(Error::StaleGeneration);
                }
                if state.clock.stop().is_none() {
                    return Err(Error::StaleGeneration);
                }
            } else if state.clock.pending().is_some() {
                return Err(Error::StaleGeneration);
            }
            state.clock.stop_notice()
        };
        if notice {
            speedup_notice(
                observer,
                "speedup.stop",
                b"GNUNET_SPEEDUP_stop_",
                110,
                b"Stopped execution speed up\n",
                None,
            );
        }
        Ok(())
    }
    /// Observe finite listener credits for a host's resource diagnostics.
    pub fn listeners(&self) -> Result<usize, Error> {
        Ok(self
            .inner
            .state
            .lock()
            .map_err(|_| Error::Io)?
            .slots
            .iter()
            .flatten()
            .count())
    }
}
fn speedup_notice(
    observer: Option<gnunet_config::diagnostic::BorrowedObserver<'_>>,
    id: &'static str,
    function: &'static [u8],
    line: u32,
    template: &'static [u8],
    relative: Option<u64>,
) {
    let Some(observer) = observer else {
        return;
    };
    // The conversion has bounded owned output and no NLS, IO, callbacks or C
    // static buffer mutation; lazy logger admission still controls actual logs.
    let formatted = relative.map(|value| crate::diagnostics::relative_time(value, false));
    let argument;
    let arguments = if let Some(value) = &formatted {
        argument = [gnunet_config::diagnostic::Argument::Bytes(value)];
        argument.as_slice()
    } else {
        &[]
    };
    observer(gnunet_config::diagnostic::Diagnostic {
        level: gnunet_config::diagnostic::Level::DEBUG,
        component: Some(b"util-speedup"),
        site: gnunet_config::diagnostic::Site {
            id,
            file: b"speedup.c",
            function,
            line,
        },
        domain: None,
        template,
        arguments,
    });
}
fn reserve_wakes(state: &State) -> Result<Vec<Waker>, Error> {
    let mut wakes = Vec::new();
    wakes
        .try_reserve_exact(state.slots.len())
        .map_err(|_| Error::Capacity)?;
    Ok(wakes)
}
fn take_wakes(state: &mut State, wakes: &mut Vec<Waker>) {
    for slot in state.slots.iter_mut().flatten() {
        if let Some(waker) = slot.waker.take() {
            wakes.push(waker);
        }
    }
}
fn wake(wakes: Vec<Waker>) {
    for waker in wakes {
        waker.wake();
    }
}
fn sample(inner: &Inner) -> Result<Sample, Error> {
    let wall = inner.wall.wall_us()?;
    let state = inner.state.lock().map_err(|_| Error::Io)?;
    Ok(Sample {
        now: state.clock.absolute(wall),
        revision: state.revision,
    })
}
impl Subscription {
    /// Copy source time; it is not a network/scheduler completion acknowledgement.
    pub fn sample(&self) -> Result<Sample, Error> {
        sample(&self.inner)
    }
    /// Register before sampling a wait. Both Ready and Pending retain the current
    /// waker, and every replacement/drop happens outside the state mutex.
    pub fn poll_changed(
        &mut self,
        cx: &mut Context<'_>,
        observed_revision: u64,
    ) -> Poll<Result<Sample, Error>> {
        let next = cx.waker().clone();
        let mut state = match self.inner.state.lock() {
            Ok(state) => state,
            Err(_) => return Poll::Ready(Err(Error::Io)),
        };
        let Some(slot) = state
            .slots
            .get_mut(self.slot)
            .and_then(Option::as_mut)
            .filter(|slot| slot.generation == self.generation)
        else {
            return Poll::Ready(Err(Error::StaleGeneration));
        };
        let old = slot.waker.replace(next);
        let changed = state.revision != observed_revision;
        drop(state);
        drop(old);
        if changed {
            Poll::Ready(self.sample())
        } else {
            Poll::Pending
        }
    }
}
impl Drop for Subscription {
    fn drop(&mut self) {
        let old = {
            let mut state = match self.inner.state.lock() {
                Ok(state) => state,
                Err(poisoned) => poisoned.into_inner(),
            };
            if state
                .slots
                .get(self.slot)
                .and_then(Option::as_ref)
                .is_some_and(|slot| slot.generation == self.generation)
            {
                state.slots[self.slot].take()
            } else {
                None
            }
        };
        drop(old);
    }
}
