//! Bounded adjustable source for real native host and broker integration tests.
use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, RuntimeClock};
use gnunet_types::Error;
use std::{
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use tokio::time::Instant;
#[derive(Clone, Copy)]
enum Base {
    Frozen(u64),
    Advancing { origin: u64, epoch: Instant },
}
struct State {
    base: Base,
    offset: i64,
    revision: u64,
    slots: Vec<Option<Option<Waker>>>,
}
struct Inner(Mutex<State>);
/// Cloning an adjustable source shares time only; subscribe reserves a new lease.
#[derive(Clone)]
pub struct Adjustable {
    inner: Arc<Inner>,
}
impl Adjustable {
    fn create(base: Base, limit: usize) -> Result<Self, Error> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(limit)
            .map_err(|_| Error::Capacity)?;
        slots.resize_with(limit, || None);
        Ok(Self {
            inner: Arc::new(Inner(Mutex::new(State {
                base,
                offset: 0,
                revision: 0,
                slots,
            }))),
        })
    }
    /// Fixed logical value, changed only by explicit set/offset revisions.
    pub fn frozen(now: u64, limit: usize) -> Result<Self, Error> {
        Self::create(Base::Frozen(now), limit)
    }
    /// Native elapsed time plus an explicit source offset.
    pub fn advancing(now: u64, limit: usize) -> Result<Self, Error> {
        Self::create(
            Base::Advancing {
                origin: now,
                epoch: Instant::now(),
            },
            limit,
        )
    }
    fn adjust(&self, base: Option<Base>, offset: i64) -> Result<(), Error> {
        let wakes = {
            let mut state = self.inner.0.lock().map_err(|_| Error::Io)?;
            let mut wakes = Vec::new();
            wakes
                .try_reserve_exact(state.slots.len())
                .map_err(|_| Error::Capacity)?;
            let revision = state.revision.checked_add(1).ok_or(Error::Overflow)?;
            if let Some(base) = base {
                state.base = base;
            }
            state.offset = offset;
            state.revision = revision;
            for slot in state.slots.iter_mut().flatten() {
                if let Some(wake) = slot.take() {
                    wakes.push(wake);
                }
            }
            wakes
        };
        for wake in wakes {
            wake.wake();
        }
        Ok(())
    }
    /// Replace logical time, preserving an explicit backwards transition.
    pub fn set(&self, now: u64) -> Result<(), Error> {
        self.adjust(Some(Base::Frozen(now)), 0)
    }
    /// Replace the process-style offset while keeping the original native epoch.
    pub fn offset(&self, offset: i64) -> Result<(), Error> {
        self.adjust(None, offset)
    }
    /// Number of live distinct waiter credits, independent of source clones.
    pub fn listeners(&self) -> Result<usize, Error> {
        let state = self.inner.0.lock().map_err(|_| Error::Io)?;
        Ok(state.slots.iter().filter(|slot| slot.is_some()).count())
    }
    /// Alias used by the native physical retry fixture.
    pub fn set_offset(&self, offset: i64) -> Result<(), Error> {
        self.offset(offset)
    }
}
fn sample(state: &State) -> Result<ClockSample, Error> {
    let now = match state.base {
        Base::Frozen(now) => now,
        Base::Advancing { origin, epoch } => origin.saturating_add(
            u64::try_from(epoch.elapsed().as_micros()).map_err(|_| Error::Overflow)?,
        ),
    };
    Ok(ClockSample {
        now: gnunet_types::AbsoluteTime::from_micros(now.saturating_add_signed(state.offset)),
        revision: state.revision,
    })
}
impl RuntimeClock for Adjustable {
    fn sample(&self) -> Result<ClockSample, Error> {
        sample(&*self.inner.0.lock().map_err(|_| Error::Io)?)
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
        let mut state = self.inner.0.lock().map_err(|_| Error::Io)?;
        let slot = state
            .slots
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        state.slots[slot] = Some(None);
        Ok(Box::new(Subscription {
            inner: self.inner.clone(),
            slot,
        }))
    }
}
struct Subscription {
    inner: Arc<Inner>,
    slot: usize,
}
impl ClockSubscription for Subscription {
    fn poll_changed(
        &mut self,
        cx: &mut Context<'_>,
        observed: u64,
    ) -> Poll<Result<ClockSample, Error>> {
        let (result, old) = {
            let mut state = match self.inner.0.lock() {
                Ok(state) => state,
                Err(_) => return Poll::Ready(Err(Error::Io)),
            };
            let Some(slot) = state.slots.get_mut(self.slot).and_then(Option::as_mut) else {
                return Poll::Ready(Err(Error::StaleGeneration));
            };
            let old = slot.replace(cx.waker().clone());
            let result = if state.revision != observed {
                Poll::Ready(sample(&state))
            } else {
                Poll::Pending
            };
            (result, old)
        };
        drop(old);
        result
    }
}
impl Drop for Subscription {
    fn drop(&mut self) {
        let old = {
            let mut state = self
                .inner
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.slots.get_mut(self.slot).and_then(Option::take)
        };
        drop(old);
    }
}
