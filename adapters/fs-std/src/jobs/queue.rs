//! Bounded due-time scheduling for actual FS task owners.
//!
//! This queue owns admission only. It starts no task, socket, timer or worker;
//! the runtime must consume its private actual-run completion before settling a
//! Permit. Removing a running entry is refused and never claims physical cancel.

use gnunet_types::{AbsoluteTime, Error};
use std::{
    collections::HashMap,
    sync::atomic::{AtomicU64, Ordering},
};

pub(crate) type Key = [u8; 32];
static NEXT_OWNER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug)]
enum State {
    Queued(usize),
    Running(u64),
    Vacant(Option<usize>),
}
#[derive(Debug)]
struct Slot {
    key: Key,
    state: State,
}
#[derive(Clone, Copy, Debug)]
struct Due {
    slot: usize,
    at: AbsoluteTime,
    order: u64,
}
impl Due {
    fn before(self, other: Self) -> bool {
        (self.at, self.order) < (other.at, other.order)
    }
}

/// One runtime admission. Only the queue that issued it may settle this exact
/// generation. It is deliberately not Clone; the native runtime's private
/// completion must retain it through the actual operation and any refusal.
#[derive(Debug)]
pub(crate) struct Permit {
    owner: u64,
    serial: u64,
    key: Key,
}
impl Permit {
    pub(crate) const fn key(&self) -> Key {
        self.key
    }
}

/// Indexed minimum heap with no abandoned/stale due nodes. Every live queued
/// entry has exactly one heap position; every running entry has none. The map
/// and slots grow only on bounded registration, never on observation polls.
#[derive(Debug)]
pub(crate) struct Queue {
    owner: u64,
    max_jobs: usize,
    max_running: usize,
    keys: HashMap<Key, usize>,
    slots: Vec<Slot>,
    free: Option<usize>,
    heap: Vec<Due>,
    running: usize,
    next_order: u64,
    next_serial: u64,
    last_now: Option<AbsoluteTime>,
}
impl Queue {
    pub(crate) fn new(max_jobs: usize, max_running: usize) -> Result<Self, Error> {
        if max_jobs == 0 || max_running == 0 || max_running > max_jobs {
            return Err(Error::InvalidInput);
        }
        let owner = NEXT_OWNER
            .try_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .map_err(|_| Error::Overflow)?;
        Ok(Self {
            owner,
            max_jobs,
            max_running,
            keys: HashMap::new(),
            slots: Vec::new(),
            free: None,
            heap: Vec::new(),
            running: 0,
            next_order: 0,
            next_serial: 0,
            last_now: None,
        })
    }

    /// Register once. A past due time is immediately eligible at the next poll;
    /// no timestamp is invented for admission or native work.
    pub(crate) fn insert(&mut self, key: Key, at: AbsoluteTime) -> Result<(), Error> {
        if self.keys.contains_key(&key) {
            return Err(Error::Conflict);
        }
        if self.keys.len() >= self.max_jobs {
            return Err(Error::Capacity);
        }
        let order = self.next_order.checked_add(1).ok_or(Error::Overflow)?;
        self.keys.try_reserve(1).map_err(|_| Error::Capacity)?;
        self.heap.try_reserve(1).map_err(|_| Error::Capacity)?;
        if self.free.is_none() {
            self.slots.try_reserve(1).map_err(|_| Error::Capacity)?;
        }
        // All fallible preflight precedes logical changes. Enlarged spare
        // allocation on a rejected preflight is not a queued or running job.
        let slot = if let Some(index) = self.free {
            let State::Vacant(next) = self.slots[index].state else {
                return Err(Error::Stale);
            };
            self.free = next;
            self.slots[index].key = key;
            self.slots[index].state = State::Queued(self.heap.len());
            index
        } else {
            let index = self.slots.len();
            self.slots.push(Slot {
                key,
                state: State::Queued(self.heap.len()),
            });
            index
        };
        self.keys.insert(key, slot);
        self.heap.push(Due { slot, at, order });
        self.sift_up(self.heap.len() - 1);
        self.next_order = order;
        Ok(())
    }

    /// Admit one genuinely due entry if concurrency permits. Every successful
    /// poll, including None, advances the known clock watermark. A rollback or
    /// exhausted generation returns an error without changing logical state.
    pub(crate) fn next(&mut self, now: AbsoluteTime) -> Result<Option<Permit>, Error> {
        if self.last_now.is_some_and(|previous| now < previous) {
            return Err(Error::TimeUncertain);
        }
        if self.running >= self.max_running || self.heap.first().is_none_or(|due| due.at > now) {
            self.last_now = Some(now);
            return Ok(None);
        }
        let serial = self.next_serial.checked_add(1).ok_or(Error::Overflow)?;
        let due = self.remove_due(0);
        let key = self.slots[due.slot].key;
        self.slots[due.slot].state = State::Running(serial);
        self.running += 1;
        self.next_serial = serial;
        self.last_now = Some(now);
        Ok(Some(Permit {
            owner: self.owner,
            serial,
            key,
        }))
    }

    /// Only an available run slot needs a due timer. With all slots occupied the
    /// actual completion/control wakeup must make progress, avoiding an already
    /// due timer spinning while it cannot admit work.
    pub(crate) fn next_due(&self) -> Option<AbsoluteTime> {
        if self.running >= self.max_running {
            None
        } else {
            self.heap.first().map(|due| due.at)
        }
    }

    /// Settle only this original owner/generation after actual native work has
    /// stopped. Some requeues in stable FIFO order; None unregisters and releases
    /// one job slot. Rejected settlement leaves the permit's run intact. A past
    /// new due time is allowed and becomes immediately ready, without clock reset.
    pub(crate) fn finish(
        &mut self,
        permit: &Permit,
        at: Option<AbsoluteTime>,
    ) -> Result<(), Error> {
        let slot = self.running_slot(permit)?;
        let order = if at.is_some() {
            let order = self.next_order.checked_add(1).ok_or(Error::Overflow)?;
            self.heap.try_reserve(1).map_err(|_| Error::Capacity)?;
            Some(order)
        } else {
            None
        };
        if let (Some(at), Some(order)) = (at, order) {
            self.slots[slot].state = State::Queued(self.heap.len());
            self.heap.push(Due { slot, at, order });
            self.sift_up(self.heap.len() - 1);
            self.next_order = order;
        } else {
            self.unregister(slot);
        }
        self.running -= 1;
        Ok(())
    }

    /// Remove a queued registration only. A running entry requires its original
    /// native completion and cannot be removed to simulate a cancellation.
    pub(crate) fn remove(&mut self, key: Key) -> Result<(), Error> {
        let slot = *self.keys.get(&key).ok_or(Error::NotFound)?;
        match self.slots[slot].state {
            State::Running(_) => Err(Error::WouldBlock),
            State::Queued(position) => {
                self.remove_due(position);
                self.unregister(slot);
                Ok(())
            }
            State::Vacant(_) => Err(Error::Stale),
        }
    }

    fn running_slot(&self, permit: &Permit) -> Result<usize, Error> {
        if permit.owner != self.owner {
            return Err(Error::StaleGeneration);
        }
        let slot = *self.keys.get(&permit.key).ok_or(Error::StaleGeneration)?;
        match self.slots[slot].state {
            State::Running(serial) if serial == permit.serial => Ok(slot),
            _ => Err(Error::StaleGeneration),
        }
    }
    fn unregister(&mut self, slot: usize) {
        self.keys.remove(&self.slots[slot].key);
        self.slots[slot].state = State::Vacant(self.free);
        self.free = Some(slot);
    }
    fn swap_due(&mut self, left: usize, right: usize) {
        self.heap.swap(left, right);
        self.slots[self.heap[left].slot].state = State::Queued(left);
        self.slots[self.heap[right].slot].state = State::Queued(right);
    }
    fn sift_up(&mut self, mut position: usize) {
        while position > 0 {
            let parent = (position - 1) / 2;
            if !self.heap[position].before(self.heap[parent]) {
                break;
            }
            self.swap_due(position, parent);
            position = parent;
        }
    }
    fn sift_down(&mut self, mut position: usize) {
        loop {
            let Some(left) = position
                .checked_mul(2)
                .and_then(|value| value.checked_add(1))
            else {
                return;
            };
            if left >= self.heap.len() {
                return;
            }
            let right = left + 1;
            let child = if right < self.heap.len() && self.heap[right].before(self.heap[left]) {
                right
            } else {
                left
            };
            if !self.heap[child].before(self.heap[position]) {
                return;
            }
            self.swap_due(position, child);
            position = child;
        }
    }
    fn remove_due(&mut self, position: usize) -> Due {
        let removed = self.heap.swap_remove(position);
        if position < self.heap.len() {
            self.slots[self.heap[position].slot].state = State::Queued(position);
            if position > 0 && self.heap[position].before(self.heap[(position - 1) / 2]) {
                self.sift_up(position);
            } else {
                self.sift_down(position);
            }
        }
        removed
    }
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Queue model tests assert finite scheduling state while propagating fallible admission"
)]
mod tests {
    use super::*;
    fn key(index: u8) -> Key {
        [index; 32]
    }
    fn take(queue: &mut Queue, now: u64) -> Result<Permit, Error> {
        queue
            .next(AbsoluteTime::from_micros(now))?
            .ok_or(Error::NotReady)
    }
    #[test]
    fn due_fifo_concurrency_and_requeue_share_one_bounded_heap() -> Result<(), Error> {
        let mut queue = Queue::new(3, 2)?;
        queue.insert(key(1), AbsoluteTime::from_micros(10))?;
        queue.insert(key(2), AbsoluteTime::from_micros(10))?;
        queue.insert(key(3), AbsoluteTime::from_micros(5))?;
        assert_eq!(queue.next_due(), Some(AbsoluteTime::from_micros(5)));
        assert!(queue.next(AbsoluteTime::from_micros(4))?.is_none());
        let first = take(&mut queue, 5)?;
        assert_eq!(first.key(), key(3));
        let second = take(&mut queue, 10)?;
        assert_eq!(second.key(), key(1));
        assert!(queue.next(AbsoluteTime::from_micros(10))?.is_none());
        assert_eq!(queue.next_due(), None);
        assert_eq!(queue.remove(key(1)), Err(Error::WouldBlock));
        queue.finish(&first, Some(AbsoluteTime::from_micros(10)))?;
        let third = take(&mut queue, 10)?;
        assert_eq!(third.key(), key(2));
        queue.finish(&second, None)?;
        let fourth = take(&mut queue, 10)?;
        assert_eq!(fourth.key(), key(3));
        queue.finish(&third, None)?;
        queue.finish(&fourth, None)?;
        assert!(queue.keys.is_empty() && queue.heap.is_empty());
        assert_eq!((queue.running, queue.slots.len()), (0, 3));
        Ok(())
    }
    #[test]
    fn foreign_and_old_permits_cannot_settle_reused_task_or_slot() -> Result<(), Error> {
        let mut a = Queue::new(1, 1)?;
        let mut b = Queue::new(1, 1)?;
        a.insert(key(1), AbsoluteTime::from_micros(1))?;
        b.insert(key(1), AbsoluteTime::from_micros(1))?;
        let original = take(&mut a, 1)?;
        let foreign = take(&mut b, 1)?;
        assert_eq!(b.finish(&original, None), Err(Error::StaleGeneration));
        assert_eq!(b.running, 1);
        a.finish(&original, None)?;
        a.insert(key(1), AbsoluteTime::from_micros(1))?;
        let newer = take(&mut a, 1)?;
        assert_eq!(a.finish(&original, None), Err(Error::StaleGeneration));
        assert_eq!(a.running, 1);
        a.finish(&newer, None)?;
        b.finish(&foreign, None)?;
        assert_eq!(a.finish(&newer, None), Err(Error::StaleGeneration));
        Ok(())
    }
    #[test]
    fn capacity_clock_and_exhaustion_refuse_without_losing_live_entries() -> Result<(), Error> {
        assert!(matches!(Queue::new(0, 1), Err(Error::InvalidInput)));
        let mut queue = Queue::new(2, 1)?;
        queue.insert(key(1), AbsoluteTime::from_micros(5))?;
        queue.insert(key(2), AbsoluteTime::from_micros(6))?;
        assert_eq!(
            queue.insert(key(3), AbsoluteTime::from_micros(1)),
            Err(Error::Capacity)
        );
        assert_eq!(
            queue.insert(key(1), AbsoluteTime::from_micros(1)),
            Err(Error::Conflict)
        );
        assert_eq!(queue.remove(key(3)), Err(Error::NotFound));
        queue.remove(key(1))?;
        assert_eq!(queue.heap.len(), 1);
        queue.insert(key(3), AbsoluteTime::from_micros(1))?;
        assert_eq!(queue.slots.len(), 2);
        queue.next_serial = u64::MAX;
        assert!(matches!(
            queue.next(AbsoluteTime::from_micros(5)),
            Err(Error::Overflow)
        ));
        assert_eq!(queue.last_now, None);
        assert_eq!(queue.heap.len(), 2);
        queue.next_serial = 0;
        let running = take(&mut queue, 5)?;
        assert_eq!(running.key(), key(3));
        assert!(matches!(
            queue.next(AbsoluteTime::from_micros(4)),
            Err(Error::TimeUncertain)
        ));
        assert_eq!(queue.last_now, Some(AbsoluteTime::from_micros(5)));
        queue.next_order = u64::MAX;
        assert_eq!(
            queue.finish(&running, Some(AbsoluteTime::from_micros(0))),
            Err(Error::Overflow)
        );
        assert_eq!(queue.running, 1);
        queue.finish(&running, None)?;
        let last = take(&mut queue, 6)?;
        assert_eq!(last.key(), key(2));
        queue.finish(&last, None)?;
        assert_eq!(queue.next_due(), None);
        assert!(queue.next(AbsoluteTime::from_micros(10))?.is_none());
        assert!(matches!(
            queue.next(AbsoluteTime::from_micros(9)),
            Err(Error::TimeUncertain)
        ));
        Ok(())
    }
}
