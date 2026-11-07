//! Bounded monotonic deadlines over generation-checked slots.
use crate::slot::SlotTable;
use gnunet_types::{Error, GenerationalId, MonoInstant, Rejected};

/// A fixed timer table; each deadline and completion consumes one real metadata slot.
pub struct TimerWheel<T, const N: usize> {
    timers: SlotTable<(MonoInstant, T), N>,
}

impl<T, const N: usize> Default for TimerWheel<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T, const N: usize> TimerWheel<T, N> {
    /// Create an empty bounded monotonic timer table.
    #[must_use]
    pub fn new() -> Self {
        Self {
            timers: SlotTable::new(),
        }
    }
    /// Schedule one completion, returning its value if metadata capacity is exhausted.
    pub fn schedule(&mut self, at: MonoInstant, value: T) -> Result<GenerationalId, Rejected<T>> {
        self.timers
            .insert((at, value))
            .map_err(|rejected| Rejected {
                value: rejected.value.1,
                reason: rejected.reason,
            })
    }
    /// Cancel a still-live timer; late IDs cannot cancel a replacement timer.
    pub fn cancel(&mut self, id: GenerationalId) -> Result<T, Error> {
        self.timers.remove(id).map(|(_, value)| value)
    }
    /// Earliest deadline; scanning is bounded by the configured timer slot count.
    #[must_use]
    pub fn next_deadline(&self) -> Option<MonoInstant> {
        self.timers.iter().map(|(_, (at, _))| *at).min()
    }
    /// Remove at most one due timer. The owner controls its own event budget.
    pub fn pop_due(&mut self, now: MonoInstant) -> Result<Option<T>, Error> {
        let id = self
            .timers
            .iter()
            .filter(|(_, (at, _))| *at <= now)
            .min_by_key(|(_, (at, _))| *at)
            .map(|(id, _)| id);
        id.map(|id| self.cancel(id)).transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_timer_cannot_cancel_replacement() -> Result<(), Error> {
        let mut timers = TimerWheel::<u8, 1>::new();
        let id = timers.schedule(MonoInstant(2), 1).map_err(|r| r.reason)?;
        timers.cancel(id)?;
        let replacement = timers.schedule(MonoInstant(3), 2).map_err(|r| r.reason)?;
        if timers.cancel(id) != Err(Error::StaleGeneration)
            || timers.pop_due(MonoInstant(2))?.is_some()
            || timers.pop_due(MonoInstant(3))? != Some(2)
            || timers.cancel(replacement) != Err(Error::StaleGeneration)
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
