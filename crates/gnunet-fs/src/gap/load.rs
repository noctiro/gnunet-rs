//! FS load policy from the original DATASTORE reply latency observations.

use gnunet_types::Error;

const DECLINE_US: u64 = 250_000;
const MAX_DECLINE_STEPS: u64 = 16;
const MAX_SAMPLE_US: u64 = 64 * 1024;
const OVERLOAD_SENTINEL: f64 = 100.0;

#[derive(Clone, Copy, Debug)]
struct Observation {
    time_us: u64,
    spike: bool,
}

/// One service-owned load estimate. GET and PUT observations use separate
/// estimators when both policies are enabled.
#[derive(Debug, Default)]
pub struct DatastoreLoad {
    last: Option<Observation>,
    running_delay: f64,
    count: u64,
    sum: u128,
    squared: u128,
}

impl DatastoreLoad {
    /// Start without observed DATASTORE work.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            last: None,
            running_delay: 0.0,
            count: 0,
            sum: 0,
            squared: 0,
        }
    }

    /// Observe a qualifying callback from the original request and clock.
    /// Delays above 65,536 microseconds are excluded from the baseline.
    /// A regressed clock leaves the original estimate unchanged.
    pub fn record(&mut self, started_us: u64, observed_us: u64) -> Result<(), Error> {
        let delay = observed_us
            .checked_sub(started_us)
            .ok_or(Error::TimeUncertain)?;
        let (running, previous_spike) = self.decayed(observed_us)?;
        let oversized = delay > MAX_SAMPLE_US;
        self.running_delay = if oversized {
            running
        } else {
            self.count = self.count.checked_add(1).ok_or(Error::Overflow)?;
            let sample = u128::from(delay);
            self.sum += sample;
            self.squared += sample * sample;
            (running * 7.0 + delay as f64) / 8.0
        };
        self.last = Some(Observation {
            time_us: observed_us,
            spike: oversized || previous_spike,
        });
        Ok(())
    }

    /// Observe the estimate at a monotonic instant. An idle interval ages the
    /// running estimate whether or not another caller inspected it meanwhile.
    pub fn at(&self, now_us: u64) -> Result<Load, Error> {
        let (running, spike) = self.decayed(now_us)?;
        if self.count < 2 {
            return Ok(Load {
                average: self.sum as f64,
                score: if spike { OVERLOAD_SENTINEL } else { 0.0 },
            });
        }
        let count = self.count as f64;
        let sum = self.sum as f64;
        let average = sum / count;
        let variance = (self.squared as f64 - average * sum) / (count - 1.0);
        // The reference compares the deviation against sample variance.
        let spread = if variance > 0.0 { variance } else { 0.01 };
        Ok(Load {
            average,
            score: (running - average).max(0.0) / spread,
        })
    }

    fn decayed(&self, now_us: u64) -> Result<(f64, bool), Error> {
        let Some(observation) = self.last else {
            return Ok((0.0, false));
        };
        let steps = now_us
            .checked_sub(observation.time_us)
            .ok_or(Error::TimeUncertain)?
            / DECLINE_US;
        if steps > MAX_DECLINE_STEPS {
            return Ok((0.0, false));
        }
        let mut running = self.running_delay;
        for _ in 0..steps {
            running *= 7.0 / 8.0;
        }
        Ok((running, observation.spike))
    }
}

/// One estimate for all forwarding decisions on the same original GET.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Load {
    average: f64,
    score: f64,
}

impl Load {
    /// GET processing requires no respect charge while the score is below one.
    #[must_use]
    pub fn free(&self) -> bool {
        self.score < 1.0
    }

    /// Admit a GET whose achievable respect charge meets the same estimate.
    #[must_use]
    pub fn admits(&self, charged: u32) -> bool {
        self.free() || self.score <= f64::from(charged)
    }

    /// Admit a migration PUT using its own estimate and original priority.
    #[must_use]
    pub fn admits_put(&self, priority: u32) -> bool {
        self.average < 50.0 || self.score < 2.0 * (1.0 + f64::from(priority))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Check the reference policy at fixed input and clock boundaries"
    )]
    fn capacity_charge_and_idle_decline_share_one_estimate() -> Result<(), Error> {
        let mut measure = DatastoreLoad::new();
        for sample in 1..=128 {
            let end = sample * 100;
            measure.record(end - 100, end)?;
        }
        measure.record(13_000, 13_101)?;
        let busy = measure.at(13_101)?;
        assert_eq!(measure.at(13_101)?, busy);
        assert!(!busy.free());
        assert!(!busy.admits(15));
        assert!(busy.admits(16));
        assert!(!busy.admits_put(6));
        assert!(busy.admits_put(7));
        let idle = measure.at(13_101 + DECLINE_US)?;
        assert!(idle.free());
        assert!(idle.admits(0));
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Verify sparse history and rejected time updates retain the original observation"
    )]
    fn oversized_sample_declines_without_poll_sensitive_state() -> Result<(), Error> {
        let mut measure = DatastoreLoad::new();
        measure.record(0, MAX_SAMPLE_US + 1)?;
        let snapshot = measure.at(MAX_SAMPLE_US + 1)?;
        assert!(!snapshot.admits(99));
        assert!(snapshot.admits(100));
        assert!(snapshot.admits_put(0));
        assert_eq!(measure.record(0, MAX_SAMPLE_US), Err(Error::TimeUncertain));
        assert_eq!(measure.at(MAX_SAMPLE_US + 1)?, snapshot);
        assert!(measure.at(MAX_SAMPLE_US + 1 + 17 * DECLINE_US)?.free());
        measure.record(MAX_SAMPLE_US + 1, MAX_SAMPLE_US + 10)?;
        assert!(!measure.at(MAX_SAMPLE_US + 10)?.free());
        measure.record(MAX_SAMPLE_US + 10, MAX_SAMPLE_US + 20)?;
        assert!(measure.at(MAX_SAMPLE_US + 20)?.free());
        Ok(())
    }
}
