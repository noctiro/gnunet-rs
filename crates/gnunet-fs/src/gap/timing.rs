//! GAP forwarding observations from the original local transmission and route owners.

// Two GNUnet MAX_CORK_DELAY intervals of one second each.
const CORK_BUDGET_US: f64 = 2_000_000.0;
const WARM_SAMPLES: u8 = 4;
const BASELINE_WINDOW: u8 = 128;

/// Local FS-to-CORE handoff delays for one authenticated peer generation.
///
/// The stock LOAD tracker starts with zero autodecline, which clears its load
/// at every read, and discards delays above 65,536 microseconds from its mean.
/// Retain the intended congestion and latency checks with a bounded moving
/// baseline over unfiltered observations. A handoff interval measures local
/// queueing, never receipt by the remote peer.
#[derive(Clone, Copy, Debug, Default)]
pub struct TransmissionTiming {
    samples: u8,
    average_us: f64,
    variance: f64,
    recent_us: f64,
    squared_load: f64,
}

impl TransmissionTiming {
    /// Start without any handoff observations.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            samples: 0,
            average_us: 0.0,
            variance: 0.0,
            recent_us: 0.0,
            squared_load: 0.0,
        }
    }

    /// Record one original completed handoff interval in microseconds.
    pub fn record(&mut self, elapsed_us: u64) {
        let sample = elapsed_us as f64;
        self.recent_us = if self.samples == 0 {
            sample
        } else {
            (self.recent_us * 7.0 + sample) / 8.0
        };
        if self.samples >= WARM_SAMPLES {
            // Use the earlier baseline so the latest delay cannot hide its own
            // excursion. One microsecond of spread is the clock's resolution.
            let above = (self.recent_us - self.average_us).max(0.0);
            self.squared_load = above * above / self.variance.max(1.0);
        }
        self.samples = (self.samples + 1).min(BASELINE_WINDOW);
        let weight = 1.0 / f64::from(self.samples);
        let change = sample - self.average_us;
        self.average_us += weight * change;
        self.variance = (1.0 - weight) * (self.variance + weight * change * change);
    }

    /// Whether this return peer requires the request to use relay-only forwarding.
    /// The absolute delay bound applies even before the relative load is warm.
    #[must_use]
    pub fn relay_only(&self, paid_priority: u32, route_lifetimes: &RouteLifetime) -> bool {
        let threshold = 3.0 * (1.0 + f64::from(paid_priority));
        self.squared_load > threshold * threshold
            || self.average_us > CORK_BUDGET_US + route_lifetimes.average_us()
    }
}

/// Service-wide history of time to the first accepted terminal result for a route.
#[derive(Clone, Copy, Debug, Default)]
pub struct RouteLifetime {
    samples: u64,
    total_us: u128,
}

impl RouteLifetime {
    /// Start without any completed route observations.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            samples: 0,
            total_us: 0,
        }
    }

    /// Record the original route's elapsed lifetime in microseconds.
    pub fn record(&mut self, elapsed_us: u64) {
        if let Some(samples) = self.samples.checked_add(1) {
            self.total_us += u128::from(elapsed_us);
            self.samples = samples;
        }
    }

    /// Mean terminal lifetime in microseconds, zero before the first observation.
    #[must_use]
    pub fn average_us(&self) -> f64 {
        self.total_us as f64 / self.samples.max(1) as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checks_congestion_against_the_warm_baseline_and_paid_priority() {
        let lifetime = RouteLifetime::new();
        let mut timing = TransmissionTiming::new();
        assert!(!timing.relay_only(0, &lifetime));
        for _ in 0..WARM_SAMPLES {
            timing.record(100);
            assert!(!timing.relay_only(0, &lifetime));
        }
        timing.record(140);
        assert!(timing.relay_only(0, &lifetime));
        assert!(!timing.relay_only(1, &lifetime));
        for _ in 0..BASELINE_WINDOW {
            timing.record(100);
        }
        assert!(!timing.relay_only(0, &lifetime));
    }

    #[test]
    fn long_handoffs_use_the_cork_budget_and_unfiltered_terminal_lifetime() {
        let mut lifetime = RouteLifetime::new();
        lifetime.record(1_000_000);
        lifetime.record(5_000_000);
        let mut timing = TransmissionTiming::new();
        timing.record(5_000_000);
        assert!(!timing.relay_only(0, &lifetime));
        assert!(timing.relay_only(0, &RouteLifetime::new()));
        timing.record(5_000_002);
        assert!(timing.relay_only(u32::MAX, &lifetime));
    }
}
