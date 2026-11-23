//! Historical priority and retry jitter for the local FS forwarding queue.

use super::Entropy;
use gnunet_types::Error;

const HISTORY_WINDOW: f64 = 128.0;
pub(super) const RETRY_FLOOR_US: u64 = 5_000_000;
const MAX_JITTER_US: u32 = u32::MAX - 1;

/// A forwarding plan's FS queue rank. This type carries no wire priority or
/// CORE transport preferences.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct QueueWeight(u64);

impl QueueWeight {
    /// Whether this attempt ranks with a fresh query.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }
}

/// Locally queued attempt with its first eligible dispatch time and rank.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Plan {
    ready_at_us: u64,
    weight: QueueWeight,
}

impl Plan {
    /// Earliest dispatch time in the original runtime's microsecond clock.
    #[must_use]
    pub const fn ready_at(self) -> u64 {
        self.ready_at_us
    }

    /// Rank among eligible attempts. Larger ranks run first.
    #[must_use]
    pub const fn weight(self) -> QueueWeight {
        self.weight
    }
}

/// One service-wide history of achievable incoming charges and planned jitter.
#[derive(Debug, Default)]
pub struct History {
    priority: f64,
    delay: f64,
}

impl History {
    /// Start from empty history.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            priority: 0.0,
            delay: 0.0,
        }
    }

    /// Observe the achievable charge once for an original, load-metered GET.
    /// The charge can be refunded when the load test declines the request.
    /// Zero charges provide no observation. Each sample can raise the estimate
    /// by at most one, independent of the sending peer's balance.
    pub fn observe_offer(&mut self, charge: u32) {
        if charge == 0 {
            return;
        }
        let sample = f64::from(charge).min(self.priority + HISTORY_WINDOW);
        self.priority = (self.priority * (HISTORY_WINDOW - 1.0) + sample) / HISTORY_WINDOW;
    }

    pub(super) fn observe_initial(&mut self) {
        self.observe_delay(0);
    }

    fn observe_delay(&mut self, jitter: u32) {
        self.delay =
            ((self.delay * (HISTORY_WINDOW - 1.0) + f64::from(jitter)) / HISTORY_WINDOW) + 0.01;
    }

    /// Schedule this route's next attempt to a particular peer. A first
    /// attempt is immediately ready. Retries draw jitter from a progressively
    /// larger window and wait at least five seconds. The caller retains this
    /// plan until dispatch or withdrawal so a poll cannot resample jitter.
    pub fn plan(
        &mut self,
        now_us: u64,
        previous_attempts: u16,
        entropy: &mut impl Entropy,
    ) -> Result<Plan, Error> {
        let jitter = if previous_attempts == 0 {
            0
        } else {
            let upper = jitter_limit(previous_attempts) + 1;
            let jitter = entropy.uniform(upper)?;
            if jitter >= upper {
                return Err(Error::InvalidInput);
            }
            jitter
        };
        let wait = u64::from(jitter) + u64::from(previous_attempts != 0) * RETRY_FLOOR_US;
        let ready_at_us = now_us.checked_add(wait).ok_or(Error::Overflow)?;
        self.observe_delay(jitter);
        // The reference rounds the weighted angle before dividing by π/4.
        let angle = libm::atan(f64::from(jitter) / self.delay);
        let weight = libm::round((self.priority + 1.0) * angle) / core::f64::consts::FRAC_PI_4;
        Ok(Plan {
            ready_at_us,
            weight: QueueWeight(weight as u64),
        })
    }
}

fn jitter_limit(previous_attempts: u16) -> u32 {
    let attempts = u64::from(previous_attempts.min(32));
    let window_seconds = if attempts < 8 {
        attempts
    } else {
        8 + (1_u64 << (attempts - 8))
    };
    // Entropy's exclusive upper bound is u32. Keep the full representable
    // range once the window reaches that limit, without wrapping it.
    (window_seconds * 1_000_000).min(u64::from(MAX_JITTER_US)) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    struct WindowEnd;

    impl Entropy for WindowEnd {
        fn uniform(&mut self, upper: u32) -> Result<u32, Error> {
            upper.checked_sub(1).ok_or(Error::InvalidInput)
        }
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert reference estimates and ready times under fixed entropy"
    )]
    fn recent_charges_rank_delayed_attempts_without_affecting_the_first_send() -> Result<(), Error>
    {
        let mut history = History::new();
        history.observe_offer(u32::MAX);
        history.observe_offer(10_000);
        history.observe_offer(0);
        assert_eq!(history.priority, 2.0);

        let first = history.plan(17, 0, &mut WindowEnd)?;
        assert_eq!(first.ready_at(), 17);
        assert_eq!(first.weight(), QueueWeight(0));

        let retry = history.plan(17, 1, &mut WindowEnd)?;
        assert_eq!(retry.ready_at(), 6_000_017);
        assert_eq!(retry.weight(), QueueWeight(6));

        history.observe_offer(1);
        assert_eq!(history.priority, 1.992_187_5);
        Ok(())
    }

    #[test]
    fn jitter_window_saturates_before_entropy_bound_overflow() {
        assert_eq!(jitter_limit(0), 0);
        assert_eq!(jitter_limit(7), 7_000_000);
        assert_eq!(jitter_limit(8), 9_000_000);
        assert_eq!(jitter_limit(9), 10_000_000);
        assert_eq!(jitter_limit(20), 4_104_000_000);
        assert_eq!(jitter_limit(21), MAX_JITTER_US);
        assert_eq!(jitter_limit(u16::MAX), MAX_JITTER_US);
    }
}
