//! Pure outage accounting shared by installed packet-service recovery policies.
use std::{io, time::Duration};
use tokio::time::Instant;

/// One fixed outage target across retries and short-lived packet admissions.
/// Counters are actual cumulative native packet I/O; a quiet stability interval
/// is caller policy and never a delivery observation. This type owns no timer,
/// task, device, packet, or native restoration authority.
#[derive(Debug, Default)]
pub struct RecoveryBudget {
    hard: Option<Instant>,
    admitted: Option<(Instant, (u64, u64))>,
}
impl RecoveryBudget {
    /// Start or resume the outage. A previous admission must meet the same
    /// caller-selected stability interval before a new outage gets a new target.
    ///
    /// # Errors
    /// Returns an error before storing a target that overflows the native clock.
    pub fn begin(
        &mut self,
        now: Instant,
        timeout: Duration,
        stability: Duration,
    ) -> io::Result<Instant> {
        if self
            .admitted
            .is_some_and(|(at, _)| now.saturating_duration_since(at) >= stability)
        {
            self.hard = None;
        }
        self.admitted = None;
        let hard = match self.hard {
            Some(hard) => hard,
            None => now
                .checked_add(timeout)
                .ok_or_else(|| io::Error::other("packet recovery target overflow"))?,
        };
        self.hard = Some(hard);
        Ok(hard)
    }
    /// Record actual source admission, without renewing its outage target.
    pub fn admitted(&mut self, now: Instant, counters: (u64, u64)) {
        self.admitted = Some((now, counters));
    }
    /// End an episode after positive native I/O or the caller's quiet interval.
    /// Returns whether an outstanding episode ended. The caller checks source
    /// liveness separately and uses a consistent interval across both methods.
    pub fn observe(&mut self, now: Instant, counters: (u64, u64), stability: Duration) -> bool {
        if self.admitted.is_some_and(|(at, before)| {
            before != counters || now.saturating_duration_since(at) >= stability
        }) {
            self.admitted = None;
            self.hard = None;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Injected monotonic targets independently assert retry and short-lived admission never renew an outage"
    )]
    fn repeated_admission_keeps_the_original_outage_target() -> io::Result<()> {
        let now = Instant::now();
        let timeout = Duration::from_secs(10);
        let stability = Duration::from_secs(1);
        let mut budget = RecoveryBudget::default();
        let hard = budget.begin(now, timeout, stability)?;
        assert_eq!(
            budget.begin(now + Duration::from_secs(2), timeout, stability)?,
            hard
        );
        budget.admitted(now + Duration::from_secs(3), (5, 7));
        assert!(!budget.observe(now + Duration::from_millis(3500), (5, 7), stability));
        assert_eq!(
            budget.begin(now + Duration::from_millis(3600), timeout, stability)?,
            hard
        );
        budget.admitted(now + Duration::from_secs(4), (5, 7));
        assert!(budget.observe(now + Duration::from_millis(4100), (6, 7), stability));
        assert_eq!(
            budget.begin(now + Duration::from_secs(5), timeout, stability)?,
            now + Duration::from_secs(15)
        );
        Ok(())
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "A quiet stable source starts a distinct later outage without requiring invented packet traffic"
    )]
    fn stable_quiet_source_starts_a_new_outage() -> io::Result<()> {
        let now = Instant::now();
        let mut budget = RecoveryBudget::default();
        budget.begin(now, Duration::from_secs(10), Duration::from_secs(1))?;
        budget.admitted(now + Duration::from_secs(2), (0, 0));
        assert_eq!(
            budget.begin(
                now + Duration::from_secs(4),
                Duration::from_secs(10),
                Duration::from_secs(1)
            )?,
            now + Duration::from_secs(14)
        );
        Ok(())
    }
}
