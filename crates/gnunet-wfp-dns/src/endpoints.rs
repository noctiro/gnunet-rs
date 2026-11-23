//! Bounded endpoint-closure observations during native flow classification.
use super::Error;
use core::num::NonZeroU64;

const CAPACITY: usize = 64;

/// The closure boundary at entry to one original native flow observation.
#[derive(Debug)]
pub struct FlowObservation(u64);

pub(super) struct EndpointClosures {
    sequence: Option<u64>,
    next: usize,
    recent: [Option<NonZeroU64>; CAPACITY],
}

impl EndpointClosures {
    pub(super) const fn new() -> Self {
        Self {
            sequence: Some(0),
            next: 0,
            recent: [None; CAPACITY],
        }
    }

    pub(super) fn begin(&self) -> Result<FlowObservation, Error> {
        self.sequence.map(FlowObservation).ok_or(Error::Capacity)
    }

    pub(super) fn record(&mut self, endpoint: NonZeroU64) {
        self.sequence = self.sequence.and_then(|sequence| sequence.checked_add(1));
        self.recent[self.next] = Some(endpoint);
        self.next = (self.next + 1) % CAPACITY;
    }

    pub(super) fn qualify(
        &self,
        FlowObservation(observed): FlowObservation,
        endpoint: NonZeroU64,
    ) -> Result<(), Error> {
        let current = self.sequence.ok_or(Error::Capacity)?;
        let seen = current.checked_sub(observed).ok_or(Error::Stale)?;
        // An overwritten close might be for this endpoint. A recent exact
        // match also covers indications queued while its closure ran.
        if seen > CAPACITY as u64 || self.recent.contains(&Some(endpoint)) {
            return Err(Error::Stale);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn overwritten_window_cannot_confirm_an_original_flow() {
        let mut closures = EndpointClosures::new();
        let original = closures.begin();
        closures.record(NonZeroU64::MIN);
        for _ in 0..CAPACITY {
            closures.record(NonZeroU64::MAX);
        }
        assert_eq!(
            original.and_then(|attempt| closures.qualify(attempt, NonZeroU64::MIN)),
            Err(Error::Stale)
        );
        assert!(
            closures
                .begin()
                .and_then(|next| closures.qualify(next, NonZeroU64::MIN))
                .is_ok()
        );
    }
}
