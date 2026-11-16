//! One current work bound shared with the retained native CLIENT connector.
use super::{Bound, Fault, Protocol};
use gnunet_service_runtime::clock::{Bounds, BoundsError, RuntimeClock};
use std::sync::{Arc, Mutex};

pub(super) struct Gate {
    bound: Mutex<Bound>,
    clock: Arc<dyn RuntimeClock>,
}
impl Gate {
    pub fn new(bound: Bound, clock: Arc<dyn RuntimeClock>) -> Self {
        Self {
            bound: Mutex::new(bound),
            clock,
        }
    }
    // Only the exclusive Runtime writes; the connector has read access. The
    // original attempt retains this gate across Pending and cancelled waits.
    pub fn set(&self, bound: Bound) -> Result<(), Protocol> {
        *self.bound.lock().map_err(|_| Protocol::Unavailable)? = bound;
        Ok(())
    }
    pub fn check(&self) -> Result<u64, Fault> {
        let bound = *self.bound.lock().map_err(|_| Protocol::Unavailable)?;
        check(bound, self.clock.as_ref())
    }
}

pub(super) fn check(bound: Bound, clock: &dyn RuntimeClock) -> Result<u64, Fault> {
    // Drop the shared-state lock before entering a fallible external provider.
    Bounds {
        expires: bound.until,
        hard: bound.hard,
    }
    .check(clock)
    .map_err(|error| match error {
        BoundsError::Deadline => Fault::Deadline,
        BoundsError::Overflow => Protocol::Overflow.into(),
        BoundsError::Clock(error) => error.into(),
    })
}
