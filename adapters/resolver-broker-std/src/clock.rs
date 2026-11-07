//! Actual logical absolute clock ports; no origin-relative clock masquerades as UTC.
pub use gnunet_service_runtime::clock::{
    AbsoluteTime, ClockSample, ClockSubscription, RuntimeClock, SystemClock,
};
