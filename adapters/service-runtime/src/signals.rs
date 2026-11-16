//! Native termination streams; console detachment precedes handler registration.
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
pub use unix::Termination;
#[cfg(windows)]
pub use windows::Termination;
