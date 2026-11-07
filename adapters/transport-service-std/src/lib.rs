//! Independent official TRANSPORT SERVICE/native provider composition.
//! No aggregate peer node or implicit key/storage/communicator fallback.
#![forbid(unsafe_code)]
pub mod burst;
pub mod discovery;
#[cfg(feature = "program")]
mod dv_control;
#[cfg(feature = "program")]
mod dv_driver;
pub mod dv_epoch;
#[cfg(feature = "program")]
mod dv_program;
pub mod dv_resources;
pub mod dv_schedule;
pub mod dv_settings;
/// Actual common Job to Actor submission using the one durable DV allocator.
pub mod dv_transmit;
pub mod epoch;
#[cfg(feature = "program")]
pub mod foreground;
pub mod generation;
pub mod hello;
pub mod owner;
pub mod pils;
pub mod publication;
#[cfg(feature = "program")]
mod reporting;
pub mod sender;
#[cfg(feature = "program")]
mod session;
pub mod settings;
#[cfg(feature = "program")]
mod statistics;
pub mod time;
pub mod validated;
pub mod writer;
/// Original independent host or cleanup boundary failure.
pub type Failure = Box<dyn std::error::Error>;
/// Original failure and independently retained physical cleanup failures.
#[derive(Debug)]
pub struct Failures {
    /// Original operation or service failure, preserved independently of cleanup.
    pub original: Option<Failure>,
    /// Actual cleanup failures from the original separately owned resources.
    pub cleanup: Vec<Failure>,
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TRANSPORT original={:?}, independent cleanup={:?}",
            self.original, self.cleanup
        )
    }
}
impl std::error::Error for Failures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.as_deref()
    }
}
