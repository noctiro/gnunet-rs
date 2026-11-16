//! Shared native lifecycle for normal streaming command processes.
mod capture;
mod signals;
mod stdout;
pub(crate) use capture::Inherited;
pub(crate) use capture::capture;
pub(crate) use signals::Signals;
pub(crate) use stdout::Stdout;
