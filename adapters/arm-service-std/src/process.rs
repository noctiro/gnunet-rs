//! ARM process policy over the shared original-child native registry.
//! Command preparation and stop routes are platform-specific; the reactor owns
//! one retained control state per admitted child and never reconstructs a PID.
use crate::registry::Recipe;
use gnunet_native::network::BorrowedStream;
pub use gnunet_service_runtime::process::{
    ChildRegistry, EnvironmentSnapshot, LaunchError, OriginalChild, Reaped, ResourceUsage,
};
use std::{
    io,
    task::{Context, Poll},
};
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
pub use gnunet_service_runtime::process::ProcessLimits;
#[cfg(unix)]
pub use unix::LaunchContext;
#[cfg(unix)]
pub(crate) use unix::*;
#[cfg(windows)]
pub(crate) use windows::*;
#[cfg(windows)]
pub use windows::{LaunchContext, ProcessLimits};

pub(crate) struct Request<'a> {
    pub context: LaunchContext<'a>,
    pub recipe: &'a Recipe,
    pub listeners: Vec<BorrowedStream<'a>>,
    pub mode: ControlMode,
}
pub(crate) struct Spawned {
    pub child: OriginalChild,
    pub control: Control,
    pub diagnostic: Option<LaunchError>,
}
pub(crate) enum SpawnResult {
    Refused { error: Option<io::Error> },
    Admitted(Spawned),
}

#[cfg(unix)]
pub(crate) type ControlEvent = std::convert::Infallible;
#[cfg(windows)]
pub(crate) enum ControlEvent {
    Ready,
    RetirementRequested,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ControlMode {
    Pipe,
    Native,
}

#[cfg(feature = "service")]
pub(crate) struct RetainedChild {
    pub original: OriginalChild,
    pub _control: Control,
}
