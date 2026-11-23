//! Original configured UDP communicator driven by an application or standalone process.
#![forbid(unsafe_code)]

mod addresses;
mod bootstrap;
mod control;
mod diagnostics;
mod embedded;
mod foreground;
mod network;
mod run;
mod settings;

pub use control::Stop;
pub use diagnostics::{Diagnostics, Severity};
pub use embedded::{EmbeddedSettings, Exit, HelloPublisher, Ready, serve_embedded};
pub use foreground::{Bound, Foreground};
pub use run::Report;

type Cause = Box<dyn std::error::Error>;
