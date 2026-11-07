//! Official v0.29.1 shared program, command-option and logging candidate.
//! Native OS formatting/regex adapters are isolated; no libgnunet FFI is used.
#![deny(unsafe_code)]
pub mod clock;
/// Ordinary configuration-tool composition with explicit selected logging.
pub mod config_command;
pub mod config_observer;
pub mod diagnostics;
pub mod format;
pub mod getopt;
pub mod helpers;
pub mod locale;
pub mod logging;
mod native;
pub mod policy;
pub mod process_stderr;
pub mod program;
pub mod reporting;
pub mod service;

pub mod shared_clock;

#[cfg(feature = "service-runtime")]
mod service_clock;

#[cfg(feature = "resolver-broker")]
pub mod broker;

#[cfg(feature = "resolver-broker")]
pub mod foreground;

#[cfg(feature = "runtime")]
pub mod runtime;

#[cfg(feature = "runtime")]
pub mod daemon;
