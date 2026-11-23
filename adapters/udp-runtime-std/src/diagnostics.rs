//! Diagnostic delivery through the enclosing application's selected sink.

use std::fmt;

/// Importance of an observation from the original communicator.
pub enum Severity {
    /// Detailed native and protocol activity.
    Debug,
    /// State transitions and terminal counters.
    Info,
    /// Failures or refused operations requiring attention.
    Warning,
}

/// Diagnostics are supplied by the outer owner and never open files or streams here.
pub trait Diagnostics {
    /// Report whether the original selected sink has latched a failure.
    fn failed(&self) -> bool {
        false
    }

    /// Publish one observation with its stable site identifier.
    #[track_caller]
    fn message(&self, severity: Severity, site: &'static str, args: fmt::Arguments<'_>);

    /// Publish a warning from the original operation.
    #[track_caller]
    fn warning(&self, site: &'static str, args: fmt::Arguments<'_>) {
        self.message(Severity::Warning, site, args);
    }

    /// Publish a detailed observation from the original operation.
    #[track_caller]
    fn debug(&self, site: &'static str, args: fmt::Arguments<'_>) {
        self.message(Severity::Debug, site, args);
    }
}

pub(super) struct Silent;

impl Diagnostics for Silent {
    fn message(&self, _: Severity, _: &'static str, _: fmt::Arguments<'_>) {}
}
