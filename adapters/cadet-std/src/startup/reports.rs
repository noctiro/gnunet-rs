//! Optional process logging during one caller-driven CADET invocation.
use gnunet_program_host::{policy::Level, reporting::Reporter};
use std::{fmt, task::Context};

#[derive(Clone, Default)]
pub(super) struct Reports(Option<Reporter>);

impl Reports {
    pub(super) fn process(reporter: Reporter) -> Self {
        Self(Some(reporter))
    }

    pub(super) fn register(&self, cx: &Context<'_>) {
        if let Some(reports) = &self.0 {
            reports.register(cx);
        }
    }

    pub(super) fn failed(&self) -> bool {
        self.0.as_ref().is_some_and(Reporter::failed)
    }

    pub(super) fn configured(&self) -> bool {
        self.0.is_some()
    }

    #[track_caller]
    pub(super) fn message(&self, level: Level, site: &'static str, args: fmt::Arguments<'_>) {
        if let Some(reports) = &self.0 {
            reports.message(level, site, args);
        }
    }

    #[track_caller]
    pub(super) fn warning(&self, site: &'static str, args: fmt::Arguments<'_>) {
        self.message(Level::WARNING, site, args);
    }

    #[track_caller]
    pub(super) fn debug(&self, site: &'static str, args: fmt::Arguments<'_>) {
        self.message(Level::DEBUG, site, args);
    }
}
