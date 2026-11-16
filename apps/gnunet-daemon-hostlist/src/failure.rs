//! Independent product, provider, output and shutdown errors.
use crate::Failure;
use std::io;
#[derive(Debug, Default)]
pub(super) struct Failures {
    pub(super) native: Option<Failure>,
    pub(super) resolver: Option<Failure>,
    pub(super) cleanup: Option<Failure>,
    pub(super) report: Option<io::Error>,
    pub(super) stopped_report: Option<io::Error>,
}
impl Failures {
    pub(super) fn finish(self) -> Result<(), Failure> {
        if self.native.is_none()
            && self.resolver.is_none()
            && self.cleanup.is_none()
            && self.report.is_none()
            && self.stopped_report.is_none()
        {
            Ok(())
        } else {
            Err(Box::new(self))
        }
    }
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HOSTLIST failures: {self:?}")
    }
}
impl std::error::Error for Failures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.native
            .as_deref()
            .or(self.resolver.as_deref())
            .or(self.cleanup.as_deref())
            .or(self
                .report
                .as_ref()
                .map(|error| error as &dyn std::error::Error))
            .or(self
                .stopped_report
                .as_ref()
                .map(|error| error as &dyn std::error::Error))
    }
}
#[derive(Debug, Default)]
pub(super) struct ShutdownFailures {
    pub(super) network: Option<Failure>,
    pub(super) durable: Option<Failure>,
    pub(super) resolver: Option<Failure>,
}
impl std::fmt::Display for ShutdownFailures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "HOSTLIST shutdown: network={:?} durable={:?} resolver={:?}",
            self.network, self.durable, self.resolver
        )
    }
}
impl std::error::Error for ShutdownFailures {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.network
            .as_deref()
            .or(self.durable.as_deref())
            .or(self.resolver.as_deref())
    }
}
