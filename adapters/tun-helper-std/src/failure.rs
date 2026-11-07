//! Bounded original syscall causes and actual byte-cursor diagnostics.
use std::{fmt, io};
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Report {
    pub input_bytes: usize,
    pub input_target: usize,
    pub output_written: usize,
    pub output_total: usize,
    pub injection_bytes: usize,
    pub injection_total: usize,
    pub injected: u64,
    pub emitted: u64,
    pub stopped: Option<&'static str>,
}
impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "input={}/{} output={}/{} TUN-write={}/{} injected={} emitted={} stop={:?}",
            self.input_bytes,
            self.input_target,
            self.output_written,
            self.output_total,
            self.injection_bytes,
            self.injection_total,
            self.injected,
            self.emitted,
            self.stopped
        )
    }
}
/// Owned original failure plus bounded independent cleanup causes. Diagnostic
/// metadata never grants readiness, delivery or native-quiescence authority.
pub struct Failure {
    pub(crate) stage: &'static str,
    pub(crate) cause: io::Error,
    pub(crate) cleanup: [Option<(&'static str, io::Error)>; 6],
    pub(crate) report: Report,
    pub(crate) code: u8,
}
impl Failure {
    /// Exit2 denotes credential-reduction failure; other actual refusals use1.
    pub const fn exit_code(&self) -> u8 {
        self.code
    }

    pub(crate) fn new(stage: &'static str, cause: io::Error) -> Self {
        Self {
            stage,
            cause,
            cleanup: std::array::from_fn(|_| None),
            report: Report::default(),
            code: 1,
        }
    }
    pub(crate) fn invalid(stage: &'static str, reason: &'static str) -> Self {
        Self::new(stage, io::Error::new(io::ErrorKind::InvalidInput, reason))
    }
    #[cfg(target_os = "linux")]
    pub(crate) fn add(&mut self, stage: &'static str, cause: io::Error) {
        // There are at most two control closes, original TUN, two standard
        // streams and signal restoration in this one process; no retry loop.
        if let Some(slot) = self.cleanup.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some((stage, cause));
        }
    }
}
impl fmt::Debug for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TunHelperFailure")
            .field("stage", &self.stage)
            .field("cause", &self.cause)
            .field("cleanup", &self.cleanup)
            .field("report", &self.report)
            .field("code", &self.code)
            .finish()
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}; actual cursors: {}",
            self.stage, self.cause, self.report
        )?;
        for (stage, cause) in self.cleanup.iter().flatten() {
            write!(f, "; independent {stage}: {cause}")?;
        }
        Ok(())
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
#[cfg(target_os = "linux")]
#[derive(Debug)]
struct Protocol(gnunet_types::Error);
#[cfg(target_os = "linux")]
impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "official helper frame: {}", self.0)
    }
}
#[cfg(target_os = "linux")]
impl std::error::Error for Protocol {}
#[cfg(target_os = "linux")]
pub(crate) fn protocol(stage: &'static str, error: gnunet_types::Error) -> Failure {
    Failure::new(
        stage,
        io::Error::new(io::ErrorKind::InvalidData, Protocol(error)),
    )
}
