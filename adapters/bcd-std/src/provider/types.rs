use gnunet_config::Configuration;
use gnunet_service_runtime::process::ChildExit;
use std::{
    fmt,
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::time::Instant;

/// Original validated HTTP fields. No member is executable TeX or a path.
pub struct RenderRequest {
    /// Select the full contact layout; it does not change QR URI bytes.
    pub full: bool,
    /// Convert the real generated PDF to a QR-only PNG when selected.
    pub png: bool,
    /// Original single-line UTF-8 GNS URI; the nickname is never percent-encoded here.
    pub uri: String,
    /// Values in the fixed public thirteen-field order; literal text only.
    pub fields: [String; 13],
    /// Optional literal GPG fingerprint text.
    pub fingerprint: String,
}
/// Original job targets, never renewed by IO or child progress.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Original canonical absolute microsecond target.
    pub expires: u64,
    /// Original native monotonic hard target.
    pub hard: Instant,
}
/// Cooperative original-job cancellation; the server retains its future to reap.
#[derive(Clone, Default)]
pub struct Stop(Arc<AtomicBool>);
impl Stop {
    /// Create one original-job cooperative stop flag.
    pub fn new() -> Self {
        Self::default()
    }
    /// Request cancellation; the caller still drives original retirement.
    pub fn request_stop(&self) {
        self.0.store(true, Ordering::Release);
    }
    /// Read only the originally shared cancellation fact.
    pub fn is_stopped(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}
/// Application-owned limits, not limits on a native tool's RSS or kernel latency.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum UTF-8 bytes per text field.
    pub field_bytes: usize,
    /// Maximum retained String capacities of the original request.
    pub request_bytes: usize,
    /// Maximum retained fixed-layout TeX source capacity.
    pub tex_bytes: usize,
    /// Maximum returned PDF/PNG allocation capacity.
    pub output_bytes: usize,
    /// Observed per-tool-log limit checked at cooperative polling boundaries.
    pub log_bytes: usize,
    /// Maximum entries examined per directory-budget/cleanup step.
    pub work_files: usize,
    /// Observed aggregate private-work-file size limit, not a kernel quota.
    pub work_bytes: usize,
    /// Finite child/file/cancellation observation interval.
    pub poll_interval: Duration,
    /// Original cleanup delay before escalation from TERM to KILL.
    pub terminate_grace: Duration,
    /// Bounded initial cleanup window before returning its owned Retirement.
    pub cleanup_grace: Duration,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            field_bytes: 2048,
            request_bytes: 32 * 1024,
            tex_bytes: 256 * 1024,
            output_bytes: 16 * 1024 * 1024,
            log_bytes: 1024 * 1024,
            work_files: 32,
            work_bytes: 40 * 1024 * 1024,
            poll_interval: Duration::from_millis(20),
            terminate_grace: Duration::from_millis(500),
            cleanup_grace: Duration::from_secs(5),
        }
    }
}
impl Limits {
    /// Validate finite values and literal paths without probing tools or files.
    pub fn validate(self) -> Result<(), Cause> {
        if self.field_bytes == 0
            || self.request_bytes < self.field_bytes
            || self.tex_bytes < 4096
            || self.output_bytes < 1024
            || self.log_bytes == 0
            || self.work_files < 8
            || self.work_bytes < self.output_bytes
        {
            return Err(Cause::Limit);
        }
        for duration in [self.poll_interval, self.terminate_grace, self.cleanup_grace] {
            if duration.is_zero() || Instant::now().checked_add(duration).is_none() {
                return Err(Cause::Limit);
            }
        }
        if self.terminate_grace > self.cleanup_grace {
            return Err(Cause::Limit);
        }
        self.reservation_bytes()?;
        Ok(())
    }
    /// Conservative application retention reservation; excludes child RSS/kernel buffers.
    pub fn reservation_bytes(self) -> Result<usize, Cause> {
        self.request_bytes
            .checked_add(self.tex_bytes)
            .and_then(|n| n.checked_add(self.output_bytes))
            .and_then(|n| {
                self.work_files
                    .checked_mul(512)
                    .and_then(|m| n.checked_add(m))
            })
            .and_then(|n| n.checked_add(128 * 1024))
            .ok_or(Cause::Limit)
    }
}
/// Explicit selected tools and parent-owned configuration. Validation is pure.
pub struct Settings {
    /// Selected absolute pdflatex executable; checked only for a render invocation.
    pub pdflatex: PathBuf,
    /// Selected absolute Ghostscript executable; only PNG invokes it.
    pub ghostscript: PathBuf,
    /// Selected absolute shared GNUnet native spawn helper.
    pub launcher: PathBuf,
    /// Explicit existing parent for exclusive mode0700 job directories.
    pub temp_root: PathBuf,
    /// Original selected PROGRAM configuration for the shared process port.
    pub configuration: Arc<Configuration>,
    /// Explicit finite application-owned limits.
    pub limits: Limits,
}
impl Settings {
    /// Validate finite values and literal paths without probing tools or files.
    pub fn validate(&self) -> Result<(), Cause> {
        self.limits.validate()?;
        for path in [
            &self.pdflatex,
            &self.ghostscript,
            &self.launcher,
            &self.temp_root,
        ] {
            if !path.is_absolute()
                || path.as_os_str().as_bytes().contains(&0)
                || path.as_os_str().as_bytes().len() > 4096
            {
                return Err(Cause::Input);
            }
        }
        Ok(())
    }
}
/// Actual original failure; no failed provider is replaced with an empty artifact.
#[derive(Debug)]
pub enum Cause {
    /// Malformed or unrepresentable literal input.
    Input,
    /// Explicit resource limit refusal.
    Limit,
    /// Observed original cancellation.
    Cancelled,
    /// Observed original time bound.
    Deadline,
    /// Original typed clock provider failure.
    Clock(gnunet_types::Error),
    /// Original typed filesystem or native IO error.
    Io(std::io::Error),
    /// Original shared launch boundary failure.
    Launch(gnunet_service_runtime::process::LaunchError),
    /// An actually reaped renderer/converter exited unsuccessfully.
    Tool {
        /// Whether this was the selected converter phase.
        png: bool,
        /// Actual original consuming-wait exit.
        exit: ChildExit,
    },
    /// Current-job file shape/ownership or output format is invalid.
    Artifact,
}
impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Cause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Clock(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Launch(error) => Some(error),
            _ => None,
        }
    }
}
impl From<std::io::Error> for Cause {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
/// Only actual wait events fill an exit. Byte counts are observed sizes.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// The original TeX invocation helper child was admitted; not exec/readiness proof.
    pub tex_spawned: bool,
    /// An actual consuming wait returned the original TeX child exit.
    pub tex_reaped: bool,
    /// Actual original TeX invocation exit, never inferred from file presence.
    pub tex_exit: Option<ChildExit>,
    /// The original selected PNG converter child was admitted.
    pub gs_spawned: bool,
    /// An actual consuming wait returned that converter exit.
    pub gs_reaped: bool,
    /// Actual original converter exit.
    pub gs_exit: Option<ChildExit>,
    /// This renderer observed cooperative cancellation.
    pub stop_requested: bool,
    /// The original canonical or native job bound was observed expired.
    pub deadline: bool,
    /// A real original-child TERM syscall was attempted.
    pub term_attempted: bool,
    /// A real original-child KILL syscall was attempted.
    pub kill_attempted: bool,
    /// Actual checked artifact length, not a peer delivery observation.
    pub output_bytes: usize,
    /// The original verified private directory was actually removed.
    pub directory_removed: bool,
    /// Original private job path; retained on an unresolved cleanup failure.
    pub directory_path: Option<PathBuf>,
    /// First independent typed cleanup failure, shared without replacing its source.
    pub cleanup_error: Option<Arc<Cause>>,
    /// Original child or private-directory cleanup is not confirmed complete.
    pub undrained: bool,
}
/// Checked bytes produced by this real invocation and its cleanup report.
pub struct Artifact {
    /// Actual checked current-job PDF or PNG bytes.
    pub bytes: Vec<u8>,
    /// Independent original native and cleanup observations.
    pub report: Report,
}
