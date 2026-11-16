//! One native process shell around an application's caller-driven service.
use super::{Preparation, Selected};
use crate::{
    logging::Logger, program::Environment, reporting::Reporter, shared_clock::SharedClock,
};
use gnunet_config::Configuration;
use gnunet_service_runtime::{BoundListeners, credentials::UnixAccess};
use gnunet_service_startup::{StopSignals, StopSubscription};
use std::{
    error::Error,
    fmt,
    future::Future,
    io::{self, Write},
    process::ExitCode,
};
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
use unix as platform;
#[cfg(windows)]
use windows as platform;

/// Original application or native startup failure; local futures need not be Send.
pub type Failure = Box<dyn Error>;

/// Service-specific configuration and business loop. The driver creates no
/// background task, Resolver or protocol owner on the application's behalf.
pub trait Application {
    /// Official configuration section and selected Logger component.
    const SECTION: &'static [u8];
    /// Installed binary name used in diagnostics.
    const BINARY: &'static str;
    /// Capacity of the shared logical-clock subscription registry.
    const CLOCK_SLOTS: usize = 256;
    /// Validated, owned application resource and protocol policy.
    type Settings;
    /// Read settings after detachment, before listeners or business admission.
    fn settings(config: &Configuration) -> Result<Self::Settings, Failure>;
    /// Explicit local credential admission; no platform invents Unix IDs.
    fn access(settings: &Self::Settings) -> UnixAccess;
    /// Drive the original service until physical business owners retire.
    /// Independent cleanup errors must remain in the returned failure.
    fn serve(context: Context<'_, Self::Settings>) -> impl Future<Output = Result<(), Failure>>;
}

/// Original process resources for one application invocation.
pub struct Context<'a, S> {
    /// Configuration loaded once after detachment.
    pub config: &'a Configuration,
    /// Owned application policy validated before identity/listener completion.
    pub settings: S,
    /// Original configured or inherited listeners, retained until serving ends.
    pub listeners: &'a BoundListeners,
    /// Original parent receiver and native stop subscriptions.
    pub signals: StopSignals,
    /// The same logical source used by the selected Logger and application.
    pub clock: SharedClock,
    /// Selected diagnostic owner; failures fence further application admission.
    pub reports: Reporter,
    /// Once-only startup notification. The application signals only after its
    /// actual readiness predicate; a local notification proves no peer result.
    pub readiness: Readiness<'a>,
}

/// Original-parent startup status, without replacement or inferred readiness.
pub struct Readiness<'a> {
    original: platform::Ready<'a>,
}
impl Readiness<'_> {
    /// Submit successful readiness once. Windows submission has a finite native
    /// bound and retains the original intent across canceled or failed waits.
    pub async fn signal(
        self,
        signals: &mut (impl StopSubscription + ?Sized),
        reports: &Reporter,
    ) -> Result<(), Failure> {
        super::acknowledge_ready(
            platform::ready(self.original),
            signals,
            reports,
            std::time::Duration::from_secs(5),
        )
        .await
    }
}

#[derive(Debug)]
struct Reported(Failure);
impl fmt::Display for Reported {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(out)
    }
}
impl Error for Reported {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}
fn finish<A: Application>(result: Result<(), Failure>, reports: &Reporter) -> Result<(), Failure> {
    if let Err(error) = &result {
        reports.message(
            crate::policy::Level::ERROR,
            "service.failure",
            format_args!("{}: {error}", A::BINARY),
        );
    }
    super::retain_diagnostic(result, reports.take_error())
        .map_err(|error| Box::new(Reported(error)) as Failure)
}

/// Enter a normal service process, including configured native detachment.
///
/// # Safety
/// Call exactly once as the fresh single-threaded executable's first operation,
/// before native resource owners, runtime registration, threads or environment
/// mutation can compete with inherited-resource capture. A capture error ends
/// startup; the driver does not replay declarations or continue after refusal.
#[expect(
    unsafe_code,
    reason = "Transfers the caller's exclusive fresh-process inheritance contract"
)]
pub unsafe fn main<A: Application>() -> ExitCode {
    // SAFETY: the caller supplies exclusive fresh-process initialization.
    match unsafe { run::<A>() } {
        Ok(code) => code,
        Err(error) => {
            let _written = writeln!(io::stderr().lock(), "{}: {error}", A::BINARY);
            ExitCode::FAILURE
        }
    }
}
/// Run a normal service process with caller-owned pre-diagnostic error handling.
/// Handled help/parser outcomes and selected-Reporter failures return their real
/// exit status. Failures before selected diagnostics retain their original error.
///
/// # Safety
/// The same unique fresh-process startup contract as [`main`] applies.
#[expect(
    unsafe_code,
    reason = "Forwards exclusive fresh-process initialization exactly once"
)]
pub unsafe fn run<A: Application>() -> Result<ExitCode, Failure> {
    // SAFETY: the caller provides main's exclusive startup contract.
    match unsafe { execute::<A>() } {
        Err(error) if error.downcast_ref::<Reported>().is_some() => Ok(ExitCode::FAILURE),
        result => result,
    }
}
#[expect(
    unsafe_code,
    reason = "Capture is the first native startup operation under main's explicit contract"
)]
unsafe fn execute<A: Application>() -> Result<ExitCode, Failure> {
    // SAFETY: the unique fresh-process contract is forwarded exactly once.
    let captured = unsafe { platform::capture() }?;
    let clock = SharedClock::native(A::CLOCK_SLOTS)?;
    let mut logger = Logger::new(A::SECTION, std::process::id(), true)?;
    let selected = match super::prepare(
        A::SECTION,
        &gnunet_config::ProjectData::default(),
        std::env::args_os(),
        &Environment::capture(),
        &mut logger,
        &clock,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )? {
        Preparation::Ready(selected) => selected,
        Preparation::Stopped { successful } => {
            return Ok(if successful {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            });
        }
    };
    platform::run::<A>(captured, selected, logger, clock).map(|()| ExitCode::SUCCESS)
}
