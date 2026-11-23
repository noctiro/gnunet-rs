//! Actual standard REGEX SERVICE frontend, parameterized by a real DHT Factory.
//!
//! NativeFactory provides the actual ordinary DHT binding, with no dummy backend.
//! It joins the admitted IPC/distributed Core, real PILS signer, shared Resolver,
//! caller's actual DHT provider, selected logging and official statistics owner.
#![deny(unsafe_code, missing_docs)]
mod control;
mod factory;
mod lifecycle;
mod native;
pub use native::NativeFactory;
mod profiler;
pub use profiler::run_profiler;
mod reporting;
mod settings;
/// Bounded original STATISTICS owner, implemented independently from business IPC.
pub mod statistics;
pub use factory::{Context, Factory};
use gnunet_program_host::{
    policy::Level,
    service::{self, native as process},
};
pub use lifecycle::{Errors, LifecycleFailure, Report};
pub use settings::Settings;
use std::{
    io::{self, Write},
    marker::PhantomData,
    process::ExitCode,
    sync::Arc,
};
/// Original native/configuration/provider failure, retaining its source chain.
pub type Failure = Box<dyn std::error::Error>;
struct Application<F>(PhantomData<F>);
impl<F: Factory> process::Application for Application<F> {
    const SECTION: &'static [u8] = b"regex";
    const BINARY: &'static str = "gnunet-service-regex";
    const CLOCK_SLOTS: usize = 1024;
    type Settings = Settings;
    fn settings(config: &gnunet_config::Configuration) -> Result<Settings, Failure> {
        Settings::read(config)
    }
    fn access(settings: &Settings) -> gnunet_service_runtime::credentials::UnixAccess {
        settings.unix
    }
    async fn serve(context: process::Context<'_, Settings>) -> Result<(), Failure> {
        let diagnostics = reporting::Diagnostics::new(context.reports.clone());
        let report = lifecycle::run::<F>(lifecycle::Inputs {
            config: context.config.duplicate()?,
            settings: context.settings,
            clock: Arc::new(context.clock),
            control: context.signals,
            frontend: lifecycle::Frontend::Service {
                bound: context.listeners,
                notification: context.readiness,
            },
            diagnostics: &diagnostics,
        })
        .await;
        let report = service::retain_diagnostic(report, diagnostics.take_failure())?;
        diagnostics.message(
            "regex.stopped",
            Level::INFO,
            format_args!("REGEX actual owners stopped: {report:?}"),
        )?;
        let mut output = io::stdout().lock();
        writeln!(output, "STOPPED regex {report:?}")?;
        output.flush()?;
        Ok(())
    }
}
/// Run the normal REGEX service with an actual caller-selected DHT factory.
/// No factory storage/provider exists before native process and listener setup.
///
/// # Safety
/// Call once as the first initialization of a fresh single-threaded executable,
/// before competing resource owners, runtime, threads or environment mutation.
#[expect(
    unsafe_code,
    reason = "Explicit executable boundary forwards unique inherited-resource ownership"
)]
pub unsafe fn run<F: Factory>() -> Result<ExitCode, Failure> {
    // SAFETY: the caller supplies the shared native process entry contract.
    unsafe { process::run::<Application<F>>() }
}
