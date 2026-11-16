//! Normal official RPS service over shared native startup.
#![deny(unsafe_code)]
mod discovery;
mod foreground;
mod lifecycle;
mod settings;
use gnunet_program_host::service::native::{self, Application, Context};
use std::error::Error;
type Cause = Box<dyn Error>;
struct Service;
impl Application for Service {
    const SECTION: &'static [u8] = b"rps";
    const BINARY: &'static str = "gnunet-service-rps";
    type Settings = settings::Settings;
    fn settings(config: &gnunet_config::Configuration) -> Result<Self::Settings, Cause> {
        settings::Settings::read(config)
    }
    fn access(settings: &Self::Settings) -> gnunet_service_runtime::credentials::UnixAccess {
        settings.access
    }
    async fn serve(context: Context<'_, Self::Settings>) -> Result<(), Cause> {
        let cleanup = lifecycle::Cleanup::default();
        let result = foreground::run(foreground::Inputs {
            config: context.config,
            settings: &context.settings,
            bound: context.listeners,
            signals: context.signals,
            clock: context.clock,
            reports: context.reports,
            notification: context.readiness,
            cleanup: cleanup.clone(),
        })
        .await;
        cleanup.finish(result)
    }
}
#[expect(
    unsafe_code,
    reason = "Fresh single-threaded executable entry transfers unique inherited resources before all runtime owners"
)]
fn main() -> std::process::ExitCode {
    // SAFETY: first and only initialization from the fresh executable entrypoint.
    unsafe { native::main::<Service>() }
}
