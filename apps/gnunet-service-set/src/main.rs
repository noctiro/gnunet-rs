//! Normal official SET service over shared native process startup.
#![deny(unsafe_code)]
mod foreground;
mod lifecycle;
mod settings;
use gnunet_program_host::service::native::{self, Application, Context};
use std::error::Error;
type Cause = Box<dyn Error>;
struct Service;
impl Application for Service {
    const SECTION: &'static [u8] = b"set";
    const BINARY: &'static str = "gnunet-service-set";
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
            ready: context.readiness,
            cleanup: cleanup.clone(),
        })
        .await;
        cleanup.finish(result)
    }
}
fn main() -> std::process::ExitCode {
    #[expect(
        unsafe_code,
        reason = "Fresh executable entry transfers exclusive inherited native resources"
    )]
    // SAFETY: first and only startup call, before competing owners or threads.
    unsafe {
        native::main::<Service>()
    }
}
