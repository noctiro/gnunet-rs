//! Normal CADET service over the shared native process driver.
#![deny(unsafe_code)]
mod control;
mod foreground;
mod identity;
mod local;
mod peer;
mod readiness;
mod settings;
mod statistics;
use gnunet_program_host::service::native::{self, Application, Context};
use std::error::Error;
type Failure = Box<dyn Error>;

struct Service;
impl Application for Service {
    const SECTION: &'static [u8] = b"cadet";
    const BINARY: &'static str = "gnunet-service-cadet";
    const CLOCK_SLOTS: usize = 4096;
    type Settings = settings::Settings;
    fn settings(config: &gnunet_config::Configuration) -> Result<Self::Settings, Failure> {
        settings::Settings::read(config)
    }
    fn access(settings: &Self::Settings) -> gnunet_service_runtime::credentials::UnixAccess {
        settings.unix
    }
    async fn serve(context: Context<'_, Self::Settings>) -> Result<(), Failure> {
        foreground::run(context).await
    }
}
fn main() -> std::process::ExitCode {
    #[expect(
        unsafe_code,
        reason = "Fresh executable entry transfers inherited resources before competing owners"
    )]
    // SAFETY: first and only startup call, before resources, runtime or threads.
    unsafe {
        native::main::<Service>()
    }
}
