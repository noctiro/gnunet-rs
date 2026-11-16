//! Normal official RECLAIM service over shared native startup.
#![deny(unsafe_code)]
mod foreground;
mod settings;
use gnunet_program_host::service::native::{self, Application, Context};
use std::error::Error;
type Failure = Box<dyn Error>;
struct Service;
impl Application for Service {
    const SECTION: &'static [u8] = b"reclaim";
    const BINARY: &'static str = "gnunet-service-reclaim";
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
#[expect(
    unsafe_code,
    reason = "Fresh single-threaded executable entry transfers unique inherited resources before all runtime owners"
)]
fn main() -> std::process::ExitCode {
    // SAFETY: first and only initialization from the fresh executable entrypoint.
    unsafe { native::main::<Service>() }
}
