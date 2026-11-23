//! Normal CADET service over the shared native process driver.
#![deny(unsafe_code)]
mod statistics;

use gnunet_cadet_host::startup::{self, Settings};
use gnunet_program_host::service::native::{self, Application, Context, Failure};

struct Service;
impl Application for Service {
    const SECTION: &'static [u8] = b"cadet";
    const BINARY: &'static str = "gnunet-service-cadet";
    const CLOCK_SLOTS: usize = startup::PROCESS_CLOCK_SLOTS;
    type Settings = Settings;

    fn settings(config: &gnunet_config::Configuration) -> Result<Self::Settings, Failure> {
        let settings = Settings::read(config)?;
        statistics::limits(settings.statistics_timeout()).validate()?;
        Ok(settings)
    }

    fn access(settings: &Self::Settings) -> gnunet_service_runtime::credentials::UnixAccess {
        settings.unix_access()
    }

    async fn serve(context: Context<'_, Self::Settings>) -> Result<(), Failure> {
        let mut instance = gnunet_ipc_unix::handle::Instance::new();
        let instance = &mut instance;
        let reports = context.reports.clone();
        startup::serve_process(context, move |publication| {
            statistics::publisher(instance, publication, reports)
        })
        .await
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
