//! Normal official CONVERSATION service over shared native process startup.
#![deny(unsafe_code)]
mod foreground;
mod lifecycle;
mod settings;
use gnunet_program_host::service::native::{self, Application, Context};
use std::error::Error;
type Cause = Box<dyn Error>;
#[derive(Clone, Copy)]
struct Mode;
impl Mode {
    const fn section(self) -> &'static [u8] {
        b"conversation"
    }
    const fn binary(self) -> &'static str {
        "gnunet-service-conversation"
    }
}
struct Service;
impl Application for Service {
    const SECTION: &'static [u8] = b"conversation";
    const BINARY: &'static str = "gnunet-service-conversation";
    const CLOCK_SLOTS: usize = 4096;
    type Settings = settings::Settings;
    fn settings(config: &gnunet_config::Configuration) -> Result<Self::Settings, Cause> {
        settings::Settings::read(config, Mode)
    }
    fn access(settings: &Self::Settings) -> gnunet_service_runtime::credentials::UnixAccess {
        settings.access
    }
    async fn serve(context: Context<'_, Self::Settings>) -> Result<(), Cause> {
        let cleanup = lifecycle::Cleanup::default();
        let result = foreground::run(foreground::Inputs {
            mode: Mode,
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
/// Enter the ordinary installed CONVERSATION service executable.
///
/// # Safety
/// Call once as a fresh single-threaded executable's first operation, before
/// native resources, runtime, threads or environment mutation can compete.
#[expect(
    unsafe_code,
    reason = "Public executable boundary forwards exclusive inheritance exactly once"
)]
pub unsafe fn main() -> std::process::ExitCode {
    // SAFETY: caller supplies the unique fresh-process initialization contract.
    unsafe { native::main::<Service>() }
}
