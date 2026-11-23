//! The installed finite per-peer REGEX publisher.
mod policy;
mod rounds;
use crate::{
    Failure, NativeFactory, Settings,
    lifecycle::{self, Frontend},
    reporting::Diagnostics,
};
use gnunet_program_host::{
    getopt::Options,
    logging::Logger,
    program::{self, Defaults, Invocation, Preparation},
    reporting::Reporter,
    service,
    shared_clock::SharedClock,
};
use gnunet_service_startup::{ClientStartup, StopSignals};
pub(crate) use policy::Policy;
pub(crate) use rounds::{RoundProgress, Rounds};
use std::{io, process::ExitCode, sync::Arc};

const BINARY: &[u8] = b"gnunet-daemon-regexprofiler";

/// Read the selected policy and run its original PILS and DHT publisher.
///
/// # Safety
/// Call from fresh single-threaded process entry before adopting any inherited
/// process resources or creating a runtime.
#[expect(
    unsafe_code,
    reason = "Capture PROGRAM's original inherited parent at process entry"
)]
pub unsafe fn run_profiler() -> Result<ExitCode, Failure> {
    // SAFETY: the command supplies the inherited resource entry contract.
    let inherited = unsafe { ClientStartup::capture()? };
    let clock = SharedClock::native(128)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(BINARY, std::process::id(), false)?;
    let prepared = program::prepare_installed(
        config,
        Invocation {
            binary_name: BINARY,
            help: Some(b"Publish the TESTBED peer's REGEXPROFILER policy through PILS and DHT."),
            select_default_filename: true,
            defaults: Defaults::Native,
        },
        Options::new(),
        std::env::args_os(),
        &program::Environment::capture(),
        &mut logger,
        &clock,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )?;
    let prepared = match prepared {
        Preparation::Ready(prepared) => prepared,
        Preparation::Stopped(stopped) => {
            return match stopped.reason {
                program::StoppedReason::Options if stopped.code >= 0 => Ok(ExitCode::SUCCESS),
                program::StoppedReason::Logging(error) => Err(error.into()),
                program::StoppedReason::Malformed(error) => Err(error.into()),
                reason => Err(io::Error::other(format!(
                    "REGEX profiler PROGRAM stopped: {reason:?}"
                ))
                .into()),
            };
        }
    };
    if !prepared.main().arguments.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "REGEX profiler accepts no positional arguments",
        )
        .into());
    }
    let config = prepared.main().config.duplicate()?;
    let mut settings = Settings::read(&config)?;
    settings.core.clients = 1;
    settings.core.jobs = 1;
    settings.core.branches = 1;
    settings.core.outputs = 1;
    settings.core.seen_results = 1;
    settings.host.clients = 1;
    settings.host.frame_bytes = 17;
    settings.host.output_bytes = 17;
    settings.driver.operations = 1;
    let policy = Policy::read(
        &config,
        settings
            .core
            .input_bytes
            .min(settings.core.compiler.expression_bytes),
    )?;
    let diagnostics = Diagnostics::new(Reporter::new(logger, clock.clone()));
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            lifecycle::run::<NativeFactory>(lifecycle::Inputs {
                config,
                settings,
                clock: Arc::new(clock),
                control: StopSignals::for_client(inherited.parent)?,
                frontend: Frontend::Profiler(policy),
                diagnostics: &diagnostics,
            })
            .await
        });
    service::retain_diagnostic(result, diagnostics.take_failure())?;
    Ok(ExitCode::SUCCESS)
}
