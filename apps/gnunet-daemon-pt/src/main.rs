//! Official PT daemon foreground; all active defaults come from [pt].
#![deny(unsafe_code)]
mod identity;
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
fn diagnostic(args: std::fmt::Arguments<'_>) {
    let _written = writeln!(io::stderr().lock(), "{args}");
}
#[expect(
    unsafe_code,
    reason = "Fresh process transfers original client inheritance before native initialization"
)]
fn main() -> ExitCode {
    // SAFETY: first and only initialization in this fresh single-threaded process.
    let result = unsafe { gnunet_service_startup::ClientStartup::capture() }
        .map_err(|error| Box::new(error) as Failure)
        .and_then(run);
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            diagnostic(format_args!("gnunet-daemon-pt: {e}"));
            ExitCode::FAILURE
        }
    }
}
fn run(startup: gnunet_service_startup::ClientStartup) -> Result<(), Failure> {
    use gnunet_program_host::{
        logging::Logger,
        program::{self, Defaults, Invocation, NlsDisabled, Preparation},
        reporting::Reporter,
        service,
        shared_clock::SharedClock,
    };
    use std::sync::Arc;

    let clock = SharedClock::native(4096)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(b"gnunet-daemon-pt", std::process::id(), false)?;
    let prepared = program::prepare(
        config,
        Invocation {
            binary_name: b"gnunet-daemon-pt",
            help: Some(b"Translate intercepted DNS through VPN allocations or DHT-discovered DNS exits. Configure TUNNEL_IPV4, TUNNEL_IPV6 and TUNNEL_DNS in [pt]. No positional arguments."),
            select_default_filename: true,
            defaults: Defaults::Native,
        },
        Default::default(),
        std::env::args_os(),
        &program::Environment::capture(),
        &mut NlsDisabled,
        &mut logger,
        &clock,
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    )?;
    let prepared = match prepared {
        Preparation::Ready(p) => *p,
        Preparation::Stopped(s) => {
            return match s.reason {
                program::StoppedReason::Options if s.code == 0 => Ok(()),
                program::StoppedReason::Logging(error) => Err(error.into()),
                program::StoppedReason::Malformed(error) => Err(error.into()),
                reason => Err(format!("PT PROGRAM stopped {reason:?} code{}", s.code).into()),
            };
        }
    };
    let reports = Reporter::new(logger, clock.clone());
    #[cfg(unix)]
    if let Some(notice) = startup.notice {
        reports.warning(
            "pt.parent.declaration",
            format_args!("PT parent control: {notice:?}"),
        );
    }
    let result = (|| -> Result<(), Failure> {
        if reports.failed() {
            return Ok(());
        }
        if !prepared.main().arguments.is_empty() {
            return Err("PT accepts no positional arguments".into());
        }
        let settings = gnunet_pt_host::settings::Settings::read(prepared.main().config)?;
        identity::apply(prepared.main().config, &reports)?;
        if reports.failed() {
            return Ok(());
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(gnunet_pt_host::foreground::scheduled(
                prepared,
                clock,
                settings,
                startup,
                reports.clone(),
            ))
    })();
    if let Err(error) = &result {
        reports.warning(
            "pt.program.failed",
            format_args!("gnunet-daemon-pt: {error}"),
        );
    }
    service::retain_diagnostic(result, reports.take_error())
}
