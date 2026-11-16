//! Actual standard PROGRAM foreground for raw QUIC and HTTP3 communicators.
//! Runtime, Resolver, external frame loans and original shutdown remain in this
//! one scoped task. There is no detached actor, fallback DNS or C transport FFI.
mod credentials;
mod observation;
mod reporting;
use crate::statistics::{NoStatistics, StatisticsFactory};
mod resources;
mod settings;
use crate::tls::Profile;
use gnunet_program_host::{
    logging::Logger,
    policy::Level,
    program::{self, Defaults, Invocation, NlsDisabled, Preparation},
    shared_clock::SharedClock,
};
use gnunet_service_startup::ClientStartup;
use reporting::Reports;
use settings::Settings;
use std::{cell::RefCell, error::Error, io, rc::Rc, sync::Arc};
mod drive;
mod failure;
mod scheduling;
use scheduling::scheduled;
/// Original native/configuration cause, without credential bytes.
pub type Failure = Box<dyn Error>;
/// Failure already routed through the selected PROGRAM diagnostics.
#[derive(Debug)]
pub struct ReportedFailure(Failure);
impl std::fmt::Display for ReportedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl Error for ReportedFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}
/// Run after the binary has performed its sole initial native startup capture. The communicator has no SERVICE listener; that boundary must reject
/// inherited listener/readiness FDs and pass through only original parent control.
/// This routine does not fork or reinterpret -v as verbosity. Shared PROGRAM
/// owns the actual standard option table, GNUNET_ARGS, locale/config and logger.
pub fn run(profile: Profile, startup: ClientStartup) -> Result<(), Failure> {
    run_with_statistics::<NoStatistics>(profile, startup)
}
/// Standard apps inject the real native publisher. Explicit embeddings may use
/// the no-publisher entry above; it does not claim observation publication.
pub fn run_with_statistics<F: StatisticsFactory + 'static>(
    profile: Profile,
    startup: ClientStartup,
) -> Result<(), Failure> {
    let parent = startup.parent;
    #[cfg(not(feature = "h3-profile"))]
    if profile == Profile::Http3 {
        return Err("HTTP3 binary requires h3-profile".into());
    }
    let clock = SharedClock::native(1024)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(settings::binary(profile), std::process::id(), false)?;
    let preparation = program::prepare(
        config,
        Invocation {
            binary_name: settings::binary(profile),
            help: Some(b"GNUnet QUIC communicator. Claimed peer identity does not establish authentication."),
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
    );
    let reports = Rc::new(RefCell::new(Reports::new(logger, clock.clone(), profile)));
    #[cfg(unix)]
    if let Some(notice) = startup.notice {
        reports.borrow_mut().log(
            "quic.parent.declaration",
            Level::WARNING,
            format_args!("parent control declaration: {notice:?}"),
        );
    }
    let result = (|| {
        let prepared = match preparation? {
            Preparation::Ready(p) => *p,
            Preparation::Stopped(s)
                if s.code == 0 && matches!(s.reason, program::StoppedReason::Options) =>
            {
                return Ok(());
            }
            Preparation::Stopped(s) => {
                return Err(
                    format!("PROGRAM stopped: {:?} (source code {})", s.reason, s.code).into(),
                );
            }
        };

        if !prepared.main().arguments.is_empty() {
            return Err("QUIC/HTTP3 communicators accept no positional arguments".into());
        }
        let settings = Settings::read(prepared.main().config, profile)?;
        #[cfg(unix)]
        {
            let user = gnunet_service_startup::configured_user(
                prepared.main().config,
                settings::section(profile),
            )?
            .map(|n| gnunet_service_startup::resolve_user(&n))
            .transpose()?;
            let privilege = gnunet_service_startup::apply_privileges(
                user.as_ref(),
                gnunet_service_startup::GroupsProfile::WithInitgroups,
            )?;
            if user.is_some() {
                reports.borrow_mut().log(
                    "quic.process.identity",
                    Level::INFO,
                    format_args!("process identity applied: {privilege:?}"),
                )
            }
        }
        #[cfg(windows)]
        gnunet_service_startup::verify_configured_identity(
            prepared.main().config,
            settings::section(profile),
        )?;
        if reports.borrow().failed() {
            return Ok(());
        }
        // All sockets, configured credential IO, TLS entropy and Tokio signal owners
        // are constructed only after the real process identity has been applied.
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(scheduled::<F>(
                prepared,
                clock,
                settings,
                parent,
                Rc::clone(&reports),
            ))
    })();
    if let Err(error) = &result {
        reports
            .borrow_mut()
            .log("quic.program.failed", Level::ERROR, format_args!("{error}"))
    }
    let diagnostic = reports.borrow_mut().take_failure();
    gnunet_program_host::service::retain_diagnostic(result, diagnostic)
        .map_err(|error| Box::new(ReportedFailure(error)) as Failure)
}
