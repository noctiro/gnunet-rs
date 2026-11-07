//! Standard interactive Messenger PROGRAM over the actual high-level client.
#![deny(unsafe_code)]
#[cfg(unix)]
mod input;
#[cfg(unix)]
mod options;
#[cfg(unix)]
mod output;
#[cfg(unix)]
mod session;
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            #[cfg(unix)]
            let selected = error.is::<output::ReportedFailure>();
            #[cfg(not(unix))]
            let selected = false;
            if !selected {
                let _diagnostic = writeln!(io::stderr().lock(), "gnunet-messenger: {error}");
            }
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<(), Failure> {
    Err("native Messenger PROGRAM requires Unix".into())
}
#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "Unique initial inherited-descriptor transfer before logger, runtime, stdin owner, source or task construction"
)]
fn run() -> Result<(), Failure> {
    use gnunet_program_host::{
        foreground,
        logging::Logger,
        program::{self, Defaults, Invocation, NlsDisabled, Preparation},
        reporting::Reporter,
        shared_clock::SharedClock,
    };
    use gnunet_service_startup::{InheritedMode, InheritedResources};
    use std::{cell::Cell, rc::Rc, sync::Arc};
    // SAFETY: first process resource capture, with no prior raw-fd ownership,
    // environment mutation, runtime, thread, stdio lock or competing source.
    let captured = unsafe {
        gnunet_service_startup::capture_from_environment(InheritedMode::CloseAfterConfiguredBind)?
    };
    match captured.inherited {
        InheritedResources::CloseAfterBind(hold) => {
            let nonempty = !hold.is_empty();
            let report = hold.abort();
            if nonempty {
                return Err(format!(
                    "Messenger has no listener; original inherited descriptors retired: {report:?}"
                )
                .into());
            }
        }
        InheritedResources::Listeners(_) => {
            return Err("unexpected Messenger activation mode".into());
        }
    }
    let clock = SharedClock::native(512)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(b"gnunet-messenger", std::process::id(), false)?;
    let selected = options::Selection::new();
    let preparation=program::prepare(config,Invocation {binary_name:b"gnunet-messenger",help:Some(b"Open or enter a Messenger room and exchange bounded stdin text or binary TALK data."),select_default_filename:true,defaults:Defaults::Native},selected.descriptors(),std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock());
    let reporter = Reporter::new(logger, clock.clone());
    if let Some(notice) = captured.control_notice {
        reporter.debug(
            "messenger.parent.notice",
            format_args!("parent-control declaration: {notice:?}"),
        );
    }
    let result = (|| -> Result<_, Failure> {
        let prepared = match preparation? {
            Preparation::Ready(prepared) => *prepared,
            Preparation::Stopped(stopped)
                if stopped.code == 0
                    && matches!(stopped.reason, program::StoppedReason::Options) =>
            {
                return Ok(None);
            }
            Preparation::Stopped(stopped) => {
                return Err(format!(
                    "Messenger PROGRAM stopped: {:?} (source code {})",
                    stopped.reason, stopped.code
                )
                .into());
            }
        };
        if !prepared.main().arguments.is_empty() {
            return Err("Messenger accepts options, not positional arguments".into());
        }
        let settings = selected.finish(prepared.main().config)?;
        let config = prepared.main().config.duplicate()?;
        Ok(Some((prepared, config, settings)))
    })();
    let result = match result {
        Ok(Some((prepared, config, settings))) => {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            match runtime {
                Err(error) => Err(Box::new(error) as Failure),
                Ok(runtime) => runtime.block_on(async {
                    use gnunet_client_host::LiveConfiguration;
                    use gnunet_resolver_broker::{Family, FamilyProfile};
                    use gnunet_service_runtime::clock::RuntimeClock;
                    let source: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
                    let native = gnunet_resolver_broker::native_profile()?;
                    let family =
                        FamilyProfile::new(native.encode(Family::V4), native.encode(Family::V6))?;
                    let live = LiveConfiguration::new(config);
                    let (mut context, resolver) = gnunet_resolver_broker::broker::<128, 256>(
                        live.clone(),
                        Default::default(),
                        family,
                        source.clone(),
                    )?;
                    let stop = Rc::new(Cell::new(false));
                    let product = session::run(session::Inputs {
                        settings,
                        live,
                        context: context.clone(),
                        resolver,
                        source,
                        reporter: reporter.clone(),
                        stop: stop.clone(),
                        parent: captured.parent_control,
                    });
                    foreground::run(prepared, &mut context, clock.clone(), stop, product)
                        .await
                        .map(|_report| ())
                }),
            }
        }
        Ok(None) => Ok(()),
        Err(error) => Err(error),
    };
    if let Err(error) = &result {
        reporter.warning(
            "messenger.program.failed",
            format_args!("Messenger: {error}"),
        );
    }
    match (result, reporter.take_error()) {
        (original, Some(logging)) => Err(Box::new(output::DiagnosticFailure {
            original: original.err(),
            logging,
        }) as Failure),
        (original, None) => original,
    }
    .map_err(|original| Box::new(output::ReportedFailure(original)) as Failure)
}
