//! Official PT daemon foreground; all active defaults come from [pt].
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
fn diagnostic(args: std::fmt::Arguments<'_>) {
    let _written = writeln!(io::stderr().lock(), "{args}");
}
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            diagnostic(format_args!("gnunet-daemon-pt: {e}"));
            ExitCode::FAILURE
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<(), Failure> {
    Err("PT native clients/foreground require Unix".into())
}
#[cfg(unix)]
#[expect(
    unsafe_code,
    reason = "sole first exec-child operation captures original parent-declared descriptors before any other FD owner or runtime"
)]
fn inherited() -> Result<
    (
        gnunet_pt_host::foreground::Inherited,
        Option<gnunet_service_startup::ControlNotice>,
    ),
    Failure,
> {
    use gnunet_service_startup::{InheritedMode, InheritedResources};
    // SAFETY: sole first startup operation, single-threaded and before config,
    // logs, signals, Resolver, runtime or any competing descriptor ownership.
    let captured = unsafe {
        gnunet_service_startup::capture_from_environment(InheritedMode::CloseAfterConfiguredBind)?
    };
    // Official PT has NOARMBIND=YES and no SERVICE/listener. Releasing an
    // unexpected inherited set is explicitly aborted startup ownership, not a
    // fictitious listener bind or readiness receipt.
    match captured.inherited {
        InheritedResources::CloseAfterBind(hold) => {
            let report = hold.abort();
            if report.owned_descriptors_released != 0 {
                return Err(
                    "PT received listener/readiness descriptors despite NOARMBIND; none were bound"
                        .into(),
                );
            }
        }
        InheritedResources::Listeners(_) => return Err("wrong PT inheritance route".into()),
    }
    Ok((
        gnunet_pt_host::foreground::Inherited {
            parent: captured.parent_control,
        },
        captured.control_notice,
    ))
}
#[cfg(unix)]
fn run() -> Result<(), Failure> {
    use gnunet_program_host::{
        logging::Logger,
        program::{self, Defaults, Invocation, NlsDisabled, Preparation},
        reporting::Reporter,
        service,
        shared_clock::SharedClock,
    };
    use gnunet_service_startup::{GroupsProfile, apply_privileges, configured_user, resolve_user};
    use std::sync::Arc;
    let (inherited, notice) = inherited()?;
    if !cfg!(any(target_os = "linux", target_os = "macos")) {
        return Err(
            "PT foreground requires an explicit native VPN AF profile on this platform".into(),
        );
    }

    let clock = SharedClock::native(4096)?;
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(b"gnunet-daemon-pt", std::process::id(), false)?;
    let prepared=program::prepare(config,Invocation{binary_name:b"gnunet-daemon-pt",help:Some(b"Official PT DNS protocol translation. [pt] TUNNEL_IPV4/TUNNEL_IPV6 rewrite A/AAAA using real VPN allocations. TUNNEL_DNS uses signed DHT exit discovery and real CADET DNS channels; it never substitutes host DNS/GNS. DNS interception and application IP forwarding belong to actual DNS/VPN services; no PT listener/device is installed. No positional arguments."),select_default_filename:true,defaults:Defaults::Native},Default::default(),std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock())?;
    let prepared = match prepared {
        Preparation::Ready(p) => *p,
        Preparation::Stopped(s) => {
            return match s.reason {
                program::StoppedReason::Options if s.code >= 0 => Ok(()),
                program::StoppedReason::Logging(error) => Err(error.into()),
                program::StoppedReason::Malformed(error) => Err(error.into()),
                reason => Err(format!("PT PROGRAM stopped {reason:?} code{}", s.code).into()),
            };
        }
    };
    let reports = Reporter::new(logger, clock.clone());
    if let Some(notice) = notice {
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
        let user = configured_user(prepared.main().config, b"pt")?
            .map(|name| resolve_user(&name))
            .transpose()?;
        let actual = apply_privileges(user.as_ref(), GroupsProfile::WithInitgroups)?;
        if user.is_some() {
            reports.debug(
                "pt.process.identity",
                format_args!("PT process identity: {actual:?}"),
            );
        }
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
                inherited,
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
