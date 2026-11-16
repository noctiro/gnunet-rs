//! Official proxy CA preparation command; authored side effects are never implicit tests.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Cause = Box<dyn Error>;
mod browsers;
mod budget;
mod certificate;
mod early;
mod files;
mod options;
mod output;

fn main() -> ExitCode {
    match execute() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _diagnostic = writeln!(io::stderr().lock(), "gnunet-gns-proxy-setup-ca: {error}");
            ExitCode::FAILURE
        }
    }
}
#[derive(Debug)]
struct Failure {
    published: Option<std::path::PathBuf>,
    original: Option<Cause>,
    summary: Option<io::Error>,
    logging: Option<io::Error>,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CA preparation: published={:?}; original={:?}; summary={:?}; logging={:?}",
            self.published, self.original, self.summary, self.logging
        )
    }
}
impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.summary.as_ref().map(|error| error as _))
            .or_else(|| self.logging.as_ref().map(|error| error as _))
    }
}
#[derive(Debug)]
struct PreparationFailure(gnunet_program_host::program::Stopped);
impl std::fmt::Display for PreparationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CA helper PROGRAM stopped {:?}, code {}",
            self.0.reason, self.0.code
        )
    }
}
impl Error for PreparationFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        use gnunet_program_host::program::StoppedReason;
        match &self.0.reason {
            StoppedReason::Logging(error) => Some(error),
            StoppedReason::Malformed(error) => Some(error),
            _ => None,
        }
    }
}
fn execute() -> Result<(), Cause> {
    use gnunet_program_host::{
        logging::Logger,
        program::{self, Defaults, Invocation, NlsDisabled, Preparation},
        reporting::Reporter,
        shared_clock::SharedClock,
    };
    use std::sync::Arc;
    let early = early::capture()?;
    let clock = SharedClock::native(32)?;
    let configuration = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let mut logger = Logger::new(b"gnunet-gns-proxy-setup-ca", std::process::id(), false)?;
    let selection = options::Selection::new();
    let prepared=program::prepare(configuration,Invocation {
        binary_name:b"gnunet-gns-proxy-setup-ca",
        help:Some(b"Prepare the GNS proxy CA. -c FILE selects configuration; -h help; -v version; -V verbose; -t reports the compiled CA provider and probes optional NSS certutil without generating a CA; -o repeats status results. The expanded [gns-proxy] PROXY_CACERT receives a self-signed CA and unencrypted PKCS#8 private key in a new private combined PEM. Existing CA files and NSS nicknames are preserved. Optional NSS certutil imports only the public certificate into native Firefox/Icecat profiles and Unix ~/.pki/nssdb. [gns-proxy-rust] NSS_CERTUTIL selects an absolute NSS executable (required on Windows); NSS_DATABASE selects a custom NSS database; missing helpers/profiles are explicitly skipped. No system-wide trust-store modification is performed."),
        select_default_filename:true,defaults:Defaults::Native,
    },selection.options(),std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock())?;
    let reporter = Reporter::new(logger, clock.clone());
    let mut published = None;
    let mut output = None;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async {
        let prepared = match prepared {
            Preparation::Ready(prepared) => *prepared,
            Preparation::Stopped(stopped)
                if stopped.code == 0
                    && matches!(stopped.reason, program::StoppedReason::Options) =>
            {
                return Ok(());
            }
            Preparation::Stopped(stopped) => {
                return Err(Box::new(PreparationFailure(stopped)) as Cause);
            }
        };
        let chosen = selection.finish(prepared.main().arguments)?;
        let mut status = output::Output::new(chosen.verbose, chosen.summary);
        let budget = budget::Budget::new(clock, reporter.clone(), early.parent).await?;
        let helper = browsers::Helper::select(prepared.main().config)?;
        let operation = async {
            if chosen.probe {
                return browsers::probe(&helper, &budget, &mut status).await;
            }
            budget.check().await?;
            let target = prepared.main().config.get_filename(
                b"gns-proxy",
                b"PROXY_CACERT",
                &gnunet_config::ProcessEnvironment,
            )?;
            if target.as_os_str().is_empty() {
                return Err("invalid CA certificate path".into());
            }
            files::absent(&target)?;
            status.info(format_args!("Generating self-signed GNS Proxy CA"))?;
            let generated = certificate::generate(&budget).await?;
            let directory_sync = files::publish(
                &target,
                &generated.certificate,
                &generated.private_key,
                &budget,
            )
            .await?;
            published = Some(target.clone());
            status.info(format_args!(
                "CA directory naming barrier: {directory_sync:?}"
            ))?;
            // Drop our serialized private-key copy before any external helper.
            let certificate::Generated {
                certificate,
                private_key,
            } = generated;
            drop(private_key);
            status.status(format_args!(
                "Prepared CA certificate and private key at {}",
                target.display()
            ))?;
            browsers::import(&helper, &target, &certificate, &budget, &mut status).await?;
            status.status(format_args!(
                "Start gnunet-gns-proxy and configure a SOCKS proxy on port 7777"
            ))?;
            Ok(())
        }
        .await;
        output = Some(status);
        operation
    });
    if let Err(error) = &result {
        reporter.warning("gns-proxy-setup-ca.failed", format_args!("{error}"));
    }
    let summary = output.as_ref().and_then(|output| output.finish().err());
    let logging = reporter.take_error();
    match (result, summary, logging) {
        (Ok(()), None, None) => Ok(()),
        (original, summary, logging) => Err(Box::new(Failure {
            published,
            original: original.err(),
            summary,
            logging,
        })),
    }
}
