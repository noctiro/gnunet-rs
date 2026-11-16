//! Ordinary installed ABD PROGRAM; all authority comes from real selected owners.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
mod options;
mod output;
mod run;
mod text;
#[derive(Debug)]
struct SelectedFailure {
    original: Option<Failure>,
    logging: Option<io::Error>,
    code: u8,
}
impl std::fmt::Display for SelectedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(e) = &self.original {
            write!(f, "ABD: {e}")?
        }
        if let Some(e) = &self.logging {
            write!(f, "; selected logger: {e}")?
        }
        Ok(())
    }
}
impl Error for SelectedFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.logging.as_ref().map(|e| e as _))
    }
}
#[expect(
    unsafe_code,
    reason = "Fresh PROGRAM captures inherited native resources before competing owners"
)]
fn main() -> ExitCode {
    // SAFETY: first and only capture in this fresh single-threaded executable.
    let result = unsafe { gnunet_service_startup::ClientStartup::capture() }
        .map_err(|error| Box::new(error) as Failure)
        .and_then(run);
    match result {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            if let Some(selected) = e.downcast_ref::<SelectedFailure>() {
                return ExitCode::from(selected.code);
            }
            let _actual = writeln!(io::stderr().lock(), "gnunet-abd: {e}");
            ExitCode::from(2)
        }
    }
}
fn run(startup: gnunet_service_startup::ClientStartup) -> Result<u8, Failure> {
    use gnunet_program_host::{
        logging::Logger,
        policy::Level,
        program::{self, Defaults, Invocation, NlsDisabled, Preparation},
        reporting::Reporter,
        shared_clock::SharedClock,
    };
    let clock = SharedClock::native(256)?;
    let config = gnunet_config::Configuration::create(
        std::sync::Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let arguments = options::Arguments::new();
    let mut logger = Logger::new(b"gnunet-abd", std::process::id(), false)?;
    let prepared=program::prepare(config,Invocation{binary_name:b"gnunet-abd",help:Some(b"Attribute delegation: select exactly one -U/--createIssuerSide, -C/--createSubjectSide, -S/--signSubjectSide, -g/--collect, -V/--verify. -e selects an existing IDENTITY ego; no private-key argument is accepted. -U uses -a label -s standard ATTR text -T TTL [-P]. -C uses -x signed DEL [-P], verifies the subject matches the ego, label @. -S uses -a ROLE -s 'PUBLIC_KEY [ROLE]' -T absolute-time/never and prints a real signed DEL. -g uses -i ISSUER -a ROLE -e EGO; -V uses -i ISSUER -a ROLE -s SUBJECT [-d 'DEL,...']. No leaves is a valid direct-GNS verification. -F/-B default to both. Subject-role leaves unrepresentable in the official plural IPC fail explicitly, never lose signed role bytes. -T store accepts standard relative/calendar/epoch-seconds/never; signed DEL uses absolute UTC. --timeout bounds the whole original identity/lookup/store/caller/output operation. PROGRAM -c/-L/-l and GNUNET_ARGS use standard configuration. Output is bounded synchronous stdout: the native deadline cannot preempt a blocked OS write. No service is spawned, no unknown mutation replayed."),select_default_filename:true,defaults:Defaults::Native},arguments.options(),std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock());
    let reporter = Reporter::new(logger, clock.clone());
    #[cfg(unix)]
    if let Some(notice) = startup.notice {
        reporter.warning(
            "abd.parent.declaration",
            format_args!("Original parent-control declaration: {notice:?}"),
        );
    }
    let mut code = 2;
    let result = (|| -> Result<u8, Failure> {
        let prepared = match prepared? {
            Preparation::Ready(p) => *p,
            Preparation::Stopped(s) => {
                if s.code == 0 && matches!(s.reason, program::StoppedReason::Options) {
                    return Ok(0);
                }
                return Err(format!("ABD PROGRAM stopped {:?} code={}", s.reason, s.code).into());
            }
        };
        let settings = options::Settings::read(prepared.main().config)?;
        let selection = arguments.selection(prepared.main().arguments, &settings)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        code = 1;
        runtime
            .block_on(run::scheduled(
                prepared,
                clock,
                settings,
                selection,
                reporter.clone(),
                startup,
            ))
            .map(|()| 0)
    })();
    if let Err(e) = &result {
        reporter.message(Level::ERROR, "abd.command.failed", format_args!("{e}"));
    }
    let logging = reporter.take_error();
    match (result, logging) {
        (Ok(c), None) => Ok(c),
        (result, logging) => Err(Box::new(SelectedFailure {
            original: result.err(),
            logging,
            code,
        })),
    }
}
