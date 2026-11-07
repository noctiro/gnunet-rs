//! Ordinary installed CONVERSATION PROGRAM; all authority comes from real selected owners.
#![forbid(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
#[cfg(unix)]
mod media;
#[cfg(unix)]
mod options;
#[cfg(unix)]
mod run;
#[cfg(unix)]
mod terminal;
#[cfg(unix)]
#[derive(Debug)]
struct SelectedFailure {
    original: Option<Failure>,
    logging: Option<io::Error>,
    code: u8,
}
#[cfg(unix)]
impl std::fmt::Display for SelectedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(e) = &self.original {
            write!(f, "CONVERSATION: {e}")?
        }
        if let Some(e) = &self.logging {
            write!(f, "; selected logger: {e}")?
        }
        Ok(())
    }
}
#[cfg(unix)]
impl Error for SelectedFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.logging.as_ref().map(|e| e as _))
    }
}
fn main() -> ExitCode {
    match run() {
        Ok(code) => ExitCode::from(code),
        Err(e) => {
            #[cfg(unix)]
            if let Some(selected) = e.downcast_ref::<SelectedFailure>() {
                return ExitCode::from(selected.code);
            }
            let _actual = writeln!(io::stderr().lock(), "gnunet-conversation: {e}");
            ExitCode::from(2)
        }
    }
}
#[cfg(not(unix))]
fn run() -> Result<u8, Failure> {
    Err("native CONVERSATION command requires Unix".into())
}
#[cfg(unix)]
fn run() -> Result<u8, Failure> {
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
    let mut logger = Logger::new(b"gnunet-conversation", std::process::id(), false)?;
    let prepared=program::prepare(config,Invocation{binary_name:b"gnunet-conversation",help:Some(b"Conversation phone with -e/--ego NAME and optional -p/--phone LINE (default [conversation].LINE). Interactive /address /call FULL_NAME /accept #N /suspend /resume [#N] /cancel [#N] /status /quit /help. Full names use the ordinary GNS API and PHONE records. Address comes from actual PILS current peer and gives publication instructions. One active media owner uses explicit same-installation Rust record/playback helpers and standard730 Ogg/Opus bytes after actual pickup/local acceptance. Child admission/local writes are not remote/media-ready receipts. Commands, queues, calls and original native/canonical lifetimes are bounded. Regular-file terminal IO and selected synchronous logging cannot be forcibly preempted. No private-key argument, hidden Resolver/media worker or official-C helper fallback."),select_default_filename:true,defaults:Defaults::Native},arguments.options(),std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock());
    let reporter = Reporter::new(logger, clock.clone());
    let mut code = 2;
    let result = (|| -> Result<u8, Failure> {
        let prepared = match prepared? {
            Preparation::Ready(p) => *p,
            Preparation::Stopped(s) => {
                if s.code == 0 && matches!(s.reason, program::StoppedReason::Options) {
                    return Ok(0);
                }
                return Err(format!(
                    "CONVERSATION PROGRAM stopped {:?} code={}",
                    s.reason, s.code
                )
                .into());
            }
        };
        let settings = options::Settings::read(prepared.main().config)?;
        let selection =
            arguments.selection(prepared.main().arguments, prepared.main().config, &settings)?;
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
            ))
            .map(|()| 0)
    })();
    if let Err(e) = &result {
        reporter.message(
            Level::ERROR,
            "conversation.command.failed",
            format_args!("{e}"),
        );
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
