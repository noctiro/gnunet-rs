//! Installed microphone and speaker diagnostic for Conversation.
#![deny(unsafe_code)]

use std::{
    io::{self, Write},
    process::ExitCode,
};

type Failure = Box<dyn std::error::Error>;

#[cfg(any(unix, windows))]
mod media_paths;
#[cfg(any(unix, windows))]
mod test_audio;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _written = writeln!(io::stderr().lock(), "gnunet-conversation-test: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn run() -> Result<(), Failure> {
    Err("native Conversation audio requires Unix or Windows".into())
}

#[cfg(any(unix, windows))]
#[expect(
    unsafe_code,
    reason = "Fresh PROGRAM entry captures the original parent control before starting the runtime"
)]
fn run() -> Result<(), Failure> {
    use gnunet_config::{Configuration, ProjectData};
    use gnunet_program_host::{
        getopt::Options,
        logging::Logger,
        program::{self, Defaults, Invocation, Preparation, StoppedReason},
        shared_clock::SharedClock,
    };
    use gnunet_service_startup::{ClientStartup, StopSignals};
    use std::sync::Arc;

    // SAFETY: first native initialization before threads or competing inherited owners.
    let inherited = unsafe { ClientStartup::capture()? };
    const COMMAND: &[u8] = b"gnunet-conversation-test";
    let clock = SharedClock::native(64)?;
    let config = Configuration::create(Arc::new(ProjectData::default()), Default::default())?;
    let mut logger = Logger::new(COMMAND, std::process::id(), false)?;
    let prepared = program::prepare_installed(
        config,
        Invocation {
            binary_name: COMMAND,
            help: Some(b"Record microphone input for five seconds and play it back locally."),
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
                StoppedReason::Options if stopped.code >= 0 => Ok(()),
                StoppedReason::Logging(error) => Err(error.into()),
                StoppedReason::Malformed(error) => Err(error.into()),
                reason => Err(io::Error::other(format!("PROGRAM stopped ({reason:?})")).into()),
            };
        }
    };
    let paths = media_paths::Paths::installed(prepared.main().config)?;
    let record = paths.program(media_paths::RECORD)?;
    let playback = paths.program(media_paths::PLAYBACK)?;
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut signals = StopSignals::for_client(inherited.parent)?;
            test_audio::run(&record, &playback, &mut signals).await
        })
}
