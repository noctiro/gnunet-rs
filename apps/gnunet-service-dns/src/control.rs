//! Explicit containing-application commands; help never enters native SDKs.
use crate::Failure;
use std::{io::Write, process::ExitCode};
mod arguments;
#[cfg(target_os = "macos")]
mod native;

const HELP: &str = "Usage: gnunet-dns-control <status|enable|disable|remove> [options]

Run the executable in its signed macOS containing application.

  status                   Load and show the saved DNS proxy configuration.
  enable --config PATH     Activate the bundled extension and save its configuration.
  disable                  Disable this application's DNS proxy configuration.
  remove                   Remove its configuration, then deactivate its extension.
  --replace                Allow an extension upgrade to this bundle's exact version.
  --timeout SECONDS        Total wait bound, 1..3600 seconds (default 120).
  --help                   Show this help without loading native preferences.
  --version                Show the program version.

PATH must be an absolute UTF-8 configuration filename readable by the provider.
An expired wait leaves any submitted native operation's outcome unconfirmed.
Saved enabled state does not establish provider readiness or DNS delivery.
";

pub(super) fn run() -> ExitCode {
    let result = execute();
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _written = writeln!(std::io::stderr().lock(), "gnunet-dns-control: {error}");
            ExitCode::FAILURE
        }
    }
}
fn execute() -> Result<(), Failure> {
    match arguments::parse(std::env::args_os().skip(1).collect())? {
        arguments::Request::Help => std::io::stdout().lock().write_all(HELP.as_bytes())?,
        arguments::Request::Version => writeln!(
            std::io::stdout().lock(),
            "gnunet-dns-control {}",
            env!("CARGO_PKG_VERSION")
        )?,
        #[cfg(target_os = "macos")]
        arguments::Request::Operation(options) => native::run(options)?,
    }
    Ok(())
}
