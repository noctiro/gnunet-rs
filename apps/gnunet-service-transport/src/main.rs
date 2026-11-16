//! Native TRANSPORT startup around one shared official authority service.
#![deny(unsafe_code)]
use std::{
    error::Error,
    io::{self, Write},
    process::ExitCode,
};
type Failure = Box<dyn Error>;
mod reporting;
#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix::run;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows::run;
fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(error) => {
            let _actual = writeln!(io::stderr().lock(), "gnunet-service-transport: {error}");
            ExitCode::FAILURE
        }
    }
}
fn finish(
    result: Result<(), Failure>,
    reports: &gnunet_program_host::reporting::Reporter,
) -> Result<ExitCode, Failure> {
    use gnunet_program_host::{policy::Level, service};
    match service::retain_diagnostic(result, reports.take_error()) {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(original) => {
            reports.message(
                Level::ERROR,
                "transport.failure",
                format_args!("gnunet-service-transport: {original}"),
            );
            if reports.failed() {
                let diagnostic = reports.take_error();
                let _actual = writeln!(
                    io::stderr().lock(),
                    "gnunet-service-transport: {original}; independent logging: {diagnostic:?}"
                );
            }
            Ok(ExitCode::FAILURE)
        }
    }
}

fn configuration(
    selected: Option<&std::path::Path>,
) -> Result<gnunet_config::Configuration, Failure> {
    let project = std::sync::Arc::new(gnunet_config::ProjectData::default());
    let mut config = gnunet_config::Configuration::create(project.clone(), Default::default())?;
    let discovered = gnunet_config::default_filename(&project)?;
    let selected = selected
        .map(std::path::Path::to_owned)
        .or_else(|| discovered.filter(|path| path.is_file()));
    config.load(selected.as_deref())?;
    Ok(config)
}
