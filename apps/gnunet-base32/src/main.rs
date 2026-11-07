//! Ordinary raw-stdin/stdout GNUnet Crockford Base32 command.
#![forbid(unsafe_code)]
use std::{
    error::Error,
    fmt,
    io::{self, Write},
    process::ExitCode,
};
type Cause = Box<dyn Error>;
#[cfg(unix)]
mod descriptors;
#[cfg(unix)]
mod spool;
#[cfg(unix)]
mod transform;

#[derive(Debug)]
struct Problem {
    code: u8,
    cause: Cause,
}
impl Problem {
    fn new(code: u8, cause: impl Error + 'static) -> Self {
        Self {
            code,
            cause: Box::new(cause),
        }
    }
    fn message(code: u8, text: &'static str) -> Self {
        Self::new(code, io::Error::other(text))
    }
}
impl fmt::Display for Problem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.cause.as_ref(), f)
    }
}
impl Error for Problem {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.cause.as_ref())
    }
}
fn main() -> ExitCode {
    match entry() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            let _actual = writeln!(io::stderr().lock(), "gnunet-base32: {error}");
            ExitCode::from(error.code)
        }
    }
}
#[cfg(not(unix))]
fn entry() -> Result<(), Problem> {
    Err(Problem::message(
        1,
        "normal Base32 descriptor ownership requires Unix",
    ))
}
#[cfg(unix)]
fn entry() -> Result<(), Problem> {
    use gnunet_program_host::{
        getopt::Options,
        helpers::{self, Target},
    };
    let decode = Target::new(0);
    let project = gnunet_config::ProjectData::default();
    let mut options = Options::new();
    options.add(helpers::flag(
        b'd',
        b"decode",
        b"decode raw Base32 stdin; otherwise encode raw bytes",
        decode.clone(),
    ));
    options.add(helpers::help(&project, Some(b"Crockford Base32 encoder/decoder. Reads stdin and writes stdout without an extra newline. Decode validates the complete input in a private disk spool before writing stdout; malformed text, including whitespace, fails. Memory is fixed-size; the spool grows with valid decoded input and actual filesystem errors remain failures. SIGINT/SIGTERM cancel, restore original stdio flags and clean the original spool. No keys, entropy, network, helper child or cryptographic operation.")));
    options.add(helpers::version(env!("CARGO_PKG_VERSION").as_bytes()));
    let mut parsed = options.run(
        b"gnunet-base32 [OPTIONS]",
        std::env::args_os(),
        std::env::var_os("POSIXLY_CORRECT").is_some(),
    );
    io::stdout()
        .lock()
        .write_all(&parsed.output.stdout)
        .map_err(|e| Problem::new(4, e))?;
    io::stderr()
        .lock()
        .write_all(&parsed.output.stderr)
        .map_err(|e| Problem::new(1, e))?;
    if let Some(cause) = parsed.output.failure.take() {
        return Err(Problem::new(1, cause));
    }
    if parsed.code == 0 {
        return Ok(());
    }
    if parsed.code < 0 {
        return Err(Problem::message(1, "invalid command options"));
    }
    if parsed.remaining().is_none_or(|rest| !rest.is_empty()) {
        return Err(Problem::message(1, "no file operands: input is stdin"));
    }
    let decode = decode.get().map_err(|e| Problem::new(1, e))? != 0;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| Problem::new(1, e))?;
    runtime.block_on(transform::run(decode))
}
