//! Generate private Windows kernel ABI inputs from explicitly supplied SDK files.
mod allowlist;
mod cli;
mod command;
mod driver;
mod generate;
mod includes;
mod receipt;
mod sdk;

use std::{error::Error, io, process::ExitCode};

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn main() -> ExitCode {
    match cli::parse().and_then(|inputs| inputs.map(run).transpose()) {
        Ok(_) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("WDK binding preparation: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run(inputs: cli::Inputs) -> Result<()> {
    generate::run(&inputs)?;
    if let Some(tools) = &inputs.driver {
        driver::build(&inputs, tools)?;
    }
    Ok(())
}
