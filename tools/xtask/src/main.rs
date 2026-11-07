//! Reproducible checks for the current official GNUnet Rust implementation.
use std::{
    env,
    error::Error,
    io::{self, Write},
    path::Path,
    process::ExitCode,
};

mod checks;
mod conformance;
mod external_contracts;
mod inputs;
mod verify;

const USAGE: &str = "usage: cargo xtask check-deps|check-features|check-noalloc|check-lints|check-external-contracts [--strict]|check-external-release [--strict]|check-conformance [--strict]|check-legacy-conformance [--strict]|check-api-inventory [--strict]|evidence-inputs|verify [all|format|lint|tools|portable|runtime|test|embedded|reference|daemon-reference]";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if writeln!(io::stderr().lock(), "xtask: {error}").is_err() {
                return ExitCode::FAILURE;
            }
            ExitCode::FAILURE
        }
    }
}
fn run() -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("workspace root absent")?;
    env::set_current_dir(root)?;
    let args: Vec<_> = env::args().skip(1).collect();
    let task = args.first().ok_or(USAGE)?;
    match task.as_str() {
        "evidence-inputs" if args.len() == 1 => return conformance::evidence_inputs(),
        "check-conformance"
        | "check-legacy-conformance"
        | "check-api-inventory"
        | "check-external-contracts"
        | "check-external-release" => {
            let strict = match args.get(1).map(String::as_str) {
                None => false,
                Some("--strict") => true,
                _ => return Err(USAGE.into()),
            };
            if args.len() > 2 {
                return Err(USAGE.into());
            }
            // This command reports pending compatibility itself. Never append a
            // generic "passed" line that could imply complete conformance.
            return if task == "check-external-release" || task == "check-conformance" {
                external_contracts::check_external_release(strict)
            } else if task == "check-external-contracts" {
                external_contracts::check_external_contracts(strict)
            } else if task == "check-api-inventory" {
                conformance::check_api_inventory(strict)
            } else {
                conformance::check_legacy_conformance(strict)
            };
        }
        "verify" => {
            if args.len() > 2 {
                return Err(USAGE.into());
            }
            verify::verify_matrix(args.get(1).map(String::as_str))?;
        }
        check if args.len() == 1 => match check {
            "check-deps" => checks::check_deps()?,
            "check-features" => checks::check_features()?,
            "check-lints" => checks::check_lints()?,
            "check-noalloc" => checks::check_noalloc()?,
            _ => return Err(USAGE.into()),
        },
        _ => return Err(USAGE.into()),
    }
    writeln!(io::stdout().lock(), "{task}: passed")?;
    Ok(())
}
