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
mod dns_bundle;
mod external_contracts;
mod inputs;
mod licenses;
mod node_stage;
mod profiles;
mod rust_target;
mod verify;

const USAGE: &str = "usage: cargo xtask check-deps|check-features|check-noalloc|check-lints|check-external-contracts [--strict]|check-external-release [--strict]|check-conformance [--strict]|check-legacy-conformance [--strict]|check-api-inventory [--strict]|evidence-inputs|verify [all|source|native|format|lint|tools|profiles|portable|runtime|test|embedded|reference|daemon-reference] [--log-dir PATH]|stage-node --output PATH [--target TRIPLE] [--install-prefix PATH] [--jobs N] [--hello-dir PATH] [--locale-dir PATH] [--wfp-package DIR] [--macos-dns-app APP.app]|stage-node-image --output PATH --target TRIPLE [--profile openharmony-small-linux] [--policy PATH] [--jobs N] [--include-nat-helpers]|stage-sdk-licenses --output PATH --target TRIPLE [--target TRIPLE ...]|bundle-dns-proxy --binary PATH --output PATH --bundle-id ID --app-group GROUP [--version VERSION]|bundle-dns-app --control-binary PATH --provider-binary PATH --output APP.app --bundle-id ID --provider-id ID --app-group GROUP [--version VERSION]";

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
    let mut native = env::args_os().skip(1).peekable();
    if native.next_if(|task| task == "stage-node").is_some() {
        return node_stage::run(root, native);
    }
    if native.next_if(|task| task == "stage-node-image").is_some() {
        return node_stage::run_image(root, native);
    }
    if native
        .next_if(|task| task == "stage-sdk-licenses")
        .is_some()
    {
        return licenses::run_sdk(root, native);
    }
    let args = native
        .map(|argument| {
            argument
                .into_string()
                .map_err(|_| "expected UTF-8 arguments")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let task = args.first().ok_or(USAGE)?;
    match task.as_str() {
        "bundle-dns-proxy" => return dns_bundle::bundle(&args[1..]),
        "bundle-dns-app" => return dns_bundle::bundle_app(&args[1..]),
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
            verify::verify_matrix(&args[1..])?;
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
