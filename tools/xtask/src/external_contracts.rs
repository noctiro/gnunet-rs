//! External protocol inventory checks, separate from C API/helper coverage.
use std::{error::Error, path::Path, process::Command};

/// Check the reviewed discovery draft; strict release readiness remains pending.
pub(crate) fn check_external_contracts(strict: bool) -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("workspace root absent")?;
    let mut command = Command::new("python3");
    command
        .current_dir(root)
        .args(["-B", "tools/external-contracts/verify.py"]);
    if strict {
        command.arg("--strict");
    }
    if !command.status()?.success() {
        return Err("external protocol inventory is invalid or not release-complete; inspect the draft report above".into());
    }
    Ok(())
}

/// Canonical strict compatibility gate over external contracts. Unknown semantic
/// inventories remain blocking; C internal API/helper coverage is not consulted.
pub(crate) fn check_external_release(strict: bool) -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or("workspace root absent")?;
    let mut command = Command::new("python3");
    command
        .current_dir(root)
        .args(["-B", "tools/external-contracts/release.py"]);
    if strict {
        command.arg("--strict");
    }
    if !command.status()?.success() {
        return Err("external compatibility release blocked or invalid; inspect external contracts, unknowns and evidence above".into());
    }
    Ok(())
}
