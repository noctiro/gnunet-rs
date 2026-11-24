//! Production executables used by host tests in other Cargo packages.
use super::CheckResult;
use serde_json::Value;
use std::{
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

pub(super) const ARM_SPAWN_HELPER_ENV: &str = "GNUNET_TEST_ARM_SPAWN_HELPER";
const ARM_SPAWN_HELPER: &str = "gnunet-arm-spawn-helper";

pub(super) fn arm_spawn_helper() -> CheckResult<PathBuf> {
    let manifest = Path::new("adapters/arm-std/Cargo.toml").canonicalize()?;
    let mut child = Command::new("cargo")
        .args([
            "build",
            "--package",
            "gnunet-arm-host",
            "--bin",
            ARM_SPAWN_HELPER,
            "--locked",
            "--message-format=json-render-diagnostics",
        ])
        .stdout(Stdio::piped())
        .spawn()?;
    let executable = child
        .stdout
        .take()
        .ok_or_else(|| "missing Cargo artifact pipe".into())
        .and_then(|stdout| find_helper(BufReader::new(stdout), &manifest));
    let status = child.wait()?;
    if !status.success() {
        return Err(format!("building {ARM_SPAWN_HELPER} failed with {status}").into());
    }
    executable
}

fn find_helper(messages: impl BufRead, manifest: &Path) -> CheckResult<PathBuf> {
    let mut executable = None;
    for line in messages.lines() {
        let line = line?;
        if !line.starts_with('{') {
            continue;
        }
        let message: Value = serde_json::from_str(&line)?;
        let target = &message["target"];
        if message["reason"] != "compiler-artifact"
            || message["manifest_path"].as_str().map(Path::new) != Some(manifest)
            || message["profile"]["test"] != false
            || target["name"] != ARM_SPAWN_HELPER
            || !target["kind"]
                .as_array()
                .is_some_and(|kind| kind == &["bin"])
        {
            continue;
        }
        let path = message["executable"]
            .as_str()
            .ok_or("Cargo helper artifact has no executable")?;
        if executable.replace(PathBuf::from(path)).is_some() {
            return Err(
                format!("Cargo reported multiple executables for {ARM_SPAWN_HELPER}").into(),
            );
        }
    }
    executable
        .filter(|path| path.is_absolute() && path.is_file())
        .ok_or_else(|| {
            format!("Cargo did not report a usable {ARM_SPAWN_HELPER} executable").into()
        })
}
