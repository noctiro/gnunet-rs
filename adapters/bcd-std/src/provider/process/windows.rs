//! Explicit native Windows process handles, private logs and exit waits.
use super::{Cause, Settings};
use gnunet_service_runtime::process::{
    ChildRegistry, Console, EnvironmentSnapshot, LaunchLimits, NativeCommand, OriginalChild, Stdio,
};
use std::{
    ffi::OsString,
    fs::File,
    os::windows::io::AsHandle,
    path::{Path, PathBuf},
};
pub(in crate::provider) fn spawn(
    registry: &mut ChildRegistry,
    _settings: &Settings,
    tool: &Path,
    argv: Vec<OsString>,
    environment: EnvironmentSnapshot,
    cwd: PathBuf,
    logs: [&File; 2],
) -> Result<OriginalChild, Cause> {
    let [stdout, stderr] = logs;
    let command = NativeCommand {
        executable: tool,
        argv0: argv.first().ok_or(Cause::Input)?,
        arguments: argv.get(1..).ok_or(Cause::Input)?,
        environment: environment.values(),
        directory: &cwd,
        stdio: [
            Stdio::Null,
            Stdio::Handle(stdout.as_handle()),
            Stdio::Handle(stderr.as_handle()),
        ],
        exported_handles: &[],
        console: Console::Detached,
    };
    registry
        .spawn(
            command,
            LaunchLimits {
                command_units: 16 * 1024,
                environment_units: 64 * 1024,
                environment_entries: 32,
                arguments: 32,
                handles: 3,
            },
        )
        .map_err(super::registry_error)
}
