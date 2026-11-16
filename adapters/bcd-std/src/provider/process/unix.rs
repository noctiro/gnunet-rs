//! Unix descriptor mapping and original child admission through the shared launcher.
use super::{Cause, Settings};
use gnunet_service_runtime::process::{
    self, ChildRegistry, DescriptorMap, EnvironmentSnapshot, NativeCommand, OriginalChild,
    ProcessLimits, SpawnResult,
};
use std::{
    ffi::OsString,
    fs::File,
    os::fd::AsFd,
    path::{Path, PathBuf},
};
pub(in crate::provider) fn spawn(
    registry: &mut ChildRegistry,
    settings: &Settings,
    tool: &Path,
    argv: Vec<OsString>,
    environment: EnvironmentSnapshot,
    cwd: PathBuf,
    logs: [&File; 2],
) -> Result<OriginalChild, Cause> {
    let [stdout, stderr] = logs;
    let limits = ProcessLimits {
        launch: process::LaunchLimits {
            max_command_bytes: 16 * 1024,
            max_arguments: 32,
            max_children: 1,
            max_environment_bytes: 64 * 1024,
        },
        max_auxiliary_bytes: 4096,
        max_descriptors: 2,
        // Two mappings bound admission credit. A duplicated source can have
        // any kernel-assigned fd number; that number is not a resource count.
        max_descriptor_number: i32::MAX,
    };
    let command = NativeCommand {
        filename: tool.as_os_str().to_owned(),
        argv,
        environment,
        environment_changes: Vec::new(),
        cwd: Some(cwd),
        stdio: 0,
        stdio_snapshot: None,
        listeners: Vec::new(),
        mappings: vec![
            DescriptorMap {
                source: stdout.as_fd(),
                target: 1,
            },
            DescriptorMap {
                source: stderr.as_fd(),
                target: 2,
            },
        ],
    };
    let admitted = process::spawn(
        &settings.configuration,
        &settings.launcher,
        command,
        limits,
        registry,
    )
    .map_err(Cause::Launch)?;
    match admitted {
        SpawnResult::Refused { error } => {
            Err(Cause::Io(error.unwrap_or_else(|| {
                std::io::Error::other("native renderer invocation refused")
            })))
        }
        SpawnResult::Admitted(spawned) => Ok(spawned.child),
    }
}
