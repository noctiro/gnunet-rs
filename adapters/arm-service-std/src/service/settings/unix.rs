//! Unix exec-helper and byte/descriptor budgets.
use super::{Failure, number};
use crate::process::ProcessLimits;
use gnunet_config::{Configuration, ProcessEnvironment, ProjectData};
use std::path::PathBuf;
pub(super) fn process(c: &Configuration, services: usize) -> Result<ProcessLimits, Failure> {
    let mut process = crate::process::ProcessLimits::default();
    process.launch.max_children = number(c, b"MAX_CHILDREN", services)?;
    process.launch.max_command_bytes =
        number(c, b"MAX_COMMAND_BYTES", process.launch.max_command_bytes)?;
    process.launch.max_arguments = number(c, b"MAX_ARGUMENTS", process.launch.max_arguments)?;
    process.launch.max_environment_bytes = number(
        c,
        b"MAX_ENVIRONMENT_BYTES",
        process.launch.max_environment_bytes,
    )?;
    process.max_descriptors = number(c, b"MAX_DESCRIPTORS", process.max_descriptors)?;
    process.max_auxiliary_bytes = number(c, b"MAX_AUXILIARY_BYTES", process.max_auxiliary_bytes)?;

    if process.launch.max_children == 0
        || process.launch.max_children > services
        || process.launch.max_command_bytes == 0
        || process.launch.max_arguments == 0
        || process.launch.max_environment_bytes == 0
        || process.max_descriptors == 0
        || process.max_auxiliary_bytes == 0
    {
        return Err("invalid finite Unix ARM process profile".into());
    }
    Ok(process)
}
pub(super) fn command_bytes(process: ProcessLimits) -> usize {
    process.launch.max_command_bytes
}
pub(super) fn helper(c: &Configuration) -> Result<PathBuf, Failure> {
    let helper = if c.have_value(b"arm-rust", b"SPAWN_HELPER") {
        c.get_filename(b"arm-rust", b"SPAWN_HELPER", &ProcessEnvironment)?
    } else {
        let executable = std::env::current_exe()?;
        let sibling = executable
            .parent()
            .ok_or("ARM executable has no directory")?
            .join("gnunet-arm-spawn-helper");
        if sibling.is_file() {
            sibling
        } else {
            ProjectData::default().libexec_binary_path(b"gnunet-arm-spawn-helper")?
        }
    };
    Ok(helper)
}
