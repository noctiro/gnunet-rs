//! Windows UTF-16, environment, handle and provider-transfer budgets.
use super::{Failure, number};
use crate::process::ProcessLimits;
use gnunet_config::Configuration;
pub(super) fn process(c: &Configuration, services: usize) -> Result<ProcessLimits, Failure> {
    for key in [
        b"SPAWN_HELPER".as_slice(),
        b"MAX_AUXILIARY_BYTES",
        b"MAX_ENVIRONMENT_BYTES",
        b"MAX_DESCRIPTORS",
    ] {
        if c.have_value(b"arm-rust", key) {
            return Err(
                "Windows ARM uses native UTF-16/handle budgets, not Unix helper/descriptor options"
                    .into(),
            );
        }
    }
    let mut process = ProcessLimits::default();
    process.max_children = number(c, b"MAX_CHILDREN", services)?;
    process.max_command_bytes = number(c, b"MAX_COMMAND_BYTES", process.max_command_bytes)?;
    process.max_listeners = number(c, b"MAX_LISTENERS_PER_CHILD", process.max_listeners)?;
    let arguments = number(c, b"MAX_ARGUMENTS", 4096)?;
    process.native.arguments = arguments.saturating_sub(1);
    process.native.command_units = number(c, b"MAX_COMMAND_UNITS", process.native.command_units)?;
    process.native.environment_units = number(
        c,
        b"MAX_ENVIRONMENT_UNITS",
        process.native.environment_units,
    )?;
    process.native.environment_entries = number(
        c,
        b"MAX_ENVIRONMENT_ENTRIES",
        process.native.environment_entries,
    )?;
    process.native.handles = number(c, b"MAX_HANDLES", process.native.handles)?;
    if process.max_children == 0
        || process.max_children > services
        || process.max_command_bytes == 0
        || process.max_listeners == 0
        || process.max_listeners > 4096
        || arguments == 0
        || process.native.command_units == 0
        || process.native.command_units > 32767
        || process.native.environment_units == 0
        || process.native.environment_entries == 0
        || process.native.handles < 3
    {
        return Err("invalid finite Windows ARM process profile".into());
    }
    Ok(process)
}
pub(super) fn command_bytes(process: ProcessLimits) -> usize {
    process.max_command_bytes
}
