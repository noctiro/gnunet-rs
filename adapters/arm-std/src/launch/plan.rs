//! Platform-independent GNUnet command text and grammar.
use super::{CommandPlan, LaunchError, LibexecContext};
use gnunet_config::{Configuration, Environment, ProjectData};
use gnunet_native::os_bytes;

pub(super) fn prepare(
    config: &Configuration,
    environment: &impl Environment,
    libexec: &mut LibexecContext<'_>,
    maximum_bytes: usize,
    maximum_arguments: usize,
) -> Result<Option<CommandPlan>, LaunchError> {
    let Some(binary) = config.get(b"arm", b"BINARY") else {
        return Ok(None);
    };
    let prefix = config
        .get(b"arm", b"PREFIX")
        .map(|value| config.expand_dollar(value, environment))
        .transpose()?;
    let postfix = config
        .get(b"arm", b"OPTIONS")
        .map(|value| config.expand_dollar(value, environment))
        .transpose()?;
    let filename = match config.get_filename(b"arm", b"CONFIG", environment) {
        Ok(path) => Some(path),
        Err(
            error @ (gnunet_config::Error::Capacity
            | gnunet_config::Error::Cycle
            | gnunet_config::Error::Overflow),
        ) => return Err(error.into()),
        Err(_) => None,
    };
    let project = ProjectData::default();
    let binary = match libexec {
        LibexecContext::Native => project.libexec_binary_path(binary)?,
        LibexecContext::Scoped(cache) => {
            project.libexec_binary_path_with(binary, environment, cache)?
        }
    };
    let binary_bytes = os_bytes::encode(binary.as_os_str());
    let daemonize = !(config.have_value(b"TESTING", b"WEAKRANDOM")
        && config
            .get_yesno(b"TESTING", b"WEAKRANDOM")
            .is_ok_and(|value| value)
        && !config.have_value(b"TESTING", b"HOSTFILE"));
    let mut command = Vec::new();
    let mut push = |value: &[u8]| -> Result<(), LaunchError> {
        if command
            .len()
            .checked_add(value.len())
            .is_none_or(|size| size > maximum_bytes)
        {
            return Err(LaunchError::Capacity);
        }
        command
            .try_reserve(value.len())
            .map_err(|_| LaunchError::Capacity)?;
        command.extend_from_slice(value);
        Ok(())
    };
    if let Some(prefix) = &prefix {
        push(prefix)?;
        push(b" \"")?;
        push(&binary_bytes)?;
        push(b"\"")?;
    } else {
        push(&binary_bytes)?;
    }
    if let Some(filename) = &filename {
        push(b" -c ")?;
        push(&os_bytes::encode(filename.as_os_str()))?;
    }
    if daemonize {
        push(b" -d")?;
    }
    if let Some(postfix) = &postfix {
        push(b" ")?;
        push(postfix)?;
    }
    #[cfg(unix)]
    let argv = super::parse_command(&command, maximum_arguments)?;
    #[cfg(windows)]
    let argv = {
        let mut fixed = Vec::new();
        if let Some(filename) = filename {
            fixed.push("-c".into());
            fixed.push(filename.into_os_string());
        }
        if daemonize {
            fixed.push("-d".into());
        }
        gnunet_service_runtime::process::compose_arguments(
            prefix.as_deref().unwrap_or_default(),
            binary.as_os_str(),
            &fixed,
            postfix.as_deref().unwrap_or_default(),
            maximum_arguments,
        )?
    };
    Ok(Some(CommandPlan {
        command,
        argv,
        daemonize,
    }))
}
