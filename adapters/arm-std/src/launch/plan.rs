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
    let mut fixed = Vec::new();
    if let Some(filename) = filename {
        fixed.push("-c".into());
        fixed.push(filename.into_os_string());
    }
    if daemonize {
        fixed.push("-d".into());
    }
    let argv = gnunet_service_runtime::process::compose_arguments(
        prefix.as_deref().unwrap_or_default(),
        binary.as_os_str(),
        &fixed,
        postfix.as_deref().unwrap_or_default(),
        maximum_arguments,
    )?;
    Ok(Some(CommandPlan {
        command,
        argv,
        daemonize,
    }))
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use gnunet_config::ProcessEnvironment;
    use std::{ffi::OsStr, io, os::unix::ffi::OsStrExt};

    #[test]
    fn bootstrap_preserves_literal_native_paths_with_wrapper_options() -> Result<(), LaunchError> {
        let binary = b"/example prefix/gnunet-arm-\xff\\service";
        let configuration = b"/example config/options \xff\".conf";
        let mut config = Configuration::default();
        for (key, value) in [
            (b"BINARY".as_slice(), binary.as_slice()),
            (b"CONFIG", configuration),
            (b"PREFIX", b"wrapper --label \"two words\""),
            (b"OPTIONS", b"--option \"quoted value\""),
        ] {
            config.set_value(b"arm", key, Some(value))?;
        }
        let plan = prepare(
            &config,
            &ProcessEnvironment,
            &mut LibexecContext::Native,
            4096,
            16,
        )?
        .ok_or(LaunchError::InvalidInput)?;
        let expected: &[&[u8]] = &[
            b"wrapper",
            b"--label",
            b"two words",
            binary,
            b"-c",
            configuration,
            b"-d",
            b"--option",
            b"quoted value",
        ];
        if !plan
            .argv
            .iter()
            .map(|value| value.as_os_str())
            .eq(expected.iter().map(|value| OsStr::from_bytes(value)))
        {
            return Err(io::Error::other("ARM bootstrap argument boundaries changed").into());
        }
        Ok(())
    }
}
