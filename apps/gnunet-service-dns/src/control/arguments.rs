//! Bounded command intent, validated before native application construction.
use crate::Failure;
use std::ffi::OsString;
#[cfg(target_os = "macos")]
use std::{path::PathBuf, time::Duration};

pub(super) enum Request {
    Help,
    Version,
    #[cfg(target_os = "macos")]
    Operation(Options),
}
#[cfg(target_os = "macos")]
pub(super) struct Options {
    pub command: Command,
    pub timeout: Duration,
}
#[cfg(target_os = "macos")]
pub(super) enum Command {
    Status,
    Enable {
        configuration: PathBuf,
        replace: bool,
    },
    Disable,
    Remove,
}
pub(super) fn parse(arguments: Vec<OsString>) -> Result<Request, Failure> {
    let mut arguments = arguments.into_iter();
    let Some(action) = arguments.next() else {
        return Ok(Request::Help);
    };
    if matches!(action.to_str(), Some("--help" | "-h" | "--version")) {
        if arguments.next().is_some() {
            return Err("help and version do not accept additional arguments".into());
        }
        return Ok(if action == "--version" {
            Request::Version
        } else {
            Request::Help
        });
    }
    #[cfg(target_os = "macos")]
    {
        operation(action, arguments)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Err("DNS proxy application management requires macOS 15 or later".into())
    }
}
#[cfg(target_os = "macos")]
fn operation(
    action: OsString,
    mut arguments: std::vec::IntoIter<OsString>,
) -> Result<Request, Failure> {
    let mut configuration = None;
    let mut replace = false;
    let mut timeout = None;
    while let Some(option) = arguments.next() {
        match option.to_str() {
            Some("--config") if configuration.is_none() => {
                let path = PathBuf::from(arguments.next().ok_or("--config requires a filename")?);
                let text = path
                    .to_str()
                    .ok_or("configuration filename must be UTF-8")?;
                if !path.is_absolute() || text.len() > 4096 || text.contains('\0') {
                    return Err("configuration requires a bounded absolute filename".into());
                }
                configuration = Some(path);
            }
            Some("--replace") if !replace => replace = true,
            Some("--timeout") if timeout.is_none() => {
                let seconds = arguments.next().ok_or("--timeout requires seconds")?;
                let seconds: u64 = seconds.to_str().ok_or("invalid timeout")?.parse()?;
                if !(1..=3600).contains(&seconds) {
                    return Err("timeout must be 1..3600 seconds".into());
                }
                timeout = Some(Duration::from_secs(seconds));
            }
            _ => return Err("unknown or duplicate DNS proxy control option".into()),
        }
    }
    if action != "enable" && (configuration.is_some() || replace) {
        return Err("--config and --replace require enable".into());
    }
    let command = match action.to_str() {
        Some("status") => Command::Status,
        Some("enable") => Command::Enable {
            configuration: configuration.ok_or("enable requires --config")?,
            replace,
        },
        Some("disable") => Command::Disable,
        Some("remove") => Command::Remove,
        _ => return Err("expected status, enable, disable or remove".into()),
    };
    Ok(Request::Operation(Options {
        command,
        timeout: timeout.unwrap_or(Duration::from_secs(120)),
    }))
}
