use crate::Failure;
use gnunet_config::Configuration;
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
};
use std::{ffi::OsString, os::unix::ffi::OsStringExt, path::PathBuf, time::Duration};
pub(super) struct Arguments {
    ego: Target<Option<Vec<u8>>>,
    phone: Target<Option<Vec<u8>>>,
    timeout: Target<u64>,
}
impl Arguments {
    pub fn new() -> Self {
        Self {
            ego: Target::new(None),
            phone: Target::new(None),
            timeout: Target::new(0),
        }
    }
    pub fn options(&self) -> Options<'static> {
        let mut options = Options::new();
        options.add(helpers::string(
            b'e',
            b"ego",
            b"NAME",
            b"Actual IDENTITY ego for caller authentication",
            self.ego.clone(),
        ));
        options.add(helpers::string(
            b'p',
            b"phone",
            b"LINE",
            b"Phone line text, hashed by the official SHA512 port mapping",
            self.phone.clone(),
        ));
        options.add(helpers::relative_time(
            0,
            b"timeout",
            b"DURATION",
            b"Finite whole original interactive session lifetime",
            self.timeout.clone(),
        ));
        options
    }
    pub fn selection(
        &self,
        remaining: &[Vec<u8>],
        c: &Configuration,
        s: &Settings,
    ) -> Result<Selection, Failure> {
        if !remaining.is_empty() {
            return Err("Conversation takes -e/-p options and interactive commands, no private-key positional input".into());
        }
        let ego = self
            .ego
            .with(|v| copy(v.as_deref().ok_or("--ego NAME is required")?, 1024, false))??;
        let phone = self.phone.with(|v| {
            copy(
                v.as_deref()
                    .or_else(|| c.get(b"conversation", b"LINE"))
                    .unwrap_or(b"1"),
                1024,
                false,
            )
        })??;
        let timeout = self.timeout.get()?;
        let life = if timeout == 0 {
            s.life
        } else {
            duration(timeout)?
        };
        Ok(Selection { ego, phone, life })
    }
}
pub(super) fn copy(input: &[u8], maximum: usize, empty: bool) -> Result<Vec<u8>, Failure> {
    if (!empty && input.is_empty()) || input.len() > maximum || input.contains(&0) {
        return Err("invalid or over-bound Conversation input".into());
    }
    std::str::from_utf8(input)?;
    let mut v = Vec::new();
    v.try_reserve_exact(input.len())?;
    if v.capacity() > maximum {
        return Err("Conversation input allocation exceeds its bound".into());
    }
    v.extend_from_slice(input);
    Ok(v)
}
fn duration(us: u64) -> Result<Duration, Failure> {
    let d = Duration::from_micros(us);
    if us == 0 || us == u64::MAX || std::time::Instant::now().checked_add(d).is_none() {
        return Err("Conversation durations must be finite and representable".into());
    }
    Ok(d)
}
pub(super) struct Selection {
    pub ego: Vec<u8>,
    pub phone: Vec<u8>,
    pub life: Duration,
}
#[derive(Clone)]
pub(super) struct Settings {
    pub pils_profile: gnunet_pils::Profile,
    pub life: Duration,
    pub startup: Duration,
    pub call: Duration,
    pub control: Duration,
    pub shutdown: Duration,
    pub command_bytes: usize,
    pub output_bytes: usize,
    pub calls: usize,
    pub playback_frames: usize,
    pub record: PathBuf,
    pub playback: PathBuf,
    pub launcher: PathBuf,
    pub native: gnunet_conversation_client_host::Limits,
    pub identity: gnunet_identity_client_host::Limits,
    pub resolver: gnunet_resolver_broker::Limits,
}
impl Settings {
    pub fn read(c: &Configuration) -> Result<Self, Failure> {
        let section = b"conversation-command-rust";
        let number = |key: &[u8], default: u64| -> Result<u64, Failure> {
            Ok(c.get(section, key)
                .map(|_| c.get_number(section, key))
                .transpose()?
                .unwrap_or(default))
        };
        let bytes = |key: &[u8], default: usize| -> Result<usize, Failure> {
            Ok(usize::try_from(
                c.get(section, key)
                    .map(|_| c.get_size(section, key))
                    .transpose()?
                    .unwrap_or(u64::try_from(default)?),
            )?)
        };
        let time = |key: &[u8], default: u64| -> Result<Duration, Failure> {
            duration(
                c.get(section, key)
                    .map(|_| c.get_time(section, key))
                    .transpose()?
                    .unwrap_or(default),
            )
        };
        let exe = std::env::current_exe()?;
        let dir = exe
            .parent()
            .ok_or("current Rust command has no installation directory")?;
        let defaults = if dir.file_name().is_some_and(|n| n == "bin") {
            dir.parent()
                .ok_or("Rust installation has no prefix")?
                .join("lib/gnunet/libexec")
        } else {
            dir.to_path_buf()
        };
        let path = |key: &[u8], name: &str| -> Result<PathBuf, Failure> {
            let p = match c.get(section, key) {
                Some(v) => PathBuf::from(OsString::from_vec(copy(v, 4096, false)?)),
                None => defaults.join(name),
            };
            if !p.is_absolute() {
                return Err(
                    "explicit media/helper paths must be absolute; no PATH fallback is used".into(),
                );
            }
            Ok(p)
        };
        let calls = usize::try_from(number(b"MAX_CALLS", 32)?)?;
        let command_bytes = bytes(b"COMMAND_BYTES", 4096)?;
        let output_bytes = bytes(b"OUTPUT_BYTES", 1048576)?;
        let playback_frames = usize::try_from(number(b"PLAYBACK_FRAMES", 8)?)?;
        if !(1..=1024).contains(&calls)
            || !(256..=65535).contains(&command_bytes)
            || !(65536..=64 * 1048576).contains(&output_bytes)
            || !(1..=64).contains(&playback_frames)
        {
            return Err("invalid finite Conversation terminal/call/media profile".into());
        }
        let native = gnunet_conversation_client_host::Limits {
            calls,
            pending: usize::try_from(number(b"PENDING_FRAMES", 64)?)?,
            queued_bytes: bytes(b"AUDIO_OUTPUT_BYTES", 1048576)?,
            retained_bytes: bytes(b"NATIVE_RETAINED_BYTES", 4194304)?,
            audio_frames: playback_frames,
            ..Default::default()
        };
        native.validate()?;
        let identity = gnunet_identity_client_host::Limits {
            operations: 1,
            egos: usize::try_from(number(b"MAX_EGOS", 1024)?)?,
            reconnect: false,
            ..Default::default()
        };
        if identity.egos == 0 || identity.egos > 65536 {
            return Err("MAX_EGOS must be1 through65536".into());
        }
        Ok(Self {
            pils_profile: gnunet_pils::Profile::configured(
                c.get(b"PILS", b"PROFILE"),
                c.get(section, b"PILS_PROFILE"),
            )?,
            life: time(b"SESSION_LIFETIME", 86400000000)?,
            startup: time(b"STARTUP_TIMEOUT", 30000000)?,
            call: time(b"CALL_LIFETIME", 86400000000)?,
            control: time(b"CONTROL_TIMEOUT", 10000000)?,
            shutdown: time(b"SHUTDOWN_GRACE", 5000000)?,
            command_bytes,
            output_bytes,
            calls,
            playback_frames,
            record: path(b"HELPER_RECORD", "gnunet-helper-audio-record")?,
            playback: path(b"HELPER_PLAYBACK", "gnunet-helper-audio-playback")?,
            launcher: path(b"HELPER_LAUNCHER", "gnunet-arm-spawn-helper")?,
            native,
            identity,
            resolver: Default::default(),
        })
    }
}
pub(super) enum Command {
    Address,
    Call(Vec<u8>),
    Accept(Option<u64>),
    Suspend,
    Resume(Option<u64>),
    Cancel(Option<u64>),
    Status,
    Quit,
    Help(Option<Vec<u8>>),
}
fn selector(value: Option<&str>) -> Result<Option<u64>, Failure> {
    value
        .map(|v| {
            let value = v.strip_prefix('#').unwrap_or(v).parse::<u64>()?;
            if value == 0 {
                return Err("call numbers start at1".into());
            }
            Ok(value)
        })
        .transpose()
}
pub(super) fn command(input: &[u8]) -> Result<Command, Failure> {
    let text = std::str::from_utf8(input)?;
    let mut words = text.split_ascii_whitespace();
    let name = words.next().unwrap_or("/help");
    let argument = words.next();
    if words.next().is_some() {
        return Err("this interactive command takes at most one argument".into());
    }
    let command = if name.eq_ignore_ascii_case("/address") {
        Command::Address
    } else if name.eq_ignore_ascii_case("/call") {
        Command::Call(copy(
            argument.ok_or("/call requires a full GNS name")?.as_bytes(),
            1024,
            false,
        )?)
    } else if name.eq_ignore_ascii_case("/accept") {
        Command::Accept(selector(argument)?)
    } else if name.eq_ignore_ascii_case("/suspend") {
        Command::Suspend
    } else if name.eq_ignore_ascii_case("/resume") {
        Command::Resume(selector(argument)?)
    } else if name.eq_ignore_ascii_case("/cancel") {
        Command::Cancel(selector(argument)?)
    } else if name.eq_ignore_ascii_case("/status") {
        Command::Status
    } else if name.eq_ignore_ascii_case("/quit") {
        Command::Quit
    } else if name.eq_ignore_ascii_case("/help") {
        Command::Help(
            argument
                .map(|a| copy(a.as_bytes(), 32, false))
                .transpose()?,
        )
    } else {
        return Err("unknown command; use /help".into());
    };
    if argument.is_some()
        && matches!(
            command,
            Command::Address | Command::Suspend | Command::Status | Command::Quit
        )
    {
        return Err("this command takes no argument".into());
    }
    Ok(command)
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    use gnunet_pils::Profile;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "The terminal must select the same actual PILS semantics as its configured node"
    )]
    fn terminal_inherits_node_profile_and_rejects_conflicting_source() -> Result<(), Failure> {
        let mut config = Configuration::default();
        assert_eq!(Settings::read(&config)?.pils_profile, Profile::Reference029);
        config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
        assert_eq!(
            Settings::read(&config)?.pils_profile,
            Profile::ReferenceDeterministic
        );
        config.set_value(
            b"conversation-command-rust",
            b"PILS_PROFILE",
            Some(b"reference029"),
        )?;
        assert!(Settings::read(&config).is_err());
        config.set_value(
            b"conversation-command-rust",
            b"PILS_PROFILE",
            Some(b"reference-deterministic"),
        )?;
        assert_eq!(
            Settings::read(&config)?.pils_profile,
            Profile::ReferenceDeterministic
        );
        config.set_value(b"PILS", b"PROFILE", Some(b"unknown"))?;
        assert!(Settings::read(&config).is_err());
        Ok(())
    }
}
