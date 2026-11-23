//! ARM process policy over the shared original-child native registry.
//! Command preparation and stop routes are platform-specific; the reactor owns
//! one retained control state per admitted child and never reconstructs a PID.
use crate::registry::Recipe;
#[cfg(unix)]
use gnunet_native::network::BorrowedStream;
pub use gnunet_service_runtime::process::{
    ChildRegistry, EnvironmentSnapshot, LaunchError, OriginalChild, Reaped, ResourceUsage,
};
use std::{
    ffi::OsString,
    io,
    task::{Context, Poll},
};
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
pub use gnunet_service_runtime::process::ProcessLimits;
#[cfg(unix)]
pub use unix::LaunchContext;
#[cfg(unix)]
pub(crate) use unix::*;
#[cfg(windows)]
pub(crate) use windows::*;
#[cfg(windows)]
pub use windows::{LaunchContext, ProcessLimits};

pub(crate) struct Request<'a> {
    pub context: LaunchContext<'a>,
    pub recipe: &'a Recipe,
    #[cfg(windows)]
    pub profile: Option<gnunet_native::process::AccountProfile>,
    #[cfg(unix)]
    pub listeners: Vec<BorrowedStream<'a>>,
    #[cfg(windows)]
    pub listeners: Vec<gnunet_native::socket_activation::Source<'a>>,
    pub mode: ControlMode,
}

fn native_arguments(
    recipe: &Recipe,
    maximum_arguments: usize,
) -> Result<(OsString, Vec<OsString>), LaunchError> {
    match recipe {
        Recipe::Native {
            prefix,
            binary,
            arguments,
            options,
            ..
        } => {
            let argv = gnunet_service_runtime::process::compose_arguments(
                prefix,
                binary,
                arguments,
                options,
                maximum_arguments,
            )?;
            let filename = argv.first().cloned().ok_or(LaunchError::InvalidInput)?;
            Ok((filename, argv))
        }
        Recipe::Simple {
            filename,
            argv0,
            options,
        } => Ok((filename.clone(), vec![argv0.clone(), options.clone()])),
    }
}
pub(crate) struct Spawned {
    pub child: OriginalChild,
    pub control: Control,
    pub diagnostic: Option<LaunchError>,
}
pub(crate) enum SpawnResult {
    Refused { error: Option<io::Error> },
    Admitted(Spawned),
}

#[cfg(unix)]
pub(crate) type ControlEvent = std::convert::Infallible;
#[cfg(windows)]
pub(crate) enum ControlEvent {
    Ready,
    RetirementRequested,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum ControlMode {
    Pipe,
    Native,
}

#[cfg(feature = "service")]
pub(crate) struct RetainedChild {
    pub original: OriginalChild,
    pub _control: Control,
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::registry::{Limits, Registry};
    use gnunet_config::{BinaryPathCache, Configuration, ProcessEnvironment, ProjectData};
    use gnunet_native::filesystem::Directory;
    use std::{ffi::OsStr, fs, os::unix::ffi::OsStrExt, path::PathBuf};

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _cleanup = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn managed_service_preserves_native_program_and_config_arguments()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut nonce = [0; 8];
        gnunet_native::entropy::fill(&mut nonce)?;
        let root = fs::canonicalize(std::env::temp_dir())?;
        let name = format!("arm-argv-{:016x}", u64::from_ne_bytes(nonce));
        Directory::open(&root)?.create_private_directory(OsStr::new(&name))?;
        let scratch = Scratch(root.join(name));
        let config_path = scratch.0.join("a config \\\".conf");
        fs::write(&config_path, b"")?;

        let binary = b"/installed prefix/gnunet-service-\xff\\test";
        let config_bytes = config_path.as_os_str().as_bytes();
        let mut config = Configuration::default();
        config.set_value(
            b"arm",
            b"GLOBAL_PREFIX",
            Some(b"/wrapper --mode \"two words\""),
        )?;
        config.set_value(b"arm", b"GLOBAL_POSTFIX", Some(b"--global={}"))?;
        for (key, value) in [
            (b"BINARY".as_slice(), binary.as_slice()),
            (b"CONFIG", config_bytes),
            (b"DEBUG", b"YES"),
            (b"OPTIONS", b"--local \"quoted value\""),
        ] {
            config.set_value(b"example", key, Some(value))?;
        }
        let registry = Registry::from_config(
            &config,
            &ProcessEnvironment,
            &ProjectData::default(),
            &mut BinaryPathCache::new(),
            Limits::default(),
        )?;
        let service = registry
            .services()
            .first()
            .ok_or("managed service absent")?;
        let (executable, argv) = native_arguments(&service.recipe, 16)?;
        let expected: &[&[u8]] = &[
            b"/wrapper",
            b"--mode",
            b"two words",
            binary,
            b"-L",
            b"DEBUG",
            b"-c",
            config_bytes,
            b"--global=example",
            b"--local",
            b"quoted value",
        ];
        if executable != "/wrapper"
            || !argv
                .iter()
                .map(|value| value.as_os_str())
                .eq(expected.iter().map(|value| OsStr::from_bytes(value)))
        {
            return Err("managed ARM argument boundaries changed".into());
        }
        Ok(())
    }
}
