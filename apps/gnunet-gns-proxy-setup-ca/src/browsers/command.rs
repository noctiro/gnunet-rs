//! Exact original NSS child; bounded native termination and exit observation.
use crate::{Cause, budget::Budget};
#[cfg(unix)]
use std::process::{Child, Command, Stdio};
use std::{
    error::Error,
    ffi::OsString,
    fmt,
    fs::File,
    io,
    path::PathBuf,
    process::ExitStatus,
    time::{Duration, Instant},
};
#[cfg(windows)]
type Child = gnunet_native::process::Process;

pub(crate) struct Helper {
    executable: Option<PathBuf>,
    #[cfg(unix)]
    explicit: bool,
    pub(super) database: Option<PathBuf>,
    #[cfg(windows)]
    environment: gnunet_service_runtime::process::EnvironmentSnapshot,
}
const BOOTSTRAP: &[&str] = &[
    "GNUNET_OS_CONTROL_PIPE",
    "LISTEN_PID",
    "LISTEN_FDS",
    "LISTEN_FDNAMES",
    "GNUNET_RS_ACTIVATION_HANDLE",
    "GNUNET_RS_DETACH_PIPE",
];
impl Helper {
    pub(crate) fn select(config: &gnunet_config::Configuration) -> Result<Self, Cause> {
        let explicit = config.get(b"gns-proxy-rust", b"NSS_CERTUTIL").is_some();
        let selected = if explicit {
            Some(config.get_absolute_filename(
                b"gns-proxy-rust",
                b"NSS_CERTUTIL",
                &gnunet_config::ProcessEnvironment,
            )?)
        } else {
            #[cfg(unix)]
            {
                Some(PathBuf::from("certutil"))
            }
            // Windows system certutil.exe is a different program. Never select
            // it through PATH or guess that its trust-store arguments are NSS.
            #[cfg(windows)]
            {
                None
            }
        };
        Ok(Self {
            executable: selected,
            #[cfg(unix)]
            explicit,
            database: if config.get(b"gns-proxy-rust", b"NSS_DATABASE").is_some() {
                Some(config.get_filename(
                    b"gns-proxy-rust",
                    b"NSS_DATABASE",
                    &gnunet_config::ProcessEnvironment,
                )?)
            } else {
                None
            },
            #[cfg(windows)]
            environment: gnunet_service_runtime::process::EnvironmentSnapshot::system()?,
        })
    }
    #[cfg(unix)]
    fn spawn(
        &self,
        arguments: &[OsString],
        input: Option<File>,
        verbose: bool,
    ) -> io::Result<Option<Child>> {
        let Some(executable) = &self.executable else {
            return Ok(None);
        };
        let mut command = Command::new(executable);
        command
            .args(arguments)
            .stdin(input.map_or_else(Stdio::null, Stdio::from))
            .stdout(Stdio::null())
            .stderr(if verbose {
                Stdio::inherit()
            } else {
                Stdio::null()
            });
        for name in BOOTSTRAP {
            command.env_remove(name);
        }
        match command.spawn() {
            Err(error) if !self.explicit && error.kind() == io::ErrorKind::NotFound => Ok(None),
            result => result.map(Some),
        }
    }
    #[cfg(windows)]
    fn spawn(
        &self,
        arguments: &[OsString],
        input: Option<File>,
        verbose: bool,
    ) -> io::Result<Option<Child>> {
        use gnunet_service_runtime::process::{Console, LaunchLimits, NativeCommand, Stdio};
        use std::os::windows::io::AsHandle;
        let Some(executable) = &self.executable else {
            return Ok(None);
        };
        let mut environment = Vec::new();
        for (key, value) in self.environment.values() {
            let bytes = gnunet_native::os_bytes::encode(key);
            if !BOOTSTRAP
                .iter()
                .any(|name| bytes.eq_ignore_ascii_case(name.as_bytes()))
            {
                environment.try_reserve(1).map_err(io::Error::other)?;
                environment.push((key.clone(), value.clone()));
            }
        }
        let child = NativeCommand {
            executable,
            argv0: executable.as_os_str(),
            arguments,
            environment: &environment,
            directory: self.environment.current_dir(),
            stdio: [
                input
                    .as_ref()
                    .map_or(Stdio::Null, |file| Stdio::Handle(file.as_handle())),
                Stdio::Null,
                if verbose { Stdio::Inherit } else { Stdio::Null },
            ],
            exported_handles: &[],
            console: Console::Inherit,
        }
        .launch(LaunchLimits::default())?;
        Ok(Some(child))
    }
    pub(crate) async fn run(
        &self,
        arguments: &[OsString],
        input: Option<File>,
        budget: &Budget,
        verbose: bool,
    ) -> Result<Option<ExitStatus>, Cause> {
        budget.check().await?;
        let Some(mut child) = self.spawn(arguments, input, verbose)? else {
            return Ok(None);
        };
        let mut observed = None;
        let result = async {
            loop {
                if let Some(status) = try_wait(&mut child)? {
                    observed = Some(status);
                    budget.check().await?;
                    return Ok::<_, Cause>(status);
                }
                budget.check().await?;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        }
        .await;
        match result {
            Ok(status) => Ok(Some(status)),
            Err(original) => {
                // Cancellation never drops wait authority before requesting
                // termination on this exact still-held original child.
                let kill = if observed.is_none() {
                    kill(&mut child).err()
                } else {
                    None
                };
                let hard = Instant::now().checked_add(Duration::from_secs(5));
                let mut reaped = observed;
                let mut wait = None;
                while reaped.is_none() {
                    match try_wait(&mut child) {
                        Ok(Some(status)) => {
                            reaped = Some(status);
                            break;
                        }
                        Err(error) => {
                            wait = Some(error);
                            break;
                        }
                        Ok(None) => {}
                    }
                    if hard.is_none_or(|hard| Instant::now() >= hard) {
                        wait = Some(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "original NSS child exit remains unobserved",
                        ));
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(Box::new(CommandFailure {
                    arguments: arguments.to_vec(),
                    original,
                    kill,
                    reaped,
                    wait,
                }))
            }
        }
    }
}
fn try_wait(child: &mut Child) -> io::Result<Option<ExitStatus>> {
    #[cfg(unix)]
    {
        child.try_wait()
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::ExitStatusExt;
        child
            .try_wait()
            .map(|status| status.map(ExitStatus::from_raw))
    }
}
fn kill(child: &mut Child) -> io::Result<()> {
    #[cfg(unix)]
    {
        child.kill()
    }
    #[cfg(windows)]
    {
        child.terminate(1)
    }
}
#[derive(Debug)]
struct CommandFailure {
    arguments: Vec<OsString>,
    original: Cause,
    kill: Option<io::Error>,
    reaped: Option<ExitStatus>,
    wait: Option<io::Error>,
}
impl fmt::Display for CommandFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NSS helper {:?}: {}; termination={:?}, exit={:?}, wait={:?}",
            self.arguments, self.original, self.kill, self.reaped, self.wait
        )
    }
}
impl Error for CommandFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.original.as_ref())
    }
}
