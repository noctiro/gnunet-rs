//! Original child ownership and explicit platform stop/notification mechanisms.
#[cfg(windows)]
use gnunet_native::process::ProcessWait;
use std::io;
#[cfg(unix)]
use std::process::Child as StdChild;
#[cfg(windows)]
use std::process::ExitStatus;

/// Native mechanism selected for the first original-child stop request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StopMethod {
    /// Unix SIGTERM sent while this original child remains exclusively wait-owned.
    SignalTerm,
    /// Windows TerminateProcess on the original native process handle.
    TerminateProcess,
}
#[cfg(unix)]
pub(super) type Child = StdChild;
#[cfg(windows)]
pub(super) struct Child {
    // Cancel callback registration before releasing the original std child.
    notification: Option<ProcessWait>,
    native: gnunet_native::process::Process,
}
#[cfg(windows)]
impl Child {
    /// Install notification only after the dispatcher retains the spawned child.
    pub(super) fn register(&mut self) -> io::Result<()> {
        self.notification = Some(ProcessWait::new(&self.native)?);
        Ok(())
    }
    pub(super) fn poll_notification(&mut self, cx: &mut std::task::Context<'_>) -> io::Result<()> {
        if let Some(notification) = &mut self.notification
            && let std::task::Poll::Ready(result) = notification.poll_exit(cx)
        {
            result?;
        }
        Ok(())
    }
    pub(super) fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        use std::os::windows::process::ExitStatusExt;
        self.native
            .try_wait()
            .map(|status| status.map(ExitStatus::from_raw))
    }
    pub(super) fn kill(&mut self) -> io::Result<()> {
        self.native.terminate(1)
    }
}
#[cfg(unix)]
pub(super) const STOP_METHOD: StopMethod = StopMethod::SignalTerm;
#[cfg(windows)]
pub(super) const STOP_METHOD: StopMethod = StopMethod::TerminateProcess;

pub(super) fn stop(child: &mut Child) -> io::Result<()> {
    #[cfg(unix)]
    {
        use nix::{
            sys::signal::{Signal, kill},
            unistd::Pid,
        };
        let pid = i32::try_from(child.id())
            .map_err(|_| io::Error::other("original PID exceeds native range"))?;
        kill(Pid::from_raw(pid), Signal::SIGTERM).map_err(io::Error::from)
    }
    #[cfg(windows)]
    {
        child.native.terminate(1)
    }
}

const BOOTSTRAP: &[&str] = &[
    "GNUNET_OS_CONTROL_PIPE",
    "LISTEN_PID",
    "LISTEN_FDS",
    "LISTEN_FDNAMES",
    "GNUNET_RS_ACTIVATION_HANDLE",
    "GNUNET_RS_DETACH_PIPE",
];
#[cfg(unix)]
pub(super) fn spawn(settings: crate::Settings) -> io::Result<Child> {
    use std::process::{Command, Stdio};
    let mut command = Command::new(settings.handler);
    command.args(settings.arguments).arg(settings.uri);
    if settings.inherit_stdio {
        command
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
    } else {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    }
    for key in BOOTSTRAP {
        command.env_remove(key);
    }
    command.spawn()
}
#[cfg(windows)]
pub(super) fn spawn(mut settings: crate::Settings) -> io::Result<Child> {
    use gnunet_service_runtime::process::{
        Console, EnvironmentSnapshot, LaunchLimits, NativeCommand, Stdio, resolve_executable,
    };
    let environment = EnvironmentSnapshot::system()?;
    let executable = resolve_executable(&settings.handler, &environment)?;
    settings
        .arguments
        .try_reserve_exact(1)
        .map_err(io::Error::other)?;
    settings.arguments.push(settings.uri);
    let values: Vec<_> = environment
        .values()
        .iter()
        .filter(|(key, _)| {
            let bytes = gnunet_native::os_bytes::encode(key);
            !BOOTSTRAP
                .iter()
                .any(|name| bytes.eq_ignore_ascii_case(name.as_bytes()))
        })
        .cloned()
        .collect();
    let stdio = if settings.inherit_stdio {
        [Stdio::Inherit, Stdio::Inherit, Stdio::Inherit]
    } else {
        [Stdio::Null, Stdio::Null, Stdio::Null]
    };
    // NativeCommand admits executable images, so the URI is passed as one
    // argument without batch dispatch.
    let native = NativeCommand {
        executable: &executable,
        argv0: &settings.handler,
        arguments: &settings.arguments,
        environment: &values,
        directory: environment.current_dir(),
        stdio,
        exported_handles: &[],
        console: Console::Inherit,
    }
    .launch(LaunchLimits::default())?;
    Ok(Child {
        notification: None,
        native,
    })
}
