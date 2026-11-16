//! Original Unix helper process with exclusively retained wait authority.
use super::{Spawned, Stop};
use crate::transport::HelperOptions;
use std::{
    future::Future,
    io,
    process::{ExitStatus, Stdio},
    task::{Context, Poll},
};
use tokio::process::Command;
pub(in crate::transport) type Input = tokio::process::ChildStdin;
pub(in crate::transport) type Output = tokio::process::ChildStdout;
pub(in crate::transport) struct Child {
    native: tokio::process::Child,
    wait_failed: bool,
}
pub(in crate::transport) fn spawn(options: &HelperOptions) -> io::Result<Spawned> {
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    if !options.skip_routing && nix::unistd::getgid() != nix::unistd::getegid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "DNS daemon requires equal real/effective groups for PF owner exemption",
        ));
    }
    let mut command = Command::new(&options.program);
    command
        .arg(&options.interface)
        .arg(options.ipv6.to_string())
        .arg(options.prefix.to_string())
        .arg(options.ipv4.to_string())
        .arg(options.mask.to_string())
        .arg(if options.skip_routing { "1" } else { "0" })
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(false);
    let mut native = command.spawn()?;
    let stdin = native.stdin.take();
    let stdout = native.stdout.take();
    let startup_error = if stdin.is_none() || stdout.is_none() {
        Some(io::Error::other(
            "DNS helper required original pipe missing",
        ))
    } else {
        None
    };
    #[cfg(target_os = "linux")]
    let startup_error = startup_error.or_else(|| {
        native
            .id()
            .ok_or_else(|| io::Error::other("DNS helper missing original PID"))
            .and_then(crate::transport::check_group)
            .err()
    });
    Ok(Spawned {
        child: Child {
            native,
            wait_failed: false,
        },
        stdin,
        stdout,
        startup_error,
    })
}
impl Child {
    pub fn id(&self) -> Option<u32> {
        self.native.id()
    }
    pub fn stop(&self, stop: Stop) -> io::Result<()> {
        if self.wait_failed {
            // A failed wait cannot authorize signaling a possibly reused PID.
            return Err(io::Error::other(
                "DNS helper original wait authority failed",
            ));
        }
        let Some(pid) = self.native.id() else {
            return Ok(());
        };
        let pid = i32::try_from(pid)
            .map(nix::unistd::Pid::from_raw)
            .map_err(io::Error::other)?;
        let signal = match stop {
            Stop::Graceful => nix::sys::signal::Signal::SIGTERM,
            Stop::Force => nix::sys::signal::Signal::SIGKILL,
        };
        match nix::sys::signal::kill(pid, signal) {
            Ok(()) | Err(nix::errno::Errno::ESRCH) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }
    pub fn poll_exit(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<ExitStatus>> {
        if self.wait_failed {
            return Poll::Pending;
        }
        let result = std::pin::pin!(self.native.wait()).as_mut().poll(cx);
        if let Poll::Ready(Err(error)) = &result
            && error.kind() == io::ErrorKind::Interrupted
        {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        if matches!(result, Poll::Ready(Err(_))) {
            self.wait_failed = true;
        }
        result
    }
}
