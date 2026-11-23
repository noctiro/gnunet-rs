//! Watchdog for the command's original Unix process group.
use super::{Outcome, REAP_GRACE, diagnostic};
use nix::{
    errno::Errno,
    sys::signal::{SigHandler, SigSet, Signal, killpg, raise, signal as disposition},
    unistd::Pid,
};
use std::{
    ffi::{OsStr, OsString},
    io,
    os::unix::process::{CommandExt, ExitStatusExt},
    process::{Child, Command, ExitCode, ExitStatus},
    time::Duration,
};
use tokio::{
    signal::unix::{Signal as ExitEvents, SignalKind, signal},
    time::{sleep, timeout},
};

#[path = "unix/terminal.rs"]
mod terminal;
use terminal::{Stop, Suspension, Terminal, TerminalJob};

const TERM_GRACE: Duration = Duration::from_millis(250);

struct Group {
    child: Child,
    id: Option<Pid>,
    terminal: Option<TerminalJob>,
}

#[derive(Clone, Copy)]
enum WaitMode {
    Running { deadline: tokio::time::Instant },
    Retiring,
}
impl Group {
    async fn wait(&mut self, exits: &mut ExitEvents, mode: WaitMode) -> io::Result<ExitStatus> {
        loop {
            match self.try_wait(mode) {
                Ok(None) => {
                    if exits.recv().await.is_none() {
                        return Err(io::Error::other("Unix child exit notification closed"));
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Some(status)) => return Ok(status),
                Err(error) => return Err(error),
            }
        }
    }

    fn try_wait(&mut self, mode: WaitMode) -> io::Result<Option<ExitStatus>> {
        if self.terminal.is_some() {
            match self.terminal_exit(mode) {
                Ok(true) => self.restore_terminal(),
                Ok(false) => return Ok(None),
                Err(error) => return Err(self.terminal_error(error)),
            }
        }
        let status = self.child.try_wait();
        if !matches!(&status, Ok(None))
            && !matches!(&status, Err(error) if error.kind() == io::ErrorKind::Interrupted)
        {
            // A consuming wait or an ambiguous error ends numeric group authority.
            self.id = None;
        }
        status
    }

    fn terminal_exit(&mut self, mode: WaitMode) -> io::Result<bool> {
        let Some(terminal) = &mut self.terminal else {
            return Ok(false);
        };
        if terminal.exited()? {
            return Ok(true);
        }
        if let WaitMode::Running { deadline } = mode
            && tokio::time::Instant::now() < deadline
            && let Some(stop) = terminal.stopped()?
        {
            match stop {
                Stop::Suspend(stop) => return self.suspend(deadline, stop),
                Stop::Handoff if tokio::time::Instant::now() < deadline => {
                    self.signal(Signal::SIGCONT)?;
                }
                Stop::Handoff => {}
            }
        }
        Ok(false)
    }

    fn suspend(&mut self, deadline: tokio::time::Instant, stop: Suspension) -> io::Result<bool> {
        if tokio::time::Instant::now() >= deadline {
            return Ok(false);
        }
        // Keep every original private group member paused while the shell
        // owns this job's stop. The unreaped leader still pins the group ID.
        self.signal(Signal::SIGSTOP)?;
        if let Some(terminal) = &mut self.terminal {
            terminal.suspend(stop)?;
        } else {
            raise(Signal::SIGSTOP)?;
        }
        if let Some(terminal) = &mut self.terminal {
            if terminal.exited()? {
                return Ok(true);
            }
            if tokio::time::Instant::now() < deadline {
                // The parent's resume supersedes the notification from the
                // stop we sent to the original group before stopping ourselves.
                terminal.discard_stop()?;
                if let Err(error) = terminal.reclaim() {
                    diagnostic(error);
                }
            }
        }
        if tokio::time::Instant::now() < deadline {
            self.signal(Signal::SIGCONT)?;
        }
        Ok(false)
    }

    fn terminal_error(&mut self, error: io::Error) -> io::Error {
        if error.raw_os_error() == Some(Errno::ECHILD as i32) {
            // Once the native wait loses custody, a numeric ID cannot
            // authorize either terminal restoration or group signals.
            self.id = None;
            self.terminal = None;
        }
        error
    }

    fn restore_terminal(&mut self) {
        if let Some(mut terminal) = self.terminal.take()
            && let Err(error) = terminal.restore()
        {
            diagnostic(error);
        }
    }

    fn signal(&self, signal: Signal) -> nix::Result<()> {
        if let Some(id) = self.id {
            match killpg(id, signal) {
                Ok(()) | Err(Errno::ESRCH) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    async fn retire(&mut self, first: Signal, exits: &mut ExitEvents) {
        if let Err(error) = self.signal(first) {
            diagnostic(error);
        }
        // Preserve the unreaped leader's PID throughout both group operations.
        // Even if it exited before this grace ended, its number cannot be reused.
        sleep(TERM_GRACE).await;
        if let Err(error) = self.signal(Signal::SIGKILL) {
            diagnostic(error);
        }
        if let Err(error) = self.child.kill() {
            diagnostic(error);
        }
        match timeout(REAP_GRACE, self.wait(exits, WaitMode::Retiring)).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => diagnostic(error),
            Err(_) => {
                diagnostic("original child exit could not be confirmed within the reap deadline")
            }
        }
    }
}
impl Drop for Group {
    fn drop(&mut self) {
        self.restore_terminal();
        if self.id.is_some() {
            let _group_signal = self.signal(Signal::SIGKILL);
            let _child_signal = self.child.kill();
        }
    }
}

pub(super) async fn run(
    program: &OsStr,
    arguments: &[OsString],
    duration: Duration,
) -> io::Result<Outcome> {
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let mut quit = signal(SignalKind::quit())?;
    let mut hangup = signal(SignalKind::hangup())?;
    let mut abort = signal(SignalKind::from_raw(Signal::SIGABRT as i32))?;
    let mut suspend = signal(SignalKind::from_raw(Signal::SIGTSTP as i32))?;
    let mut exits = signal(SignalKind::child())?;
    let terminal = Terminal::detect()?;
    let mut child = Command::new(program)
        .args(arguments)
        .process_group(0)
        .spawn()?;
    let Some(id) = i32::try_from(child.id())
        .ok()
        .filter(|id| *id > 0)
        .map(Pid::from_raw)
    else {
        let _termination = child.kill();
        return Err(io::ErrorKind::InvalidData.into());
    };
    let mut group = Group {
        child,
        id: Some(id),
        terminal: terminal.map(|terminal| terminal.bind(id)),
    };
    if let Some(terminal) = &mut group.terminal {
        terminal.start()?;
    }
    let deadline = tokio::time::Instant::now() + duration;
    let timer = tokio::time::sleep_until(deadline);
    tokio::pin!(timer);
    let signal = loop {
        break tokio::select! {
            biased;
            status = group.wait(&mut exits, WaitMode::Running { deadline }) => {
                let status = status?;
                return if let Some(code) = status.code() {
                    Ok(Outcome::Exited(code as u32))
                } else {
                    status.signal().map(Outcome::Signaled).ok_or_else(|| io::ErrorKind::InvalidData.into())
                };
            }
            _ = interrupt.recv() => Some(Signal::SIGINT),
            _ = terminate.recv() => Some(Signal::SIGTERM),
            _ = quit.recv() => Some(Signal::SIGQUIT),
            _ = hangup.recv() => Some(Signal::SIGHUP),
            _ = abort.recv() => Some(Signal::SIGABRT),
            _ = &mut timer => None,
            _ = suspend.recv() => {
                if let Err(error) = group.suspend(deadline, Suspension::LOCAL) {
                    return Err(group.terminal_error(error));
                }
                continue;
            }
        };
    };
    group
        .retire(signal.unwrap_or(Signal::SIGTERM), &mut exits)
        .await;
    Ok(signal.map_or(Outcome::Deadline, |signal| Outcome::Exited(signal as u32)))
}

pub(super) fn exit(code: u32) -> ExitCode {
    ExitCode::from(u8::try_from(code).unwrap_or(255))
}

#[expect(
    unsafe_code,
    reason = "The terminal watchdog restores only the child's classified fatal signal before exiting with that signal"
)]
pub(super) fn signal_exit(raw: i32) -> ExitCode {
    if let Ok(signal) = Signal::try_from(raw) {
        let mut signals = SigSet::empty();
        signals.add(signal);
        // SAFETY: all watchdog/runtime owners were retired by the only caller;
        // this installs the platform default instead of a user callback.
        if unsafe { disposition(signal, SigHandler::SigDfl) }.is_ok()
            && signals.thread_unblock().is_ok()
        {
            let _termination = raise(signal);
        }
    }
    ExitCode::from(u8::try_from(128_i32.saturating_add(raw)).unwrap_or(255))
}
