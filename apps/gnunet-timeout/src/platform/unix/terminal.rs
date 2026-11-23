//! Foreground ownership for an original Unix watchdog terminal.
use super::diagnostic;
use nix::{
    errno::Errno,
    libc,
    sys::signal::{
        SaFlags, SigAction, SigHandler, SigSet, SigmaskHow, Signal, killpg, raise, sigaction,
    },
    sys::stat::fstat,
    sys::termios::tcgetsid,
    unistd::{Pid, getpgid, getpgrp, getppid, getsid, tcgetpgrp, tcsetpgrp},
};
use std::{
    fs::OpenOptions,
    io,
    os::fd::{AsFd, OwnedFd},
    os::unix::fs::OpenOptionsExt,
};

#[cfg(target_os = "macos")]
#[path = "terminal/darwin.rs"]
mod darwin;

pub(super) struct Terminal {
    descriptor: OwnedFd,
    watchdog: Pid,
    admission: Admission,
    shell_job: Option<ShellJob>,
}

enum Admission {
    Immediate,
    OnAccess,
}

impl Terminal {
    pub(super) fn detect() -> io::Result<Option<Self>> {
        let stdin = io::stdin();
        let stdout = io::stdout();
        let stderr = io::stderr();
        for (input, descriptor) in [
            (true, stdin.as_fd()),
            (false, stdout.as_fd()),
            (false, stderr.as_fd()),
        ] {
            match tcgetpgrp(descriptor) {
                Ok(_) => {
                    // A first-stage pipeline can inherit terminal input even
                    // when a different stage owns interactive work.
                    let admission = if input
                        && fstat(&stdout)
                            .is_ok_and(|info| info.st_mode & libc::S_IFMT != libc::S_IFIFO)
                    {
                        Admission::Immediate
                    } else {
                        Admission::OnAccess
                    };
                    return Ok(Some(Self::new(descriptor.try_clone_to_owned()?, admission)));
                }
                Err(Errno::ENOTTY | Errno::EIO | Errno::ENXIO | Errno::EBADF) => {}
                Err(Errno::EPERM) if cfg!(target_os = "macos") => {}
                Err(error) => return Err(error.into()),
            }
        }
        // With all standard streams redirected an explicit /dev/tty read
        // by the original command can still request the same handoff.
        let descriptor = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
            .open("/dev/tty");
        match descriptor {
            Ok(file) => match tcgetpgrp(&file) {
                Ok(_) if !cfg!(target_os = "macos") || same_terminal_session(&file) => {
                    return Ok(Some(Self::new(file.into(), Admission::OnAccess)));
                }
                Ok(_) | Err(Errno::ENOTTY | Errno::EIO | Errno::ENXIO) => {}
                Err(Errno::EPERM) if cfg!(target_os = "macos") => {}
                Err(error) => return Err(error.into()),
            },
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::ENOTTY | libc::ENXIO | libc::ENODEV | libc::ENOENT | libc::EACCES)
                ) || cfg!(target_os = "macos") && error.raw_os_error() == Some(libc::EPERM) => {}
            Err(error) => return Err(error),
        }
        #[cfg(target_os = "macos")]
        if let Some(descriptor) = darwin::controlling_terminal() {
            return Ok(Some(Self::new(descriptor, Admission::OnAccess)));
        }
        Ok(None)
    }

    fn new(descriptor: OwnedFd, admission: Admission) -> Self {
        let watchdog = getpgrp();
        let shell_job = ShellJob::observe(&descriptor, watchdog);
        Self {
            descriptor,
            watchdog,
            admission,
            shell_job,
        }
    }

    pub(super) fn bind(self, child: Pid) -> TerminalJob {
        TerminalJob {
            terminal: self,
            child,
            foreground: Foreground::Shell,
        }
    }

    fn replace(&self, expected: Pid, next: Pid) -> nix::Result<bool> {
        let mut mask = SigSet::empty();
        mask.add(Signal::SIGTTOU);
        let previous = mask.thread_swap_mask(SigmaskHow::SIG_BLOCK)?;
        let result = loop {
            let result = tcgetpgrp(&self.descriptor).and_then(|current| {
                if current == expected {
                    tcsetpgrp(&self.descriptor, next).map(|()| true)
                } else {
                    Ok(false)
                }
            });
            if result != Err(Errno::EINTR) {
                break result;
            }
        };
        // Keep a successful transfer visible to its owner even in the event
        // of an independent signal-mask restoration failure.
        if let Err(error) = previous.thread_set_mask() {
            diagnostic(error);
        }
        result
    }
}

fn same_terminal_session(descriptor: impl AsFd) -> bool {
    getsid(None).is_ok_and(|session| tcgetsid(descriptor) == Ok(session))
}

pub(super) struct TerminalJob {
    terminal: Terminal,
    child: Pid,
    foreground: Foreground,
}

enum Foreground {
    Shell,
    Command { initial_handoff: bool },
    ReturnToCommand,
}

impl TerminalJob {
    pub(super) fn start(&mut self) -> io::Result<()> {
        if matches!(self.terminal.admission, Admission::Immediate) {
            self.claim(true)?;
        }
        Ok(())
    }

    pub(super) fn reclaim(&mut self) -> io::Result<()> {
        if matches!(self.foreground, Foreground::ReturnToCommand) {
            self.claim(false)?;
        }
        Ok(())
    }

    fn claim(&mut self, initial_handoff: bool) -> io::Result<bool> {
        let claimed = match self.terminal.replace(self.terminal.watchdog, self.child) {
            Ok(claimed) => claimed,
            Err(Errno::ENOTTY | Errno::EIO | Errno::ENXIO | Errno::EPERM | Errno::ESRCH) => false,
            Err(error) => return Err(error.into()),
        };
        if claimed {
            self.foreground = Foreground::Command { initial_handoff };
        }
        Ok(claimed)
    }

    pub(super) fn restore(&mut self) -> io::Result<bool> {
        if !matches!(self.foreground, Foreground::Command { .. }) {
            return Ok(false);
        }
        let restored = match self.terminal.replace(self.child, self.terminal.watchdog) {
            Ok(restored) => restored,
            Err(Errno::ENOTTY | Errno::EIO | Errno::ENXIO) => false,
            Err(error) => return Err(error.into()),
        };
        self.foreground = Foreground::ReturnToCommand;
        Ok(restored)
    }

    pub(super) fn suspend(&mut self, suspension: Suspension) -> nix::Result<()> {
        let restored = match self.restore() {
            Ok(restored) => restored,
            Err(error) => {
                diagnostic(error);
                false
            }
        };
        if let (Some(job), Some(stop)) = (self.terminal.shell_job, suspension.0) {
            match job.suspend(&self.terminal.descriptor, self.child, stop, restored) {
                Ok(true) => return Ok(()),
                Ok(false) => {}
                Err(error) => diagnostic(error),
            }
        }
        raise(Signal::SIGSTOP)
    }

    pub(super) fn exited(&self) -> nix::Result<bool> {
        let event = child_event(self.child, libc::WEXITED | libc::WNOWAIT)?;
        Ok(event.is_some_and(|event| {
            matches!(
                event.code,
                libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
            )
        }))
    }

    pub(super) fn discard_stop(&self) -> nix::Result<()> {
        let _superseded = child_event(self.child, libc::WSTOPPED)?;
        Ok(())
    }

    pub(super) fn stopped(&mut self) -> io::Result<Option<Stop>> {
        // Consume only stop notifications. The exit must remain pending until
        // foreground ownership is retired and std consumes the original child.
        let Some(event) = child_event(self.child, libc::WSTOPPED)?
            .filter(|event| event.code == libc::CLD_STOPPED)
        else {
            return Ok(None);
        };
        let initial_handoff = match &mut self.foreground {
            Foreground::Command { initial_handoff } => std::mem::take(initial_handoff),
            Foreground::Shell | Foreground::ReturnToCommand => false,
        };
        if matches!(event.status, libc::SIGTTIN | libc::SIGTTOU) {
            if initial_handoff && tcgetpgrp(&self.terminal.descriptor) == Ok(self.child) {
                return Ok(Some(Stop::Handoff));
            }
            if self.claim(false)? {
                return Ok(Some(Stop::Handoff));
            }
        }
        Ok(Some(Stop::Suspend(Suspension::from_child(event.status))))
    }
}

pub(super) enum Stop {
    Handoff,
    Suspend(Suspension),
}

pub(super) struct Suspension(Option<JobStop>);

impl Suspension {
    pub(super) const LOCAL: Self = Self(None);

    fn from_child(signal: libc::c_int) -> Self {
        // waitid reports the actual signal, without the sender or terminal
        // provenance. Only job-control stops can propagate to a shell job.
        Self(match signal {
            libc::SIGTSTP => Some(JobStop::Suspend),
            libc::SIGTTIN => Some(JobStop::Read),
            libc::SIGTTOU => Some(JobStop::Write),
            _ => None,
        })
    }
}

#[derive(Clone, Copy)]
enum JobStop {
    Suspend,
    Read,
    Write,
}

impl JobStop {
    const fn signal(self) -> Signal {
        match self {
            Self::Suspend => Signal::SIGTSTP,
            Self::Read => Signal::SIGTTIN,
            Self::Write => Signal::SIGTTOU,
        }
    }

    fn admitted(self, foreground: Pid, watchdog: Pid, child: Pid, restored: bool) -> bool {
        match self {
            Self::Suspend => restored && foreground == watchdog,
            Self::Read | Self::Write => {
                foreground.as_raw() > 1 && foreground != child && foreground != watchdog
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct ShellJob {
    group: Pid,
    parent: Pid,
    parent_group: Pid,
    session: Pid,
}

impl ShellJob {
    fn observe(terminal: &OwnedFd, group: Pid) -> Option<Self> {
        let parent = getppid();
        if group.as_raw() <= 1 || parent.as_raw() <= 1 {
            return None;
        }
        let session = tcgetsid(terminal).ok()?;
        let parent_group = getpgid(Some(parent)).ok()?;
        (parent_group != group
            && getsid(None) == Ok(session)
            && getsid(Some(parent)) == Ok(session)
            && getpgid(Some(parent)) == Ok(parent_group)
            && getppid() == parent
            && getpgrp() == group)
            .then_some(Self {
                group,
                parent,
                parent_group,
                session,
            })
    }

    #[expect(
        unsafe_code,
        reason = "Temporarily restore the default stop action on the standalone single-threaded watchdog, then restore the original action on resume"
    )]
    fn suspend(
        self,
        terminal: &OwnedFd,
        child: Pid,
        stop: JobStop,
        restored: bool,
    ) -> nix::Result<bool> {
        let signal = stop.signal();
        let admitted = || {
            Self::observe(terminal, getpgrp()) == Some(self)
                && tcgetpgrp(terminal)
                    .is_ok_and(|foreground| stop.admitted(foreground, self.group, child, restored))
        };
        if !admitted() || SigSet::thread_get_mask()?.contains(signal) {
            return Ok(false);
        }
        let default = SigAction::new(SigHandler::SigDfl, SaFlags::empty(), SigSet::empty());
        // SAFETY: only this standalone watchdog owns signal handling and the
        // current-thread runtime. Install the platform default, not a callback.
        let previous = unsafe { sigaction(signal, &default) }?;
        let result = if admitted() {
            // The watchdog's own live membership pins this ID. Preserve the
            // original stop signal and let the shell resume this group.
            killpg(self.group, signal).map(|()| true)
        } else {
            Ok(false)
        };
        // SAFETY: Restore the exact action from this signal's live registration.
        if let Err(error) = unsafe { sigaction(signal, &previous) } {
            diagnostic(error);
        }
        result
    }
}

struct ChildEvent {
    code: libc::c_int,
    status: libc::c_int,
}

#[expect(
    unsafe_code,
    reason = "Observe selected wait events without consuming the original child's exit status"
)]
fn child_event(child: Pid, events: libc::c_int) -> nix::Result<Option<ChildEvent>> {
    // SAFETY: siginfo has the platform C layout and zeroed scalar storage.
    let mut event: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // SAFETY: the original positive child ID and exact writable output stay
    // live. Exit queries include WNOWAIT to preserve the consuming Std wait.
    Errno::result(unsafe {
        libc::waitid(
            libc::P_PID,
            child.as_raw() as libc::id_t,
            &mut event,
            events | libc::WNOHANG,
        )
    })?;
    // SAFETY: waitid has initialized the SIGCHLD result, or retained the zero
    // value for a child whose exit is pending.
    let observed = unsafe { event.si_pid() };
    if observed == 0 {
        return Ok(None);
    }
    if observed == child.as_raw() {
        return Ok(Some(ChildEvent {
            code: event.si_code,
            // SAFETY: waitid returned a matching, initialized child event.
            status: unsafe { event.si_status() },
        }));
    }
    Err(Errno::EIO)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_control_stops_follow_original_terminal_ownership() {
        let watchdog = Pid::from_raw(121);
        let child = Pid::from_raw(122);
        let foreground = Pid::from_raw(123);
        assert!(JobStop::Suspend.admitted(watchdog, watchdog, child, true));
        assert!(!JobStop::Suspend.admitted(watchdog, watchdog, child, false));
        assert!(!JobStop::Suspend.admitted(foreground, watchdog, child, true));
        for stop in [JobStop::Read, JobStop::Write] {
            assert!(stop.admitted(foreground, watchdog, child, false));
            assert!(!stop.admitted(watchdog, watchdog, child, false));
            assert!(!stop.admitted(child, watchdog, child, false));
        }
        assert!(Suspension::from_child(libc::SIGSTOP).0.is_none());
        assert!(matches!(
            Suspension::from_child(libc::SIGTSTP).0,
            Some(JobStop::Suspend)
        ));
    }
}
