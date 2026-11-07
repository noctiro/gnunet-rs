//! Same actual configured-handler child, retained across dropped observation futures.
use crate::{
    Settings,
    control::{Signals, Wake},
};
use gnunet_program_host::reporting::Reporter;
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_service_startup::ParentControl;
use gnunet_types::Error as Fault;
use nix::{
    sys::signal::{Signal, kill},
    unistd::Pid,
};
use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    process::{Child, Command, ExitStatus, Stdio},
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
/// Fixed original whole-operation targets; decoding never renews dispatch time.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Original canonical microsecond deadline.
    pub expires: u64,
    /// Original native deadline, independent of clock/provider delay.
    pub hard: Instant,
}
impl Bounds {
    /// Capture the native origin before the canonical provider is called.
    pub fn new(clock: &dyn RuntimeClock, life: Duration) -> Result<Self, Cause> {
        let start = Instant::now();
        if life.is_zero() {
            return Err(Cause::Clock(Fault::InvalidInput));
        }
        let hard = start
            .checked_add(life)
            .ok_or(Cause::Clock(Fault::Overflow))?;
        let micros = u64::try_from(life.as_micros()).map_err(|_| Cause::Clock(Fault::Overflow))?;
        let expires = clock
            .sample()
            .map_err(Cause::Clock)?
            .now
            .as_micros()
            .checked_add(micros)
            .filter(|n| *n != u64::MAX)
            .ok_or(Cause::Clock(Fault::Overflow))?;
        let result = Self { expires, hard };
        result.check(clock)?;
        Ok(result)
    }
    /// Recheck the same native target after the actual provider sample.
    pub fn check(self, clock: &dyn RuntimeClock) -> Result<(), Cause> {
        if Instant::now() >= self.hard {
            return Err(Cause::Clock(Fault::Deadline));
        }
        let now = clock.sample().map_err(Cause::Clock)?.now.as_micros();
        if Instant::now() >= self.hard || now >= self.expires {
            return Err(Cause::Clock(Fault::Deadline));
        }
        Ok(())
    }
}
/// Original provider/native refusal; no stringification of an IO/clock cause.
#[derive(Debug)]
pub enum Cause {
    /// Actual signal, native process or reactor error.
    Io(io::Error),
    /// Actual original clock/deadline/resource refusal.
    Clock(Fault),
}
impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => e.fmt(f),
            Self::Clock(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Cause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Io(e) => e,
            Self::Clock(e) => e,
        })
    }
}
impl From<io::Error> for Cause {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
/// First original stop intent. It never proves the child exited.
#[derive(Clone, Copy, Debug)]
pub enum Stop {
    /// Actual original signal.
    Signal(i32),
    /// Selected diagnostic failure.
    Diagnostic,
    /// Original parent/signal port failure.
    Control,
    /// Original whole target expired.
    Deadline,
    /// Actual clock failure.
    Clock,
    /// Explicit local cancellation.
    Cancel,
}
/// Actual child facts, without URI payloads or a fabricated handler ACK.
#[derive(Clone, Debug, Default)]
pub struct Report {
    /// A real command.spawn succeeded.
    pub spawned: bool,
    /// Real consuming original wait result, if observed.
    pub status: Option<ExitStatus>,
    /// First original stop intent.
    pub stop: Option<Stop>,
    /// A TERM syscall was actually attempted.
    pub term_attempted: bool,
    /// A KILL syscall was actually attempted.
    pub kill_attempted: bool,
    /// Original child still lacks a consuming exit observation.
    pub undrained: bool,
}
impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "spawned={} status={:?} stop={:?} TERM-attempted={} KILL-attempted={} undrained={}",
            self.spawned,
            self.status,
            self.stop,
            self.term_attempted,
            self.kill_attempted,
            self.undrained
        )
    }
}
/// Original business error and independent actual child-retirement errors.
#[derive(Debug)]
pub struct DispatchFailure {
    /// First actual cancellation/provider/native error.
    pub original: Option<Cause>,
    /// Independent actual TERM error.
    pub terminate: Option<io::Error>,
    /// Independent actual KILL error.
    pub kill: Option<io::Error>,
    /// Independent actual wait error.
    pub wait: Option<io::Error>,
    /// Original child observations; no ACK inferred from exit0.
    pub report: Report,
}
impl fmt::Display for DispatchFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "URI handler {}; original={:?}; TERM={:?}; KILL={:?}; wait={:?}",
            self.report, self.original, self.terminate, self.kill, self.wait
        )
    }
}
impl std::error::Error for DispatchFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.as_ref().map(|e| e as _).or_else(|| {
            self.terminate
                .as_ref()
                .or(self.kill.as_ref())
                .or(self.wait.as_ref())
                .map(|e| e as _)
        })
    }
}
/// Independent clock-free final close observation, not an inferred reap.
#[derive(Debug)]
pub struct CloseReport {
    /// Actual observations after this retirement attempt.
    pub report: Report,
    /// Exact independent KILL error, if any.
    pub kill: Option<io::Error>,
    /// Exact independent consuming-wait error, if any.
    pub wait: Option<io::Error>,
}
/// Explicit original child owner. Retain it across canceled drive futures and
/// call close before dropping when independent cleanup observations are needed.
#[must_use = "retain the original dispatcher and independently inspect its final close report"]
pub struct Dispatcher {
    signals: Signals,
    reporter: Reporter,
    clock: Arc<dyn RuntimeClock>,
    bounds: Option<Bounds>,
    canonical: Option<Pin<Box<Deadline>>>,
    business_alarm: Option<Pin<Box<tokio::time::Sleep>>>,
    timer: Pin<Box<tokio::time::Sleep>>,
    settings: Option<Settings>,
    child: Option<Child>,
    report: Report,
    original: Option<Cause>,
    terminate: Option<io::Error>,
    kill: Option<io::Error>,
    wait: Option<io::Error>,
    stop_hard: Option<Instant>,
    reap_hard: Option<Instant>,
    grace: Duration,
    started: bool,
    finished: bool,
    authority: bool,
}
impl Dispatcher {
    /// Own one selected signal/parent/logger/clock context before image work.
    /// No handler, image provider or worker is started here.
    pub fn new(
        parent: Option<ParentControl>,
        reporter: Reporter,
        clock: Arc<dyn RuntimeClock>,
        bounds: Option<Bounds>,
    ) -> Result<Self, Cause> {
        let signals = Signals::new(parent)?;
        let canonical = bounds
            .map(|b| {
                Deadline::at(
                    clock.clone(),
                    gnunet_types::AbsoluteTime::from_micros(b.expires),
                )
                .map(Box::pin)
            })
            .transpose()
            .map_err(Cause::Clock)?;
        let business_alarm = bounds.map(|b| Box::pin(tokio::time::sleep_until(b.hard.into())));
        Ok(Self {
            signals,
            reporter,
            clock,
            bounds,
            canonical,
            business_alarm,
            timer: Box::pin(tokio::time::sleep(Duration::from_millis(100))),
            settings: None,
            child: None,
            report: Report::default(),
            original: None,
            terminate: None,
            kill: None,
            wait: None,
            stop_hard: None,
            reap_hard: None,
            grace: Duration::from_secs(5),
            started: false,
            finished: false,
            authority: true,
        })
    }
    fn ordinary(&mut self, cx: &mut Context<'_>) -> Result<(), (Stop, Cause)> {
        self.reporter.register(cx);
        if self.reporter.failed() {
            return Err((
                Stop::Diagnostic,
                Cause::Io(io::Error::other("selected URI/QR Logger failed")),
            ));
        }
        match self.signals.poll(cx) {
            Poll::Ready(Ok(Wake::Stop(value))) => {
                return Err((
                    Stop::Signal(value),
                    Cause::Io(io::Error::new(
                        io::ErrorKind::Interrupted,
                        "original URI/QR signal canceled the operation",
                    )),
                ));
            }
            Poll::Ready(Err(e)) => return Err((Stop::Control, Cause::Io(e))),
            Poll::Ready(Ok(Wake::Child)) => cx.waker().wake_by_ref(),
            Poll::Pending => {}
        }
        if let Some(b) = self.bounds
            && let Err(e) = b.check(self.clock.as_ref())
        {
            let why = if matches!(&e, Cause::Clock(Fault::Deadline)) {
                Stop::Deadline
            } else {
                Stop::Clock
            };
            return Err((why, e));
        }
        if self
            .business_alarm
            .as_mut()
            .is_some_and(|a| a.as_mut().poll(cx).is_ready())
        {
            return Err((Stop::Deadline, Cause::Clock(Fault::Deadline)));
        }
        if let Some(alarm) = &mut self.canonical {
            match alarm.as_mut().poll(cx) {
                Poll::Ready(Ok(())) => return Err((Stop::Deadline, Cause::Clock(Fault::Deadline))),
                Poll::Ready(Err(e)) => return Err((Stop::Clock, Cause::Clock(e))),
                Poll::Pending => {}
            }
        }
        if self.bounds.is_some_and(|b| Instant::now() >= b.hard) {
            return Err((Stop::Deadline, Cause::Clock(Fault::Deadline)));
        }
        Ok(())
    }
    fn stop(&mut self, why: Stop, cause: Cause) {
        self.original.get_or_insert(cause);
        if self.report.stop.is_none() {
            self.report.stop = Some(why);
            self.stop_hard = Instant::now().checked_add(self.grace);
            if self.stop_hard.is_none() {
                self.kill
                    .get_or_insert_with(|| io::Error::other("original URI stop target overflow"));
            }
        }
    }
    /// Check actual original signals/logger/whole target before new scanner work.
    /// A consumed cancellation remains fixed and cannot be cleared by another poll.
    pub fn guard(&mut self, cx: &mut Context<'_>) -> Result<(), Cause> {
        if self.report.stop.is_some() || self.finished {
            return Err(Cause::Clock(Fault::Cancelled));
        }
        match self.ordinary(cx) {
            Ok(()) => Ok(()),
            Err((why, cause)) => {
                self.report.stop = Some(why);
                Err(cause)
            }
        }
    }
    /// Stage one selected dispatch. This is admission, not an actual child spawn.
    pub fn start(&mut self, settings: Settings) -> Result<(), Cause> {
        if self.started || self.finished || self.report.stop.is_some() {
            return Err(Cause::Clock(Fault::Conflict));
        }
        self.grace = settings.grace;
        self.settings = Some(settings);
        self.started = true;
        Ok(())
    }
    /// Current original physical facts without consuming a native child result.
    #[must_use]
    pub fn report(&self) -> &Report {
        &self.report
    }
    /// Fix one original cancellation intent without a clock/provider sample.
    pub fn cancel(&mut self) {
        self.stop(Stop::Cancel, Cause::Clock(Fault::Cancelled));
    }
    fn terminal(&mut self) -> Poll<Result<Report, DispatchFailure>> {
        self.finished = true;
        self.report.undrained = self.child.is_some() && self.report.status.is_none();
        if self.original.is_some()
            || self.terminate.is_some()
            || self.kill.is_some()
            || self.wait.is_some()
            || self.report.stop.is_some()
            || !self.report.status.is_some_and(|s| s.success())
        {
            Poll::Ready(Err(DispatchFailure {
                original: self.original.take(),
                terminate: self.terminate.take(),
                kill: self.kill.take(),
                wait: self.wait.take(),
                report: self.report.clone(),
            }))
        } else {
            Poll::Ready(Ok(self.report.clone()))
        }
    }
    /// Poll the same original staged handler/child. Byte/clock/signal activity does
    /// not restart its target, and a dropped waiter does not spawn another child.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Report, DispatchFailure>> {
        if self.finished || !self.started {
            return Poll::Pending;
        }
        if self.child.is_none() && self.report.status.is_none() {
            if self.report.stop.is_some() {
                self.original.get_or_insert(Cause::Clock(Fault::Cancelled));
                self.settings = None;
                return self.terminal();
            }
            if let Err((why, cause)) = self.ordinary(cx) {
                self.stop(why, cause);
                self.settings = None;
                return self.terminal();
            }
            let Some(settings) = self.settings.take() else {
                self.original = Some(Cause::Clock(Fault::NotReady));
                return self.terminal();
            };
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
            for key in [
                "GNUNET_OS_CONTROL_PIPE",
                "LISTEN_PID",
                "LISTEN_FDS",
                "LISTEN_FDNAMES",
            ] {
                command.env_remove(key);
            }
            if let Err((why, cause)) = self.ordinary(cx) {
                self.stop(why, cause);
                return self.terminal();
            }
            match command.spawn() {
                Ok(child) => {
                    self.child = Some(child);
                    self.report.spawned = true;
                }
                Err(e) => {
                    self.original = Some(Cause::Io(e));
                    return self.terminal();
                }
            }
        }
        let observation = self.child.as_mut().map(Child::try_wait);
        match observation {
            Some(Ok(Some(status))) => {
                self.report.status = Some(status);
                self.child = None;
                // Preserve the consuming wait fact before the original whole
                // target/provider is checked. Late observation is not timely
                // completion, even when the real child happened to exit zero.
                if self.report.stop.is_none()
                    && let Err((why, cause)) = self.ordinary(cx)
                {
                    self.stop(why, cause);
                }
                return self.terminal();
            }
            Some(Ok(None)) => {}
            Some(Err(e)) if e.kind() == io::ErrorKind::Interrupted => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            Some(Err(e)) => {
                self.authority = false;
                self.wait = Some(e);
                return self.terminal();
            }
            None => return self.terminal(),
        }
        if self.report.stop.is_none() {
            if let Err((why, cause)) = self.ordinary(cx) {
                self.stop(why, cause);
            }
        } else {
            match self.signals.poll(cx) {
                Poll::Ready(Ok(Wake::Stop(_))) => self.stop_hard = Some(Instant::now()),
                Poll::Ready(Err(e)) => {
                    self.original.get_or_insert(Cause::Io(e));
                }
                Poll::Ready(Ok(Wake::Child)) => cx.waker().wake_by_ref(),
                Poll::Pending => {}
            }
        }
        if self.report.stop.is_some() && !self.report.term_attempted {
            self.report.term_attempted = true;
            if let Some(child) = &self.child {
                let result = i32::try_from(child.id())
                    .map_err(|_| io::Error::other("original PID exceeds native range"))
                    .and_then(|pid| {
                        kill(Pid::from_raw(pid), Signal::SIGTERM).map_err(io::Error::from)
                    });
                if let Err(e) = result {
                    self.terminate = Some(e);
                }
            }
        }
        if self.report.stop.is_some() && self.stop_hard.is_none_or(|at| Instant::now() >= at) {
            if !self.report.kill_attempted {
                self.report.kill_attempted = true;
                // A separate fixed cleanup-only grace observes the original
                // consuming wait after KILL; it grants no new business time.
                self.reap_hard = Instant::now().checked_add(self.grace);
                if let Some(child) = &mut self.child {
                    if let Err(e) = child.kill() {
                        self.kill = Some(e);
                    }
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            self.report.status = Some(status);
                            self.child = None;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            if e.kind() != io::ErrorKind::Interrupted {
                                self.authority = false;
                            }
                            self.wait = Some(e);
                        }
                    }
                }
            }
            if self.child.is_none()
                || !self.authority
                || self.reap_hard.is_none_or(|at| Instant::now() >= at)
            {
                return self.terminal();
            }
        }
        let now = Instant::now();
        let Some(mut next) = now.checked_add(Duration::from_millis(100)) else {
            self.stop(Stop::Control, Cause::Clock(Fault::Overflow));
            cx.waker().wake_by_ref();
            return Poll::Pending;
        };
        if let Some(hard) = if self.report.kill_attempted {
            self.reap_hard
        } else {
            self.stop_hard
        } {
            next = next.min(hard);
        }
        self.timer.as_mut().reset(next.into());
        if self.timer.as_mut().poll(cx).is_ready() {
            cx.waker().wake_by_ref();
        }
        Poll::Pending
    }
    /// Observe this same retained operation; canceling the future retains owner.
    pub async fn drive(&mut self) -> Result<Report, DispatchFailure> {
        poll_fn(|cx| self.poll(cx)).await
    }
    /// Clock-free final retirement of the original child. A KILL success is not
    /// called reaped; any still-owned wait debt remains explicit in this report.
    pub fn close(&mut self) -> CloseReport {
        self.settings = None;
        let mut kill_error = None;
        let mut wait_error = None;
        if self.child.is_some() {
            self.report.stop.get_or_insert(Stop::Cancel);
            if self.authority {
                let observed = self.child.as_mut().map(Child::try_wait);
                let live = match observed {
                    Some(Ok(Some(status))) => {
                        self.report.status = Some(status);
                        self.child = None;
                        false
                    }
                    Some(Ok(None)) => true,
                    Some(Err(e)) => {
                        // EINTR does not transfer/revoke original wait ownership,
                        // but also does not provide a fresh still-running fact.
                        if e.kind() != io::ErrorKind::Interrupted {
                            self.authority = false;
                        }
                        wait_error = Some(e);
                        false
                    }
                    None => false,
                };
                if live
                    && self.authority
                    && let Some(child) = &mut self.child
                {
                    self.report.kill_attempted = true;
                    if let Err(e) = child.kill() {
                        kill_error = Some(e);
                    }
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            self.report.status = Some(status);
                            self.child = None;
                        }
                        Ok(None) => {}
                        Err(e) => {
                            if e.kind() != io::ErrorKind::Interrupted {
                                self.authority = false;
                            }
                            wait_error = Some(e);
                        }
                    }
                }
            }
        }
        self.finished = true;
        self.report.undrained = self.child.is_some() && self.report.status.is_none();
        CloseReport {
            report: self.report.clone(),
            kill: kill_error,
            wait: wait_error,
        }
    }
}
impl Drop for Dispatcher {
    fn drop(&mut self) {
        let _actual = self.close();
    }
}
