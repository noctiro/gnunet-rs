use crate::{Failure, input, options::Settings};
use gnunet_program_host::{policy::Level, reporting::Reporter};
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_service_startup::{ControlReceiver, ParentControl};
use gnunet_types::AbsoluteTime;
use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    signal::unix::{Signal, SignalKind, signal},
    time::Instant,
};
#[derive(Debug)]
enum StopCause {
    Signal(i32),
    Deadline,
    Clock(gnunet_types::Error),
    Logging,
}
impl fmt::Display for StopCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signal(s) => write!(f, "original directory inspection cancelled by signal {s}"),
            Self::Deadline => f.write_str("original directory inspection deadline reached"),
            Self::Clock(e) => write!(f, "original directory inspection Clock failed: {e}"),
            Self::Logging => f.write_str("selected directory Logger failed"),
        }
    }
}
impl std::error::Error for StopCause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Clock(e) => Some(e),
            _ => None,
        }
    }
}
#[derive(Debug, Default)]
pub(super) struct Facts {
    pub files_opened: u128,
    pub files_complete: u128,
    pub files_validated: u128,
    pub files_failed: u128,
    pub bytes_read: u128,
    pub bytes_parsed: u128,
    pub metadata_items: u128,
    pub entries: u128,
    pub stdout_bytes: u128,
}
#[derive(Debug)]
struct Failed {
    first: Option<Failure>,
    terminal: Option<Failure>,
    output: Option<Failure>,
    facts: Facts,
}
impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "directory first={:?}; terminal={:?}; independent stdout={:?}; actual observations={:?}",
            self.first, self.terminal, self.output, self.facts
        )
    }
}
impl std::error::Error for Failed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.first
            .as_deref()
            .or(self.terminal.as_deref())
            .or(self.output.as_deref())
    }
}
pub(super) struct Guard {
    clock: Arc<dyn RuntimeClock>,
    reporter: Reporter,
    parent: Option<ControlReceiver>,
    interrupt: Signal,
    terminate: Signal,
    expires: Option<AbsoluteTime>,
    hard: Option<Instant>,
    deadline: Option<Deadline>,
    last: AbsoluteTime,
    work_units: usize,
    steps: usize,
    pub failed: bool,
    pub output_failed: bool,
}
impl Guard {
    fn new(
        settings: &Settings,
        clock: Arc<dyn RuntimeClock>,
        reporter: Reporter,
        parent: Option<ParentControl>,
    ) -> Result<Self, Failure> {
        // Capture native origin before the fallible canonical provider. Neither
        // a later yield, file, record nor metadata event renews this pair.
        let native_origin = Instant::now();
        let origin = clock.sample()?.now;
        let expires = settings
            .lifetime
            .map(|d| {
                let delta =
                    u64::try_from(d.as_micros()).map_err(|_| "directory whole target overflow")?;
                origin
                    .as_micros()
                    .checked_add(delta)
                    .map(AbsoluteTime::from_micros)
                    .ok_or("directory whole target overflow")
            })
            .transpose()?;
        let hard = settings
            .lifetime
            .map(|d| {
                native_origin
                    .checked_add(d)
                    .ok_or("directory whole native target overflow")
            })
            .transpose()?;
        let deadline = expires
            .map(|at| Deadline::at(clock.clone(), at))
            .transpose()?;
        Ok(Self {
            clock,
            reporter,
            parent: parent
                .map(|p| p.register().map_err(|f| f.error))
                .transpose()?,
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
            expires,
            hard,
            deadline,
            last: origin,
            work_units: 32,
            steps: 0,
            failed: false,
            output_failed: false,
        })
    }
    fn signals(&mut self, cx: &mut Context<'_>) -> Result<(), Failure> {
        if let Some(parent) = &mut self.parent {
            match parent.poll_signal(cx) {
                Poll::Ready(Ok(Some(value)))
                    if value == libc::SIGINT as i8 || value == libc::SIGTERM as i8 =>
                {
                    return Err(Box::new(StopCause::Signal(i32::from(value))));
                }
                Poll::Ready(Ok(Some(_))) => cx.waker().wake_by_ref(),
                Poll::Ready(Ok(None)) => self.parent = None,
                Poll::Ready(Err(e)) => return Err(e.into()),
                Poll::Pending => {}
            }
        }
        for (stream, code) in [
            (&mut self.interrupt, libc::SIGINT),
            (&mut self.terminate, libc::SIGTERM),
        ] {
            match stream.poll_recv(cx) {
                Poll::Ready(Some(())) => return Err(Box::new(StopCause::Signal(code))),
                Poll::Ready(None) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "original directory termination stream ended",
                    )
                    .into());
                }
                Poll::Pending => {}
            }
        }
        Ok(())
    }
    fn poll_check(&mut self, cx: &mut Context<'_>) -> Result<(), Failure> {
        self.reporter.register(cx);
        self.signals(cx)?;
        if self.reporter.failed() {
            return Err(Box::new(StopCause::Logging));
        }
        if self.hard.is_some_and(|at| Instant::now() >= at) {
            return Err(Box::new(StopCause::Deadline));
        }
        let now = self.clock.sample().map_err(StopCause::Clock)?.now;
        if now < self.last {
            return Err(Box::new(StopCause::Clock(
                gnunet_types::Error::TimeUncertain,
            )));
        }
        self.last = now;
        if self.expires.is_some_and(|at| now >= at)
            || self.hard.is_some_and(|at| Instant::now() >= at)
        {
            return Err(Box::new(StopCause::Deadline));
        }
        if let Some(deadline) = &mut self.deadline {
            match Pin::new(deadline).poll(cx) {
                Poll::Ready(Ok(())) => return Err(Box::new(StopCause::Deadline)),
                Poll::Ready(Err(e)) => return Err(Box::new(StopCause::Clock(e))),
                Poll::Pending => {}
            }
        }
        self.signals(cx)?;
        if self.hard.is_some_and(|at| Instant::now() >= at) {
            return Err(Box::new(StopCause::Deadline));
        }
        Ok(())
    }
    pub async fn check(&mut self) -> Result<(), Failure> {
        let answer = poll_fn(|cx| Poll::Ready(self.poll_check(cx))).await;
        if answer.is_err() {
            self.failed = true;
        }
        answer
    }
    pub async fn turn(&mut self) -> Result<(), Failure> {
        self.steps += 1;
        if self.steps >= self.work_units {
            self.steps = 0;
            tokio::task::yield_now().await;
        }
        self.check().await
    }
}

pub(super) async fn run(
    settings: Settings,
    clock: Arc<dyn RuntimeClock>,
    reporter: Reporter,
    parent: Option<ParentControl>,
) -> Result<(), Failure> {
    let mut guard = Guard::new(&settings, clock, reporter.clone(), parent)?;
    let mut facts = Facts::default();
    let mut first = None;
    let mut terminal = None;
    let mut output = None;
    let mut stdout = io::stdout().lock();
    // Reuse arenas across selected files. Carry is grown only after a real
    // input opens; plain scratch grows only on an actual NeedPlain request.
    let mut carry = Vec::new();
    let mut plain = Vec::new();
    for path in &settings.files {
        if let Err(e) = guard.check().await {
            terminal = Some(e);
            break;
        }
        match input::inspect(
            path,
            settings.limits,
            &mut carry,
            &mut plain,
            &mut guard,
            &mut stdout,
            &mut facts,
        )
        .await
        {
            Ok(()) => facts.files_complete += 1,
            Err(e) => {
                facts.files_failed += 1;
                reporter.message(Level::ERROR, "directory.file.failed", format_args!("{e}"));
                if first.is_none() {
                    first = Some(e);
                }
                if guard.failed || guard.output_failed || reporter.failed() {
                    break;
                }
            }
        }
        if let Err(e) = guard.turn().await {
            terminal = Some(e);
            break;
        }
    }
    if !guard.output_failed {
        use std::io::Write;
        if let Err(e) = stdout.flush() {
            guard.output_failed = true;
            output = Some(e.into());
        }
    }
    if terminal.is_none()
        && let Err(e) = guard.check().await
    {
        terminal = Some(e);
    }
    if first.is_some() || terminal.is_some() || output.is_some() {
        return Err(Box::new(Failed {
            first,
            terminal,
            output,
            facts,
        }));
    }
    reporter.debug(
        "directory.command.complete",
        format_args!("syntax-only file observations: {facts:?}"),
    );
    Ok(())
}
