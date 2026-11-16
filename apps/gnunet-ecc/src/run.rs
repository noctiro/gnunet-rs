use crate::{
    Failure, keys,
    options::{Operation, Settings},
};
use gnunet_program_host::reporting::Reporter;
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_service_startup::{ParentControl, StopSignals};
use gnunet_types::AbsoluteTime;
use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::Instant;

#[derive(Debug)]
enum StopCause {
    Requested,
    Deadline,
    Attempts,
    Clock(gnunet_types::Error),
    Logging,
}
impl fmt::Display for StopCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Requested => f.write_str("ECC operation stopped"),
            Self::Deadline => f.write_str("ECC operation deadline reached"),
            Self::Attempts => f.write_str("ECC candidate limit reached"),
            Self::Clock(error) => write!(f, "ECC operation clock failed: {error}"),
            Self::Logging => f.write_str("ECC operation logger failed"),
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
    pub records_read: u64,
    pub keys_generated: u64,
    pub attempts: u64,
    pub stdout_bytes: u128,
    pub stderr_bytes: u128,
    pub staged_bytes: u64,
    pub published: bool,
    pub replaced: bool,
    pub publication_attempted: bool,
    pub directory_sync: Option<gnunet_native::DirectorySync>,
    pub retained_staging: Option<PathBuf>,
}
#[derive(Debug)]
struct Failed {
    original: Option<Failure>,
    cleanup: Option<Failure>,
    facts: Facts,
}
impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ECC original={:?}; independent cleanup={:?}; actual facts={:?}",
            self.original, self.cleanup, self.facts
        )
    }
}
impl std::error::Error for Failed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.as_deref().or(self.cleanup.as_deref())
    }
}
pub(super) struct Guard {
    clock: Arc<dyn RuntimeClock>,
    reporter: Reporter,
    stops: StopSignals,
    expires: Option<AbsoluteTime>,
    hard: Option<Instant>,
    deadline: Option<Deadline>,
    last: AbsoluteTime,
    max_attempts: Option<u64>,
    work_units: usize,
    steps: usize,
}
impl Guard {
    fn new(
        settings: &Settings,
        clock: Arc<dyn RuntimeClock>,
        reporter: Reporter,
        parent: Option<ParentControl>,
    ) -> Result<Self, Failure> {
        // Capture native origin before the fallible canonical provider. Neither
        // a later yield, retry, file record nor vanity attempt renews this pair.
        let native_origin = Instant::now();
        let origin = clock.sample()?.now;
        let expires = settings
            .lifetime
            .map(|d| {
                let delta =
                    u64::try_from(d.as_micros()).map_err(|_| "ECC whole target overflow")?;
                origin
                    .as_micros()
                    .checked_add(delta)
                    .map(AbsoluteTime::from_micros)
                    .ok_or("ECC whole target overflow")
            })
            .transpose()?;
        let hard = settings
            .lifetime
            .map(|d| {
                native_origin
                    .checked_add(d)
                    .ok_or("ECC whole native target overflow")
            })
            .transpose()?;
        let deadline = expires
            .map(|at| Deadline::at(clock.clone(), at))
            .transpose()?;
        Ok(Self {
            clock,
            reporter,
            stops: StopSignals::for_client(parent)?,
            expires,
            hard,
            deadline,
            last: origin,
            max_attempts: settings.max_attempts,
            work_units: settings.work_units,
            steps: 0,
        })
    }
    fn signals(&mut self, cx: &mut Context<'_>) -> Result<(), Failure> {
        match self.stops.poll_stop(cx) {
            Poll::Ready(Ok(())) => Err(Box::new(StopCause::Requested)),
            Poll::Ready(Err(error)) => Err(error.into()),
            Poll::Pending => Ok(()),
        }
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
        poll_fn(|cx| Poll::Ready(self.poll_check(cx))).await
    }
    pub async fn turn(&mut self) -> Result<(), Failure> {
        self.steps += 1;
        if self.steps >= self.work_units {
            self.steps = 0;
            tokio::task::yield_now().await;
        }
        self.check().await
    }
    pub async fn candidate(
        &mut self,
        facts: &mut Facts,
    ) -> Result<zeroize::Zeroizing<[u8; 32]>, Failure> {
        self.check().await?;
        if self.max_attempts.is_some_and(|max| facts.attempts >= max) {
            return Err(Box::new(StopCause::Attempts));
        }
        let next = facts
            .attempts
            .checked_add(1)
            .ok_or("ECC candidate count overflow")?;
        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        getrandom::fill(seed.as_mut())?;
        facts.attempts = next;
        self.check().await?;
        Ok(seed)
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
    let mut staging = None;
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let mut result: Result<(), Failure> = async {
        guard.check().await?;
        match settings.operation {
            Operation::Examples => keys::examples(&mut guard, &mut stdout, &mut facts).await,
            Operation::Iterate { path, maximum } => {
                keys::inspect(
                    &path,
                    Some(maximum),
                    None,
                    &mut guard,
                    &mut stdout,
                    &mut stderr,
                    &mut facts,
                )
                .await
            }
            Operation::Print { path, form } => {
                keys::inspect(
                    &path,
                    None,
                    Some(form),
                    &mut guard,
                    &mut stdout,
                    &mut stderr,
                    &mut facts,
                )
                .await
            }
            Operation::Generate {
                path,
                count,
                vanity,
            } => {
                keys::generate(
                    &path,
                    count,
                    vanity.as_ref(),
                    &mut staging,
                    &mut guard,
                    &mut stderr,
                    &mut facts,
                )
                .await
            }
        }?;
        guard.check().await
    }
    .await;
    // Cleanup cannot be suppressed by the cancellation/deadline which caused it.
    // Only this original private sibling is removed, never the published target.
    let cleanup = staging
        .as_mut()
        .and_then(|s: &mut keys::Staging| s.cleanup().err());
    facts.retained_staging = staging.as_ref().and_then(keys::Staging::retained_path);
    if result.is_ok() && cleanup.is_none() {
        result = guard.check().await;
    }
    if result.is_err() || cleanup.is_some() {
        return Err(Box::new(Failed {
            original: result.err(),
            cleanup,
            facts,
        }));
    }
    reporter.debug(
        "ecc.command.complete",
        format_args!("actual public counters/commit observations: {facts:?}"),
    );
    Ok(())
}
