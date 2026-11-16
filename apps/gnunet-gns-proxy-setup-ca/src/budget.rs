//! One absolute preparation window, shared by crypto/files/process operations.
use crate::Cause;
use gnunet_program_host::{reporting::Reporter, shared_clock::SharedClock};
use gnunet_service_startup::{ParentControl, StopSignals};
use gnunet_types::AbsoluteTime;
use std::{
    cell::{Cell, RefCell},
    io,
    task::Poll,
    time::{Duration, Instant},
};

pub(super) struct Budget {
    clock: SharedClock,
    reporter: Reporter,
    hard: Instant,
    until: AbsoluteTime,
    signals: RefCell<StopSignals>,
    stopped: Cell<bool>,
}
impl Budget {
    pub(super) async fn new(
        clock: SharedClock,
        reporter: Reporter,
        parent: Option<ParentControl>,
    ) -> Result<Self, Cause> {
        let duration = Duration::from_secs(120);
        let hard = Instant::now()
            .checked_add(duration)
            .ok_or("preparation deadline overflow")?;
        let now = clock.sample()?.now;
        let until = now
            .as_micros()
            .checked_add(120_000_000)
            .filter(|value| *value != u64::MAX)
            .ok_or("preparation canonical deadline overflow")?;
        let budget = Self {
            clock,
            reporter,
            hard,
            until: AbsoluteTime::from_micros(until),
            signals: RefCell::new(StopSignals::for_client(parent)?),
            stopped: Cell::new(false),
        };
        budget.check().await?;
        Ok(budget)
    }
    pub(super) async fn check(&self) -> Result<(), Cause> {
        tokio::task::yield_now().await;
        if self.stopped.get() {
            return Err(
                io::Error::new(io::ErrorKind::Interrupted, "CA preparation stopped").into(),
            );
        }
        std::future::poll_fn(|cx| {
            self.reporter.register(cx);
            let result = match self.signals.borrow_mut().poll_stop(cx) {
                Poll::Ready(result) => {
                    self.stopped.set(true);
                    match result {
                        Err(error) => Err(Box::new(error) as Cause),
                        Ok(()) => Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "CA preparation stopped",
                        )
                        .into()),
                    }
                }
                Poll::Pending => Ok(()),
            };
            Poll::Ready(result)
        })
        .await?;
        if Instant::now() >= self.hard {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original CA preparation window expired",
            )
            .into());
        }
        if self.reporter.failed() {
            return Err(io::Error::other("selected CA preparation logger failed").into());
        }
        let now = self.clock.sample()?.now;
        if Instant::now() >= self.hard || now >= self.until {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "original CA preparation window expired",
            )
            .into());
        }
        Ok(())
    }
}
