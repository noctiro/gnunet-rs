//! Original client, Resolver, stop subscriptions and immutable record budgets.
use super::outcome::{Close, Interrupted, Lost, Meta, Report};
use crate::{Failure, control::Signals};
use gnunet_datastore_host::{self as host, Client, Operation, Request};
use gnunet_program_host::reporting::Reporter;
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_types::{AbsoluteTime, Duration as Timeout, Error};
use std::{
    cell::Cell,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    rc::Rc,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
const LIFETIME: Duration = Duration::from_secs(30);
const CADENCE: Duration = Duration::from_millis(10);
pub(crate) struct Budget {
    until: AbsoluteTime,
    hard: Instant,
    native: Pin<Box<Sleep>>,
    logical: Pin<Box<Deadline>>,
}
impl Budget {
    fn new(source: Arc<dyn RuntimeClock>) -> Result<Self, Failure> {
        let hard = Instant::now()
            .checked_add(LIFETIME)
            .ok_or("native record budget overflow")?;
        let now = source.sample()?.now;
        let until = AbsoluteTime::from_micros(
            now.as_micros()
                .checked_add(u64::try_from(LIFETIME.as_micros())?)
                .filter(|x| *x < u64::MAX)
                .ok_or("logical record budget overflow")?,
        );
        let logical = Box::pin(Deadline::at(source, until)?);
        if Instant::now() >= hard {
            return Err("record preparation exhausted original native budget".into());
        }
        Ok(Self {
            until,
            hard,
            native: Box::pin(tokio::time::sleep_until(hard)),
            logical,
        })
    }
}
pub(crate) struct Driver<'r, 'id, 'slots, 'buffers> {
    pub(super) client: Client<'id, 'slots, 'buffers>,
    pub(super) resolver: &'r mut gnunet_resolver_broker::Driver<4, 256>,
    pub(super) signals: Signals,
    pub(super) source: Arc<dyn RuntimeClock>,
    pub(super) reports: Reporter,
    pub(super) stop: Rc<Cell<bool>>,
    pub(super) pending: Option<Operation<'id>>,
    pub(super) report: Report,
    pub(super) cursor: bool,
    pub(super) closed: bool,
}
impl<'id> Driver<'_, 'id, '_, '_> {
    pub(super) fn budget(&self) -> Result<Budget, Failure> {
        if self.stop.get() || self.reports.failed() || self.closed {
            return Err("original DATASTORE owner stopped before new record intent".into());
        }
        Budget::new(self.source.clone())
    }

    fn guard(&mut self, cx: &mut Context<'_>, budget: &mut Budget) -> Result<(), Failure> {
        // This original native target is polled BEFORE any logical/Resolver path.
        if budget.native.as_mut().poll(cx).is_ready() || Instant::now() >= budget.hard {
            return Err("original DATASTORE record native deadline".into());
        }
        self.reports.register(cx);
        if self.stop.get() || self.reports.failed() {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "original DATASTORE PROGRAM/Logger stopped",
            )
            .into());
        }
        if let Poll::Ready(signal) = self.signals.poll(cx) {
            signal?;
            self.stop.set(true);
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "original DATASTORE signal stop",
            )
            .into());
        }
        if let Poll::Ready(result) = budget.logical.as_mut().poll(cx) {
            result?;
            return Err("original DATASTORE record logical deadline".into());
        }
        let now = self.source.sample()?.now;
        if Instant::now() >= budget.hard || now >= budget.until {
            return Err("original DATASTORE record deadline after clock sample".into());
        }
        Ok(())
    }
    pub(crate) async fn check(&mut self, budget: &mut Budget) -> Result<(), Failure> {
        poll_fn(|cx| Poll::Ready(self.guard(cx, budget))).await
    }
    fn poll_resolver(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Failure>> {
        let reports = self.reports.clone();
        let result = {
            let mut resolving =
                std::pin::pin!(self.resolver.drive_waiting(None, |event| reports.debug(
                    "datastore.resolver",
                    format_args!("DATASTORE Resolver={event:?}")
                )));
            resolving.as_mut().poll(cx)
        };
        result.map(|r| r.map(|_| ()).map_err(|e| Box::new(e) as Failure))
    }
    pub(crate) async fn native<T>(
        &mut self,
        budget: &mut Budget,
        work: impl Future<Output = io::Result<T>>,
    ) -> Result<T, Failure> {
        let mut work = std::pin::pin!(work);
        poll_fn(|cx| {
            self.guard(cx, budget)?;
            if let Poll::Ready(result) = work.as_mut().poll(cx) {
                return Poll::Ready(result.map_err(|error| Box::new(error) as Failure));
            }
            if let Poll::Ready(result) = self.poll_resolver(cx) {
                result?;
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        })
        .await
    }
    pub(crate) async fn pause(&mut self, budget: &mut Budget) -> Result<(), Failure> {
        let target = Instant::now()
            .checked_add(CADENCE)
            .ok_or("stdio readiness cadence overflow")?
            .min(budget.hard);
        let mut timer = Box::pin(tokio::time::sleep_until(target));
        poll_fn(|cx| {
            self.guard(cx, budget)?;
            if timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Ok(()));
            }
            match self.poll_resolver(cx) {
                Poll::Ready(result) => {
                    result?;
                    self.guard(cx, budget)?;
                    Poll::Ready(Ok(()))
                }
                Poll::Pending => Poll::Pending,
            }
        })
        .await
    }
    pub(super) fn close(&mut self) -> Close {
        let native = self.client.close().err();
        self.closed = true;
        let mut result = Close {
            native,
            ..Default::default()
        };
        if let Some(operation) = self.pending.take() {
            match self.client.take(operation) {
                Ok(taken) => {
                    let meta = Meta::from(taken.completion);
                    self.report.last = Some(meta);
                    result.completion = Some(meta);
                }
                Err(error) => result.take = Some(error),
            }
        }
        result
    }
    fn fail(&mut self, original: Failure) -> Failure {
        let client = self.close();
        Box::new(Interrupted {
            original,
            client,
            report: self.report,
        })
    }
    pub(super) async fn operation(
        &mut self,
        request: Request<'_>,
        budget: &mut Budget,
    ) -> Result<host::Taken<'id>, Failure> {
        self.check(budget).await?;
        if self.closed || self.pending.is_some() {
            return Err("original DATASTORE operation owner unavailable".into());
        }
        let now = self.source.sample()?.now;
        if now >= budget.until || Instant::now() >= budget.hard {
            return Err("original deadline before DATASTORE submission".into());
        }
        let remaining = Timeout(
            budget
                .until
                .as_micros()
                .checked_sub(now.as_micros())
                .ok_or("record budget exhausted")?,
        );
        let operation = self.client.submit(request, None, remaining)?;
        self.pending = Some(operation);
        if matches!(request, Request::Put(_)) {
            self.report.submitted = self
                .report
                .submitted
                .checked_add(1)
                .ok_or("PUT admission count overflow; actual original is retained")?;
        }
        let result = poll_fn(|cx| {
            self.guard(cx, budget)?;
            match self.client.take(operation) {
                Ok(taken) => return Poll::Ready(Ok(taken)),
                Err(host::Error::Protocol(Error::NotReady)) => {}
                Err(error) => return Poll::Ready(Err(Box::new(error) as Failure)),
            }
            for offset in 0..2 {
                let resolve = (usize::from(self.cursor) + offset) % 2 == 0;
                if resolve {
                    if let Poll::Ready(result) = self.poll_resolver(cx) {
                        result?;
                        self.guard(cx, budget)?;
                        self.cursor = false;
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                } else {
                    let result = {
                        let mut driving = std::pin::pin!(self.client.drive(Some(budget.hard)));
                        driving.as_mut().poll(cx)
                    };
                    if let Poll::Ready(result) = result {
                        match result? {
                            host::Step::Lost { cause, .. } => {
                                return Poll::Ready(Err(Box::new(Lost(cause)) as Failure));
                            }
                            host::Step::Unavailable(error) => {
                                return Poll::Ready(Err(Box::new(error) as Failure));
                            }
                            host::Step::Closed => {
                                return Poll::Ready(Err("original DATASTORE source closed".into()));
                            }
                            host::Step::Capacity => {
                                return Poll::Ready(Err(Box::new(Error::Capacity) as Failure));
                            }
                            host::Step::ConnectRetry { error, .. } => self.reports.warning(
                                "datastore.connect.retry",
                                format_args!("original unsent DATASTORE connect: {error}"),
                            ),
                            host::Step::Written {
                                bytes, complete, ..
                            } => self.reports.debug(
                                "datastore.write",
                                format_args!(
                                    "original native write bytes={bytes} whole={complete}"
                                ),
                            ),
                            _ => {}
                        }
                        self.cursor = true;
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                }
            }
            Poll::Pending
        })
        .await;
        match result {
            Ok(taken) => {
                self.pending = None;
                self.report.last = Some(Meta::from(taken.completion));
                Ok(taken)
            }
            Err(error) => Err(self.fail(error)),
        }
    }
}
