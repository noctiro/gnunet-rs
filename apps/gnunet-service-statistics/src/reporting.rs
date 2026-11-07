//! One explicit selected Logger and first diagnostic failure, no global fd2.
use crate::Failure;
use gnunet::ipc::server::{CloseReason, ServiceEvent};
use gnunet_program_host::{logging::Logger, policy::Level, service, shared_clock::SharedClock};
use gnunet_service_runtime::accepted::SocketEvent;
use std::{
    cell::RefCell,
    fmt, io,
    task::{Context, Waker},
};
pub(crate) struct Reports<'route, 'log> {
    logger: RefCell<&'route mut Logger<'log>>,
    clock: &'route SharedClock,
    failure: RefCell<Option<io::Error>>,
    waker: RefCell<Option<Waker>>,
}
impl<'route, 'log> Reports<'route, 'log> {
    pub(crate) fn new(logger: &'route mut Logger<'log>, clock: &'route SharedClock) -> Self {
        Self {
            logger: RefCell::new(logger),
            clock,
            failure: RefCell::new(None),
            waker: RefCell::new(None),
        }
    }
    pub(crate) fn register(&self, cx: &Context<'_>) {
        let mut current = self.waker.borrow_mut();
        if current
            .as_ref()
            .is_none_or(|old| !old.will_wake(cx.waker()))
        {
            *current = Some(cx.waker().clone());
        }
    }
    pub(crate) fn failed(&self) -> bool {
        self.failure.borrow().is_some()
    }
    pub(crate) fn take_failure(&self) -> Option<io::Error> {
        self.failure.borrow_mut().take()
    }
    /// Only before native admission. Retain the real IO error and abort
    /// startup; the running service leaves it latched through source retirement
    /// and the actual shutdown snapshot save.
    pub(crate) fn startup_check(&self) -> Result<(), Failure> {
        match self.take_failure() {
            Some(error) => Err(Box::new(error)),
            None => Ok(()),
        }
    }
    pub(crate) fn message(&self, level: Level, site: &'static str, message: fmt::Arguments<'_>) {
        if self.failed() {
            return;
        }
        let actual = self
            .logger
            .try_borrow_mut()
            .map_err(|_| io::Error::other("STATISTICS selected Logger already borrowed"))
            .and_then(|mut logger| {
                service::diagnostic(&mut logger, self.clock, site, level, message)
            });
        if let Err(error) = actual {
            *self.failure.borrow_mut() = Some(error);
            if let Some(waker) = self.waker.borrow().as_ref() {
                waker.wake_by_ref();
            }
        }
    }
    pub(crate) fn warning(&self, site: &'static str, message: fmt::Arguments<'_>) {
        self.message(Level::WARNING, site, message);
    }
    pub(crate) fn observe(&self, event: ServiceEvent) {
        match event {
            ServiceEvent::Socket(SocketEvent::Failed(error)) if error.is_emfile() => {}
            ServiceEvent::Socket(SocketEvent::Failed(error)) => self.warning(
                "statistics.socket.failed",
                format_args!("statistics socket: {error}"),
            ),
            ServiceEvent::Socket(event) => self.message(
                Level::DEBUG,
                "statistics.socket.activity",
                format_args!("statistics socket: {event:?}"),
            ),
            ServiceEvent::Closed(closed) => {
                let level = if matches!(&closed.reason, CloseReason::Failure(_)) {
                    Level::WARNING
                } else {
                    Level::DEBUG
                };
                self.message(
                    level,
                    "statistics.source.closed",
                    format_args!("statistics original source client={:?} cause={:?}",
                        closed.client, closed.reason),
                );
            }
            ServiceEvent::ForcedShutdown => self.warning(
                "statistics.shutdown.forced",
                format_args!("statistics original soft-stop grace expired; remaining sources physically closed"),
            ),
        }
    }
}
