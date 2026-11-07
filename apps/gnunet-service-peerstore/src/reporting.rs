//! One explicit selected Logger and first diagnostic failure, no global fd2.
use crate::Failure;
use gnunet_peerstore_host::{
    server::{CloseCause, Event},
    worker::Completion,
};
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
    /// Only before worker/native admission. Retain the real IO error and abort
    /// startup; the running service leaves it latched until all original joins.
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
            .map_err(|_| io::Error::other("PEERSTORE selected Logger already borrowed"))
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
    pub(crate) fn observe(&self, event: Event<'_>) {
        match event {
            Event::Socket(SocketEvent::Failed(error)) if error.is_emfile() => {}
            Event::Socket(SocketEvent::Failed(error)) => self.warning(
                "peerstore.socket.failed",
                format_args!("peerstore socket: {error}"),
            ),
            Event::Socket(event) => self.message(
                Level::DEBUG,
                "peerstore.socket.activity",
                format_args!("peerstore socket: {event:?}"),
            ),
            Event::Closed { loss, cause } => {
                let (level, site) = if matches!(&cause, CloseCause::Fault(_)) {
                    (Level::WARNING, "peerstore.source.failed")
                } else {
                    (Level::INFO, "peerstore.source.closed")
                };
                self.message(level,site,format_args!("peerstore source={} pending={:?} exposed={} store={:?} unknown={:?} cause={cause:?}",loss.client.value(),loss.pending,loss.exposed,loss.pending_store,loss.unknown_store));
            }
            Event::AdmissionFailed(error) => self.warning(
                "peerstore.admission",
                format_args!("peerstore admission: {error}"),
            ),
            Event::Storage {
                job,
                client,
                failure: Some(error),
            } => self.warning(
                "peerstore.storage.failed",
                format_args!(
                    "peerstore storage job={} client={:?} actual={error}",
                    job.value(),
                    client.map(|c| c.value())
                ),
            ),
            _ => {}
        }
    }
    pub(crate) fn completion(&self, completion: Completion) {
        self.message(
            Level::DEBUG,
            "peerstore.worker.retired",
            format_args!(
                "peerstore original worker completion retired: job={}",
                completion.job().value()
            ),
        );
    }
}
