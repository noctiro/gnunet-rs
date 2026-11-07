//! One explicit selected logger and one independently retained logging failure.
use super::Failure;
use gnunet_program_host::{logging::Logger, policy::Level, service, shared_clock::SharedClock};
use std::{
    cell::RefCell,
    fmt, io,
    task::{Context, Waker},
};
pub(super) struct Reports<'route, 'log> {
    logger: RefCell<&'route mut Logger<'log>>,
    clock: &'route SharedClock,
    failure: RefCell<Option<io::Error>>,
    waker: RefCell<Option<Waker>>,
}
impl<'route, 'log> Reports<'route, 'log> {
    pub(super) fn new(logger: &'route mut Logger<'log>, clock: &'route SharedClock) -> Self {
        Self {
            logger: RefCell::new(logger),
            clock,
            failure: RefCell::new(None),
            waker: RefCell::new(None),
        }
    }
    pub(super) fn register(&self, cx: &Context<'_>) {
        let mut current = self.waker.borrow_mut();
        if current
            .as_ref()
            .is_none_or(|old| !old.will_wake(cx.waker()))
        {
            *current = Some(cx.waker().clone())
        }
    }
    pub(super) fn failed(&self) -> bool {
        self.failure.borrow().is_some()
    }
    pub(super) fn take_failure(&self) -> Option<io::Error> {
        self.failure.borrow_mut().take()
    }
    pub(super) fn startup_check(&self) -> Result<(), Failure> {
        match self.take_failure() {
            None => Ok(()),
            Some(e) => Err(Box::new(e)),
        }
    }
    pub(super) fn message(&self, level: Level, site: &'static str, message: fmt::Arguments<'_>) {
        if self.failed() {
            return;
        }
        let actual = self
            .logger
            .try_borrow_mut()
            .map_err(|_| io::Error::other("ARM selected Logger already borrowed"))
            .and_then(|mut logger| {
                service::diagnostic(&mut logger, self.clock, site, level, message)
            });
        if let Err(error) = actual {
            *self.failure.borrow_mut() = Some(error);
            if let Some(w) = self.waker.borrow().as_ref() {
                w.wake_by_ref()
            }
        }
    }
    pub(super) fn warning(&self, site: &'static str, message: fmt::Arguments<'_>) {
        self.message(Level::WARNING, site, message)
    }
}
