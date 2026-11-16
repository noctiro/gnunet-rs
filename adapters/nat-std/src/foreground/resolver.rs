//! Original Resolver retirement, including PROGRAM cancellation before polling.
use gnunet_resolver_broker::{BrokerError, Driver};
use std::{cell::RefCell, rc::Rc};

#[derive(Default)]
pub(super) struct Deferred {
    pub resolver: Option<BrokerError>,
    pub report: Option<crate::server::Report>,
}
pub(super) struct Resolver {
    pub driver: Driver<64, 1024>,
    deferred: Rc<RefCell<Deferred>>,
    done: bool,
}
impl Resolver {
    pub fn new(driver: Driver<64, 1024>, deferred: Rc<RefCell<Deferred>>) -> Self {
        Self {
            driver,
            deferred,
            done: false,
        }
    }
    pub fn retain_report(&self, report: crate::server::Report) {
        if report.pending != 0 || report.unresolved != 0 {
            self.deferred.borrow_mut().report = Some(report);
        }
    }
    pub fn close(&mut self) -> Result<(), BrokerError> {
        if self.done {
            return Ok(());
        }
        self.done = true;
        self.driver.disconnect()
    }
}
impl Drop for Resolver {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            self.deferred.borrow_mut().resolver = Some(error);
        }
    }
}
