//! Original Resolver cleanup, including rejected or canceled PROGRAM tasks.
use super::diagnostic;
use gnunet_program_host::reporting::Reporter;
use gnunet_resolver_broker::{BrokerError, Driver};
use std::{cell::RefCell, rc::Rc};
pub(super) struct Resolver {
    pub driver: Driver<64, 1024>,
    deferred: Rc<RefCell<Option<BrokerError>>>,
    done: bool,
}
impl Resolver {
    pub fn new(driver: Driver<64, 1024>, deferred: Rc<RefCell<Option<BrokerError>>>) -> Self {
        Self {
            driver,
            deferred,
            done: false,
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
            *self.deferred.borrow_mut() = Some(error);
        }
    }
}

pub(super) async fn drive(
    resolver: &mut Driver<64, 1024>,
    reports: &Reporter,
) -> Result<(), gnunet_resolver_broker::BrokerError> {
    loop {
        resolver
            .drive_waiting(None, |e| {
                diagnostic(reports, format_args!("NAT CLI Resolver: {e:?}"))
            })
            .await?;
    }
}
