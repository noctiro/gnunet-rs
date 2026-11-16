//! Original Resolver retirement and deferred facts from canceled command tasks.
use gnunet_program_host::reporting::Reporter;
use gnunet_resolver_broker::{BrokerError, Driver};
use std::{cell::RefCell, error::Error, fmt, rc::Rc};
type Failure = Box<dyn Error>;
/// Bytes accepted by stdio whose original explicit flush never completed successfully.
#[derive(Debug)]
pub(crate) struct OutputAbandoned {
    pub accepted: usize,
}
impl fmt::Display for OutputAbandoned {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "public output retired with {} stdio-accepted bytes and no successful explicit flush",
            self.accepted
        )
    }
}
impl Error for OutputAbandoned {}
#[derive(Default)]
pub(crate) struct Deferred {
    pub client: Option<Failure>,
    pub resolver: Option<Failure>,
    pub output: Option<OutputAbandoned>,
}
/// One bounded slot per original cleanup owner; each owner retires once.
#[derive(Clone, Default)]
pub(crate) struct Cleanup(Rc<RefCell<Deferred>>);
impl Cleanup {
    pub fn client(&self, error: Failure) {
        self.0.borrow_mut().client = Some(error);
    }
    pub fn resolver(&self, error: Failure) {
        self.0.borrow_mut().resolver = Some(error);
    }
    pub fn output(&self, accepted: usize) {
        self.0.borrow_mut().output = Some(OutputAbandoned { accepted });
    }
    pub fn take(&self) -> Deferred {
        std::mem::take(&mut *self.0.borrow_mut())
    }
}
pub(crate) struct Resolver {
    pub driver: Driver<8, 256>,
    pub reports: Reporter,
    cleanup: Cleanup,
    closed: bool,
}
impl Resolver {
    pub fn new(driver: Driver<8, 256>, reports: Reporter, cleanup: Cleanup) -> Self {
        Self {
            driver,
            reports,
            cleanup,
            closed: false,
        }
    }
    pub fn close(&mut self) -> Result<(), BrokerError> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        self.driver.disconnect()
    }
}
impl Drop for Resolver {
    fn drop(&mut self) {
        if let Err(error) = self.close() {
            self.cleanup.resolver(Box::new(error));
        }
    }
}
