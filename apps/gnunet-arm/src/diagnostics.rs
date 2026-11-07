//! Actual selected PROGRAM logging over the shared Logger/Reporter and clock.
use crate::options::Options;
use gnunet_program_host::{
    logging::{Environment, Logger, Stamp},
    policy::Level,
    reporting::Reporter,
    service,
    shared_clock::SharedClock,
};
use gnunet_service_runtime::clock::RuntimeClock;
use std::{
    cell::RefCell,
    error::Error,
    io::{self, Write},
    rc::Rc,
    sync::Arc,
};
/// Original application or independently retained logging failure.
pub type Failure = Box<dyn Error>;
/// Actual initial native failures whose source callbacks deliberately leave the
/// CLI business return code unchanged. These observations are not successful IO.
#[derive(Debug, Default)]
pub struct InitialErrors {
    /// Original control constructor failure, before a host owner was returned.
    pub control: Option<gnunet_arm_host::HostError>,
    /// Original independent monitor constructor failure.
    pub monitor: Option<gnunet_arm_host::HostError>,
}
/// One original logging/clock selection. Clones retain the same Logger and
/// permanent failure latch; they never reopen files or manufacture a new source.
#[derive(Clone)]
pub struct Selection {
    reporter: Reporter,
    clock: SharedClock,
    source: Arc<dyn RuntimeClock>,
    cleanup: Rc<RefCell<Option<gnunet_arm_host::HostError>>>,
    initial: Rc<RefCell<InitialErrors>>,
}
impl Selection {
    /// Use the same actual policy/destination operation as PROGRAM preparation.
    /// ARM already owns a byte-preserving complete option parser; its selected
    /// -L/-l are passed unchanged instead of parsing those options a second time.
    /// No process stderr replacement or fallback logger is installed.
    pub fn new(
        options: &Options,
        clock: SharedClock,
        environment: &Environment,
        stderr: &mut impl Write,
    ) -> Result<Self, Failure> {
        let mut logger: Logger<'static> = Logger::new(b"gnunet-arm", std::process::id(), true)?;
        logger.bind_clock(clock.clone());
        let stamp = Stamp::now(clock.offset().map_err(io::Error::other)?)?;
        logger.setup_routed(
            b"gnunet-arm",
            options.log.as_deref(),
            options.logfile.as_deref(),
            environment,
            &stamp,
            stderr,
        )?;
        let source: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
        Ok(Self {
            reporter: Reporter::new(logger, clock.clone()),
            clock,
            source,
            cleanup: Rc::new(RefCell::new(None)),
            initial: Rc::new(RefCell::new(InitialErrors::default())),
        })
    }
    /// Original same-domain selected clock, including explicit testing skew.
    #[must_use]
    pub fn clock(&self) -> &SharedClock {
        &self.clock
    }
    /// Exact shared RuntimeClock identity for original Resolver/control/monitor.
    #[must_use]
    pub fn source(&self) -> Arc<dyn RuntimeClock> {
        self.source.clone()
    }
    /// Original selected diagnostic owner, never a replacement output stream.
    #[must_use]
    pub fn reporter(&self) -> &Reporter {
        &self.reporter
    }
    /// Exact native warning bytes, including their existing newline. No UTF8,
    /// lossy conversion, format-string interpretation or fd2 substitution occurs.
    #[track_caller]
    pub fn warning(&self, site: &'static str, bytes: &[u8]) {
        self.reporter.message_bytes(Level::WARNING, site, bytes);
    }
    /// Actual native/logical boundary failure through the selected destination.
    #[track_caller]
    pub fn error(&self, site: &'static str, args: std::fmt::Arguments<'_>) {
        self.reporter.message(Level::ERROR, site, args);
    }
    /// Take actual source-defined initial failure observations without changing
    /// the return-code state machine or clearing the permanent Reporter latch.
    pub fn take_initial_errors(&self) -> InitialErrors {
        std::mem::take(&mut *self.initial.borrow_mut())
    }
    pub(crate) fn initial_control(&self, error: gnunet_arm_host::HostError) {
        self.initial.borrow_mut().control = Some(error);
    }
    pub(crate) fn initial_monitor(&self, error: gnunet_arm_host::HostError) {
        self.initial.borrow_mut().monitor = Some(error);
    }
    pub(crate) fn retain_cleanup(&self, error: gnunet_arm_host::HostError) {
        let mut pending = self.cleanup.borrow_mut();
        if pending.is_none() {
            *pending = Some(error);
        }
    }
    /// First logging failure is attached after original owners physically close.
    /// Taking it never clears the shared permanent failure latch.
    pub fn finish<T>(&self, result: Result<T, Failure>) -> Result<T, Failure> {
        let logging = self.reporter.take_error();
        let cleanup = self.cleanup.borrow_mut().take();
        let initial = if result.is_err() || cleanup.is_some() || logging.is_some() {
            self.take_initial_errors()
        } else {
            InitialErrors::default()
        };
        let result = if cleanup.is_some() || initial.control.is_some() || initial.monitor.is_some()
        {
            Err(Box::new(DeferredFailure {
                original: result.err(),
                cleanup,
                initial,
            }) as Failure)
        } else {
            result
        };
        service::retain_diagnostic(result, logging)
    }
}

#[derive(Debug)]
struct DeferredFailure {
    original: Option<Failure>,
    cleanup: Option<gnunet_arm_host::HostError>,
    initial: InitialErrors,
}
impl std::fmt::Display for DeferredFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ARM CLI original={:?}; original control cleanup={:?}; initial observations={:?}",
            self.original, self.cleanup, self.initial
        )
    }
}
impl Error for DeferredFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.original
            .as_deref()
            .or(self.cleanup.as_ref().map(|e| e as &dyn Error))
            .or(self.initial.control.as_ref().map(|e| e as &dyn Error))
            .or(self.initial.monitor.as_ref().map(|e| e as &dyn Error))
    }
}
