//! Standard Resolver SERVICE entry over native endpoints and one DNS backend.
#![deny(unsafe_code)]
use gnunet_program_host::{logging::Logger, policy::Level, service, shared_clock::SharedClock};
use gnunet_resolver_host::MachineDiagnostic;
use gnunet_service_runtime::BoundListeners;
use std::{
    cell::RefCell,
    error::Error,
    fmt,
    io::{self, Write},
    process::ExitCode,
    task::{Context, Waker},
};
#[cfg(unix)]
#[path = "unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "windows.rs"]
mod platform;
type Failure = Box<dyn Error>;
fn main() -> ExitCode {
    match platform::run() {
        Ok(code) => code,
        Err(error) => {
            // Only failures before actual option/logger selection reach here.
            let _diagnostic = writeln!(io::stderr().lock(), "gnunet-service-resolver: {error}");
            ExitCode::FAILURE
        }
    }
}
struct Diagnostics<'a> {
    logger: RefCell<Logger<'a>>,
    clock: SharedClock,
    failure: RefCell<Option<io::Error>>,
    waker: RefCell<Option<Waker>>,
}
impl<'a> Diagnostics<'a> {
    fn new(logger: Logger<'a>, clock: SharedClock) -> Self {
        Self {
            logger: RefCell::new(logger),
            clock,
            failure: RefCell::new(None),
            waker: RefCell::new(None),
        }
    }
    fn message(
        &self,
        site: &'static str,
        level: Level,
        message: fmt::Arguments<'_>,
    ) -> io::Result<()> {
        service::diagnostic(
            &mut self.logger.borrow_mut(),
            &self.clock,
            site,
            level,
            message,
        )
    }
    fn machine_input(&self, diagnostic: &MachineDiagnostic) -> io::Result<()> {
        self.message(
            "resolver.machine",
            Level::WARNING,
            format_args!(
                "resolver machine input {}: {}",
                diagnostic.source, diagnostic.error
            ),
        )
    }
    fn ready(&self, bound: &BoundListeners) -> io::Result<()> {
        for error in bound.failures() {
            self.message(
                "resolver.listener.alternate",
                Level::WARNING,
                format_args!("resolver alternate listener: {error}"),
            )?;
        }
        self.message(
            "resolver.ready",
            Level::INFO,
            format_args!("Resolver ready with its DNS backend and listeners"),
        )?;
        let mut output = io::stdout().lock();
        writeln!(output, "READY resolver")?;
        output.flush()
    }
    fn observe(&self, site: &'static str, level: Level, message: fmt::Arguments<'_>) {
        if self.failure.borrow().is_some() {
            return;
        }
        if let Err(error) = self.message(site, level, message) {
            *self.failure.borrow_mut() = Some(error);
            if let Some(waker) = self.waker.borrow().as_ref() {
                waker.wake_by_ref();
            }
        }
    }
    fn failed(&self, cx: &Context<'_>) -> bool {
        let mut waker = self.waker.borrow_mut();
        if waker.as_ref().is_none_or(|old| !old.will_wake(cx.waker())) {
            *waker = Some(cx.waker().clone());
        }
        self.failure.borrow().is_some()
    }
    fn take_failure(&self) -> Option<io::Error> {
        self.failure.borrow_mut().take()
    }
}
fn complete(
    result: Result<(), Failure>,
    logger: &mut Logger<'_>,
    clock: &SharedClock,
) -> Result<ExitCode, Failure> {
    match result {
        Ok(()) => Ok(ExitCode::SUCCESS),
        Err(original) => {
            if let Err(diagnostic) = service::diagnostic(
                logger,
                clock,
                "resolver.failure",
                Level::ERROR,
                format_args!("gnunet-service-resolver: {original}"),
            ) {
                let _reported = writeln!(
                    io::stderr().lock(),
                    "gnunet-service-resolver: {original}; independent logging failure: {diagnostic}"
                );
            }
            Ok(ExitCode::FAILURE)
        }
    }
}
