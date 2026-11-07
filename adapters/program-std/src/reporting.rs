//! One PROGRAM/SERVICE-selected Logger shared by a caller's local scheduler.
//! No task, timer, fallback logger or native owner is created here.
use crate::{logging::Logger, policy::Level, service, shared_clock::SharedClock};
use std::{
    cell::{Cell, RefCell},
    fmt, io,
    rc::Rc,
    task::{Context, Waker},
};

struct Inner {
    logger: RefCell<Logger<'static>>,
    clock: SharedClock,
    failed: Cell<bool>,
    error: RefCell<Option<io::Error>>,
    waker: RefCell<Option<Waker>>,
}

/// Original selected Logger and first output error, without another runtime.
/// Clones share the same local owner. A failed write latches failure and wakes
/// the original registered task; the caller still owns shutdown and cleanup.
#[derive(Clone)]
pub struct Reporter(Rc<Inner>);

impl Reporter {
    /// Adopt the Logger after option selection and any daemon process refresh.
    /// The clock is the same explicitly shared PROGRAM/SERVICE clock.
    pub fn new(logger: Logger<'static>, clock: SharedClock) -> Self {
        Self(Rc::new(Inner {
            logger: RefCell::new(logger),
            clock,
            failed: Cell::new(false),
            error: RefCell::new(None),
            waker: RefCell::new(None),
        }))
    }

    /// Register the task which must drive original shutdown on output failure.
    pub fn register(&self, cx: &Context<'_>) {
        let mut current = self.0.waker.borrow_mut();
        if current.as_ref().is_none_or(|w| !w.will_wake(cx.waker())) {
            *current = Some(cx.waker().clone());
        }
    }

    /// First output failure remains latched even after its owned error is taken.
    pub fn failed(&self) -> bool {
        self.0.failed.get()
    }

    /// Report through the actual selected file, level and logging policy.
    /// The first error is retained independently of the original business result.
    #[track_caller]
    pub fn message(&self, level: Level, site: &'static str, args: fmt::Arguments<'_>) {
        let caller = std::panic::Location::caller();
        self.emit(|logger| {
            service::diagnostic_body(logger, &self.0.clock, site, level, caller, || {
                Ok(format!("{args}\n").into_bytes())
            })
        });
    }

    /// Emit an exact native byte body, including its caller-supplied newline.
    /// Bytes are copied only after the same policy admits this callsite. No
    /// UTF-8 decoding or replacement changes native filenames in diagnostics.
    #[track_caller]
    pub fn message_bytes(&self, level: Level, site: &'static str, bytes: &[u8]) {
        let caller = std::panic::Location::caller();
        self.emit(|logger| {
            service::diagnostic_body(logger, &self.0.clock, site, level, caller, || {
                let mut body = Vec::new();
                body.try_reserve_exact(bytes.len())
                    .map_err(io::Error::other)?;
                body.extend_from_slice(bytes);
                Ok(body)
            })
        });
    }

    fn emit(&self, logging: impl FnOnce(&mut Logger<'static>) -> io::Result<()>) {
        if self.failed() {
            return;
        }
        let result = self
            .0
            .logger
            .try_borrow_mut()
            .map_err(|_| io::Error::other("selected Logger is already borrowed"))
            .and_then(|mut logger| logging(&mut logger));
        if let Err(error) = result {
            self.0.failed.set(true);
            *self.0.error.borrow_mut() = Some(error);
            // Release the local borrow before invoking an externally owned waker.
            let waker = self.0.waker.borrow().clone();
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }

    /// Emit a warning with the original selected Logger.
    #[track_caller]
    pub fn warning(&self, site: &'static str, args: fmt::Arguments<'_>) {
        self.message(Level::WARNING, site, args);
    }

    /// Emit a debug message with the original selected Logger.
    #[track_caller]
    pub fn debug(&self, site: &'static str, args: fmt::Arguments<'_>) {
        self.message(Level::DEBUG, site, args);
    }

    /// Take the original first output error once for final error propagation.
    /// Taking it does not clear the failure latch or authorize further work.
    /// Callers can use `service::retain_diagnostic` after their actual cleanup.
    pub fn take_error(&self) -> Option<io::Error> {
        self.0.error.borrow_mut().take()
    }
}
