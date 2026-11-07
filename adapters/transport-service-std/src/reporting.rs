//! Explicit process-owned SERVICE observations. No global logger, task or FD
//! redirection is installed; callbacks finish before native ports are reborrowed.
use gnunet_program_host::policy::Level;
use gnunet_transport::PeerId;
use std::{
    cell::{Cell, RefCell},
    fmt,
    io::{self, Write},
    rc::Rc,
    task::{Context, Waker},
};
/// An actual local SERVICE fact, never a peer-delivery or publication receipt.
pub enum Notice<'a> {
    /// The original Owner can admit local IPC after its real PILS authority and
    /// persistence barrier. This callback is made at most once per process run.
    Ready {
        /// Actual current public identity of that ready Owner.
        peer: PeerId,
    },
    /// A diagnostic from the actual original driver or cleanup boundary.
    Diagnostic {
        /// Source severity, evaluated by the caller's actual selected Logger.
        level: Level,
        /// Stable callsite policy/cache identity.
        site: &'static str,
        /// Borrowed message valid only until this synchronous callback returns.
        message: fmt::Arguments<'a>,
    },
}
type Sink = dyn for<'a> FnMut(Notice<'a>) -> io::Result<()>;
struct State {
    sink: RefCell<Box<Sink>>,
    failure: RefCell<Option<io::Error>>,
    ready: Cell<bool>,
    waker: RefCell<Option<Waker>>,
}
/// Shared explicit observation owner for disjoint foreground/DV cleanup paths.
/// The first callback IO error requests ordinary source shutdown, survives all
/// actual worker joins and is returned independently of an original failure.
#[derive(Clone)]
pub struct Reports(Rc<State>);
impl Reports {
    /// Retain one caller-owned callback. No callback is invoked at construction.
    pub fn new(sink: impl for<'a> FnMut(Notice<'a>) -> io::Result<()> + 'static) -> Self {
        Self(Rc::new(State {
            sink: RefCell::new(Box::new(sink)),
            failure: RefCell::new(None),
            ready: Cell::new(false),
            waker: RefCell::new(None),
        }))
    }
    /// Explicit default for the existing embedding scheduler: diagnostics go to
    /// its actual stderr, and no daemon or external readiness owner is invented.
    pub(crate) fn stderr() -> Self {
        Self::new(|notice| match notice {
            Notice::Ready { .. } => Ok(()),
            Notice::Diagnostic { message, .. } => {
                let mut output = io::stderr().lock();
                writeln!(output, "{message}")?;
                output.flush()
            }
        })
    }
    fn emit(&self, notice: Notice<'_>) {
        if self.failed() {
            return;
        }
        let result = (self.0.sink.borrow_mut())(notice);
        if let Err(error) = result {
            *self.0.failure.borrow_mut() = Some(error);
            if let Some(waker) = self.0.waker.borrow().as_ref() {
                waker.wake_by_ref();
            }
        }
    }
    pub(crate) fn ready(&self, peer: PeerId) {
        if !self.0.ready.replace(true) {
            self.emit(Notice::Ready { peer });
        }
    }
    pub(crate) fn diagnostic(&self, message: fmt::Arguments<'_>) {
        self.message(Level::WARNING, "transport.runtime", message);
    }
    pub(crate) fn message(&self, level: Level, site: &'static str, message: fmt::Arguments<'_>) {
        self.emit(Notice::Diagnostic {
            level,
            site,
            message,
        });
    }
    pub(crate) fn register(&self, cx: &Context<'_>) {
        let mut current = self.0.waker.borrow_mut();
        if current
            .as_ref()
            .is_none_or(|old| !old.will_wake(cx.waker()))
        {
            *current = Some(cx.waker().clone());
        }
    }
    pub(crate) fn failed(&self) -> bool {
        self.0.failure.borrow().is_some()
    }
    pub(crate) fn take_failure(&self) -> Option<io::Error> {
        self.0.failure.borrow_mut().take()
    }
}
