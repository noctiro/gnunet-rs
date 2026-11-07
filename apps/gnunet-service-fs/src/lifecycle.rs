//! Same physical Resolver and independent cleanup errors, including early exits.
use crate::Cause;
use gnunet_program_host::reporting::Reporter;
use gnunet_resolver_broker::{Driver, Progress};
use std::{
    cell::RefCell,
    fmt,
    future::Future,
    rc::Rc,
    task::{Context, Poll},
};

#[derive(Clone, Default)]
pub(super) struct Cleanup(Rc<RefCell<Option<Cause>>>);
#[derive(Debug)]
struct Failed {
    original: Option<Cause>,
    resolver: Cause,
}
impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FS original={:?}; independent Resolver close={}",
            self.original, self.resolver
        )
    }
}
impl std::error::Error for Failed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.as_deref().or(Some(self.resolver.as_ref()))
    }
}
impl Cleanup {
    pub fn take_error(&self) -> Option<Cause> {
        self.0.borrow_mut().take()
    }
    fn retain(&self, error: Cause) {
        let mut current = self.0.borrow_mut();
        if current.is_none() {
            *current = Some(error);
        }
    }
    pub fn finish<T>(&self, result: Result<T, Cause>) -> Result<T, Cause> {
        match self.0.borrow_mut().take() {
            Some(resolver) => Err(Box::new(Failed {
                original: result.err(),
                resolver,
            })),
            None => result,
        }
    }
}
pub(super) struct Resolver {
    original: Option<Driver<16, 256>>,
    cleanup: Cleanup,
}
impl Resolver {
    pub fn new(original: Driver<16, 256>, cleanup: Cleanup) -> Self {
        Self {
            original: Some(original),
            cleanup,
        }
    }
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        reports: &Reporter,
    ) -> Poll<Result<Progress, gnunet_resolver_broker::BrokerError>> {
        let Some(original) = &mut self.original else {
            return Poll::Pending;
        };
        let mut driving = std::pin::pin!(original.drive_waiting(None, |event| {
            reports.debug("fs.resolver.activity", format_args!("Resolver: {event:?}"))
        }));
        driving.as_mut().poll(cx)
    }
    /// Actual physical Drop follows even when the original disconnect refuses;
    /// no new source/canonical clock is needed for this one-way retirement.
    pub fn close(&mut self) {
        if let Some(mut original) = self.original.take() {
            if let Err(error) = original.disconnect() {
                self.cleanup.retain(Box::new(error));
            }
            drop(original);
        }
    }
}
impl Drop for Resolver {
    fn drop(&mut self) {
        self.close();
    }
}

/// The selected Logger has already handled the terminal diagnostic. A caller
/// must not repeat it through fd2 and bypass the selected -L/-l destination.
#[derive(Debug)]
pub(super) struct Reported(pub Cause);
impl fmt::Display for Reported {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}
impl std::error::Error for Reported {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
