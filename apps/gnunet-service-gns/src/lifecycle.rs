//! One actual shared Resolver Driver; callback revocation is a different scope.
use crate::Cause;
use gnunet_program_host::reporting::Reporter;
use gnunet_resolver_broker::{BrokerError, Driver, Progress};
use std::{
    cell::RefCell,
    fmt,
    future::Future,
    io,
    rc::Rc,
    task::{Context, Poll},
};

#[derive(Debug, Default)]
pub(super) struct State {
    pub disconnect: Option<BrokerError>,
    pub io: Option<io::Error>,
    pub connect: Option<BrokerError>,
    pub omitted_io: u64,
    pub omitted_connect: u64,
    pub report: Option<ResolverReport>,
}
pub(super) struct ResolverReport {
    pub queued_before: Result<usize, BrokerError>,
    pub disconnect_succeeded: bool,
    pub original_driver_dropped: bool,
}
impl fmt::Debug for ResolverReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolverReport")
            .field("queued_before", &self.queued_before)
            .field("disconnect_succeeded", &self.disconnect_succeeded)
            .field("original_driver_dropped", &self.original_driver_dropped)
            .finish()
    }
}
#[derive(Clone, Default)]
pub(super) struct Cleanup(Rc<RefCell<State>>);
#[derive(Debug)]
struct Failed {
    original: Option<Cause>,
    state: State,
}
impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GNS original={:?}; shared Resolver retirement={:?}",
            self.original, self.state
        )
    }
}
impl std::error::Error for Failed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| {
                self.state
                    .disconnect
                    .as_ref()
                    .map(|e| e as &dyn std::error::Error)
            })
            .or_else(|| self.state.io.as_ref().map(|e| e as &dyn std::error::Error))
            .or_else(|| {
                self.state
                    .connect
                    .as_ref()
                    .map(|e| e as &dyn std::error::Error)
            })
    }
}
impl Cleanup {
    pub fn finish<T>(&self, result: Result<T, Cause>) -> Result<T, Cause> {
        let state = std::mem::take(&mut *self.0.borrow_mut());
        if result.is_err()
            || state.disconnect.is_some()
            || state.io.is_some()
            || state.connect.is_some()
            || state
                .report
                .as_ref()
                .is_some_and(|r| r.queued_before.is_err())
        {
            Err(Box::new(Failed {
                original: result.err(),
                state,
            }))
        } else {
            result
        }
    }
}
pub(super) struct Resolver {
    original: Option<Driver<128, 256>>,
    cleanup: Cleanup,
}
impl Resolver {
    pub fn new(original: Driver<128, 256>, cleanup: Cleanup) -> Self {
        Self {
            original: Some(original),
            cleanup,
        }
    }
    fn collect(&mut self) {
        if let Some(original) = &mut self.original {
            let mut state = self.cleanup.0.borrow_mut();
            if let Some(error) = original.take_io_error() {
                if state.io.is_none() {
                    state.io = Some(error)
                } else {
                    state.omitted_io = state.omitted_io.saturating_add(1)
                }
            }
            if let Some(error) = original.take_connect_error() {
                if state.connect.is_none() {
                    state.connect = Some(error)
                } else {
                    state.omitted_connect = state.omitted_connect.saturating_add(1)
                }
            }
        }
    }
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        reports: &Reporter,
    ) -> Poll<Result<Progress, BrokerError>> {
        let result = match &mut self.original {
            Some(original) => {
                let mut drive = std::pin::pin!(original.drive_waiting(None, |event| {
                    reports.debug("gns.resolver.activity", format_args!("Resolver {event:?}"))
                }));
                drive.as_mut().poll(cx)
            }
            None => return Poll::Pending,
        };
        self.collect();
        result
    }
    /// Original synchronous disconnect followed by physical Driver retirement.
    /// An unsuccessful disconnect is retained; Drop is not renamed successful END.
    pub fn close(&mut self) {
        self.collect();
        if let Some(mut original) = self.original.take() {
            let queued_before = original.queued_frames();
            let result = original.disconnect();
            let succeeded = result.is_ok();
            let mut state = self.cleanup.0.borrow_mut();
            state.disconnect = result.err();
            drop(original);
            state.report = Some(ResolverReport {
                queued_before,
                disconnect_succeeded: succeeded,
                original_driver_dropped: true,
            });
        }
    }
}
impl Drop for Resolver {
    fn drop(&mut self) {
        self.close();
    }
}
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
