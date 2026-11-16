//! Original output debt outlives the cancellable PROGRAM future.
use gnunet_program_host::binary_io::{Closed, Retirement, Transfer};
use std::{
    cell::RefCell,
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    rc::Rc,
    task::Poll,
    time::{Duration, Instant},
};
pub(crate) type Retained = Rc<RefCell<Option<Close>>>;
pub(crate) fn retained() -> Retained {
    Rc::new(RefCell::new(None))
}
#[derive(Debug)]
pub(crate) struct Close {
    native: Option<Retirement>,
    report: Option<Closed>,
    transfer: Option<Transfer>,
    observation: Option<io::Error>,
    until: Instant,
    late: bool,
}
impl Close {
    pub(super) fn new(native: Retirement) -> Self {
        let now = Instant::now();
        Self {
            native: Some(native),
            report: None,
            transfer: None,
            observation: None,
            until: now.checked_add(Duration::from_secs(1)).unwrap_or(now),
            late: false,
        }
    }
}
impl fmt::Display for Close {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GNS output retirement: {self:?}")
    }
}
impl Error for Close {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.observation
            .as_ref()
            .or_else(|| {
                self.report
                    .as_ref()
                    .and_then(|report| report.flush.as_ref().or(report.close.as_ref()))
            })
            .or_else(|| {
                self.transfer
                    .as_ref()
                    .and_then(|transfer| transfer.result().as_ref().err())
            })
            .map(|error| error as &dyn Error)
    }
}
pub(crate) async fn settle(retained: &Retained) {
    let until = retained.borrow().as_ref().map(|close| close.until);
    let Some(until) = until else {
        return;
    };
    let mut alarm = std::pin::pin!(tokio::time::sleep_until(until.into()));
    poll_fn(|cx| {
        let mut retained = retained.borrow_mut();
        let Some(close) = retained.as_mut() else {
            return Poll::Ready(());
        };
        if close.observation.is_none()
            && let Some(native) = &mut close.native
        {
            match native.poll_closed(cx) {
                Poll::Ready(Ok(report)) => {
                    close.late |= report.observed_at > close.until;
                    close.transfer = native.take_transfer();
                    close.report = Some(report);
                    close.native = None;
                }
                Poll::Ready(Err(error)) => close.observation = Some(error),
                Poll::Pending => {}
            }
        }
        if close.native.is_none() || close.observation.is_some() {
            if !close.late
                && close.transfer.is_none()
                && close.observation.is_none()
                && close.report.as_ref().is_some_and(Closed::successful)
            {
                *retained = None;
            }
            return Poll::Ready(());
        }
        if close.late || alarm.as_mut().poll(cx).is_ready() {
            close.late = true;
            return Poll::Ready(());
        }
        Poll::Pending
    })
    .await
}
