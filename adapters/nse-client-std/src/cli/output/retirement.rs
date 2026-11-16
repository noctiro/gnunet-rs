//! Actual native work and close observation outside the PROGRAM lifetime.
use super::Failure;
use gnunet_program_host::binary_io::{Closed, Retirement, Transfer};
use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    task::Poll,
    time::{Duration, Instant},
};
#[derive(Debug)]
struct Failed {
    // Keep original outstanding work when its native call has not returned.
    native: Retirement,
    closed: Option<Closed>,
    transfer: Option<Transfer>,
    observation: Option<io::Error>,
    late: bool,
}
impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NSE stdout retirement: {self:?}")
    }
}
impl Error for Failed {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.observation
            .as_ref()
            .or_else(|| {
                self.closed
                    .as_ref()
                    .and_then(|report| report.flush.as_ref().or(report.close.as_ref()))
            })
            .map(|cause| cause as _)
    }
}
pub(in crate::cli) async fn settle(native: Retirement) -> Result<(), Failure> {
    let now = Instant::now();
    let until = now.checked_add(Duration::from_secs(1)).unwrap_or(now);
    let mut failed = Failed {
        native,
        closed: None,
        transfer: None,
        observation: None,
        late: false,
    };
    let mut alarm = std::pin::pin!(tokio::time::sleep_until(tokio::time::Instant::from_std(
        until
    )));
    poll_fn(|cx| {
        match failed.native.poll_closed(cx) {
            Poll::Ready(Ok(report)) => {
                failed.late = report.observed_at > until;
                failed.closed = Some(report);
            }
            Poll::Ready(Err(cause)) => failed.observation = Some(cause),
            Poll::Pending => {}
        }
        if failed.transfer.is_none() {
            failed.transfer = failed.native.take_transfer();
        }
        if failed.closed.is_some() || failed.observation.is_some() {
            return Poll::Ready(());
        }
        if alarm.as_mut().poll(cx).is_ready() {
            failed.late = true;
            return Poll::Ready(());
        }
        Poll::Pending
    })
    .await;
    if !failed.late
        && failed.observation.is_none()
        && failed.transfer.is_none()
        && failed.closed.as_ref().is_some_and(Closed::successful)
    {
        Ok(())
    } else {
        Err(Box::new(failed))
    }
}
