//! Original write, flush and consuming-close receipts under one native grace.
use gnunet_program_host::binary_io;
use std::{
    future::{Future, poll_fn},
    io,
    task::Poll,
    time::{Duration, Instant},
};

pub(super) async fn retire(output: binary_io::Output, expected_transfer: bool) -> Retired {
    let hard = Instant::now().checked_add(Duration::from_secs(1));
    let mut owner = output.retire();
    let mut retired = Retired {
        transfer: None,
        closed: None,
        wait: None,
        expired: false,
        expected_transfer,
        pending: None,
    };
    if let Some(hard) = hard {
        let alarm = tokio::time::sleep_until(hard.into());
        let mut alarm = std::pin::pin!(alarm);
        let closed = poll_fn(|cx| {
            // Observe an already returned original receipt even at expiry.
            if let Poll::Ready(result) = owner.poll_closed(cx) {
                return Poll::Ready(Some(result));
            }
            if alarm.as_mut().poll(cx).is_ready() {
                return Poll::Ready(None);
            }
            Poll::Pending
        })
        .await;
        match closed {
            Some(Ok(closed)) => {
                retired.expired = closed.observed_at > hard;
                retired.closed = Some(closed);
            }
            Some(Err(error)) => retired.wait = Some(error),
            None => retired.expired = true,
        }
    } else {
        retired.wait = Some(io::Error::other("stdout close deadline overflow"));
    }
    retired.transfer = owner.take_transfer();
    if retired.closed.is_none() {
        retired.pending = Some(owner);
    }
    retired
}

/// Original native retirement facts. An unresolved owner remains in the failure;
/// neither a timeout nor dropping a receiver is a successful kernel cancellation.
#[derive(Debug)]
pub(crate) struct Retired {
    transfer: Option<binary_io::Transfer>,
    closed: Option<binary_io::Closed>,
    wait: Option<io::Error>,
    expired: bool,
    expected_transfer: bool,
    pending: Option<binary_io::Retirement>,
}
impl Retired {
    pub(crate) fn written(&self) -> Option<usize> {
        self.transfer
            .as_ref()
            .and_then(|value| value.result().as_ref().ok().copied())
    }
    pub(crate) fn closed(&self) -> bool {
        self.closed
            .as_ref()
            .is_some_and(|value| value.close.is_none())
    }
    pub(crate) fn flushed(&self) -> bool {
        self.closed
            .as_ref()
            .is_some_and(|value| value.flush.is_none())
    }
    pub(crate) fn successful(&self) -> bool {
        !self.expired
            && self.wait.is_none()
            && self.pending.is_none()
            && self
                .closed
                .as_ref()
                .is_some_and(binary_io::Closed::successful)
            && self.expected_transfer == self.transfer.is_some()
            && self.transfer.as_ref().is_none_or(|value| {
                value
                    .result()
                    .as_ref()
                    .is_ok_and(|count| *count > 0 && *count <= value.requested())
            })
    }
}
impl std::fmt::Display for Retired {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Resolver stdout retirement: {self:?}")
    }
}
impl std::error::Error for Retired {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.wait
            .as_ref()
            .or_else(|| {
                self.transfer
                    .as_ref()
                    .and_then(|value| value.result().as_ref().err())
            })
            .or_else(|| {
                self.closed
                    .as_ref()
                    .and_then(|value| value.flush.as_ref().or(value.close.as_ref()))
            })
            .map(|error| error as &(dyn std::error::Error + 'static))
            .or_else(|| self.expired.then_some(&gnunet_types::Error::Deadline as _))
    }
}
