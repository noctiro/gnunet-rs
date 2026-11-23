//! Bounded observation of fixed original I/O owners; no task or renewed work.
use super::{Closed, Direction, Retirement, Transfer};
use std::{
    future::{Future, poll_fn},
    io,
    task::{Context, Poll},
    time::Instant,
};

/// Independent original transfer, native cancellation and consuming-close receipts.
#[derive(Debug)]
pub struct Retired {
    owner: Retirement,
    expected: bool,
    settled: bool,
    transfer: Option<Transfer>,
    closed: Option<Closed>,
    wait: Option<io::Error>,
    expired: bool,
    #[cfg(windows)]
    cancel_requested: bool,
    #[cfg(windows)]
    cancel_error: Option<io::Error>,
}
impl Retired {
    fn new(owner: Retirement) -> Self {
        let expected = owner.pending.is_some() || owner.completion.is_some();
        Self {
            owner,
            expected,
            settled: false,
            transfer: None,
            closed: None,
            wait: None,
            expired: false,
            #[cfg(windows)]
            cancel_requested: false,
            #[cfg(windows)]
            cancel_error: None,
        }
    }
    fn poll(&mut self, cx: &mut Context<'_>, hard: tokio::time::Instant) {
        if self.settled {
            return;
        }
        let step = self.owner.poll_closed(cx);
        if let Some(transfer) = self.owner.take_transfer() {
            self.transfer = Some(transfer);
        }
        if let Poll::Ready(result) = step {
            self.settled = true;
            match result {
                Ok(closed) => {
                    self.expired = closed.observed_at > hard.into_std();
                    self.closed = Some(closed);
                }
                Err(error) => self.wait = Some(error),
            }
        }
    }
    #[cfg(windows)]
    fn cancel(&mut self) {
        if self.settled
            || !self.expected
            || self.transfer.is_some()
            || self.cancel_requested
            || self.cancel_error.is_some()
        {
            return;
        }
        match self.owner.request_read_cancel() {
            Ok(requested) => self.cancel_requested = requested,
            Err(error) => self.cancel_error = Some(error),
        }
    }
    fn transfer_successful(&self) -> bool {
        self.transfer
            .as_ref()
            .is_none_or(|value| match value.result() {
                Ok(count) => {
                    *count <= value.requested()
                        && (*count > 0 || value.direction() == Direction::Input)
                }
                #[cfg(windows)]
                Err(_) => {
                    self.cancel_requested && self.cancel_error.is_none() && value.read_cancelled()
                }
                #[cfg(not(windows))]
                Err(_) => false,
            })
    }
    /// Actual matching transfer and flush/close, within the original bound.
    pub fn successful(&self) -> bool {
        #[cfg(windows)]
        if self.cancel_error.is_some() {
            return false;
        }
        self.settled
            && !self.expired
            && self.wait.is_none()
            && self.closed.as_ref().is_some_and(Closed::successful)
            && self.expected == self.transfer.is_some()
            && self.transfer_successful()
    }
    /// Actual original native byte count; canceled/failed calls have no count.
    pub fn count(&self) -> Option<usize> {
        self.transfer.as_ref()?.result().as_ref().ok().copied()
    }
    /// Original native flush and consuming-close observation.
    pub fn closed(&self) -> Option<&Closed> {
        self.closed.as_ref()
    }
    /// Original transfer, including successful read bytes, without resubmission.
    pub fn transfer(&self) -> Option<&Transfer> {
        self.transfer.as_ref()
    }
    /// Actual canceled-read status, separate from request and close success.
    pub fn read_cancelled(&self) -> bool {
        #[cfg(windows)]
        {
            self.transfer.as_ref().is_some_and(Transfer::read_cancelled)
        }
        #[cfg(not(windows))]
        {
            false
        }
    }
    fn error(&self) -> Option<&(dyn std::error::Error + 'static)> {
        #[cfg(windows)]
        if let Some(error) = &self.cancel_error {
            return Some(error);
        }
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

/// Fixed original owners and independent receipts. Failed/unresolved workers
/// remain retained here; dropping this object does not assert cancellation.
#[derive(Debug)]
pub struct RetiredSet<const N: usize> {
    owners: [Option<Retired>; N],
}
impl<const N: usize> RetiredSet<N> {
    /// Inspect only the supplied original slot; None denotes an unused role.
    pub fn get(&self, index: usize) -> Option<&Retired> {
        self.owners.get(index)?.as_ref()
    }
    /// Whether every supplied owner actually retired within the original bound.
    pub fn successful(&self) -> bool {
        self.owners.iter().flatten().all(Retired::successful)
    }
}
impl<const N: usize> std::fmt::Display for RetiredSet<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "original native I/O retirement: {self:?}")
    }
}
impl<const N: usize> std::error::Error for RetiredSet<N> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.owners
            .iter()
            .flatten()
            .filter(|owner| !owner.successful())
            .find_map(Retired::error)
    }
}
/// Observe a fixed set after admission closes, under one caller-anchored native
/// deadline. Windows read cancellation targets only the retained input workers;
/// its request, actual transfer and close remain independent. No write is
/// canceled, retried or admitted, and a timeout retains the original receivers.
/// Requires a Tokio runtime with its time driver enabled.
pub async fn settle<const N: usize>(
    owners: [Option<Retirement>; N],
    hard: Instant,
) -> RetiredSet<N> {
    let mut retired = RetiredSet {
        owners: owners.map(|owner| owner.map(Retired::new)),
    };
    let alarm = tokio::time::sleep_until(hard.into());
    let mut alarm = std::pin::pin!(alarm);
    #[cfg(windows)]
    let retry = tokio::time::sleep(std::time::Duration::ZERO);
    #[cfg(windows)]
    let mut retry = std::pin::pin!(retry);
    poll_fn(|cx| {
        for owner in retired.owners.iter_mut().flatten() {
            owner.poll(cx, hard.into());
        }
        #[cfg(windows)]
        if retry.as_mut().poll(cx).is_ready() {
            for owner in retired
                .owners
                .iter_mut()
                .flatten()
                .filter(|owner| owner.owner.direction == Direction::Input)
            {
                owner.cancel();
            }
            retry
                .as_mut()
                .reset(tokio::time::Instant::now() + std::time::Duration::from_millis(25));
            let _registered = retry.as_mut().poll(cx);
        }
        if retired.owners.iter().flatten().all(|owner| owner.settled) {
            return Poll::Ready(());
        }
        if Instant::now() >= hard || alarm.as_mut().poll(cx).is_ready() {
            for owner in retired
                .owners
                .iter_mut()
                .flatten()
                .filter(|owner| !owner.settled)
            {
                owner.expired = true;
            }
            return Poll::Ready(());
        }
        Poll::Pending
    })
    .await;
    retired
}
