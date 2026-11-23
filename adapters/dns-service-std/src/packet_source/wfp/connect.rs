//! One detached native open at a time, retaining its exact UDP socket custody.
use gnunet_dnsstub_host::SocketReservations;
use gnunet_wfp_dns_host::device::{self, Started};
use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    os::windows::io::AsSocket,
    pin::Pin,
    sync::{Arc, Mutex, PoisonError, Weak},
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    sync::oneshot,
    time::{Instant, Sleep},
};

const INITIAL_DELAY: Duration = Duration::from_millis(100);
const MAXIMUM_DELAY: Duration = Duration::from_secs(1);

pub(super) fn start_timeout() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "WFP START observation deadline elapsed",
    )
}

pub(super) fn check_deadline(until: Instant) -> io::Result<()> {
    if Instant::now() >= until {
        return Err(start_timeout());
    }
    Ok(())
}

#[derive(Debug)]
enum Failure {
    Device(device::Error),
    Close {
        original: device::Error,
        close: device::Error,
    },
    Allocation(io::Error),
}
impl Failure {
    fn pending(&self) -> bool {
        matches!(self, Self::Device(error) if error.is_start_pending())
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Device(error) => error.fmt(output),
            Self::Close { original, close } => {
                write!(output, "WFP open: {original}; original FILE close: {close}")
            }
            Self::Allocation(error) => error.fmt(output),
        }
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Device(error)
            | Self::Close {
                original: error, ..
            } => Some(error),
            Self::Allocation(error) => Some(error),
        }
    }
}

struct Attempt {
    // If the receiver disappeared, this FILE drops before the original socket
    // clone. No successful detached START can outlive all of its socket owners.
    result: Result<Started, Failure>,
    reservations: SocketReservations,
}

struct Offer<T> {
    value: Weak<Mutex<Option<T>>>,
    _settled: oneshot::Sender<()>,
}

impl<T> Offer<T> {
    fn prepare(value: T) -> (Self, impl FnOnce() -> Option<T>) {
        let value = Arc::new(Mutex::new(Some(value)));
        let (settled, settlement) = oneshot::channel();
        let offer = Self {
            value: Arc::downgrade(&value),
            _settled: settled,
        };
        let reclaim = move || {
            // Only the worker waits. When the offer is dropped, ownership
            // either moved out in accept or stayed here for worker cleanup.
            let _closed = settlement.blocking_recv();
            value.lock().unwrap_or_else(PoisonError::into_inner).take()
        };
        (offer, reclaim)
    }

    fn accept(self) -> io::Result<T> {
        self.value
            .upgrade()
            .ok_or_else(|| io::Error::other("WFP START worker lost its original result"))?
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
            .ok_or_else(|| io::Error::other("WFP START offer lost its original result"))
    }
}

fn attempt(reservations: &SocketReservations) -> Result<Started, Failure> {
    let sockets = reservations.sockets();
    let mut originals = Vec::new();
    originals
        .try_reserve_exact(sockets.len())
        .map_err(|error| Failure::Allocation(io::Error::other(error)))?;
    originals.extend(sockets.map(AsSocket::as_socket));
    let device = device::Device::open().map_err(Failure::Device)?;
    match device.start(&originals) {
        Ok(started) => Ok(started),
        Err(failure) => {
            let original = failure.original;
            match failure.device.close() {
                Ok(()) => Err(Failure::Device(original)),
                Err(close) => Err(Failure::Close { original, close }),
            }
        }
    }
}

pub(super) struct Connector {
    pending: Option<oneshot::Receiver<Offer<Attempt>>>,
    delay: Duration,
    retry_at: Option<Instant>,
    until: Instant,
    timer: Pin<Box<Sleep>>,
}
impl Connector {
    pub fn in_flight(&self) -> bool {
        self.pending.is_some()
    }
    pub fn new(until: Instant) -> Self {
        Self {
            pending: None,
            delay: INITIAL_DELAY,
            retry_at: None,
            until,
            timer: Box::pin(tokio::time::sleep_until(until)),
        }
    }

    pub const fn deadline(&self) -> Instant {
        self.until
    }

    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        reservations: &SocketReservations,
    ) -> Poll<io::Result<Started>> {
        check_deadline(self.until)?;
        if let Some(retry_at) = self.retry_at.take()
            && Instant::now() < retry_at
        {
            self.retry_at = Some(retry_at);
            self.timer.as_mut().reset(retry_at.min(self.until));
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
            return Poll::Pending;
        }
        // Register the deadline even if the native attempt never completes.
        self.timer.as_mut().reset(self.until);
        if self.timer.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(start_timeout()));
        }
        if self.pending.is_none() {
            let reservations = reservations.try_clone()?;
            let (send, receive) = oneshot::channel();
            let until = self.until;
            // The same worker owns cleanup until the poller accepts the offer.
            // The mailbox carries only the right to accept, so dropping its
            // receiver cannot close the original FILE on the executor.
            let thread = std::thread::Builder::new()
                .name("gnunet-wfp-open".into())
                .spawn(move || {
                    if send.is_closed() || Instant::now() >= until {
                        return;
                    }
                    let result = attempt(&reservations);
                    let (offer, reclaim) = Offer::prepare(Attempt {
                        result,
                        reservations,
                    });
                    drop(send.send(offer));
                    if let Some(orphan) = reclaim() {
                        let Attempt {
                            result,
                            reservations,
                        } = orphan;
                        if let Ok(started) = result {
                            let _closed = started.close();
                        }
                        drop(reservations);
                    }
                })?;
            drop(thread);
            self.pending = Some(receive);
        }
        let Some(pending) = &mut self.pending else {
            return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
        };
        let offer = match Pin::new(pending).poll(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(offer) => offer,
        };
        self.pending = None;
        // Dropping a late offer lets the original worker close its own FILE.
        check_deadline(self.until)?;
        let Attempt {
            result,
            reservations: original,
        } = offer.map_err(io::Error::other)?.accept()?;
        match result {
            Ok(started) => {
                // The caller still holds the same original lease while this
                // poll returns its successful FILE for immediate adoption.
                drop(original);
                Poll::Ready(Ok(started))
            }
            Err(error) if error.pending() => {
                drop(original);
                let now = Instant::now();
                let retry_at = now
                    .checked_add(self.delay)
                    .unwrap_or(self.until)
                    .min(self.until);
                self.retry_at = Some(retry_at);
                self.timer.as_mut().reset(retry_at);
                self.delay = self.delay.saturating_mul(2).min(MAXIMUM_DELAY);
                if self.timer.as_mut().poll(cx).is_ready() {
                    cx.waker().wake_by_ref();
                }
                Poll::Pending
            }
            Err(error) => Poll::Ready(Err(io::Error::other(error))),
        }
    }
}

pub(super) async fn open(reservations: &SocketReservations, until: Instant) -> io::Result<Started> {
    let mut connector = Connector::new(until);
    poll_fn(|cx| connector.poll(cx, reservations)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancelled_mailbox_leaves_published_owner_with_worker() {
        let (offer, reclaim) = Offer::prepare(47);
        let (send, receive) = oneshot::channel();
        assert!(send.send(offer).is_ok());
        drop(receive);
        assert_eq!(reclaim(), Some(47));
    }

    #[test]
    fn accepted_offer_moves_the_original_out_before_worker_reclaims() -> io::Result<()> {
        let (offer, reclaim) = Offer::prepare(47);
        let (send, mut receive) = oneshot::channel();
        send.send(offer)
            .map_err(|_| io::Error::other("offer receiver closed"))?;
        let accepted = receive.try_recv().map_err(io::Error::other)?.accept()?;
        if accepted != 47 || reclaim().is_some() {
            return Err(io::Error::other("worker retained the accepted value"));
        }
        Ok(())
    }

    #[test]
    fn an_in_flight_open_registers_its_deadline_and_keeps_native_custody() -> io::Result<()> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let mut stub = gnunet_dnsstub_host::DnsStub::<1, 1, 1>::start(1, 512)
                    .map_err(io::Error::other)?;
                let sockets = stub
                    .reserve_sockets(gnunet_dnsstub_host::Family::V4)
                    .map_err(io::Error::other)?;
                let (send, receive) = oneshot::channel();
                let mut connector = Connector::new(Instant::now() + Duration::from_millis(30));
                // No driver is opened. A live producer holds the original
                // pending attempt until the observation deadline wakes the host.
                connector.pending = Some(receive);
                let result = tokio::time::timeout(
                    Duration::from_secs(1),
                    poll_fn(|cx| connector.poll(cx, &sockets)),
                )
                .await
                .map_err(io::Error::other)?;
                if !matches!(result, Err(error) if error.kind() == io::ErrorKind::TimedOut)
                    || !connector.in_flight()
                    || send.is_closed()
                {
                    return Err(io::Error::other(
                        "WFP deadline disowned an outstanding attempt",
                    ));
                }
                drop(connector);
                if !send.is_closed() {
                    return Err(io::Error::other(
                        "WFP cancellation kept a late offer receiver",
                    ));
                }
                Ok(())
            })
    }
}
