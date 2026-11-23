//! One original link probe in flight outside the service reactor.

use gnunet_native::transparent_dns::exclusion::{ProbeReceipt, ProbeRequest, ProbeSocket};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    task::{Context, Poll, ready},
    thread::{self, JoinHandle},
    time::Duration,
};
use tokio::{
    sync::{mpsc as async_mpsc, oneshot},
    time::{Instant, Sleep},
};

const JOIN_RECHECK: Duration = Duration::from_millis(1);

pub(super) struct Worker<Request = ProbeRequest, Receipt = ProbeReceipt> {
    send: Option<mpsc::SyncSender<Request>>,
    receipts: async_mpsc::Receiver<Receipt>,
    pending: bool,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    exit: Option<oneshot::Receiver<()>>,
    join_recheck: Option<Pin<Box<Sleep>>>,
}

impl Worker {
    pub(super) fn launch(mut socket: ProbeSocket) -> io::Result<Self> {
        Self::start(move |request| socket.run(request))
    }
}

impl<Request, Receipt> Worker<Request, Receipt> {
    fn start(mut run: impl FnMut(Request) -> Receipt + Send + 'static) -> io::Result<Self>
    where
        Request: Send + 'static,
        Receipt: Send + 'static,
    {
        let (send, receive) = mpsc::sync_channel(1);
        let (reply, receipts) = async_mpsc::channel(1);
        let (exited, exit) = oneshot::channel();
        let stopping = Arc::new(AtomicBool::new(false));
        let cancelled = Arc::clone(&stopping);
        let thread = thread::Builder::new()
            .name("dns-ingress-probe".into())
            .spawn(move || {
                while let Ok(request) = receive.recv() {
                    if cancelled.load(Ordering::Acquire) {
                        break;
                    }
                    if reply.blocking_send(run(request)).is_err() {
                        break;
                    }
                }
                drop(run);
                let _notified = exited.send(());
            })?;
        Ok(Self {
            send: Some(send),
            receipts,
            pending: false,
            stopping,
            thread: Some(thread),
            exit: Some(exit),
            join_recheck: None,
        })
    }

    pub(super) const fn busy(&self) -> bool {
        self.pending
    }

    pub(super) fn submit(&mut self, request: Request) -> io::Result<()> {
        let send = self.send.as_ref().ok_or(io::ErrorKind::NotConnected)?;
        if self.busy() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        send.try_send(request).map_err(|error| match error {
            mpsc::TrySendError::Disconnected(_) => io::ErrorKind::BrokenPipe,
            mpsc::TrySendError::Full(_) => io::ErrorKind::WouldBlock,
        })?;
        self.pending = true;
        Ok(())
    }

    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Receipt>> {
        if !self.pending {
            return Poll::Pending;
        }
        let receipt = ready!(self.receipts.poll_recv(cx));
        self.pending = false;
        Poll::Ready(receipt.ok_or_else(|| io::ErrorKind::BrokenPipe.into()))
    }

    pub(super) fn cancel(&mut self) {
        self.stopping.store(true, Ordering::Release);
        self.send = None;
        self.receipts.close();
        self.pending = false;
    }

    pub(super) fn poll_retired(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.cancel();
        let Some(thread) = &self.thread else {
            return Poll::Ready(Ok(()));
        };
        if let Some(exit) = &mut self.exit {
            let _hint = ready!(Pin::new(exit).poll(cx));
            self.exit = None;
        }
        if !thread.is_finished() {
            // The exit receipt can precede thread-local destructor completion.
            let timer = self
                .join_recheck
                .get_or_insert_with(|| Box::pin(tokio::time::sleep(JOIN_RECHECK)));
            if timer.as_mut().poll(cx).is_ready() {
                timer.as_mut().reset(Instant::now() + JOIN_RECHECK);
                let _armed = timer.as_mut().poll(cx);
            }
            return Poll::Pending;
        }
        self.join_recheck = None;
        let Some(thread) = self.thread.take() else {
            return Poll::Ready(Ok(()));
        };
        Poll::Ready(
            thread
                .join()
                .map_err(|_| io::Error::other("transparent DNS link probe worker panicked")),
        )
    }
}

impl<Request, Receipt> Drop for Worker<Request, Receipt> {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(test)]
mod tests;
