//! A bounded lane for the original native registry lookups.
use super::{Error, LookupResult, native_lookup};
use crate::Bounds;
use gnunet_native::internet_registry::Database;
use gnunet_types::Error as Fault;
use std::{
    ffi::CString,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
    thread::{self, JoinHandle},
    time::Duration,
};
use tokio::{
    sync::{mpsc, oneshot},
    time::{Instant, Sleep},
};

const PENDING_LOOKUPS: usize = 32;
const MAX_NAME_BYTES: usize = 64 * 1024;
const JOIN_RECHECK: Duration = Duration::from_millis(1);
struct Request {
    service: CString,
    protocol: CString,
    bounds: Bounds,
    cancelled: Arc<AtomicBool>,
    result: oneshot::Sender<LookupResult>,
}

/// One thread owns the native database and all admitted requests until they settle.
pub(in crate::auxiliary) struct Worker {
    sender: Option<mpsc::Sender<Request>>,
    stopping: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
    exit: Option<oneshot::Receiver<()>>,
    join_recheck: Option<Pin<Box<Sleep>>>,
}

impl Worker {
    pub(in crate::auxiliary) fn spawn() -> io::Result<Self> {
        let (sender, receiver) = mpsc::channel(PENDING_LOOKUPS);
        let (exited, exit) = oneshot::channel();
        let stopping = Arc::new(AtomicBool::new(false));
        let worker_stopping = Arc::clone(&stopping);
        let thread = thread::Builder::new()
            .name("gnunet-gns-registry".into())
            .spawn(move || {
                work(receiver, &worker_stopping);
                let _notified = exited.send(());
            })?;
        Ok(Self {
            sender: Some(sender),
            stopping,
            thread: Some(thread),
            exit: Some(exit),
            join_recheck: None,
        })
    }

    pub(in crate::auxiliary) fn start(
        &mut self,
        service: &str,
        protocol: &str,
        bounds: Bounds,
    ) -> Result<Query, Error> {
        let sender = self.sender.as_ref().ok_or(Fault::Closed)?;
        if Instant::now() >= bounds.hard() {
            return Err(Fault::Timeout.into());
        }
        let length = service
            .len()
            .checked_add(protocol.len())
            .ok_or(Fault::Overflow)?;
        if length > MAX_NAME_BYTES {
            return Err(Fault::TooLarge.into());
        }
        // Reserve a queue slot before allocating either owned native name.
        let permit = sender.try_reserve().map_err(|error| match error {
            mpsc::error::TrySendError::Full(()) => Fault::Capacity,
            mpsc::error::TrySendError::Closed(()) => Fault::Closed,
        })?;
        let service = native_name(service)?;
        let protocol = native_name(protocol)?;
        let cancelled = Arc::new(AtomicBool::new(false));
        let (result, receipt) = oneshot::channel();
        permit.send(Request {
            service,
            protocol,
            bounds,
            cancelled: Arc::clone(&cancelled),
            result,
        });
        Ok(Query {
            cancelled,
            receipt: Some(receipt),
        })
    }

    pub(in crate::auxiliary) fn begin_close(&mut self) {
        self.stopping.store(true, Ordering::Release);
        drop(self.sender.take());
    }

    /// Emit the actual thread join once. The exit signal only authorizes
    /// checking for a join; native thread teardown must also have finished.
    pub(in crate::auxiliary) fn poll_stopped(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(thread) = self.thread.as_ref() else {
            return Poll::Pending;
        };
        if let Some(exit) = &mut self.exit {
            let _signal = ready!(Pin::new(exit).poll(cx));
            self.exit = None;
        }
        if !thread.is_finished() {
            // The worker can still be retiring native thread-local data. Pace
            // rechecks without making the reactor wait in JoinHandle::join.
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
            return Poll::Pending;
        };
        Poll::Ready(
            thread
                .join()
                .map_err(|_| io::Error::other("GNS registry worker panicked")),
        )
    }

    pub(in crate::auxiliary) const fn is_stopped(&self) -> bool {
        self.thread.is_none()
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        // A fallback Drop fences queued lookups and leaves any blocking call
        // on its original thread. Only poll_stopped can confirm retirement.
        self.begin_close();
    }
}

/// The callback and cancellation flag of one original queued lookup.
pub(in crate::auxiliary) struct Query {
    cancelled: Arc<AtomicBool>,
    receipt: Option<oneshot::Receiver<LookupResult>>,
}

impl Query {
    pub(in crate::auxiliary) fn begin_close(&mut self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Drive the original result, also while closing. Cancellation cannot
    /// interrupt an OS call already entered by the worker.
    pub(in crate::auxiliary) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<LookupResult> {
        let Some(receipt) = &mut self.receipt else {
            return Poll::Ready(Err(Fault::Stale.into()));
        };
        let result = ready!(Pin::new(receipt).poll(cx));
        self.receipt = None;
        Poll::Ready(result.unwrap_or_else(|_| Err(Fault::OutcomeUnknown.into())))
    }
}

impl Drop for Query {
    fn drop(&mut self) {
        self.begin_close();
    }
}

fn native_name(name: &str) -> Result<CString, Error> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(name.len() + 1)
        .map_err(|_| Fault::Capacity)?;
    bytes.extend_from_slice(name.as_bytes());
    bytes.push(0);
    CString::from_vec_with_nul(bytes).map_err(|_| Fault::Malformed.into())
}

fn live(request: &Request, stopping: &AtomicBool) -> Result<(), Error> {
    if stopping.load(Ordering::Acquire) || request.cancelled.load(Ordering::Acquire) {
        return Err(Fault::Cancelled.into());
    }
    if Instant::now() >= request.bounds.hard() {
        return Err(Fault::Timeout.into());
    }
    Ok(())
}

fn work(mut receiver: mpsc::Receiver<Request>, stopping: &AtomicBool) {
    let mut database = None;
    while let Some(request) = receiver.blocking_recv() {
        let result = live(&request, stopping).and_then(|()| {
            let native = database.get_or_insert_with(|| Database::open().map_err(Arc::new));
            live(&request, stopping)?;
            match native {
                Ok(database) => {
                    native_lookup(database, &request.service, &request.protocol, || {
                        live(&request, stopping)
                    })
                }
                Err(error) => {
                    let original = error.raw_os_error().map_or_else(
                        || io::Error::new(error.kind(), Arc::clone(error)),
                        io::Error::from_raw_os_error,
                    );
                    Err(original.into())
                }
            }
        });
        // A canceled wait may have dropped its Rust recipient. The syscall
        // still ran and retired only here on its original thread.
        let _reported = request.result.send(result);
    }
}
