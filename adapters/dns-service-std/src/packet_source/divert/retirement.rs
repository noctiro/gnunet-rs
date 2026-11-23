//! Cancel and retire the original WinDivert filter loans off the reactor.

use gnunet_dnsstub_host::SocketReservations;
use gnunet_native::windivert::{Completion, Request, Session};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, mpsc as handoff},
    task::{Context, Poll, Wake, Waker},
    thread,
};
use tokio::{
    sync::{mpsc, oneshot},
    time::Instant,
};

pub(super) struct Job {
    pub(super) session: Session,
    pub(super) reservations: SocketReservations,
    pub(super) receive: Option<Request>,
    pub(super) send: Option<RetiringInjection>,
    pub(super) until: Instant,
}

impl Job {
    #[expect(
        clippy::mem_forget,
        reason = "An unavailable standby worker cannot retire the original filter off the reactor; keep its handle and exact upstream exemptions through process exit"
    )]
    pub(super) fn quarantine(self) {
        let Self {
            session,
            reservations,
            receive,
            send,
            ..
        } = self;
        std::mem::forget(session);
        super::quarantine(reservations);
        if let Some(request) = receive {
            request.detach();
        }
        if let Some(original) = send {
            match original.request {
                SendRequest::CancelRequired(request) | SendRequest::CancelAttempted(request) => {
                    request.detach();
                }
                SendRequest::AwaitingCancellation(ticket) => drop(ticket),
            }
        }
    }
}

pub(super) struct RetiringInjection {
    pub(super) request: SendRequest,
    pub(super) bytes: usize,
    pub(super) until: Instant,
}

pub(super) enum SendRequest {
    CancelRequired(Request),
    CancelAttempted(Request),
    AwaitingCancellation(Cancellation),
}

type CancelResult = (Request, io::Result<()>);

pub(super) struct Cancellation(oneshot::Receiver<CancelResult>);

impl Cancellation {
    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<CancelResult>> {
        Pin::new(&mut self.0).poll(cx).map_err(missing_cancellation)
    }

    fn take(&mut self) -> io::Result<CancelResult> {
        self.0.try_recv().map_err(missing_cancellation)
    }
}

impl Drop for Cancellation {
    fn drop(&mut self) {
        // If the worker has already returned the loan, release it without
        // calling CancelIoEx on whichever thread drops this observer.
        self.0.close();
        if let Ok((request, _result)) = self.0.try_recv() {
            request.detach();
        }
    }
}

fn missing_cancellation(error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, error)
}

pub(super) enum Receipt {
    Shutdown(io::Result<()>),
    Cancellation(io::Result<()>),
    WorkerFailed(io::Error),
    Close(io::Result<()>),
    Receive(io::Result<()>),
    Send {
        bytes: usize,
        result: io::Result<Completion>,
    },
    Finished,
}

// Shutdown, at most two cancellations, close, two completions, and finish.
const RECEIPTS: usize = 7;

enum Command {
    Cancel {
        request: Request,
        reply: oneshot::Sender<CancelResult>,
    },
    Retire(Job),
}

pub(super) struct Worker {
    submit: handoff::SyncSender<Command>,
    receipts: mpsc::Receiver<Receipt>,
}

impl Worker {
    pub(super) fn new() -> io::Result<Self> {
        // One cancellation and the close that takes ownership of its ticket.
        let (submit, receive) = handoff::sync_channel(2);
        let (report, receipts) = mpsc::channel(RECEIPTS);
        thread::Builder::new()
            .name("gnunet-windivert-control".into())
            .spawn(move || {
                while let Ok(command) = receive.recv() {
                    match command {
                        Command::Cancel { mut request, reply } => {
                            let result = request.request_cancel();
                            if let Err((request, _result)) = reply.send((request, result)) {
                                request.detach();
                            }
                        }
                        Command::Retire(job) => {
                            retire(job, report);
                            break;
                        }
                    }
                }
            })?;
        Ok(Self { submit, receipts })
    }

    #[expect(
        clippy::unreachable,
        reason = "TrySendError returns the submitted cancel command"
    )]
    pub(super) fn cancel(&self, request: Request) -> Result<Cancellation, (Request, io::Error)> {
        let (reply, ticket) = oneshot::channel();
        if let Err(error) = self.submit.try_send(Command::Cancel { request, reply }) {
            let (command, kind) = match error {
                handoff::TrySendError::Full(command) => (command, io::ErrorKind::WouldBlock),
                handoff::TrySendError::Disconnected(command) => {
                    (command, io::ErrorKind::BrokenPipe)
                }
            };
            let Command::Cancel { request, .. } = command else {
                unreachable!("cancellation handoff returned a different command");
            };
            let error = io::Error::new(kind, "WinDivert worker rejected original cancellation");
            return Err((request, error));
        }
        Ok(Cancellation(ticket))
    }

    #[expect(
        clippy::unreachable,
        reason = "TrySendError returns the submitted retirement job"
    )]
    pub(super) fn submit(self, job: Job) -> Result<mpsc::Receiver<Receipt>, Job> {
        if let Err(error) = self.submit.try_send(Command::Retire(job)) {
            let (handoff::TrySendError::Full(command)
            | handoff::TrySendError::Disconnected(command)) = error;
            let Command::Retire(job) = command else {
                unreachable!("retirement handoff returned a different command");
            };
            return Err(job);
        }
        Ok(self.receipts)
    }
}

/// Keep the exemptions if native close fails or the worker unwinds before it.
struct PortCustody(Option<SocketReservations>);

impl Drop for PortCustody {
    fn drop(&mut self) {
        if let Some(originals) = self.0.take() {
            super::quarantine(originals);
        }
    }
}

struct ThreadWake(thread::Thread);

impl Wake for ThreadWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

struct WaitingSend {
    request: Request,
    bytes: usize,
    until: Instant,
    needs_cancellation: bool,
}

fn retire(job: Job, receipts: mpsc::Sender<Receipt>) {
    let Job {
        session,
        reservations,
        mut receive,
        send,
        until,
    } = job;
    let mut ports = PortCustody(Some(reservations));
    let mut send = send.and_then(
        |RetiringInjection {
             request,
             bytes,
             until,
         }| {
            let (request, needs_cancellation) = match request {
                SendRequest::CancelRequired(request) => (request, true),
                SendRequest::CancelAttempted(request) => (request, false),
                // The same worker finished the queued cancellation before this job.
                SendRequest::AwaitingCancellation(mut ticket) => match ticket.take() {
                    Ok((request, result)) => {
                        let _unobserved = receipts.try_send(Receipt::Cancellation(result));
                        (request, false)
                    }
                    Err(error) => {
                        let _unobserved = receipts.try_send(Receipt::WorkerFailed(error));
                        return None;
                    }
                },
            };
            Some(WaitingSend {
                request,
                bytes,
                until,
                needs_cancellation,
            })
        },
    );
    let _unobserved = receipts.try_send(Receipt::Shutdown(session.shutdown()));
    if let Some(request) = &mut receive {
        let _unobserved = receipts.try_send(Receipt::Cancellation(request.request_cancel()));
    }
    if let Some(original) = &mut send
        && original.needs_cancellation
    {
        let _unobserved =
            receipts.try_send(Receipt::Cancellation(original.request.request_cancel()));
    }
    let close = session.close();
    if close.is_ok() {
        ports.0 = None;
    }
    let _unobserved = receipts.try_send(Receipt::Close(close));

    let waker = Waker::from(Arc::new(ThreadWake(thread::current())));
    let mut cx = Context::from_waker(&waker);
    loop {
        if let Some(request) = &mut receive
            && let Poll::Ready(result) = request.poll_discard_receive(&mut cx)
        {
            receive = None;
            let _unobserved = receipts.try_send(Receipt::Receive(result));
        }
        if let Some(original) = &mut send
            && let Poll::Ready(result) = original.request.poll_complete(&mut cx)
        {
            let bytes = original.bytes;
            send = None;
            let _unobserved = receipts.try_send(Receipt::Send { bytes, result });
        }
        let now = Instant::now();
        if send.as_ref().is_some_and(|original| now >= original.until)
            && let Some(original) = send.take()
        {
            original.request.detach();
        }
        if receive.is_none() && send.is_none() {
            break;
        }
        let next = send
            .as_ref()
            .map_or(until, |original| until.min(original.until));
        let remaining = next.saturating_duration_since(now);
        if remaining.is_zero() {
            break;
        }
        // A completion between the polls and this call retains its unpark token.
        thread::park_timeout(remaining);
    }
    if let Some(request) = receive {
        request.detach();
    }
    if let Some(original) = send {
        original.request.detach();
    }
    drop(ports);
    drop(session);
    let _unobserved = receipts.try_send(Receipt::Finished);
}
