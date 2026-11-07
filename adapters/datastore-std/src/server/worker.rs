//! One serialized backend owner. Borrowed pure identities never cross this port.
use super::{Error, Limits};
use gnunet_datastore::{
    ClientId, ClientSlot, Config, Entropy, Fault, Instance, ReplyAction, ReservationSlot, Service,
    WorkError,
    backend::{Backend, BackendError},
};
use gnunet_service_runtime::{clock::RuntimeClock, framing::OwnedFrame};
use gnunet_types::Error as ProtocolError;
use gnunet_wire::official::{AbsoluteTime, datastore::Request};
use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    thread,
};
use tokio::sync::{mpsc, oneshot};

pub(super) enum Command {
    Attach(u64),
    Request {
        client: u64,
        frame: OwnedFrame,
        tolerant: bool,
    },
    Detach(u64),
    Maintain,
    Stop,
}
pub(super) enum Action {
    Attached,
    Reply(OwnedFrame),
    NoReply,
    Detached,
    Maintained,
    Stopped { dropped: bool },
}
pub(super) struct Answer {
    pub action: Result<Action, Arc<Error>>,
    pub diagnostic: Option<Arc<Error>>,
}
struct Job {
    command: Command,
    response: oneshot::Sender<Answer>,
}
type Permit = Pin<
    Box<dyn Future<Output = Result<mpsc::OwnedPermit<Job>, mpsc::error::SendError<()>>> + Send>,
>;
// The same immutable job and its original result receiver survive every wait.
pub(super) struct Pending {
    permit: Option<Permit>,
    job: Option<Job>,
    response: oneshot::Receiver<Answer>,
}
impl Pending {
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Answer, Arc<Error>>> {
        if let Some(permit) = &mut self.permit {
            let ready = match permit.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => return Poll::Ready(Err(Arc::new(Error::WorkerGone))),
                Poll::Ready(Ok(permit)) => permit,
            };
            self.permit = None;
            let job = self
                .job
                .take()
                .ok_or_else(|| Arc::new(Error::Protocol(ProtocolError::Stale)))?;
            drop(ready.send(job));
        }
        Pin::new(&mut self.response)
            .poll(cx)
            .map(|result| result.map_err(|_| Arc::new(Error::WorkerGone)))
    }
}
pub(super) struct Worker {
    sender: Option<mpsc::Sender<Job>>,
    thread: Option<thread::JoinHandle<Result<(), Arc<Error>>>>,
    join_wait: Option<Pin<Box<tokio::time::Sleep>>>,
    exited: oneshot::Receiver<()>,
    exit_observed: bool,
    joined: bool,
    cancelled: Arc<AtomicBool>,
}
impl Worker {
    pub async fn start<B>(
        backend: B,
        config: Config,
        limits: Limits,
        clock: Arc<dyn RuntimeClock>,
    ) -> Result<Self, Arc<Error>>
    where
        B: Backend + Send + 'static,
        B::Error: std::error::Error + Send + Sync + 'static,
    {
        let (sender, receiver) = mpsc::channel(limits.worker_queue);
        let (started, ready) = oneshot::channel();
        let (exited, exit) = oneshot::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let stop = cancelled.clone();
        let thread = thread::Builder::new()
            .name("gnunet-datastore".to_owned())
            .spawn(move || {
                let result = run(backend, config, limits, clock, receiver, started, stop);
                match exited.send(()) {
                    Ok(()) | Err(()) => {}
                }
                result
            })
            .map_err(|error| Arc::new(Error::Io(error)))?;
        let mut worker = Self {
            sender: Some(sender),
            thread: Some(thread),
            join_wait: None,
            exited: exit,
            exit_observed: false,
            joined: false,
            cancelled,
        };
        match ready.await {
            Ok(Ok(())) => Ok(worker),
            Ok(Err(error)) => {
                worker.sender = None;
                let _joined = worker.join().await;
                Err(error)
            }
            Err(_) => {
                worker.sender = None;
                let _joined = worker.join().await;
                Err(Arc::new(Error::WorkerGone))
            }
        }
    }
    pub fn submit(&self, command: Command) -> Result<Pending, Arc<Error>> {
        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| Arc::new(Error::WorkerGone))?
            .clone();
        let (response, receiver) = oneshot::channel();
        Ok(Pending {
            permit: Some(Box::pin(sender.reserve_owned())),
            job: Some(Job { command, response }),
            response: receiver,
        })
    }
    pub async fn join(&mut self) -> Result<(), Arc<Error>> {
        self.sender = None;
        std::future::poll_fn(|cx| {
            if self.joined {
                return Poll::Ready(Ok(()));
            }
            let Some(thread) = &self.thread else {
                return Poll::Ready(Err(Arc::new(Error::WorkerGone)));
            };
            if !thread.is_finished() {
                if !self.exit_observed {
                    if Pin::new(&mut self.exited).poll(cx).is_pending() {
                        return Poll::Pending;
                    }
                    self.exit_observed = true;
                }
                // run() and backend Drop have returned. Still wait for the
                // actual thread (including TLS destructors) before joining.
                let timer = self.join_wait.get_or_insert_with(|| {
                    Box::pin(tokio::time::sleep(std::time::Duration::from_millis(10)))
                });
                if timer.as_mut().poll(cx).is_ready() {
                    self.join_wait = None;
                    cx.waker().wake_by_ref();
                }
                return Poll::Pending;
            }
            let Some(thread) = self.thread.take() else {
                return Poll::Ready(Err(Arc::new(Error::WorkerGone)));
            };
            let result = thread
                .join()
                .map_err(|_| Arc::new(Error::WorkerPanicked))
                .and_then(|result| result);
            self.joined = true;
            self.join_wait = None;
            Poll::Ready(result)
        })
        .await
    }
    pub fn quiesced(&self) -> bool {
        self.joined
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        self.sender = None;
    }
}
struct Random {
    error: Option<io::Error>,
}
impl Entropy for Random {
    fn next_u64(&mut self) -> Result<u64, ProtocolError> {
        let mut bytes = [0; 8];
        match getrandom::fill(&mut bytes) {
            Ok(()) => Ok(u64::from_ne_bytes(bytes)),
            Err(error) => {
                self.error = Some(io::Error::other(error));
                Err(ProtocolError::Io)
            }
        }
    }
}
fn fault<E>(error: Fault<E>, random: &mut Random) -> Arc<Error>
where
    E: BackendError + std::error::Error + Send + Sync + 'static,
{
    Arc::new(match error {
        Fault::Backend(error) => Error::Backend {
            certainty: error.certainty(),
            source: Box::new(error),
        },
        Fault::Entropy(error) => match random.error.take() {
            Some(error) => Error::Io(error),
            None => Error::Protocol(error),
        },
    })
}
fn backend_error<E>(error: E) -> Arc<Error>
where
    E: BackendError + std::error::Error + Send + Sync + 'static,
{
    Arc::new(Error::Backend {
        certainty: error.certainty(),
        source: Box::new(error),
    })
}
fn bytes(length: usize) -> Result<Vec<u8>, Arc<Error>> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| Arc::new(Error::Protocol(ProtocolError::Capacity)))?;
    bytes.resize(length, 0);
    Ok(bytes)
}
fn run<B>(
    mut backend: B,
    config: Config,
    limits: Limits,
    clock: Arc<dyn RuntimeClock>,
    mut receiver: mpsc::Receiver<Job>,
    started: oneshot::Sender<Result<(), Arc<Error>>>,
    cancelled: Arc<AtomicBool>,
) -> Result<(), Arc<Error>>
where
    B: Backend + Send + 'static,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    let mut instance = Instance::new();
    let mut clients = Vec::new();
    let mut reservations = Vec::new();
    let mut mapping: Vec<(u64, ClientId<'_>)> = Vec::new();
    let prepared = (|| {
        clients
            .try_reserve_exact(limits.clients)
            .map_err(|_| ProtocolError::Capacity)?;
        clients.resize(limits.clients, ClientSlot::default());
        reservations
            .try_reserve_exact(limits.reservations)
            .map_err(|_| ProtocolError::Capacity)?;
        reservations.resize(limits.reservations, ReservationSlot::default());
        mapping
            .try_reserve_exact(limits.clients)
            .map_err(|_| ProtocolError::Capacity)?;
        Ok::<_, ProtocolError>(())
    })();
    let mut service = match prepared
        .and_then(|()| Service::new(&mut instance, &mut clients, &mut reservations, config))
    {
        Ok(service) => service,
        Err(error) => {
            let error = Arc::new(Error::Protocol(error));
            match started.send(Err(error.clone())) {
                Ok(()) | Err(_) => {}
            }
            return Err(error);
        }
    };
    if started.send(Ok(())).is_err() {
        return service
            .shutdown(&mut backend)
            .map(|_| ())
            .map_err(backend_error);
    }
    let mut random = Random { error: None };
    let mut first_fatal = None;
    while let Some(job) = receiver.blocking_recv() {
        let stop = matches!(&job.command, Command::Stop);
        if cancelled.load(Ordering::Acquire)
            && !matches!(&job.command, Command::Detach(_) | Command::Stop)
        {
            match job.response.send(Answer {
                action: Err(Arc::new(Error::Protocol(ProtocolError::Cancelled))),
                diagnostic: None,
            }) {
                Ok(()) | Err(_) => {}
            }
            continue;
        }
        random.error = None;
        let mut diagnostic = None;
        let action = (|| match job.command {
            Command::Attach(native) => {
                if mapping.iter().any(|(id, _)| *id == native) {
                    return Err(Arc::new(Error::Protocol(ProtocolError::Conflict)));
                }
                let client = service
                    .connect()
                    .map_err(|error| Arc::new(Error::Protocol(error)))?;
                mapping.push((native, client));
                Ok(Action::Attached)
            }
            Command::Detach(native) => {
                if let Some(index) = mapping.iter().position(|(id, _)| *id == native) {
                    let (_, client) = mapping.swap_remove(index);
                    service
                        .disconnect(client)
                        .map_err(|error| Arc::new(Error::Protocol(error)))?;
                }
                Ok(Action::Detached)
            }
            Command::Request {
                client,
                frame,
                tolerant,
            } => {
                let client = mapping
                    .iter()
                    .find(|(id, _)| *id == client)
                    .map(|(_, client)| *client)
                    .ok_or_else(|| Arc::new(Error::Protocol(ProtocolError::Stale)))?;
                let request = match Request::decode(frame.bytes()) {
                    Ok(request) => request,
                    Err(ProtocolError::Unsupported) if tolerant => return Ok(Action::NoReply),
                    Err(error) => return Err(Arc::new(Error::Protocol(error))),
                };
                let mut output = bytes(gnunet_datastore::required_output(request))?;
                let now = AbsoluteTime::from_micros(
                    clock
                        .sample()
                        .map_err(|error| Arc::new(Error::Protocol(error)))?
                        .now
                        .as_micros(),
                );
                match service
                    .handle(client, request, &mut backend, &mut output, now, &mut random)
                    .map_err(|error| Arc::new(Error::Protocol(error)))?
                {
                    ReplyAction::Reply {
                        bytes,
                        fault: notice,
                    } => {
                        diagnostic = notice.map(|error| fault(error, &mut random));
                        output.truncate(bytes);
                        Ok(Action::Reply(OwnedFrame::new(output)))
                    }
                    ReplyAction::NoReply => Ok(Action::NoReply),
                    ReplyAction::Close { fault: error } => Err(fault(error, &mut random)),
                }
            }
            Command::Maintain => {
                let now = AbsoluteTime::from_micros(
                    clock
                        .sample()
                        .map_err(|error| Arc::new(Error::Protocol(error)))?
                        .now
                        .as_micros(),
                );
                service
                    .maintain(&mut backend, now)
                    .map_err(|error| match error {
                        WorkError::Protocol(error) => Arc::new(Error::Protocol(error)),
                        WorkError::Backend(error) => backend_error(error),
                    })?;
                Ok(Action::Maintained)
            }
            Command::Stop => {
                let dropped = service.shutdown(&mut backend).map_err(backend_error)?;
                Ok(Action::Stopped { dropped })
            }
        })();
        if let Err(error) = &action
            && error.fatal()
            && first_fatal.is_none()
        {
            first_fatal = Some(error.clone());
        }
        let stop_error = if stop {
            action.as_ref().err().cloned()
        } else {
            None
        };
        match job.response.send(Answer { action, diagnostic }) {
            Ok(()) | Err(_) => {}
        }
        if stop {
            return first_fatal.or(stop_error).map_or(Ok(()), Err);
        }
    }
    let shutdown = service
        .shutdown(&mut backend)
        .map(|_| ())
        .map_err(backend_error);
    first_fatal.map_or(shutdown, Err)
}
