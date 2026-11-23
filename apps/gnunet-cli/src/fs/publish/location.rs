//! Optional postorder LOC requests over the configured FS service.
use gnunet::{
    fs::{Content, Location, client},
    fs_host::{ipc, publication::plan},
    types::{AbsoluteTime, Error},
    wire::fs,
};
use std::{
    future::{Future, poll_fn},
    sync::atomic::{AtomicBool, Ordering},
    task::Poll,
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};

const REQUEST_WINDOW: Duration = Duration::from_secs(2);

pub(super) struct Worker(mpsc::Sender<Request>);

struct Request {
    content: Content,
    reply: oneshot::Sender<Option<Location>>,
}

impl Worker {
    pub(super) fn sign(&self, content: Content) -> Result<Option<Location>, plan::Error> {
        let (reply, response) = oneshot::channel();
        self.0
            .blocking_send(Request { content, reply })
            .map_err(|_| Error::Closed)?;
        Ok(response.blocking_recv().map_err(|_| Error::Closed)?)
    }
}

pub(super) struct Owner {
    source: Result<ipc::EndpointSource, ipc::Error>,
    requests: mpsc::Receiver<Request>,
    expiration: AbsoluteTime,
    deadline: AbsoluteTime,
    hard: Instant,
    peer: Option<[u8; 32]>,
}

impl Owner {
    pub(super) fn new(
        source: &ipc::EndpointSource,
        expiration: AbsoluteTime,
        deadline: AbsoluteTime,
        hard: Instant,
    ) -> (Worker, Self) {
        let (sender, requests) = mpsc::channel(1);
        (
            Worker(sender),
            Self {
                source: source.fixed_endpoint(),
                requests,
                expiration,
                deadline,
                hard,
                peer: None,
            },
        )
    }

    pub(super) async fn run(mut self, stop: &AtomicBool, warning: &mut Option<ipc::Error>) {
        let source = match self.source {
            Ok(source) => Some(source),
            Err(error) => {
                *warning = Some(error);
                None
            }
        };
        while let Some(Request { content, reply }) = self.requests.recv().await {
            let location = if let Some(source) = &source
                && warning.is_none()
                && !stop.load(Ordering::Acquire)
            {
                match sign(
                    source,
                    content,
                    client::Limits {
                        expected_loc_peer: self.peer,
                        ..Default::default()
                    },
                    self.expiration,
                    self.deadline,
                    self.hard,
                    stop,
                )
                .await
                {
                    Ok(location) => {
                        self.peer = Some(*location.peer().as_bytes());
                        Some(location)
                    }
                    Err(error) => {
                        if !stop.load(Ordering::Acquire) {
                            *warning = Some(error);
                        }
                        None
                    }
                }
            } else {
                None
            };
            let _worker_finished = reply.send(location);
        }
    }
}

async fn sign(
    source: &ipc::EndpointSource,
    content: Content,
    limits: client::Limits,
    expiration: AbsoluteTime,
    deadline: AbsoluteTime,
    hard: Instant,
    stop: &AtomicBool,
) -> Result<Location, ipc::Error> {
    let until = hard.min(Instant::now() + REQUEST_WINDOW);
    let mut alarm = std::pin::pin!(tokio::time::sleep_until(until.into()));
    let mut instance = client::Instance::new();
    let mut client = ipc::Client::<0>::new(
        &mut instance,
        fs::Request::LocSign {
            expiration,
            key: content.key,
            query: content.query,
            file_length: content.size,
        },
        source.duplicate()?,
        limits,
        ipc::Limits::default(),
        deadline,
    )?;
    let result = loop {
        let step = {
            let mut drive = std::pin::pin!(client.drive(Some(until.into())));
            poll_fn(|cx| {
                if stop.load(Ordering::Acquire) {
                    return Poll::Ready(Err(Error::Cancelled.into()));
                }
                if Instant::now() >= until || alarm.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Err(Error::Deadline.into()));
                }
                drive.as_mut().poll(cx)
            })
            .await
        };
        match step {
            Ok(ipc::Step::Event(event)) => {
                break match event.event() {
                    client::Event::Location(location) => Ok(location),
                    _ => Err(Error::Malformed.into()),
                };
            }
            Ok(ipc::Step::Retry { cause, .. } | ipc::Step::Unavailable(cause)) | Err(cause) => {
                break Err(cause);
            }
            Ok(ipc::Step::WaitDeadline) => break Err(Error::Deadline.into()),
            Ok(ipc::Step::Finished) => break Err(Error::Closed.into()),
            Ok(ipc::Step::Ignored) => tokio::task::yield_now().await,
            Ok(ipc::Step::Connected | ipc::Step::Read { .. } | ipc::Step::Written { .. }) => {}
        }
    };
    if let Err(error) = &result {
        let cause = if let ipc::Error::Protocol(cause) = error {
            *cause
        } else {
            Error::Io
        };
        client.abort_with_cause(cause)?;
    }
    result
}
