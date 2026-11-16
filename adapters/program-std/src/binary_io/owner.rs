//! Original request admission, scratch and native worker startup handoff.
use super::{Closed, Direction, MAX_CHUNK, Retirement, StartError, worker};
use std::{
    fs::File,
    future::poll_fn,
    io,
    sync::{Arc, Mutex, mpsc},
    task::{Context, Poll},
    thread::JoinHandle,
};
use tokio::sync::oneshot;
use zeroize::Zeroizing;
pub(super) struct Pending {
    pub(super) requested: usize,
    pub(super) reply: oneshot::Receiver<worker::Reply>,
}
pub(super) struct Owner {
    direction: Direction,
    capacity: usize,
    buffer: Option<Zeroizing<Vec<u8>>>,
    sender: Option<mpsc::SyncSender<worker::Work>>,
    pending: Option<Pending>,
    closed: Option<oneshot::Receiver<Closed>>,
    thread: Option<JoinHandle<()>>,
}
impl Owner {
    pub(super) fn new(
        file: File,
        direction: Direction,
        capacity: usize,
    ) -> Result<Self, StartError> {
        Self::resource(worker::Resource::File(file), direction, capacity)
    }
    pub(super) fn resource(
        file: worker::Resource,
        direction: Direction,
        capacity: usize,
    ) -> Result<Self, StartError> {
        let prepare = || -> io::Result<Zeroizing<Vec<u8>>> {
            if !(1..=MAX_CHUNK).contains(&capacity) {
                return Err(io::ErrorKind::InvalidInput.into());
            }
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(capacity)
                .map_err(|_| io::ErrorKind::OutOfMemory)?;
            bytes.resize(capacity, 0);
            Ok(Zeroizing::new(bytes))
        };
        let buffer = match prepare() {
            Ok(buffer) => buffer,
            Err(cause) => {
                return Err(StartError {
                    cause,
                    close: file.close().err(),
                });
            }
        };
        let (sender, requests) = mpsc::sync_channel(1);
        let (closed, receiver) = oneshot::channel();
        // Retain the original even if thread admission fails and drops its closure.
        let handoff = Arc::new(Mutex::new(Some(file)));
        let offered = handoff.clone();
        let thread = std::thread::Builder::new()
            .name("gnunet-binary-io".into())
            .stack_size(128 * 1024)
            .spawn(move || {
                let file = offered
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .take();
                if let Some(file) = file {
                    worker::run(file, direction, requests, closed);
                }
            });
        let thread = match thread {
            Ok(thread) => thread,
            Err(cause) => {
                let file = handoff
                    .lock()
                    .unwrap_or_else(|poison| poison.into_inner())
                    .take();
                let close = file.and_then(|file| file.close().err());
                return Err(StartError { cause, close });
            }
        };
        Ok(Self {
            direction,
            capacity,
            buffer: Some(buffer),
            sender: Some(sender),
            pending: None,
            closed: Some(receiver),
            thread: Some(thread),
        })
    }
    pub(super) fn begin(&mut self, requested: usize, bytes: Option<&[u8]>) -> io::Result<()> {
        if self.pending.is_some() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        if requested == 0 || requested > self.capacity {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut buffer = self
            .buffer
            .take()
            .ok_or_else(|| io::Error::other("original binary scratch unavailable"))?;
        if let Some(bytes) = bytes {
            buffer[..requested].copy_from_slice(bytes);
        }
        let (reply, receiver) = oneshot::channel();
        let work = worker::Work {
            buffer,
            requested,
            reply,
        };
        let Some(sender) = &self.sender else {
            self.buffer = Some(work.buffer);
            return Err(io::ErrorKind::BrokenPipe.into());
        };
        match sender.try_send(work) {
            Ok(()) => {
                self.pending = Some(Pending {
                    requested,
                    reply: receiver,
                });
                Ok(())
            }
            Err(error) => {
                let (kind, work) = match error {
                    mpsc::TrySendError::Full(work) => (io::ErrorKind::WouldBlock, work),
                    mpsc::TrySendError::Disconnected(work) => (io::ErrorKind::BrokenPipe, work),
                };
                self.buffer = Some(work.buffer);
                Err(kind.into())
            }
        }
    }
    pub(super) async fn complete(&mut self) -> io::Result<usize> {
        let reply = poll_fn(|cx| self.poll_reply(cx)).await?;
        self.buffer = Some(reply.buffer);
        reply.result
    }
    pub(super) fn bytes(&self, count: usize) -> io::Result<&[u8]> {
        self.buffer
            .as_ref()
            .and_then(|buffer| buffer.get(..count))
            .ok_or_else(|| io::ErrorKind::InvalidData.into())
    }
    fn poll_reply(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<worker::Reply>> {
        let Some(pending) = &mut self.pending else {
            return Poll::Ready(Err(io::Error::other("no original binary request")));
        };
        match std::pin::Pin::new(&mut pending.reply).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.pending = None;
                Poll::Ready(result.map_err(|_| {
                    io::Error::other("binary owner lost the original transfer receipt")
                }))
            }
        }
    }
    pub(super) fn retire(mut self) -> Retirement {
        // Closing admission leaves at most the one already admitted native call.
        self.sender.take();
        Retirement {
            direction: self.direction,
            pending: self.pending.take(),
            completion: None,
            closed: self.closed.take(),
            thread: self.thread.take(),
            receipt_lost: false,
        }
    }
}
