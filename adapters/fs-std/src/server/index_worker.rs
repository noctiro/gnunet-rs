//! Serialized blocking index operations. Original jobs survive canceled waits.
use super::Error;
use crate::index::Index;
use gnunet_service_runtime::framing::OwnedFrame;
use gnunet_types::Error as ProtocolError;
use gnunet_wire::official::fs::Response;
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    thread,
};
use tokio::sync::{mpsc, oneshot};
pub(super) enum Task {
    CollectGarbage,
    Register {
        file_id: [u8; 64],
        filename: Vec<u8>,
        device: u64,
        inode: u64,
    },
    Remove([u8; 64]),
    Next(Option<[u8; 64]>),
    Resolve {
        query: [u8; 64],
        record: [u8; 72],
    },
}
pub(super) enum Output {
    Maintained,
    Registered,
    Removed,
    Entry {
        file_id: [u8; 64],
        frame: OwnedFrame,
    },
    End(OwnedFrame),
    Resolved(Vec<u8>),
}
struct Job {
    task: Task,
    result: oneshot::Sender<Result<Output, Arc<Error>>>,
}
type Permit = Pin<
    Box<dyn Future<Output = Result<mpsc::OwnedPermit<Job>, mpsc::error::SendError<()>>> + Send>,
>;
pub(super) struct Pending {
    permit: Option<Permit>,
    job: Option<Job>,
    result: oneshot::Receiver<Result<Output, Arc<Error>>>,
}
impl Pending {
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Output, Arc<Error>>> {
        if let Some(permit) = &mut self.permit {
            let permit = match permit.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(_)) => return Poll::Ready(Err(Arc::new(Error::WorkerGone))),
                Poll::Ready(Ok(permit)) => permit,
            };
            self.permit = None;
            let Some(job) = self.job.take() else {
                return Poll::Ready(Err(Arc::new(Error::Protocol(ProtocolError::Stale))));
            };
            drop(permit.send(job));
        }
        Pin::new(&mut self.result)
            .poll(cx)
            .map(|r| r.unwrap_or_else(|_| Err(Arc::new(Error::WorkerGone))))
    }
}
struct ResolverShared {
    sender: mpsc::Sender<Job>,
}
/// Weak submission port into the one existing index owner's bounded queue.
/// Cloning this port never opens an Index/WAL or keeps a shut-down worker alive.
#[derive(Clone)]
pub struct IndexResolver {
    shared: Weak<ResolverShared>,
}
/// One actually admitted readonly resolution, retained across canceled waits.
/// It holds no queue sender or admission permit. Dropping the wait leaves the
/// original queued job with its worker and cannot keep worker shutdown alive.
pub struct Resolution {
    result: Option<oneshot::Receiver<Result<Output, Arc<Error>>>>,
}
impl IndexResolver {
    /// Admit a type6 descriptor to the one original index worker without waiting
    /// for queue capacity. Full is an explicit no-effect Capacity refusal.
    /// The original queued job checks its ciphertext key with Index::resolve.
    pub fn resolve(&self, query: [u8; 64], record: [u8; 72]) -> Result<Resolution, Arc<Error>> {
        let shared = self
            .shared
            .upgrade()
            .ok_or_else(|| Arc::new(Error::WorkerGone))?;
        let (result, receiver) = oneshot::channel();
        shared
            .sender
            .try_send(Job {
                task: Task::Resolve { query, record },
                result,
            })
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    Arc::new(Error::Protocol(ProtocolError::Capacity))
                }
                mpsc::error::TrySendError::Closed(_) => Arc::new(Error::WorkerGone),
            })?;
        Ok(Resolution {
            result: Some(receiver),
        })
    }
}
impl Resolution {
    /// Drive the original queued resolution once; no job or file read is replayed.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Vec<u8>, Arc<Error>>> {
        let Some(receiver) = &mut self.result else {
            return Poll::Ready(Err(Arc::new(Error::Protocol(ProtocolError::Stale))));
        };
        match Pin::new(receiver).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                self.result = None;
                Poll::Ready(match result {
                    Ok(Ok(Output::Resolved(bytes))) => Ok(bytes),
                    Ok(Ok(_)) => Err(Arc::new(Error::Protocol(ProtocolError::Malformed))),
                    Ok(Err(error)) => Err(error),
                    Err(_) => Err(Arc::new(Error::WorkerGone)),
                })
            }
        }
    }
}
pub(super) struct Worker {
    resolver: Option<Arc<ResolverShared>>,
    sender: Option<mpsc::Sender<Job>>,
    thread: Option<thread::JoinHandle<()>>,
    exited: oneshot::Receiver<()>,
    exit_observed: bool,
    wait: Option<Pin<Box<tokio::time::Sleep>>>,
    cancelled: Arc<AtomicBool>,
    joined: bool,
}
fn encode(response: Response<'_>) -> Result<OwnedFrame, Arc<Error>> {
    let n = response
        .encoded_len()
        .map_err(|e| Arc::new(Error::Protocol(e)))?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(n)
        .map_err(|_| Arc::new(Error::Protocol(ProtocolError::Capacity)))?;
    bytes.resize(n, 0);
    response
        .encode(&mut bytes)
        .map_err(|e| Arc::new(Error::Protocol(e)))?;
    Ok(OwnedFrame::new(bytes))
}
impl Worker {
    pub fn start(mut index: Index, capacity: usize) -> Result<Self, Arc<Error>> {
        if capacity == 0 || capacity > tokio::sync::Semaphore::MAX_PERMITS {
            return Err(Arc::new(Error::Protocol(ProtocolError::InvalidInput)));
        }
        let (sender, mut receiver) = mpsc::channel::<Job>(capacity);
        let resolver = Arc::new(ResolverShared {
            sender: sender.clone(),
        });
        let (exited, exit) = oneshot::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let stop = cancelled.clone();
        let thread = thread::Builder::new()
            .name("gnunet-fs-index".to_owned())
            .spawn(move || {
                while let Some(job) = receiver.blocking_recv() {
                    let result = if stop.load(Ordering::Acquire) {
                        Err(Arc::new(Error::Protocol(ProtocolError::Cancelled)))
                    } else {
                        match job.task {
                            Task::CollectGarbage => index
                                .collect_garbage()
                                .map(|_| Output::Maintained)
                                .map_err(|e| Arc::new(Error::Index(Box::new(e)))),
                            Task::Register {
                                file_id,
                                filename,
                                device,
                                inode,
                            } => gnunet_config::Configuration::default()
                                .expand_filename(&filename, &gnunet_config::ProcessEnvironment)
                                .map_err(|error| Arc::new(Error::Configuration(error)))
                                .and_then(|filename| {
                                    index
                                        .register_with(file_id, &filename, device, inode, |_| {
                                            !stop.load(Ordering::Acquire)
                                        })
                                        .map(|_| Output::Registered)
                                        .map_err(|e| Arc::new(Error::Index(Box::new(e))))
                                }),
                            Task::Remove(file_id) => index
                                .remove(&file_id)
                                .map(|_| Output::Removed)
                                .map_err(|e| Arc::new(Error::Index(Box::new(e)))),
                            Task::Next(after) => match index.entry_after(after.as_ref()) {
                                Ok(Some(entry)) => encode(Response::IndexEntry {
                                    file_id: entry.file_id,
                                    filename: entry.filename,
                                })
                                .map(|frame| Output::Entry {
                                    file_id: entry.file_id,
                                    frame,
                                }),
                                Ok(None) => encode(Response::IndexEnd).map(Output::End),
                                Err(e) => Err(Arc::new(Error::Index(Box::new(e)))),
                            },
                            Task::Resolve { query, record } => {
                                let mut bytes = Vec::new();
                                let length =
                                    gnunet_fs::content::BLOCK_BYTES + gnunet_fs::content::TAG_BYTES;
                                match bytes.try_reserve_exact(length) {
                                    Err(_) => {
                                        Err(Arc::new(Error::Protocol(ProtocolError::Capacity)))
                                    }
                                    Ok(()) => {
                                        bytes.resize(length, 0);
                                        match index.resolve(&query, &record, &mut bytes) {
                                            Ok(resolved) => {
                                                let length = resolved.bytes().len();
                                                bytes.truncate(length);
                                                Ok(Output::Resolved(bytes))
                                            }
                                            Err(e) => Err(Arc::new(Error::Index(Box::new(e)))),
                                        }
                                    }
                                }
                            }
                        }
                    };
                    match job.result.send(result) {
                        Ok(()) | Err(_) => {}
                    }
                }
                drop(index);
                match exited.send(()) {
                    Ok(()) | Err(()) => {}
                }
            })
            .map_err(|e| Arc::new(Error::Io(e)))?;
        Ok(Self {
            resolver: Some(resolver),
            sender: Some(sender),
            thread: Some(thread),
            exited: exit,
            exit_observed: false,
            wait: None,
            cancelled,
            joined: false,
        })
    }
    pub fn resolver(&self) -> Result<IndexResolver, Arc<Error>> {
        let shared = self
            .resolver
            .as_ref()
            .ok_or_else(|| Arc::new(Error::WorkerGone))?;
        Ok(IndexResolver {
            shared: Arc::downgrade(shared),
        })
    }
    pub fn submit(&self, task: Task) -> Result<Pending, Arc<Error>> {
        let sender = self
            .sender
            .as_ref()
            .ok_or_else(|| Arc::new(Error::WorkerGone))?
            .clone();
        let (result, receiver) = oneshot::channel();
        Ok(Pending {
            permit: Some(Box::pin(sender.reserve_owned())),
            job: Some(Job { task, result }),
            result: receiver,
        })
    }
    pub async fn join(&mut self) -> Result<(), Arc<Error>> {
        // Weak external ports cannot admit more work after shutdown starts.
        self.resolver = None;
        self.sender = None;
        std::future::poll_fn(|cx| {
            if self.joined {
                return Poll::Ready(Ok(()));
            }
            let Some(handle) = &self.thread else {
                return Poll::Ready(Err(Arc::new(Error::WorkerGone)));
            };
            if !handle.is_finished() {
                if !self.exit_observed {
                    if Pin::new(&mut self.exited).poll(cx).is_pending() {
                        return Poll::Pending;
                    }
                    self.exit_observed = true;
                }
                let wait = self.wait.get_or_insert_with(|| {
                    Box::pin(tokio::time::sleep(std::time::Duration::from_millis(10)))
                });
                if wait.as_mut().poll(cx).is_ready() {
                    self.wait = None;
                    cx.waker().wake_by_ref();
                }
                return Poll::Pending;
            }
            let Some(handle) = self.thread.take() else {
                return Poll::Ready(Err(Arc::new(Error::WorkerGone)));
            };
            let result = handle.join().map_err(|_| Arc::new(Error::WorkerPanicked));
            self.joined = true;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpolled_external_resolution_does_not_keep_worker_or_index_alive()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = std::env::temp_dir().join(format!(
            "gnunet-index-resolver-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        ));
        std::fs::create_dir(&directory)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let result = runtime.block_on(async {
            let index = Index::open(&directory, Default::default())?;
            let mut worker = Worker::start(index, 2)?;
            let resolver = worker.resolver()?;
            let mut resolution = resolver.resolve([0; 64], [0; 72])?;
            // Keep both public handles alive without polling the admitted read.
            // Neither may hold a sender which prevents the original thread EOF.
            tokio::time::timeout(std::time::Duration::from_secs(2), worker.join()).await??;
            if !worker.quiesced() {
                return Err("index worker did not actually join".into());
            }
            match resolver.resolve([0; 64], [0; 72]) {
                Err(error) if matches!(error.as_ref(), Error::WorkerGone) => {}
                _ => return Err("weak resolver admitted work after worker shutdown".into()),
            }
            let original = std::future::poll_fn(|cx| resolution.poll(cx)).await;
            if !matches!(original, Err(error) if matches!(error.as_ref(), Error::Index(_))) {
                return Err("original invalid descriptor lost its actual index refusal".into());
            }
            let consumed = std::future::poll_fn(|cx| resolution.poll(cx)).await;
            if !matches!(consumed, Err(error) if matches!(error.as_ref(), Error::Protocol(ProtocolError::Stale))) {
                return Err("consumed resolution was polled as a new operation".into());
            }
            // The sole original WAL/Index has dropped despite live weak handles.
            drop(Index::open(&directory, Default::default())?);
            Ok::<(), Box<dyn std::error::Error>>(())
        });
        let cleanup = std::fs::remove_dir_all(&directory);
        result?;
        cleanup?;
        Ok(())
    }
}
