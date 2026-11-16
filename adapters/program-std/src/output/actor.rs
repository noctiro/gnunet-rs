//! Sole I/O owner and its independently driven stop/deadline observation.
use super::{
    CHUNK, Encoding,
    state::{Cause, Counts},
};
use gnunet_service_runtime::signals::Termination;
use std::{
    future::{Future, poll_fn},
    io::{self, Write},
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    task::Poll,
    time::Instant,
};
use tokio::{sync::mpsc::Receiver, task::JoinHandle};
// Also covers thread-admission failure and unwinding: a runtime with an
// outstanding blocking call must never perform an implicit unbounded join.
pub(super) struct Background(pub Option<tokio::runtime::Runtime>);
impl Drop for Background {
    fn drop(&mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}
pub(super) struct Work {
    pub bytes: Vec<u8>,
    pub encoding: Encoding,
    pub deadline: Instant,
    pub observe_stop: bool,
    pub done: mpsc::SyncSender<Reply>,
}
pub(super) struct Buffer {
    pub bytes: Vec<u8>,
    pub result: io::Result<()>,
}
pub(super) struct Completed {
    output: Box<dyn Write + Send>,
    buffer: Buffer,
}
pub(super) enum Reply {
    Done(Buffer),
    Refused {
        cause: Cause,
        pending: Option<JoinHandle<Completed>>,
    },
}
enum Observation {
    Complete(Result<Completed, tokio::task::JoinError>),
    Refused(Cause),
}

pub(super) async fn run(
    output: impl Write + Send + 'static,
    mut receiver: Receiver<Work>,
    counts: Arc<Counts>,
) {
    let mut output: Box<dyn Write + Send> = Box::new(output);
    // Subscribe only when output work is first admitted; command setup keeps
    // its own native stop lifecycle. No synthetic Ctrl-C or timer becomes stop.
    let mut signals = None;
    while let Some(work) = receiver.recv().await {
        let Work {
            bytes,
            encoding,
            deadline,
            observe_stop,
            done,
        } = work;
        if observe_stop && signals.is_none() {
            match Termination::new() {
                Ok(source) => signals = Some(source),
                Err(error) => {
                    let _undelivered = done.send(Reply::Refused {
                        cause: Cause::StopSource(error),
                        pending: None,
                    });
                    return;
                }
            }
        }
        if Instant::now() >= deadline {
            let _undelivered = done.send(Reply::Refused {
                cause: Cause::Deadline,
                pending: None,
            });
            return;
        }
        let observed = Arc::clone(&counts);
        let retired = Arc::new(AtomicBool::new(false));
        let worker_retired = Arc::clone(&retired);
        let mut job = tokio::task::spawn_blocking(move || {
            let result = transfer(
                &mut output,
                &bytes,
                encoding,
                &observed,
                deadline,
                &worker_retired,
            );
            Completed {
                output,
                buffer: Buffer { bytes, result },
            }
        });
        let mut timer = pin!(tokio::time::sleep_until(deadline.into()));
        let observation = poll_fn(|cx| {
            if observe_stop
                && let Some(signals) = &mut signals
                && let Poll::Ready(result) = signals.poll_stop(cx)
            {
                return Poll::Ready(Observation::Refused(match result {
                    Ok(()) => Cause::Stop,
                    Err(error) => Cause::StopSource(error),
                }));
            }
            if timer.as_mut().poll(cx).is_ready() {
                return Poll::Ready(Observation::Refused(Cause::Deadline));
            }
            if let Poll::Ready(result) = std::pin::Pin::new(&mut job).poll(cx) {
                return Poll::Ready(Observation::Complete(result));
            }
            Poll::Pending
        })
        .await;
        match observation {
            Observation::Complete(Ok(completed)) => {
                output = completed.output;
                let completed = completed.buffer;
                let failed = completed.result.is_err();
                if done.send(Reply::Done(completed)).is_err() || failed {
                    return;
                }
            }
            Observation::Complete(Err(error)) => {
                let _undelivered = done.send(Reply::Refused {
                    cause: Cause::Native(io::Error::other(error)),
                    pending: None,
                });
                return;
            }
            Observation::Refused(cause) => {
                retired.store(true, Ordering::Release);
                // This is the actual blocking job, not an async forwarding
                // task that runtime shutdown could cancel ahead of the I/O.
                let _undelivered = done.send(Reply::Refused {
                    cause,
                    pending: Some(job),
                });
                return;
            }
        }
    }
}
fn transfer(
    output: &mut impl Write,
    bytes: &[u8],
    encoding: Encoding,
    counts: &Counts,
    deadline: Instant,
    retired: &AtomicBool,
) -> io::Result<()> {
    let text = match encoding {
        Encoding::Utf8 => Some(
            std::str::from_utf8(bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?,
        ),
        Encoding::Bytes => None,
    };
    let mut offset = 0;
    while offset < bytes.len() {
        let end = (offset + CHUNK).min(bytes.len());
        let end = text.map_or(end, |text| text.floor_char_boundary(end));
        let mut chunk = &bytes[offset..end];
        while !chunk.is_empty() {
            active(deadline, retired)?;
            match output.write(chunk) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(count) if count <= chunk.len() => {
                    counts.written(count as u64);
                    chunk = &chunk[count..];
                }
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "native writer exceeded input length",
                    ));
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error),
            }
        }
        offset = end;
    }
    active(deadline, retired)?;
    output.flush()?;
    counts.flushed();
    Ok(())
}
fn active(deadline: Instant, retired: &AtomicBool) -> io::Result<()> {
    if retired.load(Ordering::Acquire) || Instant::now() >= deadline {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "original output work retired; no further native call admitted",
        ))
    } else {
        Ok(())
    }
}
