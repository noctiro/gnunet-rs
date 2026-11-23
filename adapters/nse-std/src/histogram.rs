//! Optional bounded writer for the official NSE receive-time stream.
use gnunet_config::{Configuration, ProcessEnvironment};
use gnunet_native::filesystem::{Directory, close, private_single_file_identity};
use std::{
    ffi::OsStr,
    fs::File,
    io::{self, Write},
    path::{Path, PathBuf},
    sync::mpsc::{Receiver, SyncSender, sync_channel},
    time::Duration,
};
use tokio::{sync::oneshot, time::Instant};

const QUEUED: usize = 4096;
const BATCH_BYTES: usize = 1024;
const SHUTDOWN_GRACE: Duration = Duration::from_secs(2);

/// Original native error category and platform code from the histogram worker.
#[derive(Clone, Copy, Debug)]
pub struct IoFailure {
    /// Native error category.
    pub kind: io::ErrorKind,
    /// Original native code, where one exists.
    pub raw: Option<i32>,
}
impl From<io::Error> for IoFailure {
    fn from(error: io::Error) -> Self {
        Self {
            kind: error.kind(),
            raw: error.raw_os_error(),
        }
    }
}

/// Independent optional recorder refusal or original write failure.
#[derive(Clone, Copy, Debug)]
pub enum Failure {
    /// Present histogram path could not be expanded.
    Configuration,
    /// The single native writer could not be started.
    Start(IoFailure),
    /// The selected output could not be opened and qualified.
    Open(IoFailure),
    /// An original write or flush failed, possibly after a partial write.
    Write(IoFailure),
    /// The original output could not be closed cleanly.
    Close(IoFailure),
    /// The original worker ended without reporting its output.
    WorkerLost,
    /// The worker could not be observed closing before the original shutdown bound.
    TimedOut,
}

/// Actual optional recording observations. Successful writes do not assert disk durability.
#[derive(Clone, Copy, Debug, Default)]
pub struct Report {
    /// Complete records from a clean run of the original writer.
    pub written: Option<u64>,
    /// Records refused by the bounded queue or a stopped worker.
    pub dropped: u64,
    /// Actual setup, write or worker retirement failure.
    pub failure: Option<Failure>,
    /// Independent close failure following an earlier write failure.
    pub cleanup: Option<IoFailure>,
}
impl Report {
    pub(crate) fn refused(failure: Failure) -> Self {
        Self {
            failure: Some(failure),
            ..Self::default()
        }
    }
}

pub(crate) struct Recorder {
    incoming: SyncSender<u64>,
    result: oneshot::Receiver<Report>,
    dropped: u64,
}
pub(crate) struct Drain {
    result: oneshot::Receiver<Report>,
    dropped: u64,
    until: Instant,
}
impl Recorder {
    pub(crate) fn configured(config: &Configuration) -> Option<Result<Self, Failure>> {
        let directory = config.get(b"NSE", b"HISTOGRAM_DIR")?;
        if directory.is_empty() {
            return None;
        }
        Some(
            config
                .get_filename(b"NSE", b"HISTOGRAM_DIR", &ProcessEnvironment)
                .map_err(|_| Failure::Configuration)
                .and_then(Self::start),
        )
    }

    fn start(directory: PathBuf) -> Result<Self, Failure> {
        let (incoming, worker) = sync_channel(QUEUED);
        let (send, result) = oneshot::channel();
        let thread = std::thread::Builder::new()
            .name("nse-histogram".to_owned())
            .spawn(move || {
                let report = write_histogram(&directory, worker);
                let _receiver_closed = send.send(report);
            })
            .map_err(|error| Failure::Start(error.into()))?;
        drop(thread);
        Ok(Self {
            incoming,
            result,
            dropped: 0,
        })
    }

    pub(crate) fn receive(&mut self, now: u64) {
        if self.incoming.try_send(now).is_err() {
            self.dropped = self.dropped.saturating_add(1);
        }
    }

    pub(crate) fn stop(self) -> Drain {
        drop(self.incoming);
        Drain {
            result: self.result,
            dropped: self.dropped,
            until: Instant::now() + SHUTDOWN_GRACE,
        }
    }
}
impl Drain {
    pub(crate) async fn finish(self) -> Report {
        let mut report = match tokio::time::timeout_at(self.until, self.result).await {
            Ok(Ok(report)) => report,
            Ok(Err(_)) => Report::refused(Failure::WorkerLost),
            Err(_) => Report::refused(Failure::TimedOut),
        };
        report.dropped = report.dropped.saturating_add(self.dropped);
        report
    }
}

fn open(directory: &Path) -> io::Result<(File, File)> {
    let name = OsStr::new("timestamps");
    gnunet_service_runtime::private_parents(&directory.join(name))?;
    let directory = Directory::open(directory)?;
    directory.validate_namespace()?;
    // Windows byte-range locks prevent other handles from reading a locked
    // data file. Put the writer fence on its own private name.
    let guard_name = OsStr::new(".timestamps-lock");
    let guard = open_private(&directory, guard_name)?;
    guard.try_lock().map_err(io::Error::from)?;
    if !directory.same_file(guard_name, &guard)? {
        return Err(io::Error::other("original NSE histogram lock name changed"));
    }
    let file = open_private(&directory, name)?;
    file.set_len(0)?;
    Ok((file, guard))
}

fn open_private(directory: &Directory, name: &OsStr) -> io::Result<File> {
    let file = match directory.create_private_file(name) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            directory.open_file_for_update(name)?
        }
        Err(error) => return Err(error),
    };
    private_single_file_identity(&file)?;
    if !directory.same_file(name, &file)? {
        return Err(io::Error::other("original NSE histogram name changed"));
    }
    Ok(file)
}

fn write_histogram(directory: &Path, worker: Receiver<u64>) -> Report {
    let (mut file, guard) = match open(directory) {
        Ok(files) => files,
        Err(error) => return Report::refused(Failure::Open(error.into())),
    };
    let result = write_samples(&mut file, worker);
    let file_closed = close(file);
    let guard_closed = close(guard);
    let close = file_closed.and(guard_closed).err().map(IoFailure::from);
    match result {
        Ok(written) => Report {
            written: Some(written),
            failure: close.map(Failure::Close),
            ..Report::default()
        },
        Err(error) => Report {
            failure: Some(Failure::Write(error.into())),
            cleanup: close,
            ..Report::default()
        },
    }
}

fn write_samples(output: &mut File, worker: Receiver<u64>) -> io::Result<u64> {
    let mut written = 0_u64;
    let mut batch = [0_u8; BATCH_BYTES];
    while let Ok(first) = worker.recv() {
        let mut used = 0;
        for (slot, sample) in batch
            .as_chunks_mut::<8>()
            .0
            .iter_mut()
            .zip(std::iter::once(first).chain(worker.try_iter()))
        {
            *slot = sample.to_be_bytes();
            used += slot.len();
        }
        output.write_all(&batch[..used])?;
        written = written.saturating_add((used / 8) as u64);
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_stream_is_readable_before_recorder_shutdown() -> io::Result<()> {
        let directory = crate::test_support::Directory::new()?;
        let (mut output, guard) = open(&directory.0)?;
        output.write_all(b"previous run")?;
        close(output)?;
        close(guard)?;

        let mut recorder = Recorder::start(directory.0.clone())
            .map_err(|error| io::Error::other(format!("{error:?}")))?;
        let samples = [0x0001_0203_0405_0607_u64, 0x8899_aabb_ccdd_eeff_u64];
        let expected = samples
            .into_iter()
            .flat_map(u64::to_be_bytes)
            .collect::<Vec<_>>();
        for sample in samples {
            recorder.receive(sample);
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?
            .block_on(async {
                tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        let actual = std::fs::read(directory.0.join("timestamps"))?;
                        if actual == expected {
                            break Ok::<(), io::Error>(());
                        }
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                })
                .await??;
                let report = recorder.stop().finish().await;
                if report.written != Some(2) || report.failure.is_some() || report.dropped != 0 {
                    return Err(io::Error::other(format!(
                        "unexpected timestamp report: {report:?}"
                    )));
                }
                Ok(())
            })
    }
}
