//! Real cached-content authentication with caller-controlled async backpressure.
//! No socket or peer is created; destination acceptance is not durability.
#![cfg(feature = "service")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible transfer fixtures assert cancellation, exact retained prefixes and authenticated completion"
)]
use gnunet_fs_host::{
    Buffers, Control, Limits, Progress, Repository,
    ipc::EndpointSource,
    network::{DownloadOptions, Error},
};
use gnunet_types::AbsoluteTime;
use std::{
    cell::Cell,
    io,
    path::PathBuf,
    pin::Pin,
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::AsyncWrite;

struct FrozenClock;
impl gnunet_service_runtime::clock::RuntimeClock for FrozenClock {
    fn sample(&self) -> Result<gnunet_service_runtime::clock::ClockSample, gnunet_types::Error> {
        Ok(gnunet_service_runtime::clock::ClockSample {
            now: AbsoluteTime::from_micros(1_000_000),
            revision: 0,
        })
    }
    fn subscribe(
        &self,
    ) -> Result<Box<dyn gnunet_service_runtime::clock::ClockSubscription>, gnunet_types::Error>
    {
        gnunet_service_runtime::clock::RuntimeClock::subscribe(
            &gnunet_service_runtime::clock::SystemClock,
        )
    }
}

#[tokio::test(start_paused = true)]
async fn finite_download_stops_a_partial_sink_even_when_its_source_clock_stalls()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = Directory::new()?;
    let mut cache = Repository::open(&directory.0)?;
    let mut buffers = Buffers::new();
    let data = vec![7; 64];
    let published = buffers.publish(
        &mut io::Cursor::new(&data),
        data.len() as u64,
        &mut cache,
        Limits::default(),
        |_| Control::Continue,
    )?;
    let observation = Rc::new(Observation::default());
    let mut output = Destination {
        mode: Mode::CancelWrite,
        observation,
        bytes: Vec::new(),
        after_stop: 0,
        flushes: 0,
        continued_at_resume: 0,
    };
    // All ciphertext is local and authenticated. The unavailable socket is
    // unused; only the virtual original elapsed bound ends the pending sink.
    let source = EndpointSource::unix_with_clock(
        directory.0.join("unused.sock"),
        std::sync::Arc::new(FrozenClock),
    );
    let started = tokio::time::Instant::now();
    let result = buffers
        .download(
            source,
            published.content,
            &mut output,
            Some(&mut cache),
            DownloadOptions::new(AbsoluteTime::from_micros(1_100_000)),
            |_| Control::Continue,
        )
        .await;
    assert!(
        matches!(result, Err(Error::Deadline { first_io: None })),
        "a frozen source clock must not strand an already partial destination write"
    );
    assert_eq!(
        started.elapsed(),
        Duration::from_millis(100),
        "the original finite transfer allowance cannot be refreshed by progress polls"
    );
    assert_eq!(
        output.bytes,
        data[..7],
        "the destination retains its actual accepted prefix"
    );
    assert_eq!(
        output.flushes, 0,
        "an incomplete chunk must not reach destination completion"
    );
    Ok(())
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "fs-download-control-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
#[derive(Clone, Copy)]
enum Mode {
    CancelWrite,
    CancelFlush,
    Continue,
}
#[derive(Default)]
struct Observation {
    waiting: Cell<bool>,
    continued: Cell<u32>,
    stopped: Cell<bool>,
}
struct Destination {
    mode: Mode,
    observation: Rc<Observation>,
    bytes: Vec<u8>,
    after_stop: u32,
    flushes: u32,
    continued_at_resume: u32,
}
impl AsyncWrite for Destination {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.observation.stopped.get() {
            this.after_stop += 1;
        }
        let length = match this.mode {
            Mode::CancelWrite | Mode::Continue if this.bytes.is_empty() => bytes.len().min(7),
            Mode::CancelWrite => {
                this.observation.waiting.set(true);
                return Poll::Pending;
            }
            Mode::Continue if this.observation.continued.get() < 2 => {
                this.observation.waiting.set(true);
                return Poll::Pending;
            }
            Mode::Continue => {
                this.continued_at_resume = this.observation.continued.get();
                bytes.len()
            }
            Mode::CancelFlush => bytes.len(),
        };
        this.bytes.extend_from_slice(&bytes[..length]);
        Poll::Ready(Ok(length))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.observation.stopped.get() {
            this.after_stop += 1;
        }
        this.flushes += 1;
        if matches!(this.mode, Mode::CancelFlush) {
            this.observation.waiting.set(true);
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other(
            "download does not own destination shutdown",
        )))
    }
}

#[test]
fn stalled_write_flush_and_continued_partial_cursor_observe_original_control()
-> Result<(), Box<dyn std::error::Error>> {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let directory = Directory::new()?;
        let data: Vec<_> = (0..1024).map(|index| index as u8).collect();
        let mut cache = Repository::open(directory.0.join("cache"))?;
        let mut buffers = Buffers::new();
        let published = buffers.publish(&mut io::Cursor::new(&data), data.len() as u64, &mut cache, Limits::default(), |_| Control::Continue)?;
        for mode in [Mode::CancelWrite, Mode::CancelFlush, Mode::Continue] {
            let observation = Rc::new(Observation::default());
            let mut output = Destination { mode, observation: observation.clone(), bytes: Vec::new(), after_stop: 0, flushes: 0, continued_at_resume: 0 };
            // A missing endpoint must remain unused: every real encrypted block
            // is already in this held repository and is still authenticated.
            let source = EndpointSource::unix(directory.0.join("unused.sock"));
            let options = DownloadOptions::new(AbsoluteTime::from_micros(source.clock().sample()?.now.as_micros() + 5_000_000));
            let result = tokio::time::timeout(Duration::from_secs(2), buffers.download(source, published.content, &mut output, Some(&mut cache), options, |_| {
                if !observation.waiting.get() { return Control::Continue; }
                if matches!(mode, Mode::Continue) {
                    observation.continued.set(observation.continued.get() + 1);
                    Control::Continue
                } else {
                    observation.stopped.set(true);
                    Control::Cancel
                }
            })).await?;
            assert_eq!(output.after_stop, 0, "stop must precede further destination polling");
            match mode {
                Mode::CancelWrite => {
                    assert!(matches!(result, Err(Error::Cancelled(progress)) if progress == Progress::default()));
                    assert_eq!(output.bytes, data[..7]);
                    assert_eq!(output.flushes, 0);
                }
                Mode::CancelFlush => {
                    assert!(matches!(result, Err(Error::Cancelled(progress)) if progress.blocks == 1 && progress.plaintext_bytes == data.len() as u64));
                    assert_eq!(output.bytes, data);
                    assert!(output.flushes > 0);
                }
                Mode::Continue => {
                    let completed = result?;
                    assert_eq!(completed.verified.content(), published.content);
                    assert_eq!(completed.progress.plaintext_bytes, data.len() as u64);
                    assert_eq!(output.bytes, data, "the original write cursor must not replay its prefix");
                    assert!(output.continued_at_resume >= 2);
                    assert_eq!(output.flushes, 1);
                }
            }
        }
        Ok(())
    })
}
