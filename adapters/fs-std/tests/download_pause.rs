//! Caller cancellation while the one original native FS query receives no reply.
#![cfg(all(unix, feature = "service"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Native cancellation test asserts original MQ retirement and no query replay"
)]
use gnunet_fs::Content;
use gnunet_fs_host::{
    Buffers, Control, Progress,
    ipc::EndpointSource,
    network::{DownloadOptions, Error},
};
use gnunet_types::AbsoluteTime;
use gnunet_wire::official::fs::{BlockType, Request};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    task::Poll,
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    net::UnixListener,
    time::{sleep, timeout},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Socket(PathBuf);
impl Drop for Socket {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_file(&self.0);
    }
}

#[test]
fn no_reply_fetch_observes_cancel_and_closes_one_original_query_before_deadline() -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            static NEXT: AtomicU64 = AtomicU64::new(1);
            let socket = Socket(std::env::temp_dir().join(format!(
                "gnunet-fs-pause-{}-{}.sock",
                std::process::id(), NEXT.fetch_add(1, Ordering::Relaxed)
            )));
            let listener = UnixListener::bind(&socket.0)?;
            let source = EndpointSource::unix(socket.0.clone());
            let policy = DownloadOptions {
                io_slice_bytes: 13,
                ..DownloadOptions::new(AbsoluteTime::from_micros(source.clock().sample()?.now.as_micros() + 300_000_000))
            };
            // No reply is supplied: this test concerns control/ownership, not
            // content authentication or a synthetic successful/empty result.
            let content = Content { key: [11; 64], query: [22; 64], size: 1 };
            let cancel = Arc::new(AtomicBool::new(false));
            let wanted = cancel.clone();
            let observed = Arc::new(AtomicUsize::new(0));
            let seen = observed.clone();
            let peer = async {
                let (mut stream, _) = listener.accept().await?;
                let mut first = [0; 112];
                stream.read_exact(&mut first).await?;
                assert!(matches!(Request::decode(&first)?, Request::Search(search)
                    if search.query == content.query && search.block_type == BlockType::DBLOCK));
                // Require multiple control observations with Continue. The
                // pending query must not be reconstructed on each observation.
                while seen.load(Ordering::SeqCst) < 3 {
                    sleep(Duration::from_millis(10)).await;
                }
                wanted.store(true, Ordering::SeqCst);
                let mut extra = [0];
                assert_eq!(stream.read(&mut extra).await?, 0);
                Ok::<_, Box<dyn std::error::Error>>(())
            };
            let run = async {
                let mut calls = 0;
                let mut output = Vec::new();
                let result = Buffers::new().download(source, content, &mut output, None, policy, |progress| {
                    assert_eq!(progress, Progress::default());
                    calls += 1;
                        observed.store(calls, Ordering::SeqCst);
                    if cancel.load(Ordering::SeqCst) { Control::Cancel } else { Control::Continue }
                }).await;
                assert!(matches!(result, Err(Error::Cancelled(progress)) if progress == Progress::default()));
                assert!(calls >= 4);
                assert!(output.is_empty());
                Ok::<_, Box<dyn std::error::Error>>(())
            };
            // The old implementation waits for its five-minute logical
            // deadline and fails this bound. The actual peer must see EOF too.
            timeout(Duration::from_secs(3), async { tokio::try_join!(run, peer) }).await??;
            let extra_connection = std::future::poll_fn(|cx| {
                Poll::Ready(listener.poll_accept(cx).is_ready())
            }).await;
            assert!(!extra_connection);
            Ok(())
        })
}
