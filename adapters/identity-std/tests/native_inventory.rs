//! One actual Unix IPC/worker model, using only a published non-secret mock.
//! No entropy or real key is used. Helpers never open or hash persisted bytes;
//! only the production Store owns its newly marked mock-data directory.
#![cfg(unix)]
#![forbid(unsafe_code)]
use gnunet_identity::{Core, KeyType, SecretKeyView};
use gnunet_identity_host::{
    backend,
    server::{Limits, Ports, Progress, Server},
    worker::Worker,
};
use gnunet_service_runtime::{
    clock::SystemClock,
    credentials::UnixAccess,
    service::{Listener, ServiceOptions},
};
use gnunet_wire::official::identity::{Request, Response};
use std::{
    error::Error,
    future::{Future, poll_fn},
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
use zeroize::Zeroizing;
type Failure = Box<dyn Error>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> std::io::Result<Self> {
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let p =
            std::env::temp_dir().join(format!("identity-public-mock-{}-{n}", std::process::id()));
        std::fs::DirBuilder::new().mode(0o700).create(&p)?;
        Ok(Self(p))
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
async fn send(stream: &mut UnixStream, request: Request<'_>) -> Result<(), Failure> {
    let mut bytes = Zeroizing::new(vec![0; request.encoded_len()?]);
    request.encode(&mut bytes)?;
    stream.write_all(&bytes).await?;
    Ok(())
}
async fn frame(stream: &mut UnixStream) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut head = [0; 4];
    stream.read_exact(&mut head).await?;
    let len = usize::from(u16::from_be_bytes([head[0], head[1]]));
    if !(4..=128).contains(&len) {
        return Err("unexpected model frame size".into());
    }
    let mut bytes = Zeroizing::new(vec![0; len]);
    bytes[..4].copy_from_slice(&head);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert the actual mock response code"
)]
fn code(bytes: &[u8], expected: u32) -> Result<(), Failure> {
    assert!(matches!(Response::decode(bytes)?,Response::ResultCode{code} if code==expected));
    Ok(())
}
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assert the actual mock update fields"
)]
fn update(bytes: &[u8], name: Option<&[u8]>, mock: &[u8; 36]) -> Result<(), Failure> {
    match Response::decode(bytes)? {
        Response::Update { name: actual, key } => {
            assert_eq!(actual, name);
            assert_eq!(key.expose_serialized(), mock);
        }
        _ => return Err("expected actual update".into()),
    }
    Ok(())
}
async fn actor(path: PathBuf) -> Result<(), Failure> {
    let mut stream = UnixStream::connect(path).await?;
    send(&mut stream, Request::Start).await?;
    assert!(matches!(
        Response::decode(&frame(&mut stream).await?)?,
        Response::EndOfList
    ));
    // This is deliberately public structural test data, not a generated secret.
    let mut mock = [0x42; 36];
    mock[..4].copy_from_slice(&KeyType::Eddsa.value().to_be_bytes());
    send(
        &mut stream,
        Request::Create {
            name: b"alpha",
            key: SecretKeyView::new(&mock)?,
        },
    )
    .await?;
    code(&frame(&mut stream).await?, 0)?;
    update(&frame(&mut stream).await?, Some(b"alpha"), &mock)?;
    send(&mut stream, Request::LookupSuffix { name: b"www.alpha" }).await?;
    update(&frame(&mut stream).await?, Some(b"alpha"), &mock)?;
    send(
        &mut stream,
        Request::Rename {
            old: b"alpha",
            new: b"beta",
        },
    )
    .await?;
    update(&frame(&mut stream).await?, Some(b"beta"), &mock)?;
    code(&frame(&mut stream).await?, 0)?;
    send(&mut stream, Request::Lookup { name: b"alpha" }).await?;
    code(&frame(&mut stream).await?, 200)?;
    send(&mut stream, Request::Delete { name: b"beta" }).await?;
    update(&frame(&mut stream).await?, None, &mock)?;
    code(&frame(&mut stream).await?, 0)?;
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The model asserts original callback and persistence receipts while propagating setup failures"
)]
fn actual_original_mq_durable_mock_inventory_order() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let temporary = Temporary::new()?;
            let path = temporary.0.join("ipc");
            let listener = tokio::net::UnixListener::bind(&path)?;
            let listeners = [Listener::Unix(&listener)];
            let (mut store, loaded) = backend::Store::open(
                backend::Namespace::Identity,
                temporary.0.join("store"),
                backend::Limits { body_bytes: 1024 },
            )?;
            let pure = gnunet_identity::Limits {
                egos: 4,
                name_bytes: 64,
                snapshot_bytes: 16384,
            };
            let (core, generation) = Server::recover(&mut store, loaded, pure)?;
            assert_eq!(core.snapshot().egos().len(), 0);
            let mut worker = Worker::start(store)?;
            let mut server = Server::new(
                core,
                &mut worker,
                generation,
                Limits {
                    frame_bytes: 128,
                    output_bytes: 256,
                    io_slice_bytes: 3,
                    snapshot_body_bytes: 1024,
                    ..Limits::default()
                },
                Ports {
                    options: ServiceOptions::default(),
                    unix: UnixAccess {
                        match_uid: true,
                        match_gid: false,
                    },
                    clock: Arc::new(SystemClock),
                },
            )?;
            let mut peer = std::pin::pin!(actor(path));
            let result = tokio::time::timeout(
                Duration::from_secs(8),
                poll_fn(|cx| {
                    if let Poll::Ready(done) = peer.as_mut().poll(cx) {
                        return Poll::Ready(done);
                    }
                    match server.poll(cx, &listeners, None, &mut |_| {}) {
                        Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
                        Poll::Ready(Ok(Progress::Activity)) => {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                        Poll::Ready(Ok(_)) => Poll::Ready(Err("unexpected model stop".into())),
                        Poll::Pending => Poll::Pending,
                    }
                }),
            )
            .await;
            // Cleanup always runs even if the actor times out or observes a failure.
            let stopped = server.shutdown(|_| {}).await;
            result??;
            assert_eq!(stopped.report.committed, 3);
            assert_eq!(stopped.report.written, 9);
            assert_eq!(stopped.report.submitted, 3);
            assert!(stopped.failure.is_none());
            let joined = stopped.worker.ok_or("missing actual join")?;
            assert_eq!(joined.generation, 4);
            assert!(joined.failure.is_none());
            // Core type referenced directly to keep this example's dependency clear.
            let _empty = Core::new(pure, Vec::new())?;
            Ok(())
        })
}
