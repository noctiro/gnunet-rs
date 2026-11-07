//! One controlled original-MQ ownership model. Every key-shaped field is a
//! published synthetic mock below; no key generation, derivation, hash, real key
//! file or C process participates. This is not crypto/interoperability evidence.
#![cfg(unix)]
use gnunet_identity_client_host::{
    Client, EndpointSource, Error as NativeError, Instance, Limits, LocalReason, Lookup,
    LookupOutcome, LookupProgress, Outcome, Progress, SecretKey, Submission,
    clock::{ClockSample, ClockSubscription, RuntimeClock, SystemClock},
    ipc::{Request, Response, SecretKeyView},
};
use gnunet_types::Error as Fault;
use gnunet_wire::official::MessageHeader;
use std::{
    error::Error,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::Instant,
};
use zeroize::Zeroizing;
type Failure = Box<dyn Error + Send + Sync>;
struct FailingClock(AtomicBool);
impl RuntimeClock for FailingClock {
    fn sample(&self) -> Result<ClockSample, Fault> {
        if self.0.load(Ordering::Relaxed) {
            Err(Fault::NotReady)
        } else {
            SystemClock.sample()
        }
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Fault> {
        SystemClock.subscribe()
    }
}
// Public nonsecret mock serialization, deliberately never fed to public_key or
// any cryptographic operation. Only the type tag and bytes' ownership matter.
const MOCK_A: [u8; 36] = [
    0, 1, 0, 20, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1,
];
const MOCK_B: [u8; 36] = [
    0, 1, 0, 20, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2,
];
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Result<Self, Failure> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!("gic-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
async fn frame(stream: &mut UnixStream) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let mut bytes = Zeroizing::new(vec![0; MessageHeader::decode(&header)?.size()]);
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn send(stream: &mut UnixStream, response: Response<'_>) -> Result<(), Failure> {
    let mut bytes = Zeroizing::new(vec![0; response.encoded_len()?]);
    response.encode(&mut bytes)?;
    for part in bytes.chunks(7) {
        stream.write_all(part).await?;
    }
    Ok(())
}
async fn eof(stream: &mut UnixStream) -> Result<(), Failure> {
    let mut byte = [0];
    assert_eq!(stream.read(&mut byte).await?, 0);
    Ok(())
}
async fn actor(listener: UnixListener) -> Result<(), Failure> {
    let (mut stream, _) = listener.accept().await?;
    assert!(matches!(
        Request::decode(&frame(&mut stream).await?)?,
        Request::Start
    ));
    send(
        &mut stream,
        Response::Update {
            name: Some(b"alice"),
            key: SecretKeyView::new(&MOCK_A)?,
        },
    )
    .await?;
    send(&mut stream, Response::EndOfList).await?;
    assert!(matches!(
        Request::decode(&frame(&mut stream).await?)?,
        Request::Create { name: b"born", .. }
    ));
    send(&mut stream, Response::ResultCode { code: 0 }).await?;
    send(
        &mut stream,
        Response::Update {
            name: Some(b"born"),
            key: SecretKeyView::new(&MOCK_B)?,
        },
    )
    .await?;
    assert!(matches!(
        Request::decode(&frame(&mut stream).await?)?,
        Request::Rename {
            old: b"alice",
            new: b"renamed"
        }
    ));
    send(
        &mut stream,
        Response::Update {
            name: Some(b"renamed"),
            key: SecretKeyView::new(&MOCK_A)?,
        },
    )
    .await?;
    send(&mut stream, Response::ResultCode { code: 0 }).await?;
    assert!(matches!(
        Request::decode(&frame(&mut stream).await?)?,
        Request::Delete { name: b"renamed" }
    ));
    send(
        &mut stream,
        Response::Update {
            name: None,
            key: SecretKeyView::new(&MOCK_A)?,
        },
    )
    .await?;
    send(&mut stream, Response::ResultCode { code: 0 }).await?;
    assert!(matches!(
        Request::decode(&frame(&mut stream).await?)?,
        Request::Rename {
            old: b"cancelled-old",
            new: b"cancelled-new"
        }
    ));
    send(&mut stream, Response::ResultCode { code: 0 }).await?;
    assert!(matches!(
        Request::decode(&frame(&mut stream).await?)?,
        Request::Delete { name: b"lost" }
    ));
    drop(stream); // Original exposed mutation has no result and must not replay.
    let (mut fresh, _) = listener.accept().await?;
    assert!(matches!(
        Request::decode(&frame(&mut fresh).await?)?,
        Request::Start
    ));
    send(
        &mut fresh,
        Response::Update {
            name: Some(b"born"),
            key: SecretKeyView::new(&MOCK_B)?,
        },
    )
    .await?;
    send(&mut fresh, Response::EndOfList).await?;
    eof(&mut fresh).await?; // Any replayed DELETE would violate this exact EOF.
    let (mut exact, _) = listener.accept().await?;
    assert!(matches!(
        Request::decode(&frame(&mut exact).await?)?,
        Request::Lookup { name: b"ALICE" }
    ));
    send(
        &mut exact,
        Response::Update {
            name: Some(b"alice"),
            key: SecretKeyView::new(&MOCK_A)?,
        },
    )
    .await?;
    eof(&mut exact).await?;
    let (mut suffix, _) = listener.accept().await?;
    assert!(matches!(
        Request::decode(&frame(&mut suffix).await?)?,
        Request::LookupSuffix { name: b"x.missing" }
    ));
    send(&mut suffix, Response::ResultCode { code: 200 }).await?;
    eof(&mut suffix).await?;
    Ok(())
}
async fn model() -> Result<(), Failure> {
    let scratch = Scratch::new()?;
    let path = scratch.0.join("s");
    let listener = UnixListener::bind(&path)?;
    let server = tokio::spawn(actor(listener));
    let clock_control = Arc::new(FailingClock(AtomicBool::new(false)));
    let clock: Arc<dyn RuntimeClock> = clock_control.clone();
    let domain = Instance::new();
    let limits = Limits {
        io_slice_bytes: 1,
        retirement_grace: Duration::from_secs(2),
        ..Limits::default()
    };
    let mut client = Client::monitor(
        &domain,
        EndpointSource::unix_with_clock(path.clone(), clock.clone()),
        limits,
    )?;
    let until = clock
        .sample()?
        .now
        .as_micros()
        .checked_add(6_000_000)
        .ok_or(Fault::Overflow)?;
    let budget = Some(Instant::now() + Duration::from_secs(7));
    let alice = loop {
        if let Progress::Initialized(_) = client.drive(budget).await? {
            break client.egos().next().ok_or(Fault::NotFound)?.ego();
        }
    };
    assert_eq!(client.ego(alice)?.name(), b"alice");
    let unsent = client.delete(b"never-exposed", until)?;
    client.cancel(unsent)?;
    loop {
        if let Progress::Completed(c) = client.drive(budget).await? {
            assert_eq!(c.operation, unsent);
            assert!(matches!(
                c.outcome,
                Outcome::Local {
                    reason: LocalReason::Cancelled,
                    submission: Submission::Unsent,
                    ..
                }
            ));
            break;
        }
    }
    let create = client.create(b"born", SecretKey::from_serialized(&MOCK_B)?, until)?;
    loop {
        if let Progress::Completed(c) = client.drive(budget).await? {
            assert_eq!(c.operation, create);
            assert!(matches!(
                c.outcome,
                Outcome::Result {
                    code: 0,
                    created: Some(_)
                }
            ));
            break;
        }
    }
    let rename = client.rename(b"alice", b"renamed", until)?;
    loop {
        if let Progress::Completed(c) = client.drive(budget).await? {
            assert_eq!(c.operation, rename);
            assert!(matches!(c.outcome, Outcome::Result { code: 0, .. }));
            break;
        }
    }
    assert_eq!(client.ego(alice)?.name(), b"renamed");
    let delete = client.delete(b"renamed", until)?;
    loop {
        if let Progress::Completed(c) = client.drive(budget).await? {
            assert_eq!(c.operation, delete);
            assert!(matches!(c.outcome, Outcome::Result { code: 0, .. }));
            break;
        }
    }
    assert!(matches!(
        client.ego(alice),
        Err(NativeError::Protocol(Fault::StaleGeneration))
    ));
    let cancelled = client.rename(b"cancelled-old", b"cancelled-new", until)?;
    loop {
        if matches!(
            client.drive(budget).await?,
            Progress::Activity {
                written_bytes: 1,
                ..
            }
        ) {
            break;
        }
    }
    client.cancel(cancelled)?;
    loop {
        if let Progress::Completed(c) = client.drive(budget).await? {
            assert_eq!(c.operation, cancelled);
            assert!(matches!(
                c.outcome,
                Outcome::Local {
                    reason: LocalReason::Cancelled,
                    submission: Submission::Written { .. },
                    result_code: Some(0),
                    ..
                }
            ));
            break;
        }
    }
    let born = client.egos().next().ok_or(Fault::NotFound)?.ego();
    let old = client.epoch();
    let lost = client.delete(b"lost", until)?;
    loop {
        if let Progress::Completed(c) = client.drive(budget).await? {
            assert_eq!(c.operation, lost);
            assert!(matches!(
                c.outcome,
                Outcome::Local {
                    reason: LocalReason::Lost,
                    submission: Submission::Written { .. },
                    ..
                }
            ));
            break;
        }
    }
    assert!(matches!(
        client.ego(born),
        Err(NativeError::Protocol(Fault::StaleGeneration))
    ));
    loop {
        if matches!(client.drive(budget).await?, Progress::Initialized(_)) {
            break;
        }
    }
    assert_ne!(client.epoch(), old);
    assert_ne!(client.egos().next().ok_or(Fault::NotFound)?.ego(), born);
    let recovered = client.egos().next().ok_or(Fault::NotFound)?.ego();
    clock_control.0.store(true, Ordering::Relaxed);
    assert!(matches!(
        client.delete(b"clock-fault-no-request", until),
        Err(NativeError::Protocol(Fault::NotReady))
    ));
    assert!(client.epoch().is_none());
    assert!(client.ego(recovered).is_err());
    assert!(matches!(
        client.drive(budget).await?,
        Progress::Lost { report, .. } if report.egos == 1
    ));
    clock_control.0.store(false, Ordering::Relaxed);
    let _loss = client.close();
    let mut exact = Lookup::exact(
        &domain,
        EndpointSource::unix_with_clock(path.clone(), clock.clone()),
        b"ALICE",
        until,
        limits,
    )?;
    loop {
        if let LookupProgress::Finished { outcome, .. } = exact.drive(budget).await? {
            let LookupOutcome::Found(identity) = outcome else {
                return Err(Fault::Malformed.into());
            };
            assert_eq!(identity.name(), b"alice");
            assert!(format!("{identity:?}").contains("[REDACTED]"));
            assert!(exact.epoch().is_none());
            break;
        }
    }
    let mut suffix = Lookup::by_suffix(
        &domain,
        EndpointSource::unix_with_clock(path, clock),
        b"x.missing",
        until,
        limits,
    )?;
    loop {
        if let LookupProgress::Finished { outcome, .. } = suffix.drive(budget).await? {
            assert!(matches!(outcome, LookupOutcome::ResultCode(200)));
            break;
        }
    }
    server.await??;
    Ok(())
}
#[test]
fn original_fifo_monitor_cancel_loss_and_lookup() -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async { tokio::time::timeout(Duration::from_secs(8), model()).await? })
}
