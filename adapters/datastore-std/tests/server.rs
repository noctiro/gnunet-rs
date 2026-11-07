//! Actual Rust native service + official IPC + durable Rust storage.
//! These local peers are not unmodified-C interoperability acceptance.
#![cfg(all(unix, feature = "server"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Native service tests assert actual wire fields, worker settlement and durable restart"
)]
use gnunet_client::datastore::{self as pure, Request, Response};
use gnunet_client_host::{ConnectError, EndpointSource};
use gnunet_config::Configuration;
use gnunet_datastore::{Config, backend::Backend};
use gnunet_datastore_host::{
    Client, Limits as ClientLimits, Step, Taken,
    backend::{Limits as StoreLimits, Store},
    server::{Limits as ServerLimits, Progress, Server, UnixAccess},
};
use gnunet_service_runtime::{
    Activation, BoundListeners,
    clock::SystemClock,
    service::{Listener, ServiceOptions, ShutdownMode},
};
use gnunet_types::{Duration as Timeout, Error as ProtocolError};
use gnunet_wire::official::{AbsoluteTime, datastore::Data};
use std::{
    fs,
    future::{Future, poll_fn},
    io,
    os::unix::{ffi::OsStrExt, fs::PermissionsExt},
    path::{Path, PathBuf},
    pin::pin,
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
    time::{Instant, timeout},
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const WAIT: Duration = Duration::from_secs(3);

struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-datastore-service-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
        Ok(Self(path))
    }
    fn config(&self) -> TestResult<Configuration> {
        let mut config = Configuration::default();
        config.set_value(
            b"datastore",
            b"UNIXPATH",
            Some(self.0.join("service.sock").as_os_str().as_bytes()),
        )?;
        config.set_number(b"datastore", b"PORT", 0)?;
        Ok(config)
    }
    fn socket(&self) -> PathBuf {
        self.0.join("service.sock")
    }
    fn store(&self) -> PathBuf {
        self.0.join("storage")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
async fn server(store: Store) -> TestResult<Server> {
    Ok(Server::new(
        store,
        Config {
            quota_bytes: 1024 * 1024,
            ..Config::default()
        },
        ServerLimits {
            clients: 4,
            reservations: 8,
            worker_queue: 2,
            io_slice_bytes: 7,
            maintenance_interval: Duration::from_secs(3600),
        },
        ServiceOptions::default(),
        UnixAccess {
            match_uid: true,
            match_gid: false,
        },
        Arc::new(SystemClock),
    )
    .await?)
}
fn client<'id, 'slots, 'buffers>(
    instance: &'id mut pure::Instance,
    slots: &'slots mut [pure::Slot<'buffers>],
    reservations: &'slots mut [pure::ReservationSlot],
    socket: &Path,
) -> TestResult<Client<'id, 'slots, 'buffers>> {
    let core = pure::Client::new(
        instance,
        slots,
        reservations,
        pure::Limits {
            max_pending: 1,
            max_frame_bytes: 512,
            ..pure::Limits::default()
        },
    )?;
    Ok(Client::new(
        core,
        EndpointSource::unix(socket.to_owned()),
        ClientLimits {
            frame_bytes: 512,
            reply_frames: 1,
            reply_bytes: 512,
            io_slice_bytes: 5,
        },
    )?)
}
async fn exchange<'id>(
    client: &mut Client<'id, '_, '_>,
    server: &mut Server,
    listeners: &[Listener<'_>],
    request: Request<'_>,
    reservation: Option<pure::Reservation<'id>>,
) -> TestResult<Taken<'id>> {
    let operation = client.submit(request, reservation, Timeout(3_000_000))?;
    let until = Instant::now() + WAIT;
    loop {
        match client.take(operation) {
            Ok(answer) => return Ok(answer),
            Err(ConnectError::Protocol(ProtocolError::NotReady)) => {}
            Err(error) => return Err(error.into()),
        }
        // Both owners are polled once, even if the other is immediately ready.
        // The unfinished wait is dropped; all retained IO/jobs stay in its owner.
        let (service, native) = {
            let mut service = pin!(server.drive(listeners, Some(until), |_| {}));
            let mut native = pin!(client.drive(Some(until)));
            poll_fn(|cx| {
                let service = service.as_mut().poll(cx);
                let native = native.as_mut().poll(cx);
                if service.is_pending() && native.is_pending() {
                    return Poll::Pending;
                }
                Poll::Ready((
                    match service {
                        Poll::Ready(v) => Some(v),
                        Poll::Pending => None,
                    },
                    match native {
                        Poll::Ready(v) => Some(v),
                        Poll::Pending => None,
                    },
                ))
            })
            .await
        };
        if matches!(service, Some(Progress::Stopped | Progress::WaitDeadline)) {
            return Err(ProtocolError::Timeout.into());
        }
        if let Some(native) = native {
            match native? {
                Step::WaitDeadline => return Err(ProtocolError::Timeout.into()),
                Step::Unavailable(error) => return Err(error.into()),
                Step::ConnectRetry { error, .. } => return Err(error.into()),
                Step::Lost { .. } | Step::Closed => {
                    return Err(io::Error::other(
                        "original DATASTORE connection ended before response",
                    )
                    .into());
                }
                _ => {}
            }
        }
    }
}
fn status(answer: &Taken<'_>) -> TestResult<i32> {
    match answer.response()? {
        Some(Response::Status(status)) => Ok(status.code),
        _ => Err(io::Error::other("expected actual STATUS").into()),
    }
}
fn data<'a>(answer: &'a Taken<'_>) -> TestResult<Data<'a>> {
    match answer.response()? {
        Some(Response::Data(value)) => Ok(value),
        _ => Err(io::Error::other("expected actual DATA").into()),
    }
}
fn put<'a>(key: &'a [u8; 64], value: &'a [u8], reservation: u32) -> Data<'a> {
    Data {
        reservation,
        kind: 42,
        priority: 3,
        anonymity: 1,
        replication: 2,
        uid: 0,
        expiration: AbsoluteTime::NEVER,
        key,
        value,
    }
}
async fn stopped(server: &mut Server, dropped: bool) -> TestResult {
    server.request_shutdown(ShutdownMode::Immediate);
    let report = timeout(WAIT, server.shutdown(|_| {})).await?;
    assert!(report.worker_quiesced);
    assert_eq!(report.dropped_on_shutdown, dropped);
    if let Some(error) = report.failure {
        return Err(error.into());
    }
    Ok(())
}

#[test]
fn actual_client_roundtrip_selection_and_worker_joined_restart() -> TestResult {
    let directory = Directory::new()?;
    let config = directory.config()?;
    let key = [0x97; 64]; // Arbitrary DATASTORE keys need not hash their values.
    let body = b"\0native durable value\xff";
    let other = b"second value under the same key";
    runtime()?.block_on(async {
        let bound = BoundListeners::bind(&config, b"datastore", Activation::default()).await?;
        let listeners = bound.listeners();
        let mut service = server(Store::open(directory.store(), StoreLimits::default())?).await?;
        let original_uid = {
            let mut instance = pure::Instance::new();
            let mut frame = [0; 512];
            let mut slots = [pure::Slot::new(&mut frame)];
            let mut reservations = [pure::ReservationSlot::default(); 1];
            let mut native = client(
                &mut instance,
                &mut slots,
                &mut reservations,
                &directory.socket(),
            )?;
            let reserve = exchange(
                &mut native,
                &mut service,
                &listeners,
                Request::Reserve {
                    amount: body.len() as u64 + 10,
                    entries: 2,
                },
                None,
            )
            .await?;
            let authority = reserve
                .completion
                .reservation
                .ok_or("positive RESERVE authority missing")?;
            assert_eq!(status(&reserve)?, i32::try_from(authority.value())?);
            assert_eq!(
                status(
                    &exchange(
                        &mut native,
                        &mut service,
                        &listeners,
                        Request::Put(put(&key, body, authority.value())),
                        Some(authority)
                    )
                    .await?
                )?,
                1
            );
            assert_eq!(
                status(
                    &exchange(
                        &mut native,
                        &mut service,
                        &listeners,
                        Request::Release {
                            reservation: authority.value()
                        },
                        Some(authority)
                    )
                    .await?
                )?,
                1
            );
            let duplicate = Data {
                kind: 999,
                anonymity: 0,
                priority: 5,
                replication: 4,
                ..put(&key, body, 0)
            };
            assert_eq!(
                status(
                    &exchange(
                        &mut native,
                        &mut service,
                        &listeners,
                        Request::Put(duplicate),
                        None
                    )
                    .await?
                )?,
                1
            );
            let answer = exchange(
                &mut native,
                &mut service,
                &listeners,
                Request::Get {
                    key: Some(&key),
                    kind: 42,
                    next_uid: 0,
                    random: false,
                },
                None,
            )
            .await?;
            let first = data(&answer)?;
            let uid = first.uid;
            assert_ne!(uid, 0);
            assert_eq!(
                (
                    first.value,
                    first.priority,
                    first.anonymity,
                    first.replication
                ),
                (body.as_slice(), 8, 1, 6)
            );
            assert!(matches!(
                exchange(
                    &mut native,
                    &mut service,
                    &listeners,
                    Request::ZeroAnonymity {
                        kind: 42,
                        next_uid: 0
                    },
                    None
                )
                .await?
                .response()?,
                Some(Response::End)
            ));
            let second = Data {
                anonymity: 0,
                replication: 0,
                ..put(&key, other, 0)
            };
            assert_eq!(
                status(
                    &exchange(
                        &mut native,
                        &mut service,
                        &listeners,
                        Request::Put(second),
                        None
                    )
                    .await?
                )?,
                1
            );
            let answer = exchange(
                &mut native,
                &mut service,
                &listeners,
                Request::ZeroAnonymity {
                    kind: 42,
                    next_uid: 0,
                },
                None,
            )
            .await?;
            assert_eq!(data(&answer)?.value, other);
            assert!(data(&answer)?.uid > uid);
            let answer = exchange(
                &mut native,
                &mut service,
                &listeners,
                Request::Replication,
                None,
            )
            .await?;
            assert_eq!((data(&answer)?.uid, data(&answer)?.replication), (uid, 6));
            assert_eq!(
                status(
                    &exchange(
                        &mut native,
                        &mut service,
                        &listeners,
                        Request::Remove {
                            key: &key,
                            value: other
                        },
                        None
                    )
                    .await?
                )?,
                1
            );
            assert_eq!(
                status(
                    &exchange(
                        &mut native,
                        &mut service,
                        &listeners,
                        Request::Remove {
                            key: &key,
                            value: other
                        },
                        None
                    )
                    .await?
                )?,
                0
            );
            let answer = exchange(
                &mut native,
                &mut service,
                &listeners,
                Request::Get {
                    key: None,
                    kind: 0,
                    next_uid: uid,
                    random: false,
                },
                None,
            )
            .await?;
            assert_eq!(data(&answer)?.uid, uid);
            assert!(matches!(
                exchange(
                    &mut native,
                    &mut service,
                    &listeners,
                    Request::Get {
                        key: Some(&key),
                        kind: 0,
                        next_uid: uid + 1,
                        random: false
                    },
                    None
                )
                .await?
                .response()?,
                Some(Response::End)
            ));
            native.close()?;
            uid
        };
        stopped(&mut service, false).await?;
        assert_eq!(service.report().accepted, 1);
        drop(service);
        drop(listeners);
        drop(bound);

        // A fresh worker and socket reopen the on-disk WAL after the old worker
        // actually joined. Returned UID and replication decrement survive.
        let bound = BoundListeners::bind(&config, b"datastore", Activation::default()).await?;
        let listeners = bound.listeners();
        let mut service = server(Store::open(directory.store(), StoreLimits::default())?).await?;
        let mut instance = pure::Instance::new();
        let mut frame = [0; 512];
        let mut slots = [pure::Slot::new(&mut frame)];
        let mut reservations = [];
        let mut native = client(
            &mut instance,
            &mut slots,
            &mut reservations,
            &directory.socket(),
        )?;
        let answer = exchange(
            &mut native,
            &mut service,
            &listeners,
            Request::Get {
                key: Some(&key),
                kind: 42,
                next_uid: 0,
                random: false,
            },
            None,
        )
        .await?;
        let persisted = data(&answer)?;
        assert_eq!(
            (persisted.uid, persisted.value, persisted.replication),
            (original_uid, body.as_slice(), 5)
        );
        native.close()?;
        stopped(&mut service, false).await?;
        Ok(())
    })
}

// Retain one original raw IO future while driving the actual service. This
// avoids a spawned test server that could outlive its fixture on failure.
async fn with_server<T>(
    server: &mut Server,
    listeners: &[Listener<'_>],
    io: impl Future<Output = io::Result<T>>,
) -> TestResult<T> {
    enum Step<T> {
        Io(Result<io::Result<T>, tokio::time::error::Elapsed>),
        Server(Progress),
    }
    let mut io = pin!(timeout(WAIT, io));
    loop {
        let mut service = pin!(server.drive(listeners, None, |_| {}));
        match poll_fn(|cx| {
            if let Poll::Ready(value) = io.as_mut().poll(cx) {
                return Poll::Ready(Step::Io(value));
            }
            service.as_mut().poll(cx).map(Step::Server)
        })
        .await
        {
            Step::Io(value) => return Ok(value??),
            Step::Server(Progress::Stopped | Progress::WaitDeadline) => {
                return Err(io::Error::other("service stopped during original IO").into());
            }
            Step::Server(_) => {}
        }
    }
}
fn frame(request: Request<'_>) -> Result<Vec<u8>, ProtocolError> {
    let mut frame = vec![0; request.encoded_len()?];
    request.encode(&mut frame)?;
    Ok(frame)
}
async fn read_frame(socket: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    socket.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if length < 4 {
        return Err(io::Error::other("invalid service frame length"));
    }
    let mut frame = vec![0; length];
    frame[..4].copy_from_slice(&header);
    socket.read_exact(&mut frame[4..]).await?;
    Ok(frame)
}
#[test]
fn same_mq_drop_has_no_ack_and_clears_only_at_actual_shutdown() -> TestResult {
    let directory = Directory::new()?;
    let config = directory.config()?;
    let key = [0x6b; 64];
    let body = b"DROP is deferred until service shutdown";
    runtime()?.block_on(async {
        let bound = BoundListeners::bind(&config, b"datastore", Activation::default()).await?;
        let listeners = bound.listeners();
        let mut service = server(Store::open(directory.store(), StoreLimits::default())?).await?;
        let mut socket = with_server(
            &mut service,
            &listeners,
            UnixStream::connect(directory.socket()),
        )
        .await?;
        let input = frame(Request::Put(put(&key, body, 0)))?;
        let answer = with_server(&mut service, &listeners, async {
            socket.write_all(&input).await?;
            read_frame(&mut socket).await
        })
        .await?;
        assert!(matches!(Response::decode(&answer)?, Response::Status(status) if status.code == 1));
        let mut pipeline = frame(Request::Drop)?;
        pipeline.extend_from_slice(&frame(Request::Get {
            key: Some(&key),
            kind: 42,
            next_uid: 0,
            random: false,
        })?);
        let answer = with_server(&mut service, &listeners, async {
            socket.write_all(&pipeline).await?;
            read_frame(&mut socket).await
        })
        .await?;
        // If DROP emitted an ACK this would be STATUS, and if it immediately
        // removed records this would be END. Only the subsequent GET emits DATA.
        assert!(matches!(Response::decode(&answer)?, Response::Data(value) if value.value == body));
        assert!(!service.report().dropped_on_shutdown);
        stopped(&mut service, true).await?;
        assert_eq!(service.report().requests, 3);
        assert_eq!(service.report().replies, 2);
        drop(service);
        drop(socket);
        let store = Store::open(directory.store(), StoreLimits::default())?;
        assert_eq!(store.usage().entries, 0);
        assert_eq!(store.usage().value_bytes, 0);
        Ok(())
    })
}
