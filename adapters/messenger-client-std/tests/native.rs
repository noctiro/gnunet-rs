//! One controlled actual Unix IPC model using fixed PUBLIC NONSECRET room,
//! hash/member arrays and opaque text. No crypto/key provider, key files, hash,
//! entropy, storage, C implementation or actual Messenger room service executes.
#![cfg(unix)]
use gnunet_messenger_client_host::{
    Client, EndpointSource, Instance, Kind, Limits, LossCause, Notification, Operation, Progress,
    Submission,
    ipc::{Request, Response, Room, SensitiveBytes},
};
use gnunet_types::Error as Fault;
use gnunet_wire::official::MessageHeader;
use std::{error::Error, path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
type Failure = Box<dyn Error + Send + Sync>;
const ROOM: [u8; 64] = [7; 64];
const HASH: [u8; 64] = [9; 64];
const EPOCH: [u8; 64] = [11; 64];
const DOOR: [u8; 32] = [3; 32];
const MEMBER: [u8; 32] = [5; 32];
const OPAQUE: &[u8] = b"PUBLIC MOCK encoded tail; no signed-message assertion";
fn room() -> Room<'static> {
    Room {
        door: &DOOR,
        key: &ROOM,
        previous: &HASH,
        epoch: &EPOCH,
    }
}
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Result<Self, Failure> {
        let n = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!("gmsc-{}-{n}", std::process::id()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
async fn frame(stream: &mut UnixStream) -> Result<Vec<u8>, Failure> {
    let mut h = [0; 4];
    stream.read_exact(&mut h).await?;
    let mut bytes = vec![0; MessageHeader::decode(&h)?.size()];
    bytes[..4].copy_from_slice(&h);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn send(stream: &mut UnixStream, response: Response<'_>) -> Result<(), Failure> {
    let mut bytes = vec![0; response.encoded_len()?];
    response.encode(
        gnunet_messenger_client_host::Profile::LITTLE_255,
        &mut bytes,
    )?;
    for part in bytes.chunks(3) {
        stream.write_all(part).await?;
    }
    Ok(())
}
async fn eof(stream: &mut UnixStream) -> Result<(), Failure> {
    let mut b = [0];
    assert_eq!(stream.read(&mut b).await?, 0);
    Ok(())
}
async fn actor(listener: UnixListener) -> Result<(), Failure> {
    let (mut s, _) = listener.accept().await?;
    assert!(matches!(
        Request::decode(&frame(&mut s).await?)?,
        Request::Create
    ));
    for index in 0..6 {
        let bytes = frame(&mut s).await?;
        let response = match (index, Request::decode(&bytes)?) {
            (
                0,
                Request::Open {
                    room: actual,
                    public_key: None,
                },
            ) => {
                assert_eq!(actual.key, &ROOM);
                send(
                    &mut s,
                    Response::MemberId {
                        key: &ROOM,
                        id: &MEMBER,
                        reset: 1,
                    },
                )
                .await?;
                Response::Open(room())
            }
            (
                1,
                Request::Entry {
                    room: actual,
                    public_key: None,
                },
            ) => {
                assert_eq!(actual.door, &DOOR);
                Response::Entry(room())
            }
            (2, Request::Send { key, message }) => {
                assert_eq!(key, &ROOM);
                assert_eq!(message.expose(), OPAQUE);
                Response::Receive {
                    key: &ROOM,
                    sender: &HASH,
                    context: &HASH,
                    hash: &HASH,
                    epoch: &EPOCH,
                    flags: 0x80000000,
                    message: SensitiveBytes::new(OPAQUE),
                }
            }
            (3, Request::Get { key, hash }) => {
                assert_eq!(key, &ROOM);
                assert_eq!(hash, &HASH);
                Response::Missing {
                    key: &ROOM,
                    hash: &HASH,
                }
            }
            (4, Request::Sync { room: actual }) => {
                assert_eq!(actual.previous, &HASH);
                Response::Sync(room())
            }
            (5, Request::Close { room: actual }) => {
                assert_eq!(actual.epoch, &EPOCH);
                Response::Close(room())
            }
            _ => return Err(Fault::Malformed.into()),
        };
        send(&mut s, response).await?;
    }
    assert!(matches!(
        Request::decode(&frame(&mut s).await?)?,
        Request::Destroy
    ));
    eof(&mut s).await?;
    // Another client is deliberately stopped after an actual positive OPEN
    // prefix; reconnect must contain a fresh CREATE and no old OPEN suffix.
    let (mut s, _) = listener.accept().await?;
    assert!(matches!(
        Request::decode(&frame(&mut s).await?)?,
        Request::Create
    ));
    let mut partial = Vec::new();
    s.read_to_end(&mut partial).await?;
    assert!(!partial.is_empty() && partial.len() < gnunet_messenger_client_host::ipc::ROOM_LEN);
    let (mut s, _) = listener.accept().await?;
    assert!(matches!(
        Request::decode(&frame(&mut s).await?)?,
        Request::Create
    ));
    assert!(matches!(
        Request::decode(&frame(&mut s).await?)?,
        Request::Destroy
    ));
    eof(&mut s).await?;
    // A fixed partial header is sufficient to start the actual first-byte bound.
    let (mut s, _) = listener.accept().await?;
    assert!(matches!(
        Request::decode(&frame(&mut s).await?)?,
        Request::Create
    ));
    s.write_all(&[0, 104]).await?;
    eof(&mut s).await?;
    Ok(())
}
async fn written<'a>(client: &mut Client<'a>, operation: Operation<'a>) -> Result<Kind, Failure> {
    loop {
        match client.progress().await? {
            Progress::Written {
                operation: actual,
                kind,
                ..
            } if actual == operation => return Ok(kind),
            Progress::Activity { .. } | Progress::Queued { .. } => {}
            event => return Err(format!("unexpected progress {event:?}").into()),
        }
    }
}
async fn notification(client: &mut Client<'_>) -> Result<Notification, Failure> {
    loop {
        match client.progress().await? {
            Progress::Notification {
                epoch,
                notification,
            } => {
                assert_eq!(Some(epoch), client.epoch());
                return Ok(notification);
            }
            Progress::Activity { .. } => {}
            event => return Err(format!("unexpected progress {event:?}").into()),
        }
    }
}
async fn connected(client: &mut Client<'_>) -> Result<(), Failure> {
    let Progress::Attached(epoch) = client.progress().await? else {
        return Err(Fault::NotReady.into());
    };
    assert_eq!(Some(epoch), client.epoch());
    let now = client.clock().sample()?.now.as_micros();
    let expires = now.checked_add(2_000_000).ok_or(Fault::Overflow)?;
    let hard = tokio::time::Instant::now() + Duration::from_secs(2);
    assert!(matches!(
        client.submit_bounded(Request::Create, now, hard),
        Err(gnunet_messenger_client_host::Error::Protocol(
            Fault::Timeout
        ))
    ));
    assert!(matches!(
        client.submit_bounded(Request::Create, expires, tokio::time::Instant::now()),
        Err(gnunet_messenger_client_host::Error::Protocol(
            Fault::Timeout
        ))
    ));
    assert_eq!(client.pending(), 0);
    assert_eq!(client.retained_bytes(), 0);
    assert_eq!(Some(epoch), client.epoch());
    let operation = client.submit_bounded(Request::Create, expires, hard)?;
    assert_eq!(written(client, operation).await?, Kind::Create);
    Ok(())
}
async fn model() -> Result<(), Failure> {
    let scratch = Scratch::new()?;
    let path = scratch.0.join("m");
    let listener = UnixListener::bind(&path)?;
    let actor = tokio::spawn(actor(listener));
    let domain = Instance::new();
    let limits = Limits {
        profile: gnunet_messenger_client_host::Profile::LITTLE_255,
        io_slice_bytes: 7,
        ..Limits::default()
    };
    let mut client = Client::new(&domain, EndpointSource::unix(path.clone()), limits)?;
    connected(&mut client).await?;
    let requests = [
        Request::Open {
            room: room(),
            public_key: None,
        },
        Request::Entry {
            room: room(),
            public_key: None,
        },
        Request::Send {
            key: &ROOM,
            message: SensitiveBytes::new(OPAQUE),
        },
        Request::Get {
            key: &ROOM,
            hash: &HASH,
        },
        Request::Sync { room: room() },
        Request::Close { room: room() },
    ];
    for (index, request) in requests.into_iter().enumerate() {
        let operation = client.submit(request, Duration::from_secs(2))?;
        assert_eq!(written(&mut client, operation).await?, Kind::from(request));
        assert_eq!(client.pending(), 0);
        assert_eq!(client.retained_bytes(), 0);
        if index == 0 {
            let n = notification(&mut client).await?;
            assert!(matches!(
                n.view()?,
                Response::MemberId {
                    id: &MEMBER,
                    reset: 1,
                    ..
                }
            ));
        }
        let n = notification(&mut client).await?;
        match (index, n.view()?) {
            (0, Response::Open(_))
            | (1, Response::Entry(_))
            | (4, Response::Sync(_))
            | (5, Response::Close(_)) => {}
            (
                2,
                Response::Receive {
                    flags: 0x80000000,
                    message,
                    ..
                },
            ) => assert_eq!(message.expose(), OPAQUE),
            (3, Response::Missing { hash, .. }) => assert_eq!(hash, &HASH),
            _ => return Err(Fault::Malformed.into()),
        }
    }
    let destroy = client.submit(Request::Destroy, Duration::from_secs(2))?;
    assert_eq!(written(&mut client, destroy).await?, Kind::Destroy);
    assert!(client.epoch().is_none());
    assert!(client.reconnect().is_err());
    let mut client = Client::new(&domain, EndpointSource::unix(path.clone()), limits)?;
    connected(&mut client).await?;
    let old_epoch = client.epoch();
    let operation = client.submit(
        Request::Open {
            room: room(),
            public_key: None,
        },
        Duration::from_secs(2),
    )?;
    loop {
        match client.progress().await? {
            Progress::Activity { written_bytes, .. } if written_bytes > 0 => break,
            Progress::Queued { .. } => {}
            event => return Err(format!("unexpected prefix progress {event:?}").into()),
        }
    }
    let original = client.exposure(operation)?;
    assert!(matches!(original, Submission::Partial { bytes: 7, .. }));
    let loss = client.cancel(operation)?;
    assert_eq!(loss.epoch, old_epoch);
    assert!(matches!(loss.cause,LossCause::Cancelled(actual) if actual == operation));
    assert_eq!(loss.reports.len(), 1);
    assert_eq!(loss.reports[0].submission, original);
    assert_eq!(client.pending(), 0);
    assert_eq!(client.retained_bytes(), 0);
    client.reconnect()?;
    connected(&mut client).await?;
    assert_ne!(client.epoch(), old_epoch);
    assert!(client.cancel(operation).is_err()); // Does not retire the new source.
    let destroy = client.submit(Request::Destroy, Duration::from_secs(2))?;
    assert_eq!(written(&mut client, destroy).await?, Kind::Destroy);
    let mut client = Client::new(
        &domain,
        EndpointSource::unix(path),
        Limits {
            input_lifetime: Duration::from_millis(30),
            ..limits
        },
    )?;
    connected(&mut client).await?;
    let mut saw_input = false;
    loop {
        match client.progress().await? {
            Progress::Activity { read_bytes, .. } => saw_input |= read_bytes > 0,
            Progress::Lost(loss) => {
                assert!(saw_input);
                assert!(matches!(loss.cause, LossCause::InputDeadline));
                assert!(loss.reports.is_empty());
                break;
            }
            event => return Err(format!("unexpected incomplete-frame progress {event:?}").into()),
        }
    }
    let _closed = client.close();
    actor.await??;
    Ok(())
}
#[test]
fn active_ipc_original_prefix_retirement_reconnect_and_input_bound() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async { tokio::time::timeout(Duration::from_secs(10), model()).await? })
}
