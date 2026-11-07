//! One real IPC ownership model. The actor emits only actual failure results;
//! it does not compute or fabricate a successful union or peer identity.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Asserts original byte framing, generations and cancellation without weakening wire outcomes"
)]
use gnunet_setu_client_host::{
    Client, Command, EndpointSource, Incoming, Instance, Limits, Reason, Step, Submission,
    clock::SystemClock,
    ipc::{self, Request, Response},
};
use std::{error::Error, path::PathBuf, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::Instant,
};
type Failure = Box<dyn Error + Send + Sync>;
const APP: [u8; 64] = [7; 64];
const PEER: [u8; 32] = [9; 32];
const ABI: ipc::Abi = ipc::Abi {
    order: ipc::Order::Little,
    align64: 8,
};
const CONTEXT: [u8; 4] = [0, 4, 0, 1];
struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Failure> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!("gsetu-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
async fn frame(stream: &mut UnixStream) -> Result<Vec<u8>, Failure> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let n = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if n < 4 {
        return Err("short actual frame".into());
    }
    let mut bytes = vec![0; n];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn response(stream: &mut UnixStream, value: Response<'_>) -> Result<(), Failure> {
    let mut bytes = vec![0; value.encoded_len(ABI)?];
    value.encode(ABI, &mut bytes)?;
    for part in bytes.chunks(3) {
        stream.write_all(part).await?;
    }
    Ok(())
}
async fn failure(stream: &mut UnixStream, request_id: u32) -> Result<(), Failure> {
    response(
        stream,
        Response::Result {
            current_size: 0,
            request: request_id,
            status: ipc::Status::Failure,
            element: ipc::Element { kind: 0, data: &[] },
        },
    )
    .await
}
async fn suggest(stream: &mut UnixStream, accept_id: u32) -> Result<(), Failure> {
    response(
        stream,
        Response::Incoming {
            incoming: accept_id,
            peer: PEER,
            context: Some(&CONTEXT),
        },
    )
    .await
}
fn operation_options() -> ipc::Options {
    ipc::Options {
        force_full: 1,
        symmetric: 1,
        upper_bound: 0x0102_0304_0506_0708,
        bandwidth_latency_tradeoff: 43,
        bucket_factor: 7,
        hashes: 5,
        ..ipc::Options::default()
    }
}
async fn actor(listener: UnixListener) -> Result<(), Failure> {
    let (mut set, _) = listener.accept().await?;
    assert_eq!(
        Request::decode(&frame(&mut set).await?, ABI)?,
        Request::Create
    );
    assert_eq!(
        Request::decode(&frame(&mut set).await?, ABI)?,
        Request::Add(ipc::Element {
            kind: 0x1234,
            data: b"opaque\0element"
        })
    );
    let first = match Request::decode(&frame(&mut set).await?, ABI)? {
        Request::Evaluate {
            request,
            peer: PEER,
            app: APP,
            options,
            context: Some(context),
        } if context == CONTEXT && options == operation_options() => request,
        _ => return Err("first original EVALUATE missing".into()),
    };
    failure(&mut set, first).await?;
    let second = match Request::decode(&frame(&mut set).await?, ABI)? {
        Request::Evaluate { request, .. } => request,
        _ => return Err("second original EVALUATE missing".into()),
    };
    assert_ne!(first, second);
    assert_eq!(
        Request::decode(&frame(&mut set).await?, ABI)?,
        Request::Cancel { request: second }
    );
    // A late original failure is allowed to arrive after local CANCEL submission.
    failure(&mut set, second).await?;
    let (mut monitor, _) = listener.accept().await?;
    assert_eq!(
        Request::decode(&frame(&mut monitor).await?, ABI)?,
        Request::Listen {
            reserved: 0,
            app: APP
        }
    );
    suggest(&mut monitor, 7).await?;
    assert_eq!(
        Request::decode(&frame(&mut monitor).await?, ABI)?,
        Request::Reject { incoming: 7 }
    );
    suggest(&mut monitor, 8).await?;
    let third = match Request::decode(&frame(&mut set).await?, ABI)? {
        Request::Accept {
            incoming: 8,
            request,
            options,
        } if options == ipc::Options::default() => request,
        _ => return Err("original ACCEPT missing".into()),
    };
    assert_ne!(third, first);
    assert_ne!(third, second);
    failure(&mut set, third).await?;
    suggest(&mut monitor, 9).await?;
    drop(monitor);
    let (mut replacement, _) = listener.accept().await?;
    assert_eq!(
        Request::decode(&frame(&mut replacement).await?, ABI)?,
        Request::Listen {
            reserved: 0,
            app: APP
        }
    );
    suggest(&mut replacement, 9).await?; // same raw id; distinct actual MQ epoch
    assert_eq!(
        Request::decode(&frame(&mut replacement).await?, ABI)?,
        Request::Reject { incoming: 9 }
    );
    suggest(&mut replacement, 10).await?;
    assert_eq!(
        Request::decode(&frame(&mut replacement).await?, ABI)?,
        Request::Reject { incoming: 10 }
    );
    drop(set); // original set source loss; the client must not recreate it
    let mut byte = [0; 1];
    assert_eq!(replacement.read(&mut byte).await?, 0);
    Ok(())
}
async fn written(client: &mut Client<'_>, command: Command, until: Instant) -> Result<(), Failure> {
    loop {
        match client.drive(Some(until)).await? {
            Step::Written(_, _, actual) if actual == command => return Ok(()),
            Step::WaitDeadline | Step::Closed | Step::Lost(..) => {
                return Err("original write did not finish".into());
            }
            _ => {}
        }
    }
}
async fn incoming<'id>(client: &mut Client<'id>, until: Instant) -> Result<Incoming<'id>, Failure> {
    loop {
        match client.drive(Some(until)).await? {
            Step::Incoming(input) => return Ok(input),
            Step::WaitDeadline | Step::Closed | Step::Lost(..) => {
                return Err("original incoming request missing".into());
            }
            _ => {}
        }
    }
}
#[test]
fn original_set_cancel_listener_lease_and_reconnect_are_distinct() -> Result<(), Failure> {
    let directory = Directory::new()?;
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        tokio::time::timeout(Duration::from_secs(8), async {
            let socket = directory.0.join("setu.sock");
            let actor = tokio::spawn(actor(UnixListener::bind(&socket)?));
            let clock = Arc::new(SystemClock);
            let source = || EndpointSource::unix_with_clock(socket.clone(), clock.clone());
            let until = source().clock().sample()?.now.as_micros().checked_add(10_000_000).ok_or("deadline overflow")?;
            let end = Instant::now() + Duration::from_secs(6);
            let limits = Limits { operations:2, incoming:2, incoming_lifetime_micros:2_000_000, abi:ABI,
                io_slice_bytes:3, ..Limits::default() };
            let set_instance = Instance::new();
            let listener_instance = Instance::new();
            let mut set = Client::new_set(&set_instance, source(), limits, until)?;
            written(&mut set, Command::Create, end).await?;
            assert!(set.initialized());
            set.add(0x1234, b"opaque\0element", until)?;
            written(&mut set, Command::Add, end).await?;
            let first = set.evaluate(PEER, APP, operation_options(), Some(&CONTEXT), until)?;
            loop {
                match set.drive(Some(end)).await? {
                    Step::Result(result) => {
                        assert_eq!(result.operation(), first);
                        assert_eq!(result.bytes().len(), 24);
                        assert!(matches!(result.response()?, Response::Result {status:ipc::Status::Failure,..}));
                        break;
                    }
                    Step::WaitDeadline | Step::Lost(..) => return Err("actual failure reply missing".into()),
                    _ => {}
                }
            }
            let second = set.evaluate(PEER, APP, ipc::Options::default(), None, until)?;
            written(&mut set, Command::Evaluate, end).await?;
            set.cancel(second)?;
            written(&mut set, Command::Cancel, end).await?;
            assert!(matches!(set.next_event(),Some(Step::LocalEnd(operation,Reason::Cancelled,Submission::CancelSubmitted)) if operation==second));
            let unsent = set.evaluate(PEER, APP, ipc::Options::default(), None, until)?;
            set.cancel(unsent)?;
            assert!(matches!(set.next_event(),Some(Step::LocalEnd(operation,Reason::Cancelled,Submission::Unsent)) if operation==unsent));
            let mut listener = Client::new_listener(&listener_instance, source(), limits, APP, until)?;
            written(&mut listener, Command::Listen, end).await?;
            let abandoned = incoming(&mut listener, end).await?;
            assert!(abandoned.pending()); drop(abandoned);
            written(&mut listener, Command::Reject, end).await?;
            let mut accepted = incoming(&mut listener, end).await?;
            assert_eq!(accepted.request()?,Response::Incoming {incoming:8,peer:PEER,context:Some(&CONTEXT)});
            let third = set.accept(&mut accepted, ipc::Options::default(), until)?;
            assert!(!accepted.pending()); drop(accepted);
            loop {
                match set.drive(Some(end)).await? {
                    Step::Result(result) => {
                        assert_eq!(result.operation(), third);
                        assert!(matches!(result.response()?, Response::Result {status:ipc::Status::Failure,..}));
                        break;
                    }
                    Step::WaitDeadline | Step::Lost(..) => return Err("accepted operation reply missing".into()),
                    _ => {}
                }
            }
            let mut old = incoming(&mut listener, end).await?;
            let old_epoch = old.epoch().diagnostic();
            loop {
                match listener.drive(Some(end)).await? {
                    Step::Lost(..) => break,
                    Step::WaitDeadline => return Err("actual listener loss missing".into()),
                    _ => {}
                }
            }
            assert!(!old.pending());
            assert!(set.accept(&mut old, ipc::Options::default(), until).is_err());
            listener.reconnect_listener()?;
            let replacement = incoming(&mut listener, end).await?;
            assert_ne!(old_epoch, replacement.epoch().diagnostic());
            assert!(replacement.pending()); assert!(!old.pending());
            drop(replacement);
            written(&mut listener, Command::Reject, end).await?;
            let mut expired = incoming(&mut listener, end).await?;
            assert!(expired.pending());
            written(&mut listener, Command::Reject, end).await?;
            assert!(!expired.pending());
            assert!(set.accept(&mut expired, ipc::Options::default(), until).is_err());
            loop {
                match set.drive(Some(end)).await? {
                    Step::Lost(..) => break,
                    Step::WaitDeadline | Step::Closed => return Err("actual set source loss missing".into()),
                    _ => {}
                }
            }
            assert!(!set.initialized());
            assert!(set.reconnect_listener().is_err());
            assert!(set.add(1, b"after-loss", until).is_err());
            let _closed_listener = listener.close();
            let _closed_set = set.close();
            tokio::time::timeout(Duration::from_secs(2), actor).await???;
            drop((old, expired, listener, set));
            Ok::<(), Failure>(())
        }).await??;
        Ok::<(), Failure>(())
    })
}
