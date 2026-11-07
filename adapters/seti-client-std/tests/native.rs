//! One real IPC ownership model. The actor emits only actual failure results;
//! it does not compute or fabricate a successful intersection or peer identity.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Asserts original byte framing, generations and cancellation without weakening wire outcomes"
)]
use gnunet_seti_client_host::{
    Client, Command, EndpointSource, Incoming, Instance, Limits, Reason, Step, Submission,
    clock::{ClockSample, ClockSubscription, RuntimeClock, SystemClock},
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
const CONTEXT: [u8; 4] = [0, 4, 0, 1];
struct AheadClock;
impl RuntimeClock for AheadClock {
    fn sample(&self) -> Result<ClockSample, gnunet_types::Error> {
        let mut sample = SystemClock.sample()?;
        sample.now = gnunet_types::AbsoluteTime::from_micros(
            sample
                .now
                .as_micros()
                .checked_add(60_000_000)
                .ok_or(gnunet_types::Error::Overflow)?,
        );
        Ok(sample)
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, gnunet_types::Error> {
        SystemClock.subscribe()
    }
}

struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Failure> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!("gseti-{}-{stamp}", std::process::id()));
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
    let layout = ipc::ResultLayout::Aligned24;
    let mut bytes = vec![0; value.encoded_len_with_layout(layout)?];
    value.encode_with_layout(&mut bytes, layout)?;
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
            request_id,
            status: ipc::FAILURE,
            element_type: 0,
            data: &[],
        },
    )
    .await
}
async fn suggest(stream: &mut UnixStream, accept_id: u32) -> Result<(), Failure> {
    response(
        stream,
        Response::Request {
            accept_id,
            peer: PEER,
            context: Some(&CONTEXT),
        },
    )
    .await
}
async fn actor(listener: UnixListener) -> Result<(), Failure> {
    let (mut set, _) = listener.accept().await?;
    assert_eq!(Request::decode(&frame(&mut set).await?)?, Request::Create);
    assert_eq!(
        Request::decode(&frame(&mut set).await?)?,
        Request::Add {
            element_type: 0x1234,
            reserved: 0,
            data: b"opaque\0element"
        }
    );
    let first = match Request::decode(&frame(&mut set).await?)? {
        Request::Evaluate {
            request_id,
            peer: PEER,
            app_id: APP,
            return_intersection: 1,
            context: Some(context),
        } if context == CONTEXT => request_id,
        _ => return Err("first original EVALUATE missing".into()),
    };
    failure(&mut set, first).await?;
    let second = match Request::decode(&frame(&mut set).await?)? {
        Request::Evaluate { request_id, .. } => request_id,
        _ => return Err("second original EVALUATE missing".into()),
    };
    assert_ne!(first, second);
    assert_eq!(
        Request::decode(&frame(&mut set).await?)?,
        Request::Cancel { request_id: second }
    );
    let (mut monitor, _) = listener.accept().await?;
    assert_eq!(
        Request::decode(&frame(&mut monitor).await?)?,
        Request::Listen {
            operation: 0,
            app_id: APP
        }
    );
    suggest(&mut monitor, 7).await?;
    assert_eq!(
        Request::decode(&frame(&mut monitor).await?)?,
        Request::Reject { accept_id: 7 }
    );
    suggest(&mut monitor, 8).await?;
    let third = match Request::decode(&frame(&mut set).await?)? {
        Request::Accept {
            accept_id: 8,
            request_id,
            return_intersection: 0,
        } => request_id,
        _ => return Err("original ACCEPT missing".into()),
    };
    assert_ne!(third, first);
    assert_ne!(third, second);
    failure(&mut set, third).await?;
    suggest(&mut monitor, 9).await?;
    drop(monitor);
    let (mut replacement, _) = listener.accept().await?;
    assert_eq!(
        Request::decode(&frame(&mut replacement).await?)?,
        Request::Listen {
            operation: 0,
            app_id: APP
        }
    );
    suggest(&mut replacement, 9).await?; // same raw id; distinct actual MQ epoch
    assert_eq!(
        Request::decode(&frame(&mut replacement).await?)?,
        Request::Reject { accept_id: 9 }
    );
    suggest(&mut replacement, 10).await?;
    assert_eq!(
        Request::decode(&frame(&mut replacement).await?)?,
        Request::Reject { accept_id: 10 }
    );
    let mut byte = [0; 1];
    assert_eq!(replacement.read(&mut byte).await?, 0);
    assert_eq!(set.read(&mut byte).await?, 0); // no ACCEPT was sent for stale input
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
            let socket = directory.0.join("seti.sock");
            let actor = tokio::spawn(actor(UnixListener::bind(&socket)?));
            let clock = Arc::new(SystemClock);
            let source = || EndpointSource::unix_with_clock(socket.clone(), clock.clone());
            let until = source().clock().sample()?.now.as_micros().checked_add(10_000_000).ok_or("deadline overflow")?;
            let end = Instant::now() + Duration::from_secs(6);
            let limits = Limits { operations:2, incoming:2, incoming_lifetime_micros:2_000_000, result_layout:ipc::ResultLayout::Aligned24,
                io_slice_bytes:3, ..Limits::default() };
            let mut set_instance = Instance::new();
            let mut listener_instance = Instance::new();
            let set_source = EndpointSource::unix_with_clock(socket.clone(), Arc::new(AheadClock));
            let set_until = set_source.clock().sample()?.now.as_micros().checked_add(10_000_000).ok_or("set deadline overflow")?;
            let mut set = Client::new_set(&mut set_instance, set_source, limits, set_until)?;
            written(&mut set, Command::Create, end).await?;
            assert!(set.initialized());
            set.add(0x1234, b"opaque\0element", set_until)?;
            written(&mut set, Command::Add, end).await?;
            let first = set.evaluate(PEER, APP, true, Some(&CONTEXT), set_until)?;
            loop {
                match set.drive(Some(end)).await? {
                    Step::Result(result) => {
                        assert_eq!(result.operation(), first);
                        assert_eq!(result.bytes().len(), 24);
                        assert!(matches!(result.response()?, Response::Result {status:ipc::FAILURE,..}));
                        break;
                    }
                    Step::WaitDeadline | Step::Lost(..) => return Err("actual failure reply missing".into()),
                    _ => {}
                }
            }
            let second = set.evaluate(PEER, APP, false, None, set_until)?;
            written(&mut set, Command::Evaluate, end).await?;
            set.cancel(second)?;
            written(&mut set, Command::Cancel, end).await?;
            assert!(matches!(set.next_event(),Some(Step::LocalEnd(operation,Reason::Cancelled,Submission::CancelSubmitted)) if operation==second));
            let mut listener = Client::new_listener(&mut listener_instance, source(), limits, APP, until)?;
            written(&mut listener, Command::Listen, end).await?;
            let abandoned = incoming(&mut listener, end).await?;
            assert!(abandoned.pending()); drop(abandoned);
            written(&mut listener, Command::Reject, end).await?;
            let mut accepted = incoming(&mut listener, end).await?;
            assert_eq!(accepted.request()?,Response::Request {accept_id:8,peer:PEER,context:Some(&CONTEXT)});
            let third = set.accept(&mut accepted, false, set_until)?;
            assert!(!accepted.pending()); drop(accepted);
            loop {
                match set.drive(Some(end)).await? {
                    Step::Result(result) => {
                        assert_eq!(result.operation(), third);
                        assert!(matches!(result.response()?, Response::Result {status:ipc::FAILURE,..}));
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
            assert!(set.accept(&mut old, false, set_until).is_err());
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
            assert!(set.accept(&mut expired, false, set_until).is_err());
            let _closed_listener = listener.close();
            let _closed_set = set.close();
            tokio::time::timeout(Duration::from_secs(2), actor).await???;
            drop((old, expired, listener, set));
            Ok::<(), Failure>(())
        }).await??;
        Ok::<(), Failure>(())
    })
}
