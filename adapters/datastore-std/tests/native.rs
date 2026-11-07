//! Local Unix test peers exercise native lifetime; no official C interop credit.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Native tests assert original bytes, partial cursors and actual result certainty"
)]
use gnunet_client::datastore::{self as pure, Data, Outcome, Request, Response, Status};
use gnunet_client_host::{ConnectError, EndpointSource};
use gnunet_datastore_host::{Client, Limits, Step, Taken};
use gnunet_types::{Duration as Timeout, Error as ProtocolError};
use gnunet_wire::official::AbsoluteTime;
use std::{
    io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::{Instant, timeout},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Socket(PathBuf);
impl Socket {
    fn bind() -> io::Result<(Self, UnixListener)> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-datastore-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = UnixListener::bind(&path)?;
        Ok((Self(path), listener))
    }
    fn source(&self) -> EndpointSource {
        EndpointSource::unix(self.0.clone())
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.0) {
            Ok(()) | Err(_) => {}
        }
    }
}
fn limits(slice: usize, replies: usize) -> Limits {
    Limits {
        frame_bytes: 512,
        reply_frames: replies,
        reply_bytes: 512 * replies,
        io_slice_bytes: slice,
    }
}
fn value<'a>(key: &'a [u8; 64], body: &'a [u8], rid: u32) -> Data<'a> {
    Data {
        reservation: rid,
        kind: 1,
        priority: 3,
        anonymity: 0,
        replication: 2,
        uid: 0,
        expiration: AbsoluteTime::from_micros(123),
        key,
        value: body,
    }
}
async fn read_frame(peer: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    peer.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if length < 4 {
        return Err(io::Error::other("short frame"));
    }
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&header);
    peer.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
fn status(code: i32) -> Result<Vec<u8>, ProtocolError> {
    let mut bytes = vec![0; 64];
    let length = Response::Status(Status {
        code,
        min_expiration: AbsoluteTime::from_micros(456),
        message: Some(b"\xffdiagnostic\0"),
    })
    .encode(&mut bytes)?;
    bytes.truncate(length);
    Ok(bytes)
}
async fn progress<'a>(
    client: &mut Client<'a, '_, '_>,
    until: Instant,
) -> Result<Step<'a>, Box<dyn std::error::Error>> {
    match client.drive(Some(until)).await? {
        Step::WaitDeadline => Err(ProtocolError::Timeout.into()),
        step => Ok(step),
    }
}
async fn written<'a>(
    client: &mut Client<'a, '_, '_>,
    operation: pure::Operation<'a>,
) -> Result<(), Box<dyn std::error::Error>> {
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        match progress(client, until).await? {
            Step::Written {
                operation: actual,
                complete: true,
                ..
            } if actual == operation => return Ok(()),
            Step::WaitDeadline => return Err(ProtocolError::Timeout.into()),
            _ => {}
        }
    }
}
async fn result<'a>(
    client: &mut Client<'a, '_, '_>,
    operation: pure::Operation<'a>,
) -> Result<Taken<'a>, Box<dyn std::error::Error>> {
    let until = Instant::now() + Duration::from_secs(2);
    loop {
        match client.take(operation) {
            Ok(result) => return Ok(result),
            Err(ConnectError::Protocol(ProtocolError::NotReady)) => {}
            Err(error) => return Err(error.into()),
        }
        if matches!(progress(client, until).await?, Step::WaitDeadline) {
            return Err(ProtocolError::Timeout.into());
        }
    }
}

#[test]
fn actual_zero_written_cancel_keeps_same_connection_usable() -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (socket, listener) = Socket::bind()?;
            let mut instance = pure::Instance::new();
            let mut a = [0; 512];
            let mut b = [0; 512];
            let mut slots = [pure::Slot::new(&mut a), pure::Slot::new(&mut b)];
            let mut reservations = [pure::ReservationSlot::default(); 1];
            let core = pure::Client::new(
                &mut instance,
                &mut slots,
                &mut reservations,
                pure::Limits {
                    max_pending: 2,
                    max_frame_bytes: 512,
                    ..pure::Limits::default()
                },
            )?;
            let mut client = Client::new(core, socket.source(), limits(512, 2))?;
            let key = [7; 64];
            let put = client.submit(
                Request::Put(value(&key, b"zero transfer", 0)),
                None,
                Timeout(5_000_000),
            )?;
            let until = Instant::now() + Duration::from_secs(2);
            loop {
                match progress(&mut client, until).await? {
                    Step::Queued(actual) if actual == put => break,
                    Step::WaitDeadline => return Err(ProtocolError::Timeout.into()),
                    _ => {}
                }
            }
            client.cancel(put)?;
            let cancelled = client.take(put)?;
            assert_eq!(cancelled.completion.outcome, Outcome::Cancelled);
            assert!(cancelled.bytes().is_none());
            let (mut peer, _) = listener.accept().await?;
            let mut one = [0];
            assert!(
                timeout(Duration::from_millis(1), peer.read(&mut one))
                    .await
                    .is_err()
            );
            let reserve = client.submit(
                Request::Reserve {
                    amount: 3,
                    entries: 1,
                },
                None,
                Timeout(5_000_000),
            )?;
            written(&mut client, reserve).await?;
            let request = read_frame(&mut peer).await?;
            assert_eq!(
                Request::decode(&request)?,
                Request::Reserve {
                    amount: 3,
                    entries: 1
                }
            );
            peer.write_all(&status(23)?).await?;
            let answer = result(&mut client, reserve).await?;
            assert_eq!(
                answer
                    .completion
                    .reservation
                    .ok_or("reservation missing")?
                    .value(),
                23
            );
            assert!(matches!(
                answer.response()?,
                Some(Response::Status(Status { code: 23, .. }))
            ));
            client.close()?;
            Ok(())
        })
}

#[test]
fn partial_io_dropped_wait_and_owned_reply_capacity_preserve_originals() -> TestResult {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let (socket,listener)=Socket::bind()?;
        let mut instance=pure::Instance::new(); let mut a=[0;512]; let mut b=[0;512];
        let mut slots=[pure::Slot::new(&mut a),pure::Slot::new(&mut b)]; let mut reservations=[];
        let core=pure::Client::new(&mut instance,&mut slots,&mut reservations,pure::Limits { max_pending:2,max_frame_bytes:512,..pure::Limits::default() })?;
        let mut client=Client::new(core,socket.source(),limits(7,1))?;
        let key=[11;64]; let body=[0xb7;131]; let request=Request::Put(value(&key,&body,0));
        let put=client.submit(request,None,Timeout(5_000_000))?;
        let until=Instant::now()+Duration::from_secs(2); let mut partial=false;
        loop {
            match progress(&mut client, until).await? {
                Step::Written { operation,bytes,complete } if operation==put => { assert!(bytes<=7); if complete { break; } partial=true; }
                Step::WaitDeadline => return Err(ProtocolError::Timeout.into()),
                _ => {},
            }
        }
        assert!(partial);
        let (mut peer,_)=listener.accept().await?;
        let actual=read_frame(&mut peer).await?;
        assert_eq!(Request::decode(&actual)?,request);
        // This actually pending drive is dropped with the native read/timer intact.
        assert!(timeout(Duration::from_millis(1),client.drive(None)).await.is_err());
        let reply=status(0)?;
        peer.write_all(&reply[..3]).await?;
        loop { if matches!(progress(&mut client, until).await?,Step::Read { .. }) { break; } }
        assert!(timeout(Duration::from_millis(1),client.drive(None)).await.is_err());
        peer.write_all(&reply[3..]).await?;
        loop { if matches!(progress(&mut client, until).await?,Step::Reply(operation) if operation==put) { break; } }
        let get=client.submit(Request::Get { key:None,kind:0,next_uid:0,random:false },None,Timeout(5_000_000))?;
        written(&mut client,get).await?;
        let get_bytes=read_frame(&mut peer).await?;
        assert!(matches!(Request::decode(&get_bytes)?,Request::Get { key:None,.. }));
        let mut end=[0;4]; Response::End.encode(&mut end)?; peer.write_all(&end).await?;
        loop { if matches!(progress(&mut client, until).await?,Step::Capacity) { break; } }
        // Capacity stopped before pure acceptance, leaving the second completion pending.
        assert!(matches!(client.take(get),Err(ConnectError::Protocol(ProtocolError::NotReady))));
        let answer=client.take(put)?;
        assert_eq!(answer.bytes(),Some(reply.as_slice()));
        assert!(matches!(answer.completion.outcome,Outcome::Status { code:0,.. }));
        let raw=answer.into_frame().ok_or("owned status lost")?;
        assert_eq!(raw.bytes(),reply);
        let answer=result(&mut client,get).await?;
        assert_eq!(answer.completion.outcome,Outcome::NotFound);
        assert_eq!(answer.response()?,Some(Response::End));
        client.close()?;
        Ok(())
    })
}

#[test]
fn lost_mutation_is_not_replayed_reservation_expires_and_drop_has_no_ack() -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (socket, listener) = Socket::bind()?;
            let mut instance = pure::Instance::new();
            let mut a = [0; 512];
            let mut b = [0; 512];
            let mut slots = [pure::Slot::new(&mut a), pure::Slot::new(&mut b)];
            let mut reservations = [pure::ReservationSlot::default(); 1];
            let core = pure::Client::new(
                &mut instance,
                &mut slots,
                &mut reservations,
                pure::Limits {
                    max_pending: 2,
                    max_frame_bytes: 512,
                    ..pure::Limits::default()
                },
            )?;
            let mut client = Client::new(core, socket.source(), limits(512, 2))?;
            let reserve = client.submit(
                Request::Reserve {
                    amount: 1,
                    entries: 1,
                },
                None,
                Timeout(5_000_000),
            )?;
            written(&mut client, reserve).await?;
            let (mut first, _) = listener.accept().await?;
            assert!(matches!(
                Request::decode(&read_frame(&mut first).await?)?,
                Request::Reserve { .. }
            ));
            first.write_all(&status(9)?).await?;
            let reservation = result(&mut client, reserve)
                .await?
                .completion
                .reservation
                .ok_or("missing reservation")?;
            let key = [17; 64];
            let put_request = Request::Put(value(&key, b"x", 9));
            let put = client.submit(put_request, Some(reservation), Timeout(5_000_000))?;
            let get = client.submit(
                Request::Get {
                    key: Some(&key),
                    kind: 1,
                    next_uid: 0,
                    random: false,
                },
                None,
                Timeout(5_000_000),
            )?;
            written(&mut client, put).await?;
            assert_eq!(
                Request::decode(&read_frame(&mut first).await?)?,
                put_request
            );
            drop(first);
            let until = Instant::now() + Duration::from_secs(2);
            loop {
                if matches!(progress(&mut client, until).await?, Step::Lost { .. }) {
                    break;
                }
            }
            let unknown = client.take(put)?;
            assert_eq!(unknown.completion.outcome, Outcome::Unknown);
            assert!(unknown.bytes().is_none());
            assert!(matches!(
                client.submit(put_request, Some(reservation), Timeout(5_000_000)),
                Err(ConnectError::Protocol(ProtocolError::Stale))
            ));
            written(&mut client, get).await?;
            let (mut second, _) = listener.accept().await?;
            // The replacement receives only the still-unsent GET, never another PUT.
            assert!(matches!(
                Request::decode(&read_frame(&mut second).await?)?,
                Request::Get { key: Some(_), .. }
            ));
            let mut end = [0; 4];
            Response::End.encode(&mut end)?;
            second.write_all(&end).await?;
            assert_eq!(
                result(&mut client, get).await?.completion.outcome,
                Outcome::NotFound
            );
            let drop = client.submit(Request::Drop, None, Timeout(5_000_000))?;
            written(&mut client, drop).await?;
            assert_eq!(
                Request::decode(&read_frame(&mut second).await?)?,
                Request::Drop
            );
            let mut one = [0];
            assert_eq!(
                timeout(Duration::from_secs(2), second.read(&mut one)).await??,
                0
            );
            let answer = client.take(drop)?;
            assert_eq!(answer.completion.outcome, Outcome::DropUnconfirmed);
            assert!(answer.bytes().is_none());
            assert!(matches!(client.drive(None).await?, Step::Closed));
            Ok(())
        })
}
