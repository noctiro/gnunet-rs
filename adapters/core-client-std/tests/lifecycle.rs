//! Actual native ownership through partial writes, cancellation and MQ retirement.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Tests assert actual socket effects and retained source authority."
)]
use gnunet_client::core::{ClassOrder, Direction, KxState, Request, Response, Traffic};
use gnunet_core_client_host::{
    Client, EndpointSource, Inbound, Instance, Limits, Message, Monitor, MonitorEvent,
    MonitorProgress, OwnedTraffic, Peer, PeerClass, PeerId, Progress, SendOutcome,
};
use std::{
    error::Error,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::Instant,
};
type Failure = Box<dyn Error + Send + Sync>;
const LOCAL: PeerId = PeerId([4; 32]);
const A: PeerId = PeerId([5; 32]);
const MSG: [u8; 8] = [0, 8, 0, 0, 1, 2, 3, 4];
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Socket(PathBuf);
impl Socket {
    fn new() -> Result<(Self, UnixListener), Failure> {
        let path = std::env::temp_dir().join(format!(
            "gnrs-native-core-{}-{}.sock",
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
        let _removed = std::fs::remove_file(&self.0);
    }
}
fn runtime() -> Result<tokio::runtime::Runtime, Failure> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}
async fn response(stream: &mut UnixStream, value: Response<'_>) -> Result<(), Failure> {
    let mut out = [0; 256];
    let n = value.encode(&mut out, ClassOrder::Little)?;
    stream.write_all(&out[..n]).await?;
    Ok(())
}
async fn frame(stream: &mut UnixStream) -> Result<Vec<u8>, Failure> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let len = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if len < 4 {
        return Err("short frame".into());
    }
    let mut out = vec![0; len];
    out[..4].copy_from_slice(&header);
    stream.read_exact(&mut out[4..]).await?;
    Ok(out)
}
async fn init(stream: &mut UnixStream) -> Result<(), Failure> {
    assert!(matches!(
        Request::decode(&frame(stream).await?)?,
        Request::Init { .. }
    ));
    response(
        stream,
        Response::InitReply {
            identity: LOCAL,
            class: PeerClass::SERVER,
        },
    )
    .await
}
async fn ready<'a, const P: usize, const S: usize>(
    client: &mut Client<'a, P, S>,
) -> Result<Peer<'a>, Failure> {
    loop {
        match client
            .drive(Some(Instant::now() + Duration::from_secs(2)))
            .await?
        {
            Progress::Inbound {
                event: Inbound::Ready { local, .. },
                ..
            } => return Ok(local),
            Progress::Activity { .. } | Progress::Connected(_) => {}
            _ => return Err("unexpected before ready".into()),
        }
    }
}
#[test]
fn started_cancel_drains_exact_original_then_returns_source_before_rx() -> Result<(), Failure> {
    let runtime = runtime()?;
    let _entered = runtime.enter();
    runtime.block_on(tokio::time::timeout(Duration::from_secs(4), async {
        let (socket, listener) = Socket::new()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            init(&mut stream).await?;
            let request = frame(&mut stream).await?;
            let (request_id,size) = match Request::decode(&request)? {
                Request::SendRequest { peer, request_id, size, .. } if peer == LOCAL => (request_id,size),
                _ => return Err("request mismatch".into()) };
            response(&mut stream,Response::SendReady { peer: LOCAL, request_id,size }).await?;
            let payload = frame(&mut stream).await?;
            assert!(matches!(Request::decode(&payload)?, Request::Send { peer, messages, .. } if peer == LOCAL && messages == MSG));
            response(&mut stream, Response::Traffic { direction: Direction::Inbound, peer: LOCAL, traffic: Traffic::Full(&MSG) }).await?;
            // Keep the physical stream alive until client closes it explicitly.
            let mut tail=[0;1]; assert_eq!(stream.read(&mut tail).await?,0);
            Ok::<_,Failure>(())
        });
        let mut instance=Instance::new();
        let mut client=Client::<4,4>::new(&mut instance,socket.source(),ClassOrder::Little,0,&[0],Limits { sends:4, io_slice_bytes:1,..Limits::default() })?;
        let local=ready(&mut client).await?;
        assert!(client.request_available(local,MSG.len(),MSG.len())?);
        let message=Message::copy_from(&MSG)?; let original=message.as_ref().as_ptr();
        let send=client.send(local,0,u64::MAX,message).map_err(|r|r.reason)?;
        assert!(!client.request_available(local,MSG.len(),MSG.len())?);
        let mut permitted=false;
        loop {
            match client.drive(None).await? {
                Progress::Inbound { event: Inbound::SendReady { send: actual, .. }, .. } => { assert_eq!(send,actual);permitted=true; },
                Progress::Activity { epoch,written_bytes:1,payload:Some(write),.. } if permitted => {
                    let state=write.state();
                    assert_eq!(state.epoch(),epoch); assert_eq!(state.peer(),local); assert_eq!(state.send(),send);
                    assert_eq!(write.bytes(),1); assert_eq!(write.previous(),0); assert_eq!(state.written(),1);
                    assert_eq!(state.frame_bytes(),gnunet_wire::official::core::SEND_PREFIX+MSG.len());
                    assert!(state.exposed()); assert!(!state.complete()); break;
                },
                Progress::Activity { .. } => {},
                _ => return Err("unexpected before partial payload".into()),
            }
        }
        assert!(client.cancel(send)?.is_none());
        loop {
            match client.drive(None).await? {
                Progress::Finished { epoch,send:actual,completion,peer,payload } => {
                    assert_eq!(actual,send); assert_eq!(peer,local);
                    assert_eq!(payload.epoch(),epoch); assert_eq!(payload.peer(),peer); assert_eq!(payload.send(),actual);
                    assert_eq!(payload.written(),gnunet_wire::official::core::SEND_PREFIX+MSG.len());
                    assert!(payload.exposed()); assert!(payload.complete());
                    assert_eq!(completion.outcome,SendOutcome::CancelledAfterWrite);
                    assert_eq!(completion.source.as_ref().as_ptr(),original);
                    assert_eq!(completion.source.as_ref(),MSG);break;
                }
                Progress::Activity { .. } => {},
                _ => return Err("RX happened before original final write was committed".into()),
            }
        }
        loop {
            match client.drive(None).await? {
                Progress::Inbound { event: Inbound::Traffic { connection:Some(peer), traffic:OwnedTraffic::Full(body),.. }, .. } => {
                    assert_eq!(peer,local);assert_eq!(body.as_ref(),MSG);break;
                }
                Progress::Activity { .. } => {}, _ => return Err("missing owned traffic".into()),
            }
        }
        assert!(client.request_available(local,MSG.len(),MSG.len())?);
        assert_eq!(client.source_bytes(),0);
        assert!(client.close()?.is_some());
        assert!(matches!(client.drive(None).await?,Progress::PeerLost {peer,..} if peer==local));
        assert!(matches!(client.drive(None).await?,Progress::Closed));
        server.await??;
        Ok::<_,Failure>(())
    }))??;
    Ok(())
}
#[test]
fn loss_returns_original_and_all_notices_before_new_epoch_without_replay() -> Result<(), Failure> {
    let runtime = runtime()?;
    let _entered = runtime.enter();
    runtime.block_on(tokio::time::timeout(Duration::from_secs(4),async {
        let (socket,listener)=Socket::new()?;
        let server=tokio::spawn(async move {
            let (mut first,_)=listener.accept().await?;init(&mut first).await?;
            response(&mut first,Response::Connected { peer:A,class:PeerClass::ROUTER }).await?;
            let old=frame(&mut first).await?;assert!(matches!(Request::decode(&old)?,Request::SendRequest {peer,..} if peer==A));
            drop(first);
            let (mut second,_)=listener.accept().await?;init(&mut second).await?;
            let mut extra=[0;1];assert!(tokio::time::timeout(Duration::from_millis(40),second.read(&mut extra)).await.is_err());
            Ok::<_,Failure>(())
        });
        let mut instance=Instance::new();
        let mut client=Client::<4,4>::new(&mut instance,socket.source(),ClassOrder::Little,0,&[0],Limits { sends:4,..Limits::default() })?;
        let local=ready(&mut client).await?;let first_epoch=client.epoch().ok_or("epoch")?;
        let peer=loop { if let Progress::Inbound {event:Inbound::Connected(peer),..}=client.drive(None).await? {break peer;} };
        let message=Message::copy_from(&MSG)?;let pointer=message.as_ref().as_ptr();
        let send=client.send(peer,0,0,message).map_err(|r|r.reason)?;
        loop { if let Progress::Lost {epoch,..}=client.drive(None).await? {assert_eq!(epoch,first_epoch);break;} }
        assert!(matches!(client.drive(None).await?,Progress::Finished {epoch,send:actual,completion,payload,..}
            if epoch==first_epoch && actual==send && completion.outcome==SendOutcome::ConnectionLost && completion.source.as_ref().as_ptr()==pointer
                && payload.epoch()==epoch && payload.peer()==peer && payload.send()==send && payload.written()==0 && !payload.exposed() && !payload.complete()));
        let mut lost=Vec::new();
        for _ in 0..2 {match client.drive(None).await? { Progress::PeerLost {epoch,peer} => {assert_eq!(epoch,first_epoch);lost.push(peer);},_=>return Err("new epoch overwrote loss notices".into())}}
        assert!(lost.contains(&local)&&lost.contains(&peer));
        let fresh=ready(&mut client).await?;assert_ne!(fresh,local);assert_ne!(client.epoch(),Some(first_epoch));
        assert_eq!(client.pending(),0);server.await??;assert!(client.close()?.is_some());Ok::<_,Failure>(())
    }))??;
    Ok(())
}
#[test]
fn wholly_unwritten_cancel_leaves_admitted_request_and_ignores_its_ready() -> Result<(), Failure> {
    let runtime = runtime()?;
    let _entered = runtime.enter();
    runtime.block_on(tokio::time::timeout(Duration::from_secs(4), async {
        let (socket, listener) = Socket::new()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            init(&mut stream).await?;
            let request = frame(&mut stream).await?;
            let (request_id, size) = match Request::decode(&request)? {
                Request::SendRequest {
                    request_id, size, ..
                } => (request_id, size),
                _ => return Err("no canceled original request".into()),
            };
            response(
                &mut stream,
                Response::SendReady {
                    peer: LOCAL,
                    request_id,
                    size,
                },
            )
            .await?;
            let mut extra = [0; 1];
            assert_eq!(stream.read(&mut extra).await?, 0);
            Ok::<_, Failure>(())
        });
        let mut instance = Instance::new();
        let mut client = Client::<4, 4>::new(
            &mut instance,
            socket.source(),
            ClassOrder::Little,
            0,
            &[0],
            Limits {
                sends: 4,
                ..Limits::default()
            },
        )?;
        let local = ready(&mut client).await?;
        let source = Message::copy_from(&MSG)?;
        let pointer = source.as_ref().as_ptr();
        let send = client.send(local, 0, 0, source).map_err(|r| r.reason)?;
        let completion = client.cancel(send)?.ok_or("missing cancellation")?;
        assert_eq!(completion.outcome, SendOutcome::CancelledBeforePayload);
        assert_eq!(completion.source.as_ref().as_ptr(), pointer);
        loop {
            match client.drive(None).await? {
                Progress::Inbound {
                    event: Inbound::IgnoredReady { .. },
                    ..
                } => break,
                Progress::Activity { .. } => {}
                _ => return Err("canceled READY granted authority".into()),
            }
        }
        assert!(client.close()?.is_some());
        server.await??;
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}
#[test]
fn continuous_monitor_uses_actual_snapshot_and_physical_epoch() -> Result<(), Failure> {
    let runtime = runtime()?;
    let _entered = runtime.enter();
    runtime.block_on(tokio::time::timeout(Duration::from_secs(4),async {
        let (socket,listener)=Socket::new()?;
        let server=tokio::spawn(async move {
            let (mut stream,_)=listener.accept().await?;assert_eq!(Request::decode(&frame(&mut stream).await?)?,Request::Monitor);
            response(&mut stream,Response::Monitor {peer:PeerId([0;32]),state:KxState::SNAPSHOT_FINISHED,timeout:u64::MAX}).await?;
            response(&mut stream,Response::Monitor {peer:A,state:KxState(4),timeout:123}).await?;
            let mut byte=[0;1];assert_eq!(stream.read(&mut byte).await?,0);Ok::<_,Failure>(())
        });
        let mut instance=Instance::new();let mut monitor=Monitor::new(&mut instance,socket.source(),Limits {io_slice_bytes:1,..Limits::default()})?;
        let mut snapshot=false;
        loop {match monitor.drive(None).await? {
            MonitorProgress::Inbound {event:MonitorEvent::SnapshotFinished,..}=>snapshot=true,
            MonitorProgress::Inbound {epoch,event:MonitorEvent::Update {peer,state,timeout}}=>{
                assert!(snapshot);assert_eq!(peer,A);assert_eq!(state,KxState(4));assert_eq!(timeout,123);
                assert!(matches!(monitor.close()?,Some(MonitorProgress::Lost {epoch:old,..}) if old==epoch));break;
            },MonitorProgress::Connected(_)|MonitorProgress::Activity {..}=>{},_=>return Err("monitor ended after snapshot".into())}}
        assert!(matches!(monitor.drive(None).await?,MonitorProgress::Closed));server.await??;Ok::<_,Failure>(())
    }))??;
    Ok(())
}

#[test]
fn canceled_drive_preserves_partial_rx_on_the_original_socket() -> Result<(), Failure> {
    let runtime = runtime()?;
    let _entered = runtime.enter();
    runtime.block_on(tokio::time::timeout(Duration::from_secs(4), async {
        let (socket, listener) = Socket::new()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            assert!(matches!(
                Request::decode(&frame(&mut stream).await?)?,
                Request::Init { .. }
            ));
            let mut bytes = [0; 44];
            let len = Response::InitReply {
                identity: LOCAL,
                class: PeerClass::SERVER,
            }
            .encode(&mut bytes, ClassOrder::Little)?;
            stream.write_all(&bytes[..2]).await?;
            tokio::time::sleep(Duration::from_millis(30)).await;
            stream.write_all(&bytes[2..len]).await?;
            let mut extra = [0; 1];
            assert_eq!(stream.read(&mut extra).await?, 0);
            assert!(
                tokio::time::timeout(Duration::from_millis(15), listener.accept())
                    .await
                    .is_err()
            );
            Ok::<_, Failure>(())
        });
        let mut instance = Instance::new();
        let mut client = Client::<2, 2>::new(
            &mut instance,
            socket.source(),
            ClassOrder::Little,
            0,
            &[0],
            Limits {
                sends: 2,
                io_slice_bytes: 1,
                ..Limits::default()
            },
        )?;
        let epoch = loop {
            if let Progress::Connected(epoch) = client.drive(None).await? {
                break epoch;
            }
        };
        // Timeout drops a genuinely pending drive future after the RX header begins.
        loop {
            match tokio::time::timeout(Duration::from_millis(5), client.drive(None)).await {
                Err(_) => break,
                Ok(Ok(Progress::Activity { .. })) => {}
                _ => return Err("initial reply completed before deliberate split".into()),
            }
        }
        let local = ready(&mut client).await?;
        assert_eq!(local.identity(), LOCAL);
        assert_eq!(client.epoch(), Some(epoch));
        assert!(client.close()?.is_some());
        server.await??;
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}

#[test]
fn complete_capacity_refusal_retains_input_without_partial_peer_application() -> Result<(), Failure>
{
    let runtime = runtime()?;
    let _entered = runtime.enter();
    runtime.block_on(tokio::time::timeout(Duration::from_secs(4), async {
        let (socket, listener) = Socket::new()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            init(&mut stream).await?;
            response(
                &mut stream,
                Response::Connected {
                    peer: A,
                    class: PeerClass::ROUTER,
                },
            )
            .await?;
            let mut byte = [0; 1];
            assert_eq!(stream.read(&mut byte).await?, 0);
            Ok::<_, Failure>(())
        });
        let mut instance = Instance::new();
        let mut client = Client::<1, 2>::new(
            &mut instance,
            socket.source(),
            ClassOrder::Little,
            0,
            &[0],
            Limits {
                sends: 2,
                ..Limits::default()
            },
        )?;
        let local = ready(&mut client).await?;
        let epoch = client.epoch().ok_or("epoch")?;
        loop {
            match client.drive(None).await? {
                Progress::Capacity(actual) => {
                    assert_eq!(actual, epoch);
                    break;
                }
                Progress::Activity { .. } => {}
                _ => return Err("capacity input was partially consumed".into()),
            }
        }
        for _ in 0..3 {
            assert!(
                matches!(client.drive(None).await?,Progress::Capacity(actual) if actual==epoch)
            );
            assert_eq!(client.peer(LOCAL), Some(local));
            assert_eq!(client.peer(A), None);
        }
        assert!(client.close()?.is_some());
        assert!(matches!(client.drive(None).await?,Progress::PeerLost{peer,..} if peer==local));
        assert!(matches!(client.drive(None).await?, Progress::Closed));
        server.await??;
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}

#[test]
fn owned_admission_preserves_allocation_and_bounds_spare_capacity() -> Result<(), Failure> {
    let mut bad = Vec::with_capacity(64);
    bad.extend_from_slice(&[0, 8, 0, 0]);
    let bad_pointer = bad.as_ptr();
    let bad_capacity = bad.capacity();
    let rejected = match Message::try_from_owned(bad) {
        Err(rejected) => rejected,
        Ok(_) => return Err("invalid sequence admitted".into()),
    };
    assert_eq!(rejected.value.as_ptr(), bad_pointer);
    assert_eq!(rejected.value.capacity(), bad_capacity);
    assert_eq!(rejected.value, [0, 8, 0, 0]);
    let runtime = runtime()?;
    let _entered = runtime.enter();
    runtime.block_on(tokio::time::timeout(Duration::from_secs(4), async {
        let (socket, listener) = Socket::new()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            init(&mut stream).await?;
            let mut byte = [0; 1];
            assert_eq!(stream.read(&mut byte).await?, 0);
            Ok::<_, Failure>(())
        });
        let mut instance = Instance::new();
        let mut client = Client::<2, 2>::new(
            &mut instance,
            socket.source(),
            ClassOrder::Little,
            0,
            &[0],
            Limits {
                sends: 2,
                source_bytes: 8,
                ..Limits::default()
            },
        )?;
        let local = ready(&mut client).await?;
        let mut owned = Vec::with_capacity(1024);
        owned.extend_from_slice(&MSG);
        let pointer = owned.as_ptr();
        let source = Message::try_from_owned(owned).map_err(|r| r.reason)?;
        assert_eq!(source.as_ref().as_ptr(), pointer);
        let rejected = match client.send(local, 0, 0, source) {
            Err(rejected) => rejected,
            Ok(_) => return Err("spare source capacity bypassed budget".into()),
        };
        assert_eq!(rejected.reason, gnunet_types::Error::Capacity);
        assert_eq!(rejected.value.as_ref().as_ptr(), pointer);
        assert_eq!(client.pending(), 0);
        assert_eq!(client.source_bytes(), 0);
        assert!(client.close()?.is_some());
        server.await??;
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}
