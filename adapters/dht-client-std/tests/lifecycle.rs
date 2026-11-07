//! Actual Unix MQ effects retain original DHT owners across partial IO.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Socket tests assert actual bytes and original recipients."
)]
use gnunet_dht_client_host::{
    Action, Cancel, Client, EndpointSource, Event, Get, Instance, Limits, LossCause, Monitor,
    Outcome, Progress, ipc,
};
use gnunet_types::Error as ProtocolError;
use gnunet_wire::official::{AbsoluteTime, dht::Path};
use std::{
    error::Error,
    future::{Future, poll_fn},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
type Failure = Box<dyn Error + Send + Sync>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Socket(PathBuf);
impl Socket {
    fn new() -> Result<(Self, UnixListener), Failure> {
        let path = std::env::temp_dir().join(format!(
            "gnrs-native-dht-{}-{}.sock",
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
fn limits() -> Limits {
    let mut limits = Limits {
        io_slice_bytes: 1,
        ..Limits::default()
    };
    limits.output.frames = 1;
    limits.protocol.attempts = 1;
    limits
}
fn get(key: &[u8; 64]) -> Get<'_> {
    Get {
        key,
        block_type: 8,
        options: 0,
        replication: 1,
        extended_query: &[],
    }
}
fn put<'a>(key: &'a [u8; 64], payload: &'a [u8]) -> ipc::Put<'a> {
    ipc::Put {
        block_type: 8,
        options: 0,
        replication: 1,
        expiration: AbsoluteTime::NEVER,
        key,
        payload,
    }
}
async fn frame(stream: &mut UnixStream) -> Result<Vec<u8>, Failure> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let n = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if n < 4 {
        return Err("short frame".into());
    }
    let mut b = vec![0; n];
    b[..4].copy_from_slice(&header);
    stream.read_exact(&mut b[4..]).await?;
    Ok(b)
}
fn result(key: &[u8; 64], id: ipc::RequestId, payload: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let r = ipc::ResultMessage {
        block_type: 8,
        options: 0,
        put_path: Path::empty(),
        get_path: Path::empty(),
        id,
        expiration: AbsoluteTime::NEVER,
        key,
        truncated_peer: None,
        payload,
    };
    let mut b = vec![0; r.encoded_len()?];
    r.encode(&mut b)?;
    Ok(b)
}
async fn connected<'a>(c: &mut Client<'a>) -> Result<gnunet_dht_client_host::Epoch<'a>, Failure> {
    loop {
        if let Progress::Connected(e) = c.drive(None).await? {
            return Ok(e);
        }
    }
}
#[test]
fn canceled_partial_get_finishes_exact_frame_then_original_stop() -> Result<(), Failure> {
    let rt = runtime()?;
    let _entered = rt.enter();
    rt.block_on(tokio::time::timeout(Duration::from_secs(4),async{
        let (socket,listener)=Socket::new()?;
        let key=[31;64];
        let server=tokio::spawn(async move{let(mut stream,_)=listener.accept().await?;let first=frame(&mut stream).await?;let ipc::Request::Get(g)=ipc::Request::decode(&first)?else{return Err("missing original GET".into())};assert_eq!(g.key,&key);assert_eq!(g.id,ipc::RequestId([0;8]));let late=result(&key,g.id,b"late")?;stream.write_all(&late).await?;let stop=frame(&mut stream).await?;assert!(matches!(ipc::Request::decode(&stop)?,ipc::Request::Stop(s)if s.id==g.id&&s.key==g.key));let mut end=[0;1];assert_eq!(stream.read(&mut end).await?,0);Ok::<_,Failure>(())});
        let mut i=Instance::new();let mut c=Client::new(&mut i,socket.source(),limits())?;let q=c.get(get(&key))?;connected(&mut c).await?;
        assert!(matches!(c.drive(None).await?,Progress::Activity{written_bytes:1,..}));assert_eq!(c.stop(q)?,Cancel::Draining);
        let mut stopped=false;let mut late=false;while !(stopped&&late){match c.drive(None).await?{Progress::Written{action:Action::Stop(id),..}if id==q=>stopped=true,Progress::Inbound(r)=>{assert!(matches!(r.event(),Event::Ignored(_)));late=true},Progress::Activity{..}|Progress::Written{..}=>{},_=>return Err("unexpected original cancellation state".into())}}
        assert_eq!(c.snapshot().gets,0);assert!(c.close().is_some());server.await??;Ok::<_,Failure>(())
    }))??;
    Ok(())
}
#[test]
fn canceled_future_retains_partial_rx_for_same_original_query() -> Result<(), Failure> {
    let rt = runtime()?;
    let _entered = rt.enter();
    rt.block_on(tokio::time::timeout(Duration::from_secs(4), async {
        let (socket, listener) = Socket::new()?;
        let key = [32; 64];
        let (tx, rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let request = frame(&mut stream).await?;
            let ipc::Request::Get(g) = ipc::Request::decode(&request)? else {
                return Err("missing GET".into());
            };
            let reply = result(&key, g.id, b"original retained response")?;
            stream.write_all(&reply[..2]).await?;
            rx.await?;
            stream.write_all(&reply[2..]).await?;
            let mut end = [0; 1];
            assert_eq!(stream.read(&mut end).await?, 0);
            Ok::<_, Failure>(())
        });
        let mut i = Instance::new();
        let mut c = Client::new(&mut i, socket.source(), limits())?;
        let q = c.get(get(&key))?;
        let epoch = connected(&mut c).await?;
        let mut read = 0;
        while read < 2 {
            match c.drive(None).await? {
                Progress::Activity { read_bytes, .. } => read += read_bytes,
                Progress::Written { .. } => {}
                _ => return Err("unexpected before RX partial".into()),
            }
        }
        {
            let mut waiting = Box::pin(c.drive(None));
            poll_fn(|cx| {
                assert!(waiting.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        tx.send(()).map_err(|()| "server gone")?;
        loop {
            match c.drive(None).await? {
                Progress::Inbound(r) => {
                    assert_eq!(r.epoch(), epoch);
                    assert!(matches!(r.event(),Event::Result{get,..}if *get==q));
                    assert_eq!(r.result()?.payload, b"original retained response");
                    break;
                }
                Progress::Activity { .. } => {}
                _ => return Err("original partial RX was replaced".into()),
            }
        }
        c.close();
        server.await??;
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}
#[test]
fn reconnect_restores_intent_but_never_replays_partial_put() -> Result<(), Failure> {
    let rt = runtime()?;
    let _entered = rt.enter();
    rt.block_on(tokio::time::timeout(Duration::from_secs(6),async{
        let(socket,listener)=Socket::new()?;let key=[33;64];let(tx,rx)=tokio::sync::oneshot::channel();
        let server=tokio::spawn(async move{
            let(mut old,_)=listener.accept().await?;let mut id=None;
            for _ in 0..4{let b=frame(&mut old).await?;match ipc::Request::decode(&b)?{ipc::Request::Get(g)=>{id=Some(g.id);assert_eq!(g.key,&key)},ipc::Request::Known(k)=>assert_eq!(k.hashes.iter().copied().collect::<Vec<_>>(),vec![[7;64]]),ipc::Request::MonitorStart(_)|ipc::Request::HelloGet=>{},_=>return Err("unexpected old subscription".into())}}
            let id=id.ok_or("no old GET")?;old.write_all(&result(&key,id,b"remembered")?).await?;let mut prefix=[0;1];old.read_exact(&mut prefix).await?;assert_eq!(prefix,[0]);rx.await?;let mut tail=Vec::new();old.read_to_end(&mut tail).await?;assert!(tail.is_empty());
            let(mut fresh,_)=listener.accept().await?;let mut restored=[false;4];
            for _ in 0..4{let b=frame(&mut fresh).await?;match ipc::Request::decode(&b)?{ipc::Request::Get(g)=>{assert_eq!(g.id,id);assert_eq!(g.key,&key);restored[0]=true},ipc::Request::Known(k)=>{assert_eq!(k.hashes.iter().copied().collect::<Vec<_>>(),vec![[7;64],gnunet_crypto::hash512(b"remembered")]);restored[1]=true},ipc::Request::MonitorStart(_)=>restored[2]=true,ipc::Request::HelloGet=>restored[3]=true,_=>return Err("one-shot replayed onto replacement MQ".into())}}
            assert!(restored.into_iter().all(|v|v));fresh.write_all(&result(&key,id,b"fresh")?).await?;let mut monitor=[0;88];ipc::MonitorGet{options:0,block_type:8,hop_count:0,replication:1,key:&key}.encode(&mut monitor)?;fresh.write_all(&monitor).await?;let mut absent=[0;4];ipc::encode_hello(None,false,&mut absent)?;fresh.write_all(&absent).await?;
            let mut end=[0;1];assert_eq!(fresh.read(&mut end).await?,0);Ok::<_,Failure>(())
        });
        let mut i=Instance::new();let mut c=Client::new(&mut i,socket.source(),limits())?;let q=c.get(get(&key))?;c.known(q,&[[7;64]])?;let m=c.monitor(Monitor{block_type:8,get:1,result:0,put:0,key:Some(key)})?;let h=c.hello()?;let old=connected(&mut c).await?;
        loop{match c.drive(None).await?{Progress::Inbound(r)=>{assert!(matches!(r.event(),Event::Result{get,..}if *get==q));break},Progress::Activity{..}|Progress::Written{..}=>{},_=>return Err("missing old result".into())}}
        let op=c.put(put(&key,b"original must not replay"))?;assert!(matches!(c.drive(None).await?,Progress::Activity{written_bytes:1,..}));assert!(matches!(c.reconnect()?,Progress::Lost{epoch,cause:LossCause::Requested,..}if epoch==old));tx.send(()).map_err(|()|"server gone")?;
        assert!(matches!(c.drive(None).await?,Progress::Completed(n)if n.operation==op&&n.epoch==Some(old)&&n.outcome==Outcome::Lost));let fresh=connected(&mut c).await?;assert_ne!(old,fresh);
        let mut got=[false;3];while !got.into_iter().all(|v|v){match c.drive(None).await?{Progress::Inbound(r)=>{assert_eq!(r.epoch(),fresh);match r.event(){Event::Result{get,..}=>{assert_eq!(*get,q);assert_eq!(r.result()?.payload,b"fresh");got[0]=true},Event::Monitor{monitors,..}=>{assert_eq!(monitors,&vec![m]);got[1]=true},Event::Hello{requests}=>{assert_eq!(requests,&vec![h]);assert_eq!(r.hello_url()?,None);got[2]=true},_=>return Err("wrong restored recipient".into())}},Progress::Activity{..}|Progress::Written{..}=>{},_=>return Err("unexpected fresh MQ event".into())}}
        c.close();server.await??;Ok::<_,Failure>(())
    }))??;
    Ok(())
}
#[test]
fn canceled_partial_put_drains_original_payload_and_one_terminal_notice() -> Result<(), Failure> {
    let rt = runtime()?;
    let _entered = rt.enter();
    rt.block_on(tokio::time::timeout(Duration::from_secs(4), async {
        let (socket, listener) = Socket::new()?;
        let key = [34; 64];
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let b = frame(&mut stream).await?;
            let ipc::Request::Put(p) = ipc::Request::decode(&b)? else {
                return Err("missing original PUT".into());
            };
            assert_eq!(p.key, &key);
            assert_eq!(p.payload, b"unchanged original PUT");
            let mut end = [0; 1];
            assert_eq!(stream.read(&mut end).await?, 0);
            Ok::<_, Failure>(())
        });
        let mut i = Instance::new();
        let mut c = Client::new(&mut i, socket.source(), limits())?;
        let epoch = connected(&mut c).await?;
        let op = c.put(put(&key, b"unchanged original PUT"))?;
        assert!(matches!(
            c.drive(None).await?,
            Progress::Activity {
                written_bytes: 1,
                ..
            }
        ));
        assert_eq!(c.cancel(op)?, Cancel::Draining);
        loop {
            match c.drive(None).await? {
                Progress::Completed(n) => {
                    assert_eq!(
                        (n.operation, n.epoch, n.outcome),
                        (op, Some(epoch), Outcome::CanceledWritten)
                    );
                    break;
                }
                Progress::Activity { .. } => {}
                _ => return Err("wrong local PUT terminal".into()),
            }
        }
        assert_eq!(c.snapshot().operations, 0);
        c.close();
        assert!(matches!(c.drive(None).await?, Progress::Closed));
        assert!(c.recover_ports().is_err());
        server.await??;
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}
#[test]
fn actual_truncated_eof_retires_input_before_query_restoration() -> Result<(), Failure> {
    let rt = runtime()?;
    let _entered = rt.enter();
    rt.block_on(tokio::time::timeout(Duration::from_secs(4), async {
        let (socket, listener) = Socket::new()?;
        let key = [35; 64];
        let server = tokio::spawn(async move {
            let (mut old, _) = listener.accept().await?;
            let b = frame(&mut old).await?;
            let ipc::Request::Get(g) = ipc::Request::decode(&b)? else {
                return Err("GET".into());
            };
            let reply = result(&key, g.id, b"never completed")?;
            old.write_all(&reply[..5]).await?;
            drop(old);
            let (mut fresh, _) = listener.accept().await?;
            let b2 = frame(&mut fresh).await?;
            assert_eq!(b, b2);
            fresh.write_all(&result(&key, g.id, b"complete")?).await?;
            let mut end = [0; 1];
            assert_eq!(fresh.read(&mut end).await?, 0);
            Ok::<_, Failure>(())
        });
        let mut i = Instance::new();
        let mut c = Client::new(&mut i, socket.source(), limits())?;
        let q = c.get(get(&key))?;
        let old = connected(&mut c).await?;
        loop {
            match c.drive(None).await? {
                Progress::Lost {
                    epoch,
                    cause: LossCause::Io(_),
                    ..
                } => {
                    assert_eq!(epoch, old);
                    break;
                }
                Progress::Activity { .. } | Progress::Written { .. } => {}
                _ => return Err("partial EOF was not actual IO loss".into()),
            }
        }
        let fresh = connected(&mut c).await?;
        assert_ne!(fresh, old);
        loop {
            match c.drive(None).await? {
                Progress::Inbound(r) => {
                    assert_eq!(r.epoch(), fresh);
                    assert!(matches!(r.event(),Event::Result{get,..}if *get==q));
                    assert_eq!(r.result()?.payload, b"complete");
                    break;
                }
                Progress::Activity { .. } | Progress::Written { .. } => {}
                _ => return Err("retired RX contaminated replacement stream".into()),
            }
        }
        c.close();
        server.await??;
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}
