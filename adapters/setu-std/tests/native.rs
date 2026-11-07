//! One actual Unix IPC ownership model. The explicitly controlled CADET actor
//! supplies official service IPC credits/metadata; this is not C/underlay interop.
#![expect(
    clippy::panic_in_result_fn,
    reason = "One focused actual socket model checks original bind/channel/processing/retirement frames"
)]
use gnunet_cadet_host as cadet;
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{Listener, ServiceOptions},
};
use gnunet_setu::{
    service::{Limits as CoreLimits, Service},
    wire::{Abi, Element, Options, Peer, Request, Response},
};
use gnunet_setu_host::server::{Limits, Progress, Server};
use gnunet_wire::official::cadet::{Request as CRequest, Response as CResponse};
use std::{
    error::Error,
    future::{Future, poll_fn},
    task::Poll,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::oneshot,
    time::Instant,
};
async fn read(stream: &mut UnixStream) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut h = [0; 4];
    stream.read_exact(&mut h).await?;
    let n = usize::from(u16::from_be_bytes([h[0], h[1]]));
    if n < 4 {
        return Err("short frame".into());
    }
    let mut b = vec![0; n];
    b[..4].copy_from_slice(&h);
    stream.read_exact(&mut b[4..]).await?;
    Ok(b)
}
async fn app_send(s: &mut UnixStream, r: Request<'_>, abi: Abi) -> Result<(), Box<dyn Error>> {
    let mut b = vec![0; r.encoded_len(abi)?];
    r.encode(abi, &mut b)?;
    s.write_all(&b).await?;
    Ok(())
}
async fn service_send(s: &mut UnixStream, r: CResponse<'_>) -> Result<(), Box<dyn Error>> {
    let mut b = vec![0; r.encoded_len()?];
    r.encode(&mut b)?;
    s.write_all(&b).await?;
    Ok(())
}
#[test]
fn original_ports_receive_done_cancel_and_outgoing_channel() -> Result<(), Box<dyn Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async{
        let nonce=SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let dir=std::path::PathBuf::from(format!("/tmp/gsetu-{}-{nonce:x}",std::process::id()));std::fs::create_dir(&dir)?;
        let app_path=dir.join("a");let cadet_path=dir.join("c");
        let app_listener=UnixListener::bind(&app_path)?;let cadet_listener=UnixListener::bind(&cadet_path)?;
        let mut instance=cadet::Instance::new();let mut ports=[cadet::PortSlot::new();2];let mut channels=[cadet::ChannelSlot::new();4];
        let abi=Abi::native();let core=Service::new(CoreLimits{clients:2,operations:4,..CoreLimits::default()},abi)?;
        let client=cadet::Client::new(&mut instance,cadet::EndpointSource::unix(cadet_path),&mut ports,&mut channels,cadet::Limits{io_slice_bytes:1,..cadet::Limits::default()})?;
        let mut server=Server::new(core,client,Limits{clients:2,ports:2,channels:4,io_slice_bytes:1,operation_lifetime:Duration::from_secs(3),retirement_grace:Duration::from_secs(1),..Limits::default()},ServiceOptions::default(),UnixAccess::default())?;
        let (strata_tx,strata_rx)=oneshot::channel();let (opened_tx,opened_rx)=oneshot::channel();
        let outcome={
        let app=async{
            let mut listener=UnixStream::connect(&app_path).await?;
            app_send(&mut listener,Request::Listen{reserved:0,app:[3;64]},abi).await?;
            let bytes=read(&mut listener).await?;let Response::Incoming{incoming,peer,context}=Response::decode(&bytes,abi)?else{return Err("expected incoming".into())};assert_eq!(peer,[7;32]);assert!(context.is_none());
            let mut set=UnixStream::connect(&app_path).await?;
            app_send(&mut set,Request::Create,abi).await?;app_send(&mut set,Request::Add(Element{kind:11,data:b"original"}),abi).await?;
            app_send(&mut set,Request::Accept{incoming,request:1,options:Options{force_full:1,..Options::default()}},abi).await?;
            strata_rx.await?;app_send(&mut set,Request::Cancel{request:1},abi).await?;drop(listener);
            app_send(&mut set,Request::Evaluate{request:2,peer:[8;32],app:[4;64],options:Options::default(),context:None},abi).await?;
            opened_rx.await?;app_send(&mut set,Request::Cancel{request:2},abi).await?;drop(set);
            Ok::<_,Box<dyn Error>>(())
        };
        let actor=async{
            let (mut mq,_)=cadet_listener.accept().await?;
            let bytes=read(&mut mq).await?;assert_eq!(CRequest::decode(&bytes)?,CRequest::PortOpen{port:[3;64]});
            service_send(&mut mq,CResponse::ChannelCreate{channel:17,peer:[7;32],port:[3;64],options:0}).await?;
            service_send(&mut mq,CResponse::Ack{channel:17}).await?;
            let op=Peer::Operation{count:0,app:[0;64],context:None};let mut b=vec![0;op.encoded_len()?];op.encode(abi,&mut b)?;
            service_send(&mut mq,CResponse::Data{channel:17,priority:0,messages:&b}).await?;
            let (mut acked,mut strata,mut incoming_closed,mut port_closed)=(false,false,false,false);
            let mut outgoing=None;let mut strata_tx=Some(strata_tx);let mut opened_tx=Some(opened_tx);
            for _ in 0..32{
                let bytes=read(&mut mq).await?;
                match CRequest::decode(&bytes)?{
                    CRequest::Ack{channel:17}=>acked=true,
                    CRequest::Data{channel:17,messages,..}=>{assert!(matches!(Peer::decode(messages,abi)?,Peer::Strata{compressed:true,count:1,set_size:1,..}));strata=true;if let Some(tx)=strata_tx.take(){tx.send(()).map_err(|_|"strata observer lost")?;}},
                    CRequest::ChannelDestroy{channel:17}=>incoming_closed=true,
                    CRequest::PortClose{port}=>{assert_eq!(port,[3;64]);port_closed=true;},
                    CRequest::ChannelCreate{channel,peer,port,options}=>{assert_eq!(peer,[8;32]);assert_eq!(port,[4;64]);assert_eq!(options,0);outgoing=Some(channel);service_send(&mut mq,CResponse::Ack{channel}).await?;},
                    CRequest::Data{channel,messages,..}=>{assert_eq!(Some(channel),outgoing);assert!(matches!(Peer::decode(messages,abi)?,Peer::Operation{count:1,app,..}if app==[4;64]));if let Some(tx)=opened_tx.take(){tx.send(()).map_err(|_|"open observer lost")?;}},
                    CRequest::ChannelDestroy{channel}=>{assert_eq!(Some(channel),outgoing);assert!(acked&&strata&&incoming_closed&&port_closed);return Ok::<_,Box<dyn Error>>(());},
                    _=>return Err("unexpected actual CADET frame".into()),
                }
            }Err("finite actor frame bound".into())
        };
        let (mut app,mut actor)=(std::pin::pin!(app),std::pin::pin!(actor));let (mut app_done,mut actor_done)=(false,false);let until=Instant::now()+Duration::from_secs(5);
        poll_fn(|cx|{
            if !app_done && let Poll::Ready(r)=app.as_mut().poll(cx){r?;app_done=true;}
            if !actor_done && let Poll::Ready(r)=actor.as_mut().poll(cx){r?;actor_done=true;}
            if app_done&&actor_done{return Poll::Ready(Ok::<_,Box<dyn Error>>(()));}
            match server.poll(cx,&[Listener::Unix(&app_listener)],Some(until),&mut |_|{}){
                Poll::Ready(Ok(Progress::Activity))=>cx.waker().wake_by_ref(),
                Poll::Ready(Ok(Progress::WaitDeadline|Progress::Stopped))=>return Poll::Ready(Err("native model deadline".into())),
                Poll::Ready(Err(e))=>return Poll::Ready(Err(e.into())),Poll::Pending=>{},
            }Poll::Pending
        }).await
        };
        let stopped=server.shutdown(|_|{});drop(server);outcome?;if let Some(e)=stopped.failure{return Err(e.into())}
        assert_eq!(stopped.report.accepted,2);assert_eq!(stopped.report.closed,2);assert_eq!(stopped.report.receive_done,1);assert_eq!(stopped.report.peer_frames,2);
        drop(app_listener);drop(cadet_listener);std::fs::remove_dir_all(dir)?;Ok(())
    })
}
