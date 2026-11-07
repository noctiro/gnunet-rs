//! Real signed keyword results routed through two actual local CLIENT MQs.
#![cfg(all(unix, feature = "service"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Native search asserts authenticated per-query intersection"
)]
use gnunet_fs::{Content, Keyword, Keywords, Uri, client::Instance, ublock};
use gnunet_fs_host::{
    ipc,
    search::{Limits, Options, Session, Step},
};
use gnunet_types::AbsoluteTime;
use gnunet_wire::official::fs::{BlockType, ClientPut, Request, Response};
use std::{
    io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
    time::timeout,
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Socket(PathBuf);
impl Drop for Socket {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.0) {
            Ok(()) | Err(_) => {}
        }
    }
}
#[test]
fn actual_keyword_connections_emit_a_result_only_after_both_mandatory_hits() -> TestResult {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async{
        static NEXT:AtomicU64=AtomicU64::new(1);
        let socket=Socket(std::env::temp_dir().join(format!("gnunet-fs-search-{}-{}.sock",std::process::id(),NEXT.fetch_add(1,Ordering::Relaxed))));
        let listener=UnixListener::bind(&socket.0)?;
        let content=Content{key:[1;64],query:[2;64],size:3};
        let mut blocks=Vec::new();
        for label in [b"alpha".as_slice(),b"beta".as_slice()] {
            let publisher=ublock::Publisher::keyword(label,ublock::Limits::default())?;
            let mut wire=vec![0;1024];let query=*publisher.context().query();
            let block=publisher.seal(b"",content.uri(),None,&mut wire)?.bytes().to_vec();blocks.push((query,block));
        }
        let server=tokio::spawn(async move{
            let mut peers=Vec::new();
            for _ in 0..2 {
                let(mut peer,_)=listener.accept().await?;
                let mut frame=[0;112];peer.read_exact(&mut frame).await?;
                let Request::Search(query)=Request::decode(&frame)? else{return Err("expected search".into());};
                assert_eq!(query.block_type,BlockType::UBLOCK);assert_eq!(query.options,1);
                let(_,block)=blocks.iter().find(|(key,_)|*key==query.query).ok_or("wrong query")?;
                let response=Response::Put(ClientPut{block_type:BlockType::UBLOCK,expiration:AbsoluteTime::NEVER,last_transmission:AbsoluteTime::from_micros(0),num_transmissions:0,respect_offered:0,block});
                let mut frame=vec![0;response.encoded_len()?];response.encode(&mut frame)?;peer.write_all(&frame).await?;peers.push(peer);
            }
            for mut peer in peers {let mut one=[0];assert_eq!(peer.read(&mut one).await?,0);}
            Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
        });
        let source=ipc::EndpointSource::unix(socket.0.clone());
        let deadline=AbsoluteTime::from_micros(source.clock().sample()?.now.as_micros()+5_000_000);
        let path=socket.0.clone();
        let terms=[Keyword::new(b"alpha",true)?,Keyword::new(b"beta",true)?];
        let mut instances=[Instance::new(),Instance::new()];
        let mut session=Session::<_,4>::new(Uri::Keywords(Keywords::new(&terms)?),&mut instances,
            move||Ok(ipc::EndpointSource::unix(path.clone())),Options{anonymity:1,local_only:true,deadline,limits:Limits::default(),block:ublock::Limits::default(),protocol:ipc::ProtocolLimits::default(),native:ipc::Limits::default()})?;
        let mut pending=0;
        timeout(Duration::from_secs(2),async{
            loop {match session.drive(None).await? {
                Step::Pending{result}=>{pending+=1;assert!(!session.result(result).ok_or("missing partial")?.visible());},
                Step::Result{result}=>{let record=session.result(result).ok_or("missing result")?;assert!(record.visible());assert!(matches!(record.uri(gnunet_fs::Limits::default())?,Uri::Content(value) if value==content));assert_eq!(record.matched_queries().len(),2);break;},
                Step::Rejected{cause,..}=>return Err(cause.into()),
                Step::Failed{cause,..}=>return Err(cause.into()),
                _=>{},
            }}
            Ok::<_,Box<dyn std::error::Error>>(())
        }).await??;
        assert_eq!(pending,1);session.cancel()?;
        timeout(Duration::from_secs(2),server).await??.map_err(|e|io::Error::other(e.to_string()))?;
        Ok::<_,Box<dyn std::error::Error>>(())
    })
}
