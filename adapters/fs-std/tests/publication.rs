//! Actual local DATASTORE peers and complete acknowledged file-tree insertion.
#![cfg(all(unix, feature = "network"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Publication tests assert actual acknowledgements, uncertainty and cleanup"
)]
use gnunet_datastore_host::{
    Client, Instance, Limits as NativeLimits, ProtocolClient, ProtocolLimits, ReservationSlot, Slot,
};
use gnunet_fs::{
    Content,
    content::{BLOCK_BYTES, EncodedNode},
};
use gnunet_fs_host::{
    BlockSink, Buffers, Control, Insert, Limits,
    ipc::EndpointSource,
    network::{BlockOptions, Error, PublishOptions},
};
use gnunet_types::AbsoluteTime;
use gnunet_wire::official::datastore::{Request, Response, Status};
use std::{
    collections::HashMap,
    io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::timeout,
};
type TestResult = Result<(), Box<dyn std::error::Error>>;
struct Socket(PathBuf);
impl Socket {
    fn bind() -> io::Result<(Self, UnixListener)> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-fs-store-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = UnixListener::bind(&path)?;
        Ok((Self(path), listener))
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.0) {
            Ok(()) | Err(_) => {}
        }
    }
}
type Blocks = HashMap<[u8; 64], (u32, Vec<u8>)>;
#[derive(Default)]
struct Store(Blocks);
impl BlockSink for Store {
    fn insert_block(&mut self, node: EncodedNode<'_>) -> gnunet_fs_host::Result<Insert> {
        self.0.insert(
            node.block().key().query,
            (
                if node.node().level() == 0 { 1 } else { 2 },
                node.block().bytes().to_vec(),
            ),
        );
        Ok(Insert::Created)
    }
}
fn expected(data: &[u8]) -> Result<(Content, Blocks), gnunet_fs_host::Error> {
    let mut store = Store::default();
    let done = Buffers::new().publish(
        &mut io::Cursor::new(data),
        data.len() as u64,
        &mut store,
        Limits::default(),
        |_| Control::Continue,
    )?;
    Ok((done.content, store.0))
}
fn native<'a, 's, 'b>(
    instance: &'a mut Instance,
    slots: &'s mut [Slot<'b>],
    reservations: &'s mut [ReservationSlot],
    socket: &Socket,
) -> Result<Client<'a, 's, 'b>, gnunet_datastore_host::Error> {
    let core = ProtocolClient::new(
        instance,
        slots,
        reservations,
        ProtocolLimits {
            max_pending: 1,
            ..ProtocolLimits::default()
        },
    )?;
    Client::new(
        core,
        EndpointSource::unix(socket.0.clone()),
        NativeLimits {
            reply_frames: 1,
            reply_bytes: 65535,
            ..NativeLimits::default()
        },
    )
}
fn policy(client: &Client<'_, '_, '_>) -> Result<PublishOptions, gnunet_types::Error> {
    Ok(PublishOptions::new(
        AbsoluteTime::from_micros(client.clock().sample()?.now.as_micros() + 5_000_000),
        BlockOptions {
            expiration: AbsoluteTime::from_micros(99),
            priority: 10,
            anonymity: 1,
            replication: 2,
        },
    ))
}
async fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let len = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if len < 4 {
        return Err(io::Error::other("short frame"));
    }
    let mut bytes = vec![0; len];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn status(
    stream: &mut UnixStream,
    code: i32,
    message: Option<&[u8]>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let response = Response::Status(Status {
        code,
        min_expiration: AbsoluteTime::from_micros(17),
        message,
    });
    let mut bytes = vec![0; 16 + message.map_or(0, <[u8]>::len)];
    let n = response.encode(&mut bytes)?;
    stream.write_all(&bytes[..n]).await?;
    Ok(())
}

#[test]
fn every_put_is_acknowledged_and_release_failure_preserves_known_file_receipt() -> TestResult {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async{
        let data=vec![37;BLOCK_BYTES+19];let(content,expected)=expected(&data)?;let count=expected.len();
        let bytes=gnunet_fs::content::Layout::new(content.size).encoded_tree_bytes() as u64;
        let(socket,listener)=Socket::bind()?;
        let server=tokio::spawn(async move{
            let(mut stream,_)=listener.accept().await?;
            assert_eq!(Request::decode(&read_frame(&mut stream).await?)?,Request::Reserve{amount:bytes,entries:count as u32});
            status(&mut stream,7,None).await?;
            for _ in 0..count {
                let frame=read_frame(&mut stream).await?;
                let Request::Put(value)=Request::decode(&frame)? else{return Err("expected PUT".into());};
                let (kind,block)=expected.get(value.key).ok_or("unknown query")?;
                assert_eq!(value.kind,*kind);assert_eq!(value.value,block);assert_eq!(value.reservation,7);
                assert_eq!((value.priority,value.anonymity,value.replication),(10,1,2));assert_eq!(value.expiration,AbsoluteTime::from_micros(99));
                status(&mut stream,1,None).await?;
            }
            assert_eq!(Request::decode(&read_frame(&mut stream).await?)?,Request::Release{reservation:7});
            status(&mut stream,-1,Some(b"release refused\0")).await?;
            let mut one=[0];assert_eq!(stream.read(&mut one).await?,0);
            Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
        });
        let mut instance=Instance::new();let mut frame=vec![0;65535];let mut slots=[Slot::new(&mut frame)];let mut reservations=[ReservationSlot::default();1];
        let client=native(&mut instance,&mut slots,&mut reservations,&socket)?;let mut options=policy(&client)?;options.reserve_space=true;
        let done=timeout(Duration::from_secs(3),Buffers::new().store_file(&mut data.as_slice(),data.len() as u64,client,options, |_|Control::Continue)).await??;
        assert_eq!(done.content,content);assert_eq!(done.progress.blocks,count as u64);assert_eq!(done.progress.plaintext_bytes,data.len() as u64);
        let cleanup=done.cleanup.ok_or("missing cleanup refusal")?;
        assert!(matches!(cleanup.outcome,gnunet_datastore_host::Outcome::Status{code:-1,..}));
        assert!(matches!(cleanup.response()?,Some(Response::Status(reply)) if reply.message==Some(&b"release refused\0"[..])));
        timeout(Duration::from_secs(2),server).await??.map_err(|e|io::Error::other(e.to_string()))?;
        Ok::<_,Box<dyn std::error::Error>>(())
    })
}

#[test]
fn lost_root_put_reply_is_unknown_and_is_never_replayed() -> TestResult {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async{
        let(socket,listener)=Socket::bind()?;
        let server=tokio::spawn(async move{
            let(mut stream,_)=listener.accept().await?;let bytes=read_frame(&mut stream).await?;
            assert!(matches!(Request::decode(&bytes)?,Request::Put(value) if value.kind==1 && value.value.len()==16));
            drop(stream);
            assert!(timeout(Duration::from_millis(30),listener.accept()).await.is_err());
            Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
        });
        let mut instance=Instance::new();let mut frame=vec![0;65535];let mut slots=[Slot::new(&mut frame)];let mut reservations=[];
        let client=native(&mut instance,&mut slots,&mut reservations,&socket)?;let options=policy(&client)?;
        let result=timeout(Duration::from_secs(2),Buffers::new().store_file(&mut &b""[..],0,client,options, |_|Control::Continue)).await?;
        assert!(matches!(result,Err(Error::Store(failure)) if failure.outcome==gnunet_datastore_host::Outcome::Unknown && failure.query.is_some() && failure.cause.is_some()));
        server.await?.map_err(|e|io::Error::other(e.to_string()))?;
        Ok::<_,Box<dyn std::error::Error>>(())
    })
}

#[test]
fn trailing_input_is_refused_before_the_final_root_put() -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (socket, listener) = Socket::bind()?;
            let mut instance = Instance::new();
            let mut frame = vec![0; 65535];
            let mut slots = [Slot::new(&mut frame)];
            let mut reservations = [];
            let client = native(&mut instance, &mut slots, &mut reservations, &socket)?;
            let options = policy(&client)?;
            let result = Buffers::new()
                .store_file(&mut &b"abcd"[..], 3, client, options, |_| Control::Continue)
                .await;
            assert!(matches!(
                result,
                Err(Error::Local(gnunet_fs_host::Error::SourceChanged))
            ));
            assert!(
                timeout(Duration::from_millis(10), listener.accept())
                    .await
                    .is_err()
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        })
}
