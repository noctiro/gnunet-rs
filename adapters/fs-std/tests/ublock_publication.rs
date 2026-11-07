//! Real native DATASTORE exchanges for signed UBLOCK publication.
//! The socket peer is a focused Rust test fixture, not official C acceptance.
#![cfg(all(unix, feature = "network"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible publication tests assert original wire/status, multiplicity and uncertain outcomes"
)]
use gnunet_crypto::gns::EdkeySecret;
use gnunet_datastore_host::{
    Client, Instance, Limits as NativeLimits, ProtocolClient, ProtocolLimits, Slot,
};
use gnunet_fs::{
    Content, Uri, metadata as md,
    ublock::{Context, Limits as ArtifactLimits},
};
use gnunet_fs_host::{
    Buffers, Control,
    network::{
        BlockOptions, Error as TransferError,
        ublock::{FailureCause, UblockOptions},
    },
};
use gnunet_types::AbsoluteTime;
use gnunet_wire::official::datastore::{Data, Request, Response, Status};
use std::{
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
const PAYLOAD: [u8; 1024] = [0x22; 1024];
struct Socket(PathBuf);
impl Socket {
    fn bind() -> io::Result<(Self, UnixListener)> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-ublock-store-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = UnixListener::bind(&path)?;
        Ok((Self(path), listener))
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_file(&self.0);
    }
}
fn client<'id, 's, 'b>(
    instance: &'id mut Instance,
    slots: &'s mut [Slot<'b>],
    reservations: &'s mut [gnunet_datastore_host::ReservationSlot],
    socket: &Socket,
) -> Result<Client<'id, 's, 'b>, gnunet_datastore_host::Error> {
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
        gnunet_client_host::EndpointSource::unix(socket.0.clone()),
        NativeLimits {
            reply_frames: 1,
            reply_bytes: 65535,
            io_slice_bytes: 5,
            ..NativeLimits::default()
        },
    )
}
fn policy(client: &Client<'_, '_, '_>) -> Result<UblockOptions, gnunet_types::Error> {
    Ok(UblockOptions::new(
        AbsoluteTime::from_micros(client.clock().sample()?.now.as_micros() + 5_000_000),
        BlockOptions {
            expiration: AbsoluteTime::from_micros(99),
            priority: 7,
            anonymity: 2,
            replication: 3,
        },
    ))
}
fn content() -> Content {
    Content {
        key: [4; 64],
        query: [8; 64],
        size: 123,
    }
}
async fn frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
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
async fn status(stream: &mut UnixStream) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let response = Response::Status(Status {
        code: 1,
        min_expiration: AbsoluteTime::from_micros(17),
        message: None,
    });
    let mut bytes = [0; 16];
    let n = response.encode(&mut bytes)?;
    stream.write_all(&bytes[..n]).await?;
    Ok(())
}
fn inspect(
    value: Data<'_>,
    context: Context<'_>,
    update: &[u8],
) -> Result<usize, Box<dyn std::error::Error + Send + Sync>> {
    assert_eq!(
        (
            value.reservation,
            value.kind,
            value.priority,
            value.anonymity,
            value.replication,
            value.uid
        ),
        (0, 9, 7, 2, 3, 0)
    );
    assert_eq!(value.expiration, AbsoluteTime::from_micros(99));
    assert_eq!(value.key, context.query());
    let mut plain = vec![0; value.value.len()];
    let opened = context.open(value.value, &mut plain)?;
    let mut metadata = vec![0; 2048];
    let decoded = opened.decode(
        &mut metadata,
        &mut gnunet_fs_codec::Inflate::new(),
        md::Mode::Strict,
    )?;
    assert!(matches!(decoded.uri()?,Uri::Content(v) if v==content()));
    assert_eq!(decoded.update_identifier(), update);
    let metadata = decoded.metadata().ok_or("missing actual metadata")?;
    assert_eq!(metadata.accepted_entries(), 1);
    assert!(metadata.was_compressed());
    assert_eq!(metadata.items().next().ok_or("missing item")?.data, PAYLOAD);
    Ok(value.value.len())
}

#[test]
fn ksk_multiplicity_and_namespace_updates_publish_real_blocks_and_statuses() -> TestResult {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async{
  let(socket,listener)=Socket::bind()?;
  let peer=tokio::spawn(async move{
   let(mut stream,_)=listener.accept().await?;let mut bytes=0;let mut previous=None;
   for label in [b"alpha".as_slice(),b"alpha".as_slice(),b"beta".as_slice()]{let original=frame(&mut stream).await?;let Request::Put(value)=Request::decode(&original)? else{return Err("expected PUT".into());};bytes+=inspect(value,Context::keyword(label,ArtifactLimits::default())?,b"")?;
    if label==b"alpha" {if let Some(ref previous)=previous{assert_eq!(value.value,previous);}else{previous=Some(value.value.to_vec());}}
    status(&mut stream).await?;
   }
   let mut one=[0];assert_eq!(stream.read(&mut one).await?,0);
   let(mut stream,_)=listener.accept().await?;let original=frame(&mut stream).await?;let Request::Put(value)=Request::decode(&original)? else{return Err("expected namespace PUT".into());};
   let secret=EdkeySecret::from_seed([17;32]);let ns=inspect(value,Context::namespace(&secret.public_key(),b"\xffid",ArtifactLimits::default())?,b"\xfenext")?;status(&mut stream).await?;assert_eq!(stream.read(&mut one).await?,0);
   Ok::<_,Box<dyn std::error::Error+Send+Sync>>((bytes,ns))
  });
  let items=[md::Item{kind:42,format:md::Format::Binary,data:&PAYLOAD,plugin:None,mime:None}];let mut order=[0];let mut plain=[0;2048];let mut coded=[0;2048];let plan=md::plan(&items,&mut order,&mut plain,&mut coded,&mut gnunet_fs_codec::Compressor::new(),md::Limits::default(),md::Options{compression:md::Compression::Always,..md::Options::default()})?;assert!(plan.report().compressed);
  let Uri::Keywords(keywords)=Uri::parse(b"gnunet://fs/ksk/%2Balpha+alpha+beta",gnunet_fs::Limits::default())? else{return Err("expected KSK".into());};
  let mut buffers=Buffers::new();let mut instance=Instance::new();let mut wire=vec![0;65535];let mut slots=[Slot::new(&mut wire)];let mut reservations=[];
  let native=client(&mut instance,&mut slots,&mut reservations,&socket)?;let options=policy(&native)?;
  let result=timeout(Duration::from_secs(3),buffers.store_keywords(native,keywords,content().uri(),Some(&plan),options,|_|Control::Continue)).await??;
  assert_eq!(result.progress.accepted,3);assert_eq!(result.progress.last_query,Some(*Context::keyword(b"beta",ArtifactLimits::default())?.query()));assert_eq!(result.metadata_selection,Some(plan.report()));assert!(result.cleanup.is_none());assert!(matches!(result.last_response()?,Some(Response::Status(value)) if value.code==1 && value.min_expiration==AbsoluteTime::from_micros(17)));
  let mut instance=Instance::new();let mut wire=vec![0;65535];let mut slots=[Slot::new(&mut wire)];let mut reservations=[];let native=client(&mut instance,&mut slots,&mut reservations,&socket)?;let options=policy(&native)?;let secret=EdkeySecret::from_seed([17;32]);
  let ns=timeout(Duration::from_secs(3),buffers.store_namespace(native,&secret,b"\xffid",b"\xfenext",content().uri(),Some(&plan),options,|_|Control::Continue)).await??;
  assert_eq!(ns.progress.accepted,1);assert!(ns.cleanup.is_none());
  let(bytes,nsbytes)=timeout(Duration::from_secs(3),peer).await??.map_err(|e|io::Error::other(e.to_string()))?;
  assert_eq!(result.progress.wire_bytes,bytes as u128);assert_eq!(ns.progress.wire_bytes,nsbytes as u128);
  Ok::<_,Box<dyn std::error::Error>>(())
 })
}

#[test]
fn a_lost_second_weighted_put_preserves_accepted_prefix_and_is_not_replayed() -> TestResult {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async{
  let(socket,listener)=Socket::bind()?;
  let peer=tokio::spawn(async move{
   let(mut stream,_)=listener.accept().await?;
   let original=frame(&mut stream).await?;assert!(matches!(Request::decode(&original)?,Request::Put(value) if value.key==Context::keyword(b"first",ArtifactLimits::default())?.query()));status(&mut stream).await?;
   let original=frame(&mut stream).await?;assert!(matches!(Request::decode(&original)?,Request::Put(value) if value.key==Context::keyword(b"second",ArtifactLimits::default())?.query()));drop(stream);
   assert!(timeout(Duration::from_millis(40),listener.accept()).await.is_err());
   Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
  });
  let Uri::Keywords(keywords)=Uri::parse(b"gnunet://fs/ksk/first+second",gnunet_fs::Limits::default())? else{return Err("expected KSK".into());};
  let mut instance=Instance::new();let mut wire=vec![0;65535];let mut slots=[Slot::new(&mut wire)];let mut reservations=[];let native=client(&mut instance,&mut slots,&mut reservations,&socket)?;let options=policy(&native)?;
  let failure=timeout(Duration::from_secs(3),Buffers::new().store_keywords(native,keywords,content().uri(),None,options,|_|Control::Continue)).await?.err().ok_or("lost PUT became success")?;
  assert_eq!(failure.progress.accepted,1);assert_eq!(failure.failed_index,1);assert_eq!(failure.progress.last_query,Some(*Context::keyword(b"first",ArtifactLimits::default())?.query()));assert_eq!(failure.query,Some(*Context::keyword(b"second",ArtifactLimits::default())?.query()));assert!(matches!(failure.last_response()?,Some(Response::Status(value)) if value.code==1));
  assert!(matches!(failure.cause,FailureCause::Transfer(TransferError::Store(error)) if error.outcome==gnunet_datastore_host::Outcome::Unknown && error.query==failure.query));
  timeout(Duration::from_secs(3),peer).await??.map_err(|e|io::Error::other(e.to_string()))?;
  Ok::<_,Box<dyn std::error::Error>>(())
 })
}

#[test]
fn a_later_invalid_term_retains_its_index_without_submitting_any_put() -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (socket, listener) = Socket::bind()?;
            let Uri::Keywords(keywords) =
                Uri::parse(b"gnunet://fs/ksk/ok+oversize", gnunet_fs::Limits::default())?
            else {
                return Err("expected KSK".into());
            };
            let mut instance = Instance::new();
            let mut wire = vec![0; 65535];
            let mut slots = [Slot::new(&mut wire)];
            let mut reservations = [];
            let native = client(&mut instance, &mut slots, &mut reservations, &socket)?;
            let mut options = policy(&native)?;
            options.limits.max_label_bytes = 2;
            let failure = Buffers::new()
                .store_keywords(native, keywords, content().uri(), None, options, |_| {
                    Control::Continue
                })
                .await
                .err()
                .ok_or("oversize term accepted")?;
            assert_eq!(failure.failed_index, 1);
            assert_eq!(failure.progress.accepted, 0);
            assert!(failure.query.is_none());
            assert!(failure.last_response()?.is_none());
            assert!(matches!(
                failure.cause,
                FailureCause::Artifact(gnunet_fs::ublock::Error::Limit)
            ));
            assert!(
                timeout(Duration::from_millis(20), listener.accept())
                    .await
                    .is_err()
            );
            Ok(())
        })
}
