//! Actual managed namespace PUT/status exchanges and independent local graph facts.
//! These local Rust peers do not grant official-C or remote propagation acceptance.
#![cfg(all(unix, feature = "network"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible native fixtures assert real signed frames, original replies and graph-only recovery"
)]
use gnunet_datastore_host::{
    Client, Instance, Limits as NativeLimits, Outcome, ProtocolClient, ProtocolLimits,
    ReservationSlot, Slot,
};
use gnunet_fs::{
    Content, Uri, metadata as md,
    ublock::{Context, Limits as ArtifactLimits},
};
use gnunet_fs_host::{
    Buffers, Control,
    durable::store,
    namespace::{
        FailureCause,
        graph::{self, Graph},
        key::KeyFile,
    },
    network::{
        BlockOptions, Error as TransferError,
        ublock::{FailureCause as UblockCause, UblockOptions},
    },
};
use gnunet_types::AbsoluteTime;
use gnunet_wire::official::datastore::{Data, Request, Response, Status};
use std::{
    fs, io,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::timeout,
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const WAIT: Duration = Duration::from_secs(4);
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-managed-ns-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
struct Socket(PathBuf);
impl Socket {
    fn bind() -> io::Result<(Self, UnixListener)> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-managed-ns-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = UnixListener::bind(&path)?;
        Ok((Self(path), listener))
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        let _cleanup = fs::remove_file(&self.0);
    }
}
fn client<'id, 's, 'b>(
    identity: &'id mut Instance,
    slots: &'s mut [Slot<'b>],
    reservations: &'s mut [ReservationSlot],
    socket: &Socket,
) -> Result<Client<'id, 's, 'b>, gnunet_datastore_host::Error> {
    let core = ProtocolClient::new(
        identity,
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
            io_slice_bytes: 7,
            ..NativeLimits::default()
        },
    )
}
fn policy(client: &Client<'_, '_, '_>) -> Result<UblockOptions, gnunet_types::Error> {
    Ok(UblockOptions::new(
        AbsoluteTime::from_micros(client.clock().sample()?.now.as_micros() + 3_000_000),
        BlockOptions {
            expiration: AbsoluteTime::NEVER,
            priority: 7,
            anonymity: 2,
            replication: 3,
        },
    ))
}
fn content() -> Content {
    Content {
        key: [41; 64],
        query: [42; 64],
        size: 17,
    }
}
async fn frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if length < 4 {
        return Err(io::Error::other("short native frame"));
    }
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
fn status_bytes(code: i32) -> Result<Vec<u8>, gnunet_types::Error> {
    let mut bytes = vec![0; 64];
    let n = Response::Status(Status {
        code,
        min_expiration: AbsoluteTime::from_micros(123),
        message: Some(b"managed status\0"),
    })
    .encode(&mut bytes)?;
    bytes.truncate(n);
    Ok(bytes)
}
fn inspect(
    value: Data<'_>,
    namespace: &[u8; 32],
    label: &[u8],
    update: &[u8],
    metadata: Option<&[u8]>,
) -> TestResult<usize> {
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
    assert_eq!(value.expiration, AbsoluteTime::NEVER);
    let context = Context::namespace(namespace, label, ArtifactLimits::default())?;
    assert_eq!(value.key, context.query());
    let mut plain = vec![0; value.value.len()];
    let opened = context.open(value.value, &mut plain)?;
    let mut scratch = vec![0; 4096];
    let decoded = opened.decode(
        &mut scratch,
        &mut gnunet_fs_codec::Inflate::new(),
        md::Mode::Strict,
    )?;
    assert!(matches!(decoded.uri()?,Uri::Content(found) if found==content()));
    assert_eq!(decoded.update_identifier(), update);
    assert_eq!(decoded.raw_metadata(), metadata.unwrap_or_default());
    assert_eq!(decoded.metadata().is_some(), metadata.is_some());
    Ok(value.value.len())
}
async fn closed(stream: &mut UnixStream) -> io::Result<()> {
    let mut extra = [0];
    assert_eq!(stream.read(&mut extra).await?, 0);
    Ok(())
}
#[test]
fn accepted_native_publications_persist_selected_metadata_and_optional_update_distinctions()
-> TestResult {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let temporary=Temporary::new()?;let key=KeyFile::create(temporary.0.join("key"))?;let public=key.public_key();
        let graph_path=temporary.0.join("graph");
        let mut graph=Graph::create(&graph_path,public,graph::Limits::default(),store::Limits::default())?;
        let (socket,listener)=Socket::bind()?;
        let mut empty_order=[];let mut empty_scratch=[0;128];
        let empty=md::plan_uncompressed(&[],&mut empty_order,&mut empty_scratch,md::Limits::default(),md::Options::default())?;
        let mut empty_bytes=vec![0;empty.report().wire_bytes];empty.write(&mut empty_bytes)?;
        let items=[md::Item {kind:42,format:md::Format::Binary,data:b"selected metadata",plugin:None,mime:None}];
        let mut order=[0];let mut scratch=[0;1024];
        let selected=md::plan_uncompressed(&items,&mut order,&mut scratch,md::Limits::default(),md::Options::default())?;
        let mut selected_bytes=vec![0;selected.report().wire_bytes];selected.write(&mut selected_bytes)?;
        let acks=[status_bytes(1)?,status_bytes(0)?,status_bytes(7)?];
        let peer=async {
            let expected=[(b"\xffroot".as_slice(),b"next".as_slice(),None),
                (b"empty".as_slice(),b"".as_slice(),Some(empty_bytes.as_slice())),
                (b"untracked".as_slice(),b"".as_slice(),Some(selected_bytes.as_slice()))];
            let mut accepted_bytes=Vec::new();
            for (index,(label,update,metadata)) in expected.into_iter().enumerate() {
                let (mut stream,_)=listener.accept().await?;
                let original=frame(&mut stream).await?;
                let Request::Put(value)=Request::decode(&original)? else {return Err("expected managed PUT".into());};
                accepted_bytes.push(inspect(value,&public,label,update,metadata)?);
                stream.write_all(&acks[index]).await?;closed(&mut stream).await?;
            }
            assert!(timeout(Duration::from_millis(40),listener.accept()).await.is_err());
            Ok::<_,Box<dyn std::error::Error>>(accepted_bytes)
        };
        let publish=async {
            let mut receipts=Vec::new();let mut buffers=Buffers::new();
            for (index,label) in [b"\xffroot".as_slice(),b"empty".as_slice(),b"untracked".as_slice()].iter().enumerate() {
                let mut identity=Instance::new();let mut wire=vec![0;65535];let mut slots=[Slot::new(&mut wire)];let mut reservations=[];
                let native=client(&mut identity,&mut slots,&mut reservations,&socket)?;let options=policy(&native)?;
                let update=match index {0=>Some(b"next".as_slice()),1=>Some(b"".as_slice()),_=>None};
                let metadata=match index {0=>None,1=>Some(&empty),_=>Some(&selected)};
                let done=buffers.store_managed_namespace(native,&key,&mut graph,label,update,content().uri(),metadata,options,|_|Control::Continue).await?;
                assert_eq!(done.publication.progress.accepted,1);
                assert_eq!(done.publication.last_response_bytes(),Some(acks[index].as_slice()));assert!(done.publication.cleanup.is_none());
                assert_eq!(done.record.is_some(),index<2);
                assert_eq!(done.publication.metadata_selection,metadata.map(md::Plan::report));
                receipts.push(done.publication.progress.wire_bytes);
            }
            Ok::<_,Box<dyn std::error::Error>>(receipts)
        };
        let (receipts,seen)=timeout(WAIT,async {tokio::try_join!(publish,peer)}).await??;
        assert_eq!(receipts,seen.into_iter().map(|n|n as u128).collect::<Vec<_>>());
        assert_eq!(graph.record_count(),2);drop(graph);
        let mut graph=Graph::open(&graph_path,public,graph::Limits::default(),store::Limits::default())?;
        assert_eq!(graph.record_count(), 2);
        let mut ids = graph.record_ids();
        let first = graph.record(ids.next().ok_or("first record id absent")?)?.ok_or("first record absent")?;
        assert_eq!(first.identifier(),b"\xffroot");assert_eq!(first.update(),b"next");assert!(first.metadata().is_none());
        assert!(matches!(first.uri(gnunet_fs::Limits::default())?,Uri::Content(found) if found==content()));
        let second = graph.record(ids.next().ok_or("second record id absent")?)?.ok_or("second record absent")?;
        assert_eq!(second.identifier(),b"empty");assert_eq!(second.update(),b"");assert_eq!(second.metadata(),Some(empty_bytes.as_slice()));
        Ok::<_,Box<dyn std::error::Error>>(())
    })
}
#[test]
fn refused_and_lost_native_puts_never_add_graph_records_or_replay_weighted_writes() -> TestResult {
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        let temporary=Temporary::new()?;let key=KeyFile::create(temporary.0.join("key"))?;let public=key.public_key();
        let graph_path=temporary.0.join("graph");let mut graph=Graph::create(&graph_path,public,graph::Limits::default(),store::Limits::default())?;
        let (socket,listener)=Socket::bind()?;
        let peer=async {
            for (index,label) in [b"refused".as_slice(),b"lost".as_slice()].iter().enumerate() {
                let (mut stream,_)=listener.accept().await?;let original=frame(&mut stream).await?;
                let Request::Put(value)=Request::decode(&original)? else {return Err("expected namespace PUT".into());};
                inspect(value,&public,label,b"next",None)?;
                if index==0 {stream.write_all(&status_bytes(-1)?).await?;closed(&mut stream).await?;}else {drop(stream);}
            }
            assert!(timeout(Duration::from_millis(80),listener.accept()).await.is_err());
            Ok::<_,Box<dyn std::error::Error>>(())
        };
        let publish=async {
            for (index,label) in [b"refused".as_slice(),b"lost".as_slice()].iter().enumerate() {
                let mut identity=Instance::new();let mut wire=vec![0;65535];let mut slots=[Slot::new(&mut wire)];let mut reservations=[];
                let native=client(&mut identity,&mut slots,&mut reservations,&socket)?;let options=policy(&native)?;
                let failure=Buffers::new().store_managed_namespace(native,&key,&mut graph,label,Some(b"next"),content().uri(),None,options,|_|Control::Continue)
                    .await.err().ok_or("refused or lost PUT became managed success")?;
                assert!(failure.accepted.is_none());assert_eq!(graph.record_count(),0);
                let FailureCause::Publication(ublock)=&failure.cause else {return Err("native refusal was relabeled".into());};
                assert_eq!(ublock.progress.accepted,0);
                let UblockCause::Transfer(TransferError::Store(store))=&ublock.cause else {return Err("original store outcome was lost".into());};
                if index==0 {assert!(matches!(store.outcome,Outcome::Status{code:-1,..}));assert!(matches!(store.response()?,Some(Response::Status(value)) if value.code==-1));}
                else {assert_eq!(store.outcome,Outcome::Unknown);assert!(store.response()?.is_none());}
            }
            Ok::<_,Box<dyn std::error::Error>>(())
        };
        timeout(WAIT,async {tokio::try_join!(publish,peer)}).await??;
        drop(graph);let reopened=Graph::open(&graph_path,public,graph::Limits::default(),store::Limits::default())?;
        assert_eq!(reopened.record_count(),0);
        Ok::<_,Box<dyn std::error::Error>>(())
    })
}
#[test]
fn actual_ack_survives_graph_authority_failure_and_explicit_graph_only_recovery_sends_no_put()
-> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let temporary = Temporary::new()?;
            let key = KeyFile::create(temporary.0.join("key"))?;
            let public = key.public_key();
            let graph_path = temporary.0.join("graph");
            let held_path = temporary.0.join("original-graph");
            let mut graph = Graph::create(
                &graph_path,
                public,
                graph::Limits::default(),
                store::Limits::default(),
            )?;
            let (socket, listener) = Socket::bind()?;
            let ack = status_bytes(1)?;
            let items = [md::Item {
                kind: 42,
                format: md::Format::Binary,
                data: b"kept after actual ACK",
                plugin: None,
                mime: None,
            }];
            let mut order = [0];
            let mut scratch = [0; 1024];
            let plan = md::plan_uncompressed(
                &items,
                &mut order,
                &mut scratch,
                md::Limits::default(),
                md::Options::default(),
            )?;
            let mut encoded_metadata = vec![0; plan.report().wire_bytes];
            plan.write(&mut encoded_metadata)?;
            let peer = async {
                let (mut stream, _) = listener.accept().await?;
                let original = frame(&mut stream).await?;
                let Request::Put(value) = Request::decode(&original)? else {
                    return Err("expected namespace PUT".into());
                };
                let bytes = inspect(
                    value,
                    &public,
                    b"accepted",
                    b"next",
                    Some(&encoded_metadata),
                )?;
                // The real native PUT has already been observed and authenticated.
                // Change local WAL authority before its actual STATUS1 reaches the publisher.
                fs::rename(&graph_path, &held_path)?;
                fs::create_dir(&graph_path)?;
                fs::set_permissions(&graph_path, fs::Permissions::from_mode(0o700))?;
                stream.write_all(&ack).await?;
                closed(&mut stream).await?;
                assert!(
                    timeout(Duration::from_millis(100), listener.accept())
                        .await
                        .is_err()
                );
                Ok::<_, Box<dyn std::error::Error>>(bytes)
            };
            let publish = async {
                let mut identity = Instance::new();
                let mut wire = vec![0; 65535];
                let mut slots = [Slot::new(&mut wire)];
                let mut reservations = [];
                let native = client(&mut identity, &mut slots, &mut reservations, &socket)?;
                let options = policy(&native)?;
                let mut failure = Buffers::new()
                    .store_managed_namespace(
                        native,
                        &key,
                        &mut graph,
                        b"accepted",
                        Some(b"next"),
                        content().uri(),
                        Some(&plan),
                        options,
                        |_| Control::Continue,
                    )
                    .await
                    .err()
                    .ok_or("changed graph authority became managed success")?;
                assert!(matches!(
                    &failure.cause,
                    FailureCause::Graph(graph::Error::Storage(_))
                ));
                assert!(graph.storage_failure().is_some());
                assert_eq!(graph.record_count(), 0);
                let accepted = failure
                    .accepted
                    .take()
                    .ok_or("actual STATUS1 acceptance was erased")?;
                assert_eq!(accepted.publication.progress.accepted, 1);
                assert_eq!(
                    accepted.publication.last_response_bytes(),
                    Some(ack.as_slice())
                );
                assert_eq!(accepted.publication.metadata_selection, Some(plan.report()));
                assert!(accepted.publication.cleanup.is_none());
                assert_eq!(accepted.update().identifier(), b"accepted");
                assert_eq!(accepted.update().update(), b"next");
                assert_eq!(
                    accepted.update().metadata(),
                    Some(encoded_metadata.as_slice())
                );
                drop(failure);
                drop(graph);
                // Explicit test-fixture repair restores the original writer authority.
                // Product code never removes the foreign directory or retries the PUT.
                fs::remove_dir(&graph_path)?;
                fs::rename(&held_path, &graph_path)?;
                let mut reopened = Graph::open(
                    &graph_path,
                    public,
                    graph::Limits::default(),
                    store::Limits::default(),
                )?;
                assert_eq!(reopened.record_count(), 0);
                let done = accepted.record(&mut reopened)?;
                assert_eq!(done.publication.progress.accepted, 1);
                assert_eq!(done.publication.last_response_bytes(), Some(ack.as_slice()));
                assert_eq!(reopened.record_count(), 1);
                let id = done.record.ok_or("local accepted update record missing")?;
                let stored = reopened.record(id)?.ok_or("accepted record unavailable")?;
                assert_eq!(stored.identifier(), b"accepted");
                assert_eq!(stored.metadata(), Some(encoded_metadata.as_slice()));
                let wire_bytes = done.publication.progress.wire_bytes;
                drop(reopened);
                let final_graph = Graph::open(
                    &graph_path,
                    public,
                    graph::Limits::default(),
                    store::Limits::default(),
                )?;
                assert_eq!(final_graph.record_count(), 1);
                Ok::<_, Box<dyn std::error::Error>>(wire_bytes)
            };
            let (accepted, observed) =
                timeout(WAIT, async { tokio::try_join!(publish, peer) }).await??;
            assert_eq!(accepted, observed as u128);
            Ok::<_, Box<dyn std::error::Error>>(())
        })
}
