//! Actual local IPC peers for indexed publication; not original-C acceptance.
#![cfg(all(unix, feature = "network"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible publication cases assert original wire acknowledgements and actual source change boundaries"
)]
use gnunet_crypto::hash512;
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
    network::{BlockOptions, IndexPublishCause, IndexRegistration, PublishOptions},
};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use gnunet_wire::official::{
    datastore::{Request, Response, Status},
    fs::{Request as FsRequest, Response as FsResponse},
};
use std::{
    collections::HashMap,
    fs,
    io::{self, Write},
    os::unix::ffi::OsStrExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    task::Poll,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::timeout,
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const WAIT: Duration = Duration::from_secs(5);
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-index-publish-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path)?;
        Ok(Self(path))
    }
    fn socket(&self, name: &str) -> io::Result<(PathBuf, UnixListener)> {
        let path = self.0.join(name);
        let socket = UnixListener::bind(&path)?;
        Ok((path, socket))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
fn native<'id, 'slots, 'buf>(
    instance: &'id mut Instance,
    slots: &'slots mut [Slot<'buf>],
    reservations: &'slots mut [ReservationSlot],
    path: PathBuf,
) -> Result<Client<'id, 'slots, 'buf>, gnunet_datastore_host::Error> {
    let core = ProtocolClient::new(
        instance,
        slots,
        reservations,
        ProtocolLimits {
            max_pending: 1,
            ..Default::default()
        },
    )?;
    Client::new(
        core,
        EndpointSource::unix(path),
        NativeLimits {
            reply_frames: 1,
            reply_bytes: 65535,
            io_slice_bytes: 13,
            ..Default::default()
        },
    )
}
fn options(client: &Client<'_, '_, '_>, reserve: bool) -> Result<PublishOptions, ProtocolError> {
    let mut options = PublishOptions::new(
        AbsoluteTime::from_micros(client.clock().sample()?.now.as_micros() + 4_000_000),
        BlockOptions {
            expiration: AbsoluteTime::from_micros(999_999),
            priority: 365,
            anonymity: 1,
            replication: 2,
        },
    );
    options.reserve_space = reserve;
    Ok(options)
}
async fn read(stream: &mut UnixStream) -> io::Result<Option<Vec<u8>>> {
    let mut head = [0; 4];
    let first = stream.read(&mut head[..1]).await?;
    if first == 0 {
        return Ok(None);
    }
    stream.read_exact(&mut head[1..]).await?;
    let length = usize::from(u16::from_be_bytes([head[0], head[1]]));
    if length < 4 {
        return Err(io::Error::other("short wire frame"));
    }
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&head);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(Some(bytes))
}
async fn send_status(stream: &mut UnixStream, code: i32) -> TestResult {
    let status = Response::Status(Status {
        code,
        min_expiration: AbsoluteTime::UNIX_EPOCH,
        message: None,
    });
    let mut bytes = [0; 16];
    let length = status.encode(&mut bytes)?;
    for part in bytes[..length].chunks(3) {
        stream.write_all(part).await?;
    }
    Ok(())
}
async fn ack_index(stream: &mut UnixStream) -> TestResult {
    let response = FsResponse::IndexStarted;
    let mut bytes = [0; 4];
    response.encode(&mut bytes)?;
    stream.write_all(&bytes).await?;
    Ok(())
}
#[derive(Default)]
struct Captured(HashMap<[u8; 64], (u32, Vec<u8>)>);
impl BlockSink for Captured {
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
fn expected(data: &[u8]) -> gnunet_fs_host::Result<(Content, Captured)> {
    let mut blocks = Captured::default();
    let done = Buffers::new().publish(
        &mut io::Cursor::new(data),
        data.len() as u64,
        &mut blocks,
        Limits::default(),
        |_| Control::Continue,
    )?;
    Ok((done.content, blocks))
}

#[test]
fn indexed_publication_uses_real_registration_exact_reservation_and_type6_leaves() -> TestResult {
    runtime()?.block_on(async {
        for size in [0, 100001] {
            let directory = Directory::new()?;
            let input_path = directory.0.join("source");
            let data: Vec<u8> = (0..size)
                .map(|i| ((i * 17 + i / 32768) % 256) as u8)
                .collect();
            fs::write(&input_path, &data)?;
            let file_id = hash512(&data);
            let (content, reference) = expected(&data)?;
            let (fs_path, fs_listener) = directory.socket("fs.sock")?;
            let (ds_path, ds_listener) = directory.socket("ds.sock")?;
            let mut identity = Instance::new();
            let mut bytes = [0; 65535];
            let mut slots = [Slot::new(&mut bytes)];
            let mut reservations = [ReservationSlot::default(); 1];
            let client = native(&mut identity, &mut slots, &mut reservations, ds_path)?;
            let policy = options(&client, true)?;
            let mut input = tokio::fs::File::open(&input_path).await?;
            let path = tokio::fs::canonicalize(&input_path).await?;
            let peer = async {
                let (mut fs_stream, _) = fs_listener.accept().await?;
                let request = read(&mut fs_stream)
                    .await?
                    .ok_or(ProtocolError::Truncated)?;
                assert!(matches!(
                    FsRequest::decode(&request)?,
                    FsRequest::IndexStart { device: 0, inode: 0, file_id: id, filename }
                        if id == file_id && filename == path.as_os_str().as_bytes()
                ));
                ack_index(&mut fs_stream).await?;
                let (mut stream, _) = ds_listener.accept().await?;
                let reservation = read(&mut stream).await?.ok_or(ProtocolError::Truncated)?;
                let (amount, entries) = if size == 0 { (72, 1) } else { (816, 5) };
                assert!(matches!(
                    Request::decode(&reservation)?,
                    Request::Reserve { amount: a, entries: e } if (a, e) == (amount, entries)
                ));
                send_status(&mut stream, 7).await?;
                let mut offset = 0_u64;
                let mut put_count = 0;
                let mut payload_bytes = 0_u128;
                while let Some(frame) = read(&mut stream).await? {
                    match Request::decode(&frame)? {
                        Request::Put(value) => {
                            assert_eq!(
                                (
                                    value.reservation,
                                    value.priority,
                                    value.anonymity,
                                    value.replication
                                ),
                                (7, 365, 1, 2)
                            );
                            let (kind, body) =
                                reference.0.get(value.key).ok_or(ProtocolError::NotFound)?;
                            if *kind == 1 {
                                assert_eq!(value.kind, 6);
                                assert_eq!(value.value.len(), 72);
                                assert_eq!(&value.value[..64], &file_id);
                                assert_eq!(&value.value[64..], &offset.to_be_bytes());
                                offset = offset.saturating_add(BLOCK_BYTES as u64);
                            } else {
                                assert_eq!(value.kind, 2);
                                assert_eq!(value.value, body);
                            }
                            put_count += 1;
                            payload_bytes += value.value.len() as u128;
                            send_status(&mut stream, 1).await?;
                        }
                        Request::Release { reservation: 7 } => {
                            send_status(&mut stream, 1).await?;
                            break;
                        }
                        _ => {
                            return Err::<_, Box<dyn std::error::Error>>(
                                ProtocolError::Malformed.into(),
                            );
                        }
                    }
                }
                assert_eq!((put_count, payload_bytes), (entries, u128::from(amount)));
                assert!(read(&mut stream).await?.is_none());
                assert!(read(&mut fs_stream).await?.is_none());
                Ok::<_, Box<dyn std::error::Error>>(())
            };
            let publish = async {
                Buffers::new()
                    .store_indexed_file(
                        &mut input,
                        &input_path,
                        EndpointSource::unix(fs_path),
                        client,
                        policy,
                        |_| Control::Continue,
                    )
                    .await
                    .map_err(|error| Box::new(error) as Box<dyn std::error::Error>)
            };
            let (result, ()) = timeout(WAIT, async { tokio::try_join!(publish, peer) }).await??;
            assert_eq!(result.file_id, file_id);
            assert_eq!(result.stored.content, content);
            assert_eq!(result.stored.progress.plaintext_bytes, size as u64);
            assert_eq!(result.stored_bytes, if size == 0 { 72 } else { 816 });
            assert!(result.stored.cleanup.is_none());
            assert!(result.index_retirement_error.is_none());
        }
        Ok(())
    })
}

#[test]
fn indexed_failure_preserves_registration_and_put_prefix_without_unindex_or_replay() -> TestResult {
    runtime()?.block_on(async {
        for lost_index_reply in [false, true] {
            let directory = Directory::new()?;
            let path = directory.0.join("source");
            let data = vec![0x35; 100001];
            fs::write(&path, &data)?;
            let (fs_path, fs_listener) = directory.socket("fs.sock")?;
            let (ds_path, ds_listener) = directory.socket("ds.sock")?;
            let mut identity = Instance::new();
            let mut buffer = [0; 65535];
            let mut slots = [Slot::new(&mut buffer)];
            let mut reservations = [];
            let client = native(&mut identity, &mut slots, &mut reservations, ds_path)?;
            let policy = options(&client, false)?;
            let mut input = tokio::fs::File::open(&path).await?;
            let peer = async {
                let (mut fs_stream, _) = fs_listener.accept().await?;
                assert!(read(&mut fs_stream).await?.is_some());
                if lost_index_reply {
                    drop(fs_stream);
                    return Ok::<_, Box<dyn std::error::Error>>(());
                }
                ack_index(&mut fs_stream).await?;
                let (mut stream, _) = ds_listener.accept().await?;
                let mut puts = 0;
                while let Some(frame) = read(&mut stream).await? {
                    let Request::Put(value) = Request::decode(&frame)? else {
                        return Err(ProtocolError::Malformed.into());
                    };
                    assert_eq!(value.kind, 6);
                    assert_eq!(value.value.len(), 72);
                    puts += 1;
                    if puts == 1 {
                        let mut append = fs::OpenOptions::new().append(true).open(&path)?;
                        append.write_all(&[0x7a])?;
                        append.sync_all()?;
                    }
                    send_status(&mut stream, 1).await?;
                }
                assert_eq!(puts, 4);
                assert!(read(&mut fs_stream).await?.is_none());
                Ok(())
            };
            let publish = async {
                Ok::<_, Box<dyn std::error::Error>>(
                    Buffers::new()
                        .store_indexed_file(
                            &mut input,
                            &path,
                            EndpointSource::unix(fs_path),
                            client,
                            policy,
                            |_| Control::Continue,
                        )
                        .await,
                )
            };
            let (result, ()) = timeout(WAIT, async { tokio::try_join!(publish, peer) }).await??;
            let failure = result.err().ok_or(ProtocolError::InvalidInput)?;
            assert_eq!(failure.hashed_bytes, 100001);
            if lost_index_reply {
                assert_eq!(failure.registration, IndexRegistration::Unknown);
                assert_eq!(failure.progress.blocks, 0);
                assert_eq!(failure.stored_bytes, 0);
                assert!(matches!(
                    failure.cause, IndexPublishCause::Registration(ref error)
                        if error.failure.is_some_and(|f| f.outcome == ProtocolError::OutcomeUnknown)
                ));
                let queued =
                    std::future::poll_fn(|cx| Poll::Ready(ds_listener.poll_accept(cx).is_ready()))
                        .await;
                assert!(!queued);
            } else {
                assert_eq!(failure.registration, IndexRegistration::Acknowledged);
                assert_eq!(failure.progress.blocks, 4);
                assert_eq!(failure.stored_bytes, 288);
                assert!(matches!(
                    failure.cause,
                    IndexPublishCause::Transfer(gnunet_fs_host::network::Error::Local(
                        gnunet_fs_host::Error::SourceChanged
                    ))
                ));
            }
        }
        Ok(())
    })
}
