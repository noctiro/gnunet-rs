//! Private local IPC, original worker and restart with public structural fixtures.
#![cfg(any(unix, windows))]
#![forbid(unsafe_code)]
use gnunet_namestore::{Code, Filter, SecretKeyView};
use gnunet_namestore_host::{
    database,
    server::{Limits, Ports, Progress, Server},
    worker::Worker,
};
use gnunet_native::filesystem::Directory;
use gnunet_service_runtime::local::{Listener as LocalListener, Stream};
use gnunet_service_runtime::{
    clock::SystemClock,
    credentials::UnixAccess,
    service::{Listener, ServiceOptions},
};
use gnunet_snapshot_host::Namespace;
use gnunet_wire::official::{
    identity::KeyType,
    namestore::{self as wire, CString, Records, Request, Response, StoreSet},
};
#[cfg(windows)]
use socket2::{Domain, SockAddr, Socket, Type};
use std::{
    error::Error,
    future::{Future, poll_fn},
    path::PathBuf,
    sync::Arc,
    task::Poll,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;
type Failure = Box<dyn Error>;
struct Temporary(PathBuf);
impl Temporary {
    fn new() -> std::io::Result<Self> {
        let mut nonce = [0; 16];
        gnunet_native::entropy::fill(&mut nonce)?;
        let parent = std::env::temp_dir();
        let name = format!("gn-ns-{:032x}", u128::from_be_bytes(nonce));
        Directory::open(&parent)?.create_private_directory(std::ffi::OsStr::new(&name))?;
        Ok(Self(parent.join(name)))
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
fn listen(path: &std::path::Path) -> std::io::Result<LocalListener> {
    #[cfg(unix)]
    {
        LocalListener::bind(path)
    }
    #[cfg(windows)]
    {
        let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
        socket.bind(&SockAddr::unix(path)?)?;
        socket.listen(16)?;
        LocalListener::from_bound_socket(socket)
    }
}
async fn send(s: &mut Stream, r: Request<'_>) -> Result<(), Failure> {
    let mut b = Zeroizing::new(vec![0; r.encoded_len()?]);
    r.encode(&mut b)?;
    s.write_all(&b).await?;
    Ok(())
}
async fn frame(s: &mut Stream) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut h = [0; 4];
    s.read_exact(&mut h).await?;
    let length = usize::from(u16::from_be_bytes([h[0], h[1]]));
    if !(4..=512).contains(&length) {
        return Err("unexpected bounded model frame".into());
    }
    let mut b = Zeroizing::new(vec![0; length]);
    b[..4].copy_from_slice(&h);
    s.read_exact(&mut b[4..]).await?;
    Ok(b)
}
#[expect(
    clippy::panic_in_result_fn,
    reason = "The compile-only model asserts its public result code"
)]
fn code(bytes: &[u8], rid: u32, expected: u32) -> Result<(), Failure> {
    assert!(
        matches!(Response::decode(bytes)?,Response::Generic{rid:r,code:c}if r==rid&&c==expected)
    );
    Ok(())
}
#[expect(
    clippy::panic_in_result_fn,
    reason = "The compile-only model asserts its public record fields"
)]
fn record(bytes: &[u8], label: &[u8], last: u8) -> Result<(), Failure> {
    let Response::Records {
        label: l, records, ..
    } = Response::decode(bytes)?
    else {
        return Err("expected actual record".into());
    };
    assert_eq!(l.bytes(), label);
    assert_eq!(records.count(), 1);
    let one = records.records().iter().next().ok_or("missing record")??;
    assert_eq!(one.data, &[192, 0, 2, last]);
    Ok(())
}
async fn store(
    s: &mut Stream,
    rid: u32,
    key: SecretKeyView<'_>,
    sets: &[StoreSet<'_>],
    atomic: bool,
) -> Result<(), Failure> {
    let mut body = Zeroizing::new(vec![0; wire::encoded_sets_len(sets)?]);
    wire::encode_sets(sets, &mut body)?;
    send(
        s,
        Request::Store {
            rid,
            zone: key,
            single_tx: u16::from(atomic),
            reserved: 0,
            sets: wire::RecordSets::new(&body, u16::try_from(sets.len())?)?,
        },
    )
    .await
}
async fn actor(path: PathBuf) -> Result<(), Failure> {
    // Published structural mock. This is never generated or used for key math.
    let mut mock = Zeroizing::new([0x42; 36]);
    mock[..4].copy_from_slice(&KeyType::Eddsa.value().to_be_bytes());
    let key = SecretKeyView::new(&*mock)?;
    let mut raw = Zeroizing::new([0; 32]);
    raw[..8].copy_from_slice(&u64::MAX.to_be_bytes());
    raw[8..10].copy_from_slice(&4u16.to_be_bytes());
    raw[12..16].copy_from_slice(&1u32.to_be_bytes());
    raw[16..20].copy_from_slice(&[192, 0, 2, 1]);
    let first = Records::new(&*raw, 1)?;
    let mut raw2 = Zeroizing::new(*raw);
    raw2[19] = 2;
    let second = Records::new(&*raw2, 1)?;
    let mut monitor = Stream::connect(&path).await?;
    send(
        &mut monitor,
        Request::MonitorStart {
            zone: Some(key),
            iterate_first: 0,
            filter: 0,
        },
    )
    .await?;
    assert!(matches!(
        Response::decode(&frame(&mut monitor).await?)?,
        Response::MonitorSync
    ));
    let mut rpc = Stream::connect(&path).await?;
    let sets = [
        StoreSet {
            label: CString::new(b"alpha")?,
            records: first,
            reserved: 0,
        },
        StoreSet {
            label: CString::new(b"beta")?,
            records: first,
            reserved: 0,
        },
    ];
    store(&mut rpc, 1, key, &sets, true).await?;
    record(&frame(&mut monitor).await?, b"alpha", 1)?;
    let mut byte = [0];
    assert!(
        tokio::time::timeout(Duration::from_millis(5), rpc.read(&mut byte))
            .await
            .is_err()
    ); // Only one initial credit; no early STORE result.
    send(
        &mut monitor,
        Request::MonitorNext {
            limit: 1,
            reserved: 0,
        },
    )
    .await?;
    record(&frame(&mut monitor).await?, b"beta", 1)?;
    code(&frame(&mut rpc).await?, 1, 0)?;
    send(
        &mut rpc,
        Request::Lookup {
            rid: 2,
            zone: key,
            label: CString::new(b"alpha")?,
            filter: 0,
            unused: 0,
        },
    )
    .await?;
    assert!(matches!(
        Response::decode(&frame(&mut rpc).await?)?,
        Response::Lookup {
            rid: 2,
            found: 1,
            ..
        }
    ));
    send(
        &mut rpc,
        Request::EditBegin {
            rid: 3,
            zone: key,
            label: CString::new(b"alpha")?,
            hint: CString::new(b"editor")?,
            reserved: 0,
        },
    )
    .await?;
    assert!(matches!(
        Response::decode(&frame(&mut rpc).await?)?,
        Response::Edit {
            rid: 3,
            code: 0,
            hint: None,
            ..
        }
    ));
    send(
        &mut rpc,
        Request::EditCancel {
            rid: 4,
            zone: key,
            label: CString::new(b"alpha")?,
            hint: CString::new(b"editor")?,
            replacement: CString::new(b"")?,
        },
    )
    .await?;
    code(&frame(&mut rpc).await?, 4, 0)?;
    let invalid = [
        StoreSet {
            label: CString::new(b"alpha")?,
            records: second,
            reserved: 0,
        },
        StoreSet {
            label: CString::new(b"bad.name")?,
            records: first,
            reserved: 0,
        },
    ];
    store(&mut rpc, 5, key, &invalid, true).await?;
    code(&frame(&mut rpc).await?, 5, Code::LABEL_INVALID.value())?;
    send(
        &mut rpc,
        Request::Lookup {
            rid: 6,
            zone: key,
            label: CString::new(b"alpha")?,
            filter: 0,
            unused: 0,
        },
    )
    .await?;
    let b = frame(&mut rpc).await?;
    let Response::Lookup {
        records, found: 1, ..
    } = Response::decode(&b)?
    else {
        return Err("atomic prefix unexpectedly changed".into());
    };
    assert_eq!(
        records
            .records()
            .iter()
            .next()
            .ok_or("missing original")??
            .data,
        &[192, 0, 2, 1]
    );
    send(
        &mut monitor,
        Request::MonitorNext {
            limit: 1,
            reserved: 0,
        },
    )
    .await?;
    store(&mut rpc, 7, key, &invalid, false).await?;
    record(&frame(&mut monitor).await?, b"alpha", 2)?;
    code(&frame(&mut rpc).await?, 7, Code::LABEL_INVALID.value())?;
    let mut iterator = Stream::connect(&path).await?;
    send(
        &mut iterator,
        Request::IterateStart {
            rid: 10,
            zone: Some(key),
            filter: 0,
        },
    )
    .await?;
    record(&frame(&mut iterator).await?, b"beta", 1)?;
    send(&mut iterator, Request::IterateNext { rid: 10, limit: 2 }).await?;
    record(&frame(&mut iterator).await?, b"alpha", 2)?;
    assert!(matches!(
        Response::decode(&frame(&mut iterator).await?)?,
        Response::End { rid: 10 }
    ));
    drop(iterator);
    let mut stopped = Stream::connect(&path).await?;
    send(
        &mut stopped,
        Request::IterateStart {
            rid: 11,
            zone: Some(key),
            filter: 0,
        },
    )
    .await?;
    let _actual = frame(&mut stopped).await?;
    send(&mut stopped, Request::IterateStop { rid: 11 }).await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(5), stopped.read(&mut byte))
            .await
            .is_err()
    );
    drop(stopped);
    drop(monitor);
    drop(rpc);
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The aggregate model asserts original storage and independently reopened recovery observations"
)]
fn actual_mock_batch_monitor_editor_worker_and_restart() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let temporary = Temporary::new()?;
            let path = temporary.0.join("ipc");
            let directory = temporary.0.join("store");
            let listener = listen(&path)?;
            let listeners = [Listener::Unix(&listener)];
            let pure = gnunet_namestore::Limits {
                rows: 8,
                zones: 2,
                image_bytes: 4096,
                retained_bytes: 262144,
                records_per_set: 8,
                record_bytes: 128,
                batch: 4,
                ..gnunet_namestore::Limits::default()
            };
            let options = database::Options::new(directory, pure, 4096)?;
            let (core, store) = options.open()?.recover()?.into_parts();
            let generation = store.generation();
            let mut worker = Worker::start(store)?;
            let mut server = Server::new(
                core,
                &mut worker,
                generation,
                Limits {
                    clients: 4,
                    output_items: 4,
                    frame_bytes: 512,
                    output_frames: 1,
                    output_bytes: 512,
                    io_slice_bytes: 3,
                    snapshot_body_bytes: 4096,
                    iterators: 2,
                    ..Limits::default()
                },
                Ports {
                    options: ServiceOptions::default(),
                    unix: UnixAccess {
                        match_uid: cfg!(unix),
                        match_gid: false,
                    },
                    clock: Arc::new(SystemClock),
                },
            )?;
            let mut peer = std::pin::pin!(actor(path));
            let result = tokio::time::timeout(
                Duration::from_secs(8),
                poll_fn(|cx| {
                    if let Poll::Ready(done) = peer.as_mut().poll(cx) {
                        return Poll::Ready(done);
                    }
                    match server.poll(cx, &listeners, None, &mut |_| {}) {
                        Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
                        Poll::Ready(Ok(Progress::Activity)) => {
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                        Poll::Ready(Ok(_)) => Poll::Ready(Err("unexpected service stop".into())),
                        Poll::Pending => Poll::Pending,
                    }
                }),
            )
            .await;
            let stopped = server.shutdown(|_| {}).await;
            result??;
            assert_eq!(stopped.report.committed, 4);
            assert_eq!(stopped.report.submitted, 4);
            assert!(stopped.failure.is_none());
            let joined = stopped.worker.ok_or("worker was not actually joined")?;
            assert_eq!(joined.namespace, Namespace::Namestore);
            assert_eq!(joined.generation, 5);
            assert!(joined.failure.is_none());
            drop(server);
            // Only production Store/recovery interpret the newly created public-mock
            // body. No helper opens, hashes, prints, or peeks its persisted bytes.
            let (core, reopened) = options.open()?.recover()?.into_parts();
            assert_eq!(reopened.generation(), 5);
            assert_eq!(core.snapshot()?.rows().len(), 2);
            let mut mock = Zeroizing::new([0x42; 36]);
            mock[..4].copy_from_slice(&KeyType::Eddsa.value().to_be_bytes());
            let q = core.lookup(SecretKeyView::new(&*mock)?, b"alpha", Filter::NONE, 0)?;
            assert!(q.found());
            assert_eq!(
                q.records()?
                    .records()
                    .iter()
                    .next()
                    .ok_or("missing recovered record")??
                    .data,
                &[192, 0, 2, 2]
            );
            drop(reopened);
            Ok(())
        })
}
