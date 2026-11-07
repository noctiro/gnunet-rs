//! Controlled Unix DATASTORE actor with the actual native Port/Driver.
//! CORE peer announcements are explicit pure fixtures; no remote replica,
//! datastore backend, type6 worker or complete FS daemon acceptance is claimed.
#![cfg(all(unix, feature = "server"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The single model asserts actual original Unix requests/replies, copied metadata, uncertain mutation retirement and no replay"
)]
use gnunet_datastore_host::{self as ds, EndpointSource, Outcome};
use gnunet_fs::{
    content::encode_data,
    gap::{self, storage as pure},
};
use gnunet_fs_host::server::gap::storage::{Datastore, Driver, Failure, Terminal};
use gnunet_service_runtime::clock::{RuntimeClock, SystemClock};
use gnunet_types::{Duration as Timeout, Error};
use gnunet_wire::official::{
    AbsoluteTime,
    datastore::{Data, Request, Response, Status},
    fs::BlockType,
    fs_gap::Put,
};
use std::{
    future::{Future, poll_fn},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::oneshot,
};
static NEXT_SOCKET: AtomicU64 = AtomicU64::new(0);
struct Socket(PathBuf);
impl Socket {
    fn bind() -> Result<(Self, UnixListener), Failure> {
        let path = std::env::temp_dir().join(format!(
            "gnrs-fs-gstore-{}-{}.sock",
            std::process::id(),
            NEXT_SOCKET.fetch_add(1, Ordering::Relaxed)
        ));
        let listener = UnixListener::bind(&path)?;
        Ok((Self(path), listener))
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        let _removed = std::fs::remove_file(&self.0);
    }
}
struct Entropy;
impl gap::Entropy for Entropy {
    fn uniform(&mut self, upper: u32) -> Result<u32, Error> {
        upper.checked_sub(1).map(|_| 0).ok_or(Error::InvalidInput)
    }
}
async fn frame(stream: &mut UnixStream) -> Result<Vec<u8>, Failure> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if !(4..=1024).contains(&length) {
        return Err(Error::TooLarge.into());
    }
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn reply(stream: &mut UnixStream, response: Response<'_>) -> Result<(), Failure> {
    let mut bytes = [0; 1024];
    let length = response.encode(&mut bytes)?;
    stream.write_all(&bytes[..length]).await?;
    Ok(())
}
async fn next(
    driver: &mut Driver<'_, '_, '_>,
    clock: &Arc<dyn RuntimeClock>,
) -> Result<bool, Failure> {
    poll_fn(|cx| {
        let now = clock.sample()?.now.as_micros();
        driver.poll(cx, now, &mut Entropy)
    })
    .await
}

#[test]
fn original_native_store_put_replication_and_exposed_loss_are_not_replayed() -> Result<(), Failure>
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _entered = runtime.enter();
    let scenario = async {
        let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
        // Stable brands precede every borrowed owner, including the boxed native port.
        let mut gap_instance = gap::Instance::new();
        let mut storage_instance = pure::Instance::new();
        let mut datastore_instance = ds::Instance::new();
        let (socket, listener) = Socket::bind()?;
        let mut encoded = [0; 256];
        let content = encode_data(b"actual native cache and replication block", &mut encoded)?;
        let key = content.key().query;
        let ciphertext = content.bytes().to_vec();
        let mut incoming = [0; 512];
        let n = Put {
            block_type: BlockType::DBLOCK,
            expiration: AbsoluteTime::NEVER,
            block: &ciphertext,
        }
        .encode(&mut incoming)?;
        let first_now = clock.sample()?.now.as_micros();
        let cached_expiration = AbsoluteTime::from_micros(first_now + pure::YEAR_US);
        let selected_expiration = AbsoluteTime::from_micros(first_now + 2 * pure::YEAR_US);
        let (put_seen, mut put_rx) = oneshot::channel();
        let (allow_status, status_rx) = oneshot::channel();
        let (cleanup_done, cleanup_rx) = oneshot::channel();
        let actor_ciphertext = ciphertext.clone();
        let actor = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let first = frame(&mut stream).await?;
            let Request::Put(put) = Request::decode(&first)? else {
                return Err("actor expected the original cache PUT".into());
            };
            assert_eq!(
                (
                    put.reservation,
                    put.kind,
                    put.priority,
                    put.anonymity,
                    put.replication,
                    put.uid
                ),
                (0, 1, 7, 1, 0, 0)
            );
            assert_eq!(*put.key, key);
            assert_eq!(put.value, actor_ciphertext);
            assert_eq!(put.expiration, cached_expiration);
            put_seen.send(()).map_err(|_| Error::Closed)?;
            status_rx.await?;
            reply(
                &mut stream,
                Response::Status(Status {
                    code: 1,
                    min_expiration: AbsoluteTime::UNIX_EPOCH,
                    message: None,
                }),
            )
            .await?;
            let replication = frame(&mut stream).await?;
            assert_eq!(Request::decode(&replication)?, Request::Replication);
            assert_eq!(replication.len(), 4);
            reply(
                &mut stream,
                Response::Data(Data {
                    reservation: 0,
                    kind: 1,
                    priority: 9,
                    anonymity: 3,
                    replication: 7,
                    uid: 55,
                    expiration: selected_expiration,
                    key: &key,
                    value: &actor_ciphertext,
                }),
            )
            .await?;
            // The actor receives the entire second mutation, then gives no ACK.
            // Whether a real backend would commit is deliberately unknown.
            let second = frame(&mut stream).await?;
            let Request::Put(put) = Request::decode(&second)? else {
                return Err("actor expected the independent second cache PUT".into());
            };
            assert_eq!(*put.key, key);
            assert_eq!(put.value, actor_ciphertext);
            assert_eq!((put.priority, put.anonymity, put.replication), (0, 1, 0));
            stream.shutdown().await?;
            drop(stream);
            // Keep listening through explicit cleanup: an automatic replacement
            // connection for the exposed original mutation fails this model.
            tokio::select! {
                biased;
                accepted=listener.accept()=>{let _unexpected=accepted?;Err::<(),Failure>("exposed cache mutation was automatically replayed/reconnected".into())},
                cleaned=cleanup_rx=>{cleaned?;Ok::<(),Failure>(())},
            }
        });
        let mut datastore_buffer = [0; 1024];
        let mut datastore_slots = [ds::Slot::new(&mut datastore_buffer)];
        let mut reservations = [];
        let protocol = ds::ProtocolClient::new(
            &mut datastore_instance,
            &mut datastore_slots,
            &mut reservations,
            ds::ProtocolLimits {
                max_pending: 1,
                max_frame_bytes: 1024,
                max_lifetime: Timeout(2_000_000),
                ..ds::ProtocolLimits::default()
            },
        )?;
        let client = ds::Client::new(
            protocol,
            EndpointSource::unix_with_clock(socket.0.clone(), clock.clone()),
            ds::Limits {
                frame_bytes: 1024,
                reply_frames: 1,
                reply_bytes: 1024,
                io_slice_bytes: 1,
            },
        )?;
        let port = Datastore::new(client, Timeout(2_000_000))?;
        let mut neighbors = [gap::NeighborSlot::default(); 2];
        let mut result = [0; 512];
        let mut route_rows = [gap::RouteSlot::new(&mut result)];
        let mut path_rows = [gap::PathSlot::default(); 2];
        let mut output = [0; 512];
        let mut core_fixture = gap::Router::new(
            &mut gap_instance,
            &mut neighbors,
            &mut route_rows,
            &mut path_rows,
            &mut output,
            gap::Limits::default(),
        )?;
        let peer = core_fixture.attach([0x42; 32])?;
        let mut peers = [pure::PeerSlot::new(); 2];
        let mut cache_a = [0; 512];
        let mut cache_b = [0; 512];
        let mut caches = [
            pure::CacheSlot::new(&mut cache_a),
            pure::CacheSlot::new(&mut cache_b),
        ];
        let mut selected_a = [0; 512];
        let mut selected_b = [0; 512];
        let mut selected = [
            pure::MigrationSlot::new(&mut selected_a),
            pure::MigrationSlot::new(&mut selected_b),
        ];
        let owner = pure::Owner::new(
            &mut storage_instance,
            &mut peers,
            &mut caches,
            &mut selected,
            pure::Limits::default(),
        )?;
        let mut driver = Driver::new(owner, Box::new(port), None, clock.clone())?;
        driver.attach(peer, [0x42; 32])?;
        driver.receive(
            peer,
            gap::CheckedPut::decode(&incoming[..n])?,
            gap::CacheInterest {
                requested: false,
                priority: 7,
            },
            first_now,
        )?;
        poll_fn(|cx| {
            let mut observed = false;
            if let Poll::Ready(result) =
                driver.poll(cx, clock.sample()?.now.as_micros(), &mut Entropy)
            {
                result?;
                observed = true;
            }
            match std::pin::Pin::new(&mut put_rx).poll(cx) {
                Poll::Ready(result) => {
                    result?;
                    Poll::Ready(Ok::<(), Failure>(()))
                }
                Poll::Pending => {
                    if observed {
                        cx.waker().wake_by_ref()
                    }
                    Poll::Pending
                }
            }
        })
        .await?;
        assert_eq!(
            driver.owner().report().cache_stored,
            0,
            "full request write is not a storage receipt"
        );
        assert!(driver.owner().active().is_some());
        allow_status.send(()).map_err(|_| Error::Closed)?;
        while driver.owner().report().selected != 1 {
            next(&mut driver, &clock).await?;
        }
        assert_eq!(driver.owner().report().cache_stored, 1);
        assert_eq!(driver.report().terminals, 2);
        let metadata = driver
            .owner()
            .report()
            .last_selected
            .ok_or(Error::NotReady)?;
        assert_eq!(
            (
                metadata.uid,
                metadata.replication,
                metadata.anonymity,
                metadata.original_kind
            ),
            (55, 7, 3, 1)
        );
        assert_eq!(metadata.key, key);
        assert_eq!(metadata.expiration, selected_expiration);
        let raw = driver
            .report()
            .first_selected
            .as_ref()
            .ok_or(Error::NotReady)?;
        let Response::Data(data) = Response::decode(raw.bytes())? else {
            return Err(Error::Malformed.into());
        };
        assert_eq!((data.uid, data.replication, data.anonymity), (55, 7, 3));
        assert_eq!(data.value, ciphertext);
        driver.receive(
            peer,
            gap::CheckedPut::decode(&incoming[..n])?,
            gap::CacheInterest {
                requested: false,
                priority: 0,
            },
            clock.sample()?.now.as_micros(),
        )?;
        let failure = loop {
            match next(&mut driver, &clock).await {
                Ok(_) => {}
                Err(error) => break error,
            }
        };
        let terminal = failure
            .downcast_ref::<Terminal>()
            .ok_or("original uncertain terminal was not preserved")?;
        assert_eq!(terminal.outcome, Outcome::Unknown);
        assert!(terminal.frame.is_none());
        assert!(terminal.cause.is_some());
        assert!(driver.owner().fenced());
        assert!(driver.owner().active().is_none());
        assert_eq!(driver.owner().report().unknown, 1);
        assert_eq!(driver.report().terminals, 3);
        assert_eq!(
            driver.owner().report().cache_stored,
            1,
            "missing ACK cannot advance the second PUT"
        );
        let mut cx = Context::from_waker(Waker::noop());
        for _ in 0..3 {
            assert!(
                driver
                    .poll(&mut cx, clock.sample()?.now.as_micros(), &mut Entropy)
                    .is_pending()
            );
        }
        driver.request_shutdown()?;
        assert!(driver.quiesced());
        driver.close(clock.sample()?.now.as_micros())?;
        cleanup_done.send(()).map_err(|_| Error::Closed)?;
        actor.await??;
        core_fixture.request_shutdown();
        assert!(core_fixture.quiesced());
        Ok::<(), Failure>(())
    };
    runtime.block_on(tokio::time::timeout(Duration::from_secs(5), scenario))??;
    Ok(())
}
