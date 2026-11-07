//! Native FS driver over local test peers, not official C interoperability.
#![cfg(all(unix, feature = "service"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Native operation tests assert original stream and cancellation boundaries"
)]
use gnunet_fs::client::Event;
use gnunet_fs_host::ipc::{
    BlockType, Client, ClientPut, EndpointSource, Error, Instance, Limits, ProtocolLimits, Request,
    Search, Step,
};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use gnunet_wire::official::fs::Response;
use std::{
    io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::oneshot,
    time::{Instant, timeout},
};
type TestResult = Result<(), Box<dyn std::error::Error>>;

struct Socket(PathBuf);
impl Socket {
    fn bind() -> io::Result<(Self, UnixListener)> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let path = std::env::temp_dir().join(format!(
            "gnunet-fs-ipc-{}-{}.sock",
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
        match std::fs::remove_file(&self.0) {
            Ok(()) | Err(_) => {}
        }
    }
}
fn deadline(source: &EndpointSource) -> Result<AbsoluteTime, ProtocolError> {
    Ok(AbsoluteTime::from_micros(
        source.clock().sample()?.now.as_micros() + 5_000_000,
    ))
}
fn search(query: [u8; 64]) -> Request<'static> {
    Request::Search(Search {
        options: 1,
        block_type: BlockType::DBLOCK,
        anonymity: 0,
        target: [0; 32],
        query,
        seen: &[],
    })
}
async fn read_frame(stream: &mut UnixStream) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if length < 4 {
        return Err(io::Error::other("short frame"));
    }
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
fn result(block: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    let response = Response::Put(ClientPut {
        block_type: BlockType::DBLOCK,
        expiration: AbsoluteTime::NEVER,
        last_transmission: AbsoluteTime::from_micros(3),
        num_transmissions: 2,
        respect_offered: 1,
        block,
    });
    let mut bytes = vec![0; response.encoded_len()?];
    response.encode(&mut bytes)?;
    Ok(bytes)
}

#[test]
fn partial_input_survives_observation_timeout_and_dropped_wait() -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (socket, listener) = Socket::bind()?;
            let block = [7; 32];
            let query = gnunet_crypto::hash512(&block);
            let request = search(query);
            let (release, resume) = oneshot::channel();
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await?;
                let bytes = read_frame(&mut stream).await?;
                assert_eq!(Request::decode(&bytes)?, request);
                let bytes = result(&block)?;
                stream.write_all(&bytes[..2]).await?;
                resume.await.map_err(io::Error::other)?;
                stream.write_all(&bytes[2..]).await?;
                let mut one = [0; 1];
                assert_eq!(stream.read(&mut one).await?, 0);
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            });
            let source = socket.source();
            let target = deadline(&source)?;
            let mut instance = Instance::new();
            let mut client = Client::<4>::new(
                &mut instance,
                request,
                source,
                ProtocolLimits::default(),
                Limits {
                    io_slice_bytes: 1,
                    ..Limits::default()
                },
                target,
            )?;
            assert!(matches!(client.drive(None).await?, Step::Connected));
            let mut sent = 0;
            loop {
                if let Step::Written { bytes, complete } = client.drive(None).await? {
                    assert_eq!(bytes, 1);
                    sent += bytes;
                    if complete {
                        break;
                    }
                }
            }
            assert_eq!(sent, 112);
            for _ in 0..2 {
                assert!(matches!(client.drive(None).await?, Step::Read { bytes: 1 }));
            }
            assert!(matches!(
                client
                    .drive(Some(Instant::now() + Duration::from_millis(1)))
                    .await?,
                Step::WaitDeadline
            ));
            assert!(
                timeout(Duration::from_millis(1), client.drive(None))
                    .await
                    .is_err()
            );
            assert!(!client.completed());
            assert_eq!(client.failure(), None);
            release.send(()).map_err(|()| "server gone")?;
            timeout(Duration::from_secs(2), async {
                loop {
                    if let Step::Event(received) = client.drive(None).await? {
                        assert!(
                            matches!(received.event(), Event::Block(put) if put.block == block)
                        );
                        break;
                    }
                }
                Ok::<_, Error>(())
            })
            .await??;
            assert!(client.completed());
            assert!(matches!(client.drive(None).await?, Step::Finished));
            server.await?.map_err(|e| io::Error::other(e.to_string()))?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })
}

#[test]
fn partially_written_unindex_closes_original_mq_with_unknown_outcome() -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (socket, listener) = Socket::bind()?;
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await?;
                let mut bytes = Vec::new();
                stream.read_to_end(&mut bytes).await?;
                assert_eq!(bytes.len(), 1);
                Ok::<_, io::Error>(())
            });
            let source = socket.source();
            let target = deadline(&source)?;
            let mut instance = Instance::new();
            let mut client = Client::<0>::new(
                &mut instance,
                Request::Unindex { file_id: [8; 64] },
                source,
                ProtocolLimits::default(),
                Limits {
                    io_slice_bytes: 1,
                    ..Limits::default()
                },
                target,
            )?;
            assert!(matches!(client.drive(None).await?, Step::Connected));
            assert!(matches!(
                client.drive(None).await?,
                Step::Written {
                    bytes: 1,
                    complete: false
                }
            ));
            client.cancel()?;
            let failure = client.failure().ok_or("missing failure")?;
            assert_eq!(failure.cause, ProtocolError::Cancelled);
            assert_eq!(failure.outcome, ProtocolError::OutcomeUnknown);
            assert!(matches!(
                client.drive(None).await,
                Err(Error::Protocol(ProtocolError::OutcomeUnknown))
            ));
            timeout(Duration::from_secs(2), server).await???;
            Ok::<_, Box<dyn std::error::Error>>(())
        })
}

#[test]
fn search_loss_reconnects_with_original_query_and_returns_actual_block() -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (socket, listener) = Socket::bind()?;
            let block = [17; 32];
            let request = search(gnunet_crypto::hash512(&block));
            let server = tokio::spawn(async move {
                let (mut first, _) = listener.accept().await?;
                let original = read_frame(&mut first).await?;
                drop(first);
                let (mut second, _) = listener.accept().await?;
                assert_eq!(read_frame(&mut second).await?, original);
                second.write_all(&result(&block)?).await?;
                let mut one = [0; 1];
                assert_eq!(second.read(&mut one).await?, 0);
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            });
            let source = socket.source();
            let target = deadline(&source)?;
            let mut instance = Instance::new();
            let mut client = Client::<4>::new(
                &mut instance,
                request,
                source,
                ProtocolLimits::default(),
                Limits::default(),
                target,
            )?;
            let mut losses = 0;
            timeout(Duration::from_secs(2), async {
                loop {
                    match client.drive(None).await? {
                        Step::Retry {
                            cause: Error::Io(_),
                            ..
                        } => losses += 1,
                        Step::Event(received) => {
                            assert!(
                                matches!(received.event(), Event::Block(put) if put.block == block)
                            );
                            break;
                        }
                        _ => {}
                    }
                }
                Ok::<_, Error>(())
            })
            .await??;
            assert_eq!(losses, 1);
            assert!(client.completed());
            server.await?.map_err(|e| io::Error::other(e.to_string()))?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })
}

// Append to adapters/fs-std/tests/ipc.rs; uses its existing Socket/read_frame/deadline helpers.
#[test]
fn search_expiry_filter_does_not_remember_before_a_later_valid_ttl() -> TestResult {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let publisher = gnunet_fs::ublock::Publisher::keyword(
                b"renewed-ttl", gnunet_fs::ublock::Limits::default(),
            )?;
            let query = *publisher.context().query();
            let mut output = [0; 1024];
            let block = publisher.seal(b"", gnunet_fs::Content {
                key: [1; 64], query: [2; 64], size: 3,
            }.uri(), None, &mut output)?.bytes().to_vec();
            let expected = block.clone();
            let (socket, listener) = Socket::bind()?;
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await?;
                let request = read_frame(&mut stream).await?;
                assert!(matches!(Request::decode(&request)?, Request::Search(s) if s.block_type == BlockType::UBLOCK && s.query == query));
                for expiration in [AbsoluteTime::from_micros(1), AbsoluteTime::NEVER] {
                    let response = Response::Put(ClientPut {
                        block_type: BlockType::UBLOCK, expiration,
                        last_transmission: AbsoluteTime::NEVER,
                        num_transmissions: 0, respect_offered: 0, block: &block,
                    });
                    let mut frame = vec![0; response.encoded_len()?];
                    response.encode(&mut frame)?;
                    stream.write_all(&frame).await?;
                }
                let mut one = [0; 1];
                assert_eq!(stream.read(&mut one).await?, 0);
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            });
            let source = socket.source();
            let target = deadline(&source)?;
            let mut instance = Instance::new();
            let mut client = Client::<2>::new(&mut instance, Request::Search(Search {
                options: 1, block_type: BlockType::UBLOCK, anonymity: 1,
                target: [0; 32], query, seen: &[],
            }), source, ProtocolLimits::default(), Limits::default(), target)?;
            client.filter_expired_ublocks_using_source_absolute_time()?;
            let mut ignored = false;
            timeout(Duration::from_secs(2), async {
                loop {
                    match client.drive(None).await? {
                        Step::Ignored => {
                            ignored = true;
                            assert!(client.known_results().is_empty());
                        }
                        Step::Event(received) => {
                            assert!(ignored);
                            assert!(matches!(received.event(), Event::Block(put) if put.block == expected));
                            assert_eq!(client.known_results(), &[gnunet_crypto::hash512(&expected)]);
                            break;
                        }
                        _ => {}
                    }
                }
                Ok::<_, Error>(())
            }).await??;
            client.cancel()?;
            server.await?.map_err(|e| io::Error::other(e.to_string()))?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })
}
