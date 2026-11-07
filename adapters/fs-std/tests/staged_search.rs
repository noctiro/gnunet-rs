//! Actual native advertisement staging and source-bound offline search replay.
//! Local Rust peers and historical observations, not original-C/P2P acceptance.
#![cfg(all(unix, feature = "service"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible search tests assert original native frames and immutable source bindings"
)]
use gnunet_crypto::{EddsaPublicKey, gns::EdkeySecret};
use gnunet_fs::{Content, Namespace, Uri, client::Instance, ublock};
use gnunet_fs_host::{
    ipc,
    search::{
        Error, Limits, Options, Session, Step,
        observation::{Observation, Staged},
    },
};
use gnunet_types::{AbsoluteTime, Error as ProtocolError};
use gnunet_wire::official::fs::{BlockType, ClientPut, Request, Response};
use std::{
    io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::{Instant, sleep, timeout},
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const WAIT: Duration = Duration::from_secs(5);
struct Socket(PathBuf);
impl Socket {
    fn bind() -> io::Result<(Self, UnixListener)> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let socket = Self(std::env::temp_dir().join(format!(
            "gnunet-staged-search-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        )));
        let listener = UnixListener::bind(&socket.0)?;
        Ok((socket, listener))
    }
}
impl Drop for Socket {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_file(&self.0);
    }
}
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
fn options(source: &ipc::EndpointSource) -> Result<Options, ProtocolError> {
    Ok(Options {
        anonymity: 1,
        local_only: true,
        deadline: AbsoluteTime::from_micros(source.clock().sample()?.now.as_micros() + 4_000_000),
        limits: Limits::default(),
        block: ublock::Limits::default(),
        protocol: Default::default(),
        native: Default::default(),
    })
}
fn block(
    secret: &EdkeySecret,
    label: &[u8],
    update: &[u8],
    content: Content,
) -> TestResult<([u8; 64], Vec<u8>)> {
    let publisher = ublock::Publisher::namespace(secret, label, ublock::Limits::default())?;
    let mut wire = vec![0; ublock::Limits::default().max_wire_bytes];
    let query = *publisher.context().query();
    Ok((
        query,
        publisher
            .seal(update, content.uri(), None, &mut wire)?
            .bytes()
            .to_vec(),
    ))
}
async fn send(
    stream: &mut UnixStream,
    query: [u8; 64],
    body: &[u8],
    expiry: AbsoluteTime,
) -> TestResult {
    let mut request = [0; 112];
    stream.read_exact(&mut request).await?;
    assert!(
        matches!(Request::decode(&request)?,Request::Search(search) if search.query==query&&search.block_type==BlockType::UBLOCK&&search.options==1)
    );
    let response = Response::Put(ClientPut {
        block_type: BlockType::UBLOCK,
        expiration: expiry,
        last_transmission: AbsoluteTime::UNIX_EPOCH,
        num_transmissions: 0,
        respect_offered: 0,
        block: body,
    });
    let mut bytes = vec![0; response.encoded_len()?];
    response.encode(&mut bytes)?;
    stream.write_all(&bytes).await?;
    Ok(())
}
async fn stage<F, const N: usize>(session: &mut Session<'_, F, N>) -> Result<(), Error>
where
    F: FnMut() -> Result<ipc::EndpointSource, ipc::Error>,
{
    loop {
        match session.drive_staged(None).await? {
            Staged::Advertisement => return Ok(()),
            Staged::Step(Step::Rejected { cause, .. }) => return Err(cause),
            Staged::Step(Step::Failed { cause, .. }) => return Err(cause.into()),
            _ => {}
        }
    }
}
struct Stored {
    query_id: usize,
    kind: ublock::Kind,
    namespace: [u8; 32],
    label: Vec<u8>,
    lookup_key: [u8; 64],
    wire: Vec<u8>,
    expiration: AbsoluteTime,
    observed_at: AbsoluteTime,
}
impl Stored {
    fn from(observation: Observation<'_>) -> Self {
        Self {
            query_id: observation.query_id,
            kind: observation.kind,
            namespace: *observation.namespace,
            label: observation.label.to_vec(),
            lookup_key: *observation.lookup_key,
            wire: observation.wire.to_vec(),
            expiration: observation.expiration,
            observed_at: observation.observed_at,
        }
    }
    fn view(&self) -> Observation<'_> {
        Observation {
            query_id: self.query_id,
            kind: self.kind,
            namespace: &self.namespace,
            label: &self.label,
            lookup_key: &self.lookup_key,
            wire: &self.wire,
            expiration: self.expiration,
            observed_at: self.observed_at,
        }
    }
}

#[test]
fn staged_native_update_cycle_replays_its_actual_historical_bindings_without_network() -> TestResult
{
    runtime()?.block_on(async {
        let (socket, listener) = Socket::bind()?;
        let secret = EdkeySecret::from_seed([0x45; 32]);
        let namespace = Namespace::new(EddsaPublicKey::from_bytes(secret.public_key()), b"root")?;
        let one = Content {
            key: [3; 64],
            query: [4; 64],
            size: 17,
        };
        let two = Content {
            key: [5; 64],
            query: [6; 64],
            size: 19,
        };
        let root = block(&secret, b"root", b"child", one)?;
        let child = block(&secret, b"child", b"root", two)?;
        let source = ipc::EndpointSource::unix(socket.0.clone());
        let policy = options(&source)?;
        let expiry = AbsoluteTime::from_micros(source.clock().sample()?.now.as_micros() + 900_000);
        let peer = async {
            let (mut a, _) = listener.accept().await?;
            send(&mut a, root.0, &root.1, expiry).await?;
            let (mut b, _) = listener.accept().await?;
            send(&mut b, child.0, &child.1, expiry).await?;
            let mut end = [0];
            assert_eq!(a.read(&mut end).await?, 0);
            assert_eq!(b.read(&mut end).await?, 0);
            assert!(
                timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let search = async {
            let mut identities = [Instance::new(), Instance::new()];
            let mut session = Session::<_, 4>::new(
                Uri::Namespace(namespace),
                &mut identities,
                || source.duplicate(),
                policy,
            )?;
            stage(&mut session).await?;
            assert!(session.results().is_empty());
            assert_eq!(session.query_count(), 1);
            let first = Stored::from(session.observation().ok_or("missing staged root")?);
            assert_eq!(first.wire, root.1);
            assert_eq!(first.query_id, 0);
            assert!(matches!(
                session.drive_staged(Some(Instant::now())).await?,
                Staged::Advertisement
            ));
            assert_eq!(
                session
                    .observation()
                    .ok_or("lost original staged frame")?
                    .wire,
                first.wire
            );
            assert!(session.results().is_empty());
            assert_eq!(session.query_count(), 1);
            let Step::Result { result: first_id } = session.accept_staged()? else {
                return Err("root was not admitted".into());
            };
            assert!(matches!(session.result(first_id).ok_or("missing accepted root")?.uri(policy.block.uri)?,Uri::Content(actual) if actual==one));
            assert_eq!(session.query_count(), 2);
            stage(&mut session).await?;
            assert_eq!(session.results().len(), 1);
            assert_eq!(session.query_count(), 2);
            let second = Stored::from(session.observation().ok_or("missing staged child")?);
            assert_eq!(second.wire, child.1);
            assert_eq!(second.query_id, 1);
            assert!(matches!(session.accept_staged()?, Step::Result { .. }));
            assert_eq!(session.results().len(), 2);
            assert_eq!(session.query_count(), 2);
            session.cancel()?;
            Ok::<_, Box<dyn std::error::Error>>((first, second))
        };
        let ((first, second), ()) =
            timeout(WAIT, async { tokio::try_join!(search, peer) }).await??;
        drop(listener);
        // Let the actual outer expiration pass. The original native observation
        // remains valid historical state and must not be retargeted or discarded.
        sleep(Duration::from_millis(950)).await;
        let absent = ipc::EndpointSource::unix(socket.0.with_extension("absent"));
        assert!(absent.clock().sample()?.now.as_micros() > expiry.as_micros());
        let fresh = options(&absent)?;
        let mut identities = [Instance::new(), Instance::new()];
        let mut replay = Session::<_, 4>::new(
            Uri::Namespace(namespace),
            &mut identities,
            || absent.duplicate(),
            fresh,
        )?;
        assert!(matches!(replay.replay(first.view())?, Step::Result { .. }));
        assert!(matches!(replay.replay(second.view())?, Step::Result { .. }));
        assert_eq!(replay.results().len(), 2);
        assert_eq!(replay.query_count(), 2);
        assert!(matches!(replay.results()[0].uri(fresh.block.uri)?,Uri::Content(actual) if actual==one));
        assert!(matches!(replay.results()[1].uri(fresh.block.uri)?,Uri::Content(actual) if actual==two));
        let wrong_label = Observation {
            label: b"different",
            ..first.view()
        };
        assert!(replay.replay(wrong_label).is_err());
        let wrong_query = Observation {
            query_id: 1,
            ..first.view()
        };
        assert!(replay.replay(wrong_query).is_err());
        let bad_time = Observation {
            observed_at: AbsoluteTime::from_micros(0),
            ..second.view()
        };
        assert!(matches!(
            replay.replay(bad_time),
            Err(Error::Protocol(ProtocolError::TimeUncertain))
        ));
        let bad_expiry = Observation {
            expiration: AbsoluteTime::UNIX_EPOCH,
            ..second.view()
        };
        assert!(matches!(
            replay.replay(bad_expiry),
            Err(Error::Protocol(ProtocolError::Authentication))
        ));
        let mut wire = second.wire.clone();
        *wire.last_mut().ok_or("missing signed block")? ^= 1;
        let bad_wire = Observation {
            wire: &wire,
            ..second.view()
        };
        assert!(replay.replay(bad_wire).is_err());
        assert_eq!(replay.results().len(), 2);
        assert_eq!(replay.query_count(), 2);
        // The fresh endpoint has never existed. Reconstruction did not require
        // any service data, and no opaque native Received was manufactured.
        let _progress = replay.drive_staged(Some(Instant::now())).await;
        assert!(matches!(
            replay.replay(second.view()),
            Err(Error::Protocol(ProtocolError::NotReady))
        ));
        replay.cancel()?;
        Ok(())
    })
}

#[test]
fn aggregate_refusal_retains_the_original_staged_frame_without_another_service_hit() -> TestResult {
    runtime()?.block_on(async {
        let (socket, listener) = Socket::bind()?;
        let secret = EdkeySecret::from_seed([0x72; 32]);
        let namespace =
            Namespace::new(EddsaPublicKey::from_bytes(secret.public_key()), b"limited")?;
        let content = Content {
            key: [7; 64],
            query: [8; 64],
            size: 23,
        };
        let artifact = block(&secret, b"limited", b"next", content)?;
        let source = ipc::EndpointSource::unix(socket.0.clone());
        let policy = options(&source)?;
        let peer = async {
            let (mut stream, _) = listener.accept().await?;
            send(&mut stream, artifact.0, &artifact.1, AbsoluteTime::NEVER).await?;
            let mut end = [0];
            assert_eq!(stream.read(&mut end).await?, 0);
            assert!(
                timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let search = async {
            let mut identities = [Instance::new(), Instance::new()];
            let mut session = Session::<_, 4>::new(
                Uri::Namespace(namespace),
                &mut identities,
                || source.duplicate(),
                policy,
            )?;
            stage(&mut session).await?;
            let original = Stored::from(session.observation().ok_or("missing staged record")?);
            session.set_limits(Limits {
                results: 0,
                ..policy.limits
            })?;
            assert!(matches!(session.accept_staged(), Err(Error::Limit)));
            assert!(session.results().is_empty());
            assert_eq!(session.query_count(), 1);
            assert!(matches!(
                session.drive_staged(Some(Instant::now())).await?,
                Staged::Advertisement
            ));
            let retried = session
                .observation()
                .ok_or("original event disappeared on resource refusal")?;
            assert_eq!(retried.wire, original.wire);
            assert_eq!(retried.observed_at, original.observed_at);
            session.set_limits(policy.limits)?;
            assert!(matches!(session.accept_staged()?, Step::Result { .. }));
            assert_eq!(session.results().len(), 1);
            assert_eq!(session.query_count(), 2);
            session.cancel()?;
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        timeout(WAIT, async { tokio::try_join!(search, peer) }).await??;
        Ok(())
    })
}

#[test]
fn a_valid_observation_with_a_refused_continuation_replays_as_the_same_rejection() -> TestResult {
    runtime()?.block_on(async {
        let (socket, listener) = Socket::bind()?;
        let secret = EdkeySecret::from_seed([0x31; 32]);
        let namespace = Namespace::new(
            EddsaPublicKey::from_bytes(secret.public_key()),
            b"oversize-update",
        )?;
        // This is valid official UBLOCK framing and a real namespace signature.
        // The next query's raw label exceeds this Session's explicit label policy.
        let update = vec![b'x'; ublock::Limits::default().max_label_bytes + 1];
        let content = Content {
            key: [12; 64],
            query: [13; 64],
            size: 31,
        };
        let artifact = block(&secret, b"oversize-update", &update, content)?;
        let source = ipc::EndpointSource::unix(socket.0.clone());
        let policy = options(&source)?;
        let peer = async {
            let (mut stream, _) = listener.accept().await?;
            send(&mut stream, artifact.0, &artifact.1, AbsoluteTime::NEVER).await?;
            let mut end = [0];
            assert_eq!(stream.read(&mut end).await?, 0);
            assert!(
                timeout(Duration::from_millis(50), listener.accept())
                    .await
                    .is_err()
            );
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let search = async {
            let mut identities = [Instance::new(), Instance::new()];
            let mut session = Session::<_, 4>::new(
                Uri::Namespace(namespace),
                &mut identities,
                || source.duplicate(),
                policy,
            )?;
            stage(&mut session).await?;
            let observed = Stored::from(session.observation().ok_or("missing valid observation")?);
            assert!(matches!(
                session.accept_staged()?,
                Step::Rejected {
                    cause: Error::Block(ublock::Error::Limit),
                    ..
                }
            ));
            assert!(session.results().is_empty());
            assert_eq!(session.query_count(), 1);
            session.cancel()?;
            Ok::<_, Box<dyn std::error::Error>>(observed)
        };
        let (observed, ()) = timeout(WAIT, async { tokio::try_join!(search, peer) }).await??;
        let absent = ipc::EndpointSource::unix(socket.0.with_extension("absent"));
        let fresh = options(&absent)?;
        let mut identities = [Instance::new(), Instance::new()];
        let mut restored = Session::<_, 4>::new(
            Uri::Namespace(namespace),
            &mut identities,
            || absent.duplicate(),
            fresh,
        )?;
        assert!(matches!(
            restored.replay(observed.view())?,
            Step::Rejected {
                cause: Error::Block(ublock::Error::Limit),
                ..
            }
        ));
        assert!(restored.results().is_empty());
        assert_eq!(restored.query_count(), 1);
        restored.cancel()?;
        Ok(())
    })
}
