//! Native signed SKS selection proof and retained-event resource boundaries.
//! Test fixtures are local Rust peers, not original-C or P2P acceptance.
#![cfg(all(unix, feature = "service"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Focused tests assert actual signed provenance and no event loss"
)]
use gnunet_crypto::{EddsaPublicKey, gns::EdkeySecret};
use gnunet_fs::{Content, Namespace, Uri, client::Instance, ublock};
use gnunet_fs_host::{
    ipc,
    search::{Error, Limits, Options, ResultId, Session, Step, proof::NamespaceProof},
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
    net::{UnixListener, UnixStream},
    time::timeout,
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const WAIT: Duration = Duration::from_secs(5);
struct Socket(PathBuf);
impl Socket {
    fn bind() -> io::Result<(Self, UnixListener)> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let socket = Self(std::env::temp_dir().join(format!(
            "gnunet-sks-proof-{}-{}.sock",
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
fn options(source: &ipc::EndpointSource) -> Result<Options, gnunet_types::Error> {
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
    uri: Uri<'_>,
) -> TestResult<([u8; 64], Vec<u8>)> {
    let publisher = ublock::Publisher::namespace(secret, label, ublock::Limits::default())?;
    let query = *publisher.context().query();
    let mut wire = vec![0; 4096];
    let body = publisher
        .seal(update, uri, None, &mut wire)?
        .bytes()
        .to_vec();
    Ok((query, body))
}
async fn send(
    stream: &mut UnixStream,
    query: [u8; 64],
    body: &[u8],
    expiry: AbsoluteTime,
) -> TestResult {
    let mut frame = [0; 112];
    stream.read_exact(&mut frame).await?;
    assert!(matches!(Request::decode(&frame)?, Request::Search(search)
        if search.query == query && search.block_type == BlockType::UBLOCK && search.options == 1));
    let response = Response::Put(ClientPut {
        block_type: BlockType::UBLOCK,
        expiration: expiry,
        last_transmission: AbsoluteTime::UNIX_EPOCH,
        num_transmissions: 0,
        respect_offered: 0,
        block: body,
    });
    let mut wire = vec![0; response.encoded_len()?];
    response.encode(&mut wire)?;
    stream.write_all(&wire).await?;
    Ok(())
}
async fn choose<'id, F, const KNOWN: usize>(
    session: &mut Session<'id, F, KNOWN>,
) -> Result<ResultId, Error>
where
    F: FnMut() -> Result<ipc::EndpointSource, ipc::Error>,
{
    loop {
        match session.drive(None).await? {
            Step::Result { result } | Step::Update { result } => return Ok(result),
            Step::Rejected { cause, .. } => return Err(cause),
            Step::Failed { cause, .. } => return Err(cause.into()),
            _ => {}
        }
    }
}

#[test]
fn signed_update_lineage_roundtrips_without_a_new_lookup_or_mutable_cycle_parent() -> TestResult {
    runtime()?.block_on(async {
        let (socket, listener) = Socket::bind()?;
        let secret = EdkeySecret::from_seed([17; 32]);
        let original = Namespace::new(EddsaPublicKey::from_bytes(secret.public_key()), b"root")?;
        let content = Content {
            key: [3; 64],
            query: [5; 64],
            size: 123,
        };
        // The last update creates a mutable graph cycle back to the initial
        // query. Export must use its fixed creation origin, not this new parent.
        let first = block(&secret, b"root", b"child", Uri::Namespace(original))?;
        let second = block(&secret, b"child", b"root", content.uri())?;
        let source = ipc::EndpointSource::unix(socket.0.clone());
        let policy = options(&source)?;
        let expiry =
            AbsoluteTime::from_micros(source.clock().sample()?.now.as_micros() + 3_000_000);
        let peer = async {
            let (mut a, _) = listener.accept().await?;
            send(&mut a, first.0, &first.1, expiry).await?;
            let (mut b, _) = listener.accept().await?;
            send(&mut b, second.0, &second.1, expiry).await?;
            let mut one = [0];
            assert_eq!(a.read(&mut one).await?, 0);
            assert_eq!(b.read(&mut one).await?, 0);
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let select = async {
            let mut identities = [Instance::new(), Instance::new()];
            let path = socket.0.clone();
            let mut session = Session::<_, 4>::new_with_namespace_proof(
                Uri::Namespace(original),
                &mut identities,
                move || Ok(ipc::EndpointSource::unix(path.clone())),
                policy,
            )?;
            let root = choose(&mut session).await?;
            assert!(matches!(
                session
                    .result(root)
                    .ok_or("missing first")?
                    .uri(policy.block.uri)?,
                Uri::Namespace(_)
            ));
            let child = choose(&mut session).await?;
            assert_eq!(session.query_count(), 2);
            let selection = session.finish_namespace_selection(child)?;
            assert_eq!(selection.selected, content);
            assert!(selection.location.is_none());
            assert!(selection.cleanup.is_none());
            Ok::<_, Box<dyn std::error::Error>>(selection)
        };
        let (selection, ()) = timeout(WAIT, async { tokio::try_join!(select, peer) }).await??;
        drop(listener);
        let mut encoded = vec![0; selection.proof.encoded_len()?];
        selection.proof.encode(&mut encoded)?;
        let reopened = NamespaceProof::decode(&encoded, policy.limits, policy.block)?;
        reopened.verify(original, content, None, policy.limits, policy.block)?;
        // No source or clock is supplied to immutable verification.
        let wrong = Content {
            size: 124,
            ..content
        };
        assert!(
            reopened
                .verify(original, wrong, None, policy.limits, policy.block)
                .is_err()
        );
        let wrong_label = Namespace::new(original.key(), b"other")?;
        assert!(
            reopened
                .verify(wrong_label, content, None, policy.limits, policy.block)
                .is_err()
        );
        let mut modified = encoded.clone();
        let last = modified.last_mut().ok_or("missing proof")?;
        *last ^= 1;
        assert!(
            NamespaceProof::decode(&modified, policy.limits, policy.block)?
                .verify(original, content, None, policy.limits, policy.block)
                .is_err()
        );
        let mut expired = encoded.clone();
        expired[52..60].fill(0); // first original outer expiration
        assert!(
            NamespaceProof::decode(&expired, policy.limits, policy.block)?
                .verify(original, content, None, policy.limits, policy.block)
                .is_err()
        );
        let mut short = vec![0xa7; encoded.len() - 1];
        assert!(selection.proof.encode(&mut short).is_err());
        assert!(short.iter().all(|byte| *byte == 0xa7));
        let mut trailing = encoded;
        trailing.push(0);
        assert!(NamespaceProof::decode(&trailing, policy.limits, policy.block).is_err());
        Ok(())
    })
}

#[test]
fn proof_budget_refusal_keeps_original_event_and_creation_graph_for_retry() -> TestResult {
    runtime()?.block_on(async {
        let (socket, listener) = Socket::bind()?;
        let secret = EdkeySecret::from_seed([19; 32]);
        let original = Namespace::new(EddsaPublicKey::from_bytes(secret.public_key()), b"budget")?;
        let content = Content {
            key: [6; 64],
            query: [9; 64],
            size: 17,
        };
        let artifact = block(&secret, b"budget", b"next", content.uri())?;
        let source = ipc::EndpointSource::unix(socket.0.clone());
        let policy = options(&source)?;
        let peer = async {
            // Exactly one signed frame for each independent session. The proof
            // session must retry its retained event without another service hit.
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await?;
                send(&mut stream, artifact.0, &artifact.1, AbsoluteTime::NEVER).await?;
                let mut one = [0];
                assert_eq!(stream.read(&mut one).await?, 0);
            }
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        let select = async {
            let mut identities = [Instance::new(), Instance::new()];
            let path = socket.0.clone();
            let mut plain = Session::<_, 4>::new(
                Uri::Namespace(original),
                &mut identities,
                move || Ok(ipc::EndpointSource::unix(path.clone())),
                policy,
            )?;
            choose(&mut plain).await?;
            assert_eq!(plain.query_count(), 2);
            // Find the exact budget of normal projected search state. Proof
            // mode must need more and refuse before committing its child/result.
            let (mut low, mut high) = (0, policy.limits.retained_bytes);
            while low < high {
                let mid = low + (high - low) / 2;
                if plain
                    .set_limits(Limits {
                        retained_bytes: mid,
                        ..policy.limits
                    })
                    .is_ok()
                {
                    high = mid;
                } else {
                    low = mid + 1;
                }
            }
            plain.cancel()?;
            drop(plain);
            let mut identities = [Instance::new(), Instance::new()];
            let path = socket.0.clone();
            let mut proof = Session::<_, 4>::new_with_namespace_proof(
                Uri::Namespace(original),
                &mut identities,
                move || Ok(ipc::EndpointSource::unix(path.clone())),
                Options {
                    limits: Limits {
                        retained_bytes: low,
                        ..policy.limits
                    },
                    ..policy
                },
            )?;
            assert!(matches!(choose(&mut proof).await, Err(Error::Limit)));
            assert!(proof.results().is_empty());
            assert_eq!(proof.query_count(), 1);
            proof.set_limits(policy.limits)?;
            let chosen = choose(&mut proof).await?;
            assert_eq!(proof.query_count(), 2);
            let selection = proof.finish_namespace_selection(chosen)?;
            assert!(selection.cleanup.is_none());
            selection
                .proof
                .verify(original, content, None, policy.limits, policy.block)?;
            Ok::<_, Box<dyn std::error::Error>>(())
        };
        timeout(WAIT, async { tokio::try_join!(select, peer) }).await??;
        Ok(())
    })
}
