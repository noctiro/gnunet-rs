//! Actual Unix CORE socket model of the native FS GAP composition.
#![cfg(all(unix, feature = "server"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "The model asserts actual official socket frames, source ownership and physical writes."
)]
use gnunet_core_client_host::{
    EndpointSource, Instance, Limits as NativeLimits, PeerClass, PeerId, SendOutcome,
};
use gnunet_fs::{content::encode_data, gap as pure};
use gnunet_fs_host::server::{
    FailureScope, NoPeers, PeerProgress, PeerRouter, PeerShutdown, ProviderFailure, RouteAdmission,
    cadet_server::source::{
        Availability, Block, BlockSource, Failure as SourceFailure, Progress as SourceProgress,
        Retired, Retirement, Selection,
    },
    gap::{Limits, Router},
    peers::Pair,
};
use gnunet_service_runtime::{clock::RuntimeClock, framing::OwnedFrame};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    core::{ClassOrder, Direction, Request, Response, SEND_PREFIX, Traffic},
    datastore::{DATA_LEN, Data, Response as DatastoreResponse},
    fs::{BlockType, SEARCH_LOOPBACK_ONLY, Search},
    fs_gap::{GET_PREFIX, Get, MigrationStop, Put},
};
use std::{
    cell::RefCell,
    future::poll_fn,
    path::PathBuf,
    rc::Rc,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::oneshot,
};

type Failure = Box<dyn std::error::Error + Send + Sync>;

const LOCAL: PeerId = PeerId([0x41; 32]);
const PEER: PeerId = PeerId([0x42; 32]);
const LOCAL_ROUTE: u64 = 2;
const LOCAL_EXPIRATION: AbsoluteTime = AbsoluteTime::from_micros(4_000_000_000_123_456);
const SOURCE_EXPIRATION: AbsoluteTime = AbsoluteTime::from_micros(4_000_000_000_123_789);
static NEXT_SOCKET: AtomicU64 = AtomicU64::new(0);

struct Socket(PathBuf);
impl Socket {
    fn bind() -> Result<(Self, UnixListener), Failure> {
        let path = std::env::temp_dir().join(format!(
            "gnrs-fs-gap-{}-{}.sock",
            std::process::id(),
            NEXT_SOCKET.fetch_add(1, Ordering::Relaxed)
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
        let _removed = std::fs::remove_file(&self.0);
    }
}

/// Deterministic bounded draws make the model's offered query priority explicit.
struct Entropy;
impl pure::Entropy for Entropy {
    fn uniform(&mut self, upper: u32) -> Result<u32, Error> {
        upper.checked_sub(1).ok_or(Error::InvalidInput)
    }
}

#[derive(Default)]
struct SourceFacts {
    selections: Vec<Selection>,
    not_found: usize,
    found: usize,
    closed: bool,
}
/// This is a controlled BlockSource model. Its terminals are local model facts;
/// the CORE client, Unix stream, framing and write receipts remain production code.
struct Source {
    expected: [Selection; 2],
    block: Option<Block>,
    active: Option<(Selection, usize)>,
    retiring: bool,
    facts: Rc<RefCell<SourceFacts>>,
}
impl BlockSource for Source {
    fn availability(&self) -> Availability {
        if self.facts.borrow().closed {
            Availability::Closed
        } else {
            Availability::Open
        }
    }
    fn request_retire(&mut self) {
        self.retiring = self.active.is_some();
    }
    fn start(&mut self, selection: Selection) -> Result<(), SourceFailure> {
        if self.facts.borrow().closed {
            return Err(SourceFailure::service(Error::Closed));
        }
        if self.active.is_some() {
            return Err(SourceFailure::operation(Error::Conflict));
        }
        let index = self.facts.borrow().selections.len();
        if self.expected.get(index) != Some(&selection) {
            return Err(SourceFailure::operation(Error::Authentication));
        }
        self.facts.borrow_mut().selections.push(selection);
        self.active = Some((selection, index));
        self.retiring = false;
        Ok(())
    }
    fn poll(&mut self, _: &mut Context<'_>) -> Poll<Result<SourceProgress, SourceFailure>> {
        let Some((selection, index)) = self.active.take() else {
            return Poll::Pending;
        };
        if self.retiring {
            self.retiring = false;
            return Poll::Ready(Ok(SourceProgress::Retired(Retired {
                selection,
                observation: Retirement::Unsubmitted,
            })));
        }
        Poll::Ready(if index == 0 {
            self.facts.borrow_mut().not_found += 1;
            Ok(SourceProgress::NotFound)
        } else {
            self.block
                .take()
                .ok_or_else(|| SourceFailure::operation(Error::Conflict))
                .map(|block| {
                    self.facts.borrow_mut().found += 1;
                    SourceProgress::Found(block)
                })
        })
    }
    fn close(&mut self) -> Result<(), SourceFailure> {
        if self.active.is_some() {
            return Err(SourceFailure::operation(Error::WouldBlock));
        }
        self.facts.borrow_mut().closed = true;
        Ok(())
    }
}

fn encrypted(plaintext: &[u8]) -> Result<([u8; 64], Vec<u8>), Failure> {
    let mut bytes = [0; 256];
    let block = encode_data(plaintext, &mut bytes)?;
    Ok((block.key().query, block.bytes().to_vec()))
}
fn source_block(key: &[u8; 64], ciphertext: &[u8]) -> Result<Block, Failure> {
    let data = DatastoreResponse::Data(Data {
        reservation: 0,
        kind: 1,
        priority: 7,
        anonymity: 1,
        replication: 2,
        uid: 9,
        expiration: SOURCE_EXPIRATION,
        key,
        value: ciphertext,
    });
    let mut bytes = vec![0; DATA_LEN + ciphertext.len()];
    assert_eq!(data.encode(&mut bytes)?, bytes.len());
    Ok(Block::from_record(OwnedFrame::new(bytes))?)
}
fn put(ciphertext: &[u8], expiration: AbsoluteTime) -> Result<Vec<u8>, Failure> {
    let value = Put {
        block_type: BlockType::DBLOCK,
        expiration,
        block: ciphertext,
    };
    let mut bytes = vec![0; value.encoded_len()?];
    value.encode(&mut bytes)?;
    Ok(bytes)
}
async fn frame(stream: &mut UnixStream) -> Result<Vec<u8>, Failure> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if !(4..=1024).contains(&length) {
        return Err("CORE actor received a frame outside its finite bound".into());
    }
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn response(stream: &mut UnixStream, value: Response<'_>) -> Result<(), Failure> {
    let mut bytes = [0; 1024];
    let length = value.encode(&mut bytes, ClassOrder::Little)?;
    stream.write_all(&bytes[..length]).await?;
    Ok(())
}
async fn traffic(stream: &mut UnixStream, bytes: &[u8]) -> Result<(), Failure> {
    response(
        stream,
        Response::Traffic {
            direction: Direction::Inbound,
            peer: PEER,
            traffic: Traffic::Full(bytes),
        },
    )
    .await
}
async fn next(router: &mut impl PeerRouter, deliver: bool) -> Result<PeerProgress, Failure> {
    poll_fn(|cx| router.poll(cx, deliver))
        .await
        .map_err(|e| Box::new(e) as Failure)
}
fn activity(progress: PeerProgress) -> Result<(), Failure> {
    if matches!(progress, PeerProgress::Activity) {
        Ok(())
    } else {
        Err("unexpected local delivery while the consumer gate is closed".into())
    }
}

#[test]
fn actual_core_get_retains_put_and_serves_a_second_source_query() -> Result<(), Failure> {
    composed_local_query(1, [0; 32], false, false)
}

#[test]
fn unknown_target_anonymity_zero_discovers_verified_content_over_core() -> Result<(), Failure> {
    composed_local_query(0, [0; 32], false, false)
}

#[test]
fn known_target_anonymity_zero_uses_core_only_after_direct_idle() -> Result<(), Failure> {
    composed_local_query(0, PEER.0, false, false)
}

#[test]
fn admitted_direct_child_does_not_starve_actual_core_content_discovery() -> Result<(), Failure> {
    composed_local_query(0, PEER.0, true, false)
}

#[test]
fn real_peer_arrival_activates_only_retained_initial_core_intent() -> Result<(), Failure> {
    composed_local_query(0, PEER.0, true, true)
}

fn composed_local_query(
    anonymity: u32,
    target: [u8; 32],
    queued_direct: bool,
    late_peer: bool,
) -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _entered = runtime.enter();
    runtime.block_on(tokio::time::timeout(Duration::from_secs(5), async {
        let (local_key, local_ciphertext) = encrypted(b"local anonymous CORE query")?;
        let (peer_key, peer_ciphertext) = encrypted(b"independent reverse source query")?;
        assert_ne!(local_key, peer_key);
        let original_put = put(&local_ciphertext, LOCAL_EXPIRATION)?;
        let expected_return = put(&peer_ciphertext, SOURCE_EXPIRATION)?;
        let block = source_block(&peer_key, &peer_ciphertext)?;
        assert_eq!(block.data()?.kind, 1);
        assert_eq!(*block.data()?.key, peer_key);
        assert_eq!(block.data()?.value, peer_ciphertext);
        let expected_selections = [
            Selection {
                block_type: BlockType::DBLOCK,
                query: local_key,
            },
            Selection {
                block_type: BlockType::DBLOCK,
                query: peer_key,
            },
        ];
        let facts = Rc::new(RefCell::new(SourceFacts::default()));
        let source_clock = Rc::new(RefCell::new(None::<Arc<dyn RuntimeClock>>));
        let (socket, listener) = Socket::bind()?;
        let (peer_gate, peer_gate_rx) = oneshot::channel();
        let mut peer_gate = Some(peer_gate);
        let (request_seen, mut request_rx) = oneshot::channel();
        let (permit, permit_rx) = oneshot::channel();
        let (local_delivered, local_delivered_rx) = oneshot::channel();
        let actor_put = original_put.clone();
        let actor_return = expected_return.clone();
        let actor = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            match Request::decode(&frame(&mut stream).await?)? {
                Request::Init { options, types } => {
                    assert_eq!(options, 0);
                    assert_eq!(types.iter().collect::<Vec<_>>(), [137, 138, 139]);
                }
                _ => return Err("CORE actor expected the actual INIT".into()),
            }
            response(
                &mut stream,
                Response::InitReply {
                    identity: LOCAL,
                    class: PeerClass::SERVER,
                },
            )
            .await?;
            peer_gate_rx.await?;
            response(
                &mut stream,
                Response::Connected {
                    peer: PEER,
                    class: PeerClass::ROUTER,
                },
            )
            .await?;
            let request = frame(&mut stream).await?;
            let (request_id, size) = match Request::decode(&request)? {
                Request::SendRequest {
                    peer,
                    request_id,
                    size,
                    priority,
                    ..
                } if peer == PEER => {
                    assert_eq!(priority, 32);
                    assert_eq!(usize::from(size), GET_PREFIX);
                    (request_id, size)
                }
                _ => return Err("CORE actor expected the actual GET send request".into()),
            };
            request_seen
                .send(size)
                .map_err(|_| "lost request observer")?;
            permit_rx.await?;
            response(
                &mut stream,
                Response::SendReady {
                    peer: PEER,
                    request_id,
                    size,
                },
            )
            .await?;
            let send = frame(&mut stream).await?;
            match Request::decode(&send)? {
                Request::Send {
                    peer,
                    priority,
                    messages,
                    ..
                } if peer == PEER => {
                    let get = Get::decode(messages)?;
                    assert_eq!(get.block_type, BlockType::DBLOCK);
                    assert_eq!(*get.query, local_key);
                    assert_eq!(get.priority, priority);
                    assert_eq!(get.bitmap, 0);
                    assert!(get.identities.is_empty() && get.bloom.is_empty());
                }
                _ => return Err("CORE actor expected the complete actual CORE_SEND GET137".into()),
            }
            traffic(&mut stream, &actor_put).await?;
            let mut stop = [0; 16];
            MigrationStop {
                reserved: 0,
                duration: gnunet_wire::official::RelativeTime::from_micros(3_000),
            }
            .encode(&mut stop)?;
            traffic(&mut stream, &stop).await?;

            // The second, different hash cannot run before the original local
            // consumer has actually accepted its unmodified positive frame.
            local_delivered_rx.await?;
            let mut query = [0; GET_PREFIX];
            Get {
                block_type: BlockType::DBLOCK,
                priority: 3,
                ttl_seconds: 1,
                reserved: 0,
                bitmap: 0,
                query: &peer_key,
                identities: &[],
                bloom: &[],
            }
            .encode(&mut query)?;
            traffic(&mut stream, &query).await?;
            let request = frame(&mut stream).await?;
            let (request_id, size) = match Request::decode(&request)? {
                Request::SendRequest {
                    peer,
                    request_id,
                    size,
                    priority,
                    ..
                } if peer == PEER => {
                    assert_eq!(priority, 0);
                    assert_eq!(usize::from(size), actor_return.len());
                    (request_id, size)
                }
                _ => {
                    return Err("source positive did not request actual reverse CORE output".into());
                }
            };
            response(
                &mut stream,
                Response::SendReady {
                    peer: PEER,
                    request_id,
                    size,
                },
            )
            .await?;
            let send = frame(&mut stream).await?;
            assert!(matches!(
                Request::decode(&send)?,
                Request::Send { peer, messages, .. }
                    if peer == PEER && messages == actor_return
            ));
            assert_eq!(Put::decode(&actor_return)?.block, peer_ciphertext);
            let mut tail = [0; 1];
            assert_eq!(
                stream.read(&mut tail).await?,
                0,
                "explicit close must reach EOF"
            );
            Ok::<_, Failure>(())
        });

        let mut core_instance = Instance::new();
        let mut gap_instance = pure::Instance::new();
        let mut neighbors = [pure::NeighborSlot::default(); 4];
        let mut first_result = [0; 512];
        let mut second_result = [0; 512];
        let mut routes = [
            pure::RouteSlot::new(&mut first_result),
            pure::RouteSlot::new(&mut second_result),
        ];
        let mut paths = [pure::PathSlot::default(); 4];
        let mut output = [0; 512];
        let pure_gap = pure::Router::new(
            &mut gap_instance,
            &mut neighbors,
            &mut routes,
            &mut paths,
            &mut output,
            pure::Limits {
                fanout: 1,
                ..pure::Limits::default()
            },
        )?;
        let mut privacy_instance = pure::privacy::Instance::new();
        let mut credits = [pure::privacy::CreditSlot::new(); 8];
        let mut intents = [pure::privacy::IntentSlot::new(); 8];
        let privacy = pure::privacy::Policy::new(
            &mut privacy_instance,
            &mut credits,
            &mut intents,
            pure::privacy::Limits::default(),
        )?;
        let gap_router = Router::<_, _, 4, 2>::new(
            &mut core_instance,
            socket.source(),
            ClassOrder::Little,
            NativeLimits {
                sends: 2,
                io_slice_bytes: 1,
                frame_bytes: 1024,
                ..NativeLimits::default()
            },
            pure_gap,
            privacy,
            {
                let facts = facts.clone();
                let source_clock = source_clock.clone();
                move |clock| {
                    clock.sample().map_err(SourceFailure::service)?;
                    *source_clock.borrow_mut() = Some(clock);
                    Ok(Source {
                        expected: expected_selections,
                        block: Some(block),
                        active: None,
                        retiring: false,
                        facts,
                    })
                }
            },
            Entropy,
            Limits {
                local_routes: 2,
                peer_records: 6,
                packets: 2,
                query_timeout: Duration::from_secs(30),
                send_timeout: Duration::from_secs(10),
                priority: 32,
            },
        )?;
        // Unknown sources have no direct provider. The explicit discovery case
        // instead retains a nonanswering admitted primary while actual CORE
        // request/reply IO independently produces this same canonical result.
        let direct_facts = Rc::new(RefCell::new(OfferedFacts::default()));
        let direct = queued_direct.then(|| OfferedPeer {
            offer: Offered::Queued,
            facts: direct_facts.clone(),
        });
        let mut router = if queued_direct {
            Pair::discovery(direct, Some(gap_router), 2)?
        } else {
            Pair::new(direct, Some(gap_router), 2)?
        };
        assert!(Arc::ptr_eq(
            source_clock
                .borrow()
                .as_ref()
                .ok_or("source missed shared clock")?,
            &router.gap().ok_or("original GAP owner missing")?.clock()
        ));
        if !late_peer {
            peer_gate
                .take()
                .ok_or("missing original peer gate")?
                .send(())
                .map_err(|_| "lost actual peer gate")?;
            while router
                .gap()
                .ok_or("original GAP owner missing")?
                .connected_peers()
                != 1
            {
                activity(next(&mut router, false).await?)?;
            }
        }
        let local_only = Search {
            options: SEARCH_LOOPBACK_ONLY,
            block_type: BlockType::DBLOCK,
            anonymity,
            target,
            query: local_key,
            seen: &[],
        };
        assert_eq!(router.start(1, local_only, &[])?, RouteAdmission::Idle);
        assert!(matches!(
            router.start(
                LOCAL_ROUTE,
                Search {
                    options: 0,
                    block_type: BlockType::DBLOCK,
                    anonymity,
                    target,
                    query: local_key,
                    seen: &[],
                },
                &[],
            )?,
            RouteAdmission::Queued
        ));
        if late_peer {
            let original = Search {
                options: 0,
                block_type: BlockType::DBLOCK,
                anonymity,
                target,
                query: local_key,
                seen: &[],
            };
            // A newer reserved/canceled owner must not invalidate this older
            // first admission or emit a native request of its own.
            assert_eq!(router.start(3, original, &[])?, RouteAdmission::Queued);
            router.cancel(3)?;
            assert!(router.input_needed().is_none());
            let report = router.gap().ok_or("missing GAP owner")?.report();
            assert_eq!(report.initial_deferred, 2);
            assert_eq!(report.initial_activations, 0);
            assert_eq!(report.completions, 0);
            assert!(facts.borrow().selections.is_empty());
            peer_gate
                .take()
                .ok_or("missing original peer gate")?
                .send(())
                .map_err(|_| "lost actual peer gate")?;
            while router.input_needed().is_none() {
                activity(next(&mut router, false).await?)?;
            }
            assert_eq!(router.input_needed(), Some(LOCAL_ROUTE));
            assert!(facts.borrow().selections.is_empty());
            router.refresh(LOCAL_ROUTE, original, &[])?;
            assert!(router.input_needed().is_none());
            assert_eq!(
                router
                    .gap()
                    .ok_or("missing GAP owner")?
                    .report()
                    .initial_activations,
                1
            );
        }
        let promised = loop {
            tokio::select! {
                result = &mut request_rx => break result?,
                progress = next(&mut router, false) => activity(progress?)?,
            }
        };
        assert_eq!(usize::from(promised), GET_PREFIX);
        assert_eq!(
            router
                .gap()
                .ok_or("original GAP owner missing")?
                .report()
                .completions,
            0,
            "request admission is not a full payload write"
        );
        assert_eq!(facts.borrow().not_found, 1);
        assert_eq!(facts.borrow().found, 0);
        permit.send(()).map_err(|_| "lost actual SEND_READY gate")?;
        while router
            .gap()
            .ok_or("original GAP owner missing")?
            .retained_results()
            != 1
            || router
                .gap()
                .ok_or("original GAP owner missing")?
                .report()
                .migration_stops
                != 1
        {
            activity(next(&mut router, false).await?)?;
        }
        assert_eq!(
            router
                .gap()
                .ok_or("original GAP owner missing")?
                .retained_results(),
            1
        );
        assert_eq!(
            router
                .gap()
                .ok_or("original GAP owner missing")?
                .report()
                .completions,
            1
        );
        let completed = router
            .gap()
            .ok_or("original GAP owner missing")?
            .report()
            .last_completion
            .as_ref()
            .ok_or("missing actual GET completion")?;
        assert_eq!(completed.outcome, SendOutcome::Written);
        let payload = completed
            .payload
            .ok_or("missing original payload receipt")?;
        assert!(payload.exposed() && payload.complete());
        assert_eq!(payload.written(), SEND_PREFIX + GET_PREFIX);
        assert_eq!(payload.frame_bytes(), SEND_PREFIX + GET_PREFIX);
        assert_eq!(payload.send(), completed.send);
        let actual_get = Get::decode(completed.source.as_ref())?;
        assert_eq!(*actual_get.query, local_key);
        let actual_priority = actual_get.priority;
        let (raw_reply, metadata) = loop {
            match next(&mut router, true).await? {
                PeerProgress::GapReply {
                    route,
                    frame,
                    metadata,
                } => {
                    assert_eq!(route, LOCAL_ROUTE);
                    break (frame, metadata);
                }
                PeerProgress::Activity => {}
                _ => {
                    return Err(
                        "original local query did not deliver its actual GAP positive".into(),
                    );
                }
            }
        };
        assert_eq!(raw_reply.bytes(), original_put);
        assert_eq!(Put::decode(raw_reply.bytes())?.block, local_ciphertext);
        assert_eq!(metadata.num_transmissions, 1);
        assert_eq!(metadata.respect_offered, actual_priority);
        assert_ne!(metadata.last_transmission, AbsoluteTime::NEVER);
        if queued_direct {
            assert_eq!(direct_facts.borrow().starts, if late_peer { 2 } else { 1 });
            assert_eq!(direct_facts.borrow().level, Some(0));
            assert_eq!(direct_facts.borrow().target, target);
            assert!(!direct_facts.borrow().closed);
            // This standalone component test plays the canonical Server's
            // terminal consumer cancellation after owning the validated result.
            router.cancel(LOCAL_ROUTE)?;
            assert_eq!(direct_facts.borrow().cancels, if late_peer { 2 } else { 1 });
            assert!(!direct_facts.borrow().closed);
        }
        assert_eq!(
            router
                .gap()
                .ok_or("original GAP owner missing")?
                .retained_results(),
            0
        );
        local_delivered
            .send(())
            .map_err(|_| "lost local-delivery gate")?;

        let mut ended = false;
        while router
            .gap()
            .ok_or("original GAP owner missing")?
            .report()
            .completions
            != 2
        {
            match next(&mut router, false).await? {
                PeerProgress::Activity => {}
                PeerProgress::Ended(route) if route == LOCAL_ROUTE => {
                    assert!(!ended);
                    ended = true;
                }
                _ => return Err("reverse source query fabricated another local result".into()),
            }
        }
        assert!(ended || queued_direct);
        assert_eq!(facts.borrow().selections, expected_selections);
        assert_eq!(facts.borrow().not_found, 1);
        assert_eq!(facts.borrow().found, 1);
        let completed = router
            .gap()
            .ok_or("original GAP owner missing")?
            .report()
            .last_completion
            .as_ref()
            .ok_or("missing actual PUT completion")?;
        assert_eq!(completed.outcome, SendOutcome::Written);
        assert_eq!(completed.source.as_ref(), expected_return);
        let payload = completed.payload.ok_or("missing reverse PUT receipt")?;
        assert!(payload.complete());
        assert_eq!(payload.written(), SEND_PREFIX + expected_return.len());
        assert_eq!(
            router
                .gap()
                .ok_or("original GAP owner missing")?
                .report()
                .ingress_refused,
            0
        );
        assert_eq!(
            router
                .gap()
                .ok_or("original GAP owner missing")?
                .report()
                .source_failures,
            0
        );
        assert_eq!(
            router
                .gap()
                .ok_or("original GAP owner missing")?
                .report()
                .losses,
            0
        );

        router.request_shutdown();
        poll_fn(|cx| {
            match PeerRouter::poll(&mut router, cx, false) {
                Poll::Ready(Err(error)) => return Poll::Ready(Err(Box::new(error) as Failure)),
                Poll::Ready(Ok(PeerProgress::Activity | PeerProgress::Ended(_))) => {}
                Poll::Ready(Ok(_)) => {
                    return Poll::Ready(Err("shutdown fabricated a result".into()));
                }
                Poll::Pending => {}
            }
            if router.shutdown_state() == PeerShutdown::Quiesced {
                Poll::Ready(Ok(()))
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await?;
        assert!(router.shutdown_state() == PeerShutdown::Quiesced);
        router.close()?;
        assert!(facts.borrow().closed);
        actor.await??;
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}

// These explicit no-I/O providers exercise the composition's ownership contract;
// they supply no protocol result or native success fixture.
#[derive(Clone, Copy)]
enum Offered {
    Idle,
    Queued,
    Ended,
    Error,
    Retired,
    TypedRefusal,
}
#[derive(Default)]
struct OfferedFacts {
    starts: usize,
    cancels: usize,
    closed: bool,
    closes: usize,
    start_failure: Option<ProviderFailure>,
    close_failure: Option<ProviderFailure>,
    polls: usize,
    serial: u64,
    end_sent: bool,
    level: Option<u32>,
    target: [u8; 32],
    seen: Vec<[u8; 64]>,
}
struct OfferedPeer {
    offer: Offered,
    facts: Rc<RefCell<OfferedFacts>>,
}
impl PeerRouter for OfferedPeer {
    fn shutdown_state(&self) -> PeerShutdown {
        if matches!(self.offer, Offered::Retired) {
            PeerShutdown::Retired
        } else {
            PeerShutdown::Immediate
        }
    }
    fn start(
        &mut self,
        serial: u64,
        original: Search<'_>,
        seen: &[[u8; 64]],
    ) -> Result<RouteAdmission, ProviderFailure> {
        if original.options & SEARCH_LOOPBACK_ONLY != 0 {
            return Ok(RouteAdmission::Idle);
        }
        let mut facts = self.facts.borrow_mut();
        facts.starts += 1;
        facts.serial = serial;
        facts.level = Some(original.anonymity);
        facts.target = original.target;
        facts.seen = seen.to_vec();
        match self.offer {
            Offered::Idle => Ok(RouteAdmission::Idle),
            Offered::Queued | Offered::Ended => Ok(RouteAdmission::Queued),
            Offered::Error => Err(ProviderFailure::operation(Error::NotReady)),
            Offered::Retired => Err(ProviderFailure::operation(Error::StaleGeneration)),
            Offered::TypedRefusal => Err(facts
                .start_failure
                .take()
                .ok_or_else(|| ProviderFailure::operation(Error::NotReady))?),
        }
    }
    fn poll(
        &mut self,
        _: &mut Context<'_>,
        _: bool,
    ) -> Poll<Result<PeerProgress, ProviderFailure>> {
        let mut facts = self.facts.borrow_mut();
        facts.polls += 1;
        if matches!(self.offer, Offered::Ended) && !facts.end_sent {
            facts.end_sent = true;
            return Poll::Ready(Ok(PeerProgress::Ended(facts.serial)));
        }
        Poll::Pending
    }
    fn cancel(&mut self, _: u64) -> Result<(), ProviderFailure> {
        self.facts.borrow_mut().cancels += 1;
        Ok(())
    }
    fn close(&mut self) -> Result<(), ProviderFailure> {
        let mut facts = self.facts.borrow_mut();
        facts.closed = true;
        facts.closes += 1;
        match facts.close_failure.take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
#[test]
fn idle_dht_chain_falls_back_with_original_ublock_seen_and_one_consumer() -> Result<(), Failure> {
    for offer in [Offered::Idle, Offered::Retired] {
        let first = Rc::new(RefCell::new(OfferedFacts::default()));
        let second = Rc::new(RefCell::new(OfferedFacts::default()));
        let direct = Pair::<NoPeers, _>::non_anonymous(
            None,
            Some(OfferedPeer {
                offer,
                facts: first.clone(),
            }),
            2,
        )?;
        let gap = OfferedPeer {
            offer: Offered::Queued,
            facts: second.clone(),
        };
        let mut router = Pair::new(Some(direct), Some(gap), 2)?;
        let seen = [[3; 64], [4; 64]];
        let mut wire_seen = [3; 128];
        wire_seen[64..].fill(4);
        let original = Search {
            options: 0,
            block_type: BlockType::UBLOCK,
            anonymity: 0,
            target: [0; 32],
            query: [8; 64],
            seen: &wire_seen,
        };
        original.validate()?;
        assert_eq!(router.start(1, original, &seen)?, RouteAdmission::Queued);
        assert_eq!(
            first.borrow().starts,
            usize::from(matches!(offer, Offered::Idle))
        );
        let observed = second.borrow();
        assert_eq!(observed.starts, 1);
        assert_eq!(observed.level, Some(0));
        assert_eq!(observed.target, original.target);
        assert_eq!(observed.seen, seen);
        drop(observed);
        router.cancel(1)?;
        assert_eq!(first.borrow().cancels, 0);
        assert_eq!(second.borrow().cancels, 1);
        router.close()?;
    }
    Ok(())
}
#[test]
fn queued_or_failed_direct_route_never_silently_replays_to_gap() -> Result<(), Failure> {
    for offer in [Offered::Queued, Offered::Error] {
        let first = Rc::new(RefCell::new(OfferedFacts::default()));
        let second = Rc::new(RefCell::new(OfferedFacts::default()));
        let mut router = Pair::new(
            Some(OfferedPeer {
                offer,
                facts: first.clone(),
            }),
            Some(OfferedPeer {
                offer: Offered::Queued,
                facts: second.clone(),
            }),
            2,
        )?;
        let original = Search {
            options: 0,
            block_type: BlockType::DBLOCK,
            anonymity: 0,
            target: [7; 32],
            query: [8; 64],
            seen: &[],
        };
        let admitted = router.start(1, original, &[])?;
        assert_eq!(first.borrow().starts, 1);
        assert_eq!(second.borrow().starts, 0);
        if matches!(offer, Offered::Queued) {
            assert_eq!(admitted, RouteAdmission::Queued);
            router.cancel(1)?;
            assert_eq!(first.borrow().cancels, 1);
        } else {
            assert_eq!(admitted, RouteAdmission::Refused);
            assert!(first.borrow().closed);
            assert!(router.first_failure().is_some());
        }
        router.close()?;
    }
    Ok(())
}

#[test]
fn nested_dht_error_retains_its_cause_without_gap_or_healthy_cadet_close() -> Result<(), Failure> {
    let healthy = Rc::new(RefCell::new(OfferedFacts::default()));
    let failed = Rc::new(RefCell::new(OfferedFacts::default()));
    let fallback = Rc::new(RefCell::new(OfferedFacts::default()));
    let direct = Pair::non_anonymous(
        Some(OfferedPeer {
            offer: Offered::Queued,
            facts: healthy.clone(),
        }),
        Some(OfferedPeer {
            offer: Offered::Error,
            facts: failed.clone(),
        }),
        2,
    )?;
    let mut router = Pair::new(
        Some(direct),
        Some(OfferedPeer {
            offer: Offered::Queued,
            facts: fallback.clone(),
        }),
        2,
    )?;
    let original = Search {
        options: 0,
        block_type: BlockType::UBLOCK,
        anonymity: 0,
        target: [0; 32],
        query: [8; 64],
        seen: &[],
    };
    assert_eq!(router.start(1, original, &[])?, RouteAdmission::Refused);
    assert_eq!(failed.borrow().starts, 1);
    assert!(failed.borrow().closed);
    assert_eq!(healthy.borrow().starts, 0);
    assert!(!healthy.borrow().closed);
    assert_eq!(fallback.borrow().starts, 0);
    let refusal = router
        .direct()
        .and_then(|inner| inner.failure(gnunet_fs_host::server::peers::Backend::Dht))
        .ok_or("nested DHT original failure missing")?;
    assert_eq!(
        refusal.cause.cause().downcast_ref::<Error>(),
        Some(&Error::NotReady)
    );
    router.close()?;
    Ok(())
}

#[test]
fn discovery_retains_both_originals_after_one_child_delivery_ends() -> Result<(), Failure> {
    let first = Rc::new(RefCell::new(OfferedFacts::default()));
    let second = Rc::new(RefCell::new(OfferedFacts::default()));
    let mut router = Pair::discovery(
        Some(OfferedPeer {
            offer: Offered::Ended,
            facts: first.clone(),
        }),
        Some(OfferedPeer {
            offer: Offered::Queued,
            facts: second.clone(),
        }),
        2,
    )?;
    let seen = [[3; 64], [4; 64]];
    let original = Search {
        options: 0,
        block_type: BlockType::UBLOCK,
        anonymity: 0,
        target: [0; 32],
        query: [8; 64],
        seen: &[],
    };
    assert_eq!(router.start(1, original, &seen)?, RouteAdmission::Queued);
    for facts in [&first, &second] {
        assert_eq!(facts.borrow().starts, 1);
        assert_eq!(facts.borrow().level, Some(0));
        assert_eq!(facts.borrow().seen, seen);
    }
    let mut cx = Context::from_waker(std::task::Waker::noop());
    assert!(matches!(
        router.poll(&mut cx, true),
        Poll::Ready(Ok(PeerProgress::Activity))
    ));
    assert!(router.poll(&mut cx, true).is_pending());
    assert!(first.borrow().end_sent);
    assert!(!first.borrow().closed && !second.borrow().closed);
    // Neither the ended callback nor local cancellation erases the actual
    // backend's independent drain work, and no late start replays the search.
    router.cancel(1)?;
    assert_eq!(first.borrow().cancels, 1);
    assert_eq!(second.borrow().cancels, 1);
    let before = (first.borrow().polls, second.borrow().polls);
    assert!(router.poll(&mut cx, false).is_pending());
    assert!(first.borrow().polls > before.0 && second.borrow().polls > before.1);
    assert_eq!(first.borrow().starts, 1);
    assert_eq!(second.borrow().starts, 1);
    router.close()?;
    Ok(())
}

#[test]
fn discovery_secondary_refusal_does_not_orphan_admitted_primary() -> Result<(), Failure> {
    let first = Rc::new(RefCell::new(OfferedFacts::default()));
    let second = Rc::new(RefCell::new(OfferedFacts::default()));
    let mut router = Pair::discovery(
        Some(OfferedPeer {
            offer: Offered::Queued,
            facts: first.clone(),
        }),
        Some(OfferedPeer {
            offer: Offered::Error,
            facts: second.clone(),
        }),
        2,
    )?;
    let original = Search {
        options: 0,
        block_type: BlockType::DBLOCK,
        anonymity: 0,
        target: [7; 32],
        query: [8; 64],
        seen: &[],
    };
    assert_eq!(router.start(1, original, &[])?, RouteAdmission::Queued);
    assert_eq!(first.borrow().starts, 1);
    assert_eq!(second.borrow().starts, 1);
    assert!(!first.borrow().closed);
    assert!(second.borrow().closed);
    let failure = router
        .failure(gnunet_fs_host::server::peers::Backend::Gap)
        .ok_or("original discovery refusal missing")?;
    assert_eq!(
        failure.cause.cause().downcast_ref::<Error>(),
        Some(&Error::NotReady)
    );
    router.cancel(1)?;
    assert_eq!(first.borrow().cancels, 1);
    assert_eq!(second.borrow().cancels, 0);
    assert!(!first.borrow().closed);
    router.close()?;
    Ok(())
}

#[test]
fn planned_core_survives_a_real_nested_nonfatal_primary_refusal() -> Result<(), Failure> {
    let healthy = Rc::new(RefCell::new(OfferedFacts::default()));
    let failed = Rc::new(RefCell::new(OfferedFacts::default()));
    let core = Rc::new(RefCell::new(OfferedFacts::default()));
    let direct = Pair::non_anonymous(
        Some(OfferedPeer {
            offer: Offered::Queued,
            facts: healthy.clone(),
        }),
        Some(OfferedPeer {
            offer: Offered::Error,
            facts: failed.clone(),
        }),
        2,
    )?;
    let mut router = Pair::discovery(
        Some(direct),
        Some(OfferedPeer {
            offer: Offered::Queued,
            facts: core.clone(),
        }),
        2,
    )?;
    let original = Search {
        options: 0,
        block_type: BlockType::UBLOCK,
        anonymity: 0,
        target: [0; 32],
        query: [8; 64],
        seen: &[],
    };
    let seen = [[3; 64]];
    assert_eq!(router.start(1, original, &seen)?, RouteAdmission::Queued);
    assert_eq!(failed.borrow().starts, 1);
    assert!(failed.borrow().closed);
    assert_eq!(healthy.borrow().starts, 0);
    assert!(!healthy.borrow().closed);
    assert_eq!(core.borrow().starts, 1);
    assert_eq!(core.borrow().seen, seen);
    assert_eq!(core.borrow().level, Some(0));
    assert!(!core.borrow().closed);
    let refusal = router
        .direct()
        .and_then(|inner| inner.failure(gnunet_fs_host::server::peers::Backend::Dht))
        .ok_or("nested original DHT refusal missing")?;
    assert_eq!(
        refusal.cause.cause().downcast_ref::<Error>(),
        Some(&Error::NotReady)
    );
    router.cancel(1)?;
    assert_eq!(core.borrow().cancels, 1);
    assert_eq!(healthy.borrow().cancels, 0);
    assert_eq!(failed.borrow().cancels, 0);
    assert!(!healthy.borrow().closed);
    router.close()?;
    Ok(())
}

#[test]
fn planned_core_survives_primary_error_without_losing_its_typed_cause() -> Result<(), Failure> {
    let primary = Rc::new(RefCell::new(OfferedFacts::default()));
    let core = Rc::new(RefCell::new(OfferedFacts::default()));
    let mut router = Pair::discovery(
        Some(OfferedPeer {
            offer: Offered::Error,
            facts: primary.clone(),
        }),
        Some(OfferedPeer {
            offer: Offered::Queued,
            facts: core.clone(),
        }),
        2,
    )?;
    let original = Search {
        options: 0,
        block_type: BlockType::DBLOCK,
        anonymity: 0,
        target: [7; 32],
        query: [8; 64],
        seen: &[],
    };
    assert_eq!(router.start(1, original, &[])?, RouteAdmission::Queued);
    assert!(primary.borrow().closed);
    assert_eq!(core.borrow().starts, 1);
    assert!(!core.borrow().closed);
    let failure = router
        .failure(gnunet_fs_host::server::peers::Backend::Direct)
        .ok_or("original primary refusal missing")?;
    assert_eq!(
        failure.cause.cause().downcast_ref::<Error>(),
        Some(&Error::NotReady)
    );
    router.cancel(1)?;
    assert_eq!(core.borrow().cancels, 1);
    assert_eq!(primary.borrow().cancels, 0);
    router.close()?;
    Ok(())
}

#[derive(Debug)]
struct Original {
    name: &'static str,
    identity: Arc<()>,
}
impl std::fmt::Display for Original {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name)
    }
}
impl std::error::Error for Original {}
#[derive(Debug)]
struct Wrapped(Box<dyn std::error::Error + Send + Sync>);
impl std::fmt::Display for Wrapped {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "diagnostic context: {}", self.0)
    }
}
impl std::error::Error for Wrapped {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}
fn refusal(identity: &Arc<()>, scope: FailureScope) -> ProviderFailure {
    ProviderFailure::new(
        Box::new(Wrapped(Box::new(Original {
            name: "original modeled refusal",
            identity: identity.clone(),
        }))),
        scope,
    )
}
fn retains(error: &(dyn std::error::Error + 'static), identity: &Arc<()>) -> bool {
    let mut current = Some(error);
    for _ in 0..16 {
        let Some(error) = current else {
            break;
        };
        if error
            .downcast_ref::<Original>()
            .is_some_and(|e| Arc::ptr_eq(&e.identity, identity))
        {
            return true;
        }
        current = error.source();
    }
    false
}

fn scope_query() -> Search<'static> {
    Search {
        options: 0,
        block_type: BlockType::UBLOCK,
        anonymity: 0,
        target: [0; 32],
        query: [4; 64],
        seen: &[],
    }
}

#[test]
fn wrapped_shared_failure_survives_nested_pair_and_server_boundary() -> Result<(), Failure> {
    let original = Arc::new(());
    let facts = Rc::new(RefCell::new(OfferedFacts {
        start_failure: Some(refusal(&original, FailureScope::Service)),
        ..Default::default()
    }));
    let inner = Pair::<_, NoPeers>::new(
        Some(OfferedPeer {
            offer: Offered::TypedRefusal,
            facts: facts.clone(),
        }),
        None,
        2,
    )?;
    let mut outer = Pair::<_, NoPeers>::new(Some(inner), None, 2)?;
    let failure = match outer.start(1, scope_query(), &[]) {
        Err(error) => error,
        Ok(_) => return Err("shared original refusal became an admissible/local result".into()),
    };
    assert_eq!(failure.scope(), FailureScope::Service);
    let server = gnunet_fs_host::server::Error::Route(failure);
    assert!(server.is_fatal());
    assert!(retains(&server, &original));
    assert_eq!(facts.borrow().closes, 1);
    outer.close()?;
    assert_eq!(facts.borrow().closes, 1);
    Ok(())
}

#[test]
fn independent_service_cleanup_upgrades_operation_scope_without_replacing_cause()
-> Result<(), Failure> {
    let original = Arc::new(());
    let cleanup = Arc::new(());
    let observations = Rc::new(RefCell::new(OfferedFacts {
        start_failure: Some(refusal(&original, FailureScope::Operation)),
        close_failure: Some(refusal(&cleanup, FailureScope::Service)),
        ..Default::default()
    }));
    let mut pair = Pair::<_, NoPeers>::new(
        Some(OfferedPeer {
            offer: Offered::TypedRefusal,
            facts: observations.clone(),
        }),
        None,
        2,
    )?;
    let failure = match pair.start(1, scope_query(), &[]) {
        Err(error) => error,
        Ok(_) => return Err("service-wide cleanup became a nonfatal refusal".into()),
    };
    let facts = pair
        .failure(gnunet_fs_host::server::peers::Backend::Direct)
        .ok_or("missing original backend facts")?;
    assert_eq!(facts.cause.scope(), FailureScope::Operation);
    assert_eq!(
        facts.cleanup.as_ref().map(|e| e.scope()),
        Some(FailureScope::Service)
    );
    assert!(retains(facts.cause.as_ref(), &original));
    assert!(retains(
        facts.cleanup.as_ref().ok_or("missing cleanup")?.as_ref(),
        &cleanup
    ));
    let server = gnunet_fs_host::server::Error::Route(failure);
    assert!(server.is_fatal());
    assert!(retains(&server, &original));
    assert_eq!(observations.borrow().closes, 1);
    pair.close()?;
    assert_eq!(observations.borrow().closes, 1);
    Ok(())
}

// A controlled local provider refusal, carried through actual CORE attachment
// and GAP query ownership. It does not claim native DATASTORE/index failure.
struct ScopedSource {
    selection: Option<Selection>,
    ready: Rc<std::cell::Cell<bool>>,
    starts: Rc<std::cell::Cell<usize>>,
    closes: Rc<std::cell::Cell<usize>>,
    retiring: bool,
    failure: Option<SourceFailure>,
    cleanup: Option<SourceFailure>,
}
impl BlockSource for ScopedSource {
    fn request_retire(&mut self) {
        self.retiring = true;
    }
    fn start(&mut self, selection: Selection) -> Result<(), SourceFailure> {
        if self.selection.is_some() {
            return Err(SourceFailure::operation(Error::Conflict));
        }
        self.selection = Some(selection);
        self.starts.set(self.starts.get() + 1);
        Ok(())
    }
    fn poll(&mut self, _: &mut Context<'_>) -> Poll<Result<SourceProgress, SourceFailure>> {
        if !self.ready.get() {
            return Poll::Pending;
        }
        let Some(selection) = self.selection.take() else {
            return Poll::Pending;
        };
        let failure = self
            .failure
            .take()
            .ok_or_else(|| SourceFailure::operation(Error::StaleGeneration));
        Poll::Ready(failure.and_then(|cause| {
            if self.retiring {
                Ok(SourceProgress::Retired(Retired {
                    selection,
                    observation: Retirement::Failed(cause),
                }))
            } else {
                Err(cause)
            }
        }))
    }
    fn close(&mut self) -> Result<(), SourceFailure> {
        self.closes.set(self.closes.get() + 1);
        self.selection = None;
        self.cleanup.take().map_or(Ok(()), Err)
    }
}

fn source_scope_profile(
    scope: FailureScope,
    cleanup_scope: FailureScope,
    retire: bool,
) -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let _entered = runtime.enter();
    runtime.block_on(tokio::time::timeout(Duration::from_secs(5), async {
        let original = Arc::new(());
        let cleanup = Arc::new(());
        let ready = Rc::new(std::cell::Cell::new(false));
        let starts = Rc::new(std::cell::Cell::new(0));
        let closes = Rc::new(std::cell::Cell::new(0));
        let (socket, listener) = Socket::bind()?;
        let mut core_instance = Instance::new();
        let mut gap_instance = pure::Instance::new();
        let mut neighbors = [pure::NeighborSlot::default(); 4];
        let mut result = [0; 512];
        let mut routes = [pure::RouteSlot::new(&mut result)];
        let mut paths = [pure::PathSlot::default(); 4];
        let mut output = [0; 512];
        let protocol = pure::Router::new(
            &mut gap_instance,
            &mut neighbors,
            &mut routes,
            &mut paths,
            &mut output,
            pure::Limits {
                fanout: 1,
                ..Default::default()
            },
        )?;
        let mut privacy_instance = pure::privacy::Instance::new();
        let mut credits = [pure::privacy::CreditSlot::new(); 8];
        let mut intents = [pure::privacy::IntentSlot::new(); 8];
        let privacy = pure::privacy::Policy::new(
            &mut privacy_instance,
            &mut credits,
            &mut intents,
            Default::default(),
        )?;
        let source = ScopedSource {
            selection: None,
            ready: ready.clone(),
            starts: starts.clone(),
            closes: closes.clone(),
            retiring: false,
            failure: Some(refusal(&original, scope)),
            cleanup: Some(refusal(&cleanup, cleanup_scope)),
        };
        let mut router = Router::<_, _, 4, 2>::new(
            &mut core_instance,
            socket.source(),
            ClassOrder::Little,
            NativeLimits {
                sends: 2,
                io_slice_bytes: 1,
                frame_bytes: 1024,
                ..Default::default()
            },
            protocol,
            privacy,
            |_| Ok(source),
            Entropy,
            Limits {
                local_routes: 1,
                peer_records: 6,
                packets: 2,
                ..Default::default()
            },
        )?;
        // Both IO futures remain owned by this finite parent. There is no
        // detached actor/task; dropping the parent closes both original sockets.
        let actor = async {
            let (mut stream, _) = listener.accept().await?;
            assert!(matches!(
                Request::decode(&frame(&mut stream).await?)?,
                Request::Init { .. }
            ));
            response(
                &mut stream,
                Response::InitReply {
                    identity: LOCAL,
                    class: PeerClass::SERVER,
                },
            )
            .await?;
            response(
                &mut stream,
                Response::Connected {
                    peer: PEER,
                    class: PeerClass::ROUTER,
                },
            )
            .await?;
            let mut bytes = [0; 256];
            while stream.read(&mut bytes).await? != 0 {}
            Ok::<_, Failure>(())
        };
        let work = async move {
            while router.connected_peers() == 0 {
                activity(next(&mut router, false).await?)?;
            }
            let search = Search {
                options: 0,
                block_type: BlockType::DBLOCK,
                anonymity: 1,
                target: [0; 32],
                query: [6; 64],
                seen: &[],
            };
            assert_eq!(router.start(1, search, &[])?, RouteAdmission::Queued);
            while starts.get() == 0 {
                activity(next(&mut router, false).await?)?;
            }
            if retire {
                router.cancel(1)?;
            }
            ready.set(true);
            let failure = loop {
                match poll_fn(|cx| PeerRouter::poll(&mut router, cx, false)).await {
                    Err(failure) => break failure,
                    Ok(step) => {
                        activity(step)?;
                        if scope == FailureScope::Operation
                            && router.report().first_source_failure.is_some()
                        {
                            let observed = router
                                .report()
                                .first_source_failure
                                .as_ref()
                                .ok_or("lost original source failure")?;
                            assert_eq!(observed.scope(), FailureScope::Operation);
                            assert!(retains(observed, &original));
                            break router
                                .close()
                                .err()
                                .ok_or("service-wide source cleanup was swallowed")?;
                        }
                    }
                }
            };
            assert_eq!(failure.scope(), FailureScope::Service);
            if scope == FailureScope::Service {
                assert!(retains(&failure, &original));
            }
            let native = failure
                .cause()
                .downcast_ref::<gnunet_fs_host::server::gap::Error>()
                .ok_or("original GAP cause was replaced")?;
            let source_cleanup = match native {
                gnunet_fs_host::server::gap::Error::Retirement { cleanup, .. } => {
                    match cleanup.as_ref() {
                        gnunet_fs_host::server::gap::Error::Cleanup {
                            source: Some(cause),
                            ..
                        } => cause,
                        _ => return Err("source cleanup cause missing".into()),
                    }
                }
                gnunet_fs_host::server::gap::Error::Cleanup {
                    source: Some(cause),
                    ..
                } => cause,
                _ => return Err("original source cleanup was not retained".into()),
            };
            assert_eq!(source_cleanup.scope(), cleanup_scope);
            assert!(retains(source_cleanup, &cleanup));
            assert_eq!(closes.get(), 1);
            Ok::<_, Failure>(())
        };
        let (work, actor) = tokio::join!(work, actor);
        match (work, actor) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(original), Err(actor)) => {
                Err(format!("source ownership: {original}; independent CORE actor: {actor}").into())
            }
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    }))??;
    Ok(())
}

#[test]
fn wrapped_block_source_failure_keeps_service_scope_after_active_and_retired_query()
-> Result<(), Failure> {
    for retired in [false, true] {
        source_scope_profile(FailureScope::Service, FailureScope::Operation, retired)?;
    }
    Ok(())
}
#[test]
fn block_source_service_cleanup_preserves_the_original_operation_failure() -> Result<(), Failure> {
    source_scope_profile(FailureScope::Operation, FailureScope::Service, false)
}
