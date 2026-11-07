//! Real native byte/peer-generation and transactional input models. Fixture CORE
//! IPC server is not an official C or production CORE implementation.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible socket models assert exact original physical and Book effects"
)]
use gnunet_cadet::connection::{
    self, Authentication, Book, FrameSlot, Neighbor, NeighborSlot, OriginSlot, RouteSlot,
};
use gnunet_cadet_host::connection::{
    self as bridge, Binding, Bridge, Observer, PeerSlot, SendSlot, Source, Step,
};
use gnunet_cadet_host::time::Timebase;
use gnunet_core_client_host::{self as native, PayloadState, Peer, SendOutcome};
use gnunet_crypto::EddsaPrivateKey;
use gnunet_types::{Error, MonoInstant};
use gnunet_wire::official::{
    cadet_peer::{
        CONNECTION_INITIATOR_PURPOSE, ConnectionInitiatorPurpose, PathPeers, PeerMessage,
    },
    core::{ClassOrder, Direction, PeerClass, PeerId, Request, Response, Traffic},
};
use std::{
    error::Error as StdError,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    time::Instant,
};
type Failure = Box<dyn StdError + Send + Sync>;
const LOCAL: PeerId = PeerId([1; 32]);
const REMOTE: PeerId = PeerId([2; 32]);
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Socket(PathBuf);
impl Socket {
    fn new() -> Result<(Self, UnixListener), Failure> {
        let path = std::env::temp_dir().join(format!(
            "gnrs-cadet-core-{}-{}.sock",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
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
async fn frame(stream: &mut UnixStream, first: Option<u8>) -> Result<Vec<u8>, Failure> {
    let mut header = [0; 4];
    if let Some(first) = first {
        header[0] = first;
        stream.read_exact(&mut header[1..]).await?;
    } else {
        stream.read_exact(&mut header).await?;
    }
    let length = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if length < 4 {
        return Err("short fixture frame".into());
    }
    let mut bytes = vec![0; length];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn response(stream: &mut UnixStream, value: Response<'_>) -> Result<(), Failure> {
    let mut bytes = vec![0; 1024];
    let n = value.encode(&mut bytes, ClassOrder::Little)?;
    stream.write_all(&bytes[..n]).await?;
    Ok(())
}
async fn init(stream: &mut UnixStream, remote: PeerId) -> Result<(), Failure> {
    let bytes = frame(stream, None).await?;
    assert!(matches!(
        Request::decode(&bytes)?,
        Request::Init { options: 0, .. }
    ));
    response(
        stream,
        Response::InitReply {
            identity: LOCAL,
            class: PeerClass::ROUTER,
        },
    )
    .await?;
    response(
        stream,
        Response::Connected {
            peer: remote,
            class: PeerClass::ROUTER,
        },
    )
    .await
}
async fn permit(stream: &mut UnixStream, remote: PeerId) -> Result<(), Failure> {
    let bytes = frame(stream, None).await?;
    let Request::SendRequest {
        peer,
        request_id,
        size,
        ..
    } = Request::decode(&bytes)?
    else {
        return Err("missing actual request".into());
    };
    assert_eq!(peer, remote);
    response(
        stream,
        Response::SendReady {
            peer,
            request_id,
            size,
        },
    )
    .await
}
async fn traffic(
    stream: &mut UnixStream,
    remote: PeerId,
    message: PeerMessage<'_>,
) -> Result<(), Failure> {
    let mut bytes = [0; 512];
    let n = message.encode(&mut bytes)?;
    response(
        stream,
        Response::Traffic {
            direction: Direction::Inbound,
            peer: remote,
            traffic: Traffic::Full(&bytes[..n]),
        },
    )
    .await
}
#[derive(Default)]
struct Observe<'book> {
    first: Option<Neighbor<'book>>,
    ready: usize,
    neighbors: usize,
    retired: usize,
    started: usize,
    exposed: usize,
    completed: usize,
    last_outcome: Option<connection::Outcome>,
    fresh: Option<connection::ResetProof<'book>>,
    bad: bool,
}
impl<'core, 'book, const P: usize> Observer<'core, 'book, P> for Observe<'book> {
    fn neighbor(
        &mut self,
        _source: Source<'core, 'book>,
        _book: &mut Book<'book, '_, '_, P>,
        _now: MonoInstant,
    ) {
        self.neighbors += 1;
    }
    fn retired(
        &mut self,
        source: Source<'core, 'book>,
        _routes: usize,
        book: &mut Book<'book, '_, '_, P>,
        _now: MonoInstant,
    ) {
        self.retired += 1;
        self.bad |= book
            .current_neighbor(source.neighbor().identity())
            .is_some();
    }
    fn input<'message>(
        &mut self,
        source: Source<'core, 'book>,
        event: connection::Event<'book, 'message>,
        _wire: &'message [u8],
        _book: &mut Book<'book, '_, '_, P>,
        _now: MonoInstant,
    ) {
        if self.first.is_none() {
            self.first = Some(source.neighbor());
        }
        match event {
            connection::Event::Ready(_) => self.ready += 1,
            connection::Event::Created {
                reset: connection::Reset::Fresh(proof),
                ..
            } => {
                self.bad |= self.fresh.is_some();
                self.fresh = Some(proof);
            }
            _ => {}
        }
    }
    fn started(
        &mut self,
        binding: Binding<'core, 'book>,
        book: &mut Book<'book, '_, '_, P>,
        _now: MonoInstant,
    ) {
        self.started += 1;
        self.bad |= book.frame_bytes(binding.frame()).is_err();
    }
    fn exposed(
        &mut self,
        _binding: Binding<'core, 'book>,
        state: PayloadState<'core>,
        _book: &mut Book<'book, '_, '_, P>,
        _now: MonoInstant,
    ) {
        self.exposed += 1;
        self.bad |= !state.exposed();
    }
    fn completed(
        &mut self,
        done: connection::Completion<'book>,
        binding: Option<Binding<'core, 'book>>,
        state: Option<PayloadState<'core>>,
        book: &mut Book<'book, '_, '_, P>,
        _now: MonoInstant,
    ) {
        self.last_outcome = Some(done.outcome);
        self.completed += 1;
        self.bad |= book.frame_bytes(done.frame).is_err();
        if let Some(binding) = binding {
            self.bad |= done.attempt != Some(binding.attempt());
        }
        if let Some(state) = state {
            self.bad |= (done.outcome == connection::Outcome::Written) != state.complete();
        }
    }
}
fn runtime() -> Result<tokio::runtime::Runtime, Failure> {
    Ok(tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?)
}

#[test]
fn actual_create_exposure_precedes_ack_and_partial_old_peer_retires_before_same_pid_neighbor_reuse()
-> Result<(), Failure> {
    let rt = runtime()?;
    let _entered = rt.enter();
    rt.block_on(tokio::time::timeout(Duration::from_secs(8),async{
        let(socket,listener)=Socket::new()?;
        let (controls_sent, controls_seen) = tokio::sync::oneshot::channel();
        let server=tokio::spawn(async move{let(mut stream,_)=listener.accept().await?;init(&mut stream,REMOTE).await?;
            permit(&mut stream,REMOTE).await?;let bytes=frame(&mut stream,None).await?;
            let Request::Send{messages,..}=Request::decode(&bytes)? else{return Err::<(),Failure>("missing original CREATE payload".into());};
            assert!(matches!(PeerMessage::decode(messages)?,PeerMessage::ConnectionCreate{connection,..} if connection==[9;32]));
            traffic(&mut stream,REMOTE,PeerMessage::ConnectionCreateAck{reserved:0,connection:[9;32]}).await?;
            // Second payload loses its original remote generation while still
            // physically partial. New same-PID announcement must remain distinct.
            permit(&mut stream,REMOTE).await?;let mut first=[0;1];stream.read_exact(&mut first).await?;
            response(&mut stream,Response::Disconnected(REMOTE)).await?;
            response(&mut stream,Response::Connected{peer:REMOTE,class:PeerClass::ROUTER}).await?;
            controls_sent.send(()).map_err(|_| "partial control observer vanished")?;
            let bytes=frame(&mut stream,Some(first[0])).await?;
            assert!(matches!(Request::decode(&bytes)?,Request::Send{messages,..} if matches!(PeerMessage::decode(messages)?,PeerMessage::KeyExchange{connection,..} if connection==[9;32])));
            let mut tail=[0;1];assert_eq!(stream.read(&mut tail).await?,0);Ok::<_,Failure>(())
        });
        let source=native::EndpointSource::unix(socket.0.clone());
        let timebase=Timebase::new(source.clock())?;let now=timebase.sample()?.monotonic;
        let mut book_instance=connection::Instance::new();let mut neighbors=[NeighborSlot::new();2];let mut routes=[RouteSlot::<4>::new();4];
        let mut origins=[OriginSlot::new();2];let mut bytes=[[0;512];4];let mut frames=bytes.each_mut().map(|b|FrameSlot::new(b));
        let mut book=Book::new(&mut book_instance,LOCAL.0,&mut neighbors,&mut routes,&mut origins,&mut frames,now,connection::Limits::default())?;
        let mut core_instance=native::Instance::new();let mut peers=[PeerSlot::new();8];let mut sends=[SendSlot::new();4];
        let mut host=Bridge::<4,4>::new(&mut core_instance,source,&book,&mut peers,&mut sends,bridge::Limits{core:native::Limits{sends:4,io_slice_bytes:1,..native::Limits::default()},..bridge::Limits::default()},timebase)?;
        let mut observed=Observe::default();let deadline=Instant::now()+Duration::from_secs(6);
        let old=loop{match host.drive(&mut book,&mut observed,Some(deadline)).await?{Step::Neighbor(source)=>break source,Step::Core(native::Progress::WaitDeadline)=>return Err("CORE neighbor timeout".into()),_=>{}}};
        let path=[LOCAL.0,REMOTE.0];let route=book.open(PathPeers::new(&path),[9;32],Authentication::Unsigned,host.timebase().sample()?.monotonic)?.route;
        while observed.ready==0{match host.drive(&mut book,&mut observed,Some(deadline)).await?{Step::Core(native::Progress::WaitDeadline)=>return Err("actual CREATE ACK timeout".into()),Step::Dropped{..}=>return Err("valid ACK was dropped".into()),_=>{}}}
        assert_eq!(book.route_info(route)?.phase,connection::Phase::Ready);assert_eq!(observed.exposed,1);assert_eq!(observed.completed,1);
        book.queue_payload(route,PeerMessage::KeyExchange{connection:[9;32],flags:1,ephemeral_key:[3;32],ratchet_key:[4;32]},host.timebase().sample()?.monotonic)?;
        let mut replacement:Option<Peer<'_>>=None;
        let mut controls_seen = Some(controls_seen);
        loop{match host.drive(&mut book,&mut observed,Some(deadline)).await?{
            // A ready drive future does not yield to the fixture task. Pause after
            // the actual first payload byte until both real notifications are queued.
            Step::Writing{receipt,..} if receipt.previous()==0=>{if let Some(wait)=controls_seen.take(){wait.await.map_err(|_| "partial controls were not sent")?;}},
            Step::Waiting{peer,reason:Some(Error::WouldBlock),..} if peer!=old.peer()=>{assert!(host.neighbor(peer).is_none());replacement=Some(peer);},
            Step::Finished{binding:Some(binding),state,completion} if completion.outcome==SendOutcome::PeerDisconnected=>{
                assert_eq!(binding.source(),old);assert!(state.complete());assert!(replacement.is_some());break;},
            Step::Core(native::Progress::WaitDeadline)=>return Err("old partial send failed to drain".into()),_=>{}}}
        let new_peer=replacement.ok_or("missing actual replacement peer")?;let new_neighbor=host.neighbor(new_peer).ok_or("new neighbor was not admitted after old physical retirement")?;
        assert_ne!(new_neighbor,old.neighbor());assert_eq!(book.current_neighbor(REMOTE.0),Some(new_neighbor));
        assert_eq!(book.route_info(route)?.phase,connection::Phase::Retired);assert_eq!(observed.exposed,2);assert_eq!(observed.neighbors,2);assert_eq!(observed.retired,1);assert!(!observed.bad);
        let retired=host.close(&mut book,&mut observed)?;assert!(matches!(retired,Some(Step::Lost{..})));
        loop{if matches!(host.drive(&mut book,&mut observed,Some(deadline)).await?,Step::Core(native::Progress::Closed)){break;}}
        server.await??;Ok::<_,Failure>(())
    }))??;
    Ok(())
}

#[test]
fn transactional_capacity_drop_keeps_original_bytes_and_fresh_reset_effect_commits_once_after_retry()
-> Result<(), Failure> {
    let rt = runtime()?;
    let _entered = rt.enter();
    rt.block_on(tokio::time::timeout(Duration::from_secs(8), async {
        let (socket, listener) = Socket::new()?;
        let key = EddsaPrivateKey::from_seed([33; 32]);
        let remote = PeerId(*key.public_key().as_bytes());
        let mut purpose = [0; 16];
        ConnectionInitiatorPurpose { monotime: 77 }.encode(&mut purpose)?;
        let signature = *key.sign(CONNECTION_INITIATOR_PURPOSE, &purpose)?.as_bytes();
        let remote_path = [remote.0, LOCAL.0];
        let mut incoming = [0; 512];
        let size = PeerMessage::ConnectionCreate {
            options_bytes: [2, 0, 0, 0],
            has_monotime_bytes: [1, 0, 0, 0],
            monotime: 77,
            monotime_signature: signature,
            connection: [8; 32],
            path: PathPeers::new(&remote_path),
        }
        .encode(&mut incoming)?;
        let original = incoming[..size].to_vec();
        let server_wire = original.clone();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            init(&mut stream, remote).await?;
            let request = frame(&mut stream, None).await?;
            let Request::SendRequest {
                peer,
                request_id,
                size,
                ..
            } = Request::decode(&request)?
            else {
                return Err::<(), Failure>("missing held request".into());
            };
            // The one Book frame is active while no wire send permit exists.
            response(
                &mut stream,
                Response::Traffic {
                    direction: Direction::Inbound,
                    peer: remote,
                    traffic: Traffic::Full(&server_wire),
                },
            )
            .await?;
            release_rx.await.map_err(|_| "drop observation vanished")?;
            response(
                &mut stream,
                Response::SendReady {
                    peer,
                    request_id,
                    size,
                },
            )
            .await?;
            let _filler = frame(&mut stream, None).await?;
            response(
                &mut stream,
                Response::Traffic {
                    direction: Direction::Inbound,
                    peer: remote,
                    traffic: Traffic::Full(&server_wire),
                },
            )
            .await?;
            let mut tail = [0; 1];
            assert_eq!(stream.read(&mut tail).await?, 0);
            Ok::<_, Failure>(())
        });
        let source = native::EndpointSource::unix(socket.0.clone());
        let timebase = Timebase::new(source.clock())?;
        let now = timebase.sample()?.monotonic;
        let mut book_instance = connection::Instance::new();
        let mut neighbors = [NeighborSlot::new(); 2];
        let mut routes = [RouteSlot::<4>::new(); 4];
        let mut origins = [OriginSlot::new(); 1];
        let mut bytes = [[0; 512]; 1];
        let mut frames = bytes.each_mut().map(|b| FrameSlot::new(b));
        let mut book = Book::new(
            &mut book_instance,
            LOCAL.0,
            &mut neighbors,
            &mut routes,
            &mut origins,
            &mut frames,
            now,
            connection::Limits::default(),
        )?;
        let mut core_instance = native::Instance::new();
        let mut peers = [PeerSlot::new(); 8];
        let mut sends = [SendSlot::new(); 4];
        let mut host = Bridge::<4, 4>::new(
            &mut core_instance,
            source,
            &book,
            &mut peers,
            &mut sends,
            bridge::Limits {
                core: native::Limits {
                    sends: 4,
                    ..native::Limits::default()
                },
                ..bridge::Limits::default()
            },
            timebase,
        )?;
        let mut observed = Observe::default();
        let deadline = Instant::now() + Duration::from_secs(6);
        loop {
            if matches!(
                host.drive(&mut book, &mut observed, Some(deadline)).await?,
                Step::Neighbor(_)
            ) {
                break;
            }
        }
        let path = [LOCAL.0, remote.0];
        book.open(
            PathPeers::new(&path),
            [9; 32],
            Authentication::Unsigned,
            host.timebase().sample()?.monotonic,
        )?;
        loop {
            match host.drive(&mut book, &mut observed, Some(deadline)).await? {
                Step::Dropped {
                    traffic: native::OwnedTraffic::Full(bytes),
                    reason: bridge::DropReason::Protocol(Error::Capacity),
                    ..
                } => {
                    assert_eq!(bytes.as_ref(), original);
                    break;
                }
                Step::Core(native::Progress::WaitDeadline) => {
                    return Err("capacity input did not become explicit drop".into());
                }
                _ => {}
            }
        }
        assert_eq!(host.report().capacity_drops, 1);
        assert_eq!(book.observed_monotime(remote.0), None);
        assert!(observed.fresh.is_none());
        release_tx
            .send(())
            .map_err(|()| "fixture service disappeared")?;
        while observed.fresh.is_none() {
            match host.drive(&mut book, &mut observed, Some(deadline)).await? {
                Step::Dropped { .. } => {
                    return Err("retried original valid input was dropped".into());
                }
                Step::Core(native::Progress::WaitDeadline) => {
                    return Err("fresh proof callback timeout".into());
                }
                _ => {}
            }
        }
        let proof = observed
            .fresh
            .ok_or("missing retained original reset proof")?;
        assert_eq!(proof.origin(), remote.0);
        assert_eq!(proof.monotime(), 77);
        assert_eq!(book.observed_monotime(remote.0), Some(77));
        assert_eq!(host.report().inputs, 1);
        assert!(!observed.bad);
        let retired = host.close(&mut book, &mut observed)?;
        assert!(matches!(retired, Some(Step::Lost { .. })));
        loop {
            if matches!(
                host.drive(&mut book, &mut observed, Some(deadline)).await?,
                Step::Core(native::Progress::Closed)
            ) {
                break;
            }
        }
        server.await??;
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}

// Adjustable absolute source only. The real Timebase supplies separate native
// elapsed scheduling; source subscriptions are independently registered wakes.
use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, RuntimeClock};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
struct BudgetClockState {
    sample: ClockSample,
    failure: Option<Error>,
    rows: [Option<Option<Waker>>; 8],
}
#[derive(Clone)]
struct BudgetClock(Arc<Mutex<BudgetClockState>>);
impl BudgetClock {
    fn new(now: u64) -> Self {
        Self(Arc::new(Mutex::new(BudgetClockState {
            sample: ClockSample {
                now: gnunet_types::AbsoluteTime::from_micros(now),
                revision: 0,
            },
            failure: None,
            rows: core::array::from_fn(|_| None),
        })))
    }
    fn set(&self, now: u64) -> Result<(), Error> {
        let wakes: [Option<Waker>; 8] = {
            let mut state = self.0.lock().map_err(|_| Error::Io)?;
            let revision = state
                .sample
                .revision
                .checked_add(1)
                .ok_or(Error::Overflow)?;
            state.sample = ClockSample {
                now: gnunet_types::AbsoluteTime::from_micros(now),
                revision,
            };
            core::array::from_fn(|i| state.rows[i].as_ref().and_then(Clone::clone))
        };
        for waker in wakes.into_iter().flatten() {
            waker.wake();
        }
        Ok(())
    }
    fn fail(&self, failure: Option<Error>) -> Result<(), Error> {
        let wakes: [Option<Waker>; 8] = {
            let mut state = self.0.lock().map_err(|_| Error::Io)?;
            state.failure = failure;
            state.sample.revision = state
                .sample
                .revision
                .checked_add(1)
                .ok_or(Error::Overflow)?;
            core::array::from_fn(|i| state.rows[i].as_ref().and_then(Clone::clone))
        };
        for waker in wakes.into_iter().flatten() {
            waker.wake();
        }
        Ok(())
    }
}
impl RuntimeClock for BudgetClock {
    fn sample(&self) -> Result<ClockSample, Error> {
        let state = self.0.lock().map_err(|_| Error::Io)?;
        match state.failure {
            Some(reason) => Err(reason),
            None => Ok(state.sample),
        }
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
        let mut state = self.0.lock().map_err(|_| Error::Io)?;
        let slot = state
            .rows
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        state.rows[slot] = Some(None);
        Ok(Box::new(BudgetSubscription {
            clock: self.clone(),
            slot,
        }))
    }
}
struct BudgetSubscription {
    clock: BudgetClock,
    slot: usize,
}
impl ClockSubscription for BudgetSubscription {
    fn poll_changed(
        &mut self,
        cx: &mut Context<'_>,
        observed: u64,
    ) -> Poll<Result<ClockSample, Error>> {
        let mut state = match self.clock.0.lock() {
            Ok(state) => state,
            Err(_) => return Poll::Ready(Err(Error::Io)),
        };
        state.rows[self.slot] = Some(Some(cx.waker().clone()));
        if let Some(reason) = state.failure {
            Poll::Ready(Err(reason))
        } else if state.sample.revision != observed {
            Poll::Ready(Ok(state.sample))
        } else {
            Poll::Pending
        }
    }
}
impl Drop for BudgetSubscription {
    fn drop(&mut self) {
        if let Ok(mut state) = self.clock.0.lock() {
            state.rows[self.slot] = None;
        }
    }
}

#[test]
fn no_send_budget_preserves_logical_rollback_but_stops_actual_clock_failure() -> Result<(), Failure>
{
    let rt = runtime()?;
    let _entered = rt.enter();
    rt.block_on(tokio::time::timeout(Duration::from_secs(3), async {
        let (socket, listener) = Socket::new()?;
        let logical = BudgetClock::new(1_000_000);
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            init(&mut stream, REMOTE).await?;
            let mut suffix = Vec::new();
            stream.read_to_end(&mut suffix).await?;
            Ok::<_, Failure>(suffix)
        });
        let source =
            native::EndpointSource::unix_with_clock(socket.0.clone(), Arc::new(logical.clone()));
        let timebase = Timebase::new(source.clock())?;
        let mut instance = connection::Instance::new();
        let mut neighbors = [NeighborSlot::new(); 2];
        let mut routes = [RouteSlot::<4>::new(); 2];
        let mut origins = [OriginSlot::new(); 1];
        let mut buffers = [[0; 512]; 1];
        let mut frames = buffers.each_mut().map(|bytes| FrameSlot::new(bytes));
        let mut book = Book::new(
            &mut instance,
            LOCAL.0,
            &mut neighbors,
            &mut routes,
            &mut origins,
            &mut frames,
            timebase.sample()?.monotonic,
            connection::Limits::default(),
        )?;
        let mut native_instance = native::Instance::new();
        let mut peers = [PeerSlot::new(); 8];
        let mut sends = [SendSlot::new(); 4];
        let mut host = Bridge::<4, 4>::new(
            &mut native_instance,
            source,
            &book,
            &mut peers,
            &mut sends,
            bridge::Limits {
                core: native::Limits {
                    sends: 4,
                    ..native::Limits::default()
                },
                ..bridge::Limits::default()
            },
            timebase.clone(),
        )?;
        let mut observed = Observe::default();
        let original = loop {
            if let Step::Neighbor(source) = host.drive(&mut book, &mut observed, None).await? {
                break source;
            }
        };
        let before = timebase.sample()?.monotonic;
        logical.set(1)?;
        assert!(matches!(
            host.drive(&mut book, &mut observed, Some(Instant::now()))
                .await?,
            Step::Core(native::Progress::WaitDeadline)
        ));
        assert!(timebase.sample()?.monotonic >= before);
        assert_eq!(book.current_neighbor(REMOTE.0), Some(original.neighbor()));
        assert_eq!(host.report().forced_reconnects, 0);
        logical.fail(Some(Error::Unavailable))?;
        assert!(matches!(
            host.drive(&mut book, &mut observed, None).await,
            Err(gnunet_cadet_host::Error::Protocol(Error::Unavailable))
        ));
        assert_eq!(book.current_neighbor(REMOTE.0), Some(original.neighbor()));
        logical.fail(None)?;
        loop {
            if matches!(
                host.drive(&mut book, &mut observed, None).await?,
                Step::Core(native::Progress::Closed)
            ) {
                break;
            }
        }
        assert_eq!(book.current_neighbor(REMOTE.0), None);
        assert_eq!(observed.retired, 1);
        assert!(host.take_cleanup_error().is_none());
        assert!(server.await??.is_empty());
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}

#[test]
fn native_send_budgets_survive_logical_adjustments_and_retire_original_partial_mq()
-> Result<(), Failure> {
    let rt = runtime()?;
    let _entered = rt.enter();
    rt.block_on(tokio::time::timeout(Duration::from_secs(8), async {
        let (socket, listener) = Socket::new()?;
        let logical = BudgetClock::new(1_000);
        const LIFETIME: u64 = 100_000;
        const GRACE: u64 = 100_000;
        let (first_request_tx, first_request_rx) = tokio::sync::oneshot::channel();
        let advance = logical.clone();
        let adjusting = tokio::spawn(async move {
            first_request_rx.await.map_err(|_| "missing actual first CORE request")?;
            // A legitimate source rollback wakes the registered logical owner,
            // but only the original native timer may expire this send.
            advance.set(10)?;
            Ok::<_, Failure>(())
        });
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await?;
            init(&mut first, REMOTE).await?;
            let request = frame(&mut first, None).await?;
            let Request::SendRequest { deadline: first_deadline, .. } = Request::decode(&request)? else { return Err("missing first original request".into()); };
            first_request_tx.send(()).map_err(|()| "first request clock observer stopped")?;
            // Deliberately do not grant READY to the first request.
            let request = frame(&mut first, None).await?;
            let Request::SendRequest { peer, request_id, size, deadline: second_deadline, .. } = Request::decode(&request)? else { return Err("missing second original request".into()); };
            response(&mut first, Response::SendReady { peer, request_id, size }).await?;
            let mut prefix = [0; 1]; first.read_exact(&mut prefix).await?;
            let mut remainder = Vec::new(); first.read_to_end(&mut remainder).await?;
            let original_partial_bytes = 1 + remainder.len();
            let (mut second, _) = listener.accept().await?;
            init(&mut second, REMOTE).await?;
            let mut rest = Vec::new(); second.read_to_end(&mut rest).await?;
            Ok::<_, Failure>((first_deadline, second_deadline, original_partial_bytes, rest.len()))
        });
        let mut instance = connection::Instance::new();
        let mut neighbors = [NeighborSlot::new(); 2];
        let mut routes = [RouteSlot::<4>::new(); 4];
        let mut origins = [OriginSlot::new(); 1];
        let mut buffers = [[0; 512]; 2];
        let mut frames = buffers.each_mut().map(|bytes| FrameSlot::new(bytes));
        let mut native_instance = native::Instance::new();
        let mut peers = [PeerSlot::new(); 8];
        let mut sends = [SendSlot::new(); 4];
        let source = native::EndpointSource::unix_with_clock(socket.0.clone(), Arc::new(logical.clone()));
        let timebase = Timebase::new(source.clock())?;
        let mut book = Book::new(&mut instance, LOCAL.0, &mut neighbors, &mut routes, &mut origins, &mut frames, timebase.sample()?.monotonic, connection::Limits::default())?;
        let mut host = Bridge::<4,4>::new(&mut native_instance, source, &book, &mut peers, &mut sends,
            bridge::Limits {
                core: native::Limits { sends: 4, io_slice_bytes: 1, ..native::Limits::default() },
                // Finite per-admission policy overrides this deliberately stale
                // fixed value; each actual wire request gets its own expiry.
                send_deadline: 1,
                send_budget: Some(bridge::SendBudget { lifetime_micros: LIFETIME, retirement_grace_micros: GRACE }),
                ..bridge::Limits::default()
            }, timebase.clone())?;
        assert!(host.timebase().same_epoch(&timebase));
        let mut observed = Observe::default();
        let old = loop {
            if let Step::Neighbor(source) = host.drive(&mut book, &mut observed, None).await? { break source; }
        };
        let path = [LOCAL.0, REMOTE.0];
        book.open(PathPeers::new(&path), [31;32], Authentication::Unsigned, timebase.sample()?.monotonic)?;
        let first = loop {
            if let Step::Started(binding) = host.drive(&mut book, &mut observed, None).await? { break binding; }
        };
        let first_expires = host.next_deadline().ok_or("missing first native expiry")?;
        let first_hard_stop = first_expires.after(gnunet_types::Duration(GRACE))?;
        let first_native = timebase.native_bound(first_expires)?;
        loop {
            match host.drive(&mut book, &mut observed, None).await? {
                Step::SendExpired { binding: Some(binding), expires, hard_stop, outcome: bridge::Expiration::Cancelled(done), .. } => {
                    assert_eq!(binding, first);
                    assert_eq!(expires, first_expires); assert_eq!(hard_stop, first_hard_stop);
                    assert!(Instant::now() >= first_native);
                    assert_eq!(done.outcome, SendOutcome::CancelledBeforePayload);
                    break;
                }
                Step::Writing { .. } => return Err("no READY was granted for original unwritten request".into()),
                _ => {},
            }
        }
        adjusting.await??;
        assert_eq!(timebase.sample()?.absolute.as_micros(), 10);
        assert_eq!(timebase.native_bound(first_expires)?, first_native);
        assert_eq!(observed.completed, 1);
        assert_eq!(observed.last_outcome, Some(connection::Outcome::Unsent));
        assert_eq!(host.next_deadline(), None);
        logical.set(4_000)?;
        book.open(PathPeers::new(&path), [32;32], Authentication::Unsigned, timebase.sample()?.monotonic)?;
        let second = loop {
            if let Step::Started(binding) = host.drive(&mut book, &mut observed, None).await? { break binding; }
        };
        assert_ne!(second.send(), first.send());
        let second_expires = host.next_deadline().ok_or("missing second native expiry")?;
        let second_hard_stop = second_expires.after(gnunet_types::Duration(GRACE))?;
        let second_native = timebase.native_bound(second_expires)?;
        loop {
            if let Step::Writing { binding, receipt } = host.drive(&mut book, &mut observed, None).await? {
                assert_eq!(binding, second); assert_eq!(receipt.state().written(), 1); break;
            }
        }
        // Advancing UTC beyond the wire deadline cannot expire the independent
        // native budget or refresh its original target. Do not poll the partial
        // native writer while waiting: it retains its actual one-byte prefix.
        logical.set(50_000_000)?;
        assert_eq!(host.next_deadline(), Some(second_expires));
        assert_eq!(timebase.native_bound(second_expires)?, second_native);
        tokio::time::sleep_until(second_native).await;
        assert!(matches!(host.drive(&mut book, &mut observed, None).await?, Step::SendExpired { binding: Some(binding), expires, hard_stop, outcome: bridge::Expiration::Draining, .. } if binding == second && expires == second_expires && hard_stop == second_hard_stop));
        assert_eq!(observed.completed, 1); // no TTL-based fake Book settlement
        assert_eq!(host.next_deadline(), Some(second_hard_stop));
        logical.set(1)?;
        let hard_native = timebase.native_bound(second_hard_stop)?;
        assert_eq!(host.next_deadline(), Some(second_hard_stop));
        tokio::time::sleep_until(hard_native).await;
        assert!(matches!(host.drive(&mut book, &mut observed, None).await?, Step::Lost { .. }));
        assert_eq!(observed.completed, 1);
        assert_eq!(book.current_neighbor(REMOTE.0), Some(old.neighbor()));
        let mut old_finished = false;
        let mut old_retired = false;
        while !old_retired {
            match host.drive(&mut book, &mut observed, None).await? {
                Step::Finished { binding: Some(binding), state, completion } if binding == second => {
                    assert_eq!(state.written(), 1); assert!(!state.complete());
                    assert_eq!(completion.outcome, SendOutcome::ConnectionLost);
                    assert_eq!(observed.last_outcome, Some(connection::Outcome::Unknown)); old_finished = true;
                }
                Step::Retired { peer, .. } if peer == old.peer() => { assert!(old_finished); old_retired = true; }
                Step::Neighbor(_) => return Err("replacement peer reused before original native drain".into()),
                _ => {},
            }
        }
        assert_eq!(book.current_neighbor(REMOTE.0), None);
        // The real first retry may have zero delay. Preserve a replacement
        // event observed while registering/waiting instead of consuming it.
        let mut early_replacement = None;
        loop {
            let budget = Instant::now() + Duration::from_millis(2);
            match host.drive(&mut book, &mut observed, Some(budget)).await? {
                Step::Neighbor(source) => { early_replacement = Some(source); break; }
                Step::Core(native::Progress::WaitDeadline) => break,
                _ => {},
            }
        }
        // CORE's endpoint retry still uses its own documented logical source.
        // This adjustment is not supplied to the Book or any native budget.
        logical.set(10_000_001)?;
        let replacement = match early_replacement {
            Some(source) => source,
            None => loop {
                if let Step::Neighbor(source) = host.drive(&mut book, &mut observed, None).await? { break source; }
            },
        };
        // A zero caller wait observes native ownership without fabricating time.
        assert!(matches!(host.drive(&mut book, &mut observed, Some(Instant::now())).await?, Step::Core(native::Progress::WaitDeadline)));
        assert_ne!(replacement.epoch(), old.epoch());
        assert_ne!(replacement.neighbor(), old.neighbor());
        assert_eq!(observed.completed, 2);
        assert_eq!(host.report().expired_sends, 2);
        assert_eq!(host.report().forced_reconnects, 1);
        assert_eq!(host.report().cancellation_errors, 0);
        // A further legal rollback preserves this actual replacement generation.
        let before_rollback = timebase.sample()?.monotonic;
        logical.set(1)?;
        assert!(matches!(host.drive(&mut book, &mut observed, Some(Instant::now())).await?, Step::Core(native::Progress::WaitDeadline)));
        assert!(timebase.sample()?.monotonic >= before_rollback);
        assert_eq!(book.current_neighbor(REMOTE.0), Some(replacement.neighbor()));
        assert_eq!(host.report().forced_reconnects, 1);
        // A real provider refusal, unlike rollback, stops the original native
        // MQ first. Its Book retirement still awaits honest source recovery.
        logical.fail(Some(Error::Unavailable))?;
        assert!(matches!(host.drive(&mut book, &mut observed, None).await, Err(gnunet_cadet_host::Error::Protocol(Error::Unavailable))));
        assert_eq!(book.current_neighbor(REMOTE.0), Some(replacement.neighbor()));
        logical.fail(None)?;
        loop {
            if matches!(host.drive(&mut book, &mut observed, None).await?, Step::Core(native::Progress::Closed)) { break; }
        }
        assert_eq!(book.current_neighbor(REMOTE.0), None);
        assert_eq!(observed.retired, 2); assert!(!observed.bad);
        assert!(host.take_cleanup_error().is_none());
        let (first_deadline, second_deadline, partial, second_rest) = server.await??;
        assert_eq!((first_deadline, second_deadline), (1_000 + LIFETIME, 4_000 + LIFETIME));
        assert_eq!(partial, 1); assert_eq!(second_rest, 0);
        Ok::<_, Failure>(())
    }))??;
    Ok(())
}
