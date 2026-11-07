//! Actual TCP admission and generation reuse, no authenticated-node credit.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify original socket/session lifecycle"
)]
#[expect(
    dead_code,
    reason = "Shared test-only memory history contains the separate host Driver/Communicator adapters used by their own existing fixtures"
)]
#[path = "../../tcp-communicator-std/tests/support/history.rs"]
mod history;
use gnunet_crypto::{EddsaPrivateKey, Entropy};
use gnunet_service_runtime::{
    clock::{RuntimeClock, SystemClock},
    connection::Connection,
};
use gnunet_tcp_communicator_core::{
    registry::Slot,
    session::{
        Buffers, CIPHERTEXT_CAPACITY, CompletionSlot, Identity, KeyRing, Phase, Policy, Scope, Time,
    },
    wire,
};
use gnunet_tcp_communicator_host::history::{HistoryProgress, ReplayHistory, ReplayTask};
use gnunet_tcp_communicator_host::{Capacity, Clock, HostError, ManagerCapacity, OwnedFailure};
use gnunet_tcp_communicator_runtime::{NativeConnect, Pool, PoolProgress, Setup};
use gnunet_types::Error;
use std::{
    error::Error as StdError,
    future::{Future, poll_fn},
    num::NonZeroUsize,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, UnixStream},
};
type Failure = Box<dyn StdError>;
struct Random(u8);
impl Entropy for Random {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        self.0 = self.0.wrapping_add(1);
        out.fill(self.0);
        Ok(())
    }
}
struct TimePort(u64, history::MemoryHistory);
impl Clock for TimePort {
    fn read(&mut self) -> Result<Time, Error> {
        let now = SystemClock.sample()?.now.as_micros();
        self.0 = now.max(self.0.checked_add(1).ok_or(Error::Overflow)?);
        Ok(Time {
            now,
            signed: self.0,
        })
    }
    fn revision(&self) -> u64 {
        0
    }
    fn poll_change(&mut self, _: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }
}
impl ReplayHistory for TimePort {
    fn local_floor(&mut self, t: &ReplayTask) -> Result<Option<u64>, Error> {
        self.1.local_floor(t)
    }
    fn poll_store(
        &mut self,
        cx: &mut Context<'_>,
        t: &ReplayTask,
        value: u64,
    ) -> Poll<Result<(), Error>> {
        self.1.poll_store(cx, t, value)
    }
    fn store_admitted(&mut self, t: &ReplayTask, value: u64) {
        self.1.store_admitted(t, value)
    }
    fn retire_history(&mut self, t: &ReplayTask) -> Result<(), Error> {
        self.1.retire_history(t)
    }
    fn poll_history(&mut self, cx: &mut Context<'_>) -> Poll<Result<HistoryProgress, Error>> {
        self.1.poll_history(cx)
    }
}
struct Storage {
    rx: Vec<u8>,
    tx: Vec<u8>,
    plain: Vec<u8>,
    completions: Vec<CompletionSlot>,
}
impl Storage {
    fn new() -> Self {
        Self {
            rx: vec![0; wire::MAX_RECORD],
            tx: vec![0; CIPHERTEXT_CAPACITY],
            plain: vec![0; wire::MAX_RECORD],
            completions: (0..8).map(|_| CompletionSlot::default()).collect(),
        }
    }
    fn buffers(&mut self) -> Buffers<'_> {
        Buffers {
            receive: &mut self.rx,
            transmit: &mut self.tx,
            plaintext: &mut self.plain,
            completions: &mut self.completions,
        }
    }
}
fn ipc() -> Result<(Connection, UnixStream), Failure> {
    let (a, b) = UnixStream::pair()?;
    Ok((Connection::from_unix(a), b))
}
async fn step(
    pool: &mut Pool<'_>,
    clock: &mut TimePort,
    rng: &mut Random,
) -> Result<Option<PoolProgress>, OwnedFailure> {
    let mut future = Box::pin(poll_fn(|cx| pool.poll_drive(cx, clock, rng)));
    let mut cx = Context::from_waker(Waker::noop());
    let r = future.as_mut().poll(&mut cx);
    drop(future);
    tokio::time::sleep(Duration::from_millis(1)).await;
    match r {
        Poll::Ready(r) => r.map(Some),
        Poll::Pending => Ok(None),
    }
}
#[tokio::test(flavor = "current_thread")]
async fn actual_connect_is_started_before_the_future_is_polled_and_original_bytes_roundtrip()
-> Result<(), Failure> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let pending = NativeConnect::begin(listener.local_addr()?)?;
    let (mut remote, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept()).await??;
    // Actual peer accept precedes the first poll of the retained connect future.
    let mut client = pending.into_future().await?;
    client.write_all(b"original").await?;
    let mut bytes = [0; 8];
    remote.read_exact(&mut bytes).await?;
    assert_eq!(&bytes, b"original");
    remote.write_all(b"reply").await?;
    let mut answer = [0; 5];
    client.read_exact(&mut answer).await?;
    assert_eq!(&answer, b"reply");
    drop(client);
    assert_eq!(remote.read(&mut bytes).await?, 0);
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn fixed_one_slot_recycles_128_actual_native_generations_with_new_future_single_poll_drop()
-> Result<(), Failure> {
    let keys = KeyRing::from_seed([1; 32]);
    let identity = Identity::from_keys(&keys);
    let target = EddsaPrivateKey::from_seed([2; 32]).public_key();
    let mut storage = [Storage::new()];
    let mut scope = Scope::new();
    let mut slots = [Slot::new(), Slot::new()];
    let (ps, _ps_peer) = ipc()?;
    let (tr, _tr_peer) = ipc()?;
    let mut pool = Pool::new(Setup {
        services: [ps, tr],
        identity,
        scope: &mut scope,
        slots: &mut slots,
        buffers: storage.iter_mut().map(Storage::buffers).collect(),
        policy: Policy::reference(NonZeroUsize::new(128).ok_or(Error::InvalidInput)?),
        ipc: Capacity {
            ipc_bytes: 1024 * 1024,
            ipc_frames: 128,
            callbacks: 8,
        },
        capacity: ManagerCapacity {
            sessions: 1,
            pending_sends: 8,
            commands: 8,
        },
        disable_v6: false,
    })?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = format!("tcp-{}", listener.local_addr()?);
    let mut clock = TimePort(0, history::MemoryHistory::new()?);
    let mut rng = Random(0);
    let mut old = None;
    let mut retired = 0;
    for _ in 0..128 {
        let id = pool.outbound(target, address.as_bytes(), clock.read()?, &mut rng)?;
        if let Some(previous) = &old {
            assert_ne!(previous, &id);
            assert!(pool.core(previous).is_err());
        }
        let (remote, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept()).await??;
        drop(remote);
        let end = Instant::now() + Duration::from_secs(3);
        while !pool.is_empty() {
            assert!(Instant::now() < end);
            match step(&mut pool, &mut clock, &mut rng).await {
                Ok(Some(PoolProgress::Retired(original))) => {
                    assert_eq!(original, id);
                    retired += 1;
                }
                Ok(_) => {}
                Err(original) => {
                    assert_eq!(original.session.as_ref(), Some(&id));
                    assert!(matches!(original.cause, HostError::Peer(_)));
                }
            }
        }
        assert_eq!(pool.available(), 1);
        assert!(pool.core(&id).is_err());
        old = Some(id);
    }
    assert_eq!(retired, 128);
    assert!(pool.is_quiescent());
    assert!(!pool.history_recovery_required());
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn actual_peer_reset_returns_original_failure_token_and_keeps_other_native_session()
-> Result<(), Failure> {
    let keys = KeyRing::from_seed([1; 32]);
    let target = EddsaPrivateKey::from_seed([2; 32]).public_key();
    let mut backing = [Storage::new(), Storage::new()];
    let mut scope = Scope::new();
    let mut slots = [Slot::new(), Slot::new(), Slot::new(), Slot::new()];
    let (ps, _ps_peer) = ipc()?;
    let (tr, _tr_peer) = ipc()?;
    let mut pool = Pool::new(Setup {
        services: [ps, tr],
        identity: Identity::from_keys(&keys),
        scope: &mut scope,
        slots: &mut slots,
        buffers: backing.iter_mut().map(Storage::buffers).collect(),
        policy: Policy::reference(NonZeroUsize::new(128).ok_or(Error::InvalidInput)?),
        ipc: Capacity {
            ipc_bytes: 1024 * 1024,
            ipc_frames: 128,
            callbacks: 8,
        },
        capacity: ManagerCapacity {
            sessions: 2,
            pending_sends: 8,
            commands: 8,
        },
        disable_v6: false,
    })?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = format!("tcp-{}", listener.local_addr()?);
    let mut clock = TimePort(0, history::MemoryHistory::new()?);
    let mut rng = Random(0);
    let bad = pool.outbound(target, address.as_bytes(), clock.read()?, &mut rng)?;
    let (remote, _) = listener.accept().await?;
    socket2::SockRef::from(&remote).set_linger(Some(Duration::ZERO))?;
    drop(remote);
    let other = EddsaPrivateKey::from_seed([3; 32]).public_key();
    let good = pool.outbound(other, address.as_bytes(), clock.read()?, &mut rng)?;
    let (healthy, _) = listener.accept().await?;
    let mut observed = false;
    let end = Instant::now() + Duration::from_secs(3);
    while pool.len() != 1 || !observed {
        assert!(Instant::now() < end);
        match step(&mut pool, &mut clock, &mut rng).await {
            Err(original) => {
                assert_eq!(original.session.as_ref(), Some(&bad));
                assert!(matches!(original.cause, HostError::Peer(_)));
                observed = true;
            }
            Ok(Some(PoolProgress::Retired(id))) => assert_eq!(id, bad),
            Ok(_) => {}
        }
    }
    assert!(pool.core(&bad).is_err());
    assert_eq!(pool.available(), 1);
    assert_eq!(pool.core(&good)?.phase(), Phase::Initial);
    drop(healthy);
    let end = Instant::now() + Duration::from_secs(3);
    while !pool.is_empty() {
        assert!(Instant::now() < end);
        match step(&mut pool, &mut clock, &mut rng).await {
            Ok(_) => {}
            Err(original) => assert_eq!(original.session.as_ref(), Some(&good)),
        }
    }
    assert!(pool.is_quiescent());
    assert_eq!(pool.available(), 2);
    Ok(())
}

#[derive(Clone)]
struct Canonical(std::sync::Arc<CanonicalState>);
struct CanonicalState {
    refused: std::sync::atomic::AtomicBool,
    subscriptions: std::sync::atomic::AtomicUsize,
}
struct Subscription(Canonical);
impl Drop for Subscription {
    fn drop(&mut self) {
        self.0
            .0
            .subscriptions
            .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}
impl gnunet_service_runtime::clock::ClockSubscription for Subscription {
    fn poll_changed(
        &mut self,
        _: &mut Context<'_>,
        _: u64,
    ) -> Poll<Result<gnunet_service_runtime::clock::ClockSample, Error>> {
        if self.0.0.refused.load(std::sync::atomic::Ordering::SeqCst) {
            Poll::Ready(Err(Error::TimeUncertain))
        } else {
            Poll::Pending
        }
    }
}
impl RuntimeClock for Canonical {
    fn sample(&self) -> Result<gnunet_service_runtime::clock::ClockSample, Error> {
        if self.0.refused.load(std::sync::atomic::Ordering::SeqCst) {
            Err(Error::TimeUncertain)
        } else {
            SystemClock.sample()
        }
    }
    fn subscribe(
        &self,
    ) -> Result<Box<dyn gnunet_service_runtime::clock::ClockSubscription>, Error> {
        self.sample()?;
        self.0
            .subscriptions
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Box::new(Subscription(self.clone())))
    }
}
struct Scratch(std::path::PathBuf);
impl Scratch {
    fn new() -> Result<Self, Failure> {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce)?;
        let label: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let p = std::env::temp_dir().join(format!("tcp-native-{label}"));
        {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new().mode(0o700).create(&p)?;
        }
        Ok(Self(p))
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}
#[derive(Debug)]
struct PairFailure {
    original: Failure,
    cleanup: Option<gnunet_tcp_communicator_runtime::replay::Shutdown>,
}
impl std::fmt::Display for PairFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "controlled public V2 pairing: {}; cleanup={:?}",
            self.original, self.cleanup
        )
    }
}
impl StdError for PairFailure {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&*self.original)
    }
}
#[derive(Debug)]
struct LedgerCause(std::sync::Arc<gnunet_tcp_communicator_runtime::replay::Failure>);
impl std::fmt::Display for LedgerCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}
impl StdError for LedgerCause {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&*self.0)
    }
}
#[derive(Debug)]
struct JoinFailure(gnunet_tcp_communicator_runtime::process_ports::Shutdown);
impl std::fmt::Display for JoinFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "controlled public V2 join: {:?}", self.0)
    }
}
impl StdError for JoinFailure {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.0
            .ledger
            .original
            .as_ref()
            .map(|e| &**e as &dyn StdError)
    }
}
async fn paired(
    mut clock: gnunet_tcp_communicator_runtime::clock::ClockPort,
    path: &std::path::Path,
    peer: gnunet_crypto::EddsaPublicKey,
) -> Result<gnunet_tcp_communicator_runtime::process_ports::ProcessPorts, Failure> {
    use gnunet_tcp_communicator_runtime::{
        process_ports::{ProcessPorts, Resources},
        replay::{self, Ledger},
    };
    let directory = path.with_extension("ledger");
    clock.prepare_replay(peer, &directory)?;
    let mut ledger = match Ledger::open(&directory, peer, replay::Limits { records: 32 }, path) {
        Ok(ledger) => ledger,
        Err(mut rejected) => {
            let cleanup = match rejected.owner.take() {
                Some(mut original) => Some(original.shutdown(|_| {}).await),
                None => None,
            };
            return Err(Box::new(PairFailure {
                original: Box::new(rejected.error),
                cleanup,
            }));
        }
    };
    let result: Result<(), Failure> = async {
        while ledger.pending().is_some() {
            if let replay::Progress::Failed { error, .. } = poll_fn(|cx| ledger.poll(cx)).await {
                return Err(Box::new(LedgerCause(error)) as Failure);
            }
        }
        let bound = ledger.catalog()?.is_bound();
        clock.attach_catalog(&ledger.catalog()?)?;
        if !bound {
            let token = ledger.bind_frontier(path)?;
            match poll_fn(|cx| ledger.poll(cx)).await {
                replay::Progress::Bound(actual) if actual == token => {}
                replay::Progress::Failed { error, .. } => {
                    return Err(Box::new(LedgerCause(error)) as Failure);
                }
                _ => return Err(Box::new(Error::Stale) as Failure),
            }
        }
        Ok(())
    }
    .await;
    if let Err(original) = result {
        return Err(Box::new(PairFailure {
            original,
            cleanup: Some(ledger.shutdown(|_| {}).await),
        }));
    }
    match ProcessPorts::adopt(
        Resources { clock, ledger },
        gnunet_tcp_communicator_core::session::REPLAY_CAPACITY,
    ) {
        Ok(ports) => Ok(ports),
        Err(rejected) => {
            let mut resources = *rejected.resources;
            let cleanup = resources.ledger.shutdown(|_| {}).await;
            Err(Box::new(PairFailure {
                original: Box::new(rejected.error),
                cleanup: Some(cleanup),
            }))
        }
    }
}
async fn join_public_clock(
    clock: &mut gnunet_tcp_communicator_runtime::process_ports::ProcessPorts,
) -> Result<(), Failure> {
    let cleanup = clock.shutdown(|_| {}).await;
    if cleanup.ledger.stopped.is_none()
        || cleanup.ledger.original.is_some()
        || cleanup.ledger.join.is_some()
        || cleanup.drain.is_some()
    {
        return Err(Box::new(JoinFailure(cleanup)));
    }
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn actual_clock_refusal_retires_original_socket_before_typed_clean_proof_without_fresh_time()
-> Result<(), Failure> {
    use gnunet_tcp_communicator_runtime::{clock::ClockPort, epoch};
    let d = Scratch::new()?;
    let path = d.0.join("frontier");
    let canonical = Canonical(std::sync::Arc::new(CanonicalState {
        refused: std::sync::atomic::AtomicBool::new(false),
        subscriptions: std::sync::atomic::AtomicUsize::new(0),
    }));
    let clock = ClockPort::new(std::sync::Arc::new(canonical.clone()), path.clone())?;
    let keys = KeyRing::from_seed([1; 32]);
    let target = EddsaPrivateKey::from_seed([2; 32]).public_key();
    let mut backing = [Storage::new()];
    let mut scope = Scope::new();
    let mut slots = [Slot::new(), Slot::new()];
    let (ps, mut ps_peer) = ipc()?;
    let (tr, mut tr_peer) = ipc()?;
    let mut pool = Pool::new(Setup {
        services: [ps, tr],
        identity: Identity::from_keys(&keys),
        scope: &mut scope,
        slots: &mut slots,
        buffers: backing.iter_mut().map(Storage::buffers).collect(),
        policy: Policy::reference(NonZeroUsize::new(128).ok_or(Error::InvalidInput)?),
        ipc: Capacity {
            ipc_bytes: 1024 * 1024,
            ipc_frames: 128,
            callbacks: 8,
        },
        capacity: ManagerCapacity {
            sessions: 1,
            pending_sends: 8,
            commands: 8,
        },
        disable_v6: false,
    })?;
    let mut clock = paired(clock, &path, Identity::from_keys(&keys).public()).await?;
    let token = clock.begin_epoch(Identity::from_keys(&keys).public())?;
    pool.bind_epoch(token).map_err(|r| r.reason)?;
    let actual = clock.read()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = format!("tcp-{}", listener.local_addr()?);
    let mut rng = Random(0);
    let id = pool.outbound(target, address.as_bytes(), actual, &mut rng)?;
    let (mut remote, _) = listener.accept().await?;
    canonical
        .0
        .refused
        .store(true, std::sync::atomic::Ordering::SeqCst);
    let original = poll_fn(|cx| pool.poll_drive(cx, &mut clock, &mut rng)).await;
    assert!(matches!(
        original,
        Err(OwnedFailure {
            session: None,
            cause: HostError::Core(Error::TimeUncertain)
        })
    ));
    let last = clock.last_time().ok_or(Error::NotFound)?;
    assert_eq!(last.signed, actual.signed);
    assert_eq!(
        canonical
            .0
            .subscriptions
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    assert!(matches!(
        clock.take_failure(),
        Some(gnunet_tcp_communicator_runtime::process_ports::Failures {
            clock: Some(gnunet_tcp_communicator_runtime::clock::Failure::Clock(
                Error::TimeUncertain
            )),
            ..
        })
    ));
    assert!(clock.read().is_err());
    pool.retire_epoch(last)?;
    pool = match pool.into_quiescent() {
        Err(rejected) => {
            assert_eq!(rejected.reason, Error::WouldBlock);
            rejected.value
        }
        Ok(_) => return Err("live original socket produced clean proof".into()),
    };
    let end = Instant::now() + Duration::from_secs(3);
    while !pool.is_empty() {
        assert!(Instant::now() < end);
        let mut future = Box::pin(poll_fn(|cx| {
            pool.poll_retire(cx, last, &mut clock, &mut rng)
        }));
        let mut cx = Context::from_waker(Waker::noop());
        if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
            match result? {
                PoolProgress::Retired(old) => assert_eq!(old, id),
                PoolProgress::Manager(_) => {}
            }
        }
        drop(future);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    let proof = pool.into_quiescent().map_err(|r| r.reason)?;
    let mut byte = [0; 1];
    assert_eq!(remote.read(&mut byte).await?, 0);
    let mut bytes = Vec::new();
    ps_peer.read_to_end(&mut bytes).await?;
    assert!(
        bytes.is_empty(),
        "this lifecycle emitted no backend operation or fabricated backend callback"
    );
    bytes.clear();
    tr_peer.read_to_end(&mut bytes).await?;
    join_public_clock(&mut clock).await?;
    clock.finish_epoch(proof).map_err(|r| r.error)?;
    assert_eq!(std::fs::read(&path)?[8], 0);
    clock.close();
    assert!(matches!(
        epoch::Store::open(path.clone()),
        Err(epoch::Failure {
            stage: epoch::Stage::Fence,
            ..
        })
    ));
    assert_eq!(
        canonical
            .0
            .subscriptions
            .load(std::sync::atomic::Ordering::SeqCst),
        0
    );
    drop(clock);
    assert_eq!(
        epoch::Store::open(path)?.loaded()?.map(|s| s.dirty),
        Some(false)
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn cached_timestamp_range_refuses_actual_writer_fence_path_replacement() -> Result<(), Failure>
{
    use gnunet_tcp_communicator_runtime::{clock::ClockPort, epoch};
    let d = Scratch::new()?;
    let path = d.0.join("frontier");
    let clock = ClockPort::new(std::sync::Arc::new(SystemClock), path.clone())?;
    let peer = EddsaPrivateKey::from_seed([1; 32]).public_key();
    let mut clock = paired(clock, &path, peer).await?;
    let epoch = clock.begin_epoch(peer)?;
    let first = clock.read()?;
    let guard = d.0.join("frontier.tcp-lock");
    std::fs::rename(&guard, d.0.join("original-lock"))?;
    std::fs::write(&guard, [])?;
    assert!(
        clock.read().is_err(),
        "cached reserved range must not bypass the original writer-fence authority check"
    );
    assert!(matches!(
        clock.take_failure(),
        Some(gnunet_tcp_communicator_runtime::process_ports::Failures {
            clock: Some(gnunet_tcp_communicator_runtime::clock::Failure::History(
                epoch::Failure {
                    stage: epoch::Stage::Fence,
                    outcome: epoch::Outcome::Unknown,
                    ..
                }
            )),
            ..
        })
    ));
    assert_eq!(clock.last_time().map(|t| t.signed), Some(first.signed));
    let mut replacement = epoch::Store::open(path)?;
    assert!(matches!(
        replacement.begin(peer),
        Err(epoch::Failure {
            stage: epoch::Stage::BackendQuarantine,
            ..
        })
    ));
    drop(epoch);
    join_public_clock(&mut clock).await?;
    clock.close();
    Ok(())
}
