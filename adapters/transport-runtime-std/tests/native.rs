//! Actual Unix/crypto/clock/fence and original asynchronous signing lifecycles.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify independent lifecycle and signature boundaries"
)]
use gnunet_client_host::{
    EndpointSource,
    resolution::{AddressLookup, ResolutionContext, ResolutionTimer},
};
use gnunet_crypto::{EddsaPublicKey, EddsaSignature};
use gnunet_pils::{MasterKey, Profile, Service};
use gnunet_service_runtime::{
    clock::{self, ClockSample, ClockSubscription, RuntimeClock, SystemClock},
    service::Listener,
};
use gnunet_transport::{
    PeerId,
    p2p::{Challenge, Validation},
};
use gnunet_transport_host::peerstore::Journal;
use gnunet_transport_runtime::{
    Limits, LocalKeyCapability, LocalPorts, Policies, Progress, Runtime, ServicePorts,
};
use gnunet_types::Error;
use std::{
    error::Error as StdError,
    future::Future,
    io,
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
};
type Failure = Box<dyn StdError>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Failure> {
        use std::os::unix::fs::DirBuilderExt;
        let p = std::env::temp_dir().join(format!(
            "gn-trf-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&p)?;
        Ok(Self(p))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}
struct Slot {
    active: bool,
    waker: Option<Waker>,
}
struct Tracking {
    refused: AtomicBool,
    subscriptions: AtomicU64,
    slots: Mutex<Vec<Slot>>,
}
#[derive(Clone)]
struct Clock(Arc<Tracking>);
impl Clock {
    fn new() -> Self {
        Self(Arc::new(Tracking {
            refused: AtomicBool::new(false),
            subscriptions: AtomicU64::new(0),
            slots: Mutex::new(
                (0..64)
                    .map(|_| Slot {
                        active: false,
                        waker: None,
                    })
                    .collect(),
            ),
        }))
    }
    fn active(&self) -> usize {
        self.0
            .slots
            .lock()
            .map_or(0, |s| s.iter().filter(|s| s.active).count())
    }
    fn refuse(&self, value: bool) {
        self.0.refused.store(value, Ordering::SeqCst);
        if let Ok(slots) = self.0.slots.lock() {
            for s in slots.iter() {
                if let Some(w) = &s.waker {
                    w.wake_by_ref();
                }
            }
        }
    }
}
struct Subscription {
    clock: Clock,
    index: usize,
}
impl Drop for Subscription {
    fn drop(&mut self) {
        if let Ok(mut slots) = self.clock.0.slots.lock() {
            slots[self.index] = Slot {
                active: false,
                waker: None,
            };
        }
    }
}
impl ClockSubscription for Subscription {
    fn poll_changed(&mut self, cx: &mut Context<'_>, _: u64) -> Poll<Result<ClockSample, Error>> {
        if self.clock.0.refused.load(Ordering::SeqCst) {
            return Poll::Ready(Err(Error::TimeUncertain));
        }
        match self.clock.0.slots.lock() {
            Ok(mut slots) => {
                slots[self.index].waker = Some(cx.waker().clone());
                Poll::Pending
            }
            Err(_) => Poll::Ready(Err(Error::TimeUncertain)),
        }
    }
}
impl RuntimeClock for Clock {
    fn sample(&self) -> Result<ClockSample, Error> {
        if self.0.refused.load(Ordering::SeqCst) {
            Err(Error::TimeUncertain)
        } else {
            SystemClock.sample()
        }
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
        self.sample()?;
        self.0.subscriptions.fetch_add(1, Ordering::SeqCst);
        let mut slots = self.0.slots.lock().map_err(|_| Error::TimeUncertain)?;
        let index = slots
            .iter()
            .position(|s| !s.active)
            .ok_or(Error::Capacity)?;
        slots[index].active = true;
        Ok(Box::new(Subscription {
            clock: self.clone(),
            index,
        }))
    }
}
struct UnixPorts(Arc<dyn RuntimeClock>);
impl ResolutionContext for UnixPorts {
    fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.0.clone()
    }
    fn lookup(&self, _: &[u8], _: Duration) -> io::Result<Option<Box<dyn AddressLookup>>> {
        Err(io::Error::other("unexpected lookup on Unix-only context"))
    }
    fn timer(&self, delay: Duration) -> io::Result<ResolutionTimer> {
        let timer = clock::Deadline::after(self.0.clone(), delay).map_err(io::Error::other)?;
        Ok(Box::pin(
            async move { timer.await.map_err(io::Error::other) },
        ))
    }
}
fn source(path: &Path, clock: Arc<dyn RuntimeClock>) -> Result<EndpointSource, Failure> {
    use std::os::unix::ffi::OsStrExt;
    let mut cfg = gnunet_config::Configuration::default();
    cfg.set_value(b"service", b"UNIXPATH", Some(path.as_os_str().as_bytes()))?;
    Ok(EndpointSource::configuration(
        cfg,
        b"service",
        Arc::new(UnixPorts(clock)),
    ))
}
fn seed(path: &Path, value: u8) -> Result<(), Failure> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, [value; 32])?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}
fn hello() -> gnunet_pils::HelloLimits {
    gnunet_pils::HelloLimits {
        maximum_input_bytes: 65535,
        maximum_address_bytes: 4096,
        maximum_addresses: 64,
    }
}
fn pils(path: &Path, value: u8) -> Result<gnunet_pils_host::Host<4096>, Failure> {
    let listener = std::os::unix::net::UnixListener::bind(path)?;
    let service = Service::new(
        MasterKey::from_seed([value; 32]),
        Profile::Reference029,
        SystemClock.sample()?.now.as_micros(),
        hello(),
    )?;
    Ok(gnunet_pils_host::Host::new(
        listener,
        service,
        gnunet_pils_host::Limits {
            clients: 16,
            receive_bytes: 65535,
            transmit_bytes: 1024 * 1024,
            accepts_per_step: 4,
            address_bytes: 4096,
        },
    )?)
}
async fn step<'a>(
    runtime: &mut Runtime<'a>,
    pils: &mut gnunet_pils_host::Host<4096>,
    tr: &UnixListener,
    ps: &UnixListener,
) -> Result<Option<Progress<'a>>, Failure> {
    pils.poll_once(SystemClock.sample()?.now.as_micros())?;
    let tr = [Listener::Unix(tr)];
    let ps = [Listener::Unix(ps)];
    let mut observe = |_| {};
    let mut driving = Box::pin(runtime.drive(&tr, &ps, &mut observe));
    let mut cx = Context::from_waker(Waker::noop());
    let result = driving.as_mut().poll(&mut cx);
    drop(driving);
    tokio::task::yield_now().await;
    match result {
        Poll::Ready(r) => Ok(Some(r?)),
        Poll::Pending => Ok(None),
    }
}
async fn activated(
    runtime: &mut Runtime<'_>,
    pils: &mut gnunet_pils_host::Host<4096>,
    tr: &UnixListener,
    ps: &UnixListener,
) -> Result<[u8; 32], Failure> {
    let until = Instant::now() + Duration::from_secs(5);
    while Instant::now() < until {
        if let Some(Progress::Activated(peer)) = step(runtime, pils, tr, ps).await? {
            return Ok(peer);
        }
    }
    Err("actual activation timeout".into())
}
#[tokio::test(flavor = "current_thread")]
async fn profile_conditional_service_and_local_capability_adopt_actual_nonempty_announcement()
-> Result<(), Failure> {
    for local in [false, true] {
        let d = Directory::new()?;
        let pp = d.0.join("pils-profile");
        let profile = Profile::configured(Some(b"deterministic"), None)?;
        let now = SystemClock.sample()?.now.as_micros();
        let mut service =
            Service::<4096>::new(MasterKey::from_seed([17; 32]), profile, now, hello())?;
        // A nonempty genuine FEED makes the conditional announcement reject the
        // default029 verification path and requires the same address hash for
        // local private-root matching. No synthetic 1831 is supplied.
        let mut storage = [0; 256];
        let mut builder = gnunet_hello::HelloBuilder::new(&mut storage, hello());
        builder.add_address(b"tcp://127.0.0.1:77")?;
        let unsigned = builder.with_signature(
            EddsaPublicKey::from_bytes([0; 32]),
            EddsaSignature::from_bytes([0; 64]),
            gnunet_hello::AbsoluteTime::NEVER,
        );
        let mut block = vec![0; unsigned.block_len()?];
        unsigned.encode_block(&mut block)?;
        let mut feed = vec![0; 8 + block.len()];
        gnunet_wire::official::pils::Request::Feed { block: &block }.encode(&mut feed)?;
        let action = service.receive(&feed, &mut [0; 4096], now, &mut [])?;
        assert!(matches!(
            action,
            gnunet_pils::Action::Broadcast {
                identity_changed: true
            }
        ));
        let peer = *service.identity().public_key().as_bytes();
        let mut service = gnunet_pils_host::Host::new(
            std::os::unix::net::UnixListener::bind(&pp)?,
            service,
            gnunet_pils_host::Limits {
                clients: 16,
                receive_bytes: 65535,
                transmit_bytes: 1024 * 1024,
                accepts_per_step: 4,
                address_bytes: 4096,
            },
        )?;
        let tr = UnixListener::bind(d.0.join("tr"))?;
        let ps = UnixListener::bind(d.0.join("ps"))?;
        let clock: Arc<dyn RuntimeClock> = Arc::new(Clock::new());
        let ports = ServicePorts {
            pils: source(&pp, clock.clone())?,
            clock,
            journal: Journal::open_with_profiles(
                d.0.join("journal"),
                gnunet_transport_host::peerstore::HelloProfiles {
                    managed: profile.hello(),
                    discovery: profile.hello(),
                },
            )?,
        };
        let limits = Limits {
            pils_profile: profile,
            discovery_hello_profile: profile.hello(),
            ..Limits::default()
        };
        let mut instance = gnunet_pils::client::Instance::new();
        let mut runtime = if local {
            let key = d.0.join("seed");
            seed(&key, 17)?;
            Runtime::new_local(
                &mut instance,
                LocalPorts {
                    pils: ports.pils,
                    clock: ports.clock,
                    journal: ports.journal,
                    capability: LocalKeyCapability { ikm_file: key },
                },
                limits,
                Policies::default(),
            )?
        } else {
            Runtime::new_service(&mut instance, ports, limits, Policies::default())?
        };
        assert_eq!(activated(&mut runtime, &mut service, &tr, &ps).await?, peer);
        assert_eq!(runtime.report().local_key_mismatches, 0);
        assert_eq!(runtime.report().activations, 1);
        runtime.close()?;
    }
    Ok(())
}
fn frame(kind: u16, size: usize) -> Vec<u8> {
    let mut v = vec![0; size];
    v[..2].copy_from_slice(&(size as u16).to_be_bytes());
    v[2..4].copy_from_slice(&kind.to_be_bytes());
    v
}
#[derive(Default)]
struct Reader {
    pending: Vec<u8>,
    observed: Vec<Vec<u8>>,
}
impl Reader {
    async fn message(
        &mut self,
        runtime: &mut Runtime<'_>,
        pils: &mut gnunet_pils_host::Host<4096>,
        tr: &UnixListener,
        ps: &UnixListener,
        stream: &mut UnixStream,
        inner: u16,
    ) -> Result<Vec<u8>, Failure> {
        let until = Instant::now() + Duration::from_secs(3);
        while Instant::now() < until {
            if self.pending.len() >= 4 {
                let n = usize::from(u16::from_be_bytes([self.pending[0], self.pending[1]]));
                if n < 4 {
                    return Err("invalid actual frame size".into());
                }
                if self.pending.len() >= n {
                    let frame: Vec<_> = self.pending.drain(..n).collect();
                    self.observed.push(frame.clone());
                    if frame.len() >= 52
                        && frame[2..4] == 1209_u16.to_be_bytes()
                        && frame[50..52] == inner.to_be_bytes()
                    {
                        return Ok(frame);
                    }
                    continue;
                }
            }
            let _progress = step(runtime, pils, tr, ps).await?;
            let mut bytes = [0; 8192];
            match stream.try_read(&mut bytes) {
                Ok(0) => return Err("unexpected actual EOF".into()),
                Ok(n) => self.pending.extend_from_slice(&bytes[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Err(e.into()),
            }
            if self.pending.len() > 1024 * 1024 {
                return Err("observer storage budget".into());
            }
        }
        Err("actual frame timeout".into())
    }
}
#[tokio::test(flavor = "current_thread")]
async fn verified_original_signing_and_same_key_address_update_keep_original_client()
-> Result<(), Failure> {
    let d = Directory::new()?;
    let pp = d.0.join("pils");
    let key = d.0.join("seed");
    seed(&key, 17)?;
    let mut service = pils(&pp, 17)?;
    let tr = UnixListener::bind(d.0.join("tr"))?;
    let ps = UnixListener::bind(d.0.join("ps"))?;
    let clock: Arc<dyn RuntimeClock> = Arc::new(Clock::new());
    let mut instance = gnunet_pils::client::Instance::new();
    let mut runtime = Runtime::new_local(
        &mut instance,
        LocalPorts {
            pils: source(&pp, clock.clone())?,
            capability: LocalKeyCapability { ikm_file: key },
            clock,
            journal: Journal::open(d.0.join("journal"))?,
        },
        Limits::default(),
        Policies::default(),
    )?;
    let peer = activated(&mut runtime, &mut service, &tr, &ps).await?;
    assert_eq!(peer, *service.service().identity().public_key().as_bytes());
    let mut comm = UnixStream::connect(d.0.join("tr")).await?;
    let mut registration = frame(1211, 16);
    registration[4..8].copy_from_slice(&1_u32.to_be_bytes());
    registration[12..].copy_from_slice(b"tcp\0");
    comm.write_all(&registration).await?;
    let remote = PeerId([9; 32]);
    let mut queue = frame(1204, 74);
    queue[4..8].copy_from_slice(&1_u32.to_be_bytes());
    queue[8..40].copy_from_slice(&remote.0);
    queue[44..48].copy_from_slice(&u32::MAX.to_be_bytes());
    queue[48..56].copy_from_slice(&u64::MAX.to_be_bytes());
    queue[64..].copy_from_slice(b"tcp-local\0");
    comm.write_all(&queue).await?;
    let mut reader = Reader::default();
    let challenge = reader
        .message(&mut runtime, &mut service, &tr, &ps, &mut comm, 1303)
        .await?;
    assert_eq!(&challenge[2..4], &1209_u16.to_be_bytes());
    let input = Challenge {
        nonce: [42; 32],
        origin: SystemClock.sample()?.now.as_micros(),
    };
    let mut incoming = frame(1202, 136);
    incoming[16..24].copy_from_slice(&1_000_000_u64.to_be_bytes());
    incoming[24..56].copy_from_slice(&remote.0);
    incoming[88..].copy_from_slice(&input.encode());
    comm.write_all(&incoming).await?;
    let response = reader
        .message(&mut runtime, &mut service, &tr, &ps, &mut comm, 1304)
        .await?;
    let value = Validation::decode(&response[48..])?;
    assert_eq!(value.nonce, input.nonce);
    assert_eq!(value.origin, input.origin);
    EddsaPublicKey::from_bytes(peer).verify(
        35,
        &Validation::signed_region(&input.nonce, value.validity),
        &EddsaSignature::from_bytes(value.signature),
    )?;
    assert_eq!(runtime.report().validation_signatures, 1);
    // An actual official unsigned FEED makes the live service broadcast a freshly
    // signed announcement. Reference029 keeps this same key for address changes.
    let mut feeder = UnixStream::connect(&pp).await?;
    let mut storage = [0; 256];
    let mut builder = gnunet_hello::HelloBuilder::new(&mut storage, hello());
    builder.add_address(b"tcp://127.0.0.1:77")?;
    let h = builder.with_signature(
        EddsaPublicKey::from_bytes([0; 32]),
        EddsaSignature::from_bytes([0; 64]),
        gnunet_hello::AbsoluteTime::NEVER,
    );
    let mut block = vec![0; h.block_len()?];
    h.encode_block(&mut block)?;
    let mut feed = vec![0; 8 + block.len()];
    gnunet_wire::official::pils::Request::Feed { block: &block }.encode(&mut feed)?;
    feeder.write_all(&feed).await?;
    for _ in 0..80 {
        let _progress = step(&mut runtime, &mut service, &tr, &ps).await?;
    }
    assert_eq!(runtime.report().activations, 1);
    assert_eq!(runtime.report().retirements, 0);
    assert_eq!(runtime.identity(), Some(peer));
    let mut bytes = [0; 8192];
    match comm.try_read(&mut bytes) {
        Ok(n) => {
            assert_ne!(n, 0);
            reader.pending.extend_from_slice(&bytes[..n]);
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(error) => return Err(error.into()),
    }
    runtime.close()?;
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn actual_pils_eof_retires_old_mq_before_verified_replacement_on_same_runtime()
-> Result<(), Failure> {
    let d = Directory::new()?;
    let pp = d.0.join("pils");
    let key = d.0.join("seed");
    seed(&key, 17)?;
    let mut service = pils(&pp, 17)?;
    let tr = UnixListener::bind(d.0.join("tr"))?;
    let ps = UnixListener::bind(d.0.join("ps"))?;
    let clock: Arc<dyn RuntimeClock> = Arc::new(Clock::new());
    let mut instance = gnunet_pils::client::Instance::new();
    let mut limits = Limits::default();
    limits.pils.io_slice_bytes = 1;
    let mut runtime = Runtime::new_local(
        &mut instance,
        LocalPorts {
            pils: source(&pp, clock.clone())?,
            capability: LocalKeyCapability {
                ikm_file: key.clone(),
            },
            clock,
            journal: Journal::open(d.0.join("journal"))?,
        },
        limits,
        Policies::default(),
    )?;
    let old = activated(&mut runtime, &mut service, &tr, &ps).await?;
    let mut app = UnixStream::connect(d.0.join("tr")).await?;
    let mut hint = frame(1302, 49);
    hint[8..40].copy_from_slice(&[9; 32]);
    hint[40..].copy_from_slice(b"none-uri\0");
    app.write_all(&hint).await?;
    for _ in 0..20 {
        let _progress = step(&mut runtime, &mut service, &tr, &ps).await?;
    }
    assert_eq!(runtime.report().transport_connections, 1);
    drop(service);
    std::fs::remove_file(&pp)?;
    seed(&key, 18)?;
    let mut replacement = pils(&pp, 18)?;
    let until = Instant::now() + Duration::from_secs(5);
    let mut lost = false;
    let mut retired = false;
    let mut new = None;
    while Instant::now() < until && new.is_none() {
        if let Some(progress) = step(&mut runtime, &mut replacement, &tr, &ps).await? {
            match progress {
                Progress::Retired => {
                    retired = true;
                    let mut b = [0; 1];
                    assert_eq!(app.read(&mut b).await?, 0);
                }
                Progress::Pils(gnunet_pils_host::client::Progress::Lost { .. }) => lost = true,
                Progress::Activated(peer) => {
                    assert!(retired && lost);
                    new = Some(peer);
                }
                _ => {}
            }
        }
    }
    let new = new.ok_or("replacement activation timeout")?;
    assert_ne!(old, new);
    assert_eq!(
        new,
        *replacement.service().identity().public_key().as_bytes()
    );
    assert_eq!(runtime.report().activations, 2);
    assert_eq!(runtime.report().retirements, 1);
    runtime.close()?;
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn actual_clock_refusal_closes_once_without_resubscription_and_retains_writer_fence_until_drop()
-> Result<(), Failure> {
    let d = Directory::new()?;
    let pp = d.0.join("pils");
    let key = d.0.join("seed");
    seed(&key, 17)?;
    let mut service = pils(&pp, 17)?;
    let tr = UnixListener::bind(d.0.join("tr"))?;
    let ps = UnixListener::bind(d.0.join("ps"))?;
    let tracker = Clock::new();
    let clock: Arc<dyn RuntimeClock> = Arc::new(tracker.clone());
    let mut instance = gnunet_pils::client::Instance::new();
    let journal = d.0.join("journal");
    let mut runtime = Runtime::new_local(
        &mut instance,
        LocalPorts {
            pils: source(&pp, clock.clone())?,
            capability: LocalKeyCapability { ikm_file: key },
            clock,
            journal: Journal::open(&journal)?,
        },
        Limits::default(),
        Policies::default(),
    )?;
    activated(&mut runtime, &mut service, &tr, &ps).await?;
    assert!(tracker.active() >= 2);
    tracker.refuse(true);
    let trl = [Listener::Unix(&tr)];
    let psl = [Listener::Unix(&ps)];
    let mut observe = |_| {};
    let error = runtime.drive(&trl, &psl, &mut observe).await;
    assert!(matches!(
        error,
        Err(gnunet_transport_runtime::Error::Protocol(
            Error::TimeUncertain
        ))
    ));
    assert_eq!(runtime.identity(), None);
    assert_eq!(tracker.active(), 0);
    assert!(Journal::open(&journal).is_err());
    tracker.refuse(false);
    assert!(matches!(
        runtime.drive(&trl, &psl, &mut observe).await?,
        Progress::Closed
    ));
    assert_eq!(tracker.active(), 0);
    drop(runtime);
    let _next = Journal::open(&journal)?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn mismatched_local_capability_never_activates_before_actual_matching_ikm()
-> Result<(), Failure> {
    let d = Directory::new()?;
    let pp = d.0.join("pils");
    let key = d.0.join("seed");
    seed(&key, 17)?;
    let mut service = pils(&pp, 18)?;
    let tr = UnixListener::bind(d.0.join("tr"))?;
    let ps = UnixListener::bind(d.0.join("ps"))?;
    let clock: Arc<dyn RuntimeClock> = Arc::new(Clock::new());
    let mut instance = gnunet_pils::client::Instance::new();
    let mut runtime = Runtime::new_local(
        &mut instance,
        LocalPorts {
            pils: source(&pp, clock.clone())?,
            capability: LocalKeyCapability {
                ikm_file: key.clone(),
            },
            clock,
            journal: Journal::open(d.0.join("journal"))?,
        },
        Limits::default(),
        Policies::default(),
    )?;
    let until = Instant::now() + Duration::from_secs(3);
    while runtime.report().local_key_mismatches == 0 && Instant::now() < until {
        let _progress = step(&mut runtime, &mut service, &tr, &ps).await?;
    }
    assert!(runtime.report().local_key_mismatches > 0);
    assert_eq!(runtime.identity(), None);
    assert_eq!(runtime.report().activations, 0);
    assert_eq!(runtime.report().validation_signatures, 0);
    seed(&key, 18)?;
    let verified = activated(&mut runtime, &mut service, &tr, &ps).await?;
    assert_eq!(
        verified,
        *service.service().identity().public_key().as_bytes()
    );
    assert_eq!(runtime.report().activations, 1);
    runtime.close()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn real_backend_path_loss_closes_original_clients_without_input_or_epoch_replay()
-> Result<(), Failure> {
    let d = Directory::new()?;
    let pp = d.0.join("pils");
    let key = d.0.join("seed");
    seed(&key, 17)?;
    let mut service = pils(&pp, 17)?;
    let tr = UnixListener::bind(d.0.join("tr"))?;
    let ps = UnixListener::bind(d.0.join("ps"))?;
    let state = d.0.join("state");
    std::fs::create_dir(&state)?;
    let path = state.join("journal");
    let clock: Arc<dyn RuntimeClock> = Arc::new(Clock::new());
    let mut instance = gnunet_pils::client::Instance::new();
    let mut runtime = Runtime::new_local(
        &mut instance,
        LocalPorts {
            pils: source(&pp, clock.clone())?,
            capability: LocalKeyCapability { ikm_file: key },
            clock,
            journal: Journal::open(&path)?,
        },
        Limits::default(),
        Policies::default(),
    )?;
    activated(&mut runtime, &mut service, &tr, &ps).await?;
    let mut app = UnixStream::connect(d.0.join("tr")).await?;
    let mut hint = frame(1302, 49);
    hint[8..40].copy_from_slice(&[9; 32]);
    hint[40..].copy_from_slice(b"none-uri\0");
    app.write_all(&hint).await?;
    for _ in 0..30 {
        let _progress = step(&mut runtime, &mut service, &tr, &ps).await?;
    }
    assert_eq!(runtime.report().transport_connections, 1);
    let old = d.0.join("original-state");
    std::fs::rename(&state, &old)?;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let trl = [Listener::Unix(&tr)];
    let psl = [Listener::Unix(&ps)];
    let mut observe = |_| {};
    let until = Instant::now() + Duration::from_secs(2);
    let mut failed = false;
    while Instant::now() < until {
        match runtime.drive(&trl, &psl, &mut observe).await {
            Err(gnunet_transport_runtime::Error::Protocol(Error::Storage)) => {
                failed = true;
                break;
            }
            Err(other) => return Err(other.into()),
            Ok(_) => {}
        }
    }
    assert!(failed);
    assert_eq!(runtime.identity(), None);
    let mut b = [0; 1];
    assert_eq!(app.read(&mut b).await?, 0);
    assert_eq!(runtime.report().activations, 1);
    assert!(Journal::open(old.join("journal")).is_err());
    assert!(matches!(
        runtime.drive(&trl, &psl, &mut observe).await?,
        Progress::Closed
    ));
    drop(runtime);
    let _recovered = Journal::open(old.join("journal"))?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn actual_service_signing_uses_original_requests_without_any_local_ikm_and_keeps_same_key_client()
-> Result<(), Failure> {
    let d = Directory::new()?;
    let pp = d.0.join("pils");
    assert!(!d.0.join("seed").exists());
    let mut service = pils(&pp, 17)?;
    let tr = UnixListener::bind(d.0.join("tr"))?;
    let ps = UnixListener::bind(d.0.join("ps"))?;
    let clock: Arc<dyn RuntimeClock> = Arc::new(Clock::new());
    let mut instance = gnunet_pils::client::Instance::new();
    let mut runtime = Runtime::new_service(
        &mut instance,
        ServicePorts {
            pils: source(&pp, clock.clone())?,
            clock,
            journal: Journal::open(d.0.join("journal"))?,
        },
        Limits {
            pils: gnunet_pils_host::client::Limits {
                io_slice_bytes: 1,
                ..Default::default()
            },
            ..Limits::default()
        },
        Policies::default(),
    )?;
    let peer = activated(&mut runtime, &mut service, &tr, &ps).await?;
    assert_eq!(peer, *service.service().identity().public_key().as_bytes());
    let mut comm = UnixStream::connect(d.0.join("tr")).await?;
    let mut registration = frame(1211, 16);
    registration[4..8].copy_from_slice(&1_u32.to_be_bytes());
    registration[12..].copy_from_slice(b"tcp\0");
    comm.write_all(&registration).await?;
    let remote = PeerId([9; 32]);
    let mut queue = frame(1204, 74);
    queue[4..8].copy_from_slice(&1_u32.to_be_bytes());
    queue[8..40].copy_from_slice(&remote.0);
    queue[44..48].copy_from_slice(&u32::MAX.to_be_bytes());
    queue[48..56].copy_from_slice(&u64::MAX.to_be_bytes());
    queue[64..].copy_from_slice(b"tcp-local\0");
    comm.write_all(&queue).await?;
    let mut reader = Reader::default();
    let challenge = reader
        .message(&mut runtime, &mut service, &tr, &ps, &mut comm, 1303)
        .await?;
    assert_eq!(&challenge[2..4], &1209_u16.to_be_bytes());
    let input = Challenge {
        nonce: [42; 32],
        origin: SystemClock.sample()?.now.as_micros(),
    };
    let mut incoming = frame(1202, 136);
    incoming[16..24].copy_from_slice(&1_000_000_u64.to_be_bytes());
    incoming[24..56].copy_from_slice(&remote.0);
    incoming[88..].copy_from_slice(&input.encode());
    comm.write_all(&incoming).await?;
    let response = reader
        .message(&mut runtime, &mut service, &tr, &ps, &mut comm, 1304)
        .await?;
    let value = Validation::decode(&response[48..])?;
    assert_eq!(value.nonce, input.nonce);
    assert_eq!(value.origin, input.origin);
    EddsaPublicKey::from_bytes(peer).verify(
        35,
        &Validation::signed_region(&input.nonce, value.validity),
        &EddsaSignature::from_bytes(value.signature),
    )?;
    assert_eq!(runtime.report().validation_signatures, 1);
    assert_eq!(runtime.report().service_signature_requests, 1);
    assert_eq!(runtime.report().pending_service_signatures, 0);
    assert!(!d.0.join("seed").exists());
    // An actual official unsigned FEED makes the live service broadcast a freshly
    // signed announcement. Reference029 keeps this same key for address changes.
    let mut feeder = UnixStream::connect(&pp).await?;
    let mut storage = [0; 256];
    let mut builder = gnunet_hello::HelloBuilder::new(&mut storage, hello());
    builder.add_address(b"tcp://127.0.0.1:77")?;
    let h = builder.with_signature(
        EddsaPublicKey::from_bytes([0; 32]),
        EddsaSignature::from_bytes([0; 64]),
        gnunet_hello::AbsoluteTime::NEVER,
    );
    let mut block = vec![0; h.block_len()?];
    h.encode_block(&mut block)?;
    let mut feed = vec![0; 8 + block.len()];
    gnunet_wire::official::pils::Request::Feed { block: &block }.encode(&mut feed)?;
    feeder.write_all(&feed).await?;
    let until = Instant::now() + Duration::from_secs(4);
    let mut updated = false;
    while Instant::now() < until && !updated {
        if let Some(Progress::Pils(gnunet_pils_host::client::Progress::Inbound(
            gnunet_pils::client::Inbound::Identity { identity, .. },
        ))) = step(&mut runtime, &mut service, &tr, &ps).await?
        {
            updated = identity.revision() > 1 && *identity.peer().as_bytes() == peer;
        }
    }
    assert!(
        updated,
        "the actual same-key announcement must be fully consumed before checking client retention"
    );
    assert_eq!(runtime.report().activations, 1);
    assert_eq!(runtime.report().retirements, 0);
    assert_eq!(runtime.identity(), Some(peer));
    let mut bytes = [0; 8192];
    match comm.try_read(&mut bytes) {
        Ok(n) => {
            assert_ne!(n, 0);
            reader.pending.extend_from_slice(&bytes[..n]);
        }
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(error) => return Err(error.into()),
    }
    runtime.close()?;
    Ok(())
}

async fn runtime_only<'a>(
    runtime: &mut Runtime<'a>,
    tr: &UnixListener,
    ps: &UnixListener,
) -> Result<Option<Progress<'a>>, Failure> {
    let tr = [Listener::Unix(tr)];
    let ps = [Listener::Unix(ps)];
    let mut observe = |_| {};
    let mut future = Box::pin(runtime.drive(&tr, &ps, &mut observe));
    let mut cx = Context::from_waker(Waker::noop());
    let value = future.as_mut().poll(&mut cx);
    drop(future);
    tokio::task::yield_now().await;
    match value {
        Poll::Ready(value) => Ok(Some(value?)),
        Poll::Pending => Ok(None),
    }
}
fn registration_and_queue(peer: PeerId, id: u32) -> Vec<u8> {
    let mut registration = frame(1211, 16);
    registration[4..8].copy_from_slice(&1_u32.to_be_bytes());
    registration[12..].copy_from_slice(b"tcp\0");
    registration.extend_from_slice(&service_queue(peer, id));
    registration
}
fn service_queue(peer: PeerId, id: u32) -> Vec<u8> {
    let mut queue = frame(1204, 74);
    queue[4..8].copy_from_slice(&id.to_be_bytes());
    queue[8..40].copy_from_slice(&peer.0);
    queue[44..48].copy_from_slice(&u32::MAX.to_be_bytes());
    queue[48..56].copy_from_slice(&u64::MAX.to_be_bytes());
    queue[64..].copy_from_slice(b"tcp-local\0");
    queue
}
fn service_challenge(peer: PeerId, nonce: u8) -> Vec<u8> {
    let challenge = Challenge {
        nonce: [nonce; 32],
        origin: 90 + u64::from(nonce),
    };
    let mut input = frame(1202, 136);
    input[16..24].copy_from_slice(&1_000_000_u64.to_be_bytes());
    input[24..56].copy_from_slice(&peer.0);
    input[88..].copy_from_slice(&challenge.encode());
    input
}
async fn original_partial_request(
    runtime: &mut Runtime<'_>,
    tr: &UnixListener,
    ps: &UnixListener,
) -> Result<usize, Failure> {
    let end = Instant::now() + Duration::from_secs(3);
    let mut bytes = 0;
    while Instant::now() < end {
        if let Some(Progress::Pils(progress)) = runtime_only(runtime, tr, ps).await? {
            match progress {
                gnunet_pils_host::client::Progress::Activity { written_bytes, .. } => {
                    bytes += written_bytes
                }
                gnunet_pils_host::client::Progress::Written(_) => {
                    return Err("original frame completed before partial witness".into());
                }
                _ => {}
            }
        }
        if runtime.report().service_signature_requests == 1 && bytes > 0 {
            assert!(bytes < 56);
            return Ok(bytes);
        }
    }
    Err("original partial signing request timeout".into())
}
#[tokio::test(flavor = "current_thread")]
async fn canceled_partial_service_request_drains_original_frame_without_reconnecting_shared_mq()
-> Result<(), Failure> {
    let d = Directory::new()?;
    let pp = d.0.join("pils");
    let mut service = pils(&pp, 17)?;
    let tr = UnixListener::bind(d.0.join("tr"))?;
    let ps = UnixListener::bind(d.0.join("ps"))?;
    let clock: Arc<dyn RuntimeClock> = Arc::new(Clock::new());
    let mut instance = gnunet_pils::client::Instance::new();
    let mut runtime = Runtime::new_service(
        &mut instance,
        ServicePorts {
            pils: source(&pp, clock.clone())?,
            clock,
            journal: Journal::open(d.0.join("journal"))?,
        },
        Limits {
            pils: gnunet_pils_host::client::Limits {
                io_slice_bytes: 1,
                ..Default::default()
            },
            ..Limits::default()
        },
        Policies::default(),
    )?;
    let local = activated(&mut runtime, &mut service, &tr, &ps).await?;
    let a = PeerId([9; 32]);
    let b = PeerId([8; 32]);
    let mut comm = UnixStream::connect(d.0.join("tr")).await?;
    comm.write_all(&registration_and_queue(a, 1)).await?;
    let mut reader = Reader::default();
    reader
        .message(&mut runtime, &mut service, &tr, &ps, &mut comm, 1303)
        .await?;
    comm.write_all(&service_challenge(a, 42)).await?;
    let partial = original_partial_request(&mut runtime, &tr, &ps).await?;
    assert!(partial > 0);
    let mut down = frame(1205, 40);
    down[4..8].copy_from_slice(&1_u32.to_be_bytes());
    down[8..40].copy_from_slice(&a.0);
    comm.write_all(&down).await?;
    let end = Instant::now() + Duration::from_secs(3);
    while runtime.report().pending_service_signatures != 0 {
        assert!(Instant::now() < end);
        let _event = runtime_only(&mut runtime, &tr, &ps).await?;
    }
    assert_eq!(runtime.report().canceled_pils_operations, 1);
    assert_eq!(runtime.report().pils_losses, 0);
    assert_eq!(runtime.report().activations, 1);
    comm.write_all(&service_queue(b, 2)).await?;
    comm.write_all(&service_challenge(b, 43)).await?;
    let mut requests = 0;
    let mut ignored = 0;
    let mut response = None;
    let end = Instant::now() + Duration::from_secs(4);
    while Instant::now() < end && response.is_none() {
        requests += service
            .poll_once(SystemClock.sample()?.now.as_micros())?
            .requests;
        if matches!(
            runtime_only(&mut runtime, &tr, &ps).await?,
            Some(Progress::Pils(gnunet_pils_host::client::Progress::Inbound(
                gnunet_pils::client::Inbound::Ignored
            )))
        ) {
            ignored += 1;
        }
        let mut buffer = [0; 8192];
        match comm.try_read(&mut buffer) {
            Ok(0) => return Err("shared communicator unexpectedly closed".into()),
            Ok(n) => reader.pending.extend_from_slice(&buffer[..n]),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
        while reader.pending.len() >= 4 {
            let n = usize::from(u16::from_be_bytes([reader.pending[0], reader.pending[1]]));
            assert!(n >= 4);
            if reader.pending.len() < n {
                break;
            }
            let bytes: Vec<_> = reader.pending.drain(..n).collect();
            if n >= 52
                && bytes[2..4] == 1209_u16.to_be_bytes()
                && bytes[50..52] == 1304_u16.to_be_bytes()
            {
                let value = Validation::decode(&bytes[48..])?;
                assert_eq!(value.nonce, [43; 32]);
                assert_eq!(value.origin, 133);
                value.verify(local)?;
                response = Some(value);
            }
        }
    }
    assert!(response.is_some());
    assert_eq!(
        requests, 2,
        "canceled original partial payload must drain as one complete old request before the new original"
    );
    assert_eq!(ignored, 1);
    assert_eq!(runtime.report().validation_signatures, 1);
    assert_eq!(runtime.report().service_signature_requests, 2);
    assert_eq!(runtime.report().pending_service_signatures, 0);
    assert_eq!(runtime.report().pils_losses, 0);
    assert_eq!(runtime.report().retirements, 0);
    runtime.close()?;
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn service_eof_cancels_partial_old_operation_before_same_key_new_epoch_without_replay()
-> Result<(), Failure> {
    let d = Directory::new()?;
    let pp = d.0.join("pils");
    let mut service = pils(&pp, 17)?;
    let tr = UnixListener::bind(d.0.join("tr"))?;
    let ps = UnixListener::bind(d.0.join("ps"))?;
    let clock: Arc<dyn RuntimeClock> = Arc::new(Clock::new());
    let mut instance = gnunet_pils::client::Instance::new();
    let mut runtime = Runtime::new_service(
        &mut instance,
        ServicePorts {
            pils: source(&pp, clock.clone())?,
            clock,
            journal: Journal::open(d.0.join("journal"))?,
        },
        Limits {
            pils: gnunet_pils_host::client::Limits {
                io_slice_bytes: 1,
                ..Default::default()
            },
            ..Limits::default()
        },
        Policies::default(),
    )?;
    let local = activated(&mut runtime, &mut service, &tr, &ps).await?;
    let peer = PeerId([9; 32]);
    let mut comm = UnixStream::connect(d.0.join("tr")).await?;
    comm.write_all(&registration_and_queue(peer, 1)).await?;
    let mut reader = Reader::default();
    reader
        .message(&mut runtime, &mut service, &tr, &ps, &mut comm, 1303)
        .await?;
    comm.write_all(&service_challenge(peer, 42)).await?;
    assert!(original_partial_request(&mut runtime, &tr, &ps).await? > 0);
    drop(service);
    std::fs::remove_file(&pp)?;
    let mut replacement = pils(&pp, 17)?;
    let end = Instant::now() + Duration::from_secs(5);
    let mut retired = false;
    let mut lost = false;
    let mut activated = false;
    let mut requests = 0;
    while Instant::now() < end && !activated {
        requests += replacement
            .poll_once(SystemClock.sample()?.now.as_micros())?
            .requests;
        if let Some(event) = runtime_only(&mut runtime, &tr, &ps).await? {
            match event {
                Progress::Retired => {
                    retired = true;
                    assert_eq!(runtime.report().pending_service_signatures, 0);
                    let mut buffer = [0; 8192];
                    loop {
                        match comm.try_read(&mut buffer) {
                            Ok(0) => break,
                            Ok(_) => {}
                            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                                return Err("old physical client still live on retirement".into());
                            }
                            Err(e) => return Err(e.into()),
                        }
                    }
                }
                Progress::Pils(gnunet_pils_host::client::Progress::Lost { .. }) => lost = true,
                Progress::Activated(new) => {
                    assert!(retired && lost);
                    assert_eq!(new, local);
                    activated = true;
                }
                _ => {}
            }
        }
    }
    assert!(activated);
    for _ in 0..120 {
        requests += replacement
            .poll_once(SystemClock.sample()?.now.as_micros())?
            .requests;
        let _event = runtime_only(&mut runtime, &tr, &ps).await?;
    }
    assert_eq!(
        requests, 0,
        "old service side effect must not replay on same-key reconnect"
    );
    assert_eq!(runtime.report().service_signature_requests, 1);
    assert_eq!(runtime.report().validation_signatures, 0);
    assert_eq!(runtime.report().canceled_pils_operations, 1);
    assert_eq!(runtime.report().activations, 2);
    runtime.close()?;
    Ok(())
}

#[derive(Default)]
struct AddressObserver {
    announcement: Vec<u8>,
    addresses: Vec<Vec<u8>>,
}
impl AddressObserver {
    fn read(&mut self, service: &gnunet_pils_host::Host<4096>) -> Result<Vec<Vec<u8>>, Failure> {
        // Verify each changed signed announcement. Repeating signature checks
        // for every one-byte IO turn makes the pump depend on CPU throughput.
        if self.announcement != service.service().announcement() {
            self.addresses = verify_provider_addresses(service)?;
            self.announcement = service.service().announcement().to_vec();
        }
        Ok(self.addresses.clone())
    }
}
fn verify_provider_addresses(
    service: &gnunet_pils_host::Host<4096>,
) -> Result<Vec<Vec<u8>>, Failure> {
    let mut scratch = [0; 4096];
    let hello = service.service().verify_update(
        service.service().announcement(),
        &mut scratch,
        SystemClock.sample()?.now.as_micros(),
    )?;
    assert_eq!(hello.peer(), service.service().identity().public_key());
    Ok(hello.addresses().map(|a| a.as_bytes().to_vec()).collect())
}
fn local_address(id: u32, address: &[u8]) -> Vec<u8> {
    let mut b = frame(1200, 21 + address.len());
    b[4..8].copy_from_slice(&id.to_be_bytes());
    b[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
    b[16..20].copy_from_slice(&1u32.to_be_bytes());
    b[20..20 + address.len()].copy_from_slice(address);
    b
}
fn comm_registration() -> Vec<u8> {
    let mut b = frame(1211, 16);
    b[4..8].copy_from_slice(&1u32.to_be_bytes());
    b[12..].copy_from_slice(b"tcp\0");
    b
}
#[tokio::test(flavor = "current_thread")]
async fn actual_partial_feed_keeps_original_revision_and_other_communicator_through_withdrawal()
-> Result<(), Failure> {
    let mut addresses = AddressObserver::default();
    let d = Directory::new()?;
    let pp = d.0.join("pils");
    let mut service = pils(&pp, 17)?;
    let tr = UnixListener::bind(d.0.join("tr"))?;
    let ps = UnixListener::bind(d.0.join("ps"))?;
    let clock: Arc<dyn RuntimeClock> = Arc::new(Clock::new());
    let mut instance = gnunet_pils::client::Instance::new();
    let mut runtime = Runtime::new_service(
        &mut instance,
        ServicePorts {
            pils: source(&pp, clock.clone())?,
            clock,
            journal: Journal::open(d.0.join("journal"))?,
        },
        Limits {
            pils: gnunet_pils_host::client::Limits {
                io_slice_bytes: 1,
                ..Default::default()
            },
            ..Limits::default()
        },
        Policies::default(),
    )?;
    let peer = activated(&mut runtime, &mut service, &tr, &ps).await?;
    let mut a = UnixStream::connect(d.0.join("tr")).await?;
    a.write_all(&comm_registration()).await?;
    a.write_all(&local_address(0, b"tcp-127.0.0.1:42")).await?;
    let mut end = Instant::now() + Duration::from_secs(8);
    while runtime.report().address_publication_requests == 0 {
        assert!(
            Instant::now() < end,
            "actual FEED progress: {:?}; provider addresses: {:?}",
            runtime.report(),
            addresses.read(&service)?
        );
        let _original = step(&mut runtime, &mut service, &tr, &ps).await?;
    }
    for _ in 0..20 {
        let _original = step(&mut runtime, &mut service, &tr, &ps).await?;
    }
    assert_eq!(runtime.report().address_publication_requests, 1);
    assert_eq!(runtime.report().address_publication_writes, 0);
    assert!(addresses.read(&service)?.is_empty());
    let mut b = UnixStream::connect(d.0.join("tr")).await?;
    b.write_all(&comm_registration()).await?;
    b.write_all(&local_address(0, b"tcp-127.0.0.1:43")).await?;
    drop(a);
    let desired = vec![b"tcp://127.0.0.1:43".to_vec()];
    let mut observations = Vec::new();
    loop {
        assert!(
            Instant::now() < end,
            "original partial feed blocked current aggregate"
        );
        let _original = step(&mut runtime, &mut service, &tr, &ps).await?;
        let actual = addresses.read(&service)?;
        if observations.last() != Some(&actual) {
            observations.push(actual.clone());
        }
        if actual == desired && runtime.report().pending_address_publications == 0 {
            break;
        }
    }
    assert!(
        observations
            .iter()
            .any(|a| a == &vec![b"tcp://127.0.0.1:42".to_vec()])
    );
    assert_eq!(runtime.identity(), Some(peer));
    assert_eq!(runtime.report().activations, 1);
    assert_eq!(runtime.report().retirements, 0);
    assert_eq!(runtime.report().pils_losses, 0);
    // The other original communicator MQ remains usable after A's physical EOF.
    // Each real FEED plus its new announcement is several hundred one-byte
    // operations. Give each required phase its own bounded native wait budget.
    end = Instant::now() + Duration::from_secs(8);
    b.write_all(&local_address(1, b"tcp-127.0.0.1:44")).await?;
    loop {
        assert!(
            Instant::now() < end,
            "actual FEED progress: {:?}; provider addresses: {:?}",
            runtime.report(),
            addresses.read(&service)?
        );
        let _original = step(&mut runtime, &mut service, &tr, &ps).await?;
        let actual = addresses.read(&service)?;
        if actual.contains(&b"tcp://127.0.0.1:43".to_vec())
            && actual.contains(&b"tcp://127.0.0.1:44".to_vec())
            && runtime.report().pending_address_publications == 0
        {
            break;
        }
    }
    drop(b);
    end = Instant::now() + Duration::from_secs(8);
    loop {
        assert!(
            Instant::now() < end,
            "actual FEED progress: {:?}; provider addresses: {:?}",
            runtime.report(),
            addresses.read(&service)?
        );
        let _original = step(&mut runtime, &mut service, &tr, &ps).await?;
        if addresses.read(&service)?.is_empty()
            && runtime.report().pending_address_publications == 0
        {
            break;
        }
    }
    assert!(runtime.report().address_publication_requests >= 4);
    assert_eq!(
        runtime.report().address_publication_requests,
        runtime.report().address_publication_writes
    );
    assert_eq!(runtime.report().pils_losses, 0);
    runtime.close()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn actual_partial_feed_pils_eof_returns_original_loss_before_same_key_epoch_and_no_old_body_replay()
-> Result<(), Failure> {
    let mut addresses = AddressObserver::default();
    let d = Directory::new()?;
    let pp = d.0.join("pils");
    let mut service = pils(&pp, 17)?;
    let tr = UnixListener::bind(d.0.join("tr"))?;
    let ps = UnixListener::bind(d.0.join("ps"))?;
    let clock: Arc<dyn RuntimeClock> = Arc::new(Clock::new());
    let mut instance = gnunet_pils::client::Instance::new();
    let mut runtime = Runtime::new_service(
        &mut instance,
        ServicePorts {
            pils: source(&pp, clock.clone())?,
            clock,
            journal: Journal::open(d.0.join("journal"))?,
        },
        Limits {
            pils: gnunet_pils_host::client::Limits {
                io_slice_bytes: 1,
                ..Default::default()
            },
            ..Limits::default()
        },
        Policies::default(),
    )?;
    let peer = activated(&mut runtime, &mut service, &tr, &ps).await?;
    let mut old = UnixStream::connect(d.0.join("tr")).await?;
    old.write_all(&comm_registration()).await?;
    old.write_all(&local_address(0, b"tcp-127.0.0.1:42"))
        .await?;
    let end = Instant::now() + Duration::from_secs(5);
    while runtime.report().address_publication_requests == 0 {
        assert!(Instant::now() < end);
        let _original = step(&mut runtime, &mut service, &tr, &ps).await?;
    }
    for _ in 0..20 {
        let _original = step(&mut runtime, &mut service, &tr, &ps).await?;
    }
    assert_eq!(runtime.report().address_publication_requests, 1);
    assert_eq!(runtime.report().address_publication_writes, 0);
    assert!(addresses.read(&service)?.is_empty());
    drop(service);
    std::fs::remove_file(&pp)?;
    let mut replacement = pils(&pp, 17)?;
    let initial = replacement.service().announcement().to_vec();
    let mut original_loss = None;
    let mut new_written = None;
    let mut activated_again = false;
    let end = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            Instant::now() < end,
            "same-key new epoch failed: {:?}",
            runtime.report()
        );
        if let Some(event) = step(&mut runtime, &mut replacement, &tr, &ps).await? {
            match event {
                Progress::Pils(gnunet_pils_host::client::Progress::Lost { report, .. }) => {
                    let feeds = report.feeds().collect::<Vec<_>>();
                    assert_eq!(feeds.len(), 1);
                    assert_eq!(
                        feeds[0].disposition,
                        gnunet_pils::client::FeedDisposition::SubmissionUnknown
                    );
                    original_loss = Some(feeds[0].operation);
                }
                Progress::Activated(current) => {
                    assert_eq!(current, peer);
                    assert!(
                        original_loss.is_some(),
                        "new epoch activated before original loss report"
                    );
                    let mut byte = [0];
                    assert_eq!(
                        tokio::time::timeout(Duration::from_secs(1), old.read(&mut byte)).await??,
                        0
                    );
                    activated_again = true;
                }
                Progress::Pils(gnunet_pils_host::client::Progress::Written(w))
                    if w.kind == gnunet_pils::client::OperationKind::Feed =>
                {
                    assert!(activated_again);
                    new_written = Some(w.operation);
                }
                _ => {}
            }
        }
        assert!(
            addresses.read(&replacement)?.is_empty(),
            "old address body replayed into replacement PILS service"
        );
        if activated_again
            && new_written.is_some()
            && replacement.service().announcement() != initial
            && runtime.report().pending_address_publications == 0
        {
            break;
        }
    }
    assert_ne!(original_loss, new_written);
    assert_eq!(runtime.report().activations, 2);
    assert_eq!(runtime.report().address_publication_requests, 2);
    assert_eq!(runtime.report().address_publication_writes, 1);
    assert_eq!(runtime.report().address_publication_retirements, 1);
    assert_eq!(runtime.identity(), Some(peer));
    runtime.close()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn actual_later_pils_observation_gets_fresh_current_snapshot_not_old_operation_replay()
-> Result<(), Failure> {
    let mut addresses = AddressObserver::default();
    let d = Directory::new()?;
    let pp = d.0.join("pils");
    let mut service = pils(&pp, 17)?;
    let tr = UnixListener::bind(d.0.join("tr"))?;
    let ps = UnixListener::bind(d.0.join("ps"))?;
    let clock: Arc<dyn RuntimeClock> = Arc::new(Clock::new());
    let mut instance = gnunet_pils::client::Instance::new();
    let mut runtime = Runtime::new_service(
        &mut instance,
        ServicePorts {
            pils: source(&pp, clock.clone())?,
            clock,
            journal: Journal::open(d.0.join("journal"))?,
        },
        Limits::default(),
        Policies::default(),
    )?;
    let peer = activated(&mut runtime, &mut service, &tr, &ps).await?;
    let mut comm = UnixStream::connect(d.0.join("tr")).await?;
    comm.write_all(&comm_registration()).await?;
    comm.write_all(&local_address(1, b"tcp-127.0.0.1:42"))
        .await?;
    let mut originals = Vec::new();
    let desired = vec![b"tcp://127.0.0.1:42".to_vec()];
    let end = Instant::now() + Duration::from_secs(4);
    loop {
        assert!(Instant::now() < end);
        if let Some(Progress::Pils(gnunet_pils_host::client::Progress::Written(w))) =
            step(&mut runtime, &mut service, &tr, &ps).await?
            && w.kind == gnunet_pils::client::OperationKind::Feed
        {
            originals.push(w.operation);
        }
        if addresses.read(&service)? == desired
            && !originals.is_empty()
            && runtime.report().pending_address_publications == 0
        {
            break;
        }
    }
    // Another actual authorized local client submits a stale resource set through
    // the public PILS API. The real service applies it and broadcasts its own HELLO.
    // This models an observable late writer, not a fabricated Node response.
    let mut feeder_instance = gnunet_pils::client::Instance::new();
    let mut feeder = gnunet_pils_host::client::Client::<32>::new(
        &mut feeder_instance,
        source(&pp, Arc::new(SystemClock))?,
        Profile::Reference029,
        Default::default(),
        hello(),
    )?;
    let end = Instant::now() + Duration::from_secs(4);
    let mut cx = Context::from_waker(Waker::noop());
    while feeder.identity().is_none() {
        assert!(Instant::now() < end);
        let _original = step(&mut runtime, &mut service, &tr, &ps).await?;
        let mut f = Box::pin(feeder.drive(None));
        let _progress = f.as_mut().poll(&mut cx);
    }
    let mut storage = [0; 256];
    let mut stale = gnunet_hello::HelloBuilder::new(&mut storage, hello());
    stale.add_address(b"tcp://127.0.0.1:99")?;
    let stale_operation = feeder.feed_addresses(&stale)?;
    let mut observed_stale = false;
    let end = Instant::now() + Duration::from_secs(4);
    loop {
        assert!(
            Instant::now() < end,
            "current resource reconciliation stalled: {:?}",
            runtime.report()
        );
        let _native = service.poll_once(SystemClock.sample()?.now.as_micros())?;
        let state = addresses.read(&service)?;
        observed_stale |= state == vec![b"tcp://127.0.0.1:99".to_vec()];
        if let Some(Progress::Pils(gnunet_pils_host::client::Progress::Written(w))) =
            step(&mut runtime, &mut service, &tr, &ps).await?
            && w.kind == gnunet_pils::client::OperationKind::Feed
        {
            originals.push(w.operation);
        }
        {
            let mut f = Box::pin(feeder.drive(None));
            let _progress = f.as_mut().poll(&mut cx);
        }
        if observed_stale
            && addresses.read(&service)? == desired
            && runtime.report().address_reconciliations > 0
            && runtime.report().pending_address_publications == 0
            && originals.len() >= 2
        {
            break;
        }
    }
    assert_ne!(originals[0], originals[1]);
    assert!(!originals.contains(&stale_operation));
    assert_eq!(runtime.identity(), Some(peer));
    assert_eq!(runtime.report().activations, 1);
    assert_eq!(runtime.report().retirements, 0);
    let _old = feeder.close();
    runtime.close()?;
    Ok(())
}

async fn original_feed_partial(
    runtime: &mut Runtime<'_>,
    service: &mut gnunet_pils_host::Host<4096>,
    tr: &UnixListener,
    ps: &UnixListener,
) -> Result<(), Failure> {
    let mut addresses = AddressObserver::default();
    let until = Instant::now() + Duration::from_secs(3);
    loop {
        assert!(Instant::now() < until, "no original positive partial write");
        if let Some(Progress::Pils(gnunet_pils_host::client::Progress::Activity {
            written_bytes,
            ..
        })) = step(runtime, service, tr, ps).await?
            && written_bytes > 0
        {
            // This MQ has exactly one admitted operation, the original FEED.
            // io_slice1 and a positive Activity certify one actual byte,
            // with its complete-frame Written event still absent.
            assert_eq!(written_bytes, 1);
            assert_eq!(runtime.report().address_publication_requests, 1);
            assert_eq!(runtime.report().address_publication_writes, 0);
            assert!(addresses.read(service)?.is_empty());
            return Ok(());
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn graceful_shutdown_finishes_original_partial_then_empty_and_returns_original_writes()
-> Result<(), Failure> {
    let mut addresses = AddressObserver::default();
    let d = Directory::new()?;
    let pp = d.0.join("pils");
    let mut service = pils(&pp, 17)?;
    let tr = UnixListener::bind(d.0.join("tr"))?;
    let ps = UnixListener::bind(d.0.join("ps"))?;
    let tracking = Clock::new();
    let clock: Arc<dyn RuntimeClock> = Arc::new(tracking.clone());
    let mut instance = gnunet_pils::client::Instance::new();
    let mut runtime = Runtime::new_service(
        &mut instance,
        ServicePorts {
            pils: source(&pp, clock.clone())?,
            clock,
            journal: Journal::open(d.0.join("journal"))?,
        },
        Limits {
            pils: gnunet_pils_host::client::Limits {
                io_slice_bytes: 1,
                ..Default::default()
            },
            ..Limits::default()
        },
        Policies::default(),
    )?;
    let peer = activated(&mut runtime, &mut service, &tr, &ps).await?;
    let mut comm = UnixStream::connect(d.0.join("tr")).await?;
    comm.write_all(&comm_registration()).await?;
    comm.write_all(&local_address(0, b"tcp-127.0.0.1:42"))
        .await?;
    let until = Instant::now() + Duration::from_secs(4);
    while runtime.report().address_publication_requests == 0 {
        assert!(Instant::now() < until);
        let _original = step(&mut runtime, &mut service, &tr, &ps).await?;
    }
    original_feed_partial(&mut runtime, &mut service, &tr, &ps).await?;
    assert_eq!(runtime.report().address_publication_writes, 0);
    assert!(addresses.read(&service)?.is_empty());
    runtime.begin_shutdown(std::num::NonZeroU64::new(8_000_000).ok_or("budget")?)?;
    let _unadmitted = UnixStream::connect(d.0.join("tr")).await?;
    // Original service clients are physically closed before any drain progress.
    let mut byte = [0u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), comm.read(&mut byte)).await??,
        0
    );
    let mut writes = Vec::new();
    let mut seen_original_set = false;
    let until = Instant::now() + Duration::from_secs(8);
    loop {
        assert!(
            Instant::now() < until,
            "original drain blocked: {:?}",
            runtime.report()
        );
        let progress = step(&mut runtime, &mut service, &tr, &ps).await?;
        seen_original_set |= addresses.read(&service)? == vec![b"tcp://127.0.0.1:42".to_vec()];
        match progress {
            Some(Progress::Pils(gnunet_pils_host::client::Progress::Written(w)))
                if w.kind == gnunet_pils::client::OperationKind::Feed =>
            {
                assert!(!w.canceled);
                writes.push(w.operation);
            }
            Some(Progress::Drained {
                local_empty_written,
            }) => {
                assert!(local_empty_written);
                break;
            }
            _ => {}
        }
    }
    assert!(
        seen_original_set,
        "old immutable frame was not completed before FIFO empty"
    );
    assert_eq!(writes.len(), 2);
    assert_ne!(writes[0], writes[1]);
    assert_eq!(runtime.report().address_publication_requests, 2);
    assert_eq!(runtime.report().address_publication_writes, 2);
    assert_eq!(runtime.report().address_publication_retirements, 0);
    assert_eq!(runtime.report().graceful_drains, 1);
    assert_eq!(runtime.report().transport_connections, 1);
    assert!(matches!(
        step(&mut runtime, &mut service, &tr, &ps).await?,
        None | Some(Progress::Drained {
            local_empty_written: true
        })
    ));
    assert_eq!(runtime.report().graceful_drains, 1);
    assert_eq!(runtime.identity(), Some(peer));
    runtime.close()?;
    // Local fullwrite alone was the runtime promise. Separately poll the actual
    // service until it applies that already submitted complete empty frame.
    let until = Instant::now() + Duration::from_secs(2);
    while !addresses.read(&service)?.is_empty() {
        assert!(Instant::now() < until);
        service.poll_once(SystemClock.sample()?.now.as_micros())?;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(tracking.active(), 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn graceful_shutdown_timeout_retires_original_partial_without_empty_success()
-> Result<(), Failure> {
    failed_partial_drain(false).await
}

#[tokio::test(flavor = "current_thread")]
async fn graceful_shutdown_clock_refusal_retires_original_partial_without_empty_success()
-> Result<(), Failure> {
    failed_partial_drain(true).await
}

async fn failed_partial_drain(refused_clock: bool) -> Result<(), Failure> {
    let mut addresses = AddressObserver::default();
    let d = Directory::new()?;
    let pp = d.0.join("pils");
    let mut service = pils(&pp, 17)?;
    let tr = UnixListener::bind(d.0.join("tr"))?;
    let ps = UnixListener::bind(d.0.join("ps"))?;
    let tracking = Clock::new();
    let clock: Arc<dyn RuntimeClock> = Arc::new(tracking.clone());
    let mut instance = gnunet_pils::client::Instance::new();
    let mut runtime = Runtime::new_service(
        &mut instance,
        ServicePorts {
            pils: source(&pp, clock.clone())?,
            clock,
            journal: Journal::open(d.0.join("journal"))?,
        },
        Limits {
            pils: gnunet_pils_host::client::Limits {
                io_slice_bytes: 1,
                ..Default::default()
            },
            ..Limits::default()
        },
        Policies::default(),
    )?;
    let _peer = activated(&mut runtime, &mut service, &tr, &ps).await?;
    let mut comm = UnixStream::connect(d.0.join("tr")).await?;
    comm.write_all(&comm_registration()).await?;
    comm.write_all(&local_address(0, b"tcp-127.0.0.1:42"))
        .await?;
    let until = Instant::now() + Duration::from_secs(4);
    while runtime.report().address_publication_requests == 0 {
        assert!(Instant::now() < until);
        let _original = step(&mut runtime, &mut service, &tr, &ps).await?;
    }
    original_feed_partial(&mut runtime, &mut service, &tr, &ps).await?;
    runtime.begin_shutdown(if refused_clock {
        std::num::NonZeroU64::new(8_000_000).ok_or("budget")?
    } else {
        std::num::NonZeroU64::MIN
    })?;
    if refused_clock {
        tracking.refuse(true);
    }
    let error = loop {
        assert!(Instant::now() < until);
        match step(&mut runtime, &mut service, &tr, &ps).await {
            Err(error) => break error,
            Ok(Some(Progress::Drained { .. })) => {
                return Err("expired original drain claimed success".into());
            }
            _ => {}
        }
    };
    let original = error
        .downcast_ref::<gnunet_transport_runtime::Error>()
        .ok_or("runtime cause")?;
    if refused_clock {
        assert!(matches!(
            original,
            gnunet_transport_runtime::Error::Protocol(Error::TimeUncertain)
        ));
    } else {
        assert!(
            matches!(original,gnunet_transport_runtime::Error::Io(e) if e.kind()==io::ErrorKind::TimedOut)
        );
    }
    assert_eq!(runtime.report().graceful_drains, 0);
    assert_eq!(runtime.report().address_publication_writes, 0);
    assert_eq!(runtime.report().address_publication_retirements, 1);
    assert_eq!(tracking.active(), 0);
    assert!(addresses.read(&service)?.is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn graceful_shutdown_original_pils_eof_keeps_unknown_result_and_never_activates_replacement()
-> Result<(), Failure> {
    let d = Directory::new()?;
    let pp = d.0.join("pils");
    let mut service = pils(&pp, 17)?;
    let tr = UnixListener::bind(d.0.join("tr"))?;
    let ps = UnixListener::bind(d.0.join("ps"))?;
    let tracking = Clock::new();
    let clock: Arc<dyn RuntimeClock> = Arc::new(tracking.clone());
    let mut instance = gnunet_pils::client::Instance::new();
    let mut runtime = Runtime::new_service(
        &mut instance,
        ServicePorts {
            pils: source(&pp, clock.clone())?,
            clock,
            journal: Journal::open(d.0.join("journal"))?,
        },
        Limits {
            pils: gnunet_pils_host::client::Limits {
                io_slice_bytes: 1,
                ..Default::default()
            },
            ..Limits::default()
        },
        Policies::default(),
    )?;
    let _peer = activated(&mut runtime, &mut service, &tr, &ps).await?;
    let mut comm = UnixStream::connect(d.0.join("tr")).await?;
    comm.write_all(&comm_registration()).await?;
    comm.write_all(&local_address(0, b"tcp-127.0.0.1:42"))
        .await?;
    let until = Instant::now() + Duration::from_secs(4);
    while runtime.report().address_publication_requests == 0 {
        assert!(Instant::now() < until);
        let _original = step(&mut runtime, &mut service, &tr, &ps).await?;
    }
    original_feed_partial(&mut runtime, &mut service, &tr, &ps).await?;
    runtime.begin_shutdown(std::num::NonZeroU64::new(8_000_000).ok_or("budget")?)?;
    drop(service);
    std::fs::remove_file(&pp)?;
    let mut replacement = pils(&pp, 17)?;
    loop {
        assert!(Instant::now() < until);
        match step(&mut runtime, &mut replacement, &tr, &ps).await {
            Err(_) => break,
            Ok(Some(Progress::Drained { .. } | Progress::Activated(_))) => {
                return Err("lost original drain used replacement epoch".into());
            }
            _ => {}
        }
    }
    let mut original_loss = None;
    while let Some(original) = runtime.take_pils_notice() {
        if let gnunet_pils_host::client::Progress::Lost { report, .. } = original {
            let feeds = report.feeds().collect::<Vec<_>>();
            assert_eq!(feeds.len(), 1);
            assert_eq!(
                feeds[0].disposition,
                gnunet_pils::client::FeedDisposition::SubmissionUnknown
            );
            original_loss = Some(feeds[0].operation);
        }
    }
    assert!(original_loss.is_some());
    for _ in 0..40 {
        assert_eq!(
            replacement
                .poll_once(SystemClock.sample()?.now.as_micros())?
                .requests,
            0
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(runtime.report().activations, 1);
    assert_eq!(runtime.report().graceful_drains, 0);
    assert_eq!(runtime.report().address_publication_writes, 0);
    assert_eq!(runtime.report().pils_losses, 1);
    assert_eq!(tracking.active(), 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn address_quota_is_local_and_original_owners_can_delete_then_reuse() -> Result<(), Failure> {
    let mut addresses = AddressObserver::default();
    let d = Directory::new()?;
    let pp = d.0.join("pils");
    let mut service = pils(&pp, 17)?;
    let tr = UnixListener::bind(d.0.join("tr"))?;
    let ps = UnixListener::bind(d.0.join("ps"))?;
    let clock: Arc<dyn RuntimeClock> = Arc::new(Clock::new());
    let mut instance = gnunet_pils::client::Instance::new();
    let mut runtime = Runtime::new_service(
        &mut instance,
        ServicePorts {
            pils: source(&pp, clock.clone())?,
            clock,
            journal: Journal::open(d.0.join("journal"))?,
        },
        Limits::default(),
        Policies::default(),
    )?;
    let peer = activated(&mut runtime, &mut service, &tr, &ps).await?;
    let mut a = UnixStream::connect(d.0.join("tr")).await?;
    a.write_all(&comm_registration()).await?;
    let mut b = UnixStream::connect(d.0.join("tr")).await?;
    b.write_all(&comm_registration()).await?;
    for i in 0..7 {
        a.write_all(&local_address(
            i,
            format!("tcp-127.0.0.1:{}", 1000 + i).as_bytes(),
        ))
        .await?;
    }
    b.write_all(&local_address(7, b"tcp-127.0.0.1:1007"))
        .await?;
    let until = Instant::now() + Duration::from_secs(5);
    while addresses.read(&service)?.len() != 8 || runtime.report().pending_address_publications != 0
    {
        assert!(Instant::now() < until);
        let _original = step(&mut runtime, &mut service, &tr, &ps).await?;
    }
    // Original FIFO: the ninth ADD is refused, then DELETE makes a slot, and the
    // same original ninth ADD can be resubmitted and accepted without MQ loss.
    a.write_all(&local_address(8, b"tcp-127.0.0.1:1008"))
        .await?;
    let mut delete = frame(1201, 8);
    delete[4..8].copy_from_slice(&0u32.to_be_bytes());
    a.write_all(&delete).await?;
    a.write_all(&local_address(8, b"tcp-127.0.0.1:1008"))
        .await?;
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(Instant::now() < until);
        let _original = step(&mut runtime, &mut service, &tr, &ps).await?;
        let actual = addresses.read(&service)?;
        if actual.len() == 8
            && actual.contains(&b"tcp://127.0.0.1:1008".to_vec())
            && !actual.contains(&b"tcp://127.0.0.1:1000".to_vec())
            && runtime.report().pending_address_publications == 0
        {
            break;
        }
    }
    assert_eq!(runtime.report().activations, 1);
    assert_eq!(runtime.report().retirements, 0);
    assert_eq!(runtime.identity(), Some(peer));
    drop(a);
    let until = Instant::now() + Duration::from_secs(5);
    while addresses.read(&service)? != vec![b"tcp://127.0.0.1:1007".to_vec()]
        || runtime.report().pending_address_publications != 0
    {
        assert!(Instant::now() < until);
        let _original = step(&mut runtime, &mut service, &tr, &ps).await?;
    }
    b.write_all(&local_address(9, b"tcp-127.0.0.1:1009"))
        .await?;
    let until = Instant::now() + Duration::from_secs(5);
    while addresses.read(&service)?.len() != 2 || runtime.report().pending_address_publications != 0
    {
        assert!(Instant::now() < until);
        let _original = step(&mut runtime, &mut service, &tr, &ps).await?;
    }
    assert_eq!(runtime.report().transport_connections, 2);
    assert_eq!(runtime.report().activations, 1);
    assert_eq!(runtime.report().address_rejections, 1);
    runtime.close()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn address_quota65_uses_configured_publication_and_real_pils_observation()
-> Result<(), Failure> {
    let mut addresses = AddressObserver::default();
    let d = Directory::new()?;
    let pp = d.0.join("pils");
    let large = gnunet_pils::HelloLimits {
        maximum_input_bytes: 65535,
        maximum_address_bytes: 4096,
        maximum_addresses: 128,
    };
    let service = Service::new(
        MasterKey::from_seed([17; 32]),
        Profile::Reference029,
        SystemClock.sample()?.now.as_micros(),
        large,
    )?;
    let mut service = gnunet_pils_host::Host::<4096>::new(
        std::os::unix::net::UnixListener::bind(&pp)?,
        service,
        gnunet_pils_host::Limits {
            clients: 16,
            receive_bytes: 65535,
            transmit_bytes: 1024 * 1024,
            accepts_per_step: 4,
            address_bytes: 4096,
        },
    )?;
    let tr = UnixListener::bind(d.0.join("tr"))?;
    let ps = UnixListener::bind(d.0.join("ps"))?;
    let clock: Arc<dyn RuntimeClock> = Arc::new(Clock::new());
    let mut instance = gnunet_pils::client::Instance::new();
    let limits = Limits {
        transport: gnunet_transport::Limits {
            control_messages: 65,
            ..Default::default()
        },
        ..Limits::default()
    };
    let mut runtime = Runtime::new_service(
        &mut instance,
        ServicePorts {
            pils: source(&pp, clock.clone())?,
            clock,
            journal: Journal::open(d.0.join("journal"))?,
        },
        limits,
        Policies::default(),
    )?;
    let peer = activated(&mut runtime, &mut service, &tr, &ps).await?;
    let mut comm = UnixStream::connect(d.0.join("tr")).await?;
    comm.write_all(&comm_registration()).await?;
    for i in 0..65 {
        comm.write_all(&local_address(
            i,
            format!("tcp-127.0.0.1:{}", 1000 + i).as_bytes(),
        ))
        .await?;
    }
    let until = Instant::now() + Duration::from_secs(8);
    loop {
        assert!(Instant::now() < until);
        let _original = step(&mut runtime, &mut service, &tr, &ps).await?;
        if addresses.read(&service)?.len() == 65
            && runtime.report().pending_address_publications == 0
        {
            assert_eq!(*service.service().identity().public_key().as_bytes(), peer);
            break;
        }
    }
    assert_eq!(runtime.report().retirements, 0);
    assert_eq!(runtime.identity(), Some(peer));
    runtime.close()?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn address_quota_frame176_is_refused_before_subscribing_or_connecting() -> Result<(), Failure>
{
    let d = Directory::new()?;
    let pp = d.0.join("pils");
    let _service = pils(&pp, 17)?;
    let tracking = Clock::new();
    let clock: Arc<dyn RuntimeClock> = Arc::new(tracking.clone());
    let mut instance = gnunet_pils::client::Instance::new();
    let ports = ServicePorts {
        pils: source(&pp, clock.clone())?,
        clock,
        journal: Journal::open(d.0.join("journal"))?,
    };
    let before = tracking.0.subscriptions.load(Ordering::SeqCst);
    let result = Runtime::new_service(
        &mut instance,
        ports,
        Limits {
            pils: gnunet_pils_host::client::Limits {
                frame_bytes: 176,
                ..Default::default()
            },
            ..Limits::default()
        },
        Policies::default(),
    );
    assert!(matches!(
        result,
        Err(gnunet_transport_runtime::Error::Protocol(Error::Capacity))
    ));
    assert_eq!(tracking.0.subscriptions.load(Ordering::SeqCst), before);
    assert_eq!(tracking.active(), 0);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn shutdown_forever_sentinel_is_rejected_without_retiring_original_owners()
-> Result<(), Failure> {
    let mut addresses = AddressObserver::default();
    #[derive(Clone)]
    struct FrozenClock {
        tracking: Clock,
        now: u64,
    }
    impl RuntimeClock for FrozenClock {
        fn sample(&self) -> Result<ClockSample, Error> {
            let mut sample = self.tracking.sample()?;
            sample.now = gnunet_types::AbsoluteTime::from_micros(self.now);
            Ok(sample)
        }
        fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
            self.tracking.subscribe()
        }
    }
    let d = Directory::new()?;
    let pp = d.0.join("pils");
    let mut service = pils(&pp, 17)?;
    let tr = UnixListener::bind(d.0.join("tr"))?;
    let ps = UnixListener::bind(d.0.join("ps"))?;
    let tracking = Clock::new();
    let now = SystemClock.sample()?.now.as_micros();
    let clock: Arc<dyn RuntimeClock> = Arc::new(FrozenClock {
        tracking: tracking.clone(),
        now,
    });
    let mut instance = gnunet_pils::client::Instance::new();
    let mut runtime = Runtime::new_service(
        &mut instance,
        ServicePorts {
            pils: source(&pp, clock.clone())?,
            clock,
            journal: Journal::open(d.0.join("journal"))?,
        },
        Limits::default(),
        Policies::default(),
    )?;
    let peer = activated(&mut runtime, &mut service, &tr, &ps).await?;
    let mut original = UnixStream::connect(d.0.join("tr")).await?;
    original.write_all(&comm_registration()).await?;
    original
        .write_all(&local_address(1, b"tcp-127.0.0.1:42"))
        .await?;
    let until = Instant::now() + Duration::from_secs(4);
    while addresses.read(&service)? != vec![b"tcp://127.0.0.1:42".to_vec()]
        || runtime.report().pending_address_publications != 0
    {
        assert!(Instant::now() < until);
        let _event = step(&mut runtime, &mut service, &tr, &ps).await?;
    }
    let subscriptions = tracking.0.subscriptions.load(Ordering::SeqCst);
    let active = tracking.active();
    let timeout =
        std::num::NonZeroU64::new(u64::MAX - now).ok_or("nonzero finite caller timeout")?;
    assert!(matches!(
        runtime.begin_shutdown(timeout),
        Err(gnunet_transport_runtime::Error::Protocol(
            Error::InvalidInput
        ))
    ));
    assert_eq!(
        tracking.0.subscriptions.load(Ordering::SeqCst),
        subscriptions
    );
    assert_eq!(tracking.active(), active);
    assert_eq!(runtime.identity(), Some(peer));
    assert_eq!(runtime.report().retirements, 0);
    assert_eq!(runtime.report().graceful_drains, 0);
    original
        .write_all(&local_address(2, b"tcp-127.0.0.1:43"))
        .await?;
    let until = Instant::now() + Duration::from_secs(4);
    while addresses.read(&service)?.len() != 2 || runtime.report().pending_address_publications != 0
    {
        assert!(Instant::now() < until);
        let _event = step(&mut runtime, &mut service, &tr, &ps).await?;
    }
    assert_eq!(runtime.report().activations, 1);
    assert_eq!(runtime.report().transport_connections, 1);
    runtime.close()?;
    assert_eq!(tracking.active(), 0);
    Ok(())
}

#[derive(Default)]
struct OwnRows {
    addresses: Vec<Vec<u8>>,
    hellos: Vec<Vec<u8>>,
}
async fn own_rows(
    runtime: &mut Runtime<'_>,
    service: &mut gnunet_pils_host::Host<4096>,
    tr: &UnixListener,
    ps: &UnixListener,
    peer: [u8; 32],
) -> Result<OwnRows, Failure> {
    let address = ps.local_addr()?;
    let mut stream = UnixStream::connect(address.as_pathname().ok_or(Error::InvalidInput)?).await?;
    let mut request = frame(821, 48);
    request[4..36].copy_from_slice(&peer);
    request[36..40].copy_from_slice(&1_u32.to_be_bytes());
    request[40..42].copy_from_slice(&1_u16.to_be_bytes());
    stream.write_all(&request).await?;
    let mut result = OwnRows::default();
    let mut pending = Vec::new();
    let mut credit = 1usize;
    let end = Instant::now() + Duration::from_secs(3);
    while Instant::now() < end {
        let _progress = step(runtime, service, tr, ps).await?;
        let mut bytes = [0; 8192];
        match stream.try_read(&mut bytes) {
            Ok(0) => return Err("own-record iterator closed".into()),
            Ok(n) => pending.extend_from_slice(&bytes[..n]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
        while pending.len() >= 4 {
            let len = usize::from(u16::from_be_bytes([pending[0], pending[1]]));
            if len < 4 {
                return Err(Error::Malformed.into());
            }
            if pending.len() < len {
                break;
            }
            let row: Vec<_> = pending.drain(..len).collect();
            match u16::from_be_bytes([row[2], row[3]]) {
                823 => return Ok(result),
                822 => {
                    if row.len() < 60 {
                        return Err(Error::Malformed.into());
                    }
                    let ss = usize::from(u16::from_be_bytes([row[56], row[57]]));
                    let ks = usize::from(u16::from_be_bytes([row[52], row[53]]));
                    let vs = usize::from(u16::from_be_bytes([row[54], row[55]]));
                    if row.len() != 60 + ss + ks + vs {
                        return Err(Error::Malformed.into());
                    }
                    let subsystem = &row[60..60 + ss];
                    let key = &row[60 + ss..60 + ss + ks];
                    let value = &row[60 + ss + ks..];
                    if subsystem == b"transport\0" && key == b"transport-peer-hello\0" {
                        result.addresses.push(value.to_vec());
                    }
                    if subsystem == b"peerstore\0" && key == b"peerstore-peer-hello-uri\0" {
                        result.hellos.push(value.to_vec());
                    }
                    credit -= 1;
                    if credit == 0 {
                        let mut next = frame(828, 16);
                        next[4..12].copy_from_slice(&64_u64.to_be_bytes());
                        next[12..16].copy_from_slice(&1_u32.to_be_bytes());
                        stream.write_all(&next).await?;
                        credit = 64;
                    }
                }
                _ => return Err(Error::Malformed.into()),
            }
        }
        if pending.len() > 65535 {
            return Err(Error::Capacity.into());
        }
    }
    Err("own-record iterator timeout".into())
}
async fn published_own_rows(
    runtime: &mut Runtime<'_>,
    service: &mut gnunet_pils_host::Host<4096>,
    tr: &UnixListener,
    ps: &UnixListener,
    peer: [u8; 32],
    expected: usize,
) -> Result<OwnRows, Failure> {
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        let rows = own_rows(runtime, service, tr, ps, peer).await?;
        if rows.addresses.len() == expected && rows.hellos.len() == usize::from(expected != 0) {
            return Ok(rows);
        }
        if Instant::now() >= end {
            return Err("managed native publication timeout".into());
        }
    }
}
#[tokio::test(flavor = "current_thread")]
async fn native_own_publisher_commits_current_and_new_members_and_withdraws_original_leases()
-> Result<(), Failure> {
    let d = Directory::new()?;
    let pp = d.0.join("pils");
    let mut service = pils(&pp, 17)?;
    let tr = UnixListener::bind(d.0.join("tr"))?;
    let ps = UnixListener::bind(d.0.join("ps"))?;
    let clock: Arc<dyn RuntimeClock> = Arc::new(Clock::new());
    let mut instance = gnunet_pils::client::Instance::new();
    let mut runtime = Runtime::new_service(
        &mut instance,
        ServicePorts {
            pils: source(&pp, clock.clone())?,
            clock,
            journal: Journal::open(d.0.join("journal"))?,
        },
        Limits::default(),
        Policies::default(),
    )?;
    let peer = activated(&mut runtime, &mut service, &tr, &ps).await?;
    let mut a = UnixStream::connect(d.0.join("tr")).await?;
    a.write_all(&comm_registration()).await?;
    a.write_all(&local_address(0, b"tcp-127.0.0.1:2086"))
        .await?;
    let first = published_own_rows(&mut runtime, &mut service, &tr, &ps, peer, 1).await?;
    let a_value = first.addresses[0].clone();
    let a_record = gnunet_transport::own_wire::AddressRecord::parse(&a_value)?;
    a_record.verify(EddsaPublicKey::from_bytes(peer))?;
    assert_eq!(a_record.native, b"tcp-127.0.0.1:2086");
    let mut b = UnixStream::connect(d.0.join("tr")).await?;
    b.write_all(&comm_registration()).await?;
    b.write_all(&local_address(0, b"tcp-127.0.0.1:2087"))
        .await?;
    let mixed = published_own_rows(&mut runtime, &mut service, &tr, &ps, peer, 2).await?;
    assert!(mixed.addresses.contains(&a_value));
    let mut natives = Vec::new();
    let mut b_value = None;
    for value in &mixed.addresses {
        let row = gnunet_transport::own_wire::AddressRecord::parse(value)?;
        row.verify(EddsaPublicKey::from_bytes(peer))?;
        natives.push(row.native.to_vec());
        if row.native == b"tcp-127.0.0.1:2087" {
            b_value = Some(value.clone());
        }
    }
    natives.sort();
    assert_eq!(
        natives,
        [
            b"tcp-127.0.0.1:2086".to_vec(),
            b"tcp-127.0.0.1:2087".to_vec()
        ]
    );
    let mut scratch = [0; 4096];
    let hello = gnunet_hello::Hello::parse_message(&mixed.hellos[0], None, &mut scratch, hello())?;
    hello.verify_at(
        gnunet_hello::SignatureProfile::Gnunet029,
        SystemClock.sample()?.now,
    )?;
    assert_eq!(hello.peer().as_bytes(), &peer);
    assert_eq!(hello.addresses().count(), 2);
    drop(a);
    let survivor = published_own_rows(&mut runtime, &mut service, &tr, &ps, peer, 1).await?;
    assert_eq!(survivor.addresses[0], b_value.ok_or(Error::NotReady)?);
    drop(b);
    let empty = published_own_rows(&mut runtime, &mut service, &tr, &ps, peer, 0).await?;
    assert!(empty.hellos.is_empty());
    runtime.begin_shutdown(std::num::NonZeroU64::new(2_000_000).ok_or(Error::InvalidInput)?)?;
    let end = Instant::now() + Duration::from_secs(3);
    loop {
        if matches!(
            step(&mut runtime, &mut service, &tr, &ps).await?,
            Some(Progress::Drained { .. })
        ) {
            break;
        }
        assert!(Instant::now() < end, "managed shutdown did not drain");
    }
    runtime.close()?;
    assert!(!runtime.own_storage_pending());
    Ok(())
}
