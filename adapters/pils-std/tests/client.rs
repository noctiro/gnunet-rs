//! Real owned Unix Native client progress, cancellation and local service composition.
#![cfg(all(unix, feature = "client"))]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible real socket regressions assert independent protocol and ownership facts"
)]
use gnunet_pils::{
    HelloLimits, MasterKey, Profile, Service,
    client::{Completion, Identity, Inbound, Instance, KeyTarget},
};
use gnunet_pils_host::{
    Host, Limits as ServiceLimits,
    client::{Client, EndpointSource, Limits, Progress},
};
use gnunet_service_runtime::clock::{RuntimeClock, SystemClock};
use gnunet_types::Error;
use gnunet_wire::official::SignaturePurpose;
use std::{
    io,
    os::unix::net::UnixListener,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};
use tokio::time::Instant;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
struct Server {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<io::Result<usize>>>,
}
impl Server {
    fn new() -> Result<Self> {
        let mut random = [0; 8];
        getrandom::fill(&mut random)?;
        let path =
            std::env::temp_dir().join(format!("pils-native-{:016x}", u64::from_be_bytes(random)));
        std::fs::create_dir(&path)?;
        Self::at(path)
    }
    fn at(path: PathBuf) -> Result<Self> {
        let listener = UnixListener::bind(path.join("socket"))?;
        let service = Service::<4096>::new(
            MasterKey::from_seed([17; 32]),
            Profile::Reference029,
            SystemClock.sample()?.now.as_micros(),
            hello(),
        )?;
        let mut host = Host::new(
            listener,
            service,
            ServiceLimits {
                clients: 8,
                receive_bytes: 65535,
                transmit_bytes: 262140,
                accepts_per_step: 8,
                address_bytes: 4096,
            },
        )?;
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let thread = thread::spawn(move || {
            let mut requests = 0;
            while !flag.load(Ordering::SeqCst) {
                let now = SystemClock
                    .sample()
                    .map_err(io::Error::other)?
                    .now
                    .as_micros();
                requests += host.poll_once(now)?.requests;
                thread::sleep(Duration::from_millis(1));
            }
            Ok(requests)
        });
        Ok(Self {
            path,
            stop,
            thread: Some(thread),
        })
    }
    fn finish(&mut self) -> Result<usize> {
        self.stop.store(true, Ordering::SeqCst);
        let thread = self.thread.take().ok_or(Error::Stale)?;
        Ok(thread
            .join()
            .map_err(|_| io::Error::other("owned server thread panicked"))??)
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _joined = thread.join();
        }
        let _removed = std::fs::remove_dir_all(&self.path);
    }
}
fn hello() -> HelloLimits {
    HelloLimits {
        maximum_input_bytes: 65535,
        maximum_address_bytes: 4096,
        maximum_addresses: 32,
    }
}
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
fn client<'a>(instance: &'a mut Instance, server: &Server, slice: usize) -> Result<Client<'a, 4>> {
    Ok(Client::new(
        instance,
        EndpointSource::unix(server.path.join("socket")),
        Profile::Reference029,
        Limits {
            pending_operations: 4,
            frame_bytes: 65535,
            io_slice_bytes: slice,
        },
        hello(),
    )?)
}
async fn identity<'a>(client: &mut Client<'a, 4>) -> Result<Identity<'a>> {
    for _ in 0..1024 {
        match client
            .drive(Some(Instant::now() + Duration::from_secs(2)))
            .await?
        {
            Progress::Inbound(Inbound::Identity { identity, .. }) => return Ok(identity),
            Progress::Connected(_) | Progress::Activity { .. } => {}
            _ => return Err(io::Error::other("unexpected initial native event").into()),
        }
    }
    Err(io::Error::other("bounded identity event count exceeded").into())
}
fn region() -> Result<[u8; 24]> {
    let mut bytes = [0x41; 24];
    SignaturePurpose::new(35, 16)?.encode(&mut bytes)?;
    Ok(bytes)
}
#[test]
fn real_native_source_signs_owned_original_bytes_and_wait_deadline_does_not_cancel() -> Result<()> {
    let mut server = Server::new()?;
    runtime()?.block_on(async {
        let mut instance = Instance::new();
        let mut client = client(&mut instance, &server, 65535)?;
        client.enable_local_key(MasterKey::from_seed([17; 32]))?;
        let identity = identity(&mut client).await?;
        assert_eq!(
            client.local_key().ok_or(Error::NotReady)?.public_key(),
            identity.peer()
        );
        let mut payload = region()?;
        let original = payload;
        let operation = client.sign(&payload, KeyTarget::Exact(identity))?;
        payload[8] ^= 1;
        assert!(matches!(
            client.drive(Some(Instant::now())).await?,
            Progress::WaitDeadline
        ));
        assert_eq!(client.pending(), 1);
        let mut writes = 0;
        for _ in 0..128 {
            match client
                .drive(Some(Instant::now() + Duration::from_secs(2)))
                .await?
            {
                Progress::Written(fact) => {
                    assert_eq!(fact.operation, operation);
                    assert!(!fact.canceled);
                    writes += 1;
                }
                Progress::Inbound(Inbound::Complete(Completion::Signature {
                    operation: received,
                    peer,
                    signature,
                    ..
                })) => {
                    assert_eq!(received, operation);
                    assert_eq!(peer, identity.peer());
                    peer.verify(35, &original, &signature)?;
                    assert!(peer.verify(35, &payload, &signature).is_err());
                    assert_eq!(writes, 1);
                    assert_eq!(client.pending(), 0);
                    assert!(client.close().iter().all(Option::is_none));
                    return Ok::<_, Box<dyn std::error::Error>>(());
                }
                Progress::Activity {
                    read_bytes,
                    written_bytes,
                } => assert!(read_bytes + written_bytes > 0),
                _ => return Err(io::Error::other("unexpected signature native event").into()),
            }
        }
        Err(io::Error::other("bounded signature event count exceeded").into())
    })?;
    assert_eq!(server.finish()?, 1);
    Ok(())
}
#[test]
fn canceled_partial_frame_drains_original_lease_without_completing_reused_slot() -> Result<()> {
    let mut server = Server::new()?;
    runtime()?.block_on(async {
        let mut instance = Instance::new();
        let mut client = client(&mut instance, &server, 1)?;
        let identity = identity(&mut client).await?;
        let old = client.sign(&region()?, KeyTarget::Exact(identity))?;
        assert!(matches!(
            client.drive(None).await?,
            Progress::Activity {
                written_bytes: 1,
                ..
            }
        ));
        assert!(matches!(
            client.drive(Some(Instant::now())).await?,
            Progress::WaitDeadline
        ));
        client.cancel(old)?;
        let new = client.sign(&region()?, KeyTarget::Exact(identity))?;
        let mut old_written = 0;
        let mut new_written = 0;
        let mut ignored = 0;
        for _ in 0..1024 {
            match client
                .drive(Some(Instant::now() + Duration::from_secs(2)))
                .await?
            {
                Progress::Written(fact) => {
                    if fact.operation == old {
                        assert!(fact.canceled);
                        old_written += 1;
                    } else {
                        assert_eq!(fact.operation, new);
                        assert!(!fact.canceled);
                        new_written += 1;
                    }
                }
                Progress::Inbound(Inbound::Ignored) => ignored += 1,
                Progress::Inbound(Inbound::Complete(Completion::Signature {
                    operation, ..
                })) => {
                    assert_eq!(operation, new);
                    assert_eq!((old_written, new_written, ignored), (1, 1, 1));
                    assert_eq!(client.pending(), 0);
                    client.close();
                    return Ok::<_, Box<dyn std::error::Error>>(());
                }
                Progress::Activity {
                    read_bytes,
                    written_bytes,
                } => assert!(read_bytes + written_bytes > 0),
                _ => return Err(io::Error::other("unexpected partial/cancel event").into()),
            }
        }
        Err(io::Error::other("bounded partial/cancel event count exceeded").into())
    })?;
    assert_eq!(server.finish()?, 2);
    Ok(())
}

mod clock_ports {
    use super::*;
    use gnunet_client_host::resolution::{
        AddressLookup, PortError, ResolutionContext, ResolutionTimer,
    };
    use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, Deadline};
    use std::{
        sync::atomic::AtomicUsize,
        task::{Context, Poll},
    };
    struct Clock {
        now: u64,
        calls: AtomicUsize,
        fail_at: AtomicUsize,
        waiters: Arc<AtomicUsize>,
    }
    struct Waiter(Arc<AtomicUsize>);
    impl Drop for Waiter {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    impl ClockSubscription for Waiter {
        fn poll_changed(
            &mut self,
            _: &mut Context<'_>,
            _: u64,
        ) -> Poll<std::result::Result<ClockSample, Error>> {
            Poll::Pending
        }
    }
    impl RuntimeClock for Clock {
        fn sample(&self) -> std::result::Result<ClockSample, Error> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            if n == self.fail_at.load(Ordering::SeqCst) {
                Err(Error::Capacity)
            } else {
                Ok(ClockSample {
                    now: gnunet_types::AbsoluteTime::from_micros(self.now),
                    revision: 0,
                })
            }
        }
        fn subscribe(&self) -> std::result::Result<Box<dyn ClockSubscription>, Error> {
            self.waiters.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(Waiter(self.waiters.clone())))
        }
    }
    struct Resolution(Arc<Clock>);
    impl ResolutionContext for Resolution {
        fn clock(&self) -> Arc<dyn RuntimeClock> {
            self.0.clone()
        }
        fn lookup(&self, _: &[u8], _: Duration) -> io::Result<Option<Box<dyn AddressLookup>>> {
            Err(io::Error::other("unexpected DNS in Unix-only clock test"))
        }
        fn timer(&self, duration: Duration) -> io::Result<ResolutionTimer> {
            let timer = Deadline::after(self.0.clone(), duration).map_err(io::Error::other)?;
            Ok(Box::pin(
                async move { timer.await.map_err(io::Error::other) },
            ))
        }
    }
    fn configured<'a>(
        instance: &'a mut Instance,
        server: &Server,
    ) -> Result<(Client<'a, 4>, Arc<Clock>)> {
        let clock = Arc::new(Clock {
            now: SystemClock.sample()?.now.as_micros(),
            calls: AtomicUsize::new(0),
            fail_at: AtomicUsize::new(0),
            waiters: Arc::new(AtomicUsize::new(0)),
        });
        let context = Arc::new(Resolution(clock.clone()));
        let mut cfg = gnunet_config::Configuration::default();
        cfg.set_value(
            b"pils",
            b"UNIXPATH",
            Some(server.path.join("socket").as_os_str().as_encoded_bytes()),
        )?;
        let client = Client::new(
            instance,
            EndpointSource::configuration(cfg, b"pils", context),
            Profile::Reference029,
            Limits {
                pending_operations: 4,
                ..Limits::default()
            },
            hello(),
        )?;
        Ok((client, clock))
    }
    #[test]
    fn canonical_clock_refusal_keeps_original_operation_and_is_not_socket_loss() -> Result<()> {
        let mut server = Server::new()?;
        runtime()?.block_on(async {
            let mut instance = Instance::new();
            let (mut client, clock) = configured(&mut instance, &server)?;
            let id = identity(&mut client).await?;
            let epoch = client.epoch();
            assert_eq!(clock.waiters.load(Ordering::SeqCst), 1);
            let op = client.ecdh([7; 32], KeyTarget::Exact(id))?;
            clock
                .fail_at
                .store(clock.calls.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
            let error = match client.drive(None).await {
                Ok(_) => return Err(io::Error::other("clock refusal disappeared").into()),
                Err(error) => error,
            };
            match error {
                gnunet_client_host::ConnectError::Io(error) => {
                    let marked = PortError::from_io(&error).ok_or(Error::NotReady)?;
                    assert_eq!(marked.cause().kind(), io::ErrorKind::OutOfMemory);
                }
                _ => return Err(io::Error::other("clock refusal changed category").into()),
            }
            assert_eq!(client.pending(), 1);
            assert_eq!(client.epoch(), epoch);
            assert_eq!(client.identity(), Some(id));
            let mut written = 0;
            for _ in 0..256 {
                match client
                    .drive(Some(Instant::now() + Duration::from_secs(2)))
                    .await?
                {
                    Progress::Written(fact) => {
                        assert_eq!(fact.operation, op);
                        written += 1;
                    }
                    Progress::Inbound(Inbound::Complete(Completion::Ecdh {
                        operation, ..
                    })) => {
                        assert_eq!(operation, op);
                        assert_eq!(written, 1);
                        client.close();
                        assert_eq!(clock.waiters.load(Ordering::SeqCst), 0);
                        return Ok::<_, Box<dyn std::error::Error>>(());
                    }
                    Progress::Activity { .. } => {}
                    _ => return Err(io::Error::other("clock refusal caused reconnect/loss").into()),
                }
            }
            Err(io::Error::other("bounded clock-recovery steps exceeded").into())
        })?;
        assert_eq!(server.finish()?, 1);
        Ok(())
    }
    #[test]
    fn retired_mq_revokes_identity_even_when_retry_clock_registration_is_refused() -> Result<()> {
        let mut server = Server::new()?;
        runtime()?.block_on(async {
            let mut instance = Instance::new();
            let (mut client, clock) = configured(&mut instance, &server)?;
            client.enable_local_key(MasterKey::from_seed([17; 32]))?;
            let old = identity(&mut client).await?;
            let op = client.sign(&region()?, KeyTarget::Exact(old))?;
            let loss = client.reconnect()?;
            assert!(matches!(loss,Progress::Lost{ref report,..} if report.retained()==1));
            clock
                .fail_at
                .store(clock.calls.load(Ordering::SeqCst) + 1, Ordering::SeqCst);
            assert!(client.drive(None).await.is_err());
            assert!(
                client.epoch().is_none()
                    && client.identity().is_none()
                    && client.local_key().is_none()
            );
            assert_eq!(
                client.local_key_status(),
                gnunet_pils::client::LocalKeyStatus::Waiting
            );
            assert_eq!(client.pending(), 1);
            let mut connected = 0;
            let mut written = 0;
            for _ in 0..128 {
                match client
                    .drive(Some(Instant::now() + Duration::from_secs(2)))
                    .await?
                {
                    Progress::Connected(epoch) => {
                        assert_ne!(epoch, old.epoch());
                        connected += 1;
                    }
                    Progress::Written(fact) => {
                        assert_eq!(fact.operation, op);
                        written += 1;
                    }
                    Progress::Inbound(Inbound::Complete(Completion::Signature {
                        operation,
                        ..
                    })) => {
                        assert_eq!(operation, op);
                        assert_eq!((connected, written), (1, 1));
                        client.close();
                        assert_eq!(clock.waiters.load(Ordering::SeqCst), 0);
                        return Ok::<_, Box<dyn std::error::Error>>(());
                    }
                    Progress::Inbound(Inbound::Identity { .. }) | Progress::Activity { .. } => {}
                    _ => {
                        return Err(io::Error::other(
                            "retry registration refusal lost original op",
                        )
                        .into());
                    }
                }
            }
            Err(io::Error::other("bounded retry registration steps exceeded").into())
        })?;
        assert_eq!(server.finish()?, 1);
        Ok(())
    }
    #[test]
    fn ready_secret_frame_survives_dispatch_clock_refusal_and_completes_only_once() -> Result<()> {
        let mut server = Server::new()?;
        runtime()?.block_on(async {
            let mut instance = Instance::new();
            let (mut client, clock) = configured(&mut instance, &server)?;
            let id = identity(&mut client).await?;
            let epoch = client.epoch();
            let op = client.ecdh([7; 32], KeyTarget::Exact(id))?;
            loop {
                if let Progress::Written(fact) = client
                    .drive(Some(Instant::now() + Duration::from_secs(2)))
                    .await?
                {
                    assert_eq!(fact.operation, op);
                    break;
                }
            }
            assert!(matches!(
                client
                    .drive(Some(Instant::now() + Duration::from_secs(2)))
                    .await?,
                Progress::Activity { read_bytes: 4, .. }
            ));
            clock
                .fail_at
                .store(clock.calls.load(Ordering::SeqCst) + 2, Ordering::SeqCst);
            assert!(matches!(
                client
                    .drive(Some(Instant::now() + Duration::from_secs(2)))
                    .await,
                Err(gnunet_client_host::ConnectError::Io(_))
            ));
            assert_eq!(client.pending(), 1);
            assert_eq!(client.epoch(), epoch);
            match client
                .drive(Some(Instant::now() + Duration::from_secs(2)))
                .await?
            {
                Progress::Inbound(Inbound::Complete(Completion::Ecdh {
                    operation,
                    identity,
                    ..
                })) => {
                    assert_eq!(operation, op);
                    assert_eq!(identity, id);
                }
                _ => {
                    return Err(
                        io::Error::other("original held secret frame was lost/replayed").into(),
                    );
                }
            }
            assert_eq!(client.pending(), 0);
            assert!(matches!(
                client
                    .drive(Some(Instant::now() + Duration::from_millis(2)))
                    .await?,
                Progress::WaitDeadline
            ));
            client.close();
            assert_eq!(clock.waiters.load(Ordering::SeqCst), 0);
            Ok::<_, Box<dyn std::error::Error>>(())
        })?;
        assert_eq!(server.finish()?, 1);
        Ok(())
    }
}

struct RawPeer {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    control: Option<std::sync::mpsc::Sender<()>>,
    thread: Option<thread::JoinHandle<io::Result<()>>>,
}
impl RawPeer {
    fn fragmented() -> Result<Self> {
        use std::io::{Read, Write};
        let mut random = [0; 8];
        getrandom::fill(&mut random)?;
        let path =
            std::env::temp_dir().join(format!("pils-fragment-{:016x}", u64::from_be_bytes(random)));
        std::fs::create_dir(&path)?;
        let listener = UnixListener::bind(path.join("socket"))?;
        listener.set_nonblocking(true)?;
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let (control, proceed) = std::sync::mpsc::channel();
        let thread = thread::spawn(move || -> io::Result<()> {
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            let (mut stream, _) = loop {
                if stopping.load(Ordering::SeqCst) {
                    return Ok(());
                }
                match listener.accept() {
                    Ok(pair) => break pair,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && std::time::Instant::now() < deadline =>
                    {
                        thread::sleep(Duration::from_millis(1))
                    }
                    Err(error) => return Err(error),
                }
            };
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(Duration::from_secs(3)))?;
            stream.set_write_timeout(Some(Duration::from_secs(3)))?;
            let now = SystemClock
                .sample()
                .map_err(io::Error::other)?
                .now
                .as_micros();
            let mut service = Service::<4096>::new(
                MasterKey::from_seed([17; 32]),
                Profile::Reference029,
                now,
                hello(),
            )
            .map_err(io::Error::other)?;
            let update = service.announcement();
            stream.write_all(&update[..6])?;
            proceed
                .recv_timeout(Duration::from_secs(3))
                .map_err(io::Error::other)?;
            stream.write_all(&update[6..])?;
            let mut request = [0; 40];
            stream.read_exact(&mut request)?;
            let mut reply = zeroize::Zeroizing::new([0; 104]);
            let action = service
                .receive(&request, &mut [], now, &mut *reply)
                .map_err(io::Error::other)?;
            assert!(matches!(
                action,
                gnunet_pils::Action::Reply {
                    len: 72,
                    crypto_error: None
                }
            ));
            stream.write_all(&reply[..10])?;
            proceed
                .recv_timeout(Duration::from_secs(3))
                .map_err(io::Error::other)?;
            // Truncated secret reply must retire this original stream, not carry
            // its partial bytes into a later MQ or manufacture a completion.
            drop(stream);
            Ok(())
        });
        Ok(Self {
            path,
            stop,
            control: Some(control),
            thread: Some(thread),
        })
    }
    fn proceed(&self) -> Result<()> {
        self.control.as_ref().ok_or(Error::Closed)?.send(())?;
        Ok(())
    }
    fn finish(&mut self) -> Result<()> {
        Ok(self
            .thread
            .take()
            .ok_or(Error::Stale)?
            .join()
            .map_err(|_| io::Error::other("owned raw peer panicked"))??)
    }
}
impl Drop for RawPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.control = None;
        if let Some(thread) = self.thread.take() {
            let _joined = thread.join();
        }
        let _removed = std::fs::remove_dir_all(&self.path);
    }
}
#[test]
fn dropped_pending_future_preserves_partial_announcement_and_fatal_secret_eof_retires_owner()
-> Result<()> {
    let mut peer = RawPeer::fragmented()?;
    runtime()?.block_on(async {
        let mut instance = Instance::new();
        let mut client = Client::<4>::new(
            &mut instance,
            EndpointSource::unix(peer.path.join("socket")),
            Profile::Reference029,
            Limits {
                pending_operations: 4,
                ..Limits::default()
            },
            hello(),
        )?;
        let mut received = 0;
        for _ in 0..16 {
            match client
                .drive(Some(Instant::now() + Duration::from_secs(2)))
                .await?
            {
                Progress::Connected(_) => {}
                Progress::Activity {
                    read_bytes,
                    written_bytes: 0,
                } => {
                    received += read_bytes;
                    if received == 6 {
                        break;
                    }
                }
                _ => return Err(io::Error::other("unexpected partial announcement step").into()),
            }
        }
        assert_eq!(received, 6);
        let epoch = client.epoch().ok_or(Error::NotReady)?;
        // Timeout owns and drops an actually Pending drive future. This is not
        // the driver's WaitDeadline return or cancellation of a logical op.
        assert!(
            tokio::time::timeout(Duration::from_millis(2), client.drive(None))
                .await
                .is_err()
        );
        assert_eq!(client.epoch(), Some(epoch));
        assert!(client.identity().is_none());
        peer.proceed()?;
        let id = identity(&mut client).await?;
        let op = client.ecdh([7; 32], KeyTarget::Exact(id))?;
        let mut written = 0;
        let mut partial = 0;
        for _ in 0..32 {
            match client
                .drive(Some(Instant::now() + Duration::from_secs(2)))
                .await?
            {
                Progress::Written(fact) => {
                    assert_eq!(fact.operation, op);
                    written += 1;
                }
                Progress::Activity {
                    read_bytes,
                    written_bytes: 0,
                } => {
                    partial += read_bytes;
                    if partial == 10 {
                        break;
                    }
                }
                _ => return Err(io::Error::other("unexpected partial secret step").into()),
            }
        }
        assert_eq!((written, partial), (1, 10));
        peer.proceed()?;
        match client
            .drive(Some(Instant::now() + Duration::from_secs(2)))
            .await?
        {
            Progress::Lost {
                epoch: old,
                cause: gnunet_pils_host::client::LossCause::Io(error),
                report,
            } => {
                assert_eq!(old, epoch);
                assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
                assert_eq!(report.retained(), 1);
                assert_eq!(report.feeds().count(), 0);
            }
            _ => {
                return Err(
                    io::Error::other("truncated secret did not retire original owner").into(),
                );
            }
        }
        assert!(client.epoch().is_none() && client.identity().is_none());
        assert_eq!(client.pending(), 1);
        assert!(client.close().contains(&Some(op)));
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    peer.finish()?;
    Ok(())
}
#[test]
fn initial_native_failure_retains_same_mq_then_attaches_without_replaying_identity() -> Result<()> {
    let mut random = [0; 8];
    getrandom::fill(&mut random)?;
    let path =
        std::env::temp_dir().join(format!("pils-initial-{:016x}", u64::from_be_bytes(random)));
    std::fs::create_dir(&path)?;
    // The eventual Server owns cleanup of the same directory.
    runtime()?.block_on(async {
        let mut instance = Instance::new();
        let mut client = Client::<4>::new(
            &mut instance,
            EndpointSource::unix(path.join("socket")),
            Profile::Reference029,
            Limits {
                pending_operations: 4,
                ..Limits::default()
            },
            hello(),
        )?;
        let op = client.sign(&region()?, KeyTarget::ServiceCurrent)?;
        let epoch = match client
            .drive(Some(Instant::now() + Duration::from_secs(2)))
            .await?
        {
            Progress::ConnectRetry {
                epoch, retry_after, ..
            } => {
                assert_eq!(retry_after, Duration::from_millis(1));
                epoch
            }
            _ => {
                return Err(
                    io::Error::other("missing endpoint did not retain first CLIENT retry").into(),
                );
            }
        };
        assert_eq!(client.epoch(), Some(epoch));
        assert_eq!(client.pending(), 1);
        let mut server = Server::at(path.clone())?;
        let mut connected = 0;
        let mut observed = 0;
        let mut written = 0;
        for _ in 0..128 {
            match client
                .drive(Some(Instant::now() + Duration::from_secs(2)))
                .await?
            {
                Progress::Connected(actual) => {
                    assert_eq!(actual, epoch);
                    connected += 1;
                }
                Progress::Inbound(Inbound::Identity { .. }) => observed += 1,
                Progress::Written(fact) => {
                    assert_eq!(fact.operation, op);
                    written += 1;
                }
                Progress::Inbound(Inbound::Complete(Completion::Signature {
                    operation, ..
                })) => {
                    assert_eq!(operation, op);
                    assert_eq!((connected, observed, written), (1, 1, 1));
                    client.close();
                    assert_eq!(server.finish()?, 1);
                    return Ok::<_, Box<dyn std::error::Error>>(());
                }
                Progress::Activity { .. } => {}
                _ => {
                    return Err(
                        io::Error::other("initial retry changed original MQ/operation").into(),
                    );
                }
            }
        }
        Err(io::Error::other("bounded initial retry steps exceeded").into())
    })?;
    Ok(())
}
#[test]
fn manual_reconnect_returns_pending_feed_ownership_before_later_close() -> Result<()> {
    let mut server = Server::new()?;
    runtime()?.block_on(async {
        let mut instance = Instance::new();
        let mut client = client(&mut instance, &server, 1)?;
        let id = identity(&mut client).await?;
        let mut scratch = [0; 256];
        let builder = gnunet_hello::HelloBuilder::new(&mut scratch, hello());
        let feed = client.feed_addresses(&builder)?;
        assert!(matches!(
            client.drive(None).await?,
            Progress::Activity {
                written_bytes: 1,
                ..
            }
        ));
        let crypto = client.ecdh([7; 32], KeyTarget::Exact(id))?;
        let report = match client.reconnect()? {
            Progress::Lost {
                epoch,
                cause: gnunet_pils_host::client::LossCause::Requested,
                report,
            } => {
                assert_eq!(epoch, id.epoch());
                report
            }
            _ => return Err(io::Error::other("manual reconnect lost owned report").into()),
        };
        assert!(client.epoch().is_none() && client.identity().is_none());
        let closed = client.close();
        let feeds: Vec<_> = report.feeds().collect();
        assert_eq!(feeds.len(), 1);
        assert_eq!(feeds[0].operation, feed);
        assert_eq!(
            feeds[0].disposition,
            gnunet_pils::client::FeedDisposition::SubmissionUnknown
        );
        assert_eq!(report.retained(), 1);
        assert!(closed.contains(&Some(crypto)));
        assert!(!closed.contains(&Some(feed)));
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    assert_eq!(server.finish()?, 0);
    Ok(())
}
