//! Actual foreground clock-loss retirement with actual PILS and Unix service owners.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Actual EOF, original error and durable frontier assertions verify resource retirement"
)]
use gnunet_service_runtime::{
    Activation,
    clock::{ClockSample, ClockSubscription, RuntimeClock, SystemClock},
};
use gnunet_tcp_communicator_runtime::startup::{self, Limits, LocalKeyCapability, LocalStartup};
use gnunet_types::Error;
use std::{
    cell::RefCell,
    error::Error as StdError,
    future::Future,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UnixListener, UnixStream},
};
type Failure = Box<dyn StdError>;
struct Slot {
    active: bool,
    waker: Option<Waker>,
}
struct Tracking {
    refused: AtomicBool,
    slots: Mutex<Vec<Slot>>,
}
#[derive(Clone)]
struct Clock(Arc<Tracking>);
impl Clock {
    fn new() -> Self {
        Self(Arc::new(Tracking {
            refused: AtomicBool::new(false),
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

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}
fn drain(stream: &UnixStream) -> std::io::Result<bool> {
    let mut b = [0; 4096];
    loop {
        match stream.try_read(&mut b) {
            Ok(0) => return Ok(true),
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(false),
            Err(e) => return Err(e),
        }
    }
}
#[tokio::test(flavor = "current_thread")]
async fn actual_foreground_clock_refusal_drains_original_sockets_and_cleans_same_epoch()
-> Result<(), Failure> {
    let directory = Directory(std::env::temp_dir().join(format!("gn-tcpf-{}", std::process::id())));
    std::fs::create_dir(&directory.0)?;
    let root = &directory.0;
    let seed = root.join("seed");
    std::fs::write(&seed, [17; 32])?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o600))?;
    let mut config = gnunet_config::Configuration::default();
    for (section, path) in [
        (b"pils".as_slice(), root.join("pils")),
        (b"peerstore", root.join("ps")),
        (b"transport", root.join("tr")),
    ] {
        config.set_value(
            section,
            b"UNIXPATH",
            Some(path.as_os_str().as_encoded_bytes()),
        )?;
    }
    config.set_value(b"communicator-tcp", b"BINDTO", Some(b"127.0.0.1:0"))?;
    config.set_value(b"communicator-tcp", b"DISABLE_V6", Some(b"YES"))?;
    let service = gnunet_pils::Service::new(
        gnunet_pils::MasterKey::from_seed([17; 32]),
        gnunet_pils::Profile::Reference029,
        SystemClock.sample()?.now.as_micros(),
        gnunet_pils::HelloLimits {
            maximum_input_bytes: 65535,
            maximum_address_bytes: 4096,
            maximum_addresses: 64,
        },
    )?;
    let local_peer = *service.identity().public_key().as_bytes();
    let listener = std::os::unix::net::UnixListener::bind(root.join("pils"))?;
    let mut pils = gnunet_pils_host::Host::<4096>::new(
        listener,
        service,
        gnunet_pils_host::Limits {
            clients: 4,
            receive_bytes: 65535,
            transmit_bytes: 1024 * 1024,
            accepts_per_step: 4,
            address_bytes: 4096,
        },
    )?;
    let ps_listener = UnixListener::bind(root.join("ps"))?;
    let tr_listener = UnixListener::bind(root.join("tr"))?;
    let mut ps = None;
    let mut tr = None;
    let canonical = Clock::new();
    let ready = RefCell::new(None);
    let mut raw = None;
    let mut ready_since = None;
    let mut refused = false;
    let peer_name: String = local_peer
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    let path = root.join(format!("state/tcp-{peer_name}.frontier"));
    let mut future = Box::pin(startup::foreground_local_with_clock(
        LocalStartup {
            config: &config,
            activation: Activation::default(),
            state_directory: root.join("state"),
            local_key: LocalKeyCapability { ikm_file: seed },
            limits: Limits {
                sessions: 1,
                ..Limits::default()
            },
        },
        |listeners, _| {
            *ready.borrow_mut() = Some(listeners.addresses()[0]);
            Ok(())
        },
        std::future::pending(),
        |_| {},
        |_| {},
        |_| {},
        Arc::new(canonical.clone()),
    ));
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut cx = Context::from_waker(Waker::noop());
    let original = loop {
        pils.poll_once(SystemClock.sample()?.now.as_micros())?;
        if ps.is_none()
            && let Poll::Ready(result) = ps_listener.poll_accept(&mut cx)
        {
            ps = Some(result?.0);
        }
        if tr.is_none()
            && let Poll::Ready(result) = tr_listener.poll_accept(&mut cx)
        {
            tr = Some(result?.0);
        }
        if !refused && let Some(s) = &tr {
            assert!(!drain(s)?);
        }
        if let Poll::Ready(result) = future.as_mut().poll(&mut cx) {
            break result;
        }
        let address = *ready.borrow();
        if raw.is_none()
            && let Some(address) = address
        {
            let mut stream = TcpStream::connect(address).await?;
            stream.write_all(&[0]).await?;
            raw = Some(stream);
            ready_since = Some(Instant::now());
        }
        if !refused && ready_since.is_some_and(|t| t.elapsed() > Duration::from_millis(50)) {
            let bytes = std::fs::read(&path)?;
            assert_eq!(bytes[8], 1);
            canonical.refuse(true);
            refused = true;
        }
        assert!(
            Instant::now() < deadline,
            "actual original foreground failed to drain after permanent canonical clock/Resolver refusal"
        );
        tokio::time::sleep(Duration::from_millis(1)).await;
    };
    assert!(
        refused,
        "fixture exited before clock refusal: {:?}",
        original.as_ref().err()
    );
    assert!(original.is_err());
    drop(future);
    let raw = raw.ok_or("actual accepted TCP absent")?;
    let mut byte = [0];
    assert_eq!(raw.try_read(&mut byte)?, 0);
    for mut original in [ps.ok_or("actual PS absent")?, tr.ok_or("actual TR absent")?] {
        tokio::time::timeout(Duration::from_secs(1), async {
            let mut bytes = [0; 4096];
            while original.read(&mut bytes).await? != 0 {}
            Ok::<_, std::io::Error>(())
        })
        .await??;
    }
    let bytes = std::fs::read(path)?;
    let image = gnunet_tcp_communicator_runtime::replay::pairing::FrontierImage::decode(
        bytes.as_slice().try_into().map_err(|_| Error::Malformed)?,
    )?;
    assert!(!image.dirty);
    assert_eq!(image.local.as_bytes(), &local_peer);
    assert!(image.minimum > 0);
    assert!(image.reserved > 0);
    assert_eq!(canonical.active(), 0);
    Ok(())
}
