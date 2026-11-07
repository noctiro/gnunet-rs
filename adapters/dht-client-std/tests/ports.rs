//! Original clock refusals persist until explicit recovery and close releases listeners.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Port ownership tests assert refusal and listener counts."
)]
use gnunet_client_host::resolution::{
    AddressLookup, PortError, ResolutionContext, ResolutionTimer,
};
use gnunet_dht_client_host::{
    Client, EndpointSource, Instance, Limits, Progress,
    clock::{ClockSample, ClockSubscription, RuntimeClock},
};
use gnunet_types::Error;
use std::{
    error::Error as StdError,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
type Failure = Box<dyn StdError + Send + Sync>;
struct Clock {
    active: Arc<AtomicBool>,
    fail: AtomicBool,
    samples: AtomicUsize,
    subscriptions: AtomicUsize,
}
struct Listener(Arc<AtomicBool>);
impl Drop for Listener {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst)
    }
}
impl ClockSubscription for Listener {
    fn poll_changed(&mut self, _: &mut Context<'_>, _: u64) -> Poll<Result<ClockSample, Error>> {
        Poll::Pending
    }
}
impl RuntimeClock for Clock {
    fn sample(&self) -> Result<ClockSample, Error> {
        self.samples.fetch_add(1, Ordering::SeqCst);
        if self.fail.load(Ordering::SeqCst) {
            Err(Error::Capacity)
        } else {
            Ok(ClockSample {
                now: gnunet_types::AbsoluteTime::from_micros(1),
                revision: 0,
            })
        }
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
        self.subscriptions.fetch_add(1, Ordering::SeqCst);
        if self.active.swap(true, Ordering::SeqCst) {
            return Err(Error::Capacity);
        }
        Ok(Box::new(Listener(self.active.clone())))
    }
}
struct Ports {
    clock: Arc<Clock>,
    lookups: AtomicUsize,
    timers: AtomicUsize,
}
impl ResolutionContext for Ports {
    fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    fn lookup(&self, _: &[u8], _: Duration) -> io::Result<Option<Box<dyn AddressLookup>>> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::other("unexpected Resolver work"))
    }
    fn timer(&self, _: Duration) -> io::Result<ResolutionTimer> {
        self.timers.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::other("original timer refusal"))
    }
}
fn ports() -> Arc<Ports> {
    Arc::new(Ports {
        clock: Arc::new(Clock {
            active: Arc::new(AtomicBool::new(false)),
            fail: AtomicBool::new(true),
            samples: AtomicUsize::new(0),
            subscriptions: AtomicUsize::new(0),
        }),
        lookups: AtomicUsize::new(0),
        timers: AtomicUsize::new(0),
    })
}
fn source(ports: Arc<Ports>) -> Result<EndpointSource, Failure> {
    let mut cfg = gnunet_config::Configuration::default();
    cfg.set_value(
        b"dht",
        b"UNIXPATH",
        Some(b"/private/tmp/gnrs-dht-intentionally-missing.sock"),
    )?;
    Ok(EndpointSource::configuration(cfg, b"dht", ports))
}
fn refusal(error: gnunet_dht_client_host::Error) -> Result<PortError, Failure> {
    if let gnunet_dht_client_host::Error::Io(error) = error {
        PortError::from_io(&error)
            .cloned()
            .ok_or_else(|| "unmarked refusal".into())
    } else {
        Err("wrong error class".into())
    }
}
#[test]
fn original_clock_refusal_is_retained_without_hidden_sampling_or_resolution() -> Result<(), Failure>
{
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let ports = ports();
        let mut instance = Instance::new();
        let mut c = Client::new(&mut instance, source(ports.clone())?, Limits::default())?;
        let first = match c.drive(None).await {
            Err(e) => refusal(e)?,
            Ok(_) => return Err("clock refusal lost".into()),
        };
        let samples = ports.clock.samples.load(Ordering::SeqCst);
        let second = match c.drive(None).await {
            Err(e) => refusal(e)?,
            Ok(_) => return Err("retained refusal lost".into()),
        };
        assert!(std::ptr::eq(first.cause(), second.cause()));
        assert_eq!(ports.clock.samples.load(Ordering::SeqCst), samples);
        assert_eq!(ports.lookups.load(Ordering::SeqCst), 0);
        assert_eq!(ports.timers.load(Ordering::SeqCst), 0);
        c.close();
        assert!(!ports.clock.active.load(Ordering::SeqCst));
        let listeners = ports.clock.subscriptions.load(Ordering::SeqCst);
        assert!(c.recover_ports().is_err());
        assert_eq!(ports.clock.subscriptions.load(Ordering::SeqCst), listeners);
        assert!(matches!(c.drive(None).await?, Progress::Closed));
        Ok::<_, Failure>(())
    })
}
#[test]
fn dropping_unstarted_client_releases_exact_original_clock_listener() -> Result<(), Failure> {
    let ports = ports();
    let mut first = Instance::new();
    let c = Client::new(&mut first, source(ports.clone())?, Limits::default())?;
    assert!(ports.clock.active.load(Ordering::SeqCst));
    drop(c);
    assert!(!ports.clock.active.load(Ordering::SeqCst));
    let mut second = Instance::new();
    let c2 = Client::new(&mut second, source(ports.clone())?, Limits::default())?;
    assert!(ports.clock.active.load(Ordering::SeqCst));
    drop(c2);
    assert!(!ports.clock.active.load(Ordering::SeqCst));
    assert_eq!(ports.clock.subscriptions.load(Ordering::SeqCst), 2);
    Ok(())
}
