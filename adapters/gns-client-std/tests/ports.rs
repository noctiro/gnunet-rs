//! Canonical source refusals and independent generic-channel subscriptions.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Original port causes and independently held clock subscriptions are asserted"
)]
use gnunet_gns_client_host::{
    BoundedClient, EndpointSource, Error, Instance, Limits, Progress,
    clock::{ClockSample, ClockSubscription, RuntimeClock},
    resolution::{AddressLookup, PortError, ResolutionContext, ResolutionTimer},
};
use gnunet_types::Error as ProtocolError;
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
    active: Arc<AtomicUsize>,
    subscriptions: AtomicUsize,
    samples: AtomicUsize,
    refused: AtomicBool,
}
struct Subscription(Arc<AtomicUsize>);
impl Drop for Subscription {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl ClockSubscription for Subscription {
    fn poll_changed(
        &mut self,
        _: &mut Context<'_>,
        _: u64,
    ) -> Poll<Result<ClockSample, ProtocolError>> {
        Poll::Pending
    }
}
impl RuntimeClock for Clock {
    fn sample(&self) -> Result<ClockSample, ProtocolError> {
        self.samples.fetch_add(1, Ordering::SeqCst);
        if self.refused.load(Ordering::SeqCst) {
            Err(ProtocolError::TimeUncertain)
        } else {
            Ok(ClockSample {
                now: gnunet_types::AbsoluteTime::from_micros(1),
                revision: 0,
            })
        }
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, ProtocolError> {
        self.active.fetch_add(1, Ordering::SeqCst);
        self.subscriptions.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(Subscription(self.active.clone())))
    }
}
struct Ports {
    clock: Arc<Clock>,
    lookups: AtomicUsize,
    timers: AtomicUsize,
    refuse_timer: AtomicBool,
}
impl ResolutionContext for Ports {
    fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.clock.clone()
    }
    fn lookup(&self, _: &[u8], _: Duration) -> io::Result<Option<Box<dyn AddressLookup>>> {
        self.lookups.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::other("unexpected DNS work in Unix-only context"))
    }
    fn timer(&self, delay: Duration) -> io::Result<ResolutionTimer> {
        self.timers.fetch_add(1, Ordering::SeqCst);
        if self.refuse_timer.load(Ordering::SeqCst) {
            Err(io::Error::other("original GNS timer refusal"))
        } else {
            let clock: Arc<dyn RuntimeClock> = self.clock.clone();
            let deadline = gnunet_service_runtime::clock::Deadline::after(clock, delay)
                .map_err(io::Error::other)?;
            Ok(Box::pin(
                async move { deadline.await.map_err(io::Error::other) },
            ))
        }
    }
}
fn ports(refused: bool) -> Arc<Ports> {
    Arc::new(Ports {
        clock: Arc::new(Clock {
            active: Arc::new(AtomicUsize::new(0)),
            subscriptions: AtomicUsize::new(0),
            samples: AtomicUsize::new(0),
            refused: AtomicBool::new(refused),
        }),
        lookups: AtomicUsize::new(0),
        timers: AtomicUsize::new(0),
        refuse_timer: AtomicBool::new(false),
    })
}
fn source(ports: Arc<Ports>) -> Result<EndpointSource, Failure> {
    let mut cfg = gnunet_config::Configuration::default();
    let path = format!(
        "/private/tmp/gnrs-gns-port-missing-{}.sock",
        std::process::id()
    );
    cfg.set_value(b"gns", b"UNIXPATH", Some(path.as_bytes()))?;
    Ok(EndpointSource::configuration(cfg, b"gns", ports))
}
fn refusal(error: Error) -> Result<PortError, Failure> {
    match error {
        Error::Io(error) => PortError::from_io(&error)
            .cloned()
            .ok_or_else(|| "unmarked original port refusal".into()),
        _ => Err("wrong original error class".into()),
    }
}
#[tokio::test(flavor = "current_thread")]
async fn original_clock_refusal_is_retained_and_closed_owner_cannot_resubscribe()
-> Result<(), Failure> {
    let p = ports(true);
    let mut instance = Instance::new();
    let mut c = BoundedClient::<2, 32>::new(&mut instance, source(p.clone())?, Limits::default())?;
    let first = match c.drive(None).await {
        Err(error) => refusal(error)?,
        Ok(_) => return Err("missing clock refusal".into()),
    };
    let samples = p.clock.samples.load(Ordering::SeqCst);
    let next = match c.drive(None).await {
        Err(error) => refusal(error)?,
        Ok(_) => return Err("lost retained clock cause".into()),
    };
    assert!(std::ptr::eq(first.cause(), next.cause()));
    assert_eq!(p.clock.samples.load(Ordering::SeqCst), samples);
    assert_eq!(p.lookups.load(Ordering::SeqCst), 0);
    assert_eq!(p.timers.load(Ordering::SeqCst), 0);
    let _closed = c.close();
    assert_eq!(p.clock.active.load(Ordering::SeqCst), 0);
    let subscriptions = p.clock.subscriptions.load(Ordering::SeqCst);
    assert!(c.recover_ports().is_err());
    assert_eq!(p.clock.subscriptions.load(Ordering::SeqCst), subscriptions);
    assert!(matches!(c.drive(None).await?, Progress::Closed));
    Ok(())
}
#[test]
fn distinct_clients_hold_distinct_clock_subscriptions_and_invalid_limits_create_none()
-> Result<(), Failure> {
    let p = ports(true);
    let mut a = Instance::new();
    let mut b = Instance::new();
    let mut c = Instance::new();
    let mut limits = Limits::default();
    limits.output.bytes = 4;
    assert!(matches!(
        BoundedClient::<2, 32>::new(&mut c, source(p.clone())?, limits),
        Err(Error::Protocol(ProtocolError::Capacity))
    ));
    assert_eq!(p.clock.subscriptions.load(Ordering::SeqCst), 0);
    let first = BoundedClient::<2, 32>::new(&mut a, source(p.clone())?, Limits::default())?;
    let second = BoundedClient::<2, 32>::new(&mut b, source(p.clone())?, Limits::default())?;
    assert_eq!(p.clock.active.load(Ordering::SeqCst), 2);
    drop(first);
    assert_eq!(p.clock.active.load(Ordering::SeqCst), 1);
    drop(second);
    assert_eq!(p.clock.active.load(Ordering::SeqCst), 0);
    assert_eq!(p.clock.subscriptions.load(Ordering::SeqCst), 2);
    Ok(())
}
#[tokio::test(flavor = "current_thread")]
async fn actual_connect_failure_and_timer_refusal_remain_distinct_until_explicit_recovery()
-> Result<(), Failure> {
    let p = ports(false);
    p.refuse_timer.store(true, Ordering::SeqCst);
    let mut instance = Instance::new();
    let mut c = BoundedClient::<2, 32>::new(&mut instance, source(p.clone())?, Limits::default())?;
    match c.drive(None).await? {
        Progress::ConnectRetry { error, retry_after } => {
            assert_eq!(error.kind(), io::ErrorKind::NotFound);
            assert_eq!(retry_after, Duration::ZERO);
        }
        _ => return Err("actual Unix connect error not reported".into()),
    }
    let first = match c.drive(None).await {
        Err(error) => refusal(error)?,
        Ok(_) => return Err("timer refusal became native retry".into()),
    };
    let samples = p.clock.samples.load(Ordering::SeqCst);
    let timers = p.timers.load(Ordering::SeqCst);
    let second = match c.drive(None).await {
        Err(error) => refusal(error)?,
        Ok(_) => return Err("timer refusal was forgotten".into()),
    };
    assert!(std::ptr::eq(first.cause(), second.cause()));
    assert_eq!(p.clock.samples.load(Ordering::SeqCst), samples);
    assert_eq!(p.timers.load(Ordering::SeqCst), timers);
    p.refuse_timer.store(false, Ordering::SeqCst);
    c.recover_ports()?;
    assert_eq!(p.clock.subscriptions.load(Ordering::SeqCst), 1);
    match c.drive(None).await? {
        Progress::ConnectRetry { error, retry_after } => {
            assert_eq!(error.kind(), io::ErrorKind::NotFound);
            assert_eq!(retry_after, Duration::from_millis(1));
        }
        _ => return Err("original retry did not resume".into()),
    }
    let _closed = c.close();
    assert_eq!(p.clock.active.load(Ordering::SeqCst), 0);
    assert_eq!(p.lookups.load(Ordering::SeqCst), 0);
    Ok(())
}
