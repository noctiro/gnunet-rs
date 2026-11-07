//! Original source-domain failures stay retained until explicit recovery.
#![cfg(unix)]
#![expect(
    clippy::panic_in_result_fn,
    reason = "Tests assert exact port invocation counts and original error ownership."
)]
use gnunet_client_host::resolution::{
    AddressLookup, PortError, ResolutionContext, ResolutionTimer,
};
use gnunet_core_client_host::{
    ClassOrder, Client, EndpointSource, Instance, Limits, Progress,
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
}
struct Subscription(Arc<AtomicBool>);
impl Drop for Subscription {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}
impl ClockSubscription for Subscription {
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
                now: gnunet_types::AbsoluteTime::from_micros(123),
                revision: 0,
            })
        }
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
        if self.active.swap(true, Ordering::SeqCst) {
            return Err(Error::Capacity);
        }
        Ok(Box::new(Subscription(self.active.clone())))
    }
}
struct Ports {
    clock: Arc<Clock>,
    timers: AtomicUsize,
    fail_timer: AtomicBool,
    lookups: AtomicUsize,
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
        if self.fail_timer.load(Ordering::SeqCst) {
            Err(io::Error::other("original timer refused"))
        } else {
            Ok(Box::pin(async { Ok(()) }))
        }
    }
}
fn ports() -> Arc<Ports> {
    Arc::new(Ports {
        clock: Arc::new(Clock {
            active: Arc::new(AtomicBool::new(false)),
            fail: AtomicBool::new(false),
            samples: AtomicUsize::new(0),
        }),
        timers: AtomicUsize::new(0),
        fail_timer: AtomicBool::new(false),
        lookups: AtomicUsize::new(0),
    })
}
fn source(ports: Arc<Ports>) -> Result<EndpointSource, Failure> {
    let mut cfg = gnunet_config::Configuration::default();
    cfg.set_value(
        b"core",
        b"UNIXPATH",
        Some(b"/private/tmp/gnrs-core-intentionally-missing.sock"),
    )?;
    Ok(EndpointSource::configuration(cfg, b"core", ports))
}
fn marker(error: gnunet_core_client_host::Error) -> Result<PortError, Failure> {
    if let gnunet_core_client_host::Error::Io(error) = error {
        PortError::from_io(&error)
            .cloned()
            .ok_or_else(|| "not a source-domain refusal".into())
    } else {
        Err("wrong error class".into())
    }
}
#[test]
fn clock_refusal_does_not_repeat_sampling_or_start_hidden_io() -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let ports = ports();
        ports.clock.fail.store(true, Ordering::SeqCst);
        let mut instance = Instance::new();
        let mut client = Client::<2, 2>::new(
            &mut instance,
            source(ports.clone())?,
            ClassOrder::Little,
            0,
            &[0],
            Limits {
                sends: 2,
                ..Limits::default()
            },
        )?;
        let first = match client.drive(None).await {
            Err(error) => marker(error)?,
            Ok(_) => return Err("clock refusal lost".into()),
        };
        let count = ports.clock.samples.load(Ordering::SeqCst);
        let second = match client.drive(None).await {
            Err(error) => marker(error)?,
            Ok(_) => return Err("retained refusal lost".into()),
        };
        assert!(std::ptr::eq(first.cause(), second.cause()));
        assert_eq!(ports.clock.samples.load(Ordering::SeqCst), count);
        assert_eq!(ports.timers.load(Ordering::SeqCst), 0);
        assert_eq!(ports.lookups.load(Ordering::SeqCst), 0);
        ports.clock.fail.store(false, Ordering::SeqCst);
        client.recover_ports()?;
        assert!(matches!(
            client.drive(None).await?,
            Progress::ConnectRetry { .. }
        ));
        assert!(ports.clock.samples.load(Ordering::SeqCst) > count);
        let _closed = client.close()?;
        assert!(!ports.clock.active.load(Ordering::SeqCst));
        Ok::<_, Failure>(())
    })
}
#[test]
fn timer_refusal_is_retained_and_recovery_retries_only_the_original_delay() -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async{
        let ports=ports();ports.fail_timer.store(true,Ordering::SeqCst);
        let mut instance=Instance::new();let mut client=Client::<2,2>::new(&mut instance,source(ports.clone())?,ClassOrder::Little,0,&[0],Limits{sends:2,..Limits::default()})?;
        assert!(matches!(client.drive(None).await?,Progress::ConnectRetry{retry_after,..} if retry_after==Duration::ZERO));
        let first=match client.drive(None).await{Err(error)=>marker(error)?,Ok(_)=>return Err("timer refusal lost".into())};
        let second=match client.drive(None).await{Err(error)=>marker(error)?,Ok(_)=>return Err("retained timer refusal lost".into())};
        assert!(std::ptr::eq(first.cause(),second.cause()));assert_eq!(ports.timers.load(Ordering::SeqCst),1);
        ports.fail_timer.store(false,Ordering::SeqCst);client.recover_ports()?;
        assert!(matches!(client.drive(None).await?,Progress::ConnectRetry{retry_after,..} if retry_after==Duration::from_millis(1)));
        assert_eq!(ports.timers.load(Ordering::SeqCst),2);assert_eq!(ports.lookups.load(Ordering::SeqCst),0);
        let _closed=client.close()?;Ok::<_,Failure>(())
    })
}

#[test]
fn permanently_closed_application_cannot_reacquire_clock_listener() -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let ports = ports();
        ports.clock.fail.store(true, Ordering::SeqCst);
        let mut instance = Instance::new();
        let mut client = Client::<2, 2>::new(
            &mut instance,
            source(ports.clone())?,
            ClassOrder::Little,
            0,
            &[0],
            Limits {
                sends: 2,
                ..Limits::default()
            },
        )?;
        assert!(client.drive(None).await.is_err());
        let _closed = client.close()?;
        assert!(!ports.clock.active.load(Ordering::SeqCst));
        assert!(matches!(
            client.recover_ports(),
            Err(gnunet_core_client_host::Error::Protocol(Error::Closed))
        ));
        assert!(!ports.clock.active.load(Ordering::SeqCst));
        Ok::<_, Failure>(())
    })
}
#[test]
fn permanently_closed_monitor_cannot_reacquire_clock_listener() -> Result<(), Failure> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let ports = ports();
        ports.clock.fail.store(true, Ordering::SeqCst);
        let mut instance = Instance::new();
        let mut monitor = gnunet_core_client_host::Monitor::new(
            &mut instance,
            source(ports.clone())?,
            Limits::default(),
        )?;
        assert!(monitor.drive(None).await.is_err());
        let _closed = monitor.close()?;
        assert!(!ports.clock.active.load(Ordering::SeqCst));
        assert!(matches!(
            monitor.recover_ports(),
            Err(gnunet_core_client_host::Error::Protocol(Error::Closed))
        ));
        assert!(!ports.clock.active.load(Ordering::SeqCst));
        Ok::<_, Failure>(())
    })
}
