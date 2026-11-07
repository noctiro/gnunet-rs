//! Real CLIENT sockets distinguish caller time resources from native failures.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Finite real-socket witnesses assert exact cause and original MQ authority"
)]
use gnunet_arm_core::{FrameSlot, monitor::Monitor};
use gnunet_arm_host::{Clock, HostError, MonitorHost};
use gnunet_client::statistics::Selector;
use gnunet_client::statistics_handle::GetFlow;
use gnunet_client_host::{ConnectError as IpcError, Endpoint, resolution::PortError};
use gnunet_config::Configuration;
use gnunet_resolver_broker::{
    BrokerError, ClockSample, ClockSubscription, FamilyProfile, Limits, LiveConfiguration,
    RuntimeClock, broker,
};
use gnunet_types::Error;
use std::{
    error::Error as StdError,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    net::TcpListener,
    time::{Instant, timeout},
};
#[path = "../../ipc-unix/tests/support/clock_source.rs"]
pub mod clock_source;
use clock_source::Adjustable;
type Test = Result<(), Box<dyn StdError>>;
#[derive(Clone, Copy)]
enum Refusal {
    Capacity,
    Time,
    Native,
}
struct Source {
    clock: Adjustable,
    fail: AtomicBool,
    subscriptions: AtomicUsize,
    kind: Refusal,
    timer_subscription: usize,
}
impl RuntimeClock for Source {
    fn sample(&self) -> Result<ClockSample, Error> {
        if self.fail.load(Ordering::SeqCst) {
            Err(Error::Io)
        } else {
            self.clock.sample()
        }
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
        let count = self.subscriptions.fetch_add(1, Ordering::SeqCst);
        let lease = self.clock.subscribe()?;
        if count == self.timer_subscription && matches!(self.kind, Refusal::Time) {
            self.fail.store(true, Ordering::SeqCst);
        }
        Ok(lease)
    }
}
fn profile() -> Result<FamilyProfile, Box<dyn StdError>> {
    let p = gnunet_resolver_broker::native_profile()?;
    Ok(FamilyProfile::new(
        p.encode(gnunet_resolver_broker::Family::V4),
        p.encode(gnunet_resolver_broker::Family::V6),
    )?)
}
fn service(section: &[u8], port: u16) -> Result<Configuration, Box<dyn StdError>> {
    let mut cfg = Configuration::default();
    cfg.set_value(section, b"HOSTNAME", Some(b"127.0.0.1"))?;
    cfg.set_value(section, b"PORT", Some(port.to_string().as_bytes()))?;
    Ok(cfg)
}
fn context(
    kind: Refusal,
    statistics_owner: bool,
) -> Result<
    (
        gnunet_resolver_broker::Context<4, 64>,
        gnunet_resolver_broker::Driver<4, 64>,
        Arc<Source>,
    ),
    Box<dyn StdError>,
> {
    let source = Arc::new(Source {
        clock: Adjustable::frozen(
            1_000_000,
            if matches!(kind, Refusal::Capacity) {
                1 + usize::from(statistics_owner)
            } else {
                8
            },
        )?,
        fail: AtomicBool::new(false),
        subscriptions: AtomicUsize::new(0),
        kind,
        timer_subscription: 1 + usize::from(statistics_owner),
    });
    let mut config = Configuration::default();
    // Numeric source callbacks must never open this resolver endpoint.
    config.set_value(
        b"resolver",
        b"UNIXPATH",
        Some(b"/tmp/gnunet-unused-numeric-resolver"),
    )?;
    let (context, driver) = broker(
        LiveConfiguration::new(config),
        Limits::default(),
        profile()?,
        source.clone(),
    )?;
    Ok((context, driver, source))
}
fn check(error: &io::Error, kind: Refusal) -> Result<&PortError, Box<dyn StdError>> {
    let marker = PortError::from_io(error)
        .ok_or("caller time error was misclassified as native connect failure")?;
    let cause = marker
        .cause()
        .get_ref()
        .and_then(|e| e.downcast_ref::<BrokerError>())
        .ok_or("original BrokerError cause was lost")?;
    assert!(matches!(
        (kind, cause),
        (Refusal::Capacity, BrokerError::Core(Error::Capacity))
            | (Refusal::Time, BrokerError::Core(Error::Io))
    ));
    Ok(marker)
}
async fn alongside<F: std::future::Future>(
    driver: &mut gnunet_resolver_broker::Driver<4, 64>,
    future: F,
) -> Result<F::Output, Box<dyn StdError>> {
    use std::{future::Future, task::Poll};
    let mut future = std::pin::pin!(future);
    Ok(timeout(
        Duration::from_secs(2),
        std::future::poll_fn(|cx| {
            if let Poll::Ready(result) = future.as_mut().poll(cx) {
                return Poll::Ready(Ok(result));
            }
            let mut drive = std::pin::pin!(driver.drive(None, |_| {}));
            match drive.as_mut().poll(cx) {
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(_)) => {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                Poll::Pending => Poll::Pending,
            }
        }),
    )
    .await??)
}
async fn consumed(listener: &TcpListener) -> Test {
    // The failed registration can cancel the nonblocking connect before the
    // kernel completes its handshake. Any actually accepted original socket
    // must close without application bytes; zero accepts is not ready success.
    if let Ok(accepted) = timeout(Duration::from_millis(20), listener.accept()).await {
        let (mut socket, _) = accepted?;
        assert_eq!(
            timeout(Duration::from_secs(1), socket.read(&mut [0])).await??,
            0,
            "refused attempt must close its original probe without transmitting a frame"
        );
    }
    assert!(
        timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err(),
        "re-poll must not replay native connect"
    );
    Ok(())
}
async fn endpoint(kind: Refusal) -> Test {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let (context, mut driver, source) = context(kind, false)?;
    let endpoint = Endpoint::configuration(
        service(b"fixture", listener.local_addr()?.port())?,
        b"fixture",
        context.resolution_context(),
    )?;
    let mut attempt = endpoint.attempt(0);
    let first = match alongside(&mut driver, &mut attempt).await? {
        Err(e) => e,
        Ok(_) => return Err("port refusal became connection success".into()),
    };
    let marker = check(&first, kind)?;
    source.fail.store(false, Ordering::SeqCst);
    let second = match alongside(&mut driver, &mut attempt).await? {
        Err(e) => e,
        Ok(_) => return Err("terminal attempt replayed after resource repair".into()),
    };
    assert!(
        std::ptr::eq(marker.cause(), check(&second, kind)?.cause()),
        "repeat reports must retain the original cause"
    );
    assert_eq!(
        source.subscriptions.load(Ordering::SeqCst),
        2,
        "re-poll must retain the original terminal refusal rather than reserve again"
    );
    consumed(&listener).await
}
async fn arm(kind: Refusal) -> Test {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let (context, mut driver, source) = context(kind, false)?;
    let mut slots = [FrameSlot::EMPTY; 1];
    let mut bytes = [0; 16];
    let core = Monitor::new(&mut slots, &mut bytes, 1)?;
    let mut host = MonitorHost::start(
        core,
        service(b"arm", listener.local_addr()?.port())?,
        context.resolution_context(),
        Default::default(),
        Clock::system()?,
        |_| {},
    )?;
    for _ in 0..2 {
        let mut callbacks = 0;
        let result = alongside(
            &mut driver,
            host.drive(Some(Instant::now() + Duration::from_secs(1)), |_, _| {
                callbacks += 1;
            }),
        )
        .await?;
        assert_eq!(
            callbacks, 0,
            "port refusal must not fabricate monitor callback"
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => return Err("port refusal must be returned".into()),
        };
        match error {
            HostError::Endpoint(IpcError::Io(e)) => {
                check(&e, kind)?;
            }
            other => return Err(format!("wrong ARM boundary: {other}").into()),
        }
        assert_eq!(host.retry_backoff(), 0);
        assert!(
            host.take_io_error().is_none(),
            "no native retry classification"
        );
        source.fail.store(false, Ordering::SeqCst);
    }
    assert_eq!(source.subscriptions.load(Ordering::SeqCst), 2);
    host.stop();
    consumed(&listener).await
}
async fn statistics(kind: Refusal) -> Test {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let (context, mut driver, source) = context(kind, true)?;
    type Handle<'owner> = gnunet_ipc_unix::handle::StatisticsHandle<'owner, 4, 64, 2, 64, 8>;
    let mut statistics_instance_1 = gnunet_client::statistics_handle::Instance::new();
    let mut host = Handle::from_config(
        &mut statistics_instance_1,
        &service(b"statistics", listener.local_addr()?.port())?,
        context.resolution_context(),
        b"fixture",
        Default::default(),
    )?
    .ok_or("disabled")?;
    let get = host.get(Selector {
        subsystem: b"fixture",
        name: b"value",
    })?;
    let epoch = host.connection_epoch().ok_or("original MQ not admitted")?;
    for _ in 0..2 {
        let mut callbacks = 0;
        let result = alongside(
            &mut driver,
            host.drive(Some(Instant::now() + Duration::from_secs(1)), |_, _| {
                callbacks += 1;
                GetFlow::Continue
            }),
        )
        .await?;
        assert_eq!(
            callbacks, 0,
            "port refusal must not fabricate statistics callback"
        );
        let error = match result {
            Err(error) => error,
            Ok(_) => return Err("port refusal must be returned".into()),
        };
        match error {
            gnunet_ipc_unix::IpcError::Io(e) => {
                check(&e, kind)?;
            }
            other => return Err(format!("wrong STATISTICS boundary: {other}").into()),
        }
        assert_eq!(host.connection_epoch(), Some(epoch));
        assert!(host.get_callbacks_enabled(get));
        assert!(
            host.take_io_error().is_none(),
            "no native retry classification"
        );
        source.fail.store(false, Ordering::SeqCst);
    }
    assert_eq!(source.subscriptions.load(Ordering::SeqCst), 3);
    drop(host);
    consumed(&listener).await
}
fn run(future: impl std::future::Future<Output = Test>) -> Test {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(future)
}
#[test]
fn endpoint_timer_capacity_retains_exact_cause_and_never_replays_socket() -> Test {
    run(endpoint(Refusal::Capacity))
}
#[test]
fn endpoint_time_error_retains_exact_cause_and_never_replays_socket() -> Test {
    run(endpoint(Refusal::Time))
}
#[test]
fn arm_timer_capacity_preserves_original_mq_without_connect_retry() -> Test {
    run(arm(Refusal::Capacity))
}
#[test]
fn arm_time_error_preserves_original_mq_without_connect_retry() -> Test {
    run(arm(Refusal::Time))
}
#[test]
fn statistics_timer_capacity_preserves_get_epoch_without_connect_retry() -> Test {
    run(statistics(Refusal::Capacity))
}
#[test]
fn statistics_time_error_preserves_get_epoch_without_connect_retry() -> Test {
    run(statistics(Refusal::Time))
}
#[test]
fn actual_native_refusal_remains_socket_retry() -> Test {
    run(async {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        drop(listener);
        let (context, mut driver, _source) = context(Refusal::Native, true)?;
        let mut statistics_instance_2 = gnunet_client::statistics_handle::Instance::new();
        let mut host = gnunet_ipc_unix::handle::StatisticsHandle::<4, 64, 2, 64, 8>::from_config(
            &mut statistics_instance_2,
            &service(b"statistics", port)?,
            context.resolution_context(),
            b"fixture",
            Default::default(),
        )?
        .ok_or("disabled")?;
        host.get(Selector {
            subsystem: b"fixture",
            name: b"value",
        })?;
        let mut retried = false;
        let until = Instant::now() + Duration::from_secs(1);
        while !retried && Instant::now() < until {
            alongside(
                &mut driver,
                host.drive(Some(until), |event, _| {
                    if matches!(event, gnunet_ipc_unix::handle::Event::ConnectRetry { .. }) {
                        retried = true;
                    }
                    GetFlow::Continue
                }),
            )
            .await??;
        }
        assert!(retried, "real ECONNREFUSED must preserve native retry");
        let error = host.take_io_error().ok_or("missing native error")?;
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert!(PortError::from_io(&error).is_none());
        Ok(())
    })
}
