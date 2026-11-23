//! Retry ownership without opening a socket or advancing a native clock.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible retry regressions assert original timer and logical-owner custody"
)]
use super::*;
use gnunet_client_host::resolution::{AddressLookup, ResolutionContext};
use std::sync::atomic::{AtomicUsize, Ordering};

type Failure = Box<dyn std::error::Error + Send + Sync>;

#[derive(Default)]
struct Ports {
    created: AtomicUsize,
    dropped: Arc<AtomicUsize>,
}
struct Timer(Arc<AtomicUsize>);
impl Future for Timer {
    type Output = io::Result<()>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Pending
    }
}
impl Drop for Timer {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
impl ResolutionContext for Ports {
    fn clock(&self) -> Arc<dyn RuntimeClock> {
        Arc::new(clock::SystemClock)
    }

    fn lookup(&self, _: &[u8], _: Duration) -> io::Result<Option<Box<dyn AddressLookup>>> {
        Err(io::Error::other(
            "retry ownership does not resolve addresses",
        ))
    }

    fn timer(&self, _: Duration) -> io::Result<ResolutionTimer> {
        self.created.fetch_add(1, Ordering::SeqCst);
        Ok(Box::pin(Timer(Arc::clone(&self.dropped))))
    }
}

fn client<'a>(instance: &'a mut Instance, ports: Arc<Ports>) -> Result<Client<'a>, Error> {
    Client::new(
        instance,
        EndpointSource::configuration(gnunet_config::Configuration::default(), b"dht", ports),
        Limits::default(),
    )
}

#[test]
fn requested_epochs_do_not_schedule_transport_failures() -> Result<(), Failure> {
    let ports = Arc::new(Ports::default());
    let mut instance = Instance::new();
    let mut client = client(&mut instance, Arc::clone(&ports))?;
    let key = [13; 64];
    for _ in 0..32 {
        let get = client.get(Get {
            key: &key,
            block_type: 10,
            options: 1,
            replication: 1,
            extended_query: &[],
        })?;
        // Mint the actual pure owner's epoch. This test makes no claim that
        // a physical native connection was opened or successfully attached.
        let epoch = client.core.connect()?;
        assert_eq!(client.stop(get)?, Cancel::BeforeIssue);
        assert!(matches!(
            client.reconnect()?,
            Progress::Lost {
                epoch: original,
                cause: LossCause::Requested,
                retained,
            } if original == epoch && retained.gets == 0
        ));
        assert!(client.retire_io()?.is_none());
    }
    assert_eq!(ports.created.load(Ordering::SeqCst), 0);
    assert_eq!(client.physical.backoff, 0);
    assert!(client.physical.delay.is_none());
    assert!(client.physical.timer.is_none());
    assert!(matches!(
        client.reconnect(),
        Err(Error::Protocol(ProtocolError::NotReady))
    ));
    Ok(())
}

#[test]
fn deliberate_rotation_preserves_the_original_pending_failure_timer() -> Result<(), Failure> {
    let ports = Arc::new(Ports::default());
    let mut instance = Instance::new();
    let mut client = client(&mut instance, Arc::clone(&ports))?;
    let mut delay = Duration::ZERO;
    for _ in 0..18 {
        delay = client.physical.schedule();
    }
    assert!(delay > Duration::from_secs(60));
    let created = ports.created.load(Ordering::SeqCst);
    let dropped = ports.dropped.load(Ordering::SeqCst);
    let backoff = client.physical.backoff;
    assert_eq!(created, 18);
    assert_eq!(dropped, created - 1);
    let mut cx = Context::from_waker(std::task::Waker::noop());
    for _ in 0..32 {
        assert!(client.retire_io()?.is_none());
        assert!(client.physical.poll_connect(&mut cx).is_pending());
        assert_eq!(ports.created.load(Ordering::SeqCst), created);
        assert_eq!(ports.dropped.load(Ordering::SeqCst), dropped);
        assert_eq!(client.physical.backoff, backoff);
        assert_eq!(client.physical.delay, Some(delay));
    }
    assert!(client.close().is_none());
    assert!(client.physical.timer.is_none());
    assert!(client.physical.delay.is_none());
    assert_eq!(ports.dropped.load(Ordering::SeqCst), created);
    Ok(())
}
