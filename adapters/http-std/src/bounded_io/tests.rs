//! Deadline regressions at the actual counted stream effect boundary.
use super::*;
use gnunet_service_runtime::clock::{AbsoluteTime, ClockSample, ClockSubscription};
use std::{task::Waker, time::Duration};

struct Clock {
    delay: Duration,
    failure: Option<Fault>,
}
impl RuntimeClock for Clock {
    fn sample(&self) -> Result<ClockSample, Fault> {
        std::thread::sleep(self.delay);
        match self.failure {
            Some(error) => Err(error),
            None => Ok(ClockSample {
                now: AbsoluteTime::from_micros(0),
                revision: 0,
            }),
        }
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Fault> {
        Err(Fault::Unavailable)
    }
}

#[derive(Default)]
struct Spy {
    called: bool,
}
impl AsyncRead for Spy {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().called = true;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Spy {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut().called = true;
        Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().called = true;
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().called = true;
        Poll::Ready(Ok(()))
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Regression assertions retain fallible fixture setup"
)]
fn sample_crossing_the_native_bound_cannot_reach_read_write_or_flush() -> Result<(), BoundsError> {
    for operation in 0..3 {
        let clock = Arc::new(Clock {
            delay: Duration::from_millis(100),
            failure: None,
        });
        let bounds = Bounds::from_targets(
            AbsoluteTime::from_micros(1_000_000),
            Instant::now() + Duration::from_millis(50),
        )?;
        let mut counted = Counted {
            inner: Spy::default(),
            lease: Rc::new(IoLease::new(clock, bounds)),
            counts: Arc::new(Counters::default()),
            maximum: 1024,
        };
        let mut cx = Context::from_waker(Waker::noop());
        let result = match operation {
            0 => Pin::new(&mut counted)
                .poll_write(&mut cx, b"payload")
                .map_ok(|_| ()),
            1 => Pin::new(&mut counted).poll_flush(&mut cx),
            _ => Pin::new(&mut counted).poll_read(&mut cx, &mut ReadBuf::new(&mut [0; 8])),
        };
        assert!(
            matches!(result, Poll::Ready(Err(ref error)) if error.kind() == io::ErrorKind::TimedOut),
            "operation {operation} must refuse an exhausted original bound: {result:?}"
        );
        assert!(
            !counted.inner.called,
            "operation {operation} reached the underlying stream after expiry"
        );
        assert_eq!(
            counted.counts.report().written,
            0,
            "refusal cannot produce a byte receipt"
        );
    }
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Regression assertions retain fallible fixture setup"
)]
fn a_clock_source_deadline_is_not_an_operation_timeout() -> Result<(), BoundsError> {
    let bounds = Bounds::from_targets(
        AbsoluteTime::from_micros(1_000_000),
        Instant::now() + Duration::from_secs(1),
    )?;
    let lease = IoLease::new(
        Arc::new(Clock {
            delay: Duration::ZERO,
            failure: Some(Fault::Deadline),
        }),
        bounds,
    );
    let result = lease.check();
    assert!(
        matches!(result, Err(ref error) if error.kind() == io::ErrorKind::Other),
        "source failure must retain its independent cause"
    );
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Regression assertions retain fallible fixture setup"
)]
fn later_publication_cannot_extend_limits_or_lower_the_observation_floor() -> Result<(), BoundsError>
{
    let bounds = Bounds::from_targets(
        AbsoluteTime::from_micros(1_000),
        Instant::now() + Duration::from_secs(1),
    )?;
    let lease = IoLease::new(
        Arc::new(Clock {
            delay: Duration::ZERO,
            failure: None,
        }),
        bounds,
    );
    lease.tighten(500, bounds.hard(), 10);
    lease.tighten(2_000, bounds.hard() + Duration::from_secs(1), 0);
    assert_eq!(
        lease.bounds().expires(),
        500,
        "new observations cannot renew the original canonical limit"
    );
    assert_eq!(
        lease.bounds().hard(),
        bounds.hard(),
        "new observations cannot renew the original native limit"
    );
    assert!(
        lease.check().is_err(),
        "the retained observation floor rejects rollback"
    );
    Ok(())
}
