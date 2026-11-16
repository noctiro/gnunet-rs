//! One finite startup acknowledgement while original stop/log state stays live.
use crate::reporting::Reporter;
use gnunet_service_startup::{StopError, StopSubscription};
use std::{
    future::{Future, poll_fn},
    io,
    task::Poll,
    time::Duration,
};
/// Drive one original readiness notification on the caller's runtime. Its native
/// deadline is captured once; logging failure or native/parent stop aborts waiting.
///
/// Keep the actual readiness writer outside this future so cancellation retains
/// any already admitted native intent. An aborted wait does not revoke that byte.
///
/// # Errors
/// Returns the original notification/stop error, invalid lifetime, logger refusal
/// or elapsed native deadline through the caller's error type.
pub async fn acknowledge_ready<E>(
    original: impl Future<Output = Result<(), E>>,
    signals: &mut (impl StopSubscription + ?Sized),
    reports: &Reporter,
    lifetime: Duration,
) -> Result<(), E>
where
    E: From<io::Error> + From<StopError>,
{
    let until = tokio::time::Instant::now()
        .checked_add(lifetime)
        .filter(|_| !lifetime.is_zero())
        .ok_or_else(|| {
            E::from(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid startup acknowledgement lifetime",
            ))
        })?;
    let mut alarm = std::pin::pin!(tokio::time::sleep_until(until));
    let mut original = std::pin::pin!(original);
    poll_fn(|cx| {
        if alarm.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "startup acknowledgement deadline",
            )
            .into()));
        }
        reports.register(cx);
        if reports.failed() {
            return Poll::Ready(Err(io::Error::other(
                "logger failed before readiness acknowledgement",
            )
            .into()));
        }
        if let Poll::Ready(result) = signals.poll_stop(cx) {
            result?;
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "stopped before readiness acknowledgement",
            )
            .into()));
        }
        original.as_mut().poll(cx)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{logging::Logger, shared_clock::SharedClock};
    use std::{cell::Cell, error::Error, task::Context};

    struct Cancel {
        observed: bool,
    }
    impl StopSubscription for Cancel {
        fn poll_stop(&mut self, _: &mut Context<'_>) -> Poll<Result<(), StopError>> {
            self.observed = true;
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn cancellation_preserves_observer_state_without_submitting_status()
    -> Result<(), Box<dyn Error>> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(async {
                let reports = Reporter::new(
                    Logger::new(b"service-ack", std::process::id(), false)?,
                    SharedClock::native(4)?,
                );
                let mut cancel = Cancel { observed: false };
                let submissions = Cell::new(0);
                let output = poll_fn(|_| {
                    submissions.set(submissions.get() + 1);
                    Poll::Ready(Ok::<(), Box<dyn Error>>(()))
                });
                let error =
                    acknowledge_ready(output, &mut cancel, &reports, Duration::from_secs(1))
                        .await
                        .err()
                        .ok_or("cancellation allowed startup submission")?;
                if !cancel.observed
                    || submissions.get() != 0
                    || error.downcast_ref::<io::Error>().map(io::Error::kind)
                        != Some(io::ErrorKind::Interrupted)
                {
                    return Err("stop observation or original submission changed".into());
                }
                Ok(())
            })
    }
}
