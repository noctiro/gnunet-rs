//! One original native bound and first cause across observer socket retries.
use super::{IdentityLoss, IdentityUpdate, provider_loss};
use gnunet_pils::client::{Identity, Inbound};
use gnunet_pils_host::client::{Error as PilsError, Progress};
use gnunet_types::Error as ProtocolError;
use std::{error::Error, fmt, future::Future, pin::Pin, task::Context, time::Duration};
use tokio::time::{Instant, Sleep};

pub(crate) struct Recovery {
    timeout: Duration,
    pending: Option<Pending>,
}
struct Pending {
    hard: Instant,
    timer: Pin<Box<Sleep>>,
    first: Box<dyn Error>,
}
impl Recovery {
    pub const fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            pending: None,
        }
    }
    pub fn pending(&self) -> bool {
        self.pending.is_some()
    }
    pub fn first(&self) -> Option<&(dyn Error + 'static)> {
        self.pending.as_ref().map(|p| p.first.as_ref())
    }
    pub fn begin(&mut self, first: Box<dyn Error>) -> Result<(), ProtocolError> {
        if self.pending.is_some() {
            return Ok(());
        }
        let hard = Instant::now()
            .checked_add(self.timeout)
            .ok_or(ProtocolError::Overflow)?;
        self.pending = Some(Pending {
            hard,
            timer: Box::pin(tokio::time::sleep_until(hard)),
            first,
        });
        Ok(())
    }
    pub fn hard(&self) -> Option<Instant> {
        self.pending.as_ref().map(|p| p.hard)
    }
    pub fn poll_expired(&mut self, cx: &mut Context<'_>) -> Option<Box<dyn Error>> {
        let pending = self.pending.as_mut()?;
        if Instant::now() < pending.hard && pending.timer.as_mut().poll(cx).is_pending() {
            return None;
        }
        Some(self.timeout())
    }
    /// The enclosing generation may have an earlier inherited hard bound.
    /// Preserve the original physical cause when that bound ends recovery.
    pub fn timeout(&mut self) -> Box<dyn Error> {
        self.pending.take().map_or_else(
            || Box::new(ProtocolError::Deadline) as Box<dyn Error>,
            |p| Box::new(Timeout { first: p.first }),
        )
    }
    pub fn complete(&mut self) -> Result<(), Box<dyn Error>> {
        if self
            .pending
            .as_ref()
            .is_some_and(|p| Instant::now() >= p.hard)
        {
            return Err(self.timeout());
        }
        self.pending = None;
        Ok(())
    }
    /// Classify the original observation before the caller can poll application
    /// IO. No peer, provider or operation token is reconstructed by this owner.
    pub fn observe<'a>(
        &mut self,
        result: Result<Progress<'a, 1>, PilsError>,
        expected: Identity<'a>,
    ) -> Result<IdentityUpdate<'a>, Box<dyn Error>> {
        match result? {
            Progress::Inbound(Inbound::Identity { identity, .. }) => {
                Ok(IdentityUpdate::Ready(identity))
            }
            Progress::Lost {
                epoch,
                cause,
                report,
            } if cause.is_connection_loss()
                && report.feeds().next().is_none()
                && report.retained() == 0 =>
            {
                self.begin(Box::new(IdentityLoss {
                    epoch: epoch.value(),
                    cause,
                    feeds: 0,
                    retained: 0,
                }))?;
                Ok(IdentityUpdate::Waiting)
            }
            Progress::ConnectRetry { error, .. } => {
                self.begin(Box::new(error))?;
                Ok(IdentityUpdate::Waiting)
            }
            Progress::Connected(epoch) if epoch != expected.epoch() => {
                self.begin(Box::new(ProtocolError::StaleGeneration))?;
                Ok(IdentityUpdate::Waiting)
            }
            Progress::Unavailable(error) => Err(Box::new(error)),
            original @ Progress::Lost { .. } => Err(provider_loss(original)),
            Progress::Closed => Err(Box::new(ProtocolError::Closed)),
            _ => Ok(IdentityUpdate::Activity),
        }
    }
}
#[derive(Debug)]
struct Timeout {
    first: Box<dyn Error>,
}
impl fmt::Display for Timeout {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PILS identity-source recovery deadline expired: {}",
            self.first
        )
    }
}
impl Error for Timeout {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.first.as_ref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert native expiry without depending on another timer-driver turn"
    )]
    fn retries_do_not_replace_the_first_cause_and_late_readiness_is_refused()
    -> Result<(), Box<dyn Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let _entered = runtime.enter();
        let mut recovery = Recovery::new(Duration::ZERO);
        recovery.begin(Box::new(std::io::Error::other("first native source loss")))?;
        let hard = recovery.hard();
        recovery.begin(Box::new(std::io::Error::other("later socket retry")))?;
        assert_eq!(recovery.hard(), hard);
        let error = recovery
            .complete()
            .err()
            .ok_or("late readiness must not clear the bound")?;
        assert_eq!(
            error.source().ok_or("first cause missing")?.to_string(),
            "first native source loss"
        );
        let mut recovery = Recovery::new(Duration::ZERO);
        recovery.begin(Box::new(std::io::Error::other("first physical loss")))?;
        let mut cx = Context::from_waker(std::task::Waker::noop());
        let error = recovery
            .poll_expired(&mut cx)
            .ok_or("native deadline not observed")?;
        assert_eq!(
            error.source().ok_or("first cause missing")?.to_string(),
            "first physical loss"
        );
        assert!(recovery.poll_expired(&mut cx).is_none());
        Ok(())
    }
}
