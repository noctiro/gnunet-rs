//! Generation control owns its original native bound and verified observer token.
use super::{ApplicationSettings, ProtocolError};
use crate::foreground::{Failures, Stage};
use gnunet_cadet_host::{identity_dh, node, signing};
use gnunet_pils::client::Identity;
use std::{future::Future, pin::Pin, task::Context, time::Duration};
use tokio::time::{Instant, Sleep};

#[derive(Debug)]
pub(super) struct StartupFailure {
    pub reason: ProtocolError,
    pub dh: Option<gnunet_cadet_host::Error>,
    pub signing: Option<gnunet_cadet_host::Error>,
}
impl std::fmt::Display for StartupFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "peer startup {}: original DH refusal={:?}; original signing refusal={:?}",
            self.reason, self.dh, self.signing
        )
    }
}
impl std::error::Error for StartupFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.dh
            .as_ref()
            .or(self.signing.as_ref())
            .map(|error| error as &(dyn std::error::Error + 'static))
    }
}

pub(super) struct Bound {
    pub hard: Instant,
    timer: Pin<Box<Sleep>>,
}
impl Bound {
    pub fn at(hard: Instant) -> Self {
        Self {
            hard,
            timer: Box::pin(tokio::time::sleep_until(hard)),
        }
    }
    pub fn after(duration: Duration) -> Result<Self, ProtocolError> {
        Ok(Self::at(
            Instant::now()
                .checked_add(duration)
                .ok_or(ProtocolError::Overflow)?,
        ))
    }
    pub fn poll_expired(&mut self, cx: &mut Context<'_>) -> bool {
        Instant::now() >= self.hard || self.timer.as_mut().poll(cx).is_ready()
    }
}
#[derive(Clone, Copy)]
pub(super) struct Anchor<'p> {
    pub identity: Identity<'p>,
    pub hard: Option<Instant>,
}
pub(super) struct Continuity<'p, 'history> {
    pub anchor: Anchor<'p>,
    pub history: &'history mut gnunet_cadet::statistics::Snapshot,
}
#[expect(
    clippy::large_enum_variant,
    reason = "Return one original verified identity without a fallible allocation at generation retirement"
)]
pub(super) enum Exit<'p> {
    Stopped,
    Replace {
        identity: Identity<'p>,
        hard: Instant,
    },
}
#[expect(
    clippy::large_enum_variant,
    reason = "One startup result retains the original observer token and deadline without allocating on refusal"
)]
pub(super) enum Startup<'p> {
    Ready,
    Stopped,
    Replace {
        identity: Identity<'p>,
        hard: Instant,
    },
}
pub(super) enum Shutdown<'p> {
    Running,
    Replacing {
        latest: Option<Identity<'p>>,
        bound: Bound,
    },
    Grace(Bound),
    Forced(Bound),
}
impl<'p> Shutdown<'p> {
    pub fn running(&self) -> bool {
        matches!(self, Self::Running)
    }
    pub fn replacing(&self) -> bool {
        matches!(self, Self::Replacing { .. })
    }
    pub fn forced(&self) -> bool {
        matches!(self, Self::Forced(_))
    }
    pub fn accepts_stop(&self) -> bool {
        self.running() || self.replacing()
    }
    pub fn poll_expired(&mut self, cx: &mut Context<'_>) -> bool {
        match self {
            Self::Running => false,
            Self::Replacing { bound, .. } | Self::Grace(bound) | Self::Forced(bound) => {
                bound.poll_expired(cx)
            }
        }
    }
    pub fn observe(&mut self, identity: Identity<'p>) {
        if let Self::Replacing { latest, .. } = self {
            *latest = Some(identity);
        }
    }
    pub fn latest(&self) -> Option<Identity<'p>> {
        if let Self::Replacing { latest, .. } = self {
            *latest
        } else {
            None
        }
    }
    pub fn take_replacement(self) -> Option<(Identity<'p>, Instant)> {
        if let Self::Replacing {
            latest: Some(identity),
            bound,
        } = self
        {
            Some((identity, bound.hard))
        } else {
            None
        }
    }
}
pub(super) fn replacement_bound(
    settings: &ApplicationSettings,
    inherited: Option<Instant>,
) -> Result<Bound, ProtocolError> {
    let duration = settings
        .pils_startup_timeout
        .checked_add(settings.peer.forced_drain)
        .ok_or(ProtocolError::Overflow)?;
    let bound = Bound::after(duration)?;
    Ok(Bound::at(
        inherited.map_or(bound.hard, |hard| hard.min(bound.hard)),
    ))
}
pub(super) fn signer_stops_generation<const O: usize>(
    result: &Result<node::SigningProgress<'_, '_, O>, node::Error>,
) -> bool {
    if let Ok(node::SigningProgress::Native(signing::Step::Native(progress))) = result
        && provider_failed(progress)
    {
        return true;
    }
    !matches!(
        result,
        Ok(node::SigningProgress::Progress
            | node::SigningProgress::Native(
                signing::Step::Ready { .. }
                    | signing::Step::Retired { .. }
                    | signing::Step::Native(_)
            ))
    )
}
fn provider_failed<const O: usize>(progress: &gnunet_pils_host::client::Progress<'_, O>) -> bool {
    use gnunet_pils_host::client::Progress;
    matches!(
        progress,
        Progress::Unavailable(_)
            | Progress::ConnectRetry { .. }
            | Progress::Lost { .. }
            | Progress::Closed
    )
}
/// Only typed actual key/identity observations request replacement. Other source
/// errors stay failures; a generic Authentication error is never guessed to be
/// a benign address update. A hint itself grants no observer identity.
pub(super) fn source_hint<const O: usize>(
    sign: &mut Option<Result<node::SigningProgress<'_, '_, O>, node::Error>>,
    node: &mut Option<Result<node::Step<'_, '_, '_, '_, O>, node::Error>>,
    retiring: bool,
    failures: &mut Failures,
) -> bool {
    let mut hint = false;
    if let Some(Ok(node::SigningProgress::Native(step))) = sign {
        match step {
            signing::Step::IdentityChanged {
                same_epoch: true, ..
            }
            | signing::Step::KeyChanged { .. } => hint = true,
            signing::Step::IdentityChanged {
                same_epoch: false, ..
            } => failures.record(Stage::Identity, Box::new(ProtocolError::StaleGeneration)),
            signing::Step::Closed(reason)
            | signing::Step::Stopped { reason, .. }
            | signing::Step::Rejected { reason, .. }
                if !retiring =>
            {
                failures.record(Stage::Peer, Box::new(*reason))
            }
            _ => {}
        }
    }
    if let Some(Ok(node::Step::IdentityDh(step))) = node {
        match step {
            identity_dh::Step::IdentityChanged {
                same_epoch: true, ..
            }
            | identity_dh::Step::KeyChanged { .. } => hint = true,
            identity_dh::Step::IdentityChanged {
                same_epoch: false, ..
            } => failures.record(Stage::Identity, Box::new(ProtocolError::StaleGeneration)),
            identity_dh::Step::Closed(reason) | identity_dh::Step::Rejected { reason, .. }
                if !retiring =>
            {
                failures.record(Stage::Peer, Box::new(*reason))
            }
            _ => {}
        }
    }
    if matches!(
        sign,
        Some(Ok(node::SigningProgress::Native(
            signing::Step::Lost { .. }
        )))
    ) && let Some(Ok(node::SigningProgress::Native(signing::Step::Lost { original, .. }))) =
        sign.take()
    {
        failures.record(Stage::Peer, crate::identity::provider_loss(original));
    }
    if matches!(
        node,
        Some(Ok(node::Step::IdentityDh(identity_dh::Step::Lost { .. })))
    ) && let Some(Ok(node::Step::IdentityDh(identity_dh::Step::Lost { original, .. }))) =
        node.take()
    {
        failures.record(Stage::Peer, crate::identity::provider_loss(original));
    }
    if let Some(Ok(node::SigningProgress::Native(signing::Step::Native(progress)))) = sign
        && provider_failed(progress)
        && let Some(Ok(node::SigningProgress::Native(signing::Step::Native(original)))) =
            sign.take()
    {
        failures.record(Stage::Peer, crate::identity::provider_loss(original));
    }
    if let Some(Ok(node::Step::IdentityDh(identity_dh::Step::Native(progress)))) = node
        && provider_failed(progress)
        && let Some(Ok(node::Step::IdentityDh(identity_dh::Step::Native(original)))) = node.take()
    {
        failures.record(Stage::Peer, crate::identity::provider_loss(original));
    }
    if matches!(
        node,
        Some(Ok(node::Step::Core(
            gnunet_cadet_host::connection::Step::IdentityMismatch { .. }
        )))
    ) {
        hint = true;
    }
    hint
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert the original native hard bound despite deliberate starvation of the runtime timer driver"
    )]
    fn native_bound_expires_without_another_timer_driver_turn()
    -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let mut original = Bound::after(Duration::from_millis(2))?;
            let hard = original.hard;
            // Deliberately keep the sole runtime driver from taking a turn.
            // The actual native hard target must still expire on the next poll.
            std::thread::sleep(Duration::from_millis(8));
            let mut cx = Context::from_waker(std::task::Waker::noop());
            assert!(original.poll_expired(&mut cx));
            assert_eq!(original.hard, hard);
            Ok::<(), ProtocolError>(())
        })?;
        Ok(())
    }
}
