//! Verify replacement startup owners under the original generation bound.
use super::{ApplicationSettings, ProtocolError, config::PILS_OPERATIONS, lifecycle};
use crate::{
    foreground::{Failures, Stage},
    identity::{self, Dependencies, IdentityUpdate},
};
use gnunet_cadet_host::{identity_dh as dh, signing, time::Timebase};
use gnunet_pils::client::Inbound;
use gnunet_pils_host::client::Progress as PilsProgress;
use lifecycle::{Anchor, Startup};
use std::{
    error::Error,
    future::{Future, poll_fn},
    task::Poll,
};

enum StartupProgress {
    Ready,
    Activity,
    Lost(Box<dyn Error>),
}
fn startup_progress<const O: usize>(
    progress: Result<PilsProgress<'_, O>, gnunet_cadet_host::Error>,
) -> Result<StartupProgress, Box<dyn Error>> {
    match progress? {
        PilsProgress::Inbound(Inbound::Identity { .. }) => Ok(StartupProgress::Ready),
        original @ PilsProgress::Lost { .. } => {
            let recoverable = lifecycle::provider_recoverable(&original);
            let cause = identity::provider_loss(original);
            if recoverable {
                Ok(StartupProgress::Lost(cause))
            } else {
                Err(cause)
            }
        }
        PilsProgress::Unavailable(error) => Err(Box::new(error)),
        PilsProgress::Closed => Err(ProtocolError::Closed.into()),
        _ => Ok(StartupProgress::Activity),
    }
}
fn stop_startup(
    dh: &mut dh::Connecting<'_, PILS_OPERATIONS>,
    signer: &mut signing::Connecting<'_, PILS_OPERATIONS>,
    failures: &mut Failures,
) {
    let dh_retired = dh.close();
    let signing_retired = signer.close();
    if dh_retired
        .iter()
        .chain(signing_retired.iter())
        .any(Option::is_some)
    {
        failures.record(Stage::PeerCleanup, Box::new(ProtocolError::Conflict));
    }
}
/// Retain both original connecting owners while polling the same observer,
/// resolver and process controls. No operation is submitted before verification.
pub(super) async fn run<'p>(
    dh: &mut dh::Connecting<'_, PILS_OPERATIONS>,
    signer: &mut signing::Connecting<'_, PILS_OPERATIONS>,
    dependencies: &mut Dependencies<'p, '_>,
    anchor: Anchor<'p>,
    timebase: &Timebase,
    settings: &ApplicationSettings,
    failures: &mut Failures,
) -> Result<Startup<'p>, Box<dyn Error>> {
    let Anchor {
        identity,
        hard: recovery_hard,
    } = anchor;
    let delay = u64::try_from(settings.pils_startup_timeout.as_micros())
        .map_err(|_| ProtocolError::Overflow)?;
    let target = timebase
        .sample()?
        .monotonic
        .after(gnunet_types::Duration(delay))?;
    // Freeze the local startup target once in the same native epoch. Logical
    // corrections cannot renew it, and source refusals remain independent.
    let startup_hard = timebase.native_bound(target)?;
    let hard = recovery_hard.map_or(startup_hard, |hard| hard.min(startup_hard));
    let mut limit = std::pin::pin!(tokio::time::sleep_until(hard));
    let mut dh_ready = false;
    let mut signer_ready = false;
    let mut mismatch = false;
    let mut refusals = lifecycle::StartupFailure {
        reason: ProtocolError::Deadline,
        dh: None,
        signing: None,
    };
    let reporter = dependencies.reporter.clone();
    while !(dh_ready && signer_ready) {
        let mut stop = None;
        let mut expired = None;
        let mut observer = None;
        let mut resolver = None;
        let mut dh_result = None;
        let mut sign_result = None;
        {
            let mut identity_work = std::pin::pin!(dependencies.pils.drive(None));
            let mut resolving = std::pin::pin!(
                dependencies
                    .resolver
                    .drive_waiting(None, |event| identity::resolver_event(&reporter, event))
            );
            poll_fn(|cx| {
                reporter.register(cx);
                if reporter.failed() {
                    stop = Some(Ok(()));
                    return Poll::Ready(());
                }
                if let Poll::Ready(result) = dependencies.signals.poll(cx) {
                    stop = Some(result);
                    return Poll::Ready(());
                }
                let guarded = dependencies.statistics.native_guard(cx).is_ready();
                if reporter.failed() {
                    dependencies.statistics.abort();
                    stop = Some(Ok(()));
                    return Poll::Ready(());
                }
                if guarded {
                    return Poll::Ready(());
                }
                if let Some(cause) = dependencies.observer_recovery.poll_expired(cx) {
                    failures.record(Stage::Identity, cause);
                    return Poll::Ready(());
                }
                if let Err(reason) = timebase.sample() {
                    expired = Some(Err(reason));
                    return Poll::Ready(());
                }
                if limit.as_mut().poll(cx).is_ready() {
                    expired = Some(Ok(()));
                    return Poll::Ready(());
                }
                let stats_progress = dependencies.statistics.poll(cx).is_ready();
                if reporter.failed() {
                    dependencies.statistics.abort();
                    stop = Some(Ok(()));
                    return Poll::Ready(());
                }
                if let Poll::Ready(result) = identity_work.as_mut().poll(cx) {
                    let fatal = Dependencies::fatal(&result, identity);
                    observer = Some(result);
                    if fatal {
                        return Poll::Ready(());
                    }
                }
                if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                    let fatal = result.is_err();
                    resolver = Some(result);
                    if fatal {
                        return Poll::Ready(());
                    }
                }
                if reporter.failed() {
                    stop = Some(Ok(()));
                    return Poll::Ready(());
                }
                if !mismatch
                    && !dh_ready
                    && let Poll::Ready(result) = dh.poll(cx, None)
                {
                    dh_result = Some(result);
                }
                if !mismatch
                    && !signer_ready
                    && let Poll::Ready(result) = signer.poll(cx, None)
                {
                    sign_result = Some(result);
                }
                if stats_progress
                    || observer.is_some()
                    || resolver.is_some()
                    || dh_result.is_some()
                    || sign_result.is_some()
                {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
        dependencies.native_resolver_diagnostics();
        if let Some(result) = stop {
            result?;
            return Ok(Startup::Stopped);
        }
        if let Some(result) = expired {
            if result.is_ok() && dependencies.observer_recovery.pending() {
                return Err(dependencies.observer_recovery.timeout());
            }
            if let Err(reason) = result {
                refusals.reason = reason;
            }
            return Err(Box::new(refusals));
        }
        if let Some(result) = observer {
            match dependencies.observe_identity_update(result, identity, failures) {
                IdentityUpdate::Ready(observed)
                    if observed.peer() != identity.peer()
                        || observed.epoch() != identity.epoch()
                        || mismatch && observed != identity =>
                {
                    return Ok(Startup::Replace {
                        identity: observed,
                        hard: dependencies
                            .identity_recovery_hard()
                            .map_or(hard, |at| hard.min(at)),
                    });
                }
                IdentityUpdate::Waiting => {
                    stop_startup(dh, signer, failures);
                    mismatch = true;
                    dh_ready = false;
                    signer_ready = false;
                }
                _ => {}
            }
        }
        if let Some(Err(error)) = resolver {
            failures.record(Stage::Resolver, Box::new(error));
        }
        if !failures.is_empty() || reporter.failed() {
            return Err(ProtocolError::Closed.into());
        }
        let mut source_lost = false;
        if let Some(result) = dh_result {
            if dh.identity_mismatch().is_some() {
                mismatch = true;
                if let Err(error) = result {
                    refusals.dh = Some(error);
                }
            } else {
                match startup_progress(result)? {
                    StartupProgress::Ready => dh_ready = true,
                    StartupProgress::Lost(cause) => {
                        dependencies.begin_observer_recovery(cause, failures);
                        source_lost = true;
                    }
                    StartupProgress::Activity => {}
                }
            }
        }
        if let Some(result) = sign_result {
            if signer.identity_mismatch().is_some() {
                mismatch = true;
                if let Err(error) = result {
                    refusals.signing = Some(error);
                }
            } else {
                match startup_progress(result)? {
                    StartupProgress::Ready => signer_ready = true,
                    StartupProgress::Lost(cause) => {
                        dependencies.begin_observer_recovery(cause, failures);
                        source_lost = true;
                    }
                    StartupProgress::Activity => {}
                }
            }
        }
        if mismatch || source_lost {
            stop_startup(dh, signer, failures);
            dh_ready = false;
            signer_ready = false;
            mismatch = true;
            if source_lost && let Some(observed) = dependencies.pils.identity() {
                return Ok(Startup::Replace {
                    identity: observed,
                    hard: dependencies
                        .identity_recovery_hard()
                        .map_or(hard, |at| hard.min(at)),
                });
            }
        }
    }
    Ok(Startup::Ready)
}
