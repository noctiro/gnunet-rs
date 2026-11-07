//! Local-only application composition. No peer job or backend is constructed.
use crate::{
    foreground::{Diagnostics, Failures, Ready, Stage},
    identity::{self, Dependencies},
    settings::Settings,
};
use gnunet_cadet_host::server::{Progress, Server};
use gnunet_pils::client::Identity;
use gnunet_program_host::reporting::Reporter;
use gnunet_service_runtime::service::Listener;
use std::{
    error::Error,
    future::{Future, poll_fn},
    io,
    task::Poll,
};

fn reject_one_remote(
    server: &mut Server<'_, '_, '_>,
    reporter: &Reporter,
) -> Result<(), Box<dyn Error>> {
    // This foreground has not constructed any peer/CORE job. Original open
    // failure is therefore real and can retire without a fake backend receipt.
    if let Some(open) = server.canceling_open().or_else(|| server.next_open()) {
        reporter.warning("cadet.remote.unavailable",format_args!("cadet remote-open original={:?} peer-backend=unavailable; no-peer-core-job-started=true",open.channel()));
        server.open_failed(open)?;
    }
    Ok(())
}
/// Retire only effects which this composition knows never had a peer job.
/// The pure owner's barrier independently refuses outstanding real bindings.
fn apply_identity(
    server: &mut Server<'_, '_, '_>,
    peer: [u8; 32],
    channels: usize,
    reporter: &Reporter,
) -> Result<(), Box<dyn Error>> {
    server.retire_identity_channels()?;
    finish(server, channels, reporter)?;
    server.rebind_local_peer(peer)?;
    Ok(())
}

pub(super) async fn run<'p>(
    settings: &Settings,
    listeners: &[Listener<'_>],
    dependencies: &mut Dependencies<'p, '_>,
    mut identity: Identity<'p>,
    server: &mut Server<'_, '_, '_>,
    ready: &mut Ready<'_>,
    failures: &mut Failures,
) -> Result<(), Box<dyn Error>> {
    let reporter = dependencies.reporter.clone();
    let mut diagnostics = Diagnostics::new(reporter.clone());
    if let Err(error) = ready.announce(*identity.peer().as_bytes(), None) {
        failures.record(Stage::Output, Box::new(error));
    }
    while failures.is_empty() {
        let mut stopping = None;
        let mut pils_result = None;
        let mut resolver_result = None;
        let mut native_result = None;
        {
            let mut observing = std::pin::pin!(dependencies.pils.drive(None));
            let mut resolving = std::pin::pin!(
                dependencies
                    .resolver
                    .drive_waiting(None, |event| identity::resolver_event(&reporter, event))
            );
            poll_fn(|cx| {
                // Diagnostic failure wakes and follows the same original stop.
                reporter.register(cx);
                if reporter.failed() {
                    stopping = Some(Ok(()));
                    return Poll::Ready(());
                }
                // Process controls cannot be starved by always-ready app IPC.
                if let Poll::Ready(result) = dependencies.signals.poll(cx) {
                    stopping = Some(result);
                    return Poll::Ready(());
                }
                dependencies.statistics.observe(&server.statistics());
                let stats_progress = dependencies.statistics.poll(cx).is_ready();
                if reporter.failed() {
                    dependencies.statistics.abort();
                    stopping = Some(Ok(()));
                    return Poll::Ready(());
                }
                if let Poll::Ready(result) = observing.as_mut().poll(cx) {
                    let fatal = Dependencies::fatal(&result, identity);
                    pils_result = Some(result);
                    if fatal {
                        return Poll::Ready(());
                    }
                }
                if let Poll::Ready(result) = resolving.as_mut().poll(cx) {
                    let fatal = result.is_err();
                    resolver_result = Some(result);
                    if fatal {
                        return Poll::Ready(());
                    }
                }
                if reporter.failed() {
                    stopping = Some(Ok(()));
                    return Poll::Ready(());
                }
                if let Poll::Ready(result) =
                    server.poll(cx, listeners, None, &mut |event| diagnostics.observe(event))
                {
                    native_result = Some(result);
                }
                if pils_result.is_some()
                    || resolver_result.is_some()
                    || native_result.is_some()
                    || stats_progress
                {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
        // All driving futures/borrows have ended before any resource refusal
        // retires its physical MQ; the callback is never reentered.
        diagnostics.retire_refusal(server, failures);
        dependencies.native_resolver_diagnostics();
        if let Some(result) = stopping {
            if let Err(error) = result {
                failures.record(Stage::Control, Box::new(error));
            }
            break;
        }
        if let Some(result) = pils_result
            && let Some(observed) = dependencies.observe_identity_update(result, identity, failures)
        {
            if observed.peer() != identity.peer() {
                let changed = apply_identity(
                    server,
                    *observed.peer().as_bytes(),
                    settings.channels,
                    &reporter,
                );
                if let Err(error) = changed {
                    failures.record(Stage::Identity, error);
                }
            }
            if failures.is_empty() {
                identity = observed;
            }
        }
        if let Some(Err(error)) = resolver_result {
            failures.record(Stage::Resolver, Box::new(error));
        }
        match native_result {
            Some(Err(error)) => failures.record(Stage::Application, Box::new(error)),
            Some(Ok(Progress::Stopped)) => break,
            _ => {}
        }
        if failures.is_empty()
            && !reporter.failed()
            && let Err(error) = reject_one_remote(server, &reporter)
        {
            failures.record(Stage::Application, error);
        }
    }
    Ok(())
}

pub(super) fn finish(
    server: &mut Server<'_, '_, '_>,
    channels: usize,
    reporter: &Reporter,
) -> Result<(), Box<dyn Error>> {
    for _ in 0..channels {
        if server.canceling_open().is_none() {
            break;
        }
        reject_one_remote(server, reporter)?;
    }
    if !server.identity_channels_retired() {
        return Err(io::Error::other("original cleanup effect remains; no backend was configured and no remote drain is claimed").into());
    }
    Ok(())
}
