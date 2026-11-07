//! Actual standard SERVICE DV assembly. All branded domains, Source, fixed
//! slots and plaintext loans live in this async caller scope, never inside a
//! self-referential owner or an implicitly spawned runtime task.
use crate::{
    Failure, Failures,
    dv_control::{Receipts, Service, Turn},
    dv_driver::{Driver, Signal},
    dv_epoch::Bootstrap,
    dv_schedule::Scheduler,
    generation::Reservations,
    owner::{Owner, TransportContext},
    sender::DvScope,
};
use gnunet_client_host::EndpointSource;
use gnunet_crypto::Entropy;
use gnunet_transport::PeerId;
use gnunet_transport_dv_bridge_host::{Actor, Bridge};
use gnunet_transport_dv_crypto::Instance as CryptoInstance;
use gnunet_transport_dv_runtime_host as runtime;
use gnunet_transport_dv_store_host as store;
use gnunet_types::Error;
use std::{
    future::{Future, poll_fn},
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;
/// Completed source supervision; no original native/crypto token escapes.
pub(crate) struct Outcome {
    pub(crate) result: Result<(), Failure>,
    pub(crate) allow_restart: bool,
}
/// This exact startup boundary preserves its original typed cause and source
/// chain; independent retirement/join failures remain in Epoch.cleanup.
#[derive(Debug)]
struct BridgeAdmissionFailure {
    original: Failure,
}
impl std::fmt::Display for BridgeAdmissionFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TRANSPORT DV bridge admission: {}", self.original)
    }
}
impl std::error::Error for BridgeAdmissionFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.original.as_ref())
    }
}
enum Exit {
    Rotate,
    Lost(Failure),
    Stop,
    Control(Failure),
    Fatal(Failure),
}
struct Epoch {
    exit: Exit,
    cleanup: Vec<Failure>,
    safe: bool,
}
fn stopped(cleanup: Vec<Failure>) -> Outcome {
    Outcome {
        result: if cleanup.is_empty() {
            Ok(())
        } else {
            Err(Box::new(Failures {
                original: None,
                cleanup,
            }))
        },
        allow_restart: false,
    }
}
fn failure(original: Failure, cleanup: Vec<Failure>, allow_restart: bool) -> Outcome {
    Outcome {
        result: Err(Box::new(Failures {
            original: Some(original),
            cleanup,
        })),
        allow_restart,
    }
}
fn observe_store(reports: &crate::foreground::Reports, event: store::Event<'_>) {
    // The actual provider already owns/applies its original receipt. Reporting
    // a returned event does not convert canceled/Unknown work into committed.
    reports.diagnostic(format_args!(
        "TRANSPORT DV original provider event: {event:?}"
    ));
}
fn report_shutdown(report: store::Shutdown, cleanup: &mut Vec<Failure>) -> bool {
    let mut clean = true;
    if let Some(error) = report.validation {
        cleanup.push(Box::new(error));
        clean = false;
    }
    match report.worker {
        Err(error) => {
            cleanup.push(Box::new(error));
            clean = false;
        }
        Ok(stopped) => {
            if let Some(error) = stopped.failure {
                cleanup.push(Box::new(error));
                clean = false;
            }
        }
    }
    if let Some(error) = report.original {
        cleanup.push(Box::new(error));
        clean = false;
    }
    clean
}
/// Driverless phase has no attached DV Source, so the same standard native
/// path is used while real Owner/PILS/Resolver/statistics/signals advance.
fn standard<'id, E: Entropy>(
    cx: &mut std::task::Context<'_>,
    context: TransportContext<'_, 'id, E>,
) -> Poll<Result<gnunet_transport_host::Step, Failure>> {
    context.poll_standard(cx)
}
/// Explicit join before a Runtime was adopted. No constructor failure can hide
/// the qualified Provider's real shutdown report behind a destructor.
async fn join_unadopted<'id, 'owner, E: Entropy>(
    provider: &mut store::Provider<'id>,
    service: &mut Service<'_, '_, '_>,
    owner: &mut Owner<'owner, E>,
    reservations: &mut Reservations,
    notes: &mut Receipts<'owner>,
    cleanup: &mut Vec<Failure>,
) -> bool {
    provider.request_stop();
    let reports = service.reports.clone();
    let shutdown = provider.shutdown(|event| observe_store(&reports, event));
    let mut shutdown = std::pin::pin!(shutdown);
    let mut owner_failed = owner.is_stopped();
    loop {
        let mut actual = None;
        let turn = poll_fn(|cx| {
            // Never consume an actual worker result then replace it with an
            // unrelated socket/Resolver failure in this same poll.
            if let Poll::Ready(report) = shutdown.as_mut().poll(cx) {
                actual = Some(report);
                return Poll::Ready(Ok(true));
            }
            let control = if owner_failed {
                service
                    .poll_cleanup(cx)
                    .map(|result| result.map(|_| Turn::Activity))
            } else {
                service.poll(cx, owner, reservations, notes, &mut standard)
            };
            while let Some(event) = notes.pop() {
                notes.reports.observe(event);
            }
            match control {
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(Turn::Stop)) => {
                    cleanup.extend(owner.stop(&mut |event| notes.observe(event)));
                    owner_failed = true;
                    Poll::Ready(Ok(false))
                }
                Poll::Ready(Ok(Turn::Activity)) => Poll::Ready(Ok(false)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;
        match turn {
            Ok(true) => return actual.is_some_and(|report| report_shutdown(report, cleanup)),
            Ok(false) => tokio::task::yield_now().await,
            Err(error) => {
                cleanup.push(error);
                cleanup.extend(owner.stop(&mut |event| notes.observe(event)));
                owner_failed = true;
            }
        }
    }
}
/// Setup failed before any Actor IO was admitted. Its original Provider join
/// is still real and fair to the same process ports; no constructor destructor
/// or optimistic future cancellation is used as a shutdown receipt.
async fn join_setup<'id, 'source, 'pils, 'slots, 'out, 'owner, E: Entropy>(
    actor: &mut Actor<'id, 'source, 'pils, 'slots, 'out>,
    service: &mut Service<'_, '_, '_>,
    owner: &mut Owner<'owner, E>,
    reservations: &mut Reservations,
    notes: &mut Receipts<'owner>,
    cleanup: &mut Vec<Failure>,
) -> bool {
    actor.close();
    let reports = service.reports.clone();
    let shutdown = actor.shutdown(|event| observe_store(&reports, event));
    let mut shutdown = std::pin::pin!(shutdown);
    loop {
        let mut actual = None;
        let turn = poll_fn(|cx| {
            if let Poll::Ready(report) = shutdown.as_mut().poll(cx) {
                actual = Some(report);
                return Poll::Ready(Ok(true));
            }
            let control = if owner.is_stopped() {
                service
                    .poll_cleanup(cx)
                    .map(|result| result.map(|_| Turn::Activity))
            } else {
                service.poll(cx, owner, reservations, notes, &mut standard)
            };
            while let Some(event) = notes.pop() {
                notes.reports.observe(event);
            }
            match control {
                Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                Poll::Ready(Ok(Turn::Stop)) => {
                    cleanup.extend(owner.stop(&mut |event| notes.observe(event)));
                    Poll::Ready(Ok(false))
                }
                Poll::Ready(Ok(Turn::Activity)) => Poll::Ready(Ok(false)),
                Poll::Pending => Poll::Pending,
            }
        })
        .await;
        match turn {
            Ok(true) => return actual.is_some_and(|report| report_shutdown(report, cleanup)),
            Ok(false) => tokio::task::yield_now().await,
            Err(error) => {
                cleanup.push(error);
                cleanup.extend(owner.stop(&mut |event| notes.observe(event)));
            }
        }
    }
}
/// Real same-process sources are rebuilt only after their original physical
/// work/provider joins settled. Read-only bootstrap retries are fresh sources;
/// old mutation/frame/range/nonce operations are never replayed.
pub(crate) async fn serve<'owner, E: Entropy, P: Entropy>(
    service: &mut Service<'_, '_, '_>,
    owner: &mut Owner<'owner, E>,
    reservations: &mut Reservations,
    endpoint: &EndpointSource,
    entropy: &mut P,
) -> Outcome {
    let mut recent = Vec::new();
    if let Err(_error) = recent.try_reserve_exact(32) {
        return failure(Box::new(Error::Capacity), Vec::new(), false);
    }
    let mut failures = 0u32;
    loop {
        let mut notes = match Receipts::new(service.reports.clone()) {
            Ok(notes) => notes,
            Err(error) => return failure(Box::new(error), recent, false),
        };
        if service.stop_requested() {
            loop {
                let result =
                    poll_fn(|cx| service.poll(cx, owner, reservations, &mut notes, &mut standard))
                        .await;
                while let Some(event) = notes.pop() {
                    notes.reports.observe(event);
                }
                match result {
                    Ok(Turn::Stop) => return stopped(recent),
                    Ok(Turn::Activity) => tokio::task::yield_now().await,
                    Err(error) => return failure(error, recent, owner.native_restart_requested()),
                }
            }
        }
        let epoch = epoch(service, owner, reservations, endpoint, entropy, &mut notes).await;
        while let Some(event) = notes.pop() {
            notes.reports.observe(event);
        }
        match epoch.exit {
            Exit::Stop => {
                recent.extend(epoch.cleanup);
                return stopped(recent);
            }
            Exit::Control(error) => {
                recent.extend(epoch.cleanup);
                return failure(
                    error,
                    recent,
                    epoch.safe && owner.native_restart_requested(),
                );
            }
            Exit::Fatal(error) => {
                recent.extend(epoch.cleanup);
                return failure(error, recent, false);
            }
            Exit::Rotate if epoch.safe && epoch.cleanup.is_empty() => {
                failures = 0;
                recent.clear();
                continue;
            }
            Exit::Rotate => {
                recent.extend(epoch.cleanup);
                return failure(Box::new(Error::OutcomeUnknown), recent, false);
            }
            Exit::Lost(error) if epoch.safe && epoch.cleanup.is_empty() => {
                service.reports.diagnostic(format_args!(
                    "TRANSPORT original DV source retired: {error}"
                ));
                if recent.len() == 32 {
                    return failure(error, recent, false);
                }
                recent.push(error);
                failures = failures.saturating_add(1);
            }
            Exit::Lost(error) => {
                recent.extend(epoch.cleanup);
                return failure(error, recent, false);
            }
        }
        if service.stop_requested() {
            continue;
        }
        let delay = Duration::from_millis(100u64.checked_shl(failures.min(8)).unwrap_or(25_600));
        let target = match Instant::now().checked_add(delay) {
            Some(target) => target,
            None => return failure(Box::new(Error::Overflow), recent, false),
        };
        let mut timer = std::pin::pin!(tokio::time::sleep_until(target));
        loop {
            let result = poll_fn(|cx| {
                let control = service.poll(cx, owner, reservations, &mut notes, &mut standard);
                if let Poll::Ready(Err(error)) = control {
                    return Poll::Ready(Err(error));
                }
                if matches!(control, Poll::Ready(Ok(Turn::Stop))) {
                    return Poll::Ready(Ok(true));
                }
                if timer.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Ok(false));
                }
                if control.is_ready() {
                    Poll::Ready(Ok(false))
                } else {
                    Poll::Pending
                }
            })
            .await;
            while let Some(event) = notes.pop() {
                notes.reports.observe(event);
            }
            match result {
                Err(error) => return failure(error, recent, owner.native_restart_requested()),
                Ok(true) => return stopped(recent),
                Ok(false) if Instant::now() >= target => break,
                Ok(false) => tokio::task::yield_now().await,
            }
        }
    }
}
async fn epoch<'owner, E: Entropy, P: Entropy>(
    service: &mut Service<'_, '_, '_>,
    owner: &mut Owner<'owner, E>,
    reservations: &mut Reservations,
    endpoint: &EndpointSource,
    entropy: &mut P,
    notes: &mut Receipts<'owner>,
) -> Epoch {
    let mut cleanup = Vec::new();
    let runtime_id = runtime::Instance::new();
    let crypto_id = CryptoInstance::new();
    let route_id = gnunet_transport::dv::routes::Instance::new();
    let mut pils_id = gnunet_pils::client::Instance::new();
    // Qualification/open is an explicit synchronous OS startup boundary. It
    // occurs before this DV client's initial/source targets are minted; no
    // claim of forcibly canceling an OS open/fsync is made.
    let mut provider = match store::Provider::open(
        &service.settings.dv.store,
        store::Limits {
            records: service.settings.dv.records,
        },
    ) {
        Ok(provider) => Some(provider),
        Err(error) => {
            return Epoch {
                exit: Exit::Fatal(Box::new(error)),
                cleanup,
                safe: false,
            };
        }
    };
    let boot = endpoint
        .duplicate()
        .map_err(|error| Box::new(error) as Failure)
        .and_then(|endpoint| Bootstrap::new(&mut pils_id, endpoint, service.settings));
    let mut bootstrap = match boot {
        Ok(bootstrap) => bootstrap,
        Err(error) => {
            if let Some(provider) = &mut provider {
                let _clean =
                    join_unadopted(provider, service, owner, reservations, notes, &mut cleanup)
                        .await;
            }
            return Epoch {
                exit: Exit::Fatal(error),
                cleanup,
                safe: false,
            };
        }
    };
    let ready = loop {
        let mut actual = None;
        let result = poll_fn(|cx| {
            let control = service.poll(cx, owner, reservations, notes, &mut standard);
            if let Poll::Ready(Err(error)) = control {
                return Poll::Ready(Err((Exit::Control(error), false)));
            }
            if matches!(control, Poll::Ready(Ok(Turn::Stop))) {
                return Poll::Ready(Err((Exit::Stop, true)));
            }
            match bootstrap.poll(cx, owner) {
                Poll::Ready(Ok(ready)) => {
                    actual = Some(ready);
                    Poll::Ready(Ok(true))
                }
                Poll::Ready(Err(error)) => Poll::Ready(Err((Exit::Lost(error), true))),
                Poll::Pending => {
                    if control.is_ready() {
                        Poll::Ready(Ok(false))
                    } else {
                        Poll::Pending
                    }
                }
            }
        })
        .await;
        while let Some(event) = notes.pop() {
            notes.reports.observe(event);
        }
        match result {
            Ok(true) => match actual {
                Some(ready) => break ready,
                None => {
                    bootstrap.close();
                    if let Some(provider) = &mut provider {
                        let _clean = join_unadopted(
                            provider,
                            service,
                            owner,
                            reservations,
                            notes,
                            &mut cleanup,
                        )
                        .await;
                    }
                    return Epoch {
                        exit: Exit::Fatal(Box::new(Error::OutcomeUnknown)),
                        cleanup,
                        safe: false,
                    };
                }
            },
            Ok(false) => tokio::task::yield_now().await,
            Err((exit, safe)) => {
                bootstrap.close();
                let joined = match &mut provider {
                    Some(provider) => {
                        join_unadopted(provider, service, owner, reservations, notes, &mut cleanup)
                            .await
                    }
                    None => false,
                };
                return Epoch {
                    exit,
                    cleanup,
                    safe: safe && joined,
                };
            }
        }
    };
    let identity = ready.identity();
    let (mut client, scope, original) = ready.into_parts();
    if Instant::now() >= original.hard || owner.dv_scope().as_ref() != Some(&scope) {
        let _closed = client.close();
        let joined = match &mut provider {
            Some(provider) => {
                join_unadopted(provider, service, owner, reservations, notes, &mut cleanup).await
            }
            None => false,
        };
        return Epoch {
            exit: Exit::Rotate,
            cleanup,
            safe: joined,
        };
    }
    let times = match owner.dv_times(&scope) {
        Ok(times) => times,
        Err(error) => {
            let _closed = client.close();
            let joined = match &mut provider {
                Some(provider) => {
                    join_unadopted(provider, service, owner, reservations, notes, &mut cleanup)
                        .await
                }
                None => false,
            };
            return Epoch {
                exit: Exit::Control(Box::new(error)),
                cleanup,
                safe: joined,
            };
        }
    };
    let source = match crypto_id.source(
        PeerId(*identity.peer().as_bytes()),
        times.absolute().as_micros(),
        original.expires.min(identity.expiration().as_micros()),
    ) {
        Ok(source) => source,
        Err(error) => {
            let _closed = client.close();
            let joined = match &mut provider {
                Some(provider) => {
                    join_unadopted(provider, service, owner, reservations, notes, &mut cleanup)
                        .await
                }
                None => false,
            };
            return Epoch {
                exit: Exit::Fatal(Box::new(error)),
                cleanup,
                safe: joined,
            };
        }
    };
    // Source and all domains precede Pools. Actor only BORROWS these externally
    // stable slots/loans through this async scope; no self-reference or leak.
    let mut pools = match crate::dv_resources::Pools::new(service.settings.dv.pools) {
        Ok(pools) => pools,
        Err(error) => {
            source.retire();
            let _closed = client.close();
            if let Some(provider) = &mut provider {
                let _joined =
                    join_unadopted(provider, service, owner, reservations, notes, &mut cleanup)
                        .await;
            }
            return Epoch {
                exit: Exit::Fatal(Box::new(error)),
                cleanup,
                safe: false,
            };
        }
    };
    let storage = match pools.storage() {
        Ok(storage) => storage,
        Err(error) => {
            source.retire();
            let _closed = client.close();
            if let Some(provider) = &mut provider {
                let _joined =
                    join_unadopted(provider, service, owner, reservations, notes, &mut cleanup)
                        .await;
            }
            return Epoch {
                exit: Exit::Fatal(Box::new(error)),
                cleanup,
                safe: false,
            };
        }
    };
    if Instant::now() >= original.hard {
        source.retire();
        let _closed = client.close();
        let joined = match &mut provider {
            Some(provider) => {
                join_unadopted(provider, service, owner, reservations, notes, &mut cleanup).await
            }
            None => false,
        };
        return Epoch {
            exit: Exit::Lost(Box::new(Error::Deadline)),
            cleanup,
            safe: joined,
        };
    }
    let mut limits = service.settings.dv.actor;
    let Some(remaining) = original
        .hard
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
    else {
        source.retire();
        let _closed = client.close();
        let joined = match &mut provider {
            Some(provider) => {
                join_unadopted(provider, service, owner, reservations, notes, &mut cleanup).await
            }
            None => false,
        };
        return Epoch {
            exit: Exit::Lost(Box::new(Error::Deadline)),
            cleanup,
            safe: joined,
        };
    };
    limits.source = remaining;
    limits.input = service.settings.pils.input;
    limits.retirement_grace = service.settings.pils.retire;
    let runtime = runtime::Runtime::try_new(
        &runtime_id,
        &source,
        &route_id,
        client,
        &mut provider,
        owner.dv_clock(),
        storage,
        limits,
    );
    let mut actor = match runtime {
        Ok(actor) => actor,
        Err(error) => {
            source.retire();
            if let Some(provider) = &mut provider {
                let _joined =
                    join_unadopted(provider, service, owner, reservations, notes, &mut cleanup)
                        .await;
            }
            return Epoch {
                exit: Exit::Fatal(Box::new(error)),
                cleanup,
                safe: false,
            };
        }
    };
    if let Err(error) = actor.restrict_source_hard(original.hard) {
        let clean = join_setup(
            &mut actor,
            service,
            owner,
            reservations,
            notes,
            &mut cleanup,
        )
        .await;
        return Epoch {
            exit: Exit::Lost(Box::new(error)),
            cleanup,
            safe: clean,
        };
    }
    let native_epoch = match owner.dv_native_epoch() {
        Ok(epoch) => epoch,
        Err(error) => {
            let _clean = join_setup(
                &mut actor,
                service,
                owner,
                reservations,
                notes,
                &mut cleanup,
            )
            .await;
            return Epoch {
                exit: Exit::Fatal(Box::new(error)),
                cleanup,
                safe: false,
            };
        }
    };
    let adopted = owner
        .dv_server(&scope)
        .map_err(|error| Box::new(error) as Failure)
        .and_then(|server| {
            Bridge::adopt_at(server, &actor, service.settings.dv.bridge, native_epoch)
                .map_err(|error| Box::new(error) as Failure)
        })
        .map_err(|original| Box::new(BridgeAdmissionFailure { original }) as Failure);
    let mut bridge = match adopted {
        Ok(bridge) => bridge,
        Err(error) => {
            let _clean = join_setup(
                &mut actor,
                service,
                owner,
                reservations,
                notes,
                &mut cleanup,
            )
            .await;
            return Epoch {
                exit: Exit::Fatal(error),
                cleanup,
                safe: false,
            };
        }
    };
    let scheduler = Scheduler::new(&actor, owner, service.settings.dv.scheduler);
    let mut scheduler = match scheduler {
        Ok(scheduler) => scheduler,
        Err(error) => {
            match owner.dv_server(&scope) {
                Ok(server) => {
                    if let Err(error) = bridge.begin_close(server, &mut actor) {
                        cleanup.push(Box::new(error));
                    }
                }
                Err(error) => cleanup.push(Box::new(error)),
            }
            let _clean = join_setup(
                &mut actor,
                service,
                owner,
                reservations,
                notes,
                &mut cleanup,
            )
            .await;
            if let Ok(server) = owner.dv_server(&scope)
                && let Err(error) = bridge.close(server, &actor)
            {
                cleanup.push(Box::new(error));
            }
            return Epoch {
                exit: Exit::Fatal(error),
                cleanup,
                safe: false,
            };
        }
    };
    let mut driver = match Driver::new(service.settings.dv.quantum, service.reports.clone()) {
        Ok(driver) => driver,
        Err(error) => {
            scheduler.close(&mut actor);
            actor.close();
            if let Ok(server) = owner.dv_server(&scope)
                && let Err(error) = bridge.begin_close(server, &mut actor)
            {
                cleanup.push(Box::new(error));
            }
            let _clean = join_setup(
                &mut actor,
                service,
                owner,
                reservations,
                notes,
                &mut cleanup,
            )
            .await;
            if let Ok(server) = owner.dv_server(&scope)
                && let Err(error) = bridge.close(server, &actor)
            {
                cleanup.push(Box::new(error));
            }
            return Epoch {
                exit: Exit::Fatal(Box::new(error)),
                cleanup,
                safe: false,
            };
        }
    };
    let mut transmit = crate::dv_transmit::Transmit::new();
    let exit = loop {
        let result = poll_fn(|cx| {
            driver.poll(
                cx,
                service,
                owner,
                &mut actor,
                &mut bridge,
                &mut scheduler,
                &mut transmit,
                &scope,
                reservations,
                entropy,
                notes,
            )
        })
        .await;
        match result {
            Ok(Signal::Activity) => tokio::task::yield_now().await,
            Ok(Signal::Stop) => break Exit::Stop,
            Ok(Signal::Rebuild) => break Exit::Rotate,
            Err(error) => {
                break if owner.is_stopped() {
                    Exit::Control(error)
                } else {
                    Exit::Lost(error)
                };
            }
        }
    };
    cleanup.extend(driver.take_cleanup());
    let safe = retire(
        service,
        owner,
        reservations,
        notes,
        &scope,
        &mut actor,
        &mut bridge,
        &mut scheduler,
        &mut transmit,
        &mut driver,
        &mut cleanup,
    )
    .await;
    Epoch {
        exit,
        cleanup,
        safe,
    }
}
/// No canonical sample is needed to settle the original reservation worker
/// after physical Owner stop. This remains its one original exact Drain.
fn poll_stopped_reservation<'owner, E: Entropy>(
    cx: &mut std::task::Context<'_>,
    owner: &mut Owner<'owner, E>,
    reservations: &mut Reservations,
    notes: &mut Receipts<'owner>,
    drain: &mut Option<crate::epoch::Drain<'owner>>,
    captured: &mut bool,
    cleanup: &mut Vec<Failure>,
) -> Poll<bool> {
    if !owner.is_stopped() {
        return Poll::Pending;
    }
    if !*captured {
        *captured = true;
        match owner.take_reservation_drain() {
            Ok(actual) => *drain = actual,
            Err(error) => cleanup.push(Box::new(error)),
        }
    }
    let Some(original) = drain else {
        return Poll::Pending;
    };
    if original.finished() {
        return Poll::Pending;
    }
    match original.poll(cx, reservations) {
        Poll::Pending => Poll::Pending,
        Poll::Ready(Ok(outcome)) => {
            if let crate::epoch::ReservationOutcome::Failed { error, .. } = &outcome {
                cleanup.push(error.boxed());
            }
            if matches!(
                &outcome,
                crate::epoch::ReservationOutcome::Mismatched { .. }
            ) {
                cleanup.push(Box::new(Error::Stale));
            }
            notes.observe(crate::owner::Event::ReservationRetired(outcome));
            Poll::Ready(true)
        }
        Poll::Ready(Err(error)) => {
            cleanup.push(Box::new(error));
            Poll::Ready(true)
        }
    }
}
#[derive(Debug)]
struct Unsettled {
    inputs: usize,
    outputs: usize,
    native: usize,
    flow: usize,
    range: Option<crate::generation::Request>,
}
impl std::fmt::Display for Unsettled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "original DV retirement incomplete: input={} output={} native={} flow={} range={:?}",
            self.inputs, self.outputs, self.native, self.flow, self.range
        )
    }
}
impl std::error::Error for Unsettled {}
#[expect(
    clippy::too_many_arguments,
    reason = "Original source owners stay externally borrowed through real native/worker retirement"
)]
async fn retire<'id, 'source, 'pils, 'slots, 'out, 'owner, E: Entropy>(
    service: &mut Service<'_, '_, '_>,
    owner: &mut Owner<'owner, E>,
    reservations: &mut Reservations,
    notes: &mut Receipts<'owner>,
    scope: &DvScope<'owner>,
    actor: &mut Actor<'id, 'source, 'pils, 'slots, 'out>,
    bridge: &mut Bridge<'id>,
    scheduler: &mut Scheduler<'id, 'pils, 'owner>,
    transmit: &mut crate::dv_transmit::Transmit<'id>,
    driver: &mut Driver,
    cleanup: &mut Vec<Failure>,
) -> bool {
    scheduler.close(actor);
    transmit.close();
    actor.close();
    let mut safe = true;
    match owner.dv_server(scope) {
        Ok(server) => {
            let result = bridge.begin_close(server, actor);
            if let Some(original) = server.take_native_retirement() {
                service
                    .reports
                    .observe(crate::owner::Event::NativeRetired(original));
            }
            if let Err(error) = result {
                cleanup.push(Box::new(error));
                safe = false;
            }
        }
        Err(error) => {
            cleanup.push(Box::new(error));
            safe = false;
        }
    }
    let hard = Instant::now().checked_add(service.settings.pils.retire);
    let mut forced = false;
    let mut grace = hard.map(|hard| Box::pin(tokio::time::sleep_until(hard)));
    let mut drain = None;
    let mut captured = false;
    loop {
        let before = cleanup.len();
        let progress = (|| -> Result<bool, Failure> {
            let mut changed = false;
            changed |= driver.output_one(owner, actor, bridge, scope, true)?;
            changed |= driver.input_one(owner, actor, bridge, scope, true)?;
            let server = owner.dv_server(scope)?;
            changed |= bridge.settle_send(server, actor)?.is_some();
            changed |= bridge.release_input(server)?.is_some();
            bridge.reap_transfers(server)?;
            changed |= bridge.discard_inbox(server)?;
            changed |= bridge.drain_unadmitted(server)?;
            Ok(changed)
        })();
        driver.retirements(owner, scope);
        let local = match progress {
            Ok(changed) => changed,
            Err(error) => {
                cleanup.push(error);
                safe = false;
                false
            }
        };
        if let Err(error) = Driver::receipts(actor, owner, scheduler, notes) {
            cleanup.push(error);
            safe = false;
        }
        let settled = actor.input_tokens().next().is_none()
            && actor.output_tokens().next().is_none()
            && bridge.native_outputs_pending() == 0
            && bridge.pending_flow_control() == 0;
        if settled {
            break;
        }
        let expired = hard.is_none_or(|hard| Instant::now() >= hard);
        if expired && !forced {
            // This is actual physical source retirement, not a per-packet
            // CANCEL/unsent claim. It may terminate other original MQ work.
            forced = true;
            safe = false;
            cleanup.extend(owner.stop(&mut |event| notes.observe(event)));
            if let Ok(server) = owner.dv_server(scope)
                && let Err(error) = bridge.begin_close(server, actor)
            {
                cleanup.push(Box::new(error));
            }
        } else if expired && forced {
            cleanup.push(Box::new(Unsettled {
                inputs: actor.input_tokens().count(),
                outputs: actor.output_tokens().count(),
                native: bridge.native_outputs_pending(),
                flow: bridge.pending_flow_control(),
                range: scheduler.pending_range().cloned(),
            }));
            break;
        }
        // All tracked transfers were retired above. Standard cleanup polling
        // cannot admit new DV work: the source is retiring and raw RX stays
        // held behind its original gate until discard/physical retirement.
        let result = poll_fn(|cx| {
            if let Some(grace) = &mut grace
                && grace.as_mut().poll(cx).is_ready()
            {
                return Poll::Ready(Ok(()));
            }
            if poll_stopped_reservation(
                cx,
                owner,
                reservations,
                notes,
                &mut drain,
                &mut captured,
                cleanup,
            )
            .is_ready()
            {
                return Poll::Ready(Ok(()));
            }
            let ports = if owner.is_stopped() {
                service.poll_cleanup(cx)
            } else {
                service
                    .poll(cx, owner, reservations, notes, &mut standard)
                    .map(|result| result.map(|_| ()))
            };
            match ports {
                Poll::Pending if local => Poll::Ready(Ok(())),
                other => other,
            }
        })
        .await;
        if let Err(error) = result {
            cleanup.push(error);
            safe = false;
            cleanup.extend(owner.stop(&mut |event| notes.observe(event)));
        }
        if cleanup.len() != before {
            safe = false;
        }
        tokio::task::yield_now().await;
    }
    // The qualified Provider is joined even if native metadata failed to settle.
    // Its real completion is polled first and never replaced by Resolver error.
    let mut report = None;
    {
        let reports = service.reports.clone();
        let shutdown = actor.shutdown(|event| observe_store(&reports, event));
        let mut shutdown = std::pin::pin!(shutdown);
        loop {
            let result = poll_fn(|cx| {
                if let Poll::Ready(actual) = shutdown.as_mut().poll(cx) {
                    report = Some(actual);
                    return Poll::Ready(Ok(true));
                }
                if poll_stopped_reservation(
                    cx,
                    owner,
                    reservations,
                    notes,
                    &mut drain,
                    &mut captured,
                    cleanup,
                )
                .is_ready()
                {
                    return Poll::Ready(Ok(false));
                }
                let control = if owner.is_stopped() {
                    service
                        .poll_cleanup(cx)
                        .map(|result| result.map(|_| Turn::Activity))
                } else {
                    service.poll(cx, owner, reservations, notes, &mut standard)
                };
                match control {
                    Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
                    Poll::Ready(Ok(Turn::Stop)) => {
                        cleanup.extend(owner.stop(&mut |event| notes.observe(event)));
                        Poll::Ready(Ok(false))
                    }
                    Poll::Ready(Ok(Turn::Activity)) => Poll::Ready(Ok(false)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await;
            match result {
                Ok(true) => break,
                Ok(false) => tokio::task::yield_now().await,
                Err(error) => {
                    cleanup.push(error);
                    safe = false;
                    cleanup.extend(owner.stop(&mut |event| notes.observe(event)));
                }
            }
        }
    }
    match report {
        Some(actual) => safe &= report_shutdown(actual, cleanup),
        None => {
            cleanup.push(Box::new(Error::OutcomeUnknown));
            safe = false;
        }
    }
    if let Some(error) = actor.take_cleanup_error() {
        cleanup.push(Box::new(error));
        safe = false;
    }
    if let Some(error) = scheduler.take_cleanup_error() {
        cleanup.push(error);
        safe = false;
    }
    if let Err(error) = Driver::receipts(actor, owner, scheduler, notes) {
        cleanup.push(error);
        safe = false;
    }
    // An old admitted shared monotime range belongs to this old scheduler until
    // its ORIGINAL actual receipt/unknown terminal result has been observed.
    while scheduler.pending_range().is_some() {
        let result = poll_fn(|cx| {
            if poll_stopped_reservation(
                cx,
                owner,
                reservations,
                notes,
                &mut drain,
                &mut captured,
                cleanup,
            )
            .is_ready()
            {
                return Poll::Ready(Ok(()));
            }
            if owner.is_stopped() {
                // A completed/absent original Drain cannot wake us again. The
                // caller reports any remaining exact Scheduler request as
                // unknown below; it must not await an unrelated port forever.
                if captured && drain.as_ref().is_none_or(|original| original.finished()) {
                    return Poll::Ready(Ok(()));
                }
                return service.poll_cleanup(cx);
            }
            service
                .poll(cx, owner, reservations, notes, &mut standard)
                .map(|result| result.map(|_| ()))
        })
        .await;
        if let Err(error) = result {
            cleanup.push(error);
            safe = false;
            cleanup.extend(owner.stop(&mut |event| notes.observe(event)));
        }
        if let Err(error) = Driver::receipts(actor, owner, scheduler, notes) {
            cleanup.push(error);
            safe = false;
        }
        if owner.is_stopped()
            && captured
            && drain.as_ref().is_none_or(|original| original.finished())
            && scheduler.pending_range().is_some()
        {
            cleanup.push(Box::new(Unsettled {
                inputs: actor.input_tokens().count(),
                outputs: actor.output_tokens().count(),
                native: bridge.native_outputs_pending(),
                flow: bridge.pending_flow_control(),
                range: scheduler.pending_range().cloned(),
            }));
            safe = false;
            break;
        }
        tokio::task::yield_now().await;
    }
    // Finishing the join grants no incoming processing/ACK. Any final actual
    // returned rows are consumed under their original tokens before gate close.
    for _ in 0..service
        .settings
        .dv
        .actor
        .inputs
        .saturating_add(service.settings.dv.actor.outputs)
        .saturating_mul(2)
        .saturating_add(8)
    {
        let mut changed = false;
        let output = driver.output_one(owner, actor, bridge, scope, true);
        driver.retirements(owner, scope);
        match output {
            Ok(actual) => changed |= actual,
            Err(error) => {
                cleanup.push(error);
                safe = false;
            }
        }
        match driver.input_one(owner, actor, bridge, scope, true) {
            Ok(actual) => changed |= actual,
            Err(error) => {
                cleanup.push(error);
                safe = false;
            }
        }
        if let Ok(server) = owner.dv_server(scope) {
            let result = bridge.settle_send(server, actor);
            if let Some(original) = server.take_native_retirement() {
                service
                    .reports
                    .observe(crate::owner::Event::NativeRetired(original));
            }
            match result {
                Ok(actual) => changed |= actual.is_some(),
                Err(error) => {
                    cleanup.push(Box::new(error));
                    safe = false;
                }
            }
            match bridge.release_input(server) {
                Ok(actual) => changed |= actual.is_some(),
                Err(error) => {
                    cleanup.push(Box::new(error));
                    safe = false;
                }
            }
            if let Err(error) = bridge.reap_transfers(server) {
                cleanup.push(Box::new(error));
                safe = false;
            }
            match bridge.drain_unadmitted(server) {
                Ok(actual) => changed |= actual,
                Err(error) => {
                    cleanup.push(Box::new(error));
                    safe = false;
                }
            }
        }
        if !changed {
            break;
        }
    }
    match owner.dv_server(scope) {
        Ok(server) => {
            let result = bridge.close(server, actor);
            if let Some(original) = server.take_native_retirement() {
                service
                    .reports
                    .observe(crate::owner::Event::NativeRetired(original));
            }
            if let Err(error) = result {
                cleanup.push(Box::new(error));
                safe = false;
            }
        }
        Err(error) => {
            cleanup.push(Box::new(error));
            safe = false;
        }
    }
    safe && cleanup.is_empty()
}
