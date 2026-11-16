//! Original PILS epochs, CORE sessions and one explicitly retired Resolver.
use super::{ForegroundPolicy, ForegroundResources, PilsFeed};
use crate::{Host, HostError, Limits, Report};
use gnunet_client_host::Endpoint;
use gnunet_config::ProcessEnvironment;
use gnunet_core::session::Identity;
use gnunet_pils::MasterKey;
use gnunet_resolver_broker::{Driver, FamilyProfile, LiveConfiguration, broker};
use gnunet_service_runtime::{BoundListeners, accepted::SocketEvent, clock::RuntimeClock};
use gnunet_types::Error;
use gnunet_wire::official::core::PeerId;
use std::{
    error::Error as StdError,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::Poll,
    time::Duration,
};

enum Selection<T> {
    Value(T),
    Stopped,
}
async fn services<F: Future, S: Future<Output = io::Result<()>>>(
    future: F,
    driver: &mut Driver<128, 256>,
    mut shutdown: Pin<&mut S>,
) -> Result<Selection<F::Output>, Box<dyn StdError>> {
    let mut operation = std::pin::pin!(future);
    loop {
        let mut resolver = std::pin::pin!(driver.drive_waiting(None, |_| {}));
        let selected = poll_fn(|cx| {
            if let Poll::Ready(value) = shutdown.as_mut().poll(cx) {
                return Poll::Ready(
                    value
                        .map(|()| Some(Selection::Stopped))
                        .map_err(|cause| Box::new(cause) as Box<dyn StdError>),
                );
            }
            let progress = match resolver.as_mut().poll(cx) {
                Poll::Ready(Err(cause)) => {
                    return Poll::Ready(Err(Box::new(cause) as Box<dyn StdError>));
                }
                Poll::Ready(Ok(_)) => true,
                Poll::Pending => false,
            };
            if let Poll::Ready(value) = operation.as_mut().poll(cx) {
                return Poll::Ready(Ok(Some(Selection::Value(value))));
            }
            if progress {
                Poll::Ready(Ok(None))
            } else {
                Poll::Pending
            }
        })
        .await?;
        if let Some(value) = selected {
            return Ok(value);
        }
        tokio::task::yield_now().await;
    }
}
enum Epoch {
    Rotate(Identity),
    PilsLost,
    HostStopped,
}
fn accumulate(total: &mut Report, one: Report) {
    macro_rules! add {($($field:ident),*)=>{$(total.$field=total.$field.saturating_add(one.$field);)*};}
    add!(
        accepted,
        closed,
        requests,
        authenticated,
        payloads,
        transport_sends,
        receive_credits,
        rejected_records,
        rejected_epoch,
        rejected_authentication,
        rejected_replay,
        rejected_truncated,
        rejected_malformed,
        rejected_invalid_input,
        rejected_unsupported,
        transport_losses,
        transport_disconnections,
        association_expirations,
        late_send_credits
    );
    if total.first_peer_loss.is_none() {
        total.first_peer_loss = one.first_peer_loss;
    }
}

struct EpochPorts<'a> {
    bound: &'a BoundListeners,
    policy: ForegroundPolicy,
    master: &'a MasterKey,
    pils: &'a Endpoint,
    transport: &'a Endpoint,
    resolver: &'a mut Driver<128, 256>,
    limits: Limits,
    clock: Arc<dyn RuntimeClock>,
}
async fn epochs(
    ports: EpochPorts<'_>,
    mut ready: impl FnMut(&BoundListeners, PeerId) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    mut observe: impl FnMut(SocketEvent),
    notification: impl Future<Output = Result<(), Box<dyn StdError>>>,
    total: &mut Report,
) -> Result<(), Box<dyn StdError>> {
    let EpochPorts {
        bound,
        policy,
        master,
        pils: pils_endpoint,
        transport: transport_endpoint,
        resolver,
        limits,
        clock,
    } = ports;
    let ForegroundPolicy {
        options,
        unix_access,
        local_class,
        profile,
    } = policy;
    let notification = std::pin::pin!(notification);
    let mut notification = Some(notification);
    let mut shutdown = std::pin::pin!(shutdown);
    let mut round = 0_u64;
    loop {
        let connection =
            match services(pils_endpoint.attempt(round), resolver, shutdown.as_mut()).await? {
                Selection::Stopped => return Ok(()),
                Selection::Value(Ok(c)) => c,
                Selection::Value(Err(_)) => {
                    round = round.checked_add(1).ok_or(Error::Capacity)?;
                    if matches!(
                        services(
                            tokio::time::sleep(Duration::from_secs(1)),
                            resolver,
                            shutdown.as_mut()
                        )
                        .await?,
                        Selection::Stopped
                    ) {
                        return Ok(());
                    }
                    continue;
                }
            };
        let mut pils = PilsFeed::with_profile(connection, clock.clone(), profile)?;
        let first = poll_fn(|cx| pils.poll_identity(cx, master));
        let mut identity = match services(first, resolver, shutdown.as_mut()).await? {
            Selection::Stopped => return Ok(()),
            Selection::Value(Ok(i)) => i,
            Selection::Value(Err(e @ HostError::Clock(_))) => return Err(e.into()),
            Selection::Value(Err(_)) => {
                round = round.checked_add(1).ok_or(Error::Capacity)?;
                if matches!(
                    services(
                        tokio::time::sleep(Duration::from_secs(1)),
                        resolver,
                        shutdown.as_mut()
                    )
                    .await?,
                    Selection::Stopped
                ) {
                    return Ok(());
                }
                continue;
            }
        };
        loop {
            let mut host = Host::with_clock(
                &identity,
                b"",
                local_class,
                transport_endpoint.clone(),
                limits,
                options.clone(),
                clock.clone(),
            )?;
            let result: Result<Selection<Result<Epoch, HostError>>, Box<dyn StdError>> = async {
                host.set_unix_access(unix_access)?;
                ready(bound, host.identity())?;
                if let Some(original) = notification.take() {
                    match services(
                        tokio::time::timeout(Duration::from_secs(10), original),
                        resolver,
                        shutdown.as_mut(),
                    )
                    .await?
                    {
                        Selection::Value(Ok(result)) => result?,
                        Selection::Value(Err(_)) => {
                            return Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "CORE readiness acknowledgement deadline",
                            )
                            .into());
                        }
                        Selection::Stopped => {
                            return Err(io::Error::new(
                                io::ErrorKind::Interrupted,
                                "CORE stopped before readiness acknowledgement",
                            )
                            .into());
                        }
                    }
                }
                let public = identity.public_key();
                let listeners = bound.listeners();
                {
                    let mut drive = std::pin::pin!(host.drive(&listeners, &mut observe));
                    let epoch = poll_fn(|cx| {
                        match pils.poll_identity(cx, master) {
                            Poll::Ready(Ok(next)) if next.public_key() != public => {
                                return Poll::Ready(Ok(Epoch::Rotate(next)));
                            }
                            Poll::Ready(Ok(_)) => cx.waker().wake_by_ref(),
                            Poll::Ready(Err(e @ HostError::Clock(_))) => {
                                return Poll::Ready(Err(e));
                            }
                            Poll::Ready(Err(_)) => return Poll::Ready(Ok(Epoch::PilsLost)),
                            Poll::Pending => {}
                        }
                        match drive.as_mut().poll(cx) {
                            Poll::Ready(result) => Poll::Ready(result.map(|()| Epoch::HostStopped)),
                            Poll::Pending => Poll::Pending,
                        }
                    });
                    services(epoch, resolver, shutdown.as_mut()).await
                }
            }
            .await;
            host.shutdown();
            accumulate(total, host.report());
            drop(host);
            match result? {
                Selection::Stopped => return Ok(()),
                Selection::Value(Err(e)) => return Err(e.into()),
                Selection::Value(Ok(Epoch::HostStopped)) => return Ok(()),
                Selection::Value(Ok(Epoch::PilsLost)) => break,
                Selection::Value(Ok(Epoch::Rotate(next))) => identity = next,
            }
        }
        round = round.checked_add(1).ok_or(Error::Capacity)?;
        if matches!(
            services(
                tokio::time::sleep(Duration::from_secs(1)),
                resolver,
                shutdown.as_mut()
            )
            .await?,
            Selection::Stopped
        ) {
            return Ok(());
        }
    }
}
#[derive(Debug)]
struct Failure {
    original: Option<Box<dyn StdError>>,
    cleanup: Vec<Box<dyn StdError>>,
    report: Report,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "CORE original={:?}; independent cleanup={:?}; local report={:?}",
            self.original, self.cleanup, self.report
        )
    }
}
impl StdError for Failure {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.cleanup.first().map(|cause| cause.as_ref()))
    }
}
pub(super) async fn run_foreground(
    resources: ForegroundResources<'_>,
    limits: Limits,
    ready: impl FnMut(&BoundListeners, PeerId) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe: impl FnMut(SocketEvent),
    clock: Arc<dyn RuntimeClock>,
    notification: impl Future<Output = Result<(), Box<dyn StdError>>>,
) -> Result<Report, Box<dyn StdError>> {
    let ForegroundResources {
        config,
        bound,
        policy,
    } = resources;
    let key_path = config.get_filename(b"PEER", b"PRIVATE_KEY", &ProcessEnvironment)?;
    let master = gnunet_pils_host::identity::load_existing(&key_path)?;
    let native = gnunet_resolver_broker::native_profile()?;
    let family = FamilyProfile::new(
        native.encode(gnunet_resolver_broker::Family::V4),
        native.encode(gnunet_resolver_broker::Family::V6),
    )?;
    let live = LiveConfiguration::new(config.duplicate()?);
    let (context, mut resolver) =
        broker::<128, 256>(live.clone(), Default::default(), family, clock.clone())?;

    let mut total = Report::default();
    let outcome = async {
        let resolution = context.resolution_context();
        let pils = Endpoint::configuration_live(live.clone(), b"pils", resolution.clone())?;
        let transport = Endpoint::configuration_live(live, b"transport", resolution)?;
        epochs(
            EpochPorts {
                bound: &bound,
                policy,
                master: &master,
                pils: &pils,
                transport: &transport,
                resolver: &mut resolver,
                limits,
                clock,
            },
            ready,
            shutdown,
            observe,
            notification,
            &mut total,
        )
        .await
    }
    .await;
    let mut cleanup: Vec<Box<dyn StdError>> = Vec::new();
    if let Err(cause) = resolver.disconnect() {
        cleanup.push(Box::new(cause));
    }
    if let Some(cause) = resolver.take_io_error() {
        cleanup.push(Box::new(cause));
    }
    if let Some(cause) = resolver.take_connect_error() {
        cleanup.push(Box::new(cause));
    }
    match outcome {
        Ok(()) if cleanup.is_empty() => Ok(total),
        outcome => Err(Box::new(Failure {
            original: outcome.err(),
            cleanup,
            report: total,
        })),
    }
}
