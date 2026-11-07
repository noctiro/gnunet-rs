//! Actual optional CORE/PILS peer composition; all backing stores stay outside Node.
mod config;
mod discovery;
mod lifecycle;
mod transport;
use crate::{
    foreground::{Diagnostics, Failures, Ready, Stage},
    identity::{self, Dependencies},
    settings::Settings as ApplicationSettings,
};
pub(crate) use config::Settings;
use config::{CORE_PEERS, FRAME_BYTES, PATH_PEERS, PILS_OPERATIONS, SENDS};
use gnunet_cadet::{
    connection::{self as pure_connection, Book},
    peer,
    tunnel::{self, context, controller, identity_dh as pure_dh},
};
use gnunet_cadet_host::{
    connection::{self as bridge, Bridge},
    identity_dh as dh,
    node::{self, Node},
    server::{self, CloseCause, Server},
    signing::{self, monotime},
    time::Timebase,
};
use gnunet_client_host::EndpointSource;
use gnunet_crypto::Entropy as EntropyPort;
use gnunet_pils::{
    HelloLimits,
    client::{Identity, Inbound, Instance as PilsInstance},
};
use gnunet_pils_host::client::{Limits as PilsLimits, Progress as PilsProgress};
use gnunet_service_runtime::service::Listener;
use gnunet_types::Error as ProtocolError;
use std::{
    error::Error,
    future::{Future, poll_fn},
    io,
    sync::Arc,
    task::Poll,
};

pub(super) struct Endpoints {
    pub core: EndpointSource,
    pub dht: EndpointSource,
    pub transport: EndpointSource,
    pub dh: EndpointSource,
    pub signing: EndpointSource,
}
pub(super) struct Setup<'run, 'child> {
    pub(super) endpoints: Endpoints,
    pub(super) ready: &'run mut Ready<'child>,
}
use lifecycle::{Anchor, Continuity, Exit, Shutdown, Startup};

struct Entropy;
impl EntropyPort for Entropy {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), ProtocolError> {
        getrandom::fill(bytes).map_err(|_| ProtocolError::Entropy)
    }
}
fn pool<T>(length: usize, mut value: impl FnMut() -> T) -> Result<Vec<T>, ProtocolError> {
    let mut result = Vec::new();
    result
        .try_reserve_exact(length)
        .map_err(|_| ProtocolError::Capacity)?;
    for _ in 0..length {
        result.push(value());
    }
    Ok(result)
}
fn hello() -> HelloLimits {
    HelloLimits {
        maximum_input_bytes: 65535,
        maximum_address_bytes: 65535,
        maximum_addresses: 128,
    }
}
fn startup_progress<const O: usize>(
    progress: Result<PilsProgress<'_, O>, gnunet_cadet_host::Error>,
) -> Result<bool, Box<dyn Error>> {
    match progress? {
        PilsProgress::Inbound(Inbound::Identity { .. }) => Ok(true),
        PilsProgress::Lost { cause, .. } => {
            Err(io::Error::other(format!("original peer PILS startup MQ lost: {cause:?}")).into())
        }
        PilsProgress::Unavailable(error) => Err(Box::new(error)),
        PilsProgress::Closed => Err(ProtocolError::Closed.into()),
        _ => Ok(false),
    }
}
/// Retain both original connecting owners while polling the same observer,
/// resolver and process controls. No operation is submitted before verification.
async fn startup<'p>(
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
            if let Err(reason) = result {
                refusals.reason = reason;
            }
            return Err(Box::new(refusals));
        }
        if let Some(result) = observer
            && let Some(observed) = dependencies.observe_identity_update(result, identity, failures)
            && (observed.peer() != identity.peer() || mismatch && observed != identity)
        {
            return Ok(Startup::Replace {
                identity: observed,
                hard,
            });
        }
        if let Some(Err(error)) = resolver {
            failures.record(Stage::Resolver, Box::new(error));
        }
        if !failures.is_empty() || reporter.failed() {
            return Err(ProtocolError::Closed.into());
        }
        if let Some(result) = dh_result {
            if dh.identity_mismatch().is_some() {
                mismatch = true;
                if let Err(error) = result {
                    refusals.dh = Some(error);
                }
            } else {
                dh_ready |= startup_progress(result)?;
            }
        }
        if let Some(result) = sign_result {
            if signer.identity_mismatch().is_some() {
                mismatch = true;
                if let Err(error) = result {
                    refusals.signing = Some(error);
                }
            } else {
                signer_ready |= startup_progress(result)?;
            }
        }
    }
    Ok(Startup::Ready)
}

async fn generation<'p>(
    settings: &ApplicationSettings,
    listeners: &[Listener<'_>],
    dependencies: &mut Dependencies<'p, '_>,
    server: &mut Server<'_, '_, '_>,
    setup: Setup<'_, '_>,
    failures: &mut Failures,
    continuity: Continuity<'p, '_>,
) -> Result<Exit<'p>, Box<dyn Error>> {
    let Continuity {
        anchor: Anchor {
            mut identity,
            hard: mut recovery_hard,
        },
        history,
    } = continuity;
    if recovery_hard.is_some_and(|hard| tokio::time::Instant::now() >= hard) {
        return Err(ProtocolError::Deadline.into());
    }
    let Setup { endpoints, ready } = setup;
    let reporter = dependencies.reporter.clone();
    let limits = &settings.peer;
    let local = *identity.peer().as_bytes();
    let clock = server.clock();
    let timebase = Timebase::new(clock.clone())?;
    // Metadata/clock reservations happen before native Node/PILS operations.
    let mut dht_instance = gnunet_dht_client_host::Instance::new();
    let mut discovery = discovery::Driver::new(
        &mut dht_instance,
        endpoints.dht,
        timebase.clone(),
        local,
        discovery::Policy {
            maximum: limits.channels,
            path_peers: PATH_PEERS,
            replication: limits.discovery_replication,
            signature_profile: settings.pils_profile.hello(),
        },
    )?;
    let mut monotime = monotime::Store::open_for_peer(
        limits
            .monotime_file
            .as_deref()
            .ok_or(ProtocolError::InvalidInput)?,
        local,
    )?;
    // The only disk reservation precedes peer startup; refills below happen
    // after every socket/future borrow has ended, never inside Node polling.
    let range = monotime.reserve(clock.sample()?.now.as_micros(), limits.monotime_reservation)?;
    let node_domain = context::Instance::new();
    let mut context_rows = pool(limits.tunnels, context::Slot::new)?;
    let contexts = context::Registry::new(&node_domain, &mut context_rows)?;
    let channel_domain = peer::Instance::new();
    let source_domain = pure_dh::Instance::new();
    let mut source_rows = [pure_dh::Slot::new()];
    let mut sources = pure_dh::Registry::new(&source_domain, &mut source_rows)?;
    let mut dh_instance = PilsInstance::new();
    let mut sign_instance = PilsInstance::new();
    let mut dh_jobs = pool(PILS_OPERATIONS, dh::JobSlot::new)?;
    let mut dh_contexts = pool(limits.tunnels, dh::ContextSlot::new)?;
    let mut sign_jobs = pool(PILS_OPERATIONS, signing::JobSlot::new)?;
    let native_limits = PilsLimits {
        pending_operations: PILS_OPERATIONS,
        io_slice_bytes: settings.native.io_slice_bytes,
        ..PilsLimits::default()
    };
    let mut dh_connecting = dh::Connecting::<PILS_OPERATIONS>::new(
        &mut dh_instance,
        endpoints.dh,
        local,
        settings.pils_profile,
        native_limits,
        hello(),
    )?;
    let mut sign_connecting = signing::Connecting::<PILS_OPERATIONS>::new(
        &mut sign_instance,
        endpoints.signing,
        local,
        settings.pils_profile,
        native_limits,
        hello(),
    )?;
    if !Arc::ptr_eq(&clock, &dh_connecting.clock())
        || !Arc::ptr_eq(&clock, &sign_connecting.clock())
    {
        return Err(ProtocolError::Conflict.into());
    }
    match startup(
        &mut dh_connecting,
        &mut sign_connecting,
        dependencies,
        Anchor {
            identity,
            hard: recovery_hard,
        },
        &timebase,
        settings,
        failures,
    )
    .await?
    {
        Startup::Ready => {}
        Startup::Stopped => return Ok(Exit::Stopped),
        Startup::Replace { identity, hard } => return Ok(Exit::Replace { identity, hard }),
    }
    let dh_port = dh_connecting
        .bind(
            &mut sources,
            &mut dh_jobs,
            &mut dh_contexts,
            timebase.clone(),
        )
        .map_err(|rejected| rejected.reason)?;
    let mut book_domain = pure_connection::Instance::new();
    let mut neighbors = pool(CORE_PEERS, pure_connection::NeighborSlot::default)?;
    let mut routes = pool(limits.routes, pure_connection::RouteSlot::<PATH_PEERS>::new)?;
    let mut origins = pool(limits.origins, pure_connection::OriginSlot::default)?;
    let mut frame_bytes = pool(
        limits
            .frames
            .checked_mul(FRAME_BYTES)
            .ok_or(ProtocolError::Overflow)?,
        || 0_u8,
    )?;
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(limits.frames)
        .map_err(|_| ProtocolError::Capacity)?;
    for bytes in frame_bytes.as_chunks_mut::<FRAME_BYTES>().0 {
        frames.push(pure_connection::FrameSlot::new(bytes));
    }
    let now = timebase.sample()?.monotonic;
    let book = Book::new(
        &mut book_domain,
        local,
        &mut neighbors,
        &mut routes,
        &mut origins,
        &mut frames,
        now,
        limits.connection,
    )?;
    let mut signer = sign_connecting
        .bind(
            &book,
            &mut sign_jobs,
            signing::Limits::default(),
            timebase.clone(),
        )
        .map_err(|rejected| rejected.reason)?;
    let mut core_domain = gnunet_core_client_host::Instance::new();
    let mut core_peers = pool(CORE_PEERS + SENDS, bridge::PeerSlot::new)?;
    let mut core_sends = pool(SENDS, bridge::SendSlot::new)?;
    let bridge = Bridge::<CORE_PEERS, SENDS>::new(
        &mut core_domain,
        endpoints.core,
        &book,
        &mut core_peers,
        &mut core_sends,
        limits.bridge,
        timebase.clone(),
    )?;
    let per_tunnel = limits
        .skipped
        .checked_mul(4)
        .ok_or(ProtocolError::Overflow)?;
    let mut keys = pool(
        limits
            .tunnels
            .checked_mul(per_tunnel)
            .ok_or(ProtocolError::Overflow)?,
        tunnel::SkippedSlot::new,
    )?;
    let mut tunnels = Vec::new();
    tunnels
        .try_reserve_exact(limits.tunnels)
        .map_err(|_| ProtocolError::Capacity)?;
    for key in keys.chunks_exact_mut(per_tunnel) {
        let (a, rest) = key.split_at_mut(limits.skipped);
        let (b, rest) = rest.split_at_mut(limits.skipped);
        let (c, d) = rest.split_at_mut(limits.skipped);
        tunnels.push(controller::Stores {
            first: tunnel::Storage {
                skipped: a,
                staging: b,
            },
            second: tunnel::Storage {
                skipped: c,
                staging: d,
            },
        });
    }
    let slots = limits
        .channels
        .checked_mul(limits.window)
        .ok_or(ProtocolError::Overflow)?;
    let bytes = slots
        .checked_mul(limits.payload)
        .ok_or(ProtocolError::Overflow)?;
    let mut outgoing = pool(bytes, || 0_u8)?;
    let mut incoming = pool(bytes, || 0_u8)?;
    let mut sends = Vec::new();
    let mut receives = Vec::new();
    sends
        .try_reserve_exact(slots)
        .map_err(|_| ProtocolError::Capacity)?;
    receives
        .try_reserve_exact(slots)
        .map_err(|_| ProtocolError::Capacity)?;
    for bytes in outgoing.chunks_exact_mut(limits.payload) {
        sends.push(peer::SendSlot::new(bytes));
    }
    for bytes in incoming.chunks_exact_mut(limits.payload) {
        receives.push(peer::ReceiveSlot::new(bytes));
    }
    let mut channels = Vec::new();
    channels
        .try_reserve_exact(limits.channels)
        .map_err(|_| ProtocolError::Capacity)?;
    for (sends, receives) in sends
        .chunks_exact_mut(limits.window)
        .zip(receives.chunks_exact_mut(limits.window))
    {
        channels.push(node::ChannelBuffers { sends, receives });
    }
    let mut plaintext = pool(limits.plaintext_bytes, || 0_u8)?;
    let mut ciphertext = pool(limits.ciphertext_bytes, || 0_u8)?;
    let mut node = Node::new(
        node::Parts {
            server,
            book,
            bridge,
            identity_dh: dh_port,
        },
        node::Storage {
            contexts,
            channel_domain: &channel_domain,
            tunnels,
            channels,
            plaintext: &mut plaintext,
            ciphertext: &mut ciphertext,
        },
        limits.node,
        Entropy,
    )?;
    node.install_monotime_range(range)?;
    let mut transport = transport::Driver::new(
        endpoints.transport,
        timebase.clone(),
        limits.tunnels,
        limits
            .channels
            .checked_add(limits.tunnels)
            .ok_or(ProtocolError::Overflow)?,
        settings.native.io_slice_bytes,
        std::time::Duration::from_micros(limits.node.opening_micros),
    )?;
    let mut diagnostics = Diagnostics::new(reporter.clone());
    // Readiness failure stays in this same actual Node cleanup path rather than
    // returning through Drop with opaque original port/effect retirement facts.
    if let Err(error) = ready.announce(local, Some(limits.payload_memory)) {
        failures.record(Stage::Output, Box::new(error));
    }
    let mut shutdown = Shutdown::Running;
    let mut recovery = recovery_hard.map(lifecycle::Bound::at);
    let mut first_refusal = None;
    let mut loose_retained_reported = false;
    let mut loose_bound_reported = false;
    loop {
        if shutdown.running() && failures.is_empty() && !reporter.failed() {
            // Native expiry/cancel has priority over any new DHT IO. Tickets
            // retain the original app open, target, and Node-minted hard bound.
            let maintained = discovery.maintain(|wanted| node.discovery_current(wanted));
            match maintained {
                Ok(Some(expired)) => {
                    if let Err(error) = node.expire_discovery(expired)
                        && !matches!(error, node::Error::Protocol(ProtocolError::StaleGeneration))
                    {
                        failures.record(Stage::Peer, Box::new(error));
                    }
                }
                Ok(None) => {}
                Err(error) => failures.record(Stage::Peer, error),
            }
            if failures.is_empty() {
                let mut after = None;
                while let Some(wanted) = node.discovery_after(after) {
                    after = Some(wanted.open);
                    if !discovery.contains(wanted) {
                        let start = node
                            .discovery_hard(wanted)
                            .map_err(|error| Box::new(error) as Box<dyn Error>)
                            .and_then(|hard| discovery.start(wanted, hard));
                        if let Err(error) = start {
                            if error.downcast_ref::<ProtocolError>()
                                == Some(&ProtocolError::WouldBlock)
                            {
                                break;
                            }
                            if error.downcast_ref::<ProtocolError>()
                                == Some(&ProtocolError::Deadline)
                            {
                                if let Err(error) = node.expire_discovery(wanted) {
                                    failures.record(Stage::Peer, Box::new(error));
                                }
                            } else {
                                failures.record(Stage::Peer, error);
                            }
                            break;
                        }
                    }
                }
            }
            if failures.is_empty() {
                let admission = match discovery.candidate() {
                    Ok(Some(path)) => Some((
                        path.original,
                        node.admit_discovery(path.original, path.peers, path.observed),
                    )),
                    Ok(None) => None,
                    Err(error) => {
                        failures.record(Stage::Peer, error);
                        None
                    }
                };
                if let Some((wanted, result)) = admission {
                    match result {
                        Ok(true) => {
                            if let Err(error) = discovery.admitted(wanted) {
                                failures.record(Stage::Peer, error);
                            }
                        }
                        Ok(false)
                        | Err(node::Error::Protocol(
                            ProtocolError::Capacity
                            | ProtocolError::WouldBlock
                            | ProtocolError::NotReady,
                        )) => {}
                        Err(node::Error::Protocol(
                            ProtocolError::StaleGeneration | ProtocolError::Deadline,
                        )) => {
                            // Original expiry/cancel cleanup is settled by maintain,
                            // never retagged to a subsequent app channel.
                        }
                        Err(node::Error::Protocol(
                            reason @ (ProtocolError::Authentication
                            | ProtocolError::Malformed
                            | ProtocolError::InvalidInput
                            | ProtocolError::Unsupported
                            | ProtocolError::Truncated
                            | ProtocolError::TooLarge),
                        )) => discovery.reject(wanted, reason),
                        Err(error) => failures.record(Stage::Peer, Box::new(error)),
                    }
                }
            }
        }
        if shutdown.running()
            && failures.is_empty()
            && !reporter.failed()
            && let Err(error) = transport.maintain(|cursor| node.transport_after(cursor))
        {
            failures.record(Stage::Peer, error);
        }
        let mut stop = None;
        let mut observer = None;
        let mut resolver = None;
        let mut transport_result = None;
        let mut node_result = None;
        let mut discovery_result = None;
        let mut sign_result = None;
        let mut grace_done = false;
        {
            let mut identity_work = std::pin::pin!(dependencies.pils.drive(None));
            let mut resolving = std::pin::pin!(
                dependencies
                    .resolver
                    .drive_waiting(None, |event| identity::resolver_event(&reporter, event))
            );
            poll_fn(|cx| {
                reporter.register(cx);
                if shutdown.running() && reporter.failed() {
                    stop = Some(Ok(()));
                    return Poll::Ready(());
                }
                if shutdown.running() && !failures.is_empty() {
                    stop = Some(Ok(()));
                    return Poll::Ready(());
                }
                if shutdown.accepts_stop()
                    && let Poll::Ready(result) = dependencies.signals.poll(cx)
                {
                    stop = Some(result);
                    return Poll::Ready(());
                }
                if recovery
                    .as_mut()
                    .is_some_and(|bound| bound.poll_expired(cx))
                {
                    grace_done = true;
                    return Poll::Ready(());
                }
                if shutdown.poll_expired(cx) {
                    grace_done = true;
                    return Poll::Ready(());
                }
                {
                    let mut snapshot = node.statistics();
                    snapshot.merge(history);
                    dependencies.statistics.observe(&snapshot);
                }
                let stats_progress = dependencies.statistics.poll(cx).is_ready();
                if reporter.failed() {
                    dependencies.statistics.abort();
                    if shutdown.running() {
                        stop = Some(Ok(()));
                        return Poll::Ready(());
                    }
                }
                // After a known diagnostic failure, only original Node/signer
                // cleanup below may run; no fresh observer/Resolver work starts.
                if !reporter.failed()
                    && let Poll::Ready(result) = identity_work.as_mut().poll(cx)
                {
                    let fatal = Dependencies::fatal(&result, identity);
                    observer = Some(result);
                    if fatal {
                        return Poll::Ready(());
                    }
                }
                if !reporter.failed()
                    && let Poll::Ready(result) = resolving.as_mut().poll(cx)
                {
                    let fatal = result.is_err();
                    resolver = Some(result);
                    if fatal {
                        return Poll::Ready(());
                    }
                }
                if shutdown.running() && reporter.failed() {
                    stop = Some(Ok(()));
                    return Poll::Ready(());
                }
                // Discovery IO precedes this round's Node/signing observations.
                // A Node event returns to the outer maintain before any later DHT
                // poll, so a known cancelled/expired original cannot issue a GET.
                if shutdown.running()
                    && !reporter.failed()
                    && let Poll::Ready(result) = discovery.poll(cx)
                {
                    let fatal = result.is_err();
                    discovery_result = Some(result);
                    if fatal {
                        return Poll::Ready(());
                    }
                }
                // The same original Node demand projection was refreshed before
                // this poll. No local hint receipt changes Book/CORE eligibility.
                if shutdown.running()
                    && !reporter.failed()
                    && let Poll::Ready(result) = transport.poll(cx)
                {
                    let fatal = result.is_err();
                    transport_result = Some(result);
                    if fatal {
                        return Poll::Ready(());
                    }
                }
                // Each real owner is polled once even when a sibling is ready.
                if !node.peers_retired()
                    && let Poll::Ready(result) = node.poll_signing(cx, &mut signer, None)
                {
                    let changed = lifecycle::signer_stops_generation(&result);
                    sign_result = Some(result);
                    if changed {
                        return Poll::Ready(());
                    }
                }
                if !node.peers_retired()
                    && let Poll::Ready(result) = node.poll(
                        cx,
                        if shutdown.running() { listeners } else { &[] },
                        None,
                        &mut |event| diagnostics.observe(event),
                    )
                {
                    node_result = Some(result);
                }
                if stats_progress
                    || observer.is_some()
                    || resolver.is_some()
                    || node_result.is_some()
                    || sign_result.is_some()
                    || discovery_result.is_some()
                    || transport_result.is_some()
                {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        }
        if let Some((client, reason)) = diagnostics.retire.take()
            && let Err(error) = node.close_client(
                client,
                CloseCause::Fault(server::Error::Protocol(reason)),
                &mut |event| diagnostics.observe(event),
            )
        {
            failures.record(Stage::PeerCleanup, Box::new(error));
        }
        dependencies.native_resolver_diagnostics();
        let mut next_identity = None;
        if let Some(result) = observer
            && let Some(observed) = dependencies.observe_identity_update(result, identity, failures)
        {
            if observed.peer() != identity.peer() || shutdown.replacing() {
                next_identity = Some(observed);
            } else {
                identity = observed;
            }
        }
        let source_hint = lifecycle::source_hint(
            &mut sign_result,
            &mut node_result,
            !shutdown.running(),
            failures,
        );
        if shutdown.replacing()
            && let Some(observed) = next_identity
        {
            shutdown.observe(observed);
        }
        if shutdown.running() && (next_identity.is_some() || source_hint) && failures.is_empty() {
            match lifecycle::replacement_bound(settings, recovery_hard) {
                Ok(bound) => {
                    reporter.debug(
                        "cadet.identity.retire",
                        format_args!("retiring original peer generation"),
                    );
                    let closed = node.retire_peers();
                    if let Err(error) = closed.core {
                        failures.record(Stage::PeerCleanup, Box::new(error));
                    }
                    if let Err(error) = closed.applications {
                        failures.record(Stage::PeerCleanup, Box::new(error));
                    }
                    let _signing = signer.close();
                    if let Err(error) = discovery.close() {
                        failures.record(Stage::PeerCleanup, error);
                    }
                    if let Err(error) = transport.close() {
                        failures.record(Stage::PeerCleanup, error);
                    }
                    reporter.debug("cadet.identity.retire.sources", format_args!("original CORE, DH, signing, discovery and TRANSPORT sources physically retired; metadata drain remains"));
                    shutdown = Shutdown::Replacing {
                        latest: next_identity.or(Some(identity)),
                        bound,
                    };
                    recovery = None;
                }
                Err(error) => failures.record(Stage::Identity, Box::new(error)),
            }
        }
        if let Some(Err(error)) = resolver {
            failures.record(Stage::Resolver, Box::new(error));
        }
        if let Some(Err(error)) = sign_result {
            failures.record(Stage::Peer, Box::new(error));
        }
        if let Some(Err(error)) = discovery_result {
            failures.record(Stage::Peer, error);
        }
        if let Some(Err(error)) = transport_result {
            failures.record(Stage::Peer, error);
        }
        match node_result {
            Some(Ok(node::Step::MonotimeRequired)) if shutdown.running() && !reporter.failed() => {
                let next = clock
                    .sample()
                    .map_err(|e| Box::new(e) as Box<dyn Error>)
                    .and_then(|sample| {
                        monotime
                            .reserve(sample.now.as_micros(), limits.monotime_reservation)
                            .map_err(|e| Box::new(e) as Box<dyn Error>)
                    });
                match next {
                    Ok(range) => {
                        if let Err(error) = node.install_monotime_range(range) {
                            failures.record(Stage::Peer, Box::new(error));
                        }
                    }
                    Err(error) => failures.record(Stage::Peer, error),
                }
            }
            Some(Ok(node::Step::Refused(refusal))) if first_refusal.is_none() => {
                first_refusal = Some(refusal)
            }
            Some(Ok(node::Step::Quiescent)) => break,
            Some(Err(error)) => {
                failures.record(Stage::Peer, Box::new(error));
                if shutdown.forced() {
                    break;
                }
            }
            _ => {}
        }
        // These two bounded milestones observe committed original Node facts.
        // At most one line each is emitted for this whole original process;
        // neither a retry, packet log, application result nor remote ACK exists.
        if shutdown.running() && failures.is_empty() && !reporter.failed() {
            let actual = node.report();
            if !loose_retained_reported && actual.loose_retained > 0 {
                loose_retained_reported = true;
                reporter.message(
                    gnunet_program_host::policy::Level::INFO,
                    "cadet.peer.loose.retained",
                    format_args!(
                        "cadet original closed-port wait retained: total={}",
                        actual.loose_retained
                    ),
                );
            }
            if !loose_bound_reported && actual.loose_bound > 0 {
                loose_bound_reported = true;
                reporter.message(
                    gnunet_program_host::policy::Level::INFO,
                    "cadet.peer.loose.bound",
                    format_args!(
                        "cadet original closed-port wait bound: total={}",
                        actual.loose_bound
                    ),
                );
            }
        }
        let shutdown_requested = stop.is_some();
        if let Some(Err(error)) = stop {
            failures.record(Stage::Control, Box::new(error));
        }
        if node.quiescent() {
            break;
        }
        if node.peers_retired()
            && signer.jobs_retired()
            && shutdown.latest().is_some()
            && !shutdown_requested
            && !grace_done
            && failures.is_empty()
            && !reporter.failed()
        {
            break;
        }
        if node.ready() && recovery.is_some() {
            recovery = None;
            recovery_hard = None;
            reporter.debug(
                "cadet.identity.ready",
                format_args!("replacement generation matched actual CORE and PILS identity"),
            );
        }
        if grace_done && (shutdown.running() || shutdown.replacing()) {
            failures.record(Stage::Identity, Box::new(ProtocolError::Deadline));
        }
        if shutdown.running() && (shutdown_requested || !failures.is_empty()) {
            if let Err(error) = discovery.close() {
                failures.record(Stage::PeerCleanup, error);
            }
            if let Err(error) = transport.close() {
                failures.record(Stage::PeerCleanup, error);
            }
            node.request_shutdown(settings.options.shutdown);
            shutdown = Shutdown::Grace(lifecycle::Bound::after(limits.shutdown_grace)?);
        }
        if (grace_done
            || !failures.is_empty()
            || reporter.failed()
            || shutdown.replacing() && shutdown_requested)
            && !shutdown.forced()
        {
            let closed = node.close(&mut |event| diagnostics.observe(event));
            if let Err(error) = closed.core {
                failures.record(Stage::PeerCleanup, Box::new(error));
            }
            if let Err(error) = closed.applications {
                failures.record(Stage::PeerCleanup, Box::new(error));
            }
            let outstanding = signer.close();
            reporter.warning("cadet.peer.forced",format_args!("cadet forced physical retirement dh-operations={} sign-operations={}; effects-quiescence=pending",closed.identity_dh.iter().flatten().count(),outstanding.iter().flatten().count()));
            shutdown = Shutdown::Forced(lifecycle::Bound::after(limits.forced_drain)?);
        } else if shutdown.forced() && grace_done {
            break;
        }
        // Ready cleanup observations may otherwise monopolize this foreground
        // future and starve the native IO/signal/timer driver. Spend one runtime
        // cooperative unit per bounded turn; retained owners/cursors stay put.
        tokio::task::consume_budget().await;
    }
    // No extra discovery IO at exit: STOP is requested on each actual GET,
    // then the original MQ is physically retired and its facts retained.
    if let Err(error) = discovery.close() {
        failures.record(Stage::PeerCleanup, error);
    }
    if let Err(error) = transport.close() {
        failures.record(Stage::PeerCleanup, error);
    }
    reporter.message(
        gnunet_program_host::policy::Level::INFO,
        "cadet.peer.transport.summary",
        format_args!(
            "cadet original-demand TRANSPORT hints={:?}",
            transport.report()
        ),
    );
    reporter.message(
        gnunet_program_host::policy::Level::INFO,
        "cadet.peer.discovery.summary",
        format_args!("cadet original-open DHT discovery={:?}", discovery.report()),
    );
    // Even an early quiescent/error path stops the independent signing MQ.
    let sign_retired = signer.close();
    // All actual native stops above have happened; keep original Node/Book
    // alive to observe any honest retained cleanup inventory before Drop.
    {
        let mut snapshot = node.statistics();
        snapshot.merge(history);
        dependencies.statistics.observe(&snapshot);
    }
    if !node.quiescent() && !(shutdown.replacing() && node.peers_retired() && signer.jobs_retired())
    {
        failures.record(Stage::PeerCleanup,Box::new(io::Error::other("actual peer sockets stopped; original coordinator effects did not fully drain before the finite shutdown bound")));
    }
    // One bounded record per fixed slot's last original occupant. These are
    // authenticated owner inputs/results, not payload, key or a packet history.
    for observation in node.channel_observations() {
        reporter.message(
            gnunet_program_host::policy::Level::INFO,
            "cadet.peer.channel-inputs",
            format_args!("cadet original channel input time-domain=native-elapsed observations={observation:?}"),
        );
    }
    reporter.message(gnunet_program_host::policy::Level::INFO,"cadet.peer.summary",format_args!("cadet peer summary={:?} first-refusal={:?} signer={:?} final-sign-retirements={} coordinator-quiescent={}",node.report(),first_refusal,signer.report(),sign_retired.iter().flatten().count(),node.quiescent()));
    if failures.is_empty()
        && !reporter.failed()
        && let Some((identity, hard)) = shutdown.take_replacement()
    {
        if !signer.jobs_retired() {
            return Err(ProtocolError::NotReady.into());
        }
        node.release_applications()?;
        history.merge(&node.peer_statistics().into_history());
        return Ok(Exit::Replace { identity, hard });
    }
    Ok(Exit::Stopped)
}

pub(super) async fn run<'p>(
    settings: &ApplicationSettings,
    listeners: &[Listener<'_>],
    dependencies: &mut Dependencies<'p, '_>,
    mut identity: Identity<'p>,
    server: &mut Server<'_, '_, '_>,
    setup: Setup<'_, '_>,
    failures: &mut Failures,
) -> Result<(), Box<dyn Error>> {
    let Setup { endpoints, ready } = setup;
    let mut history = gnunet_cadet::statistics::Snapshot::new();
    let mut hard = None;
    loop {
        let mut snapshot = server.statistics();
        snapshot.merge(&history);
        dependencies.statistics.observe(&snapshot);
        let next = generation(
            settings,
            listeners,
            dependencies,
            server,
            Setup {
                endpoints: endpoints.duplicate()?,
                ready,
            },
            failures,
            Continuity {
                anchor: Anchor { identity, hard },
                history: &mut history,
            },
        )
        .await;
        match next {
            Ok(Exit::Replace {
                identity: observed,
                hard: original,
            }) if failures.is_empty() && !dependencies.reporter.failed() => {
                server.rebind_local_peer(*observed.peer().as_bytes())?;
                identity = observed;
                hard = Some(original);
            }
            Ok(_) => return Ok(()),
            Err(error) => {
                let mut snapshot = server.statistics();
                snapshot.merge(&history);
                dependencies.statistics.observe(&snapshot);
                return Err(error);
            }
        }
    }
}
impl Endpoints {
    fn duplicate(&self) -> Result<Self, gnunet_client_host::ConnectError> {
        Ok(Self {
            core: self.core.duplicate()?,
            dht: self.dht.duplicate()?,
            transport: self.transport.duplicate()?,
            dh: self.dh.duplicate()?,
            signing: self.signing.duplicate()?,
        })
    }
}
