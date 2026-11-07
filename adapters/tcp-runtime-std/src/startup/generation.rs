//! One immutable TCP identity generation and all original physical cleanup.
use super::{
    Diagnostic, Failure, IdentityEvent, Limits, Observers, Report, ReversalEvent, TransportEvent,
    identity, independent, observation, publication, replay, reversal,
};
use crate::statistics::StatisticsFactory;
use crate::{
    Pool, PoolProgress, Setup, addresses, dial::Dial, listeners::Listeners, settings::Settings,
};
use gnunet_client_host::EndpointSource;
use gnunet_config::Configuration;
use gnunet_crypto::Entropy;
use gnunet_nat_client_host as nat;
use gnunet_pils::client as pc;
use gnunet_pils_host::client::{self as pils, Client};
use gnunet_resolver_broker::LiveConfiguration;
use gnunet_service_runtime::{
    accepted::{AcceptState, SocketEvent},
    clock::RuntimeClock,
    connection::Connection,
    service::PeerAddress,
};
use gnunet_tcp_communicator_core::{
    registry::Slot,
    session::{
        Buffers, CIPHERTEXT_CAPACITY, CompletionSlot, Identity, KeyRing, REPLAY_CAPACITY, Scope,
    },
    wire,
};
use gnunet_tcp_communicator_host::{Clock, CreateId, HostError, ManagerCapacity, OwnedFailure};
use gnunet_types::Error;
use std::{
    error::Error as StdError,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    task::Poll,
    time::Duration,
};

pub(super) struct Input<'run, 'id, S: ?Sized, F: StatisticsFactory> {
    pub config: &'run Configuration,
    pub settings: &'run Settings,
    pub listeners: &'run Listeners,
    pub namespace: &'run replay::Namespace,
    pub continuity: &'run mut identity::Continuity<'id>,
    pub limits: Limits,
    pub identity: pc::Identity<'id>,
    pub connections: [Connection; 2],
    pub transport: &'run mut Dial,
    pub pils: &'run mut Client<'id>,
    pub resolver: &'run mut gnunet_resolver_broker::Driver<128, 256>,
    pub shutdown: Pin<&'run mut S>,
    pub ready: &'run mut dyn FnMut(&Listeners, [u8; 32]) -> io::Result<()>,
    pub observers: Observers<'run>,
    pub endpoint: &'run dyn Fn(&'static [u8]) -> EndpointSource,
    pub source: Arc<dyn RuntimeClock>,
    pub live: &'run LiveConfiguration,
    pub context: &'run gnunet_resolver_broker::Context<128, 256>,
    pub statistics: &'run mut Option<observation::Owner<F::Driver>>,
    pub statistics_factory: &'run mut Option<F>,
    pub last_metrics: &'run mut Option<crate::statistics::Metrics>,
}

pub(super) struct Exit {
    pub report: Report,
    pub replacing: bool,
}
#[derive(Clone, Copy)]
enum Phase {
    Active,
    Replacing,
    Stopping,
}
impl Phase {
    fn active(self) -> bool {
        matches!(self, Self::Active)
    }
    fn replacing(self) -> bool {
        matches!(self, Self::Replacing)
    }
}

pub(super) async fn run<S, F>(input: Input<'_, '_, S, F>) -> Result<Exit, Failure>
where
    S: Future<Output = io::Result<()>> + ?Sized,
    F: StatisticsFactory,
{
    let Input {
        config,
        settings,
        listeners,
        namespace,
        continuity,
        limits,
        identity,
        connections,
        transport: tr,
        pils,
        resolver,
        mut shutdown,
        ready,
        observers,
        endpoint,
        source,
        live,
        context,
        statistics,
        statistics_factory,
        last_metrics,
    } = input;
    let Observers {
        socket: observe_socket,
        pils: observe_pils,
        diagnostic: diagnose,
        resolver: observe_resolver,
        addresses: observe_addresses,
        failed,
    } = observers;
    let listener_ports = listeners.ports();
    let mut cursor = 0;
    let keys = pils.with_active_seed(|seed| KeyRing::from_seed(*seed))?;
    if keys.public() != identity.peer() {
        return Err(Error::Authentication.into());
    }
    let entries = limits
        .sessions
        .checked_mul(REPLAY_CAPACITY)
        .ok_or(Error::Overflow)?;
    poll_fn(|cx| Poll::Ready(continuity.guard(cx))).await?;
    let mut poll_observation = |step: replay::Observation<'_, '_>| {
        statistics.as_mut().is_some_and(|owner| match step {
            replay::Observation::Poll(cx) => owner.poll(cx, failed()),
            replay::Observation::Abort => {
                owner.abort();
                true
            }
        })
    };
    let prepared = replay::bootstrap(replay::Bootstrap {
        config,
        namespace,
        continuity,
        source,
        identity,
        pils,
        resolver,
        shutdown: shutdown.as_mut(),
        observe_pils,
        observe_resolver,
        diagnose,
        failed,
        entries,
        poll_observation: &mut poll_observation,
    })
    .await?;
    let mut clock = match prepared {
        replay::Prepared::Ready(clock) => clock,
        replay::Prepared::Stop => {
            let _original = pils.close();
            return Ok(Exit {
                report: Report::default(),
                replacing: false,
            });
        }
        replay::Prepared::Superseded => {
            return Ok(Exit {
                report: Report::default(),
                replacing: true,
            });
        }
    };
    // This finally encloses every fallible allocation, Pool admission and
    // runtime exit after the actual original worker has been admitted.
    let mut quiescent = None;
    let mut epoch_started = false;
    let mut cleanup_hard = None;
    let mut replacing = false;
    let outcome = async {
        let mut storage = Vec::new();
        storage
            .try_reserve_exact(limits.sessions)
            .map_err(|_| Error::Capacity)?;
        let mut slots = Vec::new();
        let registry_slots=limits.sessions.checked_mul(2).ok_or(Error::Capacity)?;
        slots.try_reserve_exact(registry_slots).map_err(|_|Error::Capacity)?;
        slots.resize_with(registry_slots,Slot::new);
        for _ in 0..limits.sessions {
            let stopped = poll_fn(|cx| Poll::Ready(if failed() { Ok(true) } else {
                match shutdown.as_mut().poll(cx) {
                    Poll::Ready(result) => result.map(|()| true), Poll::Pending => Ok(false),
                }
            })).await?;
            if stopped { cleanup_hard=Some(tokio::time::Instant::now()+Duration::from_secs(30)); return Ok(Report::default()); }
            storage.push(Storage::new(limits.ipc.callbacks)?);
            tokio::task::yield_now().await;
        }
        let mut buffers = Vec::new();
        buffers
            .try_reserve_exact(limits.sessions)
            .map_err(|_| Error::Capacity)?;
        buffers.extend(storage.iter_mut().map(Storage::buffers));
        let mut scope = Scope::new();
        let services = connections;
        let mut pool = Pool::new(Setup {
            services,
            identity: Identity::from_keys(&keys),
            scope: &mut scope,
            slots: &mut slots,
            buffers,
            policy: settings.policy,
            ipc: limits.ipc,
            capacity: ManagerCapacity {
                sessions: limits.sessions,
                pending_sends: limits.pending_sends,
                commands: limits.commands,
            },
            disable_v6: settings.disable_v6,
        })?;
        *last_metrics=Some(continuity.combine(pool.metrics()));
        let stopped = poll_fn(|cx| Poll::Ready(if failed() { Ok(true) } else {
            match shutdown.as_mut().poll(cx) {
                Poll::Ready(result) => result.map(|()| true), Poll::Pending => Ok(false),
            }
        })).await?;
        if stopped { cleanup_hard=Some(tokio::time::Instant::now()+Duration::from_secs(30)); return Ok(Report::default()); }
        let epoch = clock.begin_epoch(identity.peer())?;
        epoch_started = true;
        pool.bind_epoch(epoch).map_err(|r| r.reason)?;
        let _first_actual = clock.read()?;
        let nat_instance = nat::Instance::new();
        let mut reversals = reversal::Driver::new(clock.source(), limits.sessions)?;
        let mut original_pool = Some(pool);
        let adopted = publication::Owner::try_adopt(
            &mut original_pool, listeners, &nat_instance, endpoint(b"nat"),
            clock.source(), settings.disable_v6,
        );
        let (mut publication, initial_failure) = match adopted {
            Ok(owner) => (owner,None),
            Err(error) => (
                publication::Owner::unpublished(original_pool.take().ok_or(Error::Conflict)?),
                Some(Box::new(error) as Failure),
            ),
        };
        let mut generation_ready = false;
        let mut result: Result<(), Failure> = initial_failure.map_or(Ok(()),Err);
        let mut phase = if result.is_err() { Phase::Stopping } else { Phase::Active };
        let mut force = !phase.active();
        let mut pending: Option<(CreateId, bool)> = None;
        let mut report = Report { generations: 1, ..Report::default() };
        let mut transport_connecting = false;
        let mut transport_restoring = None;
        let mut accepted = AcceptState::default();
        let mut listener_cursor = 0usize;
        let cleanup_deadline = tokio::time::sleep(Duration::from_secs(30));
        tokio::pin!(cleanup_deadline);
        let mut cleanup_started = false;
        let mut cleanup_expired = false;
        let mut pool_closing = false;
        let mut pool_retired = false;
        let mut resolver_live = true;
        let mut pils_live = true;
        loop {
            if let Some(pool)=publication.pool_mut(){*last_metrics=Some(continuity.combine(pool.metrics()));}
            if phase.active() && !failed()
                && let Some(generation)=transport_restoring
                && publication.pool_mut().is_some_and(|pool|pool.transport_reannounced()) {
                transport_restoring=None;
                report.transport_reannounced=report.transport_reannounced.saturating_add(1);
                diagnose(Diagnostic::Transport(TransportEvent::Reannounced{generation}));
            }
            if let Some(owner)=statistics.as_mut() {
                // This loop also has a canonical close transition before its
                // event await; do not hide an original statistics hard there.
                poll_fn(|cx|Poll::Ready(owner.guard(cx,failed() || (force && !phase.replacing())))).await;
                if failed() || (force && !phase.replacing()){owner.abort();}
                else if let Some(metrics)=*last_metrics {owner.refresh(metrics,false);}
            }
            if phase.active() && publication.is_retiring() { phase=Phase::Stopping; }
            if failed() { phase=Phase::Stopping; force = true; }
            if !matches!(phase, Phase::Stopping) {
                let checked = poll_fn(|cx| Poll::Ready(continuity.guard(cx))).await
                    .and_then(|()| {
                        let next = pils.identity().ok_or(Error::StaleGeneration)?;
                        continuity.verify(next, clock.source().as_ref())?;
                        Ok(next)
                    });
                match checked {
                    Ok(next) if phase.active() && next.peer() != identity.peer() => {
                        match continuity.changing(next, clock.source()) {
                            Ok(()) => {
                                diagnose(Diagnostic::Identity(IdentityEvent::Retiring {
                                    previous: *identity.peer().as_bytes(), next: *next.peer().as_bytes(),
                                }));
                                phase = Phase::Replacing;
                                force = true;
                            }
                            Err(error) => { result = Err(independent(result, error)); phase = Phase::Stopping; force = true; }
                        }
                    }
                    Ok(_) => {}
                    Err(error) => { result = Err(independent(result, error)); phase = Phase::Stopping; force = true; }
                }
            }
            if !phase.active() && !cleanup_started {
                // Cancel the one retained native acquisition, preserving its
                // original unobserved errno/notice. No new MQ is attached after
                // the first Stop, Logger or identity fence.
                let (retry,unreported)=tr.close();
                if let Some(retry)=retry {diagnose(Diagnostic::Retry(retry));}
                if let Some(error)=unreported {diagnose(Diagnostic::Transport(TransportEvent::DialRetired(error)));}
                transport_connecting=false;
                transport_restoring=None;
                // This owner uses a previously matched local KeyRing, not
                // outstanding PILS crypto jobs. Close the public source once;
                // no failed/Closed client is repeatedly polled during cleanup.
                if !phase.replacing() {
                    let _original = pils.close();
                    pils_live = false;
                }
                cleanup_deadline
                    .as_mut()
                    .reset(continuity.bounds().map_or_else(
                        || tokio::time::Instant::now() + Duration::from_secs(30), |(hard, _)| hard));
                cleanup_started = true;
                cleanup_hard = Some(cleanup_deadline.deadline());
                clock.begin_stop();
                publication.begin_close();
            }
            if matches!(phase, Phase::Stopping) && pils_live {
                let _original = pils.close();
                pils_live = false;
            }
            if !phase.active() && publication.has_pool()
                && ((!pool_closing && publication.is_returned()) || (force && !pool_retired)) {
                pool_closing = true;
                let pool = publication.pool_mut().ok_or(Error::Closed)?;
                let Some(last) = clock.last_time() else {
                    return Err(independent(result, "no actual time available; dirty TCP epoch retained".into()));
                };
                let closing = if force {
                    pool_retired = true;
                    pool.retire_epoch(last)
                } else {
                    match clock.read() {
                        Ok(time) => pool.begin_shutdown(time),
                        Err(error) => {
                            force = true;
                            let cause = clock.take_failure().map_or_else(
                                || Box::new(error) as Failure,
                                |e| Box::new(e) as Failure,
                            );
                            result = Err(independent(result, cause));
                            pool_retired = true;
                            pool.retire_epoch(last)
                        }
                    }
                };
                if let Err(error) = closing { result = Err(independent(result, error.into())); }
            }
            if let Some((id, value)) = &pending
                && let Some(pool) = publication.pool_mut() {
                match pool.created(id, *value) {
                    Ok(()) => pending = None,
                    Err(HostError::Core(Error::WouldBlock | Error::Capacity)) => {}
                    Err(error) => {
                        let (id,native_admitted)=pending.take().ok_or(Error::Conflict)?;
                        result = Err(independent(result,Box::new(CreateRetirement {id,native_admitted,error})));
                        phase=Phase::Stopping;
                        force = true;
                    }
                }
            }
            if phase.active() && !publication.is_retiring() && !generation_ready && statistics_factory.is_none() {
                let first = continuity.activate();
                if first && let Err(error) = ready(listeners, *identity.peer().as_bytes()) {
                    result = Err(error.into()); phase=Phase::Stopping; force = true;
                } else {
                    generation_ready = true;
                    diagnose(Diagnostic::Identity(IdentityEvent::Ready { peer: *identity.peer().as_bytes() }));
                }
            }
            if !phase.active() && pool_closing && publication.is_returned()
                && pending.is_none() && reversals.is_empty()
                && let Some(pool) = publication.pool_mut()
                && pool.is_empty() && pool.is_quiescent()
            {
                break;
            }
            #[expect(
                clippy::large_enum_variant,
                reason = "Original bounded PILS secret/loss progress remains owned across fair event selection without allocation"
            )]
            enum Running<'a,'nat> {
                Stop,
                ForceStop,
                Activity,
                StatisticsStart,
                Pils(pils::Progress<'a>),
                Pool(Result<PoolProgress, OwnedFailure>),
                Transport(Result<Connection,crate::dial::Failure>),
                Addresses(addresses::Event<'nat>),
                Reversal(reversal::Step),
                Create {id:CreateId,peer:gnunet_crypto::EddsaPublicKey,address:[u8;128],size:usize,valid:bool},
                Accept(gnunet_service_runtime::accepted::AcceptedConnection),
                Socket(gnunet_service_runtime::accepted::AcceptError),
                Timeout,
            }
            let event = {
                let mut driving = std::pin::pin!(pils.drive(None));
                let mut resolving = std::pin::pin!(resolver.drive_waiting(None, &mut *observe_resolver));
                poll_fn(|cx| {
                    let statistics_activity=statistics.as_mut().is_some_and(|owner|owner.guard(cx,failed() || (force && !phase.replacing())));
                    if !force && failed() { return Poll::Ready(Ok(Running::ForceStop)); }
                    if !matches!(phase, Phase::Stopping) && let Err(error) = continuity.guard(cx) {
                        return Poll::Ready(Err(error));
                    }
                    if !matches!(phase, Phase::Stopping) && let Poll::Ready(r) = shutdown.as_mut().poll(cx) {
                        return Poll::Ready(
                            r.map(|()| Running::Stop)
                                .map_err(|e| Box::new(e) as Failure),
                        );
                    }
                    if cleanup_started && !cleanup_expired && cleanup_deadline.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(Ok(Running::Timeout));
                    }
                    if let Some(pool)=publication.pool_mut()
                        && let Some(error)=pool.poll_native_guard(cx) {
                        return Poll::Ready(Ok(Running::Pool(Err(error))));
                    }
                    if let Some(step)=reversals.guard(cx,&mut publication) {
                        return Poll::Ready(Ok(Running::Reversal(step)));
                    }
                    // First publisher construction is selected only after this
                    // same original Stop/Logger/native guard and before any peer
                    // class can create nonzero observations for its baseline.
                    if phase.active() && !failed() && statistics_factory.is_some(){return Poll::Ready(Ok(Running::StatisticsStart));}
                    // A permanent process-port failure is reported once. Polling
                    // that refused owner again would starve original cleanup below.
                    let activity = if resolver_live && !failed() && !cleanup_expired {
                        match resolving.as_mut().poll(cx) {
                            Poll::Ready(Ok(_)) => true,
                            Poll::Ready(Err(error)) => {
                                resolver_live = false;
                                return Poll::Ready(Err(Box::new(error) as Failure));
                            }
                            Poll::Pending => false,
                        }
                    } else {
                        false
                    };
                    if !force && failed() { return Poll::Ready(Ok(Running::ForceStop)); }
                    for offset in 0..8 {
                        let part = (cursor + offset) % 8;
                        match part {
                            0 => {
                                if !pils_live { continue; }
                                if let Poll::Ready(r) = driving.as_mut().poll(cx) {
                                    cursor = 1;
                                    return Poll::Ready(
                                        r.map(Running::Pils).map_err(|e| Box::new(e) as Failure),
                                    );
                                }
                            }
                            1 => {
                                let Some(pool) = publication.pool_mut() else { continue; };
                                if force && !pool_retired { continue; }
                                let polled = if force {
                                    match clock.last_time() {
                                        Some(last) => pool.poll_retire(cx, last, &mut clock, &mut Random),
                                        None => {
                                            return Poll::Ready(Err(
                                                "missing original cleanup time".into()
                                            ));
                                        }
                                    }
                                } else {
                                    pool.poll_drive(cx, &mut clock, &mut Random)
                                };
                                if let Poll::Ready(r) = polled {
                                    cursor = 2;
                                    return Poll::Ready(Ok(Running::Pool(r)));
                                }
                            }
                            2 => {
                                if let Poll::Ready(event) = publication.poll(cx, phase.active() && !failed()) {
                                    cursor = 3;
                                    return Poll::Ready(Ok(Running::Addresses(event)));
                                }
                            }
                            3 => {
                                if let Poll::Ready(step)=reversals.poll(cx,&mut publication,&mut clock,&mut Random,identity.peer(),phase.active()&&!failed()) {
                                    cursor=4;return Poll::Ready(Ok(Running::Reversal(step)));
                                }
                            }
                            4 => {
                                if phase.active() && !publication.is_retiring() && reversals.can_accept()
                                    && publication.pool_mut().is_some_and(|pool| pool.available() > 0)
                                    && accepted.ready() {
                                    for offset in 0..listener_ports.len() {
                                        let i = (listener_cursor + offset) % listener_ports.len();
                                        if let Poll::Ready(r) =
                                            listener_ports[i].poll_canonical_connection(cx)
                                        {
                                            listener_cursor = (i + 1) % listener_ports.len();
                                            cursor = 5;
                                            return Poll::Ready(Ok(match r {
                                                Ok(c) => Running::Accept(c),
                                                Err(e) => Running::Socket(e),
                                            }));
                                        }
                                    }
                                }
                            }
                            5=>{
                                if phase.active() && !publication.is_retiring() && pending.is_none() && !reversals.has_create()
                                    && let Some(pool)=publication.pool_mut() && let Some(command)=pool.command() {
                                    let mut address=[0;128];let size=command.address.len();let valid=size<=address.len();
                                    if valid {address[..size].copy_from_slice(command.address);}
                                    cursor=6;
                                    return Poll::Ready(Ok(Running::Create{id:command.id,peer:command.peer,address,size,valid}));
                                }
                            }
                            6=>{
                                if let Some(owner)=statistics.as_mut() && owner.poll(cx,failed() || (force && !phase.replacing())){
                                    cursor=7;return Poll::Ready(Ok(Running::Activity));
                                }
                            }
                            _=>{
                                if phase.active() && !failed() && transport_connecting {
                                    if let Some(retry)=tr.take_retry(){diagnose(Diagnostic::Retry(retry));}
                                    if failed(){return Poll::Ready(Ok(Running::ForceStop));}
                                    if let Poll::Ready(result)=tr.poll(cx){
                                        cursor=0;return Poll::Ready(Ok(Running::Transport(result)));
                                    }
                                }
                            }
                        }
                    }
                    if activity || statistics_activity {
                        Poll::Ready(Ok(Running::Activity))
                    } else {
                        Poll::Pending
                    }
                })
                .await
            };
            if let Some(pool)=publication.pool_mut(){*last_metrics=Some(continuity.combine(pool.metrics()));}
            match event {
                Ok(Running::StatisticsStart)=>{
                    if !failed() && phase.active() && let Some(factory)=statistics_factory.take(){
                        let metrics=publication.pool_mut().ok_or(Error::Closed)?.metrics();
                        *last_metrics=Some(metrics);
                        *statistics=Some(observation::create(factory,live.clone(),context.resolution_context(),clock.source(),metrics));
                    }
                },
                Ok(Running::Transport(connection))=>{
                    transport_connecting=false;
                    match connection {
                        Ok(connection) if phase.active() && !failed()=>{
                            let pool=publication.pool_mut().ok_or(Error::Closed)?;
                            match pool.attach_transport(connection) {
                                Ok(())=>{
                                    let generation=pool.transport_epoch();
                                    transport_restoring=Some(generation);
                                    report.transport_attachments=report.transport_attachments.saturating_add(1);
                                    diagnose(Diagnostic::Transport(TransportEvent::Attached{generation}));
                                },
                                Err(rejected)=>{
                                    drop(rejected.value);
                                    result=Err(independent(result,rejected.reason.into()));
                                    phase=Phase::Stopping;force=true;
                                },
                            }
                        },
                        Ok(connection)=>{drop(connection);phase=Phase::Stopping;},
                        Err(error)=>{result=Err(independent(result,Box::new(error)));phase=Phase::Stopping;force=true;},
                    }
                },
                Ok(Running::Create{id,peer,address,size,valid})=>{
                    if failed(){phase=Phase::Stopping;force=true;continue;}
                    let pool=publication.pool_mut().ok_or(Error::Closed)?;
                if let Err(error)=pool.claim_create(&id) {
                    return Err(independent(result,Box::new(CreateRetirement {id,native_admitted:false,error})));
                }
                report.creates = report.creates.saturating_add(1);
                let reverse = valid && gnunet_tcp_communicator_core::registry::Address::parse(&address[..size])
                    .and_then(|address| address.reversal()).unwrap_or(false);
                if reverse {
                    match reversals.start(pool,id,peer,&address[..size]) {
                        Ok(())=>{},
                        Err(rejected)=>{
                            report.rejected=report.rejected.saturating_add(1);
                            diagnose(Diagnostic::Admission(crate::AdmissionError::Core(rejected.reason)));
                            pending=Some((rejected.value,false));
                        }
                    }
                } else {
                    let admission = if valid {
                        match clock.read() {
                            Ok(time) => pool.outbound(peer, &address[..size], time, &mut Random),
                            Err(error) => Err(crate::AdmissionError::Core(error)),
                        }
                    } else { Err(crate::AdmissionError::Core(Error::TooLarge)) };
                    let value=match admission {
                        Ok(_)=>{report.outbound=report.outbound.saturating_add(1);true},
                        Err(original)=>{report.rejected=report.rejected.saturating_add(1);diagnose(Diagnostic::Admission(original));false},
                    };
                    pending=Some((id,value));
                }
                if let Some(cause)=clock.take_failure() {
                    result=Err(independent(result,Box::new(cause)));
                    phase=Phase::Stopping;force=true;
                }
                },
                Ok(Running::Stop) => phase=Phase::Stopping,
                Ok(Running::ForceStop) => {
                    phase=Phase::Stopping; force = true;

                },
                Ok(Running::Activity) => {}
                Ok(Running::Timeout) => {
                    result = Err(independent(result,
                        "TCP cleanup deadline: dirty original epoch retained for explicit backend recovery".into()));
                    cleanup_expired = true; phase=Phase::Stopping; force = true;
                    let had_addresses = publication.has_addresses();
                    publication.abort();
                    if !had_addresses {
                        return Err(independent(result,Box::new(AddressAborted {pending,report,reversal:reversals.retirement()})));
                    }
                },
                Ok(Running::Reversal(step)) => {
                    if let Some(created)=step.created {
                        if pending.is_some() {return Err(independent(result,Error::Conflict.into()));}
                        if created.1 {report.outbound=report.outbound.saturating_add(1);}else{report.rejected=report.rejected.saturating_add(1);}
                        pending=Some(created);
                    }
                    if matches!(&step.event,ReversalEvent::Handoff{result:Ok(_),..}) {report.accepted=report.accepted.saturating_add(1);}
                    diagnose(Diagnostic::Reversal(step.event));
                    if let Some(error)=step.fatal {result=Err(independent(result,error.into()));phase=Phase::Stopping;force=true;}
                    if let Some(cause)=clock.take_failure(){result=Err(independent(result,Box::new(cause)));phase=Phase::Stopping;force=true;}
                },
                Ok(Running::Addresses(event)) => {
                    observe_addresses(&event);
                    match event {
                        addresses::Event::Failed(error) => {
                            result=Err(independent(result,Box::new(error)));
                            phase=Phase::Stopping;force=true;
                        },
                        addresses::Event::Nat(nat::Progress::Ended(end))
                            if matches!(&end.source.cause,nat::Cause::Clock(_) | nat::Cause::Error(nat::Error::Clock(_))) => {
                            result=Err(independent(result,Box::new(NatClockFailure(end.source.cause))));
                            phase=Phase::Stopping;force=true;
                        },
                        addresses::Event::Aborted => return Err(independent(result,Box::new(AddressAborted {pending,report,reversal:reversals.retirement()}))),
                        _=>{},
                    }
                    if phase.active() && publication.is_retiring() {phase=Phase::Stopping;}
                },
                Ok(Running::Pils(original)) => {
                    if let pils::Progress::Inbound(pc::Inbound::Identity { .. }) = &original {
                        report.identity_updates = report.identity_updates.saturating_add(1);
                    }
                    if let Err(error) = identity::observe(original, observe_pils) {
                        result = Err(independent(result, error)); phase = Phase::Stopping; force = true;
                    }
                }
                Ok(Running::Pool(Ok(PoolProgress::Retired(_)))) => {
                    report.retired = report.retired.saturating_add(1);
                    accepted.client_closed();
                }
                Ok(Running::Pool(Ok(_))) => {}
                Ok(Running::Pool(Err(original))) => {
                    if let Some(id) = &original.session {
                        publication.pool_mut().ok_or(Error::Closed)?.lost(id)?;
                        diagnose(Diagnostic::Peer(original));
                    } else {
                        let clock_failure=clock.take_failure();
                        let recoverable= phase.active() && !failed() && clock_failure.is_none()
                            && original.cause.transport_io_retired()
                            && publication.pool_mut().is_some_and(|pool| !pool.transport_online() && !pool.history_recovery_required());
                        if recoverable {
                            // The host already retired only this old MQ's flows,
                            // commands and SEND callbacks. Keep the same Pool,
                            // healthy TCP streams/cipher cursors and replay epoch.
                            transport_restoring=None;
                            if let Some((id,native_admitted))=pending.take(){
                                report.creates_retired=report.creates_retired.saturating_add(1);
                                diagnose(Diagnostic::Transport(TransportEvent::CreateRetired{id,native_admitted,cancellation:None}));
                            }
                            let mut reversal_failed=false;
                            reversals.transport_lost(&mut publication,|id,native_admitted,cancellation|{
                                reversal_failed |= cancellation.is_some();
                                report.creates_retired=report.creates_retired.saturating_add(1);
                                diagnose(Diagnostic::Transport(TransportEvent::CreateRetired{id,native_admitted,cancellation}));
                            });
                            report.transport_losses=report.transport_losses.saturating_add(1);
                            diagnose(Diagnostic::Transport(TransportEvent::Lost(original)));
                            if reversal_failed {
                                result=Err(independent(result,Error::Conflict.into()));phase=Phase::Stopping;force=true;
                            } else if failed() {
                                phase=Phase::Stopping;force=true;
                            } else if let Err(error)=tr.restart() {
                                result=Err(independent(result,error.into()));phase=Phase::Stopping;force=true;
                            } else {
                                transport_connecting=true;
                            }
                            continue;
                        }
                        let cause = match clock_failure {
                            None => Box::new(original) as Failure,
                            Some(error) => independent(Err(Box::new(original)), Box::new(error)),
                        };
                        if force && cleanup_started && pool_retired {
                            // The original shared owner has failed while already
                            // retiring. Drop closes its physical MQs; no clean proof
                            // is returned and no repeated cause log can grow forever.
                            return Err(independent(Err(independent(result,cause)),Box::new(reversals.retirement())));
                        }
                        result = Err(independent(result, cause));
                        phase=Phase::Stopping;
                        force = true;

                    }
                }
                Ok(Running::Socket(error)) => observe_socket(accepted.failed(error)),
                Ok(Running::Accept(original)) => {
                    let (connection, peer, diagnostics) = original.into_parts();
                    for d in diagnostics {
                        observe_socket(SocketEvent::Diagnostic(d));
                    }
                    if failed() { drop(connection); phase=Phase::Stopping; force = true; continue; }
                    let PeerAddress::Tcp(address) = peer else {
                        return Err("TCP listener returned non-TCP peer".into());
                    };
                    if let Err(error)=reversals.accept(connection,address) {
                        report.rejected=report.rejected.saturating_add(1);
                        diagnose(Diagnostic::Admission(crate::AdmissionError::Core(error)));
                    }
                    if let Some(cause)=clock.take_failure() {
                        result=Err(independent(result,Box::new(cause)));
                        phase=Phase::Stopping;force=true;
                    }
                }
                Err(error) => {
                    result = Err(independent(result, error));
                    phase=Phase::Stopping;
                    force = true;

                }
            }
            tokio::task::yield_now().await;
        }
        let pool = publication.take_pool().ok_or(Error::Closed)?;
        *last_metrics=Some(continuity.combine(pool.metrics()));
        let proof = match pool.into_quiescent() {
            Ok(proof) => proof,
            Err(original) => return Err(independent(result, original.reason.into())),
        };
        quiescent = Some(proof);
        result?;
        replacing = phase.replacing();
        if !replacing { let _original = pils.close(); }
        Ok(report)
        }.await;
    if outcome.is_err() || !replacing {
        let _original = pils.close();
    }
    if (!replacing || outcome.is_err())
        && let Some(owner) = statistics.as_mut()
    {
        owner.begin_close(*last_metrics, outcome.is_ok() && !failed());
    }
    let finishing = replay::finish(
        &mut clock,
        quiescent,
        epoch_started,
        outcome,
        cleanup_hard,
        diagnose,
    );
    let report = if let Some(owner) = statistics.as_mut() {
        owner
            .worker(finishing, resolver, observe_resolver, failed)
            .await?
    } else {
        finishing.await?
    };
    Ok(Exit { report, replacing })
}

struct Storage {
    rx: Vec<u8>,
    tx: Vec<u8>,
    plain: Vec<u8>,
    completions: Vec<CompletionSlot>,
}
fn zeroes(n: usize) -> Result<Vec<u8>, Error> {
    let mut b = Vec::new();
    b.try_reserve_exact(n).map_err(|_| Error::Capacity)?;
    b.resize(n, 0);
    Ok(b)
}
impl Storage {
    fn new(callbacks: usize) -> Result<Self, Error> {
        let mut completions = Vec::new();
        completions
            .try_reserve_exact(callbacks)
            .map_err(|_| Error::Capacity)?;
        completions.resize_with(callbacks, CompletionSlot::default);
        Ok(Self {
            rx: zeroes(wire::MAX_RECORD)?,
            tx: zeroes(CIPHERTEXT_CAPACITY)?,
            plain: zeroes(wire::MAX_RECORD)?,
            completions,
        })
    }
    fn buffers(&mut self) -> Buffers<'_> {
        Buffers {
            receive: &mut self.rx,
            transmit: &mut self.tx,
            plaintext: &mut self.plain,
            completions: &mut self.completions,
        }
    }
}

struct Random;
impl Entropy for Random {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(out).map_err(|_| Error::Entropy)
    }
}

#[derive(Debug)]
struct NatClockFailure(nat::Cause);
impl std::fmt::Display for NatClockFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "original NAT clock/source: {:?}", self.0)
    }
}
impl StdError for NatClockFailure {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match &self.0 {
            nat::Cause::Io(error) => Some(error),
            nat::Cause::Ports(error) => Some(error),
            nat::Cause::Error(error) => Some(error),
            _ => None,
        }
    }
}
#[derive(Debug)]
struct CreateRetirement {
    id: CreateId,
    native_admitted: bool,
    error: HostError,
}
impl std::fmt::Display for CreateRetirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "original TCP CREATE {:?} native-admitted={} has no callback write completion: {}",
            self.id, self.native_admitted, self.error
        )
    }
}
impl StdError for CreateRetirement {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&self.error)
    }
}
#[derive(Debug)]
struct AddressAborted {
    pending: Option<(CreateId, bool)>,
    report: Report,
    reversal: reversal::Retirement,
}
impl std::fmt::Display for AddressAborted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "original TCP address/Pool physically aborted; dirty epoch retained; pending CREATE={:?}; observed {:?}; {}",
            self.pending, self.report, self.reversal
        )
    }
}
impl StdError for AddressAborted {}
