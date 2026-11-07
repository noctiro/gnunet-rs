//! Direct caller-driven SERVICE over the original native TUN/CADET/REGEX owners.
use crate::{
    Failure,
    control::Signals,
    discovery,
    lifecycle::{self, Cleanup, Stage},
    settings::{self, Settings, TunMode},
};
use gnunet_cadet_host as cadet;
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_config::Configuration;
use gnunet_program_host::{policy::Level, reporting::Reporter};
use gnunet_resolver_broker::Driver as ResolverDriver;
use gnunet_service_runtime::{
    BoundListeners,
    clock::RuntimeClock,
    service::{Listener, ShutdownMode},
};
use gnunet_service_startup::{ParentControl, daemon::ChildReady};
use gnunet_tun_host as tun;
use gnunet_vpn as core;
use gnunet_vpn_host::{
    coordinator::{Coordinator, Device, Event, Parts, Progress},
    server,
};
use std::{
    future::{Future, poll_fn},
    io::{self, Write},
    os::fd::OwnedFd,
    sync::Arc,
    task::Poll,
};
use tokio::time::Instant;
struct Diagnostics {
    backend: bool,
    failed: bool,
    reports: Reporter,
    cleanup: Cleanup,
}
impl Diagnostics {
    fn new(reports: Reporter, cleanup: Cleanup) -> Self {
        Self {
            backend: false,
            failed: false,
            reports,
            cleanup,
        }
    }
    fn observe(&mut self, event: Event<'_, '_>) {
        match event {
            Event::BackendConnected(epoch)=>{
                self.backend=true;
                self.reports.debug("vpn.cadet.connected",format_args!("VPN actual CADET attached epoch={}",epoch.value()));
            },
            Event::BackendLost{report,cause}=>{
                self.backend=false;
                self.reports.warning("vpn.cadet.lost",format_args!("VPN original CADET lost={report:?} cause={cause:?}; original payload replay=false"));
            },
            Event::BackendRetry{error,retry_after}=>self.reports.warning("vpn.cadet.retry",format_args!("VPN actual CADET connection failed={error}; retry={retry_after:?}")),
            Event::TunLost(loss)=>{
                self.failed=true;
                self.reports.warning("vpn.tun.lost",format_args!("VPN actual original TUN loss={loss:?}"));
                self.cleanup.retain(Stage::ObservedTun,Box::new(lifecycle::TunLoss(loss)));
            },
            Event::TunCoreLost(loss)=>self.reports.debug("vpn.tun.retired",format_args!("VPN original TUN scope retired={loss:?}")),
            Event::PeerLost(loss)=>self.reports.debug("vpn.peer.retired",format_args!("VPN original peer retired={loss:?}")),
            Event::ControlFailed(error)=>{
                self.failed=true;
                self.reports.warning("vpn.control.failed",format_args!("VPN actual original native control failure={error:?}"));
                self.cleanup.retain(Stage::ObservedControl,Box::new(error));
            },
            Event::NativeError(error)=>{
                self.reports.warning("vpn.native.failed",format_args!("VPN original platform failure={error}"));
            },
            Event::CleanupUncertain{reason}=>self.reports.warning("vpn.cleanup.uncertain",format_args!("VPN original route cleanup remains uncertain={reason}")),
            Event::Route(c)=>self.reports.debug("vpn.route.complete",format_args!("VPN actual route completion={c:?}")),
            Event::RouteQuery(c)=>self.reports.debug("vpn.route.query",format_args!("VPN actual route query={c:?}")),
            Event::Applied(r)=>self.reports.debug("vpn.native.applied",format_args!("VPN actual native applied={r:?}")),
            Event::Snapshot(s)=>self.reports.debug("vpn.interface.snapshot",format_args!("VPN actual original interface snapshot={s:?}")),
            Event::Ipv6(o)=>self.reports.debug("vpn.ipv6.observed",format_args!("VPN actual IPv6 observation={o:?}")),
            Event::Ipv6Ended(c)=>self.reports.debug("vpn.ipv6.retired",format_args!("VPN original IPv6 observer retired={c:?}")),
            Event::Dropped{flow,reason}=>self.reports.debug("vpn.packet.refused",format_args!("VPN input refused flow={flow:?} reason={reason}")),
            Event::RetiredWrite{transmit,effect,complete}=>self.reports.debug("vpn.write.retiring",format_args!("VPN original channel retired during actual TX: tx={transmit:?} effect={effect:?} whole={complete}")),
            Event::Discovery(d)=>self.reports.warning("vpn.discovery.unhandled",format_args!("VPN unhandled original external discovery={d:?}")),
            Event::Ipc(server::Event::Closed{client,cause,loss})=>self.reports.debug("vpn.ipc.closed",format_args!("VPN original IPC closed client={} cause={cause:?} loss={loss:?}",client.value())),
            Event::Ipc(server::Event::CleanupFailed(error))=>{
                self.failed=true;
                self.reports.warning("vpn.ipc.cleanup.failed",format_args!("VPN original IPC cleanup failure={error}"));
                self.cleanup.retain(Stage::ObservedIpc,Box::new(error));
            },
            _=>{},
        }
    }
}
fn observe_regex(reports: &Reporter, event: discovery::Event<'_, '_>) {
    match event {
        discovery::Event::Constructed{discovery,job}=>reports.debug("vpn.regex.constructed",format_args!("VPN REGEX original constructed discovery={discovery:?} job={job:?}")),
        discovery::Event::Queued{discovery,job,epoch}=>reports.debug("vpn.regex.queued",format_args!("VPN REGEX actual request queued discovery={discovery:?} job={job:?} epoch={epoch:?}")),
        discovery::Event::Written{discovery,job,epoch}=>reports.debug("vpn.regex.written",format_args!("VPN REGEX original whole local write discovery={discovery:?} job={job:?} epoch={epoch:?}; no service ACK")),
        discovery::Event::Selected{discovery,job,epoch,peer}=>reports.debug("vpn.regex.selected",format_args!("VPN REGEX actual discovered peer discovery={discovery:?} job={job:?} epoch={epoch:?} peer={peer:02x?}; endpoint authentication unclaimed")),
        discovery::Event::Inconclusive{discovery,reason}=>reports.warning("vpn.regex.inconclusive",format_args!("VPN REGEX original inconclusive discovery={discovery:?} reason={reason}; no-exit proof absent")),
        discovery::Event::NativeEnded{discovery,end}=>reports.debug("vpn.regex.retired",format_args!("VPN REGEX actual original MQ retired discovery={discovery:?} native={end:?}; remote revocation unclaimed")),
        discovery::Event::NativeError{discovery,error}=>reports.warning("vpn.regex.native.failed",format_args!("VPN REGEX original native failure discovery={discovery:?} error={error}")),
        discovery::Event::VpnError{discovery,error}=>reports.warning("vpn.regex.core.failed",format_args!("VPN REGEX original VPN refusal discovery={discovery:?} error={error}")),
        discovery::Event::Retired{discovery,original_already_stale}=>reports.debug("vpn.regex.settled",format_args!("VPN REGEX original job retired discovery={discovery:?} already-stale={original_already_stale}")),
    }
}
fn resolver_event(reports: &Reporter, event: gnunet_resolver_broker::DriverEvent) {
    match event {
        gnunet_resolver_broker::DriverEvent::Lost { .. }
        | gnunet_resolver_broker::DriverEvent::Unavailable
        | gnunet_resolver_broker::DriverEvent::SocketRetry { .. } => reports.warning(
            "vpn.resolver.failed",
            format_args!("VPN actual Resolver {event:?}"),
        ),
        _ => reports.debug(
            "vpn.resolver.activity",
            format_args!("VPN actual Resolver {event:?}"),
        ),
    }
}
struct Resolver {
    driver: ResolverDriver<64, 256>,
    cleanup: Cleanup,
    reports: Reporter,
    closed: bool,
}
impl Resolver {
    fn close(&mut self) {
        if self.closed {
            return;
        }
        self.closed = true;
        if let Err(error) = self.driver.disconnect() {
            self.reports.warning(
                "vpn.resolver.close.failed",
                format_args!("VPN independent Resolver disconnect: {error}"),
            );
            self.cleanup.retain(Stage::Resolver, Box::new(error));
        }
    }
}
impl Drop for Resolver {
    fn drop(&mut self) {
        self.close();
    }
}
struct Owners<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy, 'regex> {
    vpn: Coordinator<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>,
    discovery: Option<discovery::Provider<'id, 'regex>>,
    reports: Reporter,
    cleanup: Cleanup,
    done: bool,
}
impl Owners<'_, '_, '_, '_, '_, '_, '_> {
    fn close_discovery(&mut self) {
        if let Some(provider) = &mut self.discovery
            && let Err(error) = provider.close_all(&mut self.vpn, &mut |event| {
                observe_regex(&self.reports, event)
            })
        {
            self.cleanup.retain(Stage::Discovery, Box::new(error));
        }
    }
    fn retire(&mut self) {
        if self.done {
            return;
        }
        self.close_discovery();
        let regex = self.discovery.as_ref().map(|p| p.report());
        let regex_pending = self.discovery.as_ref().map_or(0, |p| p.pending());
        let mut diagnostics = Diagnostics::new(self.reports.clone(), self.cleanup.clone());
        self.vpn.close(&mut |event| diagnostics.observe(event));
        let debt = self.vpn.debt();
        if let Some(closed) = self.vpn.close_report() {
            self.cleanup.facts(lifecycle::Facts {
                native: closed.report,
                ipc: closed.ipc.report,
                cadet: closed.cadet.map(lifecycle::CadetFact::from_original),
                tun: closed.tun.as_ref().map(lifecycle::TunFact::from_original),
                unconfirmed_control_closes: closed.unconfirmed_control_closes,
                debt,
                regex,
                regex_pending,
            });
        } else {
            self.cleanup.retain(
                Stage::Coordinator,
                "VPN original close report missing".into(),
            );
        }
        self.cleanup.coordinator(self.vpn.take_cleanup_errors());
        if !matches!(
            debt.routes,
            core::RouteState::Absent | core::RouteState::BorrowedReleased
        ) || debt.flows != 0
            || debt.buffers != 0
            || debt.discoveries != 0
            || debt.unconfirmed_control_closes != 0
            || regex_pending != 0
        {
            self.cleanup.retain(Stage::Debt, core_error_unknown());
        }
        self.done = true;
    }
}
fn core_error_unknown() -> Failure {
    gnunet_types::Error::OutcomeUnknown.into()
}
impl Drop for Owners<'_, '_, '_, '_, '_, '_, '_> {
    fn drop(&mut self) {
        if !self.done {
            self.retire();
            self.reports.warning("vpn.cancelled",format_args!("VPN caller future dropped: original REGEX/IPC/CADET/TUN physical close attempted; actual independent causes/debt retained, downstream processing unclaimed"));
        }
    }
}
fn target(duration: std::time::Duration) -> Result<Instant, Failure> {
    Instant::now()
        .checked_add(duration)
        .ok_or_else(|| "VPN native deadline overflow".into())
}
async fn open(
    settings: &Settings,
    inherited: Option<OwnedFd>,
    cleanup: &Cleanup,
) -> Result<Device, Failure> {
    let limits = tun::Limits {
        packet_bytes: settings.core.packet_bytes,
    };
    let device = match settings.mode {
        TunMode::Preopened => {
            let fd = inherited.ok_or(
                "preopened mode requires GNUNET_VPN_TUN_FD exclusively transferred by the parent",
            )?;
            Device::borrow_existing(tun::AsyncTun::new(tun::OwnedTun::from_fd(fd, limits)?)?)
        }
        TunMode::Fresh => {
            if inherited.is_some() {
                return Err(
                    "fresh mode refuses GNUNET_VPN_TUN_FD; choose explicit preopened mode".into(),
                );
            }
            #[cfg(target_os = "linux")]
            {
                let ipv4 = settings
                    .core
                    .ipv4
                    .map(|prefix| match prefix.interface {
                        core::Address::V4(address) => {
                            let mask = if prefix.bits == 0 {
                                0
                            } else {
                                u32::MAX << (32 - prefix.bits)
                            };
                            Ok((address.into(), std::net::Ipv4Addr::from(mask)))
                        }
                        _ => Err(gnunet_types::Error::InvalidInput),
                    })
                    .transpose()?;
                let ipv6 = settings
                    .core
                    .ipv6
                    .map(|prefix| match prefix.interface {
                        core::Address::V6(address) => Ok((address.into(), prefix.bits)),
                        _ => Err(gnunet_types::Error::InvalidInput),
                    })
                    .transpose()?;
                Device::start_helper(
                    tun::helper::Options {
                        executable: settings
                            .helper
                            .clone()
                            .ok_or("fresh Linux helper path missing")?,
                        interface: settings.ifname.clone(),
                        ipv4,
                        ipv6,
                        mtu: settings.helper_mtu,
                        until: target(settings.coordinator.control_timeout)?,
                        partial_lifetime: settings.helper_partial,
                    },
                    limits,
                )?
            }
            #[cfg(target_os = "macos")]
            {
                let unit = settings
                    .ifname
                    .strip_prefix("utun")
                    .ok_or("macOS IFNAME must be utunN")?
                    .parse()?;
                Device::open_utun_unit(Some(unit), limits)?
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                return Err("fresh native VPN TUN is implemented only for Linux and macOS".into());
            }
        }
    };
    if device.info().name != settings.ifname {
        let observed = device.info().name.clone();
        let mut io = device.into_io();
        let loss = io.close();
        if let Some(report) = io.reap_helper().await {
            cleanup.helper(report);
        }
        return Err(Box::new(lifecycle::Qualification {
            expected: settings.ifname.clone(),
            observed,
            loss,
        }));
    }
    Ok(device)
}
enum Turn {
    Signal,
    Progress(Progress),
}
async fn turn(
    owners: &mut Owners<'_, '_, '_, '_, '_, '_, '_>,
    resolver: &mut Resolver,
    signals: &mut Signals,
    listeners: &[Listener<'_>],
    until: Option<Instant>,
    diagnostics: &mut Diagnostics,
) -> Result<Turn, Failure> {
    let reports = owners.reports.clone();
    let (vpn, discovery) = (&mut owners.vpn, &mut owners.discovery);
    let mut resolving = std::pin::pin!(
        resolver
            .driver
            .drive_waiting(until, |event| resolver_event(&reports, event))
    );
    poll_fn(|cx| {
        reports.register(cx);
        if reports.failed() {
            return Poll::Ready(Ok(Turn::Signal));
        }
        if let Poll::Ready(signal) = signals.poll(cx) {
            return Poll::Ready(signal.map(|()| Turn::Signal).map_err(Into::into));
        }
        let guarded = vpn.poll_native_guard(cx, &mut |event| diagnostics.observe(event))?;
        if reports.failed() || diagnostics.failed {
            return Poll::Ready(Ok(Turn::Signal));
        }
        let mut changed = guarded;
        changed |= match resolving.as_mut().poll(cx) {
            Poll::Ready(Ok(_)) => true,
            Poll::Ready(Err(error)) => return Poll::Ready(Err(Box::new(error) as Failure)),
            Poll::Pending => false,
        };
        if reports.failed() {
            return Poll::Ready(Ok(Turn::Signal));
        }
        let mut deferred = None;
        let mut duplicate_refusal = false;
        let step = vpn.poll(cx, listeners, until, &mut |event| match event {
            Event::Discovery(request) => {
                let refusal = if reports.failed() {
                    Some(discovery::Rejected {
                        request,
                        reason: gnunet_types::Error::Cancelled,
                    })
                } else {
                    match discovery.as_mut() {
                        Some(provider) => provider.offer(request).err(),
                        None => Some(discovery::Rejected {
                            request,
                            reason: gnunet_types::Error::Unavailable,
                        }),
                    }
                };
                if let Some(refusal) = refusal {
                    if deferred.is_some() {
                        duplicate_refusal = true
                    } else {
                        deferred = Some(refusal)
                    }
                }
            }
            event => diagnostics.observe(event),
        });
        let step = match step {
            Poll::Ready(Err(error)) => return Poll::Ready(Err(Box::new(error) as Failure)),
            other => other,
        };
        if reports.failed() || diagnostics.failed {
            return Poll::Ready(Ok(Turn::Signal));
        }
        if duplicate_refusal {
            return Poll::Ready(Err(gnunet_types::Error::Capacity.into()));
        }
        if let Some(rejected) = deferred {
            if let Err(error) = discovery::Provider::reject(rejected, vpn, &mut |event| {
                observe_regex(&reports, event)
            }) {
                return Poll::Ready(Err(Box::new(error) as Failure));
            }
            changed = true;
        }
        if reports.failed() {
            return Poll::Ready(Ok(Turn::Signal));
        }
        if let Some(provider) = discovery.as_mut() {
            match provider.poll(cx, vpn, &mut |event| observe_regex(&reports, event)) {
                Poll::Ready(Ok(())) => changed = true,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(Box::new(error) as Failure)),
                Poll::Pending => {}
            }
        }
        if reports.failed() {
            return Poll::Ready(Ok(Turn::Signal));
        }
        match step {
            Poll::Ready(Ok(progress)) => Poll::Ready(Ok(Turn::Progress(progress))),
            Poll::Ready(Err(error)) => Poll::Ready(Err(Box::new(error) as Failure)),
            Poll::Pending if changed => Poll::Ready(Ok(Turn::Progress(Progress::Activity))),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}
pub(super) struct Inputs<'a> {
    pub config: &'a Configuration,
    pub settings: &'a Settings,
    pub bound: &'a BoundListeners,
    pub parent: Option<ParentControl>,
    pub tun: Option<OwnedFd>,
    pub clock: Arc<dyn RuntimeClock>,
    pub reports: Reporter,
    pub child: &'a mut ChildReady,
    pub cleanup: Cleanup,
}
pub(super) async fn run(input: Inputs<'_>) -> Result<(), Failure> {
    let Inputs {
        config,
        settings,
        bound,
        parent,
        tun,
        clock,
        reports,
        child,
        cleanup,
    } = input;
    let mut signals = Signals::new(parent)?;
    let live = LiveConfiguration::new(config.duplicate()?);
    let (context, driver) = gnunet_resolver_broker::broker::<64, 256>(
        live.clone(),
        settings.resolver,
        gnunet_resolver_broker::native_profile()?,
        clock.clone(),
    )?;
    let mut resolver = Resolver {
        driver,
        cleanup: cleanup.clone(),
        reports: reports.clone(),
        closed: false,
    };
    let mut domain = core::Instance::new();
    let mut clients = settings::filled(settings.clients, core::ClientSlot::new)?;
    let mut requests = settings::filled(settings.requests, core::RequestSlot::new)?;
    let mut leases = settings::filled(settings.leases, core::LeaseSlot::new)?;
    let mut flows = settings::filled(settings.flows, core::FlowSlot::new)?;
    let packet_count = settings
        .small_count
        .checked_add(settings.large_count)
        .ok_or("packet count overflow")?;
    let mut backing = Vec::new();
    backing.try_reserve_exact(packet_count)?;
    for _ in 0..settings.small_count {
        backing.push(settings::bytes(settings.small_bytes)?);
    }
    for _ in 0..settings.large_count {
        backing.push(settings::bytes(settings.large_bytes)?);
    }
    let mut packets = Vec::new();
    packets.try_reserve_exact(packet_count)?;
    for b in &mut backing {
        packets.push(core::PacketSlot::new(b));
    }
    let engine = core::Engine::new(
        &mut domain,
        core::Storage {
            clients: &mut clients,
            requests: &mut requests,
            leases: &mut leases,
            flows: &mut flows,
            packets: &mut packets,
        },
        settings.core,
    )?;
    let server = server::Server::new(
        engine,
        clock.clone(),
        settings.native,
        settings.options.clone(),
        settings.unix,
    )?;
    let mut cadet_domain = cadet::Instance::new();
    let mut ports = []; // VPN is an outbound-only application, never a fake listener.
    let mut channels = settings::filled(settings.flows, cadet::ChannelSlot::new)?;
    let regex_source = settings
        .regex
        .map(|_| EndpointSource::live(live.clone(), b"regex", context.resolution_context()));
    let backend = cadet::Client::new(
        &mut cadet_domain,
        EndpointSource::live(live, b"cadet", context.resolution_context()),
        &mut ports,
        &mut channels,
        settings.cadet,
    )?;
    if reports.failed() {
        return Ok(());
    }
    if let Some(stopped) = poll_fn(|cx| match signals.poll(cx) {
        Poll::Ready(value) => Poll::Ready(Some(value)),
        Poll::Pending => Poll::Ready(None),
    })
    .await
    {
        stopped?;
        return Err("VPN stopped before helper/device admission".into());
    }
    let device = open(settings, tun, &cleanup).await?;
    let regex_domain = gnunet_regex_client_host::Instance::new();
    let mut diagnostics = Diagnostics::new(reports.clone(), cleanup.clone());
    let vpn = match Coordinator::new(
        Parts {
            server,
            cadet: backend,
            device,
        },
        &settings.exits,
        settings.coordinator,
    ) {
        Ok(vpn) => vpn,
        Err(rejected) => {
            let mut parts = rejected.parts;
            let ipc = parts
                .server
                .shutdown(|event| diagnostics.observe(Event::Ipc(event)));
            if let Some(error) = ipc.failure {
                cleanup.retain(Stage::ConstructionIpc, Box::new(error));
            }
            if let Err(error) = parts.cadet.close() {
                cleanup.retain(Stage::ConstructionCadet, Box::new(error));
            }
            let mut device = parts.device.into_io();
            let loss = device.close();
            if loss.close_error.is_some() {
                cleanup.retain(Stage::ConstructionTun, Box::new(lifecycle::TunLoss(loss)));
            }
            if let Some(report) = device.reap_helper().await {
                cleanup.helper(report);
            }
            return Err(Box::new(rejected.error));
        }
    };
    let mut owners = Owners {
        vpn,
        discovery: None,
        reports: reports.clone(),
        cleanup: cleanup.clone(),
        done: false,
    };
    let result=async {
    owners.discovery = match (settings.regex, regex_source) {
        (Some(limits), Some(source)) => Some(discovery::Provider::new(
            &regex_domain,
            source,
            owners.vpn.clock(),
            limits,
        )?),
        (None, None) => None,
        _ => return Err(gnunet_types::Error::InvalidInput.into()),
    };
    let listeners = bound.listeners();
    let startup = target(settings.startup)?;

        // Original fixed startup limit covers true provisioning/route/DAD and
        // actual CADET attachment; neither allocation nor CreateQueued is ready.
        let mut turns=0u8;
        loop {
            if reports.failed(){return Err("VPN selected diagnostic source failed before readiness".into())}
            if diagnostics.backend&&owners.vpn.tun_ready()? {break}
            match turn(&mut owners,&mut resolver,&mut signals,&[],Some(startup),&mut diagnostics).await? {
                // Exact terminal callback causes are already owned by Cleanup.
                // Main finishes them as failure without sending ChildReady.
                Turn::Signal if diagnostics.failed=>return Ok(()),
                Turn::Signal=>return Err("VPN stopped before actual TUN plan/CADET source readiness".into()),
                Turn::Progress(Progress::WaitDeadline)=>return Err("actual native VPN startup reached its original finite deadline".into()),
                Turn::Progress(Progress::Stopped)=>return Err("actual VPN sources stopped during startup".into()),
                Turn::Progress(Progress::Activity)=>{},
            }
            turns=turns.wrapping_add(1);if turns.is_multiple_of(64){tokio::task::yield_now().await;}
        }
        reports.message(Level::INFO,"vpn.ready",format_args!("VPN actual packet source and observed kernel interface plan with CADET source ready; remote reachability unclaimed"));
        if reports.failed(){return Err("VPN readiness diagnostic failed; original logger error retained".into())}
        {
            let actual = owners.vpn.device_info();
            let actual_name = &actual.name;
            let actual_index = actual.index;
            let mut output=io::stdout().lock();
            writeln!(output,"READY vpn wire=0.29.1 tun={} index={} mode={:?} native-plan=observed packet-source={} cadet=attached configured-exits={} automatic-regex={} shared-packet-bytes={} runtime=current-thread remote-reachability=unasserted",actual_name,actual_index,settings.mode,if owners.vpn.uses_helper(){"helper-pipes"}else{"native-fd"},settings.exits.len(),if settings.regex.is_some(){"on-demand-client"}else{"disabled"},settings.backing_bytes)?;
            output.flush()?;
        }
        child.ready()?;
        let mut stopping=None;
        loop {
            match turn(&mut owners,&mut resolver,&mut signals,&listeners,stopping,&mut diagnostics).await? {
                Turn::Signal if !reports.failed()&&!diagnostics.failed&&stopping.is_none()&&settings.options.shutdown==ShutdownMode::Soft=>{
                    owners.close_discovery();
                    if reports.failed(){break}
                    owners.vpn.request_shutdown();
                    stopping=Some(target(settings.coordinator.shutdown_grace)?);
                },
                Turn::Signal=>break,
                Turn::Progress(Progress::Stopped) if stopping.is_none()=>return Err("actual VPN sources stopped without a process shutdown request".into()),
                Turn::Progress(Progress::Stopped|Progress::WaitDeadline)=>break,
                Turn::Progress(Progress::Activity)=>{},
            }
            turns=turns.wrapping_add(1);if turns.is_multiple_of(64){tokio::task::yield_now().await;}
        }
        Ok::<(),Failure>(())
    }.await;
    // No source error short-circuits another original physical close.
    owners.retire();
    // Actual SIGKILL/pipe closure does not stand in for original wait/reap.
    // This future remains owned until that native wait returns its real result.
    if let Some(report) = owners.vpn.reap_helper().await {
        cleanup.helper(report);
    }
    resolver.close();
    if let Err(error) = cleanup.output() {
        cleanup.retain(Stage::Output, Box::new(error));
    }
    result
}
