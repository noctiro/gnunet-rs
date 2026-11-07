//! Process sockets/address intent survive healthy identity cuts; old IO authority retires.
mod identity;
use crate::{
    Cause,
    addresses::{Addresses, Anchor, NatObservation},
    bootstrap::Dial,
    control::Control,
    network::Scanner,
    settings::Settings,
};
use gnunet_client_host::EndpointSource;
use gnunet_nat_client_host as nat;
use gnunet_pils_host::client::{self as pils, Client};
use gnunet_program_host::{policy::Level, reporting::Reporter};
use gnunet_resolver_broker::Driver;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_transport_application_host::{self as application, Application, Bounds};
use gnunet_udp_communicator_core::send::Mode;
use gnunet_udp_communicator_host::{
    communicator::{Activity, Communicator, Configuration, Failure as CommFailure},
    driver::{Capacity, Time},
    replay::Namespace,
    socket::DatagramSocket,
};
use gnunet_wire::official::AbsoluteTime;
use std::{
    future::{Future, poll_fn},
    io,
    os::unix::fs::DirBuilderExt,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::time::Sleep;

pub(super) struct Inputs {
    pub settings: Settings,
    pub sockets: Vec<DatagramSocket>,
    pub control: Control,
    pub resolver: Driver<8, 64>,
    pub clock: Arc<dyn RuntimeClock>,
    pub reporter: Reporter,
    pub pils: EndpointSource,
    pub nat: EndpointSource,
    pub transport: EndpointSource,
    pub application: EndpointSource,
}
#[derive(Debug, Default)]
pub(super) struct Report {
    pub code: u8,
    registered: bool,
    identity_updates: u64,
    identity_recovered: u64,
    stopped: bool,
    drained: bool,
    physical_closed: bool,
    pils_retired: usize,
    nat_retired: bool,
    resolver_disconnected: bool,
    traffic: Traffic,
}
/// Fixed observations of completed native activity, without packet ownership.
#[derive(Debug, Default)]
struct Traffic {
    native_initial: Datagrams,
    native_box: Datagrams,
    // This subset is also included in native_box.
    native_rekey: Datagrams,
    incoming_initial: Datagrams,
    incoming_box: Datagrams,
    discarded: u64,
    first_discard: Option<gnunet_types::Error>,
    last_discard: Option<gnunet_types::Error>,
    overflow: bool,
}
#[derive(Debug, Default)]
struct Datagrams {
    packets: u64,
    bytes: u64,
}
fn add_total(total: &mut u64, amount: u64, overflow: &mut bool) {
    if let Some(sum) = total.checked_add(amount) {
        *total = sum;
    } else {
        *total = u64::MAX;
        *overflow = true;
    }
}
impl Datagrams {
    fn record(&mut self, bytes: usize, overflow: &mut bool) {
        add_total(&mut self.packets, 1, overflow);
        match u64::try_from(bytes) {
            Ok(bytes) => add_total(&mut self.bytes, bytes, overflow),
            Err(_) => {
                self.bytes = u64::MAX;
                *overflow = true;
            }
        }
    }
}
impl Traffic {
    fn observe(&mut self, activity: Activity) {
        match activity {
            Activity::NativeSent { mode, bytes, .. } => match mode {
                Mode::Initial => self.native_initial.record(bytes, &mut self.overflow),
                Mode::Box { rekey, .. } => {
                    self.native_box.record(bytes, &mut self.overflow);
                    if rekey {
                        self.native_rekey.record(bytes, &mut self.overflow);
                    }
                }
            },
            Activity::Incoming { boxed, bytes, .. } => {
                if boxed {
                    self.incoming_box.record(bytes, &mut self.overflow);
                } else {
                    self.incoming_initial.record(bytes, &mut self.overflow);
                }
            }
            Activity::Discarded(error) => {
                add_total(&mut self.discarded, 1, &mut self.overflow);
                if self.first_discard.is_none() {
                    self.first_discard = Some(error);
                }
                self.last_discard = Some(error);
            }
            _ => {}
        }
    }
    fn summarize(&self, reporter: &Reporter) {
        reporter.message(
            Level::INFO,
            "udp.traffic",
            format_args!(
                "UDP actual datagram traffic: native_initial_packets={} native_initial_bytes={} native_box_packets={} native_box_bytes={} native_rekey_packets={} native_rekey_bytes={} incoming_initial_packets={} incoming_initial_bytes={} incoming_box_packets={} incoming_box_bytes={} discarded={} first_discard={:?} last_discard={:?} overflow={}",
                self.native_initial.packets,
                self.native_initial.bytes,
                self.native_box.packets,
                self.native_box.bytes,
                self.native_rekey.packets,
                self.native_rekey.bytes,
                self.incoming_initial.packets,
                self.incoming_initial.bytes,
                self.incoming_box.packets,
                self.incoming_box.bytes,
                self.discarded,
                self.first_discard,
                self.last_discard,
                self.overflow,
            ),
        );
    }
}
#[derive(Debug)]
struct Failed {
    original: Option<Cause>,
    cleanup: Vec<Cause>,
    report: Report,
}
impl std::fmt::Display for Failed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UDP original={:?}; cleanup={:?}; local facts={:?}",
            self.original, self.cleanup, self.report
        )
    }
}
impl std::error::Error for Failed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original
            .as_deref()
            .or_else(|| self.cleanup.first().map(|error| error.as_ref()))
    }
}
struct Entropy;
impl gnunet_crypto::Entropy for Entropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), gnunet_types::Error> {
        getrandom::fill(out).map_err(|_| gnunet_types::Error::Entropy)
    }
}
#[expect(
    clippy::large_enum_variant,
    reason = "Original owned PILS/NAT retirement receipts stay inline; progress does not introduce a fallible heap allocation"
)]
enum Step<'n, 'p> {
    Stop(io::Result<()>),
    Pils(Result<pils::Progress<'p>, pils::Error>),
    Nat(Result<nat::Progress<'n>, nat::Error>),
    Comm(Result<Activity, gnunet_udp_communicator_host::communicator::Failure>),
    App(Result<application::Step, application::Error>),
    Resolver(Result<gnunet_resolver_broker::Progress, gnunet_resolver_broker::BrokerError>),
    Refresh(io::Result<()>),
    Wake,
    Failure(Cause),
    Connection(Result<gnunet_service_runtime::connection::Connection, Cause>),
}
fn address_event(event: crate::addresses::Event, reporter: &Reporter) {
    use crate::addresses::Event;
    let address = match event {
        Event::AddQueued(id)
        | Event::AddWritten(id)
        | Event::RemoveQueued(id)
        | Event::RemoveWritten(id)
        | Event::PublicationUnknown(id)
        | Event::RemovedUnsubmitted(id) => Some(id),
        _ => None,
    };
    reporter.debug(
        "udp.address",
        format_args!("{event:?}; address identifier={address:?}"),
    );
}
fn micros(origin: Instant) -> Result<u64, Cause> {
    Ok(u64::try_from(origin.elapsed().as_micros())?)
}
fn sample(clock: &dyn RuntimeClock) -> Result<Anchor, Cause> {
    let native = Instant::now();
    let now = clock.sample()?.now;
    Ok(Anchor { utc: now, native })
}
fn native_expired(alarm: &mut std::pin::Pin<Box<Sleep>>, cx: &mut Context<'_>) -> bool {
    alarm.as_mut().poll(cx).is_ready()
}
fn nat_registration<'id>(
    instance: &'id nat::Instance,
    source: EndpointSource,
    bound: &[std::net::SocketAddr],
    now: u64,
) -> Result<nat::Registration<'id>, Cause> {
    let profile = nat::native_profile()?;
    let mut scratch = [0; 56];
    let mut writer = nat::ipc::AddressWriter::new(&mut scratch, profile);
    for address in bound {
        writer.push(match address {
            std::net::SocketAddr::V4(a) => nat::ipc::Address::V4 {
                ip: a.ip().octets(),
                port: a.port(),
            },
            std::net::SocketAddr::V6(a) => nat::ipc::Address::V6 {
                ip: a.ip().octets(),
                port: a.port(),
                flow: a.flowinfo(),
                scope: a.scope_id(),
            },
        })?;
    }
    let request = nat::RegistrationRequest {
        flags: nat::ipc::ADDRESSES | nat::ipc::REVERSAL,
        protocol: 17,
        addresses: writer.addresses(),
        section: b"communicator-udp",
    };
    let until = now
        .checked_add(30_000_000)
        .filter(|n| *n != u64::MAX)
        .ok_or("NAT registration time overflow")?;
    Ok(nat::Registration::new(
        instance,
        source,
        request,
        nat::Profiles::same(profile),
        nat::Deadlines {
            send_until: until,
            first_input_until: None,
            until: u64::MAX,
        },
        nat::Limits::default(),
    )?)
}
#[derive(Debug)]
struct PilsLost {
    cause: pils::LossCause,
    feeds: usize,
    retained: usize,
}
impl std::fmt::Display for PilsLost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "original PILS source lost: {:?}; original feeds={}, retained crypto={}",
            self.cause, self.feeds, self.retained
        )
    }
}
impl std::error::Error for PilsLost {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            pils::LossCause::Io(error) => Some(error),
            pils::LossCause::Setup(error) => Some(error),
            pils::LossCause::Protocol(error) | pils::LossCause::Resource(error) => Some(error),
            pils::LossCause::Eof | pils::LossCause::Requested => None,
        }
    }
}
#[derive(Debug)]
struct NatLost {
    cause: nat::Cause,
    notification: bool,
    addresses: usize,
    pending_writes: usize,
}
impl std::fmt::Display for NatLost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "original NAT source ended: {:?}; held callback={}, addresses={}, pending writes={}",
            self.cause, self.notification, self.addresses, self.pending_writes
        )
    }
}
impl std::error::Error for NatLost {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            nat::Cause::Io(error) => Some(error),
            nat::Cause::Ports(error) => Some(error),
            nat::Cause::Error(error) => Some(error),
            _ => None,
        }
    }
}
fn nat_loss(end: nat::End<'_>) -> Cause {
    Box::new(NatLost {
        notification: end.notification.is_some(),
        addresses: end.addresses.len(),
        pending_writes: end.source.writes.len(),
        cause: end.source.cause,
    })
}
fn pils_event(event: pils::Progress<'_>, reporter: &Reporter) -> Result<(), Cause> {
    match event {
        pils::Progress::Lost { cause, report, .. } => Err(Box::new(PilsLost {
            cause,
            feeds: report.feeds().count(),
            retained: report.retained(),
        })),
        pils::Progress::Unavailable(error) => Err(error.into()),
        pils::Progress::Closed => Err("original PILS source closed".into()),
        pils::Progress::ConnectRetry { error, .. } => {
            reporter.warning("udp.pils.connect", format_args!("{error}"));
            Ok(())
        }
        _ => Ok(()),
    }
}
pub(super) async fn run(inputs: Inputs) -> Result<Report, Cause> {
    let Inputs {
        settings,
        sockets,
        mut control,
        mut resolver,
        clock,
        reporter,
        pils: pils_source,
        nat: nat_source,
        transport,
        application: app_source,
    } = inputs;
    let mut report = Report::default();
    let mut cleanup = Vec::new();
    let mut pils_instance = gnunet_pils::client::Instance::new();
    let nat_instance = nat::Instance::new();
    let burst_instance = gnunet_udp_communicator_host::burst::Instance::new();
    let mut pils = Client::<32>::new(
        &mut pils_instance,
        pils_source,
        settings.identity_profile,
        Default::default(),
        gnunet_pils::HelloLimits {
            maximum_input_bytes: 65535,
            maximum_address_bytes: 65535,
            maximum_addresses: 1024,
        },
    )?;
    let mut identities: Option<identity::State<'_>> = None;
    let mut comm = None;
    let mut registration = None;
    let mut addresses = Addresses::new(128, 8192, Duration::from_secs(30))?;
    let mut app = None;

    let original=async {
        let origin=Instant::now();
        let hard=tokio::time::Instant::now().checked_add(Duration::from_micros(settings.startup_micros)).ok_or("UDP startup time overflow")?;
        let mut startup=Box::pin(tokio::time::sleep_until(hard));
        while pils.identity().is_none() {
            let step={
                let mut receiving=std::pin::pin!(pils.drive(Some(hard)));
                let mut resolving=std::pin::pin!(resolver.drive_waiting(Some(hard),|event|reporter.debug("udp.resolver",format_args!("{event:?}"))));
                poll_fn(|cx|{
                    if let Poll::Ready(result)=control.poll(cx){return Poll::Ready(Step::Stop(result));}
                    if native_expired(&mut startup,cx){return Poll::Ready(Step::Pils(Err(gnunet_types::Error::Deadline.into())));}
                    if let Poll::Ready(result)=receiving.as_mut().poll(cx){return Poll::Ready(Step::Pils(result));}
                    resolving.as_mut().poll(cx).map(Step::Resolver)
                }).await
            };
            match step {Step::Stop(result)=>{result?;report.stopped=true;return Ok::<(),Cause>(());},Step::Pils(event)=>pils_event(event?,&reporter)?,Step::Resolver(result)=>{result?;},_=>return Err("unexpected UDP startup step".into())}
        }
        if tokio::time::Instant::now()>=hard{return Err("UDP startup expired before existing-key access".into());}
        // This existing-key read is after configured USERNAME and verified PILS.
        // It never creates/replaces the official identity or a fallback seed.
        let master=gnunet_pils_host::identity::load_existing(&settings.ikm)?;
        if pils.enable_local_key(master)?!=gnunet_pils::client::LocalKeyStatus::Matched{return Err("existing UDP key does not match current verified PILS".into());}
        let original_epoch=pils.identity().ok_or(gnunet_types::Error::NotReady)?.epoch();
        if tokio::time::Instant::now()>=hard{return Err("UDP startup expired before state access".into());}
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(&settings.directory)?;
        {use std::os::unix::fs::MetadataExt;let metadata=std::fs::symlink_metadata(&settings.directory)?;
        if !metadata.is_dir() || metadata.uid()!=nix::unistd::geteuid().as_raw() || metadata.mode()&0o077!=0 {return Err("UDP replay directory must be private and owned by the configured process identity".into());}}
        let namespace=Namespace::open(&settings.directory)?;
        let mut dialing=Dial::new(transport);
        let connection=loop {
            let step={
                let mut receiving=std::pin::pin!(pils.drive(Some(hard)));
                let mut resolving=std::pin::pin!(resolver.drive_waiting(Some(hard),|event|reporter.debug("udp.resolver",format_args!("{event:?}"))));
                poll_fn(|cx|{
                    if let Poll::Ready(result)=control.poll(cx){return Poll::Ready(Step::Stop(result));}
                    if native_expired(&mut startup,cx){return Poll::Ready(Step::Failure("UDP startup expired".into()));}
                    if let Poll::Ready(result)=receiving.as_mut().poll(cx){return Poll::Ready(Step::Pils(result));}
                    if let Poll::Ready(result)=resolving.as_mut().poll(cx){return Poll::Ready(Step::Resolver(result));}
                    if control.stopped(){return Poll::Ready(Step::Stop(Ok(())));}
                    dialing.poll(cx,&reporter).map(Step::Connection)
                }).await
            };
            match step {
                Step::Connection(result)=>break result?,
                Step::Pils(event)=>{
                    let event=event?;
                    if matches!(&event,pils::Progress::Inbound(gnunet_pils::client::Inbound::Identity{..})) {
                        if tokio::time::Instant::now()>=hard{return Err("UDP startup expired before PILS refresh".into());}
                        let selected=pils.identity().ok_or(gnunet_types::Error::NotReady)?;
                        if selected.epoch()!=original_epoch{return Err(gnunet_types::Error::StaleGeneration.into());}
                        if selected.expiration()<=sample(clock.as_ref())?.utc{return Err(gnunet_types::Error::Timeout.into());}
                    }
                    pils_event(event,&reporter)?;
                },
                Step::Resolver(result)=>{result?;},
                Step::Stop(result)=>{result?;report.stopped=true;return Ok(());},
                Step::Failure(error)=>return Err(error),
                _=>return Err("unexpected UDP dial step".into()),
            }
        };
        if tokio::time::Instant::now()>=hard{return Err("UDP startup expired before communicator admission".into());}
        identities=Some(identity::State::new(namespace,&pils,settings.peers,clock.clone(),sample(clock.as_ref())?.utc)?);
        let local=identities.as_ref().ok_or("missing UDP identity owner")?.binding()?.peer();
        if tokio::time::Instant::now()>=hard{return Err("UDP startup expired during durable identity preparation".into());}
        let owner=Communicator::new(connection,sockets,Configuration{local,peers:settings.peers,endpoints:settings.endpoints,capacity:Capacity::default(),transmit:settings.transmit},micros(origin)?)?;
        comm=Some(owner);
        let owner=comm.as_mut().ok_or("missing original UDP communicator")?;
        owner.enable_burst(&burst_instance,clock.clone(),Default::default())?;
        let bound:Vec<_>=owner.local_addresses().collect();
        let mut scanner=Scanner::new()?;
        addresses.replace_interfaces(&scanner.advertised(&bound)?,&mut |address|scanner.classify(address))?;
        if !settings.disable_broadcast {
            owner.enable_discovery(Default::default())?;
            owner.update_interfaces(&scanner.discovery(&bound)?)?;
        }
        registration=Some(nat_registration(&nat_instance,nat_source,&bound,clock.sample()?.now.as_micros())?);
        app=Some(Application::new(app_source,65535,Duration::from_secs(60),Duration::from_secs(86400))?);
        let mut wake=Box::pin(tokio::time::sleep(Duration::from_secs(86400)));
        let mut cursor=0usize;let mut entropy=Entropy;
        let mut last_wall=AbsoluteTime::UNIX_EPOCH;
        loop {
            tokio::task::consume_budget().await;
            if let Poll::Ready(result)=poll_fn(|cx|Poll::Ready(control.poll(cx))).await {result?;report.stopped=true;break;}
            let owner=comm.as_mut().ok_or("missing original UDP communicator")?;
            let identity=identities.as_mut().ok_or("missing original UDP identity owner")?;
            poll_fn(|cx|Poll::Ready(identity.guard(cx))).await?;
            let key=identity.binding()?;
            let nat=registration.as_mut().ok_or("missing original NAT registration")?;
            let application=app.as_mut().ok_or("missing original TRANSPORT application")?;
            // Native original-operation guards run before any canonical sample.
            let native_nat=poll_fn(|cx|{
                addresses.poll_native_guard(cx)?;
                if let Some(error)=owner.poll_native_guard(cx){return Poll::Ready(Err(Box::new(error) as Cause));}
                if let Some(retired)=application.poll_native_guard(cx){
                    reporter.warning("udp.application.retired",format_args!("epoch={} written={} remaining={}",retired.epoch,retired.written,retired.remaining));
                    return Poll::Ready(Err("original TRANSPORT application native limit expired".into()));
                }
                Poll::Ready(match nat.poll_native_guard(cx,None){Poll::Pending=>Ok(None),Poll::Ready(result)=>result.map(Some).map_err(|error|Box::new(error) as Cause)})
            }).await?;
            if let Some(event)=native_nat {
                let observed=addresses.observe_nat(nat,&event,&mut |address|scanner.classify(address))?;
                reporter.warning("udp.nat.native-limit",format_args!("{observed:?}"));
                if let nat::Progress::Ended(end)=event {report.nat_retired=true;return Err(nat_loss(end));}
                continue;
            }
            if let Some(burst)=owner.take_burst_report(){reporter.debug("udp.burst",format_args!("{burst:?}"));}
            let anchor=sample(clock.as_ref())?;
            if anchor.utc<last_wall{return Err(gnunet_types::Error::TimeUncertain.into());}
            last_wall=anchor.utc;
            addresses.check_time(anchor.utc)?;
            if let Some(event)=addresses.advance(owner,&mut pils,key,Some(anchor))?{address_event(event,&reporter);continue;}
            if owner.transport_ready() && application.idle() && let Some(hint)=owner.take_discovered(){
                let address=format!("udp-{}",hint.source);
                application.validate(hint.peer,address.as_bytes(),hint.network,Bounds::new(clock.as_ref(),Duration::from_secs(30))?)?;
            }
            let target=owner.next_wakeup().and_then(|t|origin.checked_add(Duration::from_micros(t))).unwrap_or_else(||Instant::now()+Duration::from_secs(86400));
            wake.as_mut().reset(target.into());
            let step={
                let mut resolving=std::pin::pin!(resolver.drive_waiting(None,|event|reporter.debug("udp.resolver",format_args!("{event:?}"))));
                poll_fn(|cx|{
                    if let Poll::Ready(result)=control.poll(cx){return Poll::Ready(Step::Stop(result));}
                    if let Err(error)=identity.guard(cx){return Poll::Ready(Step::Failure(error));}
                    // This cache belongs only to this poll invocation, never
                    // to the pending future across a timer/socket wake.
                    let mut current_time=None;
                    for offset in 0..7 {
                        if control.stopped(){return Poll::Ready(Step::Stop(Ok(())));}
                        if let Err(error)=addresses.poll_native_guard(cx){return Poll::Ready(Step::Failure(Box::new(error)));}
                        if let Some(error)=owner.poll_native_guard(cx){return Poll::Ready(Step::Comm(Err(error)));}
                        if let Some(retired)=application.poll_native_guard(cx){
                            reporter.warning("udp.application.expired",format_args!("epoch={} submitted={} written={} remaining={}",retired.epoch,retired.submitted,retired.written,retired.remaining));
                            return Poll::Ready(Step::App(Err(gnunet_types::Error::Deadline.into())));
                        }
                        if let Poll::Ready(result)=nat.poll_native_guard(cx,None){return Poll::Ready(Step::Nat(result));}
                        let time=match current_time {
                            Some(time)=>time,
                            None=>{
                                // Original native guards precede this fallible
                                // canonical sample and all old native IO.
                                let current=match sample(clock.as_ref()) {
                                    Ok(current)=>current,
                                    Err(error)=>return Poll::Ready(Step::Failure(error)),
                                };
                                if current.utc<last_wall {
                                    return Poll::Ready(Step::Failure(gnunet_types::Error::TimeUncertain.into()));
                                }
                                last_wall=current.utc;
                                if let Err(error)=addresses.check_time(current.utc) {
                                    return Poll::Ready(Step::Failure(Box::new(error)));
                                }
                                let now=match micros(origin) {
                                    Ok(now)=>now,
                                    Err(error)=>return Poll::Ready(Step::Failure(error)),
                                };
                                let time=Time{now,utc:current.utc};
                                current_time=Some(time);
                                // A synchronous Clock provider may have taken
                                // time. Recheck original native targets before
                                // old IO, without another sample or new bounds.
                                if let Poll::Ready(result)=control.poll(cx){return Poll::Ready(Step::Stop(result));}
                                if let Err(error)=addresses.poll_native_guard(cx){return Poll::Ready(Step::Failure(Box::new(error)));}
                                if let Some(error)=owner.poll_native_guard(cx){return Poll::Ready(Step::Comm(Err(error)));}
                                if let Some(retired)=application.poll_native_guard(cx){
                                    reporter.warning("udp.application.expired",format_args!("epoch={} submitted={} written={} remaining={}",retired.epoch,retired.submitted,retired.written,retired.remaining));
                                    return Poll::Ready(Step::App(Err(gnunet_types::Error::Deadline.into())));
                                }
                                if let Poll::Ready(result)=nat.poll_native_guard(cx,None){return Poll::Ready(Step::Nat(result));}
                                time
                            },
                        };
                        if let Err(error)=identity.guard(cx){return Poll::Ready(Step::Failure(error));}
                        let class=(cursor+offset)%7;
                        let result=match class {
                            0=>{
                                let (key,journal)=match identity.ports(){Ok(ports)=>ports,Err(error)=>return Poll::Ready(Step::Failure(error.into()))};
                                owner.poll_bound(cx,key,&pils,journal,time,&mut entropy,&mut |address|scanner.classify(address)).map(Step::Comm)
                            },
                            1=>nat.poll(cx,None).map(Step::Nat),
                            2=>{let mut receiving=std::pin::pin!(pils.drive(None));receiving.as_mut().poll(cx).map(Step::Pils)},
                            3=>resolving.as_mut().poll(cx).map(Step::Resolver),
                            4=>application.poll(cx).map(Step::App),
                            5=>scanner.poll_refresh(cx).map(Step::Refresh),
                            _ if !owner.transport_attached()=>dialing.poll(cx,&reporter).map(Step::Connection),
                            _=>Poll::Pending,
                        };
                        if result.is_ready(){cursor=(class+1)%7;return result;}
                    }
                    if wake.as_mut().poll(cx).is_ready(){Poll::Ready(Step::Wake)}else{Poll::Pending}
                }).await
            };
            match step {
                Step::Stop(result)=>{result?;report.stopped=true;break;},
                Step::Comm(result)=>match result {
                    Ok(Activity::Registered)=>{report.registered=true;reporter.message(Level::INFO,"udp.transport.registered",format_args!("generation={} whole local registration written",owner.transport_generation()));},
                    Ok(Activity::Restored)=>{
                        poll_fn(|cx|Poll::Ready(identity.guard(cx))).await?;
                        if identity.restored(){report.identity_recovered=report.identity_recovered.saturating_add(1);}
                        reporter.message(Level::INFO,"udp.transport.restored",format_args!("generation={} current queues wholly reannounced",owner.transport_generation()));
                    },
                    Ok(Activity::Closed)=>return Err("original UDP communicator physically closed".into()),
                    Ok(activity @ (Activity::NativeSent{..}|Activity::Incoming{..}|Activity::Discarded(_)))=>report.traffic.observe(activity),
                    Ok(_)=>{},
                    Err(error @ (CommFailure::TransportEof|CommFailure::Transport(_))) if !owner.transport_attached() && !owner.is_closed()=>{
                        reporter.warning("udp.transport.disconnected",format_args!("{error}"));
                        let loss=owner.transport_loss().ok_or("UDP source retired without its original loss report")?;
                        reporter.warning("udp.transport.lost",format_args!("generation={} registered={} input bytes={} held input={} held ack={} retired operations={}",loss.generation,loss.registered,loss.input_bytes,loss.held_input,loss.held_ack,loss.retired.len()));
                        for retired in loss.retired {reporter.debug("udp.transport.retired",format_args!("{retired:?}"));}
                        addresses.transport_lost(owner)?;
                        dialing.disconnected()?;
                    },
                    Err(error)=>return Err(error.into()),
                },
                Step::Pils(event)=>{
                    let event=event?;
                    addresses.observe_pils(&event)?;
                    if matches!(&event,pils::Progress::Inbound(gnunet_pils::client::Inbound::Identity{..})) {
                        // The original observer owns both same-key refreshes
                        // and healthy changed-peer cuts. Address intent and
                        // original FEED effects keep their separate lifetime.
                        let current=sample(clock.as_ref())?;
                        if current.utc<last_wall{return Err(gnunet_types::Error::TimeUncertain.into());}
                        last_wall=current.utc;
                        let mut cut=None;
                        let changed=identity.select(&pils,owner,current.utc,&mut |retired|{
                            reporter.message(Level::INFO,"udp.identity.retired",format_args!("{retired:?}"));
                            cut=Some(retired);
                            if reporter.failed(){Err("UDP identity retirement diagnostic failed".into())}else{Ok(())}
                        })?;
                        poll_fn(|cx|Poll::Ready(identity.guard(cx))).await?;
                        if changed {
                            let retired=cut.ok_or("missing actual UDP identity retirement")?;
                            let loss=owner.transport_loss().ok_or("UDP identity cut has no original source retirement")?;
                            reporter.message(Level::INFO,"udp.identity.source-retired",format_args!("generation={} input_bytes={} retired_operations={}",loss.generation,loss.input_bytes,loss.retired.len()));
                            for operation in loss.retired {reporter.debug("udp.identity.operation-retired",format_args!("{operation:?}"));}
                            addresses.transport_lost(owner)?;
                            if retired.transport_was_attached{dialing.disconnected()?;}
                            report.identity_updates=report.identity_updates.saturating_add(1);
                            reporter.message(Level::INFO,"udp.identity.selected",format_args!("peer={:?}; original sockets and address intent retained",identity.binding()?.peer()));
                        }
                    }
                    pils_event(event,&reporter)?;
                },
                Step::Nat(event)=>{let event=event?;
                    match addresses.observe_nat(nat,&event,&mut |address|scanner.classify(address))? {
                        NatObservation::Accepted=>{if matches!(event,nat::Progress::Notification{..}){nat.release_notification()?;}},
                        NatObservation::Backpressure=>{return Err("UDP NAT address capacity exhausted with original callback retained".into());},
                        NatObservation::None|NatObservation::Retired=>{},
                        NatObservation::Reverse(view)=>{reporter.warning("udp.nat.reverse",format_args!("official UDP reversal callback has no implemented reversal action: {}",view.remote));addresses.release_reverse(nat,view)?;},
                    }
                    if let nat::Progress::Ended(end)=event {report.nat_retired=true;return Err(nat_loss(end));}
                },
                Step::App(event)=>match event? {
                    application::Step::Lost{report:retired,cause}=>{reporter.warning("udp.application.lost",format_args!("epoch={} written={} remaining={} cause={cause:?}",retired.epoch,retired.written,retired.remaining));application.restart(Duration::from_secs(60))?;},
                    application::Step::Retry(error)=>reporter.warning("udp.application.connect",format_args!("{error}")),
                    _=>{},
                },
                Step::Resolver(result)=>{result?;},
                Step::Refresh(Ok(()))=>{addresses.replace_interfaces(&scanner.advertised(&bound)?,&mut |address|scanner.classify(address))?;if !settings.disable_broadcast{owner.update_interfaces(&scanner.discovery(&bound)?)?;}},
                Step::Refresh(Err(error))=>reporter.warning("udp.interfaces.failed",format_args!("retaining previous actual snapshot: {error}")),
                Step::Wake=>{},
                Step::Failure(error)=>return Err(error),
                Step::Connection(connection)=>{
                    owner.reconnect(connection?)?;
                    reporter.message(Level::INFO,"udp.transport.connected",format_args!("generation={} replacement local source attached",owner.transport_generation()));
                },
            }
        }
        Ok(())
    }.await.err();
    // One fixed native retirement allowance spans withdrawals, the original
    // empty FEED attempt and queue-down drain. It never renews on progress.
    addresses.begin_close();
    if let Some(nat) = &mut registration
        && let Some(end) = nat.close()
    {
        reporter.debug("udp.nat.retired", format_args!("{end:?}"));
        report.nat_retired = true;
    }
    if let Some(app) = &mut app {
        let retired = app.close();
        reporter.debug(
            "udp.application.retired",
            format_args!(
                "epoch={} written={} remaining={}",
                retired.epoch, retired.written, retired.remaining
            ),
        );
    }
    let mut retirement = Box::pin(tokio::time::sleep(Duration::from_secs(5)));
    if let Some(owner) = &mut comm {
        let mut forced = owner.is_quiescent();
        // Clock-independent removals are still admitted on this original MQ.
        // A clock failure prevents new FEED, but does not prevent physical close.
        loop {
            if poll_fn(|cx| Poll::Ready(native_expired(&mut retirement, cx))).await {
                break;
            }
            if let Err(error) = poll_fn(|cx| Poll::Ready(addresses.poll_native_guard(cx))).await {
                cleanup.push(Box::new(error) as Cause);
                let lost = pils.close();
                addresses.pils_retired(&lost);
                report.pils_retired += lost.iter().flatten().count();
                owner.close();
                forced = true;
                break;
            }
            let anchor = if reporter.failed() {
                None
            } else {
                sample(clock.as_ref()).ok()
            };
            if let Some(key) = identities.as_ref().and_then(|v| v.binding().ok()) {
                match addresses.advance(owner, &mut pils, key, anchor) {
                    Ok(Some(event)) => {
                        address_event(event, &reporter);
                        continue;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        cleanup.push(Box::new(error) as Cause);
                        let lost = pils.close();
                        addresses.pils_retired(&lost);
                        report.pils_retired += lost.iter().flatten().count();
                        owner.close();
                        forced = true;
                        break;
                    }
                }
            }
            if addresses.idle() {
                break;
            }
            let step = poll_fn(|cx| {
                if native_expired(&mut retirement, cx) {
                    return Poll::Ready(None);
                }
                if let Err(error) = addresses.poll_native_guard(cx) {
                    return Poll::Ready(Some(Step::Failure(Box::new(error))));
                }
                if let Poll::Ready(result) = owner.poll_publications(cx) {
                    return Poll::Ready(Some(Step::Comm(result)));
                }
                let mut receiving = std::pin::pin!(pils.drive(None));
                receiving
                    .as_mut()
                    .poll(cx)
                    .map(|result| Some(Step::Pils(result)))
            })
            .await;
            match step {
                Some(Step::Failure(error)) => {
                    cleanup.push(error);
                    let lost = pils.close();
                    addresses.pils_retired(&lost);
                    report.pils_retired += lost.iter().flatten().count();
                    owner.close();
                    forced = true;
                    break;
                }
                Some(Step::Comm(Ok(_))) => {}
                Some(Step::Comm(Err(error))) => {
                    cleanup.push(Box::new(error) as Cause);
                    break;
                }
                Some(Step::Pils(Ok(event))) => {
                    if let Err(error) = addresses.observe_pils(&event) {
                        cleanup.push(Box::new(error) as Cause);
                        break;
                    }
                    if let Err(error) = pils_event(event, &reporter) {
                        cleanup.push(error);
                        break;
                    }
                }
                Some(Step::Pils(Err(error))) => {
                    cleanup.push(Box::new(error) as Cause);
                    break;
                }
                _ => break,
            }
        }
        if let Err(error) = owner.finish() {
            cleanup.push(Box::new(error) as Cause);
        }
        while !owner.is_quiescent() {
            match poll_fn(|cx| {
                if native_expired(&mut retirement, cx) {
                    Poll::Ready(None)
                } else {
                    owner.poll_close(cx).map(Some)
                }
            })
            .await
            {
                Some(Ok(_)) => {}
                Some(Err(error)) => {
                    cleanup.push(Box::new(error) as Cause);
                    break;
                }
                None => break,
            }
        }
        report.drained = !forced && owner.is_quiescent();
        if !report.drained {
            cleanup.push(
                "UDP original queue cleanup did not drain within the fixed native allowance".into(),
            );
        }
        owner.close();
        report.physical_closed = owner.is_quiescent();
        if let Err(error) = addresses.retire_comm(owner) {
            cleanup.push(Box::new(error) as Cause);
        }
    }
    if let Some(identity) = &mut identities {
        identity.close();
    }
    let lost = pils.close();
    report.pils_retired += lost.iter().flatten().count();
    addresses.pils_retired(&lost);
    let address_report = addresses.report();
    reporter.debug("udp.address.retired",format_args!("claims={} rows={} pending publication={} pending feed={} desired feed unsubmitted={}; {address_report:?}",address_report.claims,address_report.rows,address_report.pending_publication,address_report.pending_feed,address_report.desired_feed_unsubmitted));
    if let Some(error) = resolver.take_io_error() {
        cleanup.push(Box::new(error) as Cause);
    }
    if let Some(error) = resolver.take_connect_error() {
        cleanup.push(Box::new(error) as Cause);
    }
    match resolver.disconnect() {
        Ok(()) => report.resolver_disconnected = true,
        Err(error) => cleanup.push(Box::new(error) as Cause),
    }
    drop(identities);
    // The same fixed snapshot is retained in Report on either outcome. No
    // native traffic exists before the earlier setup constructors succeed.
    report.traffic.summarize(&reporter);
    reporter.message(
        Level::INFO,
        "udp.identity.summary",
        format_args!(
            "UDP identity updates={} recovered={}; drained={} physical_closed={}",
            report.identity_updates,
            report.identity_recovered,
            report.drained,
            report.physical_closed
        ),
    );
    if original.is_some() || !cleanup.is_empty() {
        Err(Box::new(Failed {
            original,
            cleanup,
            report,
        }))
    } else {
        Ok(report)
    }
}
