use crate::{Exit, Ready};
use std::{cell::Cell, error::Error, fmt, future::Future, io, net::SocketAddr, pin::Pin};
use tokio::{
    sync::{mpsc, watch},
    time::Instant,
};

type Cause = Box<dyn Error>;

/// Services owned by the native node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Service {
    /// Native resolver IPC and DNS requests.
    Resolver,
    /// Persistent peer root and verified signing service.
    Pils,
    /// TRANSPORT and its public PEERSTORE listener.
    Transport,
    /// Native address registration and NAT discovery for the communicators.
    Nat,
    /// Authenticated peer sessions and CORE client IPC.
    Core,
    /// Network size estimation over the authenticated CORE topology.
    Nse,
    /// DHT storage, routing and local client IPC.
    Dht,
    /// CADET channel routing and local client IPC.
    Cadet,
    /// REGEX IPC with the node's original DHT and PILS connections.
    Regex,
    /// Application-owned VPN packet and route provider.
    Vpn,
    /// Peer-facing TCP communicator.
    Tcp,
    /// Peer-facing UDP communicator.
    Udp,
    /// Peer-facing raw QUIC communicator.
    Quic,
    /// Peer-facing HTTP/3 communicator.
    Http3,
    /// Private UNIX datagram testing communicator.
    Unix,
}

impl Service {
    fn phases(self) -> (Phase, Phase) {
        match self {
            Self::Resolver | Self::Pils => (Phase::Foundation, Phase::StopFoundation),
            Self::Transport | Self::Nat => (Phase::Transport, Phase::StopTransport),
            Self::Core | Self::Tcp | Self::Udp | Self::Quic | Self::Http3 | Self::Unix => {
                (Phase::Consumers, Phase::StopConsumers)
            }
            Self::Nse => (Phase::Estimation, Phase::StopEstimation),
            Self::Dht => (Phase::Discovery, Phase::StopDiscovery),
            Self::Cadet | Self::Regex => (Phase::Applications, Phase::StopApplications),
            Self::Vpn => (Phase::Vpn, Phase::StopVpn),
        }
    }

    fn start(self) -> Phase {
        self.phases().0
    }

    fn stop(self) -> Phase {
        self.phases().1
    }
}

const SERVICES: [Service; 15] = [
    Service::Resolver,
    Service::Pils,
    Service::Transport,
    Service::Nat,
    Service::Core,
    Service::Nse,
    Service::Dht,
    Service::Cadet,
    Service::Regex,
    Service::Vpn,
    Service::Tcp,
    Service::Udp,
    Service::Quic,
    Service::Http3,
    Service::Unix,
];
pub(crate) const EVENT_CAPACITY: usize = SERVICES.len() * 2;

/// A service's original startup, drive or retirement error.
#[derive(Debug)]
pub struct ServiceFailure {
    /// The owner that reported the failure.
    pub service: Service,
    /// Original error including its own cleanup details where available.
    pub cause: Cause,
}

/// The first observed reason the node started to retire.
#[derive(Debug)]
pub enum FailureCause {
    /// A service failed or exited before being asked to stop.
    Service(ServiceFailure),
    /// The host's stop future failed.
    Stop(io::Error),
    /// The host's readiness callback failed.
    Ready(io::Error),
    /// The initial readiness deadline elapsed.
    Deadline,
    /// The initial verified peer identity disagreed across owners.
    Identity(Service),
    /// The embedding host lacks its required runtime context.
    Runtime(io::Error),
}

/// The original node failure and any independent later service failures.
#[derive(Debug)]
pub struct Failure {
    /// First cause, preserved through retirement.
    pub cause: FailureCause,
    /// Errors returned later by other original owners.
    pub retirement: Vec<ServiceFailure>,
}

impl From<FailureCause> for Failure {
    fn from(cause: FailureCause) -> Self {
        Self {
            cause,
            retirement: Vec::new(),
        }
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.cause {
            FailureCause::Service(failure) => {
                write!(f, "{:?}: {}", failure.service, failure.cause)?
            }
            FailureCause::Stop(error) => write!(f, "node stop: {error}")?,
            FailureCause::Ready(error) => write!(f, "node readiness: {error}")?,
            FailureCause::Deadline => f.write_str("node startup deadline")?,
            FailureCause::Identity(service) => {
                write!(f, "inconsistent peer identity at {service:?} readiness")?
            }
            FailureCause::Runtime(error) => write!(f, "node runtime: {error}")?,
        }
        for failure in &self.retirement {
            write!(
                f,
                ". {:?} retirement failed with {}",
                failure.service, failure.cause
            )?;
        }
        Ok(())
    }
}

impl Error for Failure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match &self.cause {
            FailureCause::Service(failure) => Some(failure.cause.as_ref()),
            FailureCause::Stop(error)
            | FailureCause::Ready(error)
            | FailureCause::Runtime(error) => Some(error),
            FailureCause::Deadline | FailureCause::Identity(_) => None,
        }
    }
}

#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Phase {
    Foundation,
    Transport,
    Consumers,
    Estimation,
    Discovery,
    Applications,
    Vpn,
    Running,
    StopVpn,
    StopApplications,
    StopDiscovery,
    StopEstimation,
    StopConsumers,
    StopTransport,
    StopFoundation,
}

pub(crate) enum ReadyNotice {
    Resolver,
    Pils([u8; 32]),
    Transport([u8; 32]),
    Nat,
    Core([u8; 32]),
    Nse([u8; 32]),
    Dht([u8; 32]),
    Cadet([u8; 32]),
    Regex([u8; 32]),
    Vpn,
    Tcp {
        peer: [u8; 32],
        endpoints: Vec<SocketAddr>,
    },
    Udp {
        peer: [u8; 32],
        endpoints: Vec<SocketAddr>,
    },
    Quic {
        peer: [u8; 32],
        address: SocketAddr,
    },
    Http3 {
        peer: [u8; 32],
        address: SocketAddr,
    },
    #[cfg(unix)]
    Unix {
        peer: [u8; 32],
        mtu: std::num::NonZeroU16,
    },
}

pub(crate) enum ChildExit {
    Skipped,
    Finished {
        result: Result<(), Cause>,
        stopping: bool,
    },
}

pub(crate) enum Notice {
    Ready(ReadyNotice),
    Exited { service: Service, result: ChildExit },
}

pub(crate) struct Readiness {
    notices: mpsc::Sender<Notice>,
    published: bool,
}

impl Readiness {
    pub(crate) fn publish(&mut self, ready: ReadyNotice) -> io::Result<()> {
        if !self.published {
            self.notices
                .try_send(Notice::Ready(ready))
                .map_err(|_| io::ErrorKind::BrokenPipe)?;
            self.published = true;
        }
        Ok(())
    }
}

pub(crate) struct Stop<'owner> {
    phase: watch::Receiver<Phase>,
    threshold: Phase,
    observed: &'owner Cell<bool>,
}

impl Stop<'_> {
    pub(crate) async fn wait(mut self) -> io::Result<()> {
        let _reached = self.phase.wait_for(|phase| *phase >= self.threshold).await;
        self.observed.set(true);
        Ok(())
    }
}

pub(crate) fn drive<'a>(
    service: Service,
    mut phase: watch::Receiver<Phase>,
    notices: mpsc::Sender<Notice>,
    run: impl AsyncFnOnce(Stop<'_>, Readiness) -> Result<(), Cause> + 'a,
) -> Pin<Box<dyn Future<Output = ()> + 'a>> {
    Box::pin(async move {
        let start = phase
            .wait_for(|phase| *phase >= service.start())
            .await
            .is_ok_and(|phase| *phase < Phase::StopVpn);
        let result = if start {
            let observed = Cell::new(false);
            let result = run(
                Stop {
                    phase,
                    threshold: service.stop(),
                    observed: &observed,
                },
                Readiness {
                    notices: notices.clone(),
                    published: false,
                },
            )
            .await;
            ChildExit::Finished {
                result,
                stopping: observed.get(),
            }
        } else {
            ChildExit::Skipped
        };
        let _delivered = notices.send(Notice::Exited { service, result }).await;
    })
}

#[derive(Default)]
enum OptionalReady<T> {
    #[default]
    Disabled,
    Waiting,
    Ready(T),
}

impl<T: Copy> OptionalReady<T> {
    fn for_profile(enabled: bool) -> Self {
        if enabled {
            Self::Waiting
        } else {
            Self::Disabled
        }
    }

    fn ready(&self) -> Option<Option<T>> {
        match self {
            Self::Disabled => Some(None),
            Self::Waiting => None,
            Self::Ready(value) => Some(Some(*value)),
        }
    }
}

pub(crate) struct OptionalServices {
    pub(crate) regex: bool,
    pub(crate) vpn: bool,
    pub(crate) udp: bool,
    pub(crate) quic: bool,
    pub(crate) http3: bool,
    pub(crate) unix: bool,
}

#[derive(Default)]
struct Initial {
    resolver: bool,
    peer: Option<[u8; 32]>,
    tcp: Option<Vec<SocketAddr>>,
    udp: Option<Vec<SocketAddr>>,
    quic: OptionalReady<SocketAddr>,
    http3: OptionalReady<SocketAddr>,
    unix: OptionalReady<std::num::NonZeroU16>,
    regex: OptionalReady<()>,
    vpn: OptionalReady<()>,
    transport: bool,
    nat: bool,
    core: bool,
    nse: bool,
    dht: bool,
    cadet: bool,
    ready: Option<Ready>,
}

impl Initial {
    fn apply(&mut self, phase: Phase, notice: ReadyNotice) -> Result<Phase, FailureCause> {
        match notice {
            ReadyNotice::Resolver => self.resolver = true,
            ReadyNotice::Pils(peer) => self.peer = Some(peer),
            ReadyNotice::Transport(peer) => {
                self.check_peer(Service::Transport, peer)?;
                self.transport = true;
            }
            ReadyNotice::Nat => self.nat = true,
            ReadyNotice::Core(peer) => {
                self.check_peer(Service::Core, peer)?;
                self.core = true;
            }
            ReadyNotice::Dht(peer) => {
                self.check_peer(Service::Dht, peer)?;
                self.dht = true;
            }
            ReadyNotice::Nse(peer) => {
                self.check_peer(Service::Nse, peer)?;
                self.nse = true;
            }
            ReadyNotice::Cadet(peer) => {
                self.check_peer(Service::Cadet, peer)?;
                self.cadet = true;
            }
            ReadyNotice::Regex(peer) => {
                self.check_peer(Service::Regex, peer)?;
                self.regex = OptionalReady::Ready(());
            }
            ReadyNotice::Vpn => self.vpn = OptionalReady::Ready(()),
            ReadyNotice::Tcp { peer, endpoints } => {
                self.check_peer(Service::Tcp, peer)?;
                self.tcp = Some(endpoints);
            }
            ReadyNotice::Udp { peer, endpoints } => {
                self.check_peer(Service::Udp, peer)?;
                self.udp = Some(endpoints);
            }
            ReadyNotice::Quic { peer, address } => {
                self.check_peer(Service::Quic, peer)?;
                self.quic = OptionalReady::Ready(address);
            }
            ReadyNotice::Http3 { peer, address } => {
                self.check_peer(Service::Http3, peer)?;
                self.http3 = OptionalReady::Ready(address);
            }
            #[cfg(unix)]
            ReadyNotice::Unix { peer, mtu } => {
                self.check_peer(Service::Unix, peer)?;
                self.unix = OptionalReady::Ready(mtu);
            }
        }
        if phase == Phase::Foundation && self.resolver && self.peer.is_some() {
            return Ok(Phase::Transport);
        }
        if phase == Phase::Transport && self.transport && self.nat {
            return Ok(Phase::Consumers);
        }
        Ok(match phase {
            Phase::Consumers if self.core => Phase::Estimation,
            Phase::Estimation if self.nse => Phase::Discovery,
            Phase::Discovery if self.dht => Phase::Applications,
            Phase::Applications if self.cadet && self.regex.ready().is_some() => Phase::Vpn,
            _ => phase,
        })
    }

    fn complete(&mut self, phase: Phase) -> Option<Ready> {
        if phase == Phase::Vpn
            && let (
                Some(peer),
                Some(tcp),
                Some(udp),
                Some(quic),
                Some(http3),
                Some(unix_mtu),
                Some(vpn),
            ) = (
                self.peer,
                &mut self.tcp,
                &mut self.udp,
                self.quic.ready(),
                self.http3.ready(),
                self.unix.ready(),
                self.vpn.ready(),
            )
        {
            return Some(Ready {
                peer,
                tcp_addresses: std::mem::take(tcp),
                udp_addresses: std::mem::take(udp),
                quic_address: quic,
                http3_address: http3,
                unix_mtu,
                vpn_ready: vpn.is_some(),
            });
        }
        None
    }

    fn check_peer(&self, service: Service, peer: [u8; 32]) -> Result<(), FailureCause> {
        if self.peer != Some(peer) {
            return Err(FailureCause::Identity(service));
        }
        Ok(())
    }
}

pub(crate) async fn supervise(
    phases: watch::Sender<Phase>,
    mut notices: mpsc::Receiver<Notice>,
    deadline: Instant,
    optional: OptionalServices,
    stop: impl Future<Output = io::Result<()>>,
    publish: impl FnOnce(&Ready) -> io::Result<()>,
) -> Result<Exit, Failure> {
    let mut stop = std::pin::pin!(stop);
    let mut deadline = std::pin::pin!(tokio::time::sleep_until(deadline));
    let mut publish = Some(publish);
    let mut initial = Initial {
        quic: OptionalReady::for_profile(optional.quic),
        http3: OptionalReady::for_profile(optional.http3),
        unix: OptionalReady::for_profile(optional.unix),
        udp: (!optional.udp).then(Vec::new),
        regex: OptionalReady::for_profile(optional.regex),
        vpn: OptionalReady::for_profile(optional.vpn),
        ..Initial::default()
    };
    let mut failure = None::<Failure>;
    let mut phase = Phase::Foundation;
    let mut exited = [false; SERVICES.len()];
    exited[Service::Quic as usize] = !optional.quic;
    exited[Service::Http3 as usize] = !optional.http3;
    exited[Service::Unix as usize] = !optional.unix;
    exited[Service::Udp as usize] = !optional.udp;
    exited[Service::Regex as usize] = !optional.regex;
    exited[Service::Vpn as usize] = !optional.vpn;
    let mut batch = Vec::with_capacity(EVENT_CAPACITY);

    while !exited.iter().all(|ended| *ended) {
        let next = tokio::select! {
            biased;
            stopped = &mut stop, if phase < Phase::StopVpn => {
                failure = stopped.err().map(|error| FailureCause::Stop(error).into());
                Phase::StopVpn
            }
            () = &mut deadline, if phase < Phase::StopVpn && initial.ready.is_none() => {
                failure = Some(FailureCause::Deadline.into());
                Phase::StopVpn
            }
            received = notices.recv_many(&mut batch, EVENT_CAPACITY) => {
                if received == 0 {
                    return Err(FailureCause::Runtime(io::ErrorKind::BrokenPipe.into()).into());
                }
                let mut next = phase;
                for notice in batch.drain(..) {
                    match notice {
                        Notice::Ready(ready) if next < Phase::StopVpn => {
                            next = match initial.apply(next, ready) {
                                Ok(advance) => advance,
                                Err(error) => {
                                    failure = Some(error.into());
                                    Phase::StopVpn
                                }
                            };
                        }
                        Notice::Ready(_) => {}
                        Notice::Exited { service, result } => {
                            exited[service as usize] = true;
                            let error = match result {
                                ChildExit::Finished { result: Err(error), .. } => Some(error),
                                ChildExit::Finished { result: Ok(()), stopping: false } => {
                                    Some(io::Error::other("required GNUnet service stopped early").into())
                                }
                                ChildExit::Finished { result: Ok(()), stopping: true } | ChildExit::Skipped => None,
                            };
                            if let Some(cause) = error {
                                let original = ServiceFailure { service, cause };
                                if let Some(prior) = &mut failure {
                                    prior.retirement.push(original);
                                } else {
                                    failure = Some(FailureCause::Service(original).into());
                                }
                                next = next.max(Phase::StopVpn);
                            }
                        }
                    }
                }
                if let Some(ready) = initial.complete(next)
                    && let Some(publish) = publish.take()
                {
                    match publish(&ready) {
                        Ok(()) => {
                            initial.ready = Some(ready);
                            next = Phase::Running;
                        }
                        Err(error) => {
                            failure = Some(FailureCause::Ready(error).into());
                            next = Phase::StopVpn;
                        }
                    }
                }
                next
            }
        };

        let stopping_done = |threshold| {
            SERVICES
                .iter()
                .zip(exited)
                .all(|(service, stopped)| service.stop() > threshold || stopped)
        };
        let mut next = next;
        for (stage, after) in [
            (Phase::StopVpn, Phase::StopApplications),
            (Phase::StopApplications, Phase::StopDiscovery),
            (Phase::StopDiscovery, Phase::StopEstimation),
            (Phase::StopEstimation, Phase::StopConsumers),
            (Phase::StopConsumers, Phase::StopTransport),
            (Phase::StopTransport, Phase::StopFoundation),
        ] {
            if next == stage && stopping_done(stage) {
                next = after;
            }
        }
        if next != phase {
            phase = next;
            phases.send_replace(phase);
        }
    }

    match failure {
        Some(error) => Err(error),
        None => Ok(initial.ready.map_or(Exit::BeforeReady, Exit::AfterReady)),
    }
}

#[cfg(test)]
mod tests;
