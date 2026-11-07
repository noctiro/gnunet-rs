//! Official CLIENT socket attempts with one explicit process Resolver port.
//! No per-query Resolver MQ, hidden global, or native DNS substitution exists.
use crate::{
    ConnectError, ConnectGuard, live_configuration::LiveConfiguration, resolution::PortError,
};
use gnunet_config::{Configuration, ProcessEnvironment};
use std::{
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::net::TcpStream;
#[cfg(unix)]
use tokio::net::UnixStream;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
type SocketFuture = Pin<
    Box<dyn Future<Output = io::Result<gnunet_service_runtime::connection::Connection>> + Send>,
>;
pub(crate) type Connect = Pin<Box<ConnectionFuture>>;
/// A terminal port refusal is retained in this original attempt. Re-polling
/// reports the same cause without replaying its consumed socket/DNS effects.
pub(crate) struct ConnectionFuture {
    pending: Pin<
        Box<dyn Future<Output = io::Result<gnunet_service_runtime::connection::Connection>> + Send>,
    >,
    boundary: Option<PortError>,
}
impl Future for ConnectionFuture {
    type Output = io::Result<gnunet_service_runtime::connection::Connection>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if let Some(error) = &this.boundary {
            return Poll::Ready(Err(error.to_io()));
        }
        match this.pending.as_mut().poll(cx) {
            Poll::Ready(Err(error)) => {
                this.boundary = PortError::from_io(&error).cloned();
                Poll::Ready(Err(error))
            }
            result => result,
        }
    }
}
pub(crate) enum Source {
    Fixed {
        endpoint: std::sync::Arc<Endpoint>,
        clock: std::sync::Arc<dyn gnunet_service_runtime::clock::RuntimeClock>,
    },
    Unix {
        path: PathBuf,
        clock: std::sync::Arc<dyn gnunet_service_runtime::clock::RuntimeClock>,
    },
    Configuration {
        config: Box<Configuration>,
        service: &'static [u8],
        resolution: crate::resolution::SharedResolution,
    },
    Live {
        config: LiveConfiguration,
        service: &'static [u8],
        resolution: crate::resolution::SharedResolution,
    },
}
#[derive(Clone)]
struct Target {
    hostname: Vec<u8>,
    port: u16,
}
#[derive(Clone)]
struct BasicEndpoint {
    unix: Option<PathBuf>,
    tcp: Option<Target>,
}
#[derive(Clone)]
struct LiveInputs {
    service: LiveConfiguration,
    section: &'static [u8],
}
#[derive(Clone)]
pub(crate) struct Endpoint {
    live: Option<LiveInputs>,
    service: std::sync::Arc<BasicEndpoint>,
    resolution: Option<crate::resolution::SharedResolution>,
    limits: crate::resolution::ResolutionLimits,
}
fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}
fn basic(config: &Configuration, service: &[u8]) -> Result<BasicEndpoint, ConnectError> {
    let unix = if config.get(service, b"UNIXPATH").is_some() {
        let path = config.get_filename(service, b"UNIXPATH", &ProcessEnvironment)?;
        if path.as_os_str().is_empty() {
            return Err(gnunet_config::Error::InvalidValue.into());
        }
        Some(path)
    } else {
        None
    };
    let tcp = config
        .get_number(service, b"PORT")
        .ok()
        .and_then(|port| u16::try_from(port).ok())
        .filter(|port| *port != 0)
        .zip(config.get(service, b"HOSTNAME"))
        .filter(|(_, hostname)| !hostname.is_empty())
        .map(|(port, hostname)| Target {
            hostname: hostname.to_vec(),
            port,
        });
    if unix.is_none() && tcp.is_none() {
        return Err(gnunet_config::Error::InvalidValue.into());
    }
    Ok(BasicEndpoint { unix, tcp })
}

impl Source {
    pub(crate) fn duplicate(&self) -> Result<Self, ConnectError> {
        Ok(match self {
            Self::Fixed { endpoint, clock } => Self::Fixed {
                endpoint: endpoint.clone(),
                clock: clock.clone(),
            },
            Self::Unix { path, clock } => Self::Unix {
                path: path.clone(),
                clock: clock.clone(),
            },
            Self::Configuration {
                config,
                service,
                resolution,
            } => Self::Configuration {
                config: Box::new(config.duplicate()?),
                service,
                resolution: resolution.clone(),
            },
            Self::Live {
                config,
                service,
                resolution,
            } => Self::Live {
                config: config.clone(),
                service,
                resolution: resolution.clone(),
            },
        })
    }
    pub(crate) fn snapshots<const N: usize>(
        sources: [&Self; N],
    ) -> Result<[Self; N], ConnectError> {
        let mut fixed: Vec<Self> = Vec::new();
        fixed
            .try_reserve_exact(N)
            .map_err(|_| gnunet_types::Error::Capacity)?;
        for (at, source) in sources.iter().enumerate() {
            let next = match source {
                Self::Live {
                    config,
                    service,
                    resolution,
                } => {
                    let prior = sources[..at].iter().position(
                        |s| matches!(s, Self::Live { config: old, .. } if config.same(old)),
                    );
                    let snapshot = match prior {
                        Some(index) => match &fixed[index] {
                            Self::Configuration { config, .. } => config.duplicate()?,
                            _ => return Err(gnunet_types::Error::Conflict.into()),
                        },
                        None => config.snapshot()?,
                    };
                    Self::Configuration {
                        config: Box::new(snapshot),
                        service,
                        resolution: resolution.clone(),
                    }
                }
                _ => source.duplicate()?,
            };
            fixed.push(next);
        }
        fixed
            .try_into()
            .map_err(|_| gnunet_types::Error::Conflict.into())
    }
    pub(crate) fn configuration_snapshot(&self) -> Result<Option<Configuration>, ConnectError> {
        match self {
            Self::Fixed { .. } => Ok(None),
            Self::Unix { .. } => Ok(None),
            Self::Configuration { config, .. } => Ok(Some(config.duplicate()?)),
            Self::Live { config, .. } => config.snapshot().map(Some),
        }
    }
    pub(crate) fn unix(path: PathBuf) -> Self {
        Self::Unix {
            path,
            clock: std::sync::Arc::new(gnunet_service_runtime::clock::SystemClock),
        }
    }
    pub(crate) fn clock(&self) -> std::sync::Arc<dyn gnunet_service_runtime::clock::RuntimeClock> {
        match self {
            Self::Unix { clock, .. } | Self::Fixed { clock, .. } => clock.clone(),
            Self::Configuration { resolution, .. } | Self::Live { resolution, .. } => {
                resolution.clock()
            }
        }
    }
    /// Register native CLIENT retry in the same source as its selected process
    /// resolver. Direct Unix embeddings select the canonical native wall source.
    pub(crate) fn timer(
        &self,
        duration: Duration,
    ) -> io::Result<crate::resolution::ResolutionTimer> {
        match self {
            Self::Fixed { endpoint, clock } => match &endpoint.resolution {
                Some(resolution) => resolution.timer(duration).map_err(PortError::mark),
                None => native_timer(clock, duration),
            },
            Self::Configuration { resolution, .. } | Self::Live { resolution, .. } => {
                resolution.timer(duration).map_err(PortError::mark)
            }
            Self::Unix { clock, .. } => native_timer(clock, duration),
        }
    }
    pub(crate) fn resolve(&self) -> Result<Endpoint, ConnectError> {
        match self {
            Self::Fixed { endpoint, .. } => Ok((**endpoint).clone()),
            Self::Unix { path, .. } => Ok(Endpoint {
                live: None,
                service: std::sync::Arc::new(BasicEndpoint {
                    unix: Some(path.clone()),
                    tcp: None,
                }),
                resolution: None,
                limits: Default::default(),
            }),
            Self::Configuration {
                config,
                service,
                resolution,
            } => Ok(Endpoint {
                live: None,
                service: std::sync::Arc::new(basic(config, service)?),
                resolution: Some(resolution.clone()),
                limits: Default::default(),
            }),
            Self::Live {
                config,
                service,
                resolution,
            } => {
                let snapshot = config.snapshot()?;
                Ok(Endpoint {
                    live: Some(LiveInputs {
                        service: config.clone(),
                        section: service,
                    }),
                    service: std::sync::Arc::new(basic(&snapshot, service)?),
                    resolution: Some(resolution.clone()),
                    limits: Default::default(),
                })
            }
        }
    }
    pub(crate) fn fixed_endpoint(&self) -> Result<Self, ConnectError> {
        if matches!(self, Self::Fixed { .. }) {
            return self.duplicate();
        }
        // In particular, Live must become Configuration before selection. A
        // frozen endpoint retains no LiveInputs that can later retarget Unix IO.
        let clock = self.clock();
        let endpoint = if matches!(self, Self::Live { .. }) {
            let [snapshot] = Self::snapshots([self])?;
            snapshot.resolve()?
        } else {
            // A pre-frozen Configuration already supplies its exact view; no
            // redundant full configuration copy is needed for endpoint selection.
            self.resolve()?
        };
        if endpoint.live.is_some() {
            return Err(gnunet_types::Error::Conflict.into());
        }
        Ok(Self::Fixed {
            endpoint: std::sync::Arc::new(endpoint),
            clock,
        })
    }
    pub(crate) fn fixed_storage_bytes(&self) -> Result<Option<usize>, ConnectError> {
        let Self::Fixed { endpoint, .. } = self else {
            return Ok(None);
        };
        let names = endpoint
            .service
            .unix
            .as_ref()
            .map_or(0, PathBuf::capacity)
            .checked_add(
                endpoint
                    .service
                    .tcp
                    .as_ref()
                    .map_or(0, |v| v.hostname.capacity()),
            )
            .ok_or(gnunet_types::Error::Overflow)?;
        let metadata = std::mem::size_of::<Endpoint>()
            .checked_add(std::mem::size_of::<BasicEndpoint>())
            .and_then(|n| n.checked_add(4 * std::mem::size_of::<usize>()))
            .ok_or(gnunet_types::Error::Overflow)?;
        Ok(Some(
            names
                .checked_add(metadata)
                .ok_or(gnunet_types::Error::Overflow)?,
        ))
    }
}
fn native_timer(
    clock: &std::sync::Arc<dyn gnunet_service_runtime::clock::RuntimeClock>,
    duration: Duration,
) -> io::Result<crate::resolution::ResolutionTimer> {
    let timer = gnunet_service_runtime::clock::Deadline::after(clock.clone(), duration)
        .map_err(|error| PortError::mark(io::Error::other(error)))?;
    Ok(Box::pin(async move {
        timer
            .await
            .map_err(|error| PortError::mark(io::Error::other(error)))
    }))
}
pub(crate) fn live_endpoint(
    config: LiveConfiguration,
    service: &'static [u8],
    resolution: crate::resolution::SharedResolution,
) -> Result<Endpoint, ConnectError> {
    Source::Live {
        config,
        service,
        resolution,
    }
    .resolve()
}
pub(crate) fn set_limits(
    endpoint: &mut Endpoint,
    limits: crate::resolution::ResolutionLimits,
) -> Result<(), ConnectError> {
    if limits.max_address_probes == 0 {
        return Err(gnunet_types::Error::InvalidInput.into());
    }
    endpoint.limits = limits;
    Ok(())
}
fn live_unix(configuration: &Configuration, service: &[u8]) -> io::Result<Option<PathBuf>> {
    if configuration.get(service, b"UNIXPATH").is_none() {
        return Ok(None);
    }
    match configuration.get_filename(service, b"UNIXPATH", &ProcessEnvironment) {
        Ok(path) => Ok((!path.as_os_str().is_empty()).then_some(path)),
        Err(error @ gnunet_config::Error::Capacity)
        | Err(error @ gnunet_config::Error::Overflow) => Err(io::Error::new(
            io::ErrorKind::OutOfMemory,
            error.to_string(),
        )),
        Err(_) => Ok(None),
    }
}
fn native_guard(guard: &Option<ConnectGuard>) -> io::Result<()> {
    match guard {
        Some(guard) => guard().map_err(PortError::mark),
        None => Ok(()),
    }
}
#[cfg(unix)]
async fn connect_unix(
    path: PathBuf,
    guard: Option<ConnectGuard>,
) -> io::Result<gnunet_service_runtime::connection::Connection> {
    let path = gnunet_service_runtime::network::shorten_unixpath(&path)?;
    native_guard(&guard)?;
    let mut connecting = std::pin::pin!(UnixStream::connect(path));
    poll_fn(|cx| {
        native_guard(&guard)?;
        connecting.as_mut().poll(cx)
    })
    .await
    .map(gnunet_service_runtime::connection::Connection::from_unix)
}
#[cfg(not(unix))]
async fn connect_unix(
    _: PathBuf,
    guard: Option<ConnectGuard>,
) -> io::Result<gnunet_service_runtime::connection::Connection> {
    native_guard(&guard)?;
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "native local socket backend is unavailable; configure official TCP IPC",
    ))
}

enum StartedProbe {
    Started(Probe),
    Failed(io::Error),
}
fn start_probe(
    address: SocketAddr,
    resolution: crate::resolution::SharedResolution,
    cx: &mut Context<'_>,
) -> io::Result<StartedProbe> {
    start_probe_guarded(address, resolution, cx, None)
}
fn start_probe_guarded(
    address: SocketAddr,
    resolution: crate::resolution::SharedResolution,
    cx: &mut Context<'_>,
    guard: Option<ConnectGuard>,
) -> io::Result<StartedProbe> {
    native_guard(&guard)?;
    // Source socket/create/connect runs in the address callback. Only after
    // that syscall phase does add_write_net sample its original 5s timeout.
    let mut connecting = Box::pin(TcpStream::connect(address));
    let initial = connecting.as_mut().poll(cx);
    if let Poll::Ready(Err(error)) = initial {
        return Ok(StartedProbe::Failed(error));
    }
    let mut timer = resolution.timer(CONNECT_TIMEOUT).map_err(PortError::mark)?;
    native_guard(&guard)?;
    match initial {
        Poll::Ready(Ok(stream)) => match stream.set_nodelay(true) {
            Ok(()) => Ok(StartedProbe::Started(Probe {
                pending: None,
                connected: Some(gnunet_service_runtime::connection::Connection::from_tcp(
                    stream,
                )),
                guard,
            })),
            Err(error) => Ok(StartedProbe::Failed(error)),
        },
        Poll::Pending => Ok(StartedProbe::Started(Probe {
            connected: None,
            guard: guard.clone(),
            pending: Some(Box::pin(async move {
                let stream = poll_fn(|cx| {
                    native_guard(&guard)?;
                    if let Poll::Ready(result) = connecting.as_mut().poll(cx) {
                        return Poll::Ready(result);
                    }
                    match timer.as_mut().poll(cx) {
                        Poll::Ready(Ok(())) => Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "official TCP address probe expired",
                        ))),
                        Poll::Ready(Err(error)) => Poll::Ready(Err(PortError::mark(error))),
                        Poll::Pending => Poll::Pending,
                    }
                })
                .await?;
                native_guard(&guard)?;
                stream.set_nodelay(true)?;
                Ok(gnunet_service_runtime::connection::Connection::from_tcp(
                    stream,
                ))
            })),
        })),
        Poll::Ready(Err(error)) => Ok(StartedProbe::Failed(error)),
    }
}

struct Probe {
    pending: Option<SocketFuture>,
    connected: Option<gnunet_service_runtime::connection::Connection>,
    guard: Option<ConnectGuard>,
}
impl Probe {
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<gnunet_service_runtime::connection::Connection>> {
        native_guard(&self.guard)?;
        if let Some(stream) = self.connected.take() {
            return Poll::Ready(Ok(stream));
        }
        match self.pending.as_mut() {
            Some(pending) => pending.as_mut().poll(cx),
            None => Poll::Ready(Err(io::ErrorKind::NotConnected.into())),
        }
    }
}
struct Probes {
    resolution: crate::resolution::SharedResolution,
    limit: usize,
    sockets: Vec<Probe>,
    issued: usize,
    last_error: Option<io::Error>,
    guard: Option<ConnectGuard>,
}
impl Probes {
    fn with_resolution(resolution: crate::resolution::SharedResolution, limit: usize) -> Self {
        Self {
            resolution,
            limit,
            sockets: Vec::new(),
            issued: 0,
            last_error: None,
            guard: None,
        }
    }
    fn add(&mut self, mut address: SocketAddr, port: u16, cx: &mut Context<'_>) -> io::Result<()> {
        if self.issued >= self.limit {
            return Err(PortError::mark(io::Error::new(
                io::ErrorKind::OutOfMemory,
                "official client address-probe capacity exhausted",
            )));
        }
        self.sockets
            .try_reserve(1)
            .map_err(|_| PortError::mark(io::ErrorKind::OutOfMemory.into()))?;
        // The original resolved sockaddr may carry an IPv6 interface/flow.
        // Match CLIENT's full-address copy: only the configured port changes.
        address.set_port(port);
        let started = match &self.guard {
            Some(guard) => {
                start_probe_guarded(address, self.resolution.clone(), cx, Some(guard.clone()))?
            }
            None => start_probe(address, self.resolution.clone(), cx)?,
        };
        match started {
            StartedProbe::Started(probe) => self.sockets.push(probe),
            StartedProbe::Failed(error) => self.last_error = Some(error),
        }
        self.issued += 1;
        Ok(())
    }
    fn poll(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<gnunet_service_runtime::connection::Connection>> {
        let mut index = 0;
        while index < self.sockets.len() {
            match self.sockets[index].poll(cx) {
                Poll::Ready(Ok(stream)) => {
                    self.sockets.clear();
                    return Poll::Ready(Ok(stream));
                }
                Poll::Ready(Err(error)) => {
                    if PortError::from_io(&error).is_some() {
                        return Poll::Ready(Err(error));
                    }
                    drop(self.sockets.remove(index));
                    self.last_error = Some(error);
                }
                Poll::Pending => index += 1,
            }
        }
        Poll::Pending
    }
    fn failure(&mut self) -> io::Error {
        self.last_error.take().unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "official resolver returned no usable addresses",
            )
        })
    }
}

/// One CLIENT attempt using an explicitly shared official process Resolver.
type SharedConnect = Pin<
    Box<
        dyn Future<
                Output = io::Result<(
                    gnunet_service_runtime::connection::Connection,
                    Option<Box<dyn gnunet_service_runtime::connection::ConnectionLease>>,
                )>,
            > + Send,
    >,
>;
fn attempt_shared(
    endpoint: Endpoint,
    round: u64,
    resolution: crate::resolution::SharedResolution,
    limits: crate::resolution::ResolutionLimits,
    guard: Option<ConnectGuard>,
) -> SharedConnect {
    Box::pin(async move {
        native_guard(&guard)?;
        let mut endpoint = endpoint;
        if (round.is_multiple_of(2) || endpoint.service.tcp.is_none())
            && let Some(live) = &endpoint.live
        {
            let config = live
                .service
                .snapshot()
                .map_err(|error| io::Error::other(error.to_string()))?;
            endpoint.service = std::sync::Arc::new(BasicEndpoint {
                unix: live_unix(&config, live.section)?,
                tcp: endpoint.service.tcp.clone(),
            });
        }
        let mut unix_error = None;
        if (round.is_multiple_of(2) || endpoint.service.tcp.is_none())
            && let Some(path) = &endpoint.service.unix
        {
            match connect_unix(path.clone(), guard.clone()).await {
                Ok(stream) => {
                    native_guard(&guard)?;
                    return Ok((stream, None));
                }
                Err(error) if PortError::from_io(&error).is_some() => return Err(error),
                Err(error) => unix_error = Some(error),
            }
        }
        let Some(target) = &endpoint.service.tcp else {
            return Err(unix_error.unwrap_or_else(|| invalid("no official service endpoint")));
        };
        native_guard(&guard)?;
        let Some(mut query) = resolution
            .lookup(&target.hostname, CONNECT_TIMEOUT)
            .map_err(PortError::mark)?
        else {
            // Native start_connect receives no handle and no callback here;
            // it schedules no connect-failure task. Only owner destruction ends
            // this original attempt; selection updates do not invent a retry.
            return std::future::pending().await;
        };
        let mut probes = Probes::with_resolution(resolution, limits.max_address_probes);
        probes.guard = guard.clone();
        let mut complete = false;
        let stream = poll_fn(|cx| {
            while !complete {
                native_guard(&guard)?;
                match query.poll_socket_addr(cx) {
                    Poll::Ready(Ok(Some(address))) => {
                        if let Err(error) = probes.add(address, target.port, cx) {
                            return Poll::Ready(Err(error));
                        }
                        if let Err(error) = query.address_effect_done() {
                            return Poll::Ready(Err(PortError::mark(error)));
                        }
                    }
                    Poll::Ready(Ok(None)) => complete = true,
                    Poll::Ready(Err(error)) => {
                        return Poll::Ready(Err(PortError::mark(error)));
                    }
                    Poll::Pending => break,
                }
            }
            if let Poll::Ready(result) = probes.poll(cx) {
                return Poll::Ready(result);
            }
            if complete && probes.sockets.is_empty() {
                Poll::Ready(Err(probes.failure()))
            } else {
                Poll::Pending
            }
        })
        .await?;
        // A successful TCP probe does not cancel dns_active in client.c. Keep
        // the real subscription, ignoring later values until END/timeout/drop.
        let lease = query.connected().map_err(PortError::mark)?;
        native_guard(&guard)?;
        Ok((stream, Some(lease)))
    })
}

pub(crate) fn attempt(endpoint: Endpoint, round: u64) -> Connect {
    attempt_guarded(endpoint, round, None)
}
pub(crate) fn attempt_guarded(
    endpoint: Endpoint,
    round: u64,
    guard: Option<ConnectGuard>,
) -> Connect {
    Box::pin(ConnectionFuture {
        boundary: None,
        pending: Box::pin(async move {
            native_guard(&guard)?;
            let resolution = endpoint.resolution.clone();
            let limits = endpoint.limits;
            if let Some(resolution) = resolution {
                let (stream, lease) =
                    attempt_shared(endpoint, round, resolution, limits, guard.clone()).await?;
                match lease {
                    Some(lease) => stream
                        .with_lease(lease)
                        .map_err(|rejected| io::Error::other(rejected.reason)),
                    None => Ok(stream),
                }
            } else {
                let mut endpoint = endpoint;
                if let Some(live) = &endpoint.live {
                    endpoint.service = std::sync::Arc::new(BasicEndpoint {
                        unix: live_unix(
                            &live.service.snapshot().map_err(io::Error::other)?,
                            live.section,
                        )?,
                        tcp: endpoint.service.tcp.clone(),
                    });
                }
                if endpoint.service.tcp.is_some() {
                    return Err(invalid("TCP endpoint requires explicit process Resolver"));
                }
                let path = endpoint
                    .service
                    .unix
                    .as_ref()
                    .ok_or_else(|| invalid("no Unix endpoint"))?;
                let stream = connect_unix(path.clone(), guard.clone()).await?;
                native_guard(&guard)?;
                Ok(stream)
            }
        }),
    })
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::panic_in_result_fn,
        reason = "Filename/endpoint assertions retain actual configuration errors"
    )]
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;
    fn config() -> Configuration {
        Configuration::new(Default::default())
    }
    #[test]
    fn expanded_unix_validation_precedes_tcp_and_raw_empty_is_a_relative_path() -> TestResult {
        let mut cfg = config();
        cfg.set_value(b"statistics", b"PORT", Some(b"12345"))?;
        cfg.set_value(b"statistics", b"HOSTNAME", Some(b"127.0.0.1"))?;
        assert!(basic(&cfg, b"statistics")?.tcp.is_some());
        cfg.set_value(b"statistics", b"UNIXPATH", Some(b""))?;
        assert!(basic(&cfg, b"statistics")?.unix.is_some());
        // C filename_expand("") is cwd + '/', not an absent endpoint. A
        // genuine expansion/capacity failure must still precede valid TCP.
        let limits = gnunet_config::Limits {
            max_expanded_bytes: 1,
            ..Default::default()
        };
        let mut limited = Configuration::new(limits);
        limited.set_value(b"statistics", b"PORT", Some(b"12345"))?;
        limited.set_value(b"statistics", b"HOSTNAME", Some(b"127.0.0.1"))?;
        limited.set_value(b"statistics", b"UNIXPATH", Some(b"relative"))?;
        assert!(basic(&limited, b"statistics").is_err());
        cfg.set_value(
            b"statistics",
            b"UNIXPATH",
            Some(b"/tmp/valid-gnunet-socket"),
        )?;
        cfg.set_value(b"statistics", b"PORT", Some(b"999999"))?;
        let endpoint = basic(&cfg, b"statistics")?;
        assert!(endpoint.unix.is_some());
        assert!(endpoint.tcp.is_none());
        cfg.set_value(b"statistics", b"UNIXPATH", None)?;
        assert!(basic(&cfg, b"statistics").is_err());
        Ok(())
    }
}
