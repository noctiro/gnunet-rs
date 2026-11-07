//! Official CLIENT connection selection and explicit process Resolver ports.
//!
//! This facade uses the same Unix/TCP and official Resolver implementation as
//! the existing clients. A connected socket establishes no application handshake
//! or remote processing. The caller retains its connection attempt and partial
//! I/O state across canceled drive futures and owns retry scheduling separately.
/// Retained generic CLIENT connection, canonical clock and framed IO ownership.
pub mod channel;
/// Caller-owned configuration that is sampled only at documented CLIENT effects.
mod client_transport;
mod live_configuration;
/// Official weak service-presence observation.
pub mod presence;
/// Typed process Resolver effects, independent of the broker implementation.
pub mod resolution;
use gnunet_config::Configuration;
use gnunet_service_runtime::connection::Connection;
pub use live_configuration::LiveConfiguration;
use std::{
    future::Future,
    io,
    path::PathBuf,
    pin::Pin,
    task::{Context, Poll},
};

/// Owned poll-time gate for a retained Send connection attempt. The callback
/// reads original caller cancellation/time/known-source state only; it must not
/// perform native IO, reenter this attempt, or claim a newly observed source.
/// Refusal is retained as an original port error, never an ordinary retry.
pub type ConnectGuard = std::sync::Arc<dyn Fn() -> io::Result<()> + Send + Sync>;

/// Validated endpoint snapshot for one logical official CLIENT connection.
/// Cloning retains the same selection inputs; it does not open a socket.
#[derive(Clone)]
pub struct Endpoint(client_transport::Endpoint);
impl Endpoint {
    /// Validate one configured logical MQ with the caller's shared process Resolver.
    pub fn configuration(
        config: Configuration,
        service: &'static [u8],
        resolution: crate::resolution::SharedResolution,
    ) -> Result<Self, ConnectError> {
        client_transport::Source::Configuration {
            config: Box::new(config),
            service,
            resolution,
        }
        .resolve()
        .map(Self)
    }
    /// Cache TCP for this MQ; reread live service UNIXPATH only at later attempts.
    /// Resolver selection is owned independently by the supplied shared context.
    pub fn configuration_live(
        configuration: LiveConfiguration,
        service: &'static [u8],
        resolution: crate::resolution::SharedResolution,
    ) -> Result<Self, ConnectError> {
        client_transport::live_endpoint(configuration, service, resolution).map(Self)
    }
    /// Direct Unix-only connection; it never opens any Resolver MQ.
    pub fn unix(path: PathBuf) -> Result<Self, ConnectError> {
        client_transport::Source::unix(path).resolve().map(Self)
    }
    /// Change only the explicit bounded probe capacity before starting an attempt.
    pub fn with_probe_limits(
        mut self,
        limits: crate::resolution::ResolutionLimits,
    ) -> Result<Self, ConnectError> {
        client_transport::set_limits(&mut self.0, limits)?;
        Ok(self)
    }
    /// Own the original partial socket/DNS attempt across canceled wait futures.
    pub fn attempt(&self, round: u64) -> ConnectionAttempt {
        ConnectionAttempt(client_transport::attempt(self.0.clone(), round))
    }
    /// Retain an owned original gate through actual Resolver/probe/connect
    /// callbacks, including each native connect poll and socket option phase.
    /// No borrowed poll callback escapes into the Send connection future.
    pub fn attempt_guarded(&self, round: u64, guard: ConnectGuard) -> ConnectionAttempt {
        ConnectionAttempt(client_transport::attempt_guarded(
            self.0.clone(),
            round,
            Some(guard),
        ))
    }
}

/// One owned connection attempt; no application frames are submitted by it.
#[must_use = "the connection attempt must be polled or explicitly dropped"]
pub struct ConnectionAttempt(Pin<Box<dyn Future<Output = io::Result<Connection>> + Send>>);

impl Future for ConnectionAttempt {
    type Output = io::Result<Connection>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().0.as_mut().poll(cx)
    }
}

/// Caller-owned endpoint selection source, sampled at explicit MQ effects.
pub struct EndpointSource(client_transport::Source);
impl EndpointSource {
    /// Retain an independent endpoint selector with the same original clock and
    /// Resolver. Snapshot configuration is copied fallibly; live configuration
    /// remains shared. This creates no waiter, MQ, reconnect or hidden Resolver.
    pub fn duplicate(&self) -> Result<Self, ConnectError> {
        self.0.duplicate().map(Self)
    }
    /// Freeze one original selector. Subsequent live configuration replacement
    /// cannot retarget this selector; no DNS result or connection epoch is invented.
    pub fn snapshot(&self) -> Result<Self, ConnectError> {
        let [fixed] = Self::snapshot_all([self])?;
        Ok(fixed)
    }
    /// Freeze only the selected Unix/TCP endpoint and share its immutable names
    /// across later logical MQs. Live configuration is first actually snapshotted;
    /// its future replacement cannot retarget this explicit fixed profile. This
    /// performs configuration selection only, never DNS/socket/timer/native IO.
    /// The same original clock and explicit process Resolver remain selected.
    pub fn fixed_endpoint(&self) -> Result<Self, ConnectError> {
        self.0.fixed_endpoint().map(Self)
    }
    /// Dynamic storage shared by one fixed endpoint selection: original path and
    /// hostname capacities plus its two Arc payloads/control words. Duplicates
    /// share this allocation, so callers charge it once per original selection.
    /// None means this is a different profile with independently owned config.
    /// Inline selector/channel/future, Resolver/clock and native IO allocations
    /// remain separately owned; this is not allocator-overhead or RSS accounting.
    pub fn fixed_endpoint_storage_bytes(&self) -> Result<Option<usize>, ConnectError> {
        self.0.fixed_storage_bytes()
    }
    /// Freeze a bounded caller group. Sources sharing the same LiveConfiguration
    /// all derive from one coherent configuration copy, even when that live object
    /// is concurrently replaced. Separate domains remain separate. No socket opens.
    pub fn snapshot_all<const N: usize>(sources: [&Self; N]) -> Result<[Self; N], ConnectError> {
        client_transport::Source::snapshots(sources.map(|s| &s.0)).map(|fixed| fixed.map(Self))
    }
    /// Copy this selector's configuration for mapping rules in the same original
    /// request. A frozen selector returns its fixed configuration; Unix has none.
    /// This grants no new authority beyond the caller-owned selector.
    pub fn configuration_snapshot(&self) -> Result<Option<Configuration>, ConnectError> {
        self.0.configuration_snapshot()
    }
    /// A direct Unix endpoint; no Resolver is created.
    pub fn unix(path: PathBuf) -> Self {
        Self(client_transport::Source::unix(path))
    }
    /// Direct Unix endpoint using an explicitly shared caller clock. Creating
    /// the selector reserves no timer/listener and starts no Resolver or socket.
    pub fn unix_with_clock(
        path: PathBuf,
        clock: std::sync::Arc<dyn gnunet_service_runtime::clock::RuntimeClock>,
    ) -> Self {
        Self(client_transport::Source::Unix { path, clock })
    }
    /// Retain a configuration snapshot and the caller's shared Resolver.
    pub fn configuration(
        config: Configuration,
        service: &'static [u8],
        resolution: resolution::SharedResolution,
    ) -> Self {
        Self(client_transport::Source::Configuration {
            config: Box::new(config),
            service,
            resolution,
        })
    }
    /// Retain explicit live configuration, with an independently selected Resolver.
    pub fn live(
        config: LiveConfiguration,
        service: &'static [u8],
        resolution: resolution::SharedResolution,
    ) -> Self {
        Self(client_transport::Source::Live {
            config,
            service,
            resolution,
        })
    }
    /// Share the original canonical clock source without creating a waiter.
    pub fn clock(&self) -> std::sync::Arc<dyn gnunet_service_runtime::clock::RuntimeClock> {
        self.0.clock()
    }
    /// Reserve a real source-domain timer, preserving original port errors.
    pub fn timer(&self, duration: std::time::Duration) -> io::Result<resolution::ResolutionTimer> {
        self.0.timer(duration)
    }
    /// Sample the source for a new logical MQ without opening a socket.
    pub fn resolve(&self) -> Result<Endpoint, ConnectError> {
        self.0.resolve().map(Endpoint)
    }
}
/// Boundary failures from the OS, original deadline or official message validation.
#[derive(Debug)]
pub enum ConnectError {
    /// Official service configuration/path validation failed.
    Configuration(gnunet_config::Error),
    /// An OS/socket failure.
    Io(io::Error),
    /// Invalid/unsupported official message or exhausted caller capacity.
    Protocol(gnunet_types::Error),
}
impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Configuration(error) => write!(f, "IPC configuration: {error}"),
            Self::Io(error) => write!(f, "IPC I/O: {error}"),
            Self::Protocol(error) => write!(f, "IPC protocol: {error:?}"),
        }
    }
}
impl std::error::Error for ConnectError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Configuration(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Protocol(e) => Some(e),
        }
    }
}
impl From<gnunet_config::Error> for ConnectError {
    fn from(value: gnunet_config::Error) -> Self {
        Self::Configuration(value)
    }
}
impl From<io::Error> for ConnectError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}
impl From<gnunet_types::Error> for ConnectError {
    fn from(value: gnunet_types::Error) -> Self {
        Self::Protocol(value)
    }
}
