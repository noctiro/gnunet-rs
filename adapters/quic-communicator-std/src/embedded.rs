//! A communicator owned by the caller's reactor and shutdown future.
use crate::{
    Event, Fault, Limits, Progress, Runtime, Sources, credentials::Tls, frame_pool::FramePool,
    tls::Profile,
};
use gnunet_service_runtime::network_change::NetworkChanges;
use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    task::Poll,
};

#[cfg(feature = "embedded-config")]
pub use crate::configured::Configured;

/// Explicit resources for one native communicator.
pub struct Settings {
    /// TRANSPORT, PILS and optional NAT selectors, all on the same caller clock.
    pub sources: Sources,
    /// Actual numeric UDP bind. A zero port uses an ephemeral port.
    pub bind: SocketAddr,
    /// Configured TLS authority, which selects the raw QUIC or HTTP/3 profile.
    pub tls: Tls,
    /// Bounded runtime and per-connection resources.
    pub limits: Limits,
    /// Maximum retained receive-slab and loan metadata bytes.
    pub frame_pool_bytes: usize,
    /// Paced hints for the original native interface classification scanner.
    pub network_changes: NetworkChanges,
    /// Preparation of the original QUIC/HTTP3 UDP socket before bind/send.
    pub socket_policy: gnunet_service_runtime::network::SocketPolicy,
}

/// Initial whole TRANSPORT registration and verified local PILS observation.
pub struct Ready {
    /// Original raw QUIC or HTTP/3 profile.
    pub profile: Profile,
    /// Verified local peer from the original PILS source.
    pub peer: [u8; 32],
    /// Actual bound UDP endpoint.
    pub address: SocketAddr,
}

/// An original communicator or host cause.
#[derive(Debug)]
pub enum Cause {
    /// Actual original startup or runtime failure.
    Runtime(Fault),
    /// Host stop future failure.
    Stop(io::Error),
    /// Host readiness callback refusal.
    Readiness(io::Error),
}

impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(error) => error.fmt(f),
            Self::Stop(error) => write!(f, "QUIC host stop failed with {error}"),
            Self::Readiness(error) => write!(f, "QUIC readiness callback failed with {error}"),
        }
    }
}
impl std::error::Error for Cause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(match self {
            Self::Runtime(error) => error,
            Self::Stop(error) | Self::Readiness(error) => error,
        })
    }
}

/// Original result and any independent retirement failure.
#[derive(Debug)]
pub struct Failure {
    /// First cause, when retirement follows a failure.
    pub original: Option<Cause>,
    /// Independent cleanup error from the original native runtime.
    pub cleanup: Option<Box<Fault>>,
}

impl Failure {
    fn original(cause: Cause) -> Self {
        Self {
            original: Some(cause),
            cleanup: None,
        }
    }
}
impl From<Fault> for Failure {
    fn from(cause: Fault) -> Self {
        Self::original(Cause::Runtime(cause))
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(original) = &self.original {
            original.fmt(f)?;
        }
        if let Some(error) = &self.cleanup {
            if self.original.is_some() {
                f.write_str(". ")?;
            }
            write!(f, "QUIC cleanup failed with {error}")?;
        }
        Ok(())
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        if let Some(cause) = &self.original {
            Some(cause)
        } else {
            self.cleanup.as_deref().map(|error| error as _)
        }
    }
}

/// Drive this communicator on an I/O and timer-enabled Tokio reactor. Complete
/// `stop` and keep polling until the same native owners have retired.
/// Readiness reports local registration and bind, before remote connection.
pub async fn serve(
    settings: Settings,
    on_ready: impl FnOnce(Ready) -> io::Result<()>,
    stop: impl Future<Output = io::Result<()>>,
    observe: impl FnMut(Event<'_>),
) -> Result<(), Failure> {
    serve_owned(
        Launch {
            profile: settings.tls.profile(),
            limits: settings.limits,
            frame_pool_bytes: settings.frame_pool_bytes,
            network_changes: settings.network_changes,
            socket_policy: settings.socket_policy,
        },
        || Ok((settings.sources, settings.bind, settings.tls)),
        on_ready,
        stop,
        observe,
    )
    .await
}

/// Drive the official configured profile. The caller supplies the same native
/// service selectors and clock through Sources. If using NAT, pass the
/// configured advertisement bound and the profile's section to its selector.
/// Credential and listener I/O begins only after the stop check.
#[cfg(feature = "embedded-config")]
pub async fn serve_configured(
    configured: Configured,
    sources: Sources,
    network_changes: NetworkChanges,
    socket_policy: gnunet_service_runtime::network::SocketPolicy,
    on_ready: impl FnOnce(Ready) -> io::Result<()>,
    stop: impl Future<Output = io::Result<()>>,
    observe: impl FnMut(Event<'_>),
) -> Result<(), Box<dyn std::error::Error>> {
    serve_owned(
        Launch {
            profile: configured.profile,
            limits: configured.limits,
            frame_pool_bytes: configured.frame_pool_bytes,
            network_changes,
            socket_policy,
        },
        || {
            let bind = configured.bind.socket()?;
            let (tls, _) = configured.prepare_tls()?;
            Ok((sources, bind, tls))
        },
        on_ready,
        stop,
        observe,
    )
    .await
}

struct Launch {
    profile: Profile,
    limits: Limits,
    frame_pool_bytes: usize,
    network_changes: NetworkChanges,
    socket_policy: gnunet_service_runtime::network::SocketPolicy,
}

async fn serve_owned<E: From<Failure> + From<Fault>>(
    launch: Launch,
    prepare: impl FnOnce() -> Result<(Sources, SocketAddr, Tls), E>,
    on_ready: impl FnOnce(Ready) -> io::Result<()>,
    stop: impl Future<Output = io::Result<()>>,
    mut observe: impl FnMut(Event<'_>),
) -> Result<(), E> {
    let Launch {
        profile,
        limits,
        frame_pool_bytes,
        network_changes,
        socket_policy,
    } = launch;
    let mut stop = std::pin::pin!(stop);
    let preflight = |result: io::Result<()>| {
        result.map_err(|error| E::from(Failure::original(Cause::Stop(error))))
    };
    if let Poll::Ready(result) = poll_fn(|cx| Poll::Ready(stop.as_mut().poll(cx))).await {
        return preflight(result);
    }
    tokio::runtime::Handle::try_current()
        .map_err(|_| Fault::from(gnunet_types::Error::NotReady))?;
    let pool = FramePool::new(profile, limits, frame_pool_bytes)?;
    if let Poll::Ready(result) = poll_fn(|cx| Poll::Ready(stop.as_mut().poll(cx))).await {
        return preflight(result);
    }
    let (sources, bind, tls) = prepare()?;
    if let Poll::Ready(result) = poll_fn(|cx| Poll::Ready(stop.as_mut().poll(cx))).await {
        return preflight(result);
    }
    pool.run(sources, bind, tls, socket_policy, async |runtime| {
        runtime.set_network_changes(network_changes);
        let original = drive(runtime, profile, on_ready, stop, &mut observe)
            .await
            .err();
        let cleanup = runtime.shutdown(&mut observe).await.cleanup.map(Box::new);
        if original.is_some() || cleanup.is_some() {
            Err(Failure { original, cleanup }.into())
        } else {
            Ok(())
        }
    })
    .await
}

async fn drive<'id>(
    runtime: &mut Runtime<'id, '_, '_, '_, '_>,
    profile: Profile,
    on_ready: impl FnOnce(Ready) -> io::Result<()>,
    stop: impl Future<Output = io::Result<()>>,
    observe: &mut impl FnMut(Event<'id>),
) -> Result<(), Cause> {
    let mut stop = std::pin::pin!(stop);
    let mut on_ready = Some(on_ready);
    loop {
        let step = poll_fn(|cx| {
            if let Poll::Ready(result) = stop.as_mut().poll(cx) {
                return Poll::Ready(result.map(|()| None).map_err(Cause::Stop));
            }
            runtime
                .poll(cx, None, &mut *observe)
                .map(|result| result.map(Some).map_err(Cause::Runtime))
        })
        .await?;
        if matches!(step, None | Some(Progress::Stopped)) {
            return Ok(());
        }
        if runtime.is_ready()
            && let Some(ready) = on_ready.take()
        {
            let peer = runtime.peer().ok_or(Cause::Runtime(Fault::IdentityLost))?;
            let address = runtime.local_addr().map_err(Cause::Runtime)?;
            ready(Ready {
                profile,
                peer,
                address,
            })
            .map_err(Cause::Readiness)?;
        }
        tokio::task::yield_now().await;
    }
}
