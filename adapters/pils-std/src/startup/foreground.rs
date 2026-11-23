//! Caller-owned startup, readiness and physical PILS retirement.
#[cfg(windows)]
use super::unix_access;
use super::{Prepared, prepare_using, verify_configured_identity};
use crate::service::{Limits, Progress, Report};
use gnunet_config::{Configuration, Environment};
use gnunet_service_runtime::{
    Activation, BoundListeners, accepted::SocketEvent, clock::RuntimeClock, credentials::UnixAccess,
};
use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    task::Poll,
};

type Failure = Box<dyn Error>;

/// Configuration and native listener authority supplied by the embedding host.
pub struct EmbeddedStartup<'a> {
    /// Official configuration with absolute `[PEER] PRIVATE_KEY` and, for a
    /// fresh local bind, absolute `[PILS] UNIXPATH`.
    pub config: &'a Configuration,
    /// Original listeners to adopt. An empty set selects a fresh local bind.
    pub activation: Activation,
    /// Bounded service resources.
    pub limits: Limits,
}

/// Clean physical retirement with the actual readiness observation.
#[derive(Clone, Copy, Debug)]
pub enum ForegroundExit {
    /// Stop arrived before the readiness callback completed.
    BeforeReady(Report),
    /// The readiness callback completed before retirement.
    AfterReady(Report),
}

impl ForegroundExit {
    /// Actual service counters at retirement.
    #[must_use]
    pub const fn report(self) -> Report {
        match self {
            Self::BeforeReady(report) | Self::AfterReady(report) => report,
        }
    }
}

/// Original startup or runtime failure with the counters after physical close.
#[derive(Debug)]
pub struct ForegroundFailure {
    report: Report,
    original: Failure,
    cleanup: Option<Failure>,
}

impl ForegroundFailure {
    fn startup(error: impl Into<Failure>) -> Self {
        Self {
            report: Report::default(),
            original: error.into(),
            cleanup: None,
        }
    }

    /// Actual counters at retirement, or zero when service never started.
    #[must_use]
    pub const fn report(&self) -> Report {
        self.report
    }
}

impl fmt::Display for ForegroundFailure {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.original, out)?;
        if let Some(cleanup) = &self.cleanup {
            write!(out, ". PILS cleanup observer also failed: {cleanup}")?;
        }
        Ok(())
    }
}

impl Error for ForegroundFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.original.as_ref())
    }
}

struct AbsolutePaths;

impl Environment for AbsolutePaths {
    fn variable(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }

    fn current_dir(&self) -> io::Result<PathBuf> {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "embedded PILS requires absolute paths",
        ))
    }
}

fn absolute_path(config: &Configuration, section: &[u8], key: &[u8]) -> Result<PathBuf, Failure> {
    Ok(config.get_absolute_filename(section, key, &AbsolutePaths)?)
}

/// Prepare and drive the actual PILS service on the caller's I/O runtime.
/// Fresh startup binds the configured local endpoint, with owner access by
/// default. Paths come from the supplied configuration and never use the process
/// environment. The host supplies the canonical clock, readiness and stop.
/// Stop precedes startup, listener polling and readiness polling. Synchronous
/// private-root preparation must return before a concurrent stop can be seen.
pub async fn foreground_embedded(
    setup: EmbeddedStartup<'_>,
    clock: Arc<dyn RuntimeClock>,
    ready: impl AsyncFnOnce(&BoundListeners, [u8; 32]) -> Result<(), Failure>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe_socket: impl FnMut(SocketEvent),
    observe_progress: impl FnMut(&Progress) -> io::Result<()>,
) -> Result<ForegroundExit, ForegroundFailure> {
    let EmbeddedStartup {
        config,
        activation,
        limits,
    } = setup;
    let mut shutdown = std::pin::pin!(shutdown);
    if until_stop(std::future::ready(()), shutdown.as_mut())
        .await
        .map_err(ForegroundFailure::startup)?
        .is_none()
    {
        return Ok(ForegroundExit::BeforeReady(Report::default()));
    }
    let prepared = prepare_using(config, clock, limits, || {
        absolute_path(config, b"PEER", b"PRIVATE_KEY")
    })
    .map_err(ForegroundFailure::startup)?;
    let bound = until_stop(bind_embedded(config, activation), shutdown.as_mut())
        .await
        .map_err(ForegroundFailure::startup)?
        .transpose()
        .map_err(ForegroundFailure::startup)?;
    let Some(bound) = bound else {
        return Ok(ForegroundExit::BeforeReady(Report::default()));
    };
    foreground_listening_with_async_ready(
        prepared,
        bound,
        ready,
        shutdown.as_mut(),
        observe_socket,
        observe_progress,
    )
    .await
}

async fn bind_embedded(
    config: &Configuration,
    activation: Activation,
) -> Result<BoundListeners, Failure> {
    if activation.is_empty() {
        let path = absolute_path(config, b"PILS", b"UNIXPATH")?;
        let access = UnixAccess::from_config(config, b"PILS")?
            .map(Into::into)
            .unwrap_or_default();
        return Ok(BoundListeners::bind_local(path, access).await?);
    }
    #[cfg(unix)]
    return BoundListeners::bind(config, b"PILS", activation).await;
    #[cfg(windows)]
    Ok(BoundListeners::from_activation_with_access(
        activation,
        unix_access(config)?,
    )?)
}

/// Bind the configured or inherited Unix/TCP listeners using desktop startup
/// configuration, then drive the prepared host with synchronous readiness.
pub async fn foreground(
    prepared: Prepared,
    activation: Activation,
    ready: impl FnOnce(&BoundListeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe_socket: impl FnMut(SocketEvent),
    observe_progress: impl FnMut(&Progress) -> io::Result<()>,
) -> Result<Report, Failure> {
    verify_configured_identity(&prepared.config)?;
    #[cfg(unix)]
    let bound = BoundListeners::bind(&prepared.config, b"PILS", activation).await?;
    #[cfg(windows)]
    let bound = {
        let access = unix_access(&prepared.config)?;
        if activation.is_empty() {
            BoundListeners::bind_configured(&prepared.config, b"PILS", access.into()).await?
        } else {
            BoundListeners::from_activation_with_access(activation, access)?
        }
    };
    foreground_listening(
        prepared,
        bound,
        ready,
        shutdown,
        observe_socket,
        observe_progress,
    )
    .await
}

/// Drive the prepared host on the caller's original listeners with synchronous
/// readiness. This entry does no new binding or private-root preparation.
pub async fn foreground_listening(
    prepared: Prepared,
    bound: BoundListeners,
    ready: impl FnOnce(&BoundListeners, [u8; 32]) -> io::Result<()>,
    shutdown: impl Future<Output = io::Result<()>>,
    observe_socket: impl FnMut(SocketEvent),
    observe_progress: impl FnMut(&Progress) -> io::Result<()>,
) -> Result<Report, Failure> {
    Ok(foreground_listening_with_async_ready(
        prepared,
        bound,
        async |bound, peer| Ok(ready(bound, peer)?),
        shutdown,
        observe_socket,
        observe_progress,
    )
    .await?
    .report())
}

/// Drive the prepared host on original listeners under host-owned readiness
/// and stop futures. A stop drops a pending readiness wait. A host may retain
/// the underlying acknowledgement owner outside its readiness future.
pub async fn foreground_listening_with_async_ready(
    prepared: Prepared,
    bound: BoundListeners,
    ready: impl AsyncFnOnce(&BoundListeners, [u8; 32]) -> Result<(), Failure>,
    shutdown: impl Future<Output = io::Result<()>>,
    mut observe_socket: impl FnMut(SocketEvent),
    mut observe_progress: impl FnMut(&Progress) -> io::Result<()>,
) -> Result<ForegroundExit, ForegroundFailure> {
    verify_configured_identity(&prepared.config).map_err(ForegroundFailure::startup)?;
    let mut host = prepared.into_host();
    let mut shutdown = std::pin::pin!(shutdown);
    let mut acknowledged = false;
    let outcome: Result<(), Failure> = async {
        let peer = host
            .identity()
            .ok_or("PILS prepared owner is already closed")?;
        if until_stop(ready(&bound, peer), shutdown.as_mut())
            .await?
            .transpose()?
            .is_none()
        {
            return Ok(());
        }
        acknowledged = true;
        let listeners = bound.listeners();
        while let Some(progress) = until_stop(
            host.drive(&listeners, &mut observe_socket, None),
            shutdown.as_mut(),
        )
        .await?
        .transpose()?
        {
            observe_progress(&progress)?;
            if matches!(progress, Progress::Closed) {
                break;
            }
        }
        Ok(())
    }
    .await;

    host.close();
    let mut cleanup = None;
    while let Some(event) = host.next_event() {
        if let Err(error) = observe_progress(&event) {
            cleanup.get_or_insert_with(|| Box::new(error) as Failure);
        }
    }
    let report = host.report();
    match (outcome, cleanup) {
        (Err(original), cleanup) => Err(ForegroundFailure {
            report,
            original,
            cleanup,
        }),
        (Ok(()), Some(original)) => Err(ForegroundFailure {
            report,
            original,
            cleanup: None,
        }),
        (Ok(()), None) if acknowledged => Ok(ForegroundExit::AfterReady(report)),
        (Ok(()), None) => Ok(ForegroundExit::BeforeReady(report)),
    }
}

async fn until_stop<T>(
    work: impl Future<Output = T>,
    mut stop: Pin<&mut impl Future<Output = io::Result<()>>>,
) -> io::Result<Option<T>> {
    let mut work = std::pin::pin!(work);
    poll_fn(|cx| {
        if let Poll::Ready(result) = stop.as_mut().poll(cx) {
            return Poll::Ready(result.map(|()| None));
        }
        work.as_mut().poll(cx).map(Some).map(Ok)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnunet_service_runtime::clock::SystemClock;
    use std::{
        cell::Cell,
        task::{Context, Waker},
    };

    #[test]
    fn stop_precedes_embedded_preparation_and_readiness() {
        let config = Configuration::new(Default::default());
        let ready_called = Cell::new(false);
        let mut owner = std::pin::pin!(foreground_embedded(
            EmbeddedStartup {
                config: &config,
                activation: Activation::default(),
                limits: Limits::default(),
            },
            Arc::new(SystemClock),
            async |_: &BoundListeners, _| {
                ready_called.set(true);
                Ok(())
            },
            std::future::ready(Ok(())),
            |_| {},
            |_| Ok(()),
        ));
        let result = owner.as_mut().poll(&mut Context::from_waker(Waker::noop()));
        assert!(matches!(
            result,
            Poll::Ready(Ok(ForegroundExit::BeforeReady(_)))
        ));
        assert!(!ready_called.get());
    }
}
