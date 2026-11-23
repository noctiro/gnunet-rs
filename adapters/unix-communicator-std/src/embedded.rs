//! Caller-driven foreground for the local UNIX testing communicator.
use crate::{Close, Error, Event, Fault, Instance, Limits, Progress, Runtime, Sources};
use std::{
    fmt,
    future::{Future, poll_fn},
    io,
    task::Poll,
};

#[cfg(feature = "embedded-config")]
pub use crate::configured::Configured;

/// Official configuration section for the UNIX testing communicator.
pub const SECTION: &[u8] = b"communicator-unix";

/// Explicit dependencies of one native UNIX communicator.
pub struct Settings {
    /// Original TRANSPORT and PILS selectors sharing the caller's clock.
    pub sources: Sources,
    /// Native filesystem path bytes or a Linux ABI abstract name.
    pub path: Vec<u8>,
    /// Original runtime bounds and PILS profile.
    pub limits: Limits,
}

/// The local PILS identity and original whole registration/address writes.
pub struct Ready {
    /// Verified local announcement's peer key.
    pub peer: [u8; 32],
    /// Complete inner datagram MTU on this native source.
    pub mtu: usize,
}

/// One original failure with its independent native cleanup.
#[derive(Debug)]
pub enum Failure {
    /// Original communicator error, including its observed cleanup.
    Runtime(Error),
    /// Stop future failure and physical cleanup, when startup had occurred.
    Stop {
        /// Original host failure.
        cause: io::Error,
        /// Actual socket and callback retirement.
        cleanup: Option<Close>,
    },
    /// Application readiness refusal followed by actual retirement.
    Readiness {
        /// Original host failure.
        cause: io::Error,
        /// Actual socket and callback retirement.
        cleanup: Close,
    },
    /// Retirement returned an unresolved descriptor or path result.
    Cleanup(Close),
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runtime(error) => error.fmt(f),
            Self::Stop { cause, cleanup } => {
                write!(f, "UNIX host stop failed with {cause}. Cleanup {cleanup:?}")
            }
            Self::Readiness { cause, cleanup } => {
                write!(
                    f,
                    "UNIX readiness callback failed with {cause}. Cleanup {cleanup:?}"
                )
            }
            Self::Cleanup(report) => write!(f, "UNIX cleanup unresolved {report:?}"),
        }
    }
}

impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            Self::Stop { cause, .. } | Self::Readiness { cause, .. } => Some(cause),
            Self::Cleanup(_) => None,
        }
    }
}

/// Drive one local testing communicator on the caller's Tokio reactor with I/O
/// and timers enabled. Complete the stop future and await original retirement.
/// Native datagrams supply unauthenticated peer claims.
pub async fn serve(
    settings: Settings,
    on_ready: impl FnOnce(Ready) -> io::Result<()>,
    stop: impl Future<Output = io::Result<()>>,
    mut observe: impl FnMut(Event<'_>),
) -> Result<(), Failure> {
    let mut stop = std::pin::pin!(stop);
    if let Poll::Ready(result) = poll_fn(|cx| Poll::Ready(stop.as_mut().poll(cx))).await {
        return result.map_err(|cause| Failure::Stop {
            cause,
            cleanup: None,
        });
    }
    tokio::runtime::Handle::try_current()
        .map_err(|error| Failure::Runtime(Fault::Io(io::Error::other(error)).into()))?;
    let instance = Instance::new();
    let mut pils = gnunet_pils::client::Instance::new();
    let mut runtime = Runtime::bind(
        &instance,
        &mut pils,
        settings.sources,
        &settings.path,
        settings.limits,
    )
    .map_err(Failure::Runtime)?;
    let mut on_ready = Some(on_ready);
    loop {
        let turn = poll_fn(|cx| {
            if let Poll::Ready(result) = stop.as_mut().poll(cx) {
                return Poll::Ready(Turn::Stop(result));
            }
            runtime.poll(cx, None, &mut observe).map(Turn::Drive)
        })
        .await;
        match turn {
            Turn::Stop(stopped) => {
                let cleanup = runtime.close(&mut observe);
                return match stopped {
                    Ok(()) if cleanup.uncertain() => Err(Failure::Cleanup(cleanup)),
                    Ok(()) => Ok(()),
                    Err(cause) => Err(Failure::Stop {
                        cause,
                        cleanup: Some(cleanup),
                    }),
                };
            }
            Turn::Drive(Err(error)) => return Err(Failure::Runtime(error)),
            Turn::Drive(Ok(Progress::Stopped)) => return Ok(()),
            Turn::Drive(Ok(Progress::Activity | Progress::WaitDeadline)) => {}
        }
        if runtime.ready()
            && let Some(peer) = runtime.peer()
            && let Some(ready) = on_ready.take()
            && let Err(cause) = ready(Ready {
                peer,
                mtu: runtime.mtu(),
            })
        {
            return Err(Failure::Readiness {
                cause,
                cleanup: runtime.close(&mut observe),
            });
        }
        tokio::task::yield_now().await;
    }
}

enum Turn {
    Stop(io::Result<()>),
    Drive(Result<Progress, Error>),
}

/// Drive a parsed official UNIX communicator using the caller's original
/// TRANSPORT and PILS selectors and clock.
#[cfg(feature = "embedded-config")]
pub async fn serve_configured(
    configured: Configured,
    sources: Sources,
    on_ready: impl FnOnce(Ready) -> io::Result<()>,
    stop: impl Future<Output = io::Result<()>>,
    observe: impl FnMut(Event<'_>),
) -> Result<(), Failure> {
    serve(
        Settings {
            path: configured.path,
            limits: configured.limits,
            sources,
        },
        on_ready,
        stop,
        observe,
    )
    .await
}
