//! One original shared Resolver query, bound before USERNAME. No OS DNS,
//! second broker, private MQ, background task, or saved-address rebinding.
use crate::{
    listeners::{Listeners, PreparedListeners},
    settings::Settings,
};
use gnunet_resolver_broker::{BrokerError, Driver, DriverEvent};
use gnunet_service_runtime::{Activation, clock::Deadline};
use gnunet_types::Error;
use std::{
    error::Error as StdError,
    fmt,
    future::{Future, poll_fn},
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::Poll,
    time::Duration,
};
use tokio::time::Instant;

type Cause = Box<dyn StdError>;
/// Original callback and native effects, for the selected process Reporter.
#[derive(Debug)]
pub enum Event<'a> {
    /// An actual original shared broker observation.
    Resolver(DriverEvent),
    /// A real bind/listen refusal; other returned addresses can still succeed.
    BindFailed {
        /// Original callback's requested endpoint.
        address: SocketAddr,
        /// Original syscall cause, before callback release.
        error: &'a io::Error,
    },
    /// An actual broker socket failure, not a manufactured DNS END.
    Native(&'a io::Error),
    /// Actual broker endpoint/configuration refusal.
    Connection(&'a BrokerError),
}
/// Real bounded startup diagnostics; a failed Logger gates the next provider.
pub struct Observers<'a> {
    /// Synchronous original-event consumer, without a new scheduled task.
    pub event: &'a mut dyn FnMut(Event<'_>),
    /// Permanent selected Logger/PROGRAM stop latch.
    pub failed: &'a dyn Fn() -> bool,
}
/// Declared descriptor/callback capacity, not another configuration protocol.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum original address callbacks/bind attempts; never silently truncated.
    pub addresses: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self { addresses: 16 }
    }
}
/// Terminal original cause and independent native/endpoint/bind diagnostics.
/// A queued DNS request is not a successful bind or a fabricated final callback.
#[derive(Debug)]
pub struct Failure {
    /// Actual terminal stop, budget, callback, or resource refusal.
    pub original: Cause,
    /// First original socket failure, if different from the terminal cause.
    pub native: Option<io::Error>,
    /// First original endpoint/configuration refusal.
    pub connection: Option<BrokerError>,
    /// First actual bind/listen refusal among returned addresses.
    pub binding: Option<io::Error>,
}
impl Failure {
    fn new(error: impl StdError + 'static) -> Self {
        Self {
            original: Box::new(error),
            native: None,
            connection: None,
            binding: None,
        }
    }
}
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "TCP hostname prebinding: {}; native={:?}; endpoint={:?}; bind={:?}",
            self.original, self.native, self.connection, self.binding
        )
    }
}
impl StdError for Failure {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(&*self.original)
    }
}
fn timeout() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "original TCP BINDTO sixty-second budget expired",
    )
}
enum Turn {
    Address(IpAddr),
    End,
    Driven,
    Stop,
}
/// Resolve only hostname BINDTO through this exact caller-owned process Driver.
/// Every callback is acknowledged after its actual bind attempt. Returned FDs
/// remain prebound across USERNAME and are registered by `finish` without bind.
/// Numeric/inherited routes bypass DNS entirely. None is an actual local stop,
/// never Resolver END or readiness. Dropping this future cancels its original
/// query/leases and closes all prebound FDs; the caller still owns the Driver.
pub async fn prepare<
    const R: usize,
    const N: usize,
    S: Future<Output = io::Result<()>> + ?Sized,
>(
    settings: &Settings,
    activation: Activation,
    resolver: &mut Driver<R, N>,
    mut shutdown: Pin<&mut S>,
    limits: Limits,
    observers: Observers<'_>,
) -> Result<Option<PreparedListeners>, Failure> {
    let Observers { event, failed } = observers;
    let stopping = poll_fn(|cx| {
        Poll::Ready(if failed() {
            Some(Ok(()))
        } else {
            match shutdown.as_mut().poll(cx) {
                Poll::Ready(result) => Some(result),
                Poll::Pending => None,
            }
        })
    })
    .await;
    if let Some(result) = stopping {
        result.map_err(Failure::new)?;
        return Ok(None);
    }
    let Some(hostname) = settings
        .hostname
        .as_ref()
        .filter(|_| activation.sockets.is_empty())
    else {
        return Listeners::prepare(settings, activation)
            .map(Some)
            .map_err(Failure::new);
    };
    if limits.addresses == 0 || limits.addresses > 256 {
        return Err(Failure::new(Error::Capacity));
    }
    let mut listeners = PreparedListeners::reserve(limits.addresses).map_err(Failure::new)?;
    // Capture native hard before subscriptions, samples, or query admission.
    let hard = Instant::now()
        .checked_add(Duration::from_secs(60))
        .ok_or_else(|| Failure::new(Error::Overflow))?;
    let port = resolver.context().resolution_context();
    let clock = port.clock();
    let now = clock.sample().map_err(Failure::new)?.now;
    let until = now
        .as_micros()
        .checked_add(60_000_000)
        .filter(|value| *value != u64::MAX)
        .ok_or_else(|| Failure::new(Error::Overflow))?;
    let mut deadline = Box::pin(
        Deadline::at(
            clock.clone(),
            gnunet_types::AbsoluteTime::from_micros(until),
        )
        .map_err(Failure::new)?,
    );
    let mut native = Box::pin(tokio::time::sleep_until(hard));
    let admitted = poll_fn(|cx| {
        if failed() {
            return Poll::Ready(Ok(false));
        }
        if Instant::now() >= hard {
            return Poll::Ready(Err(Failure::new(timeout())));
        }
        if let Poll::Ready(result) = shutdown.as_mut().poll(cx) {
            return Poll::Ready(result.map(|()| false).map_err(Failure::new));
        }
        if let Poll::Ready(result) = deadline.as_mut().poll(cx) {
            return Poll::Ready(Err(match result {
                Ok(()) => Failure::new(timeout()),
                Err(error) => Failure::new(error),
            }));
        }
        if failed() {
            return Poll::Ready(Ok(false));
        }
        if Instant::now() >= hard {
            return Poll::Ready(Err(Failure::new(timeout())));
        }
        Poll::Ready(Ok(true))
    })
    .await?;
    if !admitted || failed() {
        return Ok(None);
    }
    if Instant::now() >= hard {
        return Err(Failure::new(timeout()));
    }
    let lookup = if settings.disable_v6 {
        port.lookup_ipv4(hostname.name(), Duration::from_secs(60))
    } else {
        port.lookup(hostname.name(), Duration::from_secs(60))
    };
    let mut lookup = lookup.map_err(Failure::new)?.ok_or_else(|| {
        Failure::new(io::Error::new(
            io::ErrorKind::NotConnected,
            "official Resolver did not admit original BINDTO request",
        ))
    })?;
    let mut callbacks = 0usize;
    let mut first_native = None;
    let mut first_connection = None;
    let mut first_bind = None;
    let mut result = loop {
        let turn = {
            let mut driving = std::pin::pin!(
                resolver.drive_waiting(Some(hard), |value| event(Event::Resolver(value)))
            );
            poll_fn(|cx| {
                if failed() {
                    return Poll::Ready(Ok(Turn::Stop));
                }
                if Instant::now() >= hard {
                    return Poll::Ready(Err(Failure::new(timeout())));
                }
                // Native hard remains a wake source even if the canonical clock
                // repeatedly returns Pending due to a revision race.
                if native.as_mut().poll(cx).is_ready() {
                    return Poll::Ready(Err(Failure::new(timeout())));
                }
                if let Poll::Ready(result) = shutdown.as_mut().poll(cx) {
                    return Poll::Ready(result.map(|()| Turn::Stop).map_err(Failure::new));
                }
                if failed() {
                    return Poll::Ready(Ok(Turn::Stop));
                }
                if let Poll::Ready(result) = deadline.as_mut().poll(cx) {
                    return Poll::Ready(Err(match result {
                        Ok(()) => Failure::new(timeout()),
                        Err(error) => Failure::new(error),
                    }));
                }
                match lookup.poll_next(cx) {
                    Poll::Ready(Ok(Some(address))) => {
                        return Poll::Ready(Ok(Turn::Address(address)));
                    }
                    Poll::Ready(Ok(None)) => return Poll::Ready(Ok(Turn::End)),
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(Failure::new(error))),
                    Poll::Pending => {}
                }
                if failed() {
                    return Poll::Ready(Ok(Turn::Stop));
                }
                if Instant::now() >= hard {
                    return Poll::Ready(Err(Failure::new(timeout())));
                }
                driving
                    .as_mut()
                    .poll(cx)
                    .map(|result| result.map(|_| Turn::Driven).map_err(Failure::new))
            })
            .await
        };
        if let Some(error) = resolver.take_io_error() {
            event(Event::Native(&error));
            if first_native.is_none() {
                first_native = Some(error);
            }
        }
        if let Some(error) = resolver.take_connect_error() {
            event(Event::Connection(&error));
            if first_connection.is_none() {
                first_connection = Some(error);
            }
        }
        match turn {
            Err(error) => break Err(error),
            Ok(Turn::Stop) => break Ok(None),
            Ok(Turn::Driven) => {}
            Ok(Turn::End) => {
                if failed() {
                    break Ok(None);
                }
                if Instant::now() >= hard {
                    break Err(Failure::new(timeout()));
                }
                match clock.sample() {
                    Ok(sample) if sample.now.as_micros() >= until => {
                        break Err(Failure::new(timeout()));
                    }
                    Err(error) => break Err(Failure::new(error)),
                    Ok(_) => {}
                }
                if Instant::now() >= hard {
                    break Err(Failure::new(timeout()));
                }
                if failed() {
                    break Ok(None);
                }
                if listeners.is_empty() {
                    break Err(Failure::new(io::Error::new(
                        io::ErrorKind::AddrNotAvailable,
                        "original Resolver END without an actual listening socket",
                    )));
                }
                break Ok(Some(listeners));
            }
            Ok(Turn::Address(ip)) => {
                // A Logger callback can fail while the Driver produced this
                // address. Do not admit another native effect afterwards.
                if failed() {
                    break Ok(None);
                }
                if Instant::now() >= hard {
                    break Err(Failure::new(timeout()));
                }
                match clock.sample() {
                    Ok(sample) if sample.now.as_micros() >= until => {
                        break Err(Failure::new(timeout()));
                    }
                    Err(error) => break Err(Failure::new(error)),
                    Ok(_) => {}
                }
                if Instant::now() >= hard {
                    break Err(Failure::new(timeout()));
                }
                if callbacks == limits.addresses {
                    break Err(Failure::new(Error::Capacity));
                }
                callbacks += 1;
                if settings.disable_v6 && ip.is_ipv6() {
                    break Err(Failure::new(Error::Unsupported));
                }
                let address = SocketAddr::new(ip, hostname.port());
                if failed() {
                    break Ok(None);
                }
                if Instant::now() >= hard {
                    break Err(Failure::new(timeout()));
                }
                let attempt = listeners.bind(address);
                if let Err(error) = attempt {
                    event(Event::BindFailed {
                        address,
                        error: &error,
                    });
                    if first_bind.is_none() {
                        first_bind = Some(error);
                    }
                }
                // Failure is an actual socket attempt as well. This releases
                // only this original callback; it does not claim a listener.
                if let Err(error) = lookup.address_effect_done() {
                    break Err(Failure::new(error));
                }
                if failed() {
                    break Ok(None);
                }
                tokio::task::yield_now().await;
            }
        }
    };
    // Dropping the original query also retires any held callback before Services
    // may disconnect its sole Driver. No new query, END or bind is fabricated.
    drop(lookup);
    if matches!(&result, Ok(None))
        && (first_native.is_some() || first_connection.is_some() || first_bind.is_some())
    {
        result = Err(Failure::new(io::Error::new(
            io::ErrorKind::Interrupted,
            "original TCP prebinding stopped with retained provider diagnostics",
        )));
    }
    result.map_err(|mut error| {
        error.native = first_native;
        error.connection = first_connection;
        error.binding = first_bind;
        error
    })
}
