//! Bounded read-only IPv6 DAD/address observations for one original TUN epoch.
use crate::{Epoch, Info, OwnedTun};
use std::{
    future::{Future, poll_fn},
    io,
    net::Ipv6Addr,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::Backend;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos::Backend;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod unsupported {
    use super::*;
    pub(super) struct Backend;
    impl Backend {
        pub(super) fn new(_: &Ipv6Target, _: Ipv6WatchOptions) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "IPv6 readiness requires Linux/macOS",
            ))
        }
        pub(super) fn begin(&mut self) -> io::Result<()> {
            Err(io::ErrorKind::Unsupported.into())
        }
        pub(super) fn poll(
            &mut self,
            _: &mut Context<'_>,
            _: &Ipv6Target,
        ) -> Poll<io::Result<Step>> {
            Poll::Ready(Err(io::ErrorKind::Unsupported.into()))
        }
        pub(super) fn close(self) -> io::Result<()> {
            Ok(())
        }
    }
}
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use unsupported::Backend;
/// Immutable exact address/interface identity and original observation deadline.
#[derive(Clone, Debug)]
pub struct Ipv6Target {
    epoch: Epoch,
    interface: Info,
    address: Ipv6Addr,
    prefix: u8,
    deadline: Instant,
}
impl Ipv6Target {
    /// Original TUN lifetime; this token never retains its descriptor.
    #[must_use]
    pub const fn epoch(&self) -> &Epoch {
        &self.epoch
    }
    /// Original kernel-qualified interface, never rebound by name/index reuse.
    #[must_use]
    pub const fn interface(&self) -> &Info {
        &self.interface
    }
    /// Exact requested IPv6 address.
    #[must_use]
    pub const fn address(&self) -> Ipv6Addr {
        self.address
    }
    /// Exact required prefix length.
    #[must_use]
    pub const fn prefix(&self) -> u8 {
        self.prefix
    }
    /// Original absolute finite deadline, unchanged by drive waits or queries.
    #[must_use]
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }
}
/// Actual address state at the native query, without remote-delivery evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ipv6State {
    /// Present with the exact prefix, but kernel DAD remains in progress.
    Tentative,
    /// Kernel explicitly reports duplicate-address detection failed.
    DadFailed,
    /// Exact tuple exists without tentative/duplicate/detached flags.
    /// This does not prove link-up, route installation or future availability.
    Ready,
    /// macOS reports the address detached from its link.
    Detached,
    /// Complete kernel query reports the address absent from this interface.
    Missing,
    /// Address exists on this interface with a different prefix.
    PrefixMismatch {
        /// Actual kernel prefix length, not silently normalized.
        observed: u8,
    },
}
/// One actual completed native read-only query. Repeated samples are intentional.
#[derive(Clone, Debug)]
pub struct Ipv6Observation {
    /// Original immutable query identity.
    pub target: Ipv6Target,
    /// Actual kernel state for the original address/prefix.
    pub state: Ipv6State,
    /// Exact OS flags (Linux IFA_FLAGS, macOS IN6_IFF), if address was present.
    pub native_flags: Option<u32>,
    /// Time the native observation completed; never resets the original deadline.
    pub observed_at: Instant,
}
/// Honest reason the original observer retired; no readiness is fabricated.
#[derive(Debug)]
pub enum Ipv6End {
    /// Original finite lifetime elapsed.
    Deadline,
    /// Original TUN closed/transferred or its original name/index disappeared.
    SourceRetired,
    /// Caller explicitly stopped this read-only observer.
    Cancelled,
    /// Actual native error or explicit bounded-query/malformed-data failure.
    Error(io::Error),
}
/// Terminal observer, retaining the original target and most recent real sample.
#[derive(Debug)]
pub struct Ipv6Completion {
    /// Original epoch/interface/address/prefix/deadline.
    pub target: Ipv6Target,
    /// Actual stop cause.
    pub reason: Ipv6End,
    /// Last real sample, independent of the stop cause.
    pub last: Option<Ipv6Observation>,
    /// Separate actual native query-socket close error, never retried.
    pub close_error: Option<io::Error>,
}
/// One bounded step. Ready/Missing/DadFailed observations do not stop monitoring.
#[derive(Debug)]
pub enum Ipv6Progress {
    /// One completed actual native sample.
    Observed(Ipv6Observation),
    /// One bounded Linux request/datagram; not proof of address readiness.
    Activity {
        /// Actual native bytes sent/received.
        bytes: usize,
    },
    /// Original observer retired and its native query socket was closed.
    Complete(Ipv6Completion),
    /// One caller wait elapsed; original owner/deadline remain.
    WaitDeadline,
    /// The original completion was already consumed.
    Finished,
}
/// Explicit bounded sampling resources; no hidden task/subscription is started.
#[derive(Clone, Copy, Debug)]
pub struct Ipv6WatchOptions {
    /// Sampling interval, from1ms through1s. Also bounds idle source-loss checks.
    pub interval: Duration,
    /// Linux maximum datagrams in one complete address dump, from1 through256.
    pub dump_datagrams: usize,
    /// Linux maximum received bytes per dump, from32768 through1048576.
    pub dump_bytes: usize,
}
impl Default for Ipv6WatchOptions {
    fn default() -> Self {
        Self {
            interval: Duration::from_millis(50),
            dump_datagrams: 64,
            dump_bytes: 262144,
        }
    }
}
impl Ipv6WatchOptions {
    fn validate(self) -> io::Result<()> {
        if self.interval < Duration::from_millis(1)
            || self.interval > Duration::from_secs(1)
            || !(1..=256).contains(&self.dump_datagrams)
            || !(32768..=1048576).contains(&self.dump_bytes)
        {
            return Err(crate::platform::invalid(
                "invalid IPv6 readiness resource bound",
            ));
        }
        Ok(())
    }
}
pub(super) enum Step {
    #[cfg(target_os = "linux")]
    Activity(usize),
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    Sample(Ipv6State, Option<u32>),
}
/// Caller-driven original read-only kernel observer. No background thread, address
/// mutation, automatic rebind, or replay occurs. Drop only releases its query FD.
#[must_use]
pub struct Ipv6Watch {
    target: Ipv6Target,
    backend: Option<Backend>,
    options: Ipv6WatchOptions,
    alarm: Pin<Box<Sleep>>,
    interval: Pin<Box<Sleep>>,
    querying: bool,
    last: Option<Ipv6Observation>,
}
impl OwnedTun {
    /// Start read-only DAD/address observation for this verified original device.
    /// Success creates the real query socket but does not mean the address exists.
    pub fn watch_ipv6(
        &self,
        address: Ipv6Addr,
        prefix: u8,
        until: Instant,
        options: Ipv6WatchOptions,
    ) -> io::Result<Ipv6Watch> {
        options.validate()?;
        if prefix > 128 {
            return Err(crate::platform::invalid("IPv6 prefix overflow"));
        }
        if !self.epoch.current() || self.fd.is_none() {
            return Err(io::ErrorKind::NotConnected.into());
        }
        if Instant::now() >= until {
            return Err(io::ErrorKind::TimedOut.into());
        }
        tokio::runtime::Handle::try_current().map_err(|e| io::Error::other(e.to_string()))?;
        let info = crate::platform::verify(self.fd.as_ref().ok_or(io::ErrorKind::NotConnected)?)?;
        if info.index != self.info.index || info.name != self.info.name {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "original TUN interface changed",
            ));
        }
        watch(
            self.epoch(),
            self.info.clone(),
            address,
            prefix,
            until,
            options,
        )
    }
}
impl Ipv6Watch {
    /// Original query identity, unchanged across repeated samples.
    #[must_use]
    pub const fn target(&self) -> &Ipv6Target {
        &self.target
    }
    /// Most recent completed actual query, not an assurance of future availability.
    #[must_use]
    pub const fn last(&self) -> Option<&Ipv6Observation> {
        self.last.as_ref()
    }
    fn complete(&mut self, reason: Ipv6End) -> Ipv6Progress {
        let Some(backend) = self.backend.take() else {
            return Ipv6Progress::Finished;
        };
        let close_error = backend.close().err();
        Ipv6Progress::Complete(Ipv6Completion {
            target: self.target.clone(),
            reason,
            last: self.last.take(),
            close_error,
        })
    }
    /// Close the original read-only query socket now; never changes configuration.
    pub fn cancel(&mut self) -> Ipv6Progress {
        let reason = if !self.target.epoch.current() {
            Ipv6End::SourceRetired
        } else if Instant::now() >= self.target.deadline {
            Ipv6End::Deadline
        } else {
            Ipv6End::Cancelled
        };
        self.complete(reason)
    }
    fn source(&self) -> io::Result<bool> {
        if !self.target.epoch.current() {
            return Ok(false);
        }
        match crate::platform::index(&self.target.interface.name) {
            Ok(index) => Ok(index == self.target.interface.index),
            Err(e)
                if matches!(
                    e.raw_os_error(),
                    Some(libc::ENXIO | libc::ENODEV | libc::ENOENT)
                ) =>
            {
                Ok(false)
            }
            Err(e) => Err(e),
        }
    }
    /// At most one netlink send/receive, or one bounded group of macOS address
    /// ioctls. Fixed original deadline and periodic epoch checks remain armed.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Ipv6Progress> {
        if self.backend.is_none() {
            return Poll::Ready(Ipv6Progress::Finished);
        }
        match self.source() {
            Ok(true) => {}
            Ok(false) => return Poll::Ready(self.complete(Ipv6End::SourceRetired)),
            Err(e) => return Poll::Ready(self.complete(Ipv6End::Error(e))),
        }
        if Instant::now() >= self.target.deadline || self.alarm.as_mut().poll(cx).is_ready() {
            return Poll::Ready(self.complete(Ipv6End::Deadline));
        }
        // Always arm an interval wake, even during a stalled dump, so source
        // retirement is observed without requiring an epoch-internal hidden task.
        let tick = self.interval.as_mut().poll(cx).is_ready();
        if tick {
            let next = (Instant::now() + self.options.interval).min(self.target.deadline);
            self.interval.as_mut().reset(next);
            let _armed = self.interval.as_mut().poll(cx);
        }
        if !self.querying {
            if !tick {
                return Poll::Pending;
            }
            let Some(backend) = self.backend.as_mut() else {
                return Poll::Ready(Ipv6Progress::Finished);
            };
            if let Err(e) = backend.begin() {
                return Poll::Ready(self.complete(Ipv6End::Error(e)));
            }
            self.querying = true;
        }
        let Some(backend) = self.backend.as_mut() else {
            return Poll::Ready(Ipv6Progress::Finished);
        };
        match backend.poll(cx, &self.target) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(self.complete(Ipv6End::Error(e))),
            #[cfg(target_os = "linux")]
            Poll::Ready(Ok(Step::Activity(bytes))) => Poll::Ready(Ipv6Progress::Activity { bytes }),
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            Poll::Ready(Ok(Step::Sample(state, native_flags))) => {
                match self.source() {
                    Ok(true) => {}
                    Ok(false) => return Poll::Ready(self.complete(Ipv6End::SourceRetired)),
                    Err(e) => return Poll::Ready(self.complete(Ipv6End::Error(e))),
                }
                let observed_at = Instant::now();
                if observed_at >= self.target.deadline {
                    return Poll::Ready(self.complete(Ipv6End::Deadline));
                }
                self.querying = false;
                self.interval
                    .as_mut()
                    .reset((Instant::now() + self.options.interval).min(self.target.deadline));
                let observation = Ipv6Observation {
                    target: self.target.clone(),
                    state,
                    native_flags,
                    observed_at,
                };
                self.last = Some(observation.clone());
                Poll::Ready(Ipv6Progress::Observed(observation))
            }
        }
    }
    /// Await one bounded step; dropping this future preserves the original query.
    /// A shorter wait never extends the original finite observation deadline.
    pub async fn drive(&mut self, until: Instant) -> Ipv6Progress {
        let mut wait = Box::pin(tokio::time::sleep_until(until));
        poll_fn(|cx| {
            // Service original source/deadline before a caller's wait timeout.
            if !self.target.epoch.current()
                || Instant::now() >= self.target.deadline
                || self.backend.is_none()
            {
                return self.poll(cx);
            }
            if wait.as_mut().poll(cx).is_ready() {
                Poll::Ready(Ipv6Progress::WaitDeadline)
            } else {
                self.poll(cx)
            }
        })
        .await
    }
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn malformed() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid/incomplete IPv6 address query",
    )
}

/// Real observer used by both the descriptor owner and an actual helper pipe
/// source. A source-bound kernel interface check precedes socket construction.
pub(crate) fn watch(
    epoch: Epoch,
    info: Info,
    address: Ipv6Addr,
    prefix: u8,
    until: Instant,
    options: Ipv6WatchOptions,
) -> io::Result<Ipv6Watch> {
    options.validate()?;
    if prefix > 128 {
        return Err(crate::platform::invalid("IPv6 prefix overflow"));
    }
    crate::helper::check_interface(&epoch, &info, until).map_err(io::Error::other)?;
    let target = Ipv6Target {
        epoch,
        interface: info,
        address,
        prefix,
        deadline: until,
    };
    let mut backend = Backend::new(&target, options)?;
    backend.begin()?;
    Ok(Ipv6Watch {
        target,
        backend: Some(backend),
        options,
        alarm: Box::pin(tokio::time::sleep_until(until)),
        interval: Box::pin(tokio::time::sleep_until(Instant::now())),
        querying: true,
        last: None,
    })
}
