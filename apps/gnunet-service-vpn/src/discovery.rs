//! Bounded actual REGEX searches for original VPN discovery operations.
//! No DHT implementation, remote authentication, search DONE or private wire is
//! manufactured here. All original sources share the caller's Resolver/clock.
use gnunet_client_host::EndpointSource;
use gnunet_regex_client_host as regex;
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use gnunet_vpn::{self as core, AfProfile, Discovery, DiscoveryRequest, Phase};
use gnunet_vpn_host::coordinator::{Coordinator, Error as VpnError};
use std::{
    fmt,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};
type Vpn<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy> =
    Coordinator<'id, 'store, 'bytes, 'cadet, 'cstore, 'policy>;
/// Fixed actual MQ/search resource and original finite budgets.
#[derive(Clone, Copy, Debug)]
pub(super) struct Limits {
    pub searches: usize,
    pub send_micros: u64,
    pub first_result_micros: u64,
    pub lifetime_micros: u64,
    pub peer_af: AfProfile,
    pub native: regex::Limits,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            searches: 16,
            send_micros: 10_000_000,
            first_result_micros: 30_000_000,
            lifetime_micros: 60_000_000,
            peer_af: AfProfile::native(),
            native: regex::Limits::default(),
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), Fault> {
        self.peer_af.validate()?;
        if !(1..=256).contains(&self.searches)
            || self.send_micros == 0
            || self.send_micros > self.first_result_micros
            || self.first_result_micros > self.lifetime_micros
            || self.lifetime_micros == u64::MAX
            || Instant::now()
                .checked_add(Duration::from_micros(self.lifetime_micros))
                .is_none()
        {
            return Err(Fault::InvalidInput);
        }
        Ok(())
    }
}
#[derive(Debug)]
pub(super) enum Error {
    Protocol(Fault),
    Native(regex::Error),
    Vpn(VpnError),
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(e) => e.fmt(f),
            Self::Native(e) => e.fmt(f),
            Self::Vpn(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
impl From<regex::Error> for Error {
    fn from(e: regex::Error) -> Self {
        Self::Native(e)
    }
}
impl From<VpnError> for Error {
    fn from(e: VpnError) -> Self {
        Self::Vpn(e)
    }
}
/// Original rejected offer; apply this only after the Coordinator callback ends.
#[derive(Debug)]
pub(super) struct Rejected<'id> {
    pub request: DiscoveryRequest<'id>,
    pub reason: Fault,
}
/// Physical and original-domain observations; callbacks must not reenter owners.
#[derive(Debug)]
pub(super) enum Event<'id, 'regex> {
    Constructed {
        discovery: Discovery<'id>,
        job: regex::Job<'regex>,
    },
    Queued {
        discovery: Discovery<'id>,
        job: regex::Job<'regex>,
        epoch: regex::Epoch<'regex>,
    },
    Written {
        discovery: Discovery<'id>,
        job: regex::Job<'regex>,
        epoch: regex::Epoch<'regex>,
    },
    Selected {
        discovery: Discovery<'id>,
        job: regex::Job<'regex>,
        epoch: regex::Epoch<'regex>,
        peer: [u8; 32],
    },
    Inconclusive {
        discovery: Discovery<'id>,
        reason: Fault,
    },
    NativeEnded {
        discovery: Discovery<'id>,
        end: regex::End<'regex>,
    },
    NativeError {
        discovery: Discovery<'id>,
        error: regex::Error,
    },
    VpnError {
        discovery: Discovery<'id>,
        error: VpnError,
    },
    Retired {
        discovery: Discovery<'id>,
        original_already_stale: bool,
    },
}
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Report {
    pub offered: u64,
    pub constructed: u64,
    pub queued: u64,
    pub written: u64,
    pub selected: u64,
    pub inconclusive: u64,
    pub physical_retired: u64,
    pub retired: u64,
    pub late_retired: u64,
    pub cleanup_errors: u64,
}
struct Entry<'id, 'regex> {
    request: DiscoveryRequest<'id>,
    search: Option<regex::Search<'regex>>,
    queued: bool,
    done: bool,
    selected: bool,
    failure: Option<Fault>,
    failed_core: bool,
    hard: Instant,
}
/// Caller-driven bounded actual Search owners. One stable native allocation
/// domain is reused without a mutable per-search borrow, leak or global id.
pub(super) struct Provider<'id, 'regex> {
    domain: &'regex regex::Instance,
    source: EndpointSource,
    clock: Arc<dyn RuntimeClock>,
    limits: Limits,
    slots: Vec<Option<Entry<'id, 'regex>>>,
    cursor: usize,
    stopping: bool,
    alarm: Option<Pin<Box<Sleep>>>,
    alarm_at: Option<Instant>,
    report: Report,
}
impl<'id, 'regex> Provider<'id, 'regex> {
    pub fn new(
        domain: &'regex regex::Instance,
        source: EndpointSource,
        clock: Arc<dyn RuntimeClock>,
        limits: Limits,
    ) -> Result<Self, Error> {
        limits.validate()?;
        if !Arc::ptr_eq(&source.clock(), &clock) {
            return Err(Fault::InvalidInput.into());
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(limits.searches)
            .map_err(|_| Fault::Capacity)?;
        slots.resize_with(limits.searches, || None);
        Ok(Self {
            domain,
            source,
            clock,
            limits,
            slots,
            cursor: 0,
            stopping: false,
            alarm: None,
            alarm_at: None,
            report: Report::default(),
        })
    }
    /// Callback-safe metadata admission only. It neither opens an MQ nor calls
    /// into Coordinator. A rejected original must be handled after that callback.
    pub fn offer(&mut self, request: DiscoveryRequest<'id>) -> Result<(), Rejected<'id>> {
        let reason = if self.stopping {
            Some(Fault::Closed)
        } else if self
            .slots
            .iter()
            .flatten()
            .any(|e| e.request.discovery == request.discovery)
        {
            Some(Fault::Conflict)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(Rejected { request, reason });
        }
        let Some(i) = self.slots.iter().position(Option::is_none) else {
            return Err(Rejected {
                request,
                reason: Fault::Capacity,
            });
        };
        let Some(hard) =
            Instant::now().checked_add(Duration::from_micros(self.limits.lifetime_micros))
        else {
            return Err(Rejected {
                request,
                reason: Fault::Overflow,
            });
        };
        self.slots[i] = Some(Entry {
            request,
            search: None,
            queued: false,
            done: false,
            selected: false,
            failure: None,
            failed_core: false,
            hard,
        });
        self.report.offered = self.report.offered.saturating_add(1);
        Ok(())
    }
    pub const fn report(&self) -> Report {
        self.report
    }
    pub fn pending(&self) -> usize {
        self.slots.iter().flatten().count()
    }
    fn stale(error: &VpnError) -> bool {
        matches!(
            error,
            VpnError::Protocol(Fault::Stale | Fault::StaleGeneration)
        )
    }
    fn live<'s, 'b, 'c, 'cs, 'p>(
        vpn: &Vpn<'id, 's, 'b, 'c, 'cs, 'p>,
        request: DiscoveryRequest<'id>,
    ) -> Result<bool, Fault> {
        if vpn.close_report().is_some() {
            return Ok(false);
        }
        Ok(vpn.engine().flow_info(request.discovery.flow())?.phase == Phase::Discovering)
    }
    fn emit_failure(
        entry: &mut Entry<'id, 'regex>,
        reason: Fault,
        report: &mut Report,
        observe: &mut impl FnMut(Event<'id, 'regex>),
    ) {
        if entry.failure.is_none() && !entry.selected {
            entry.failure = Some(reason);
            report.inconclusive = report.inconclusive.saturating_add(1);
            observe(Event::Inconclusive {
                discovery: entry.request.discovery,
                reason,
            });
        }
    }
    fn close_entry(
        entry: &mut Entry<'id, 'regex>,
        report: &mut Report,
        observe: &mut impl FnMut(Event<'id, 'regex>),
    ) -> Result<(), Error> {
        if entry.done {
            return Ok(());
        }
        if let Some(search) = entry.search.as_mut() {
            let expected = search.job();
            let epoch = search.epoch();
            let end = search.cancel().ok_or(Fault::OutcomeUnknown)?;
            if end.job != expected || end.epoch != epoch {
                return Err(Fault::StaleGeneration.into());
            }
            if end.retired_mq {
                report.physical_retired = report.physical_retired.saturating_add(1);
            }
            observe(Event::NativeEnded {
                discovery: entry.request.discovery,
                end,
            });
        }
        // No Search construction means no native attempt existed. A constructed
        // Search reaches here only after its original native cancel/end receipt.
        entry.done = true;
        Ok(())
    }
    fn settle<'s, 'b, 'c, 'cs, 'p>(
        entry: &mut Entry<'id, 'regex>,
        vpn: &mut Vpn<'id, 's, 'b, 'c, 'cs, 'p>,
        report: &mut Report,
        observe: &mut impl FnMut(Event<'id, 'regex>),
    ) -> Result<bool, Error> {
        if !entry.done {
            return Ok(false);
        }
        let d = entry.request.discovery;
        if !entry.selected && !entry.failed_core {
            let reason = entry.failure.unwrap_or(Fault::Cancelled);
            match vpn.discovery_failed(d, reason) {
                Ok(()) => entry.failed_core = true,
                Err(e) if Self::stale(&e) => entry.failed_core = true,
                Err(error) => {
                    report.cleanup_errors = report.cleanup_errors.saturating_add(1);
                    observe(Event::VpnError {
                        discovery: d,
                        error,
                    });
                    return Ok(false);
                }
            }
        }
        match vpn.retire_discovery(d) {
            Ok(()) => {
                report.retired = report.retired.saturating_add(1);
                observe(Event::Retired {
                    discovery: d,
                    original_already_stale: false,
                });
                Ok(true)
            }
            Err(e) if Self::stale(&e) => {
                report.late_retired = report.late_retired.saturating_add(1);
                observe(Event::Retired {
                    discovery: d,
                    original_already_stale: true,
                });
                Ok(true)
            }
            Err(error) => {
                report.cleanup_errors = report.cleanup_errors.saturating_add(1);
                observe(Event::VpnError {
                    discovery: d,
                    error,
                });
                Ok(false)
            }
        }
    }
    /// Settle an explicitly refused, never-constructed offer after callback exit.
    /// A duplicate offer does not cancel its already-owned original Search.
    pub fn reject<'s, 'b, 'c, 'cs, 'p>(
        rejected: Rejected<'id>,
        vpn: &mut Vpn<'id, 's, 'b, 'c, 'cs, 'p>,
        observe: &mut impl FnMut(Event<'id, 'regex>),
    ) -> Result<(), Error> {
        if rejected.reason == Fault::Conflict {
            return Err(Fault::Conflict.into());
        }
        let d = rejected.request.discovery;
        observe(Event::Inconclusive {
            discovery: d,
            reason: rejected.reason,
        });
        if let Err(error) = vpn.discovery_failed(d, rejected.reason)
            && !Self::stale(&error)
        {
            return Err(error.into());
        }
        match vpn.retire_discovery(d) {
            Ok(()) => observe(Event::Retired {
                discovery: d,
                original_already_stale: false,
            }),
            Err(error) if Self::stale(&error) => observe(Event::Retired {
                discovery: d,
                original_already_stale: true,
            }),
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }
    fn construct(&self, entry: &mut Entry<'id, 'regex>) -> Result<(), Error> {
        let mut text = [0u8; core::discovery::IPV6_SEARCH_LEN];
        let n =
            core::discovery::exit_search(entry.request.destination, entry.request.port, &mut text)?;
        let now = self.clock.sample()?.now.as_micros();
        let add = |n| now.checked_add(n).ok_or(Fault::Overflow);
        let deadlines = regex::Deadlines {
            send_until: add(self.limits.send_micros)?,
            first_result_until: Some(add(self.limits.first_result_micros)?),
            until: add(self.limits.lifetime_micros)?,
        };
        entry.search = Some(regex::Search::new(
            self.domain,
            self.source.duplicate()?,
            &text[..n],
            deadlines,
            self.limits.native,
        )?);
        Ok(())
    }
    fn turn<'s, 'b, 'c, 'cs, 'p>(
        &mut self,
        entry: &mut Entry<'id, 'regex>,
        cx: &mut Context<'_>,
        vpn: &mut Vpn<'id, 's, 'b, 'c, 'cs, 'p>,
        observe: &mut impl FnMut(Event<'id, 'regex>),
    ) -> Result<bool, Error> {
        if entry.done {
            return Self::settle(entry, vpn, &mut self.report, observe);
        }
        let live = match Self::live(vpn, entry.request) {
            Ok(x) => x,
            Err(Fault::Stale | Fault::StaleGeneration) => false,
            Err(e) => return Err(e.into()),
        };
        if self.stopping || !live || Instant::now() >= entry.hard {
            Self::emit_failure(
                entry,
                if Instant::now() >= entry.hard {
                    Fault::Timeout
                } else {
                    Fault::Cancelled
                },
                &mut self.report,
                observe,
            );
            Self::close_entry(entry, &mut self.report, observe)?;
            return Self::settle(entry, vpn, &mut self.report, observe);
        }
        if entry.search.is_none() {
            // Before creating any real native job, validate the exact original
            // unqueued capability; a copied old request cannot recreate a search.
            if let Err(e) = vpn.engine().can_queue_discovery(entry.request.discovery) {
                Self::emit_failure(entry, e, &mut self.report, observe);
                entry.done = true;
                return Self::settle(entry, vpn, &mut self.report, observe);
            }
            match self.construct(entry) {
                Ok(()) => {
                    self.report.constructed = self.report.constructed.saturating_add(1);
                    let search = entry.search.as_ref().ok_or(Fault::NotReady)?;
                    observe(Event::Constructed {
                        discovery: entry.request.discovery,
                        job: search.job(),
                    });
                    return Ok(true);
                }
                Err(error) => {
                    let reason = match &error {
                        Error::Protocol(e) => *e,
                        Error::Native(regex::Error::Protocol(e)) => *e,
                        _ => Fault::Unavailable,
                    };
                    Self::emit_failure(entry, reason, &mut self.report, observe);
                    match error {
                        Error::Native(error) => observe(Event::NativeError {
                            discovery: entry.request.discovery,
                            error,
                        }),
                        Error::Vpn(error) => observe(Event::VpnError {
                            discovery: entry.request.discovery,
                            error,
                        }),
                        Error::Protocol(_) => {}
                    }
                    entry.done = true;
                    return Self::settle(entry, vpn, &mut self.report, observe);
                }
            }
        }
        let search = entry.search.as_mut().ok_or(Fault::NotReady)?;
        let step = {
            let mut driving = std::pin::pin!(search.drive(None));
            match driving.as_mut().poll(cx) {
                Poll::Pending => return Ok(false),
                Poll::Ready(value) => value,
            }
        };
        match step {
            Ok(regex::Progress::Connected { job, epoch }) => {
                if job != search.job() || Some(epoch) != search.epoch() {
                    return Err(Fault::StaleGeneration.into());
                }
            }
            Ok(regex::Progress::Queued { job, epoch, .. }) => {
                if job != search.job() || Some(epoch) != search.epoch() {
                    return Err(Fault::StaleGeneration.into());
                }
                // Re-registering the same readonly search has a new physical
                // epoch, but does not repeat the original pure discovery commit.
                let admission = if entry.queued {
                    Ok(())
                } else {
                    vpn.discovery_queued(entry.request.discovery)
                };
                match admission {
                    Ok(()) => {
                        entry.queued = true;
                        self.report.queued = self.report.queued.saturating_add(1);
                        observe(Event::Queued {
                            discovery: entry.request.discovery,
                            job,
                            epoch,
                        });
                    }
                    Err(error) => {
                        observe(Event::VpnError {
                            discovery: entry.request.discovery,
                            error,
                        });
                        Self::emit_failure(entry, Fault::Cancelled, &mut self.report, observe);
                        Self::close_entry(entry, &mut self.report, observe)?;
                        return Self::settle(entry, vpn, &mut self.report, observe);
                    }
                }
            }
            Ok(regex::Progress::Submitted { job, epoch, .. }) => {
                if !entry.queued || job != search.job() || Some(epoch) != search.epoch() {
                    return Err(Fault::StaleGeneration.into());
                }
                self.report.written = self.report.written.saturating_add(1);
                observe(Event::Written {
                    discovery: entry.request.discovery,
                    job,
                    epoch,
                });
            }
            Ok(regex::Progress::ResultReady {
                job,
                epoch,
                ordinal,
            }) => {
                if !entry.queued || job != search.job() || Some(epoch) != search.epoch() {
                    return Err(Fault::StaleGeneration.into());
                }
                let view = search.result()?.ok_or(Fault::NotReady)?;
                if view.job != job || view.epoch != epoch || view.ordinal != ordinal {
                    return Err(Fault::StaleGeneration.into());
                }
                let peer = view.result.peer; // Actual IPC result, not authentication.
                match vpn.select_exit(entry.request.discovery, peer, self.limits.peer_af) {
                    Ok(()) => {
                        entry.selected = true;
                        self.report.selected = self.report.selected.saturating_add(1);
                        observe(Event::Selected {
                            discovery: entry.request.discovery,
                            job,
                            epoch,
                            peer,
                        });
                    }
                    Err(error) => {
                        observe(Event::VpnError {
                            discovery: entry.request.discovery,
                            error,
                        });
                        Self::emit_failure(entry, Fault::Cancelled, &mut self.report, observe);
                    }
                }
                // First valid actual result matches official VPN selection. Close
                // the original continuous search before retiring its pure job.
                Self::close_entry(entry, &mut self.report, observe)?;
                return Self::settle(entry, vpn, &mut self.report, observe);
            }
            Ok(regex::Progress::SourceLost { end, .. }) => {
                if end.job != search.job() || end.epoch != search.epoch() {
                    return Err(Fault::StaleGeneration.into());
                }
                if end.retired_mq {
                    self.report.physical_retired = self.report.physical_retired.saturating_add(1);
                }
                observe(Event::NativeEnded {
                    discovery: entry.request.discovery,
                    end,
                });
                // Keep the same discovery and its original native/logical
                // targets. The SDK will restore only this retained search.
            }
            Ok(regex::Progress::Ended(end)) => {
                if end.job != search.job() || end.epoch != search.epoch() {
                    return Err(Fault::StaleGeneration.into());
                }
                let reason = match &end.cause {
                    regex::EndCause::LifetimeDeadline
                    | regex::EndCause::FirstResultDeadline
                    | regex::EndCause::SendDeadline
                    | regex::EndCause::GraceDeadline => Fault::Timeout,
                    regex::EndCause::Cancelled
                    | regex::EndCause::Closed
                    | regex::EndCause::Graceful => Fault::Cancelled,
                    regex::EndCause::Protocol(e)
                    | regex::EndCause::Resource(e)
                    | regex::EndCause::Clock(e) => *e,
                    regex::EndCause::Io(_) => Fault::Io,
                    _ => Fault::Unavailable,
                };
                if end.retired_mq {
                    self.report.physical_retired = self.report.physical_retired.saturating_add(1);
                }
                observe(Event::NativeEnded {
                    discovery: entry.request.discovery,
                    end,
                });
                entry.done = true;
                Self::emit_failure(entry, reason, &mut self.report, observe);
                return Self::settle(entry, vpn, &mut self.report, observe);
            }
            Ok(regex::Progress::Unavailable(error)) | Err(error) => {
                observe(Event::NativeError {
                    discovery: entry.request.discovery,
                    error,
                });
                Self::emit_failure(entry, Fault::Unavailable, &mut self.report, observe);
                Self::close_entry(entry, &mut self.report, observe)?;
                return Self::settle(entry, vpn, &mut self.report, observe);
            }
            Ok(regex::Progress::ConnectRetry { error, .. }) => observe(Event::NativeError {
                discovery: entry.request.discovery,
                error: regex::Error::Io(error),
            }),
            Ok(regex::Progress::Activity { .. }) => {}
            Ok(regex::Progress::WaitDeadline) => return Ok(false),
            Ok(regex::Progress::Closed) => return Err(Fault::OutcomeUnknown.into()),
        }
        Ok(true)
    }
    /// Poll every original active MQ once, starting at a rotating cursor. One
    /// stalled search cannot prevent other searches/results/deadlines progressing.
    pub fn poll<'s, 'b, 'c, 'cs, 'p>(
        &mut self,
        cx: &mut Context<'_>,
        vpn: &mut Vpn<'id, 's, 'b, 'c, 'cs, 'p>,
        observe: &mut impl FnMut(Event<'id, 'regex>),
    ) -> Poll<Result<(), Error>> {
        if !Arc::ptr_eq(&vpn.clock(), &self.clock) {
            return Poll::Ready(Err(Fault::InvalidInput.into()));
        }
        let mut changed = false;
        for _ in 0..self.slots.len() {
            let i = self.cursor;
            self.cursor = (self.cursor + 1) % self.slots.len();
            let Some(mut entry) = self.slots[i].take() else {
                continue;
            };
            let result = self.turn(&mut entry, cx, vpn, observe);
            let gone = entry.done && result.as_ref().is_ok_and(|done| *done);
            if !gone {
                self.slots[i] = Some(entry);
            }
            match result {
                Ok(progress) => changed |= progress,
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        let at = self
            .slots
            .iter()
            .flatten()
            .filter(|e| !e.done)
            .map(|e| e.hard)
            .min();
        if self.alarm_at != at {
            self.alarm = at.map(|t| Box::pin(tokio::time::sleep_until(t)));
            self.alarm_at = at;
        }
        if self
            .alarm
            .as_mut()
            .is_some_and(|alarm| alarm.as_mut().poll(cx).is_ready())
        {
            cx.waker().wake_by_ref();
        }
        if changed {
            cx.waker().wake_by_ref();
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
    /// Stop and close every original Search independently without a clock read,
    /// then retire original pure work. Return the first error after trying all
    /// slots; preserve every actual End/native/coordinator error in the observer.
    pub fn close_all<'s, 'b, 'c, 'cs, 'p>(
        &mut self,
        vpn: &mut Vpn<'id, 's, 'b, 'c, 'cs, 'p>,
        observe: &mut impl FnMut(Event<'id, 'regex>),
    ) -> Result<Report, Error> {
        self.stopping = true;
        self.alarm = None;
        self.alarm_at = None;
        let mut first = None;
        for i in 0..self.slots.len() {
            let Some(mut entry) = self.slots[i].take() else {
                continue;
            };
            Self::emit_failure(&mut entry, Fault::Cancelled, &mut self.report, observe);
            match Self::close_entry(&mut entry, &mut self.report, observe) {
                Ok(()) => match Self::settle(&mut entry, vpn, &mut self.report, observe) {
                    Ok(true) => {}
                    Ok(false) => self.slots[i] = Some(entry),
                    Err(e) => {
                        self.slots[i] = Some(entry);
                        if first.is_none() {
                            first = Some(e);
                        }
                    }
                },
                Err(e) => {
                    self.report.cleanup_errors = self.report.cleanup_errors.saturating_add(1);
                    self.slots[i] = Some(entry);
                    if first.is_none() {
                        first = Some(e);
                    }
                }
            }
        }
        if let Some(error) = first {
            return Err(error);
        }
        if self.pending() != 0 {
            return Err(Fault::OutcomeUnknown.into());
        }
        Ok(self.report)
    }
}
