//! Actual bounded REGEX announcement MQs; a local write is never publication.
use crate::Failure;
use gnunet_client_host::EndpointSource;
use gnunet_config::Configuration;
use gnunet_regex_client_host::{
    self as regex, Announcement, AnnouncementRequest, Deadlines, End, Instance, Job, Progress,
    RelativeTime,
};
use gnunet_service_runtime::clock::{Deadline, RuntimeClock};
use gnunet_types::{AbsoluteTime, Error as Fault};
use gnunet_vpn::{Address, Family, discovery::policy};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
const LOCAL: &[u8] = b"exit-rust";
const REFRESH_MICROS: u64 = 30 * 60 * 1_000_000;
#[derive(Debug)]
pub(super) struct Spec {
    pub family: Family,
    pub expression: Vec<u8>,
    pub compression: u16,
}
#[derive(Clone, Copy)]
pub(super) struct Options {
    send: Duration,
    lifetime: Duration,
    retry: Duration,
    native: regex::Limits,
}
pub(super) struct Definitions {
    pub rules: Vec<policy::Rule>,
    specs: Vec<Spec>,
    options: Options,
}
fn number(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(c.get(LOCAL, key)
        .map(|_| c.get_number(LOCAL, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn duration(c: &Configuration, key: &[u8], default: u64) -> Result<Duration, Failure> {
    let micros = c
        .get(LOCAL, key)
        .map(|_| c.get_time(LOCAL, key))
        .transpose()?
        .unwrap_or(default);
    let delay = Duration::from_micros(micros);
    if micros == 0 || micros == u64::MAX || std::time::Instant::now().checked_add(delay).is_none() {
        return Err("REGEX native lifetime/send/retry bound must be finite and nonzero".into());
    }
    Ok(delay)
}
impl Definitions {
    pub fn read(c: &Configuration, exit4: bool, exit6: bool) -> Result<Self, Failure> {
        if c.get(LOCAL, b"POLICY").is_some() || c.get(LOCAL, b"DEFAULT_ALLOW").is_some() {
            return Err("[exit-rust] POLICY/DEFAULT_ALLOW conflict with official Internet authorization; configure [exit] EXIT_RANGE_IPV4_POLICY/EXIT_RANGE_IPV6_POLICY".into());
        }
        let max_rules = number(c, b"REGEX_POLICY_RULES", 512)?;
        if !(1..=4096).contains(&max_rules) {
            return Err("REGEX_POLICY_RULES must be1..4096".into());
        }
        let send = duration(c, b"REGEX_SEND_TIMEOUT", 10_000_000)?;
        let lifetime = duration(c, b"REGEX_JOB_LIFETIME", 6 * 60 * 60 * 1_000_000)?;
        if lifetime < send {
            return Err("REGEX_JOB_LIFETIME is shorter than REGEX_SEND_TIMEOUT".into());
        }
        let retry = duration(c, b"REGEX_RECONNECT_DELAY", 1_000_000)?;
        let frame_bytes = number(c, b"REGEX_FRAME_BYTES", 65535)?;
        let native = regex::Limits {
            frame_bytes,
            io_slice_bytes: number(c, b"REGEX_IO_SLICE_BYTES", frame_bytes)?,
            ..regex::Limits::default()
        };
        if !(40..=65535).contains(&native.frame_bytes)
            || native.io_slice_bytes == 0
            || native.io_slice_bytes > native.frame_bytes
        {
            return Err("invalid bounded REGEX frame/I/O capacity".into());
        }
        let mut rules = Vec::new();
        let mut specs = Vec::new();
        specs.try_reserve_exact(2)?;
        for (enabled, family, key, compression) in [
            (exit4, Family::V4, b"EXIT_RANGE_IPV4_POLICY".as_slice(), 4),
            (exit6, Family::V6, b"EXIT_RANGE_IPV6_POLICY".as_slice(), 8),
        ] {
            if !enabled {
                continue;
            }
            let text = std::str::from_utf8(
                c.get(b"exit", key)
                    .ok_or("enabled Internet family requires its official EXIT_RANGE policy")?,
            )?;
            let count = text.bytes().filter(|b| *b == b';').count();
            if count > max_rules || rules.len().checked_add(count).is_none_or(|n| n > max_rules) {
                return Err("official EXIT policy exceeds REGEX_POLICY_RULES total bound".into());
            }
            let network = match family {
                Family::V4 => Address::V4([0; 4]),
                Family::V6 => Address::V6([0; 16]),
            };
            let seed = policy::Rule::prefix(network, 0, policy::Ports::Any)?;
            let start = rules.len();
            rules.try_reserve_exact(count)?;
            rules.resize(start + count, seed);
            let actual = policy::parse_into(family, text, &mut rules[start..])?;
            rules.truncate(start + actual);
            let Some(size) = policy::compiled_exit_len(family, text)? else {
                continue;
            };
            if size.checked_add(17).is_none_or(|n| n > native.frame_bytes) {
                return Err("official EXIT expression exceeds REGEX_FRAME_BYTES".into());
            }
            let mut expression = Vec::new();
            expression.try_reserve_exact(size)?;
            expression.resize(size, 0);
            if policy::compile_exit(family, text, &mut expression)? != Some(size) {
                return Err(
                    "official EXIT expression changed between measurement and output".into(),
                );
            }
            specs.push(Spec {
                family,
                expression,
                compression,
            });
        }
        Ok(Self {
            rules,
            specs,
            options: Options {
                send,
                lifetime,
                retry,
                native,
            },
        })
    }
}
#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Report {
    pub configured: usize,
    pub operations: u64,
    pub submitted: u64,
    pub ended: u64,
    pub cancelled: u64,
    pub active: usize,
}
impl std::fmt::Display for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "configured={} operations={} submitted={} ended={} cancelled={} active={}",
            self.configured,
            self.operations,
            self.submitted,
            self.ended,
            self.cancelled,
            self.active
        )
    }
}
#[derive(Debug)]
pub(super) enum Event<'id> {
    Started {
        family: Family,
        generation: u64,
        job: Job<'id>,
    },
    Native {
        family: Family,
        generation: u64,
        progress: Progress<'id>,
    },
    Cancelled {
        family: Family,
        generation: u64,
        end: End<'id>,
    },
}
struct Slot<'id> {
    job: Option<Announcement<'id>>,
    retry: Option<Pin<Box<Deadline>>>,
    generation: u64,
    submitted: bool,
}
impl Slot<'_> {
    fn new() -> Self {
        Self {
            job: None,
            retry: None,
            generation: 0,
            submitted: false,
        }
    }
}
/// Caller-driven owner, borrowing one stable external identity domain and the
/// same shared process CLIENT/Resolver source as the existing foreground.
pub(super) struct Owner<'cfg, 'id> {
    instance: &'id Instance,
    source: EndpointSource,
    clock: Arc<dyn RuntimeClock>,
    definitions: &'cfg Definitions,
    slots: [Slot<'id>; 2],
    enabled: bool,
    closed: bool,
    report: Report,
}
impl<'cfg, 'id> Owner<'cfg, 'id> {
    pub fn new(
        instance: &'id Instance,
        source: EndpointSource,
        definitions: &'cfg Definitions,
    ) -> Self {
        let clock = source.clock();
        Self {
            instance,
            source,
            clock,
            definitions,
            slots: std::array::from_fn(|_| Slot::new()),
            enabled: false,
            closed: false,
            report: Report {
                configured: definitions.specs.len(),
                ..Report::default()
            },
        }
    }
    /// Called only after genuine TUN/address/DAD readiness and actual CADET port
    /// writes. It starts no MQ until the owner is polled on the existing runtime.
    pub fn enable(&mut self) {
        if !self.closed {
            self.enabled = true;
        }
    }
    pub fn submitted(&self) -> bool {
        self.definitions.specs.is_empty()
            || (!self.closed
                && self.enabled
                && self.slots[..self.definitions.specs.len()]
                    .iter()
                    .all(|s| s.submitted))
    }
    pub fn report(&self) -> Report {
        self.report
    }
    fn target(now: AbsoluteTime, delay: Duration) -> Result<AbsoluteTime, Failure> {
        let micros = u64::try_from(delay.as_micros())?;
        now.as_micros()
            .checked_add(micros)
            .filter(|t| *t != u64::MAX)
            .map(AbsoluteTime::from_micros)
            .ok_or_else(|| Fault::Overflow.into())
    }
    fn poll_inner(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<bool, Failure>> {
        if self.closed || !self.enabled {
            return Poll::Pending;
        }
        let mut activity = false;
        for i in 0..self.definitions.specs.len() {
            if self.slots[i].job.is_none() {
                if let Some(retry) = self.slots[i].retry.as_mut() {
                    match retry.as_mut().poll(cx) {
                        Poll::Pending => continue,
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                        Poll::Ready(Ok(_)) => {
                            self.slots[i].retry = None;
                        }
                    }
                }
                let now = self.clock.sample()?.now;
                let options = self.definitions.options;
                let deadlines = Deadlines {
                    send_until: Self::target(now, options.send)?.as_micros(),
                    first_result_until: None,
                    until: Self::target(now, options.lifetime)?.as_micros(),
                };
                let spec = &self.definitions.specs[i];
                let generation = self.slots[i]
                    .generation
                    .checked_add(1)
                    .ok_or(Fault::Overflow)?;
                let job = Announcement::new(
                    self.instance,
                    self.source.duplicate()?,
                    AnnouncementRequest {
                        regex: &spec.expression,
                        compression: spec.compression,
                        refresh_delay: RelativeTime::from_micros(REFRESH_MICROS),
                    },
                    deadlines,
                    options.native,
                )?;
                observe(Event::Started {
                    family: spec.family,
                    generation,
                    job: job.job(),
                });
                self.slots[i].job = Some(job);
                self.slots[i].generation = generation;
                self.slots[i].submitted = false;
                self.report.operations = self.report.operations.saturating_add(1);
                self.report.active += 1;
                activity = true;
                continue;
            }
            let step = {
                let job = self.slots[i].job.as_mut().ok_or(Fault::Conflict)?;
                let mut driving = std::pin::pin!(job.drive(None));
                driving.as_mut().poll(cx)
            };
            match step {
                Poll::Pending => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e.into())),
                Poll::Ready(Ok(progress)) => {
                    activity = true;
                    let ended = matches!(&progress, Progress::Ended(_));
                    match &progress {
                        Progress::SourceLost { .. } => {
                            // The same finite registration survives; it has not
                            // yet been wholly written on its replacement MQ.
                            self.slots[i].submitted = false;
                        }
                        Progress::Submitted { .. } => {
                            self.slots[i].submitted = true;
                            self.report.submitted = self.report.submitted.saturating_add(1);
                        }
                        Progress::ResultReady { .. } => {
                            return Poll::Ready(
                                Err("announcement received a search RESULT".into()),
                            );
                        }
                        Progress::Closed => {
                            return Poll::Ready(Err(
                                "announcement lost its original ending receipt".into(),
                            ));
                        }
                        _ => {}
                    }
                    if !matches!(&progress, Progress::Activity { .. }) {
                        observe(Event::Native {
                            family: self.definitions.specs[i].family,
                            generation: self.slots[i].generation,
                            progress,
                        });
                    }
                    if ended {
                        self.slots[i].job = None;
                        self.slots[i].submitted = false;
                        self.report.ended = self.report.ended.saturating_add(1);
                        self.report.active = self.report.active.saturating_sub(1);
                        let target =
                            Self::target(self.clock.sample()?.now, self.definitions.options.retry)?;
                        self.slots[i].retry =
                            Some(Box::pin(Deadline::at(Arc::clone(&self.clock), target)?));
                    }
                }
            }
        }
        if activity {
            cx.waker().wake_by_ref();
            Poll::Ready(Ok(true))
        } else {
            Poll::Pending
        }
    }
    /// A fatal local clock/CLIENT error closes both original MQs before returning.
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        observe: &mut impl FnMut(Event<'id>),
    ) -> Poll<Result<bool, Failure>> {
        match self.poll_inner(cx, observe) {
            Poll::Ready(Err(e)) => {
                self.close(observe);
                Poll::Ready(Err(e))
            }
            value => value,
        }
    }
    /// Suspend visibility after a real configured source/port loses readiness.
    /// Restoring readiness starts new jobs; no old MQ or suffix is revived.
    pub fn pause(&mut self, observe: &mut impl FnMut(Event<'id>)) {
        self.enabled = false;
        for i in 0..self.definitions.specs.len() {
            self.slots[i].retry = None;
            if let Some(mut job) = self.slots[i].job.take()
                && let Some(end) = job.cancel()
            {
                self.report.cancelled = self.report.cancelled.saturating_add(1);
                observe(Event::Cancelled {
                    family: self.definitions.specs[i].family,
                    generation: self.slots[i].generation,
                    end,
                });
            }
            self.slots[i].submitted = false;
        }
        self.report.active = 0;
    }
    /// Independent physical cancellation, with no clock, Resolver or ACK wait.
    pub fn close(&mut self, observe: &mut impl FnMut(Event<'id>)) -> Report {
        if !self.closed {
            self.closed = true;
            self.pause(observe);
        }
        self.report
    }
}
impl Drop for Owner<'_, '_> {
    fn drop(&mut self) {
        for slot in &mut self.slots {
            if let Some(mut job) = slot.job.take() {
                let _closed = job.close();
            }
        }
    }
}
