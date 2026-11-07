//! Same original TRANSPORT command, public utility scan and actual socket transfer.
use super::*;
use gnunet_nat_burst_host::{self as native, Burst, ReadyParameters, SelectedSocket, Selection};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::AbsoluteTime;
pub use native::Instance;
pub use native::wire::Endian;
use std::{future::Future, net::IpAddr, pin::Pin, time::Duration};
use tokio::time::Sleep;

/// Local finite resource/ABI choices; no private protocol negotiation.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// Whole original command lifetime, positive and at most the official60s.
    pub lifetime: Duration,
    /// Existing public utility descriptor, pacing and I/O bounds.
    pub scan: native::Limits,
    /// Explicit ABI of received native unsigned probe fields. Selection uses
    /// actual recvfrom endpoints, never this unauthenticated advertised port.
    pub remote_order: Endian,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            lifetime: Duration::from_secs(60),
            scan: native::Limits::default(),
            remote_order: local_order(),
        }
    }
}
fn local_order() -> Endian {
    if cfg!(target_endian = "little") {
        Endian::Little
    } else {
        Endian::Big
    }
}
/// Original local facts, never authentication or proof of NAT reachability.
#[derive(Debug)]
pub struct Report {
    /// Diagnostic serial, scoped to this original communicator/MQ.
    pub serial: u64,
    /// Original requested public peer, not the unauthenticated probe assertion.
    pub peer: PeerId,
    /// Original actual finite RTT argument; no new readiness evidence is invented.
    pub rtt_us: u64,
    /// Actual utility terminal cause, including original native I/O error.
    pub cause: native::Cause,
    /// Actual local scan operations.
    pub scan: native::Report,
    /// Non-probe datagrams consumed before a scan socket became an endpoint.
    /// These were not authenticated/delivered and follow the utility's boundary.
    pub ignored_scan_datagrams: u64,
    /// Original selected socket became a normal bounded endpoint candidate.
    pub candidate_installed: bool,
    /// Actual queued1254, when present. Query Communicator::publication for its
    /// original whole-write/retirement state; enqueue is not a callback receipt.
    pub completion: Option<Publication>,
}
/// Owned original failure, independent of actual descriptor retirement.
#[derive(Debug)]
pub struct Failure {
    /// Original command and actual utility outcome.
    pub report: Report,
    /// Independent admission/native-hard failure after or before selection.
    pub admission: Option<Error>,
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "UDP original burst {} {:?}; admission={:?}",
            self.report.serial, self.report.cause, self.admission
        )
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.report.cause {
            native::Cause::Clock(error) => Some(error),
            native::Cause::Io { error, .. } => Some(error),
            _ => self
                .admission
                .as_ref()
                .map(|error| error as &dyn std::error::Error),
        }
    }
}
pub(super) enum Probe {
    Unrelated,
    /// Same original default receipt is retained until the original initial
    /// probe actually writes, never copied or treated as a completed callback.
    Pending,
    Selected,
}
struct Active<'id> {
    serial: u64,
    peer: PeerId,
    rtt: u64,
    remote: SocketAddr,
    default: usize,
    until: AbsoluteTime,
    hard: Instant,
    alarm: Pin<Box<Sleep>>,
    input_released: bool,
    owner: Option<Burst<'id>>,
    selection: Option<Selection<'id>>,
    end: Option<native::End<'id>>,
    ignored: u64,
}
pub(super) struct Port<'id> {
    instance: &'id Instance,
    clock: Arc<dyn RuntimeClock>,
    pub(super) policy: Policy,
    serial: u64,
    active: Option<Active<'id>>,
    report: Option<Report>,
    cancelled: Option<Report>,
    fence: Option<u64>,
}
impl<'id> Port<'id> {
    fn report(mut active: Active<'id>, installed: bool, completion: Option<Publication>) -> Report {
        if let Some(owner) = active.owner.take() {
            active.end = owner.into_end();
        }
        let (cause, scan) = active.end.take().map_or(
            (native::Cause::Cancelled, native::Report::default()),
            |end| (end.cause, end.report),
        );
        Report {
            serial: active.serial,
            peer: active.peer,
            rtt_us: active.rtt,
            cause,
            scan,
            ignored_scan_datagrams: active.ignored,
            candidate_installed: installed,
            completion,
        }
    }
    fn fail(&mut self, admission: Option<Error>) -> Option<Failure> {
        self.active.take().map(|active| Failure {
            report: Self::report(active, false, None),
            admission,
        })
    }
    fn cancel(&mut self) {
        if let Some(active) = self.active.take() {
            // At most one completed original report and one newly observed,
            // not-started command can coexist. Keep both bounded original ends.
            let report = Self::report(active, false, None);
            if self.report.is_none() {
                self.report = Some(report);
            } else {
                self.cancelled = Some(report);
            }
        }
    }
}
impl<'id> Communicator<'id> {
    /// Enable the real public burst path before any original registration bytes
    /// are written. Instance and clock are supplied by the actual foreground.
    /// The single-peer Driver remains an explicitly non-burst embedding.
    pub fn enable_burst(
        &mut self,
        instance: &'id Instance,
        clock: Arc<dyn RuntimeClock>,
        policy: Policy,
    ) -> Result<(), super::Failure> {
        if self.closing
            || self.closed
            || self.burst.is_some()
            || self.registered
            || self.io.queued_frames() != 0
            || self.effects.len() != 1
            || !matches!(
                self.effects.front().map(|effect| effect.origin),
                Some(Origin::Register)
            )
            || policy.lifetime.is_zero()
            || policy.lifetime > Duration::from_secs(60)
            || !(1..=512).contains(&policy.scan.sockets)
            || !(1..=1024).contains(&policy.scan.io_budget)
            || policy.scan.send_interval.is_zero()
            || policy.scan.socket_lifetime.is_zero()
        {
            return Err(Error::InvalidInput.into());
        }
        let slots = self
            .defaults
            .checked_add(self.configuration.endpoints)
            .ok_or(Error::Overflow)?;
        self.sockets
            .try_reserve_exact(slots - self.sockets.len())
            .map_err(|_| Error::Capacity)?;
        self.completions
            .try_reserve_exact(slots - self.completions.len())
            .map_err(|_| Error::Capacity)?;
        let frame = frozen(16, |out| transport::register(true, out))?;
        // Same original registration envelope/sequence, still wholly unexposed.
        self.effects.front_mut().ok_or(Error::Stale)?.frame = frame;
        self.burst = Some(Port {
            instance,
            clock,
            policy,
            serial: 0,
            active: None,
            report: None,
            cancelled: None,
            fence: None,
        });
        Ok(())
    }
    /// Move one actual local terminal report. Completion remains an original
    /// publication ticket, and neither selection nor1254 authenticates the peer.
    pub fn take_burst_report(&mut self) -> Option<Report> {
        self.burst
            .as_mut()
            .and_then(|port| port.report.take().or_else(|| port.cancelled.take()))
    }
    pub(super) fn cancel_burst(&mut self) {
        if let Some(port) = &mut self.burst {
            port.cancel();
        }
    }
    pub(super) fn transport_lost_burst(&mut self) {
        if let Some(port) = &mut self.burst {
            port.cancel();
            // The original report retains its exact publication ticket; a new
            // source must never wait on or complete this retired MQ fence.
            port.fence = None;
        }
    }
    pub(super) fn burst_native_guard(&mut self, cx: &mut Context<'_>) -> Option<super::Failure> {
        let port = self.burst.as_mut()?;
        let active = port.active.as_mut()?;
        if let Some(owner) = &mut active.owner {
            owner.poll_native_guard(cx);
        }
        let expired = Instant::now() >= active.hard || active.alarm.as_mut().poll(cx).is_ready();
        if expired {
            let failure = port.fail(Some(Error::Deadline))?;
            self.close();
            Some(super::Failure::Burst(failure))
        } else {
            None
        }
    }
    pub(super) fn burst_command(
        &mut self,
        peer: PeerId,
        rtt: u64,
        ip: IpAddr,
    ) -> Result<Option<Activity>, super::Failure> {
        let port = self.burst.as_ref().ok_or(Error::Unsupported)?;
        if let Some(active) = &port.active {
            if active.input_released
                || active.peer != peer
                || active.rtt != rtt
                || active.remote.ip() != ip
            {
                return Err(Error::Conflict.into());
            }
        } else {
            // Reserve native hard before any canonical clock, native metadata,
            // utility allocation or wait on output/previous completion capacity.
            let hard = Instant::now()
                .checked_add(port.policy.lifetime)
                .ok_or(Error::Overflow)?;
            if peer == self.configuration.local || rtt == u64::MAX {
                return Err(Error::InvalidInput.into());
            }
            let default = self
                .sockets
                .iter()
                .take(self.defaults)
                .position(|socket| socket.local_address().is_ipv4() == ip.is_ipv4())
                .ok_or(Error::Unsupported)?;
            let remote = SocketAddr::new(ip, self.sockets[default].local_address().port());
            let sample = port.clock.sample()?;
            if Instant::now() >= hard {
                return Err(Error::Deadline.into());
            }
            let remaining =
                u64::try_from(hard.saturating_duration_since(Instant::now()).as_micros())
                    .map_err(|_| Error::Overflow)?;
            let until = AbsoluteTime::from_micros(
                sample
                    .now
                    .as_micros()
                    .checked_add(remaining)
                    .filter(|n| *n != u64::MAX)
                    .ok_or(Error::Overflow)?,
            );
            let serial = port.serial.checked_add(1).ok_or(Error::Overflow)?;
            let active = Active {
                serial,
                peer,
                rtt,
                remote,
                default,
                until,
                hard,
                alarm: Box::pin(tokio::time::sleep_until(hard.into())),
                input_released: false,
                owner: None,
                selection: None,
                end: None,
                ignored: 0,
            };
            let port = self.burst.as_mut().ok_or(Error::Stale)?;
            port.serial = serial;
            port.active = Some(active);
        }
        let port = self.burst.as_mut().ok_or(Error::Stale)?;
        if port.report.is_some()
            || port.cancelled.is_some()
            || port
                .fence
                .is_some_and(|sequence| sequence > self.written_effect)
        {
            return Ok(None);
        }
        port.fence = None;
        let active = port.active.as_mut().ok_or(Error::Stale)?;
        if Instant::now() >= active.hard {
            return Err(Error::Deadline.into());
        }
        if active.owner.is_none() {
            let default = self.sockets[active.default].shared()?;
            let parameters = ReadyParameters {
                remote: active.remote,
                public_peer: self.configuration.local,
                local_order: local_order(),
                remote_order: port.policy.remote_order,
                until: active.until,
                hard: active.hard,
            };
            active.owner = Some(
                Burst::start_ready(
                    port.instance,
                    default,
                    parameters,
                    port.policy.scan,
                    port.clock.clone(),
                )
                .map_err(super::Failure::BurstStart)?,
            );
        }
        active.input_released = true;
        if !self.io.release_frame() {
            return Err(Error::Stale.into());
        }
        Ok(Some(Activity::Burst))
    }
    pub(super) fn burst_probe(
        &mut self,
        socket: usize,
        receipt: Receipt,
    ) -> Result<Probe, super::Failure> {
        let Some(port) = &mut self.burst else {
            return Ok(Probe::Unrelated);
        };
        if receipt.len() != native::wire::MESSAGE_BYTES {
            return Ok(Probe::Unrelated);
        }
        let Some(active) = &mut port.active else {
            return Ok(Probe::Unrelated);
        };
        if socket != active.default {
            return Ok(Probe::Unrelated);
        }
        if receipt.address().ip() != active.remote.ip() {
            return Ok(Probe::Unrelated);
        }
        let Some(owner) = &mut active.owner else {
            return Ok(Probe::Pending);
        };
        if owner.report().datagrams_written == 0 {
            return Ok(Probe::Pending);
        }
        let id = owner.default_socket();
        let selected = owner
            .on_datagram(id, receipt.address(), self.sockets[socket].bytes(receipt)?)
            .map_err(super::Failure::BurstStart)?;
        if selected == native::Disposition::Selected {
            self.sockets[socket].consume(receipt)?;
            Ok(Probe::Selected)
        } else {
            Ok(Probe::Unrelated)
        }
    }
    pub(super) fn burst_step(
        &mut self,
        cx: &mut Context<'_>,
        now: u64,
        classify: &mut impl FnMut(SocketAddr) -> io::Result<u32>,
    ) -> Result<Option<Activity>, super::Failure> {
        let Some(port) = &mut self.burst else {
            return Ok(None);
        };
        let Some(active) = &mut port.active else {
            return Ok(None);
        };
        if !active.input_released {
            return Ok(None);
        }
        if let Some(owner) = &mut active.owner {
            let mut ignored = 0u64;
            match owner.poll_step(cx, |event| {
                if matches!(event, native::Event::Datagram { .. }) {
                    ignored = ignored.saturating_add(1);
                }
            }) {
                Poll::Pending => {
                    active.ignored = active.ignored.saturating_add(ignored);
                    return Ok(None);
                }
                Poll::Ready(native::Step::Progress) => {
                    active.ignored = active.ignored.saturating_add(ignored);
                    return Ok(Some(Activity::Burst));
                }
                Poll::Ready(native::Step::Stopped) => {
                    active.ignored = active.ignored.saturating_add(ignored);
                    let failure = port.fail(None).ok_or(Error::Stale)?;
                    return Err(super::Failure::Burst(failure));
                }
                Poll::Ready(native::Step::Selected) => {
                    active.ignored = active.ignored.saturating_add(ignored);
                    active.selection = owner.take_selection();
                    active.end = active.owner.take().and_then(Burst::into_end);
                }
            }
        }
        if !self.room(2, 256) {
            return Ok(None);
        }
        let port = self.burst.as_mut().ok_or(Error::Stale)?;
        let active = port.active.as_mut().ok_or(Error::Stale)?;
        if Instant::now() >= active.hard {
            return Err(Error::Deadline.into());
        }
        let selected = active.selection.as_ref().ok_or(Error::Stale)?;
        let peer = active.peer;
        let target = selected.remote;
        let socket = if selected.id.is_default() {
            active.default
        } else {
            self.sockets
                .iter()
                .enumerate()
                .skip(self.defaults)
                .find_map(|(index, socket)| {
                    (socket.is_closed()
                        && self.completions[index].is_none()
                        && !self
                            .endpoints
                            .iter()
                            .any(|entry| entry.as_ref().is_some_and(|entry| entry.socket == index)))
                    .then_some(index)
                })
                .unwrap_or(self.sockets.len())
        };
        if socket >= self.defaults + self.configuration.endpoints {
            return Err(Error::Capacity.into());
        }
        if self.endpoints.iter().flatten().any(|entry| {
            entry.peer == peer && entry.target == target && entry.socket == socket && entry.retiring
        }) {
            // Keep the actual selected socket and original burst deadline until
            // maintenance finishes the old sender generation. It cannot supply
            // a live queue or a successful publication fence for this burst.
            return Ok(None);
        }
        let existing = self.endpoints.iter().any(|entry| {
            entry.as_ref().is_some_and(|entry| {
                entry.peer == peer && entry.target == target && entry.socket == socket
            })
        });
        if !existing && !self.endpoints.iter().any(Option::is_none) {
            return Ok(None);
        }
        let finish = frozen(4, transport::burst_finished)?;
        // All fixed sidecar Vec capacity was reserved by enable_burst. The new
        // RX owner is constructed before queue/publication admission.
        let selected = self
            .burst
            .as_mut()
            .and_then(|port| port.active.as_mut())
            .and_then(|active| active.selection.take())
            .ok_or(Error::Stale)?;
        match selected.socket {
            SelectedSocket::Default(_clone) => {}
            SelectedSocket::Scan(actual) => {
                let adopted = DatagramSocket::adopt(actual)?;
                if socket == self.sockets.len() {
                    self.sockets.push(adopted);
                    self.completions.push(None);
                } else {
                    self.sockets[socket] = adopted;
                }
            }
        }
        let plan = self.prepare_endpoint_on(peer, target, socket, now, classify)?;
        if Instant::now()
            >= self
                .burst
                .as_ref()
                .and_then(|port| port.active.as_ref())
                .ok_or(Error::Stale)?
                .hard
        {
            return Err(Error::Deadline.into());
        }
        match plan {
            EndpointAdmission::New(plan) => self.commit_endpoint(plan)?,
            EndpointAdmission::Live => {}
            // The pre-adoption gate above checked this exact tuple. No caller
            // can mutate it during this synchronous ownership transfer.
            EndpointAdmission::Retiring => return Err(Error::Stale.into()),
        }
        self.push(finish, Origin::Effect)?;
        let completion = Publication {
            source: self.publication_source.clone(),
            sequence: self.next_effect,
        };
        let port = self.burst.as_mut().ok_or(Error::Stale)?;
        port.fence = Some(self.next_effect);
        let active = port.active.take().ok_or(Error::Stale)?;
        port.report = Some(Port::report(active, true, Some(completion)));
        Ok(Some(Activity::Burst))
    }
}
