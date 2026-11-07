//! Official burst orchestration on existing FLOW/communicator ownership. HELLO
//! hints and measured RTTs never install a direct route or authenticate a peer.
use super::*;
use crate::engine::dv_bridge::Source;
use gnunet_nat::burst::BurstSync;
use gnunet_wire::official::{AbsoluteTime, RelativeTime, communicator::StartBurst};
/// Official daemon's fixed burst completion timeout, in microseconds.
pub const COMMAND_TIMEOUT: u64 = 60_000_000;
/// Bounded local policy; the wire and communicator timeout are unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Policy {
    enabled: bool,
    lifetime: RelativeTime,
}
impl Policy {
    /// Bound the entire original FLOW→lookup→delay→command operation. The
    /// command has at most the official60s and never outlives this original.
    pub fn checked(enabled: bool, lifetime: RelativeTime) -> Result<Self, Error> {
        if lifetime.as_micros() == 0 || lifetime.is_forever() {
            return Err(Error::InvalidInput);
        }
        Ok(Self { enabled, lifetime })
    }
    /// Actual configured USE_BURST_NAT value, without an execution claim.
    pub const fn enabled(self) -> bool {
        self.enabled
    }
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            enabled: false,
            lifetime: RelativeTime::from_micros(120_000_000),
        }
    }
}
/// Exact original Engine allocation and checked burst serial, absent on wire.
#[derive(Clone, Debug)]
pub struct Id {
    instance: Arc<()>,
    serial: u64,
}
impl PartialEq for Id {
    fn eq(&self, other: &Self) -> bool {
        self.serial == other.serial && Arc::ptr_eq(&self.instance, &other.instance)
    }
}
impl Eq for Id {}
/// Actual local stage; Enqueued makes no whole-write or traversal assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// Awaiting a real original HELLO-derived literal-IP hint.
    Lookup,
    /// Awaiting the actual util readiness delay under original bounds.
    Delay,
    /// Standard1253 admitted to the original selected communicator output.
    Enqueued,
    /// Original deadline passed; native selected MQ must physically retire.
    Closing,
}
/// Immutable original demand/selected-owner view, without raw candidate bytes.
#[derive(Clone, Debug)]
pub struct Request {
    /// Exact original Engine/job allocation.
    pub id: Id,
    /// Claimed target from an accepted original FLOW.
    pub peer: PeerId,
    /// Original local request deadline; never renewed by lookup or retries.
    pub until: MonoInstant,
    /// Original absolute bound, possibly shortened by actual HELLO expiration.
    pub expires: AbsoluteTime,
    /// Actual stage of this original request.
    pub stage: Stage,
    /// Original scheduled start, after the actual util readiness delay.
    pub starts: Option<MonoInstant>,
    /// Only this actual communicator may finish/close the admitted command.
    pub selected: Option<ClientId>,
    /// Fixed command timeout capped by original request lifetime.
    pub command_until: Option<MonoInstant>,
}
/// Actual local terminal cause; none asserts successful NAT traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum End {
    /// The original selected communicator sent its real1254 callback.
    Finished,
    /// Its real physical native MQ closed before a matching callback.
    Closed,
    /// Original request or command deadline expired; an admitted command only
    /// completes retirement after its selected native MQ physically closes.
    Deadline,
    /// Original DV source/path retired while still preparing a command.
    SourceLost,
    /// A real directly validated queue appeared before command admission.
    DirectAvailable,
    /// Real HELLO enumeration completed without an eligible literal-IP hint.
    NoAddress,
    /// The same target's subsequent unsynchronized FLOW cancelled its delay.
    Cancelled,
}
/// One retained actual terminal fact. Taking it grants no route/signature/ACK.
#[derive(Clone, Debug)]
pub struct Outcome {
    /// Original complete demand and, if admitted, actual selected owner.
    pub original: Request,
    /// Actual terminal cause, separate from native-delivery assurance.
    pub reason: End,
}
struct Path {
    source: Source,
    peer: PeerId,
    rtt: u64,
    until: u64,
    retry: u64,
}
struct Task {
    request: Request,
    source: Source,
    path_until: u64,
    rtt: u64,
    delay: u64,
    address: Vec<u8>,
}
pub(super) struct Book {
    policy: Policy,
    maximum: usize,
    serial: u64,
    paths: Vec<Path>,
    task: Option<Task>,
    outcome: Option<Outcome>,
}
impl Book {
    pub(super) fn new(maximum: usize) -> Self {
        Self {
            policy: Policy::default(),
            maximum,
            serial: 0,
            paths: Vec::new(),
            task: None,
            outcome: None,
        }
    }
}
impl Engine {
    /// Configure before the first burst demand. Default-off embeddings have no
    /// implicit provider, task, socket or private communicator fallback.
    pub fn configure_burst(&mut self, policy: Policy) -> Result<(), Error> {
        if self.burst.serial != 0 || self.burst.task.is_some() {
            return Err(Error::NotReady);
        }
        if policy.enabled {
            self.burst
                .paths
                .try_reserve_exact(self.burst.maximum.saturating_sub(self.burst.paths.len()))
                .map_err(|_| Error::Capacity)?;
        }
        self.burst.policy = policy;
        Ok(())
    }
    /// Supply an actual measured confirmed DV path RTT, tied to the original
    /// current source and its fixed remaining native validity by the host.
    /// This port supplies synchronization evidence only, not a direct route.
    pub fn burst_dv_path(
        &mut self,
        source: &Source,
        peer: PeerId,
        rtt: gnunet_types::Duration,
        remaining: gnunet_types::Duration,
        times: Times,
    ) -> Result<(), Error> {
        self.validate_times(times)?;
        if !self.dv_source_accepting() || self.dv_current_source() != Some(source) {
            return Err(Error::Stale);
        }
        if peer == self.identity || rtt.0 == u64::MAX || remaining.0 == 0 || remaining.0 == u64::MAX
        {
            return Err(Error::InvalidInput);
        }
        let until = times
            .monotonic_after(RelativeTime::from_micros(remaining.0))?
            .0;
        let current = self.dv_current_source().cloned();
        self.burst.paths.retain(|path| {
            path.until > times.monotonic().0 && current.as_ref() == Some(&path.source)
        });
        if let Some(path) = self.burst.paths.iter_mut().find(|p| p.peer == peer) {
            path.source = source.clone();
            path.rtt = rtt.0;
            path.until = until;
        } else {
            if self.burst.paths.len() == self.burst.maximum {
                return Err(Error::Capacity);
            }
            self.burst
                .paths
                .try_reserve_exact(self.burst.maximum.saturating_sub(self.burst.paths.len()))
                .map_err(|_| Error::Capacity)?;
            self.burst.paths.push(Path {
                source: source.clone(),
                peer,
                rtt: rtt.0,
                until,
                retry: 0,
            });
        }
        Ok(())
    }
    /// Current original demand, retained across every host Pending/backpressure.
    pub fn burst_request(&self) -> Option<&Request> {
        self.burst.task.as_ref().map(|t| &t.request)
    }
    /// Take the retained original actual outcome once; a bounded terminal slot
    /// backpressures creation instead of overwriting an unobserved result.
    pub fn take_burst_outcome(&mut self) -> Option<Outcome> {
        self.burst.outcome.take()
    }
    fn burst_has_direct(&self, peer: PeerId, now: u64) -> bool {
        self.routes
            .iter()
            .any(|r| r.description.peer == peer && r.valid_until > now)
    }
    fn burst_finish(&mut self, reason: End) {
        if let Some(task) = self.burst.task.take() {
            if let Some(path) = self
                .burst
                .paths
                .iter_mut()
                .find(|p| p.peer == task.request.peer)
            {
                path.retry = self.last_monotonic.saturating_add(1_000_000);
            }
            self.burst.outcome = Some(Outcome {
                original: task.request,
                reason,
            });
        }
    }
    /// Actual outgoing synchronization metadata. An unknown DV estimate stays
    /// FOREVER; membership/connectivity never manufactures a measured RTT.
    pub(super) fn burst_flow_status(&self, peer: PeerId, now: u64) -> (u64, bool) {
        if !self.dv_source_accepting() {
            return (u64::MAX, false);
        }
        let local = self
            .burst
            .paths
            .iter()
            .find(|path| {
                path.peer == peer
                    && path.until > now
                    && self.dv_current_source() == Some(&path.source)
            })
            .map(|path| path.rtt)
            .unwrap_or(u64::MAX);
        let remote = self
            .peers
            .iter()
            .find(|p| p.id == peer)
            .map(|p| p.remote_burst_rtt)
            .unwrap_or(u64::MAX);
        let ready = BurstSync {
            rtt_micros: remote,
            ready: 0,
        }
        .delay(local)
        .is_some();
        (local, ready)
    }
    pub(super) fn burst_flow(
        &mut self,
        peer: PeerId,
        flow: Flow,
        times: Times,
    ) -> Result<(), Error> {
        if !self.burst.policy.enabled || !self.dv_source_accepting() {
            return Ok(());
        }
        let now = times.monotonic().0;
        if self.burst.task.is_some() {
            return Ok(());
        }
        if self.burst.outcome.is_some()
            || self.burst_has_direct(peer, now)
            || !self
                .clients
                .iter()
                .any(|c| c.role == Role::Communicator && c.can_burst)
        {
            return Ok(());
        }
        let Some(path) = self.burst.paths.iter().find(|p| {
            p.peer == peer
                && p.until > now
                && p.retry <= now
                && self.dv_current_source() == Some(&p.source)
        }) else {
            return Ok(());
        };
        let Some(delay) = (BurstSync {
            rtt_micros: flow.rtt,
            ready: i32::from(flow.sync_ready),
        })
        .delay(path.rtt) else {
            return Ok(());
        };
        let until = times
            .monotonic_after(self.burst.policy.lifetime)?
            .0
            .min(path.until);
        if delay >= until.saturating_sub(now) {
            return Ok(());
        }
        let serial = self.burst.serial.checked_add(1).ok_or(Error::Overflow)?;
        let request = Request {
            id: Id {
                instance: self.instance.clone(),
                serial,
            },
            peer,
            until: MonoInstant(until),
            expires: times.absolute_after(self.burst.policy.lifetime)?,
            stage: Stage::Lookup,
            starts: None,
            selected: None,
            command_until: None,
        };
        self.burst.task = Some(Task {
            request,
            source: path.source.clone(),
            path_until: path.until,
            rtt: flow.rtt,
            delay,
            address: Vec::new(),
        });
        self.burst.serial = serial;
        Ok(())
    }
    /// Offer only a real original HELLO-derived literal-IP hint through the
    /// actual host port. Its expiration can shorten, never extend, this demand.
    pub fn burst_candidate(
        &mut self,
        id: &Id,
        address: &[u8],
        expiration: AbsoluteTime,
        times: Times,
    ) -> Result<(), Error> {
        self.validate_times(times)?;
        self.burst_maintenance(times)?;
        let task = self
            .burst
            .task
            .as_mut()
            .filter(|t| t.request.id == *id)
            .ok_or(Error::Stale)?;
        if task.request.stage != Stage::Lookup {
            return Err(Error::Stale);
        }
        if address.is_empty() || address.len() > 45 || address.contains(&0) {
            return Err(Error::Malformed);
        }
        if expiration <= times.absolute() {
            return Err(Error::Deadline);
        }
        let starts = times.monotonic_after(RelativeTime::from_micros(task.delay))?;
        if starts >= task.request.until {
            return Err(Error::Deadline);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(address.len())
            .map_err(|_| Error::Capacity)?;
        bytes.extend_from_slice(address);
        task.address = bytes;
        task.request.starts = Some(starts);
        task.request.expires = task.request.expires.min(expiration);
        task.request.stage = Stage::Delay;
        Ok(())
    }
    /// Cancel only preparation of the exact original. An admitted/partial
    /// command must retire through its real selected native MQ instead.
    pub fn cancel_burst(&mut self, id: &Id, reason: End) -> Result<(), Error> {
        let task = self
            .burst
            .task
            .as_ref()
            .filter(|t| t.request.id == *id)
            .ok_or(Error::Stale)?;
        if matches!(task.request.stage, Stage::Enqueued | Stage::Closing) {
            return Err(Error::WouldBlock);
        }
        if matches!(reason, End::Finished | End::Closed) {
            return Err(Error::PermissionDenied);
        }
        self.burst_finish(reason);
        Ok(())
    }
    pub(super) fn burst_maintenance(&mut self, times: Times) -> Result<(), Error> {
        let Some(task) = &self.burst.task else {
            return Ok(());
        };
        let command = matches!(task.request.stage, Stage::Enqueued | Stage::Closing);
        let expired = times.monotonic() >= task.request.until
            || times.absolute() >= task.request.expires
            || task
                .request
                .command_until
                .is_some_and(|until| times.monotonic() >= until);
        if command {
            if expired {
                self.burst.task.as_mut().ok_or(Error::Stale)?.request.stage = Stage::Closing;
            }
        } else if expired || times.monotonic().0 >= task.path_until {
            self.burst_finish(End::Deadline);
        } else if !self.dv_source_accepting() || self.dv_current_source() != Some(&task.source) {
            self.burst_finish(End::SourceLost);
        } else if self.burst_has_direct(task.request.peer, times.monotonic().0) {
            self.burst_finish(End::DirectAvailable);
        }
        Ok(())
    }
    /// Drive the original finite delay and enqueue standard1253 to exactly one
    /// actually registered can_burst communicator. Enqueue is no remote ACK.
    pub fn drive_burst(&mut self, times: Times) -> Result<bool, Error> {
        self.time_at(times)?;
        self.burst_maintenance(times)?;
        let Some(task) = &self.burst.task else {
            return Ok(false);
        };
        if task.request.stage != Stage::Delay
            || task.request.starts.is_none_or(|at| at > times.monotonic())
        {
            return Ok(false);
        }
        let Some(owner) = self
            .clients
            .iter()
            .find(|c| c.role == Role::Communicator && c.can_burst)
            .map(|c| c.id.clone())
        else {
            return Ok(false);
        };
        if self.output.len() >= self.limits.messages + self.limits.control_messages {
            return Ok(false);
        }
        let command = StartBurst {
            peer: task.request.peer.0,
            rtt_micros: task.rtt,
            address: &task.address,
        };
        let mut bytes = Vec::new();
        let length = command.encoded_len()?;
        bytes
            .try_reserve_exact(length)
            .map_err(|_| Error::Capacity)?;
        bytes.resize(length, 0);
        command.encode(&mut bytes)?;
        let until = times
            .monotonic_after(RelativeTime::from_micros(COMMAND_TIMEOUT))?
            .min(task.request.until);
        self.emit(owner.clone(), bytes)?;
        let task = self.burst.task.as_mut().ok_or(Error::Stale)?;
        task.request.stage = Stage::Enqueued;
        task.request.selected = Some(owner);
        task.request.command_until = Some(until);
        Ok(true)
    }
    /// Require real selected-MQ retirement for an expired admitted command.
    /// The native host closes its actual source before releasing this debt.
    pub fn expire_burst_command(&mut self, id: &Id) -> Result<(), Error> {
        let task = self
            .burst
            .task
            .as_mut()
            .filter(|t| t.request.id == *id)
            .ok_or(Error::Stale)?;
        if task.request.selected.is_none() {
            return Err(Error::NotReady);
        }
        task.request.stage = Stage::Closing;
        Ok(())
    }
    pub(super) fn burst_finished(&mut self, owner: &ClientId) -> bool {
        if self.burst.task.as_ref().is_some_and(|task| {
            task.request.stage == Stage::Enqueued && task.request.selected.as_ref() == Some(owner)
        }) {
            self.burst_finish(End::Finished);
            true
        } else {
            false
        }
    }
    pub(super) fn burst_closed(&mut self, owner: &ClientId) {
        if let Some(task) = &self.burst.task
            && task.request.selected.as_ref() == Some(owner)
        {
            let reason = if task.request.stage == Stage::Closing {
                End::Deadline
            } else {
                End::Closed
            };
            self.burst_finish(reason);
        }
    }
}
