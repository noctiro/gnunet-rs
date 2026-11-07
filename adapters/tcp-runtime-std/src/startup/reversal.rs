//! One caller-polled owner for original port-zero CREATEs and clear prototypes.
//! Clear probes select expected signers; only the existing Session verifies them.
use super::publication;
use crate::{AdmissionError, Reversal, addresses, preamble};
use gnunet_crypto::{EddsaPublicKey, Entropy};
use gnunet_nat_client_host as nat;
use gnunet_service_runtime::{
    clock::{ClockSubscription, RuntimeClock},
    connection::Connection,
};
use gnunet_tcp_communicator_core::{registry::REVERSAL_US, session::PROTO_US};
use gnunet_tcp_communicator_host::{Clock, CreateId, HandshakeBounds, SessionId};
use gnunet_types::{Error, Rejected};
use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

/// Read-only diagnostic identity of a genuinely canceled original NAT write.
/// These numbers cannot reconstruct the original tokens or authorize new work.
#[derive(Debug)]
pub struct CancelledWrite {
    /// Original NAT allocation diagnostic pair.
    pub session: (u64, u64),
    /// Original actually attached MQ diagnostic pair.
    pub epoch: (u64, u64),
    /// Original canceled FIFO operation diagnostic pair.
    pub write: (u64, u64),
    /// Actual zero-exposure submission returned by cancel_write.
    pub submission: nat::Submission,
}
/// Actual source/prototype observations, without a claim of authenticated delivery.
#[derive(Debug)]
pub enum Event {
    /// The original NAT MQ accepted the request locally. Written remains separate.
    NatAdmitted {
        /// Expected signer, still unauthenticated.
        peer: EddsaPublicKey,
        /// Original reversal IP.
        remote: Ipv4Addr,
    },
    /// The real original Session reached Established for the expected same-IP sender.
    Authenticated {
        /// Verified initial signer.
        peer: EddsaPublicKey,
        /// Original pending IP.
        remote: Ipv4Addr,
    },
    /// Original pending metadata retired; no remote cancellation receipt is implied.
    ParentRetired {
        /// Expected peer of this exact original request.
        peer: EddsaPublicKey,
        /// Original pending IP.
        remote: Ipv4Addr,
        /// Exact local retirement reason.
        reason: Error,
        /// Original NAT submission refusal, independent of local retirement.
        original: Option<addresses::Failure>,
        /// Independent original NAT cancellation refusal.
        cancellation: Option<addresses::Failure>,
        /// Actual unexposed-write cancellation, separate from expiration or ACK.
        cancelled: Option<CancelledWrite>,
    },
    /// Positive bytes consumed from an original preamble socket.
    Read(preamble::ReadProgress),
    /// Actual native connect/probe-write progress, never peer authentication.
    ConnectBack(preamble::ConnectProgress),
    /// An original socket entered the existing Session/manager.
    Handoff {
        /// Original Session admission or its real failure.
        result: Result<SessionId, Failure>,
        /// Actual preamble bytes consumed before handoff/refusal.
        read: usize,
        /// Actual clear-probe bytes written before handoff/refusal.
        written: usize,
    },
    /// Clock-free retirement of an unfinished original prototype.
    PrototypeRetired {
        /// Actual retained bytes from the same socket.
        read: usize,
        /// Actual clear-probe bytes written on the same socket.
        written: usize,
    },
    /// Actual isolated original failure.
    Failed(Failure),
}
/// Typed original failures retained by the foreground diagnostic observer.
#[derive(Debug)]
pub enum Failure {
    /// Actual local clock, bounds, registry or capacity refusal.
    Core(Error),
    /// Actual preamble/connect/write error and original byte counts.
    Prototype(preamble::Failure),
    /// Actual Session/native admission failure after socket disposal.
    Admission(AdmissionError),
    /// Actual original registration error.
    Nat(addresses::Failure),
    /// Independent connect/probe refusal and original callback-release refusal.
    PrototypeAndNat {
        /// Original native/prototype cause with exact transferred byte counts.
        prototype: preamble::Failure,
        /// Independent failure releasing that original callback.
        notification: addresses::Failure,
    },
}
impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TCP reversal: {self:?}")
    }
}
impl std::error::Error for Failure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Prototype(e) => Some(e),
            Self::Admission(e) => Some(e),
            Self::Nat(e) => Some(e),
            Self::PrototypeAndNat { prototype, .. } => Some(prototype),
            Self::Core(_) => None,
        }
    }
}
pub(super) struct Step {
    pub created: Option<(CreateId, bool)>,
    pub event: Event,
    pub fatal: Option<Error>,
}
impl Step {
    fn event(event: Event) -> Self {
        Self {
            created: None,
            event,
            fatal: None,
        }
    }
}
/// A bounded terminal observation, not a claim that unfinished requests succeeded.
#[derive(Debug)]
pub(super) struct Retirement {
    pub pending_create: Option<CreateId>,
    pub waiting: usize,
    pub accepted: usize,
    pub connectback: usize,
    pub read: usize,
    pub written: usize,
}
impl std::fmt::Display for Retirement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "original TCP reversal retirement: CREATE={:?}, pending={}, accepted={}, connectback={}, read={}, written={}",
            self.pending_create,
            self.waiting,
            self.accepted,
            self.connectback,
            self.read,
            self.written
        )
    }
}
impl std::error::Error for Retirement {}
struct Pending<'nat, 'pool> {
    original: Reversal<'pool>,
    create: Option<CreateId>,
    proof: Option<addresses::ReverseWrite<'nat, 'pool>>,
    until: u64,
    hard: Instant,
    alarm: Pin<Box<Sleep>>,
}
struct Accepted {
    admission: preamble::Admission,
    remote: SocketAddr,
}
struct ConnectBack {
    original: preamble::ConnectBack,
    remote: SocketAddr,
}
/// Fixed metadata/native owner sets. All payload buffers remain in the one Pool.
pub(super) struct Driver<'nat, 'pool> {
    source: Arc<dyn RuntimeClock>,
    subscription: Option<Box<dyn ClockSubscription>>,
    revision: u64,
    pending: Vec<Pending<'nat, 'pool>>,
    accepted: Vec<Accepted>,
    connectback: Vec<ConnectBack>,
    capacity: usize,
    cursor: usize,
    closing: bool,
}
impl<'nat, 'pool> Driver<'nat, 'pool> {
    pub(super) fn new(source: Arc<dyn RuntimeClock>, capacity: usize) -> Result<Self, Error> {
        if capacity == 0 || capacity > 4096 {
            return Err(Error::Capacity);
        }
        let mut pending = Vec::new();
        let mut accepted = Vec::new();
        let mut connectback = Vec::new();
        pending
            .try_reserve_exact(capacity)
            .map_err(|_| Error::Capacity)?;
        accepted
            .try_reserve_exact(capacity)
            .map_err(|_| Error::Capacity)?;
        connectback
            .try_reserve_exact(capacity)
            .map_err(|_| Error::Capacity)?;
        let subscription = source.subscribe()?;
        Ok(Self {
            source,
            subscription: Some(subscription),
            revision: 0,
            pending,
            accepted,
            connectback,
            capacity,
            cursor: 0,
            closing: false,
        })
    }
    pub(super) fn retirement(&self) -> Retirement {
        Retirement {
            pending_create: self.pending.iter().find_map(|row| row.create.clone()),
            waiting: self.pending.len(),
            accepted: self.accepted.len(),
            connectback: self.connectback.len(),
            read: self
                .accepted
                .iter()
                .map(|row| row.admission.retained())
                .sum(),
            written: self
                .connectback
                .iter()
                .map(|row| row.original.written())
                .sum(),
        }
    }
    /// Retire old TRANSPORT callbacks without replaying an unsubmitted reversal.
    /// Existing admitted NAT writes keep their exact original source and target;
    /// peer sockets/prototypes and their native bounds are not reconstructed.
    pub(super) fn transport_lost(
        &mut self,
        owner: &mut publication::Owner<'nat, 'pool, '_>,
        mut observe: impl FnMut(CreateId, bool, Option<Error>),
    ) {
        let mut index = 0;
        while index < self.pending.len() {
            if self.pending[index].proof.is_none() {
                let row = self.pending.remove(index);
                let cancellation = owner.pool_mut().map_or(Some(Error::Closed), |pool| {
                    if pool.reversal_live(&row.original) {
                        pool.cancel_reversal(&row.original).err()
                    } else {
                        None
                    }
                });
                if let Some(create) = row.create {
                    observe(create, false, cancellation);
                }
            } else {
                if let Some(create) = self.pending[index].create.take() {
                    observe(create, true, None);
                }
                index += 1;
            }
        }
    }
    pub(super) fn has_create(&self) -> bool {
        self.pending.iter().any(|r| r.create.is_some())
    }
    pub(super) fn can_accept(&self) -> bool {
        !self.closing && self.accepted.len() + self.connectback.len() < self.capacity
    }
    pub(super) fn is_empty(&self) -> bool {
        self.pending.is_empty() && self.accepted.is_empty() && self.connectback.is_empty()
    }
    fn sample(&mut self, cx: &mut Context<'_>) -> Result<u64, Error> {
        let subscription = self.subscription.as_mut().ok_or(Error::Closed)?;
        if let Poll::Ready(result) = subscription.poll_changed(cx, self.revision) {
            self.revision = result?.revision;
        }
        let sample = self.source.sample()?;
        self.revision = sample.revision;
        if let Poll::Ready(result) = subscription.poll_changed(cx, self.revision) {
            self.revision = result?.revision;
            cx.waker().wake_by_ref();
        }
        Ok(sample.now.as_micros())
    }
    fn bounds_at(now: u64, micros: u64, first: Instant) -> Result<preamble::Bounds, Error> {
        let until = now
            .checked_add(micros)
            .filter(|v| *v != u64::MAX)
            .ok_or(Error::Overflow)?;
        let hard = first
            .checked_add(Duration::from_micros(micros))
            .ok_or(Error::Overflow)?;
        preamble::Bounds::new(until, hard)
    }
    pub(super) fn start(
        &mut self,
        pool: &mut crate::Pool<'pool>,
        id: CreateId,
        peer: EddsaPublicKey,
        address: &[u8],
    ) -> Result<(), Rejected<CreateId>> {
        let admitted = (|| {
            if self.closing {
                return Err(Error::Closed);
            }
            if self.pending.len() == self.capacity {
                return Err(Error::Capacity);
            }
            let first = Instant::now();
            let now = self.source.sample()?.now.as_micros();
            let bounds = Self::bounds_at(now, 30_000_000, first)?;
            let original = pool.plan_reversal(peer, address)?;
            Ok((original, bounds))
        })();
        match admitted {
            Ok((original, bounds)) => {
                self.pending.push(Pending {
                    original,
                    create: Some(id),
                    proof: None,
                    until: bounds.until(),
                    hard: bounds.hard(),
                    alarm: Box::pin(tokio::time::sleep_until(bounds.hard())),
                });
                Ok(())
            }
            Err(reason) => Err(Rejected { reason, value: id }),
        }
    }
    pub(super) fn accept(
        &mut self,
        connection: Connection,
        remote: SocketAddr,
    ) -> Result<(), Error> {
        if !self.can_accept() {
            return Err(Error::Capacity);
        }
        let first = Instant::now();
        let bounds = Self::bounds_at(self.source.sample()?.now.as_micros(), PROTO_US, first)?;
        self.accepted.push(Accepted {
            admission: preamble::Admission::new(connection, bounds),
            remote,
        });
        Ok(())
    }
    fn retire_parent(
        &mut self,
        index: usize,
        owner: &mut publication::Owner<'nat, 'pool, '_>,
        cx: &mut Context<'_>,
        reason: Error,
        original: Option<addresses::Failure>,
    ) -> Step {
        let row = self.pending.remove(index);
        let mut cancelled = None;
        let mut cancellation = None;
        if let Some(proof) = &row.proof
            && let Some(published) = owner.published_mut()
        {
            match published.cancel_unexposed_reverse(cx, proof) {
                Ok(end) => {
                    cancelled = end.map(|end| CancelledWrite {
                        session: proof.session().diagnostic(),
                        epoch: proof.epoch().diagnostic(),
                        write: end.write.diagnostic(),
                        submission: end.submission,
                    })
                }
                Err(addresses::Failure::Protocol(Error::Stale | Error::Closed)) => {}
                Err(error) => cancellation = Some(error),
            }
        }
        if let Some(pool) = owner.pool_mut()
            && pool.reversal_live(&row.original)
            && let Err(error) = pool.cancel_reversal(&row.original)
        {
            cancellation.get_or_insert(addresses::Failure::Protocol(error));
        }
        Step {
            created: row.create.map(|id| (id, false)),
            event: Event::ParentRetired {
                peer: row.original.peer(),
                remote: row.original.remote(),
                reason,
                original,
                cancellation,
                cancelled,
            },
            fatal: None,
        }
    }
    /// Original native guards are checked before any canonical clock or IO class.
    pub(super) fn guard(
        &mut self,
        cx: &mut Context<'_>,
        owner: &mut publication::Owner<'nat, 'pool, '_>,
    ) -> Option<Step> {
        for index in 0..self.pending.len() {
            let row = &mut self.pending[index];
            if Instant::now() >= row.hard || row.alarm.as_mut().poll(cx).is_ready() {
                return Some(self.retire_parent(index, owner, cx, Error::Deadline, None));
            }
        }
        for index in 0..self.accepted.len() {
            if let Some(error) = self.accepted[index].admission.poll_native_guard(cx) {
                self.accepted.remove(index);
                return Some(Step::event(Event::Failed(Failure::Prototype(error))));
            }
        }
        for index in 0..self.connectback.len() {
            if let Some(error) = self.connectback[index].original.poll_native_guard(cx) {
                self.connectback.remove(index);
                return Some(Step::event(Event::Failed(Failure::Prototype(error))));
            }
        }
        None
    }
    fn stopped(
        &mut self,
        cx: &mut Context<'_>,
        owner: &mut publication::Owner<'nat, 'pool, '_>,
    ) -> Option<Step> {
        self.closing = true;
        self.subscription = None;
        if !self.pending.is_empty() {
            return Some(self.retire_parent(0, owner, cx, Error::Closed, None));
        }
        if let Some(mut row) = self.accepted.pop() {
            let read = row.admission.retained();
            row.admission.abort();
            return Some(Step::event(Event::PrototypeRetired { read, written: 0 }));
        }
        if let Some(mut row) = self.connectback.pop() {
            let written = row.original.written();
            row.original.abort();
            return Some(Step::event(Event::PrototypeRetired { read: 0, written }));
        }
        None
    }
    fn failure(error: Error) -> Step {
        Step {
            created: None,
            event: Event::Failed(Failure::Core(error)),
            fatal: Some(error),
        }
    }
    /// Poll each bounded class fairly; native IO stays owned across Pending turns.
    pub(super) fn poll(
        &mut self,
        cx: &mut Context<'_>,
        owner: &mut publication::Owner<'nat, 'pool, '_>,
        clock: &mut impl Clock,
        entropy: &mut impl Entropy,
        local: EddsaPublicKey,
        allow: bool,
    ) -> Poll<Step> {
        if !allow || self.closing {
            return self.stopped(cx, owner).map_or(Poll::Pending, Poll::Ready);
        }
        if let Some(step) = self.guard(cx, owner) {
            return Poll::Ready(step);
        }
        let now = match self.sample(cx) {
            Ok(now) => now,
            Err(error) => {
                self.closing = true;
                return Poll::Ready(Self::failure(error));
            }
        };
        for offset in 0..4 {
            let class = (self.cursor + offset) % 4;
            let ready = match class {
                0 => self.pending_step(cx, owner, now),
                1 => self.accepted_step(cx, owner, clock, entropy, now),
                2 => self.connect_step(cx, owner, clock, entropy, now),
                _ => self.callback_step(cx, owner, local, now),
            };
            if let Some(step) = ready {
                self.cursor = (class + 1) % 4;
                return Poll::Ready(step);
            }
        }
        Poll::Pending
    }
    fn pending_step(
        &mut self,
        cx: &mut Context<'_>,
        owner: &mut publication::Owner<'nat, 'pool, '_>,
        now: u64,
    ) -> Option<Step> {
        for index in 0..self.pending.len() {
            if now >= self.pending[index].until || Instant::now() >= self.pending[index].hard {
                return Some(self.retire_parent(index, owner, cx, Error::Deadline, None));
            }
            if self.pending[index].proof.is_some() {
                let completed = owner
                    .pool_mut()
                    .ok_or(Error::Closed)
                    .and_then(|pool| pool.complete_reversal(&self.pending[index].original, now));
                match completed {
                    Ok(true) => {
                        let row = self.pending.remove(index);
                        return Some(Step::event(Event::Authenticated {
                            peer: row.original.peer(),
                            remote: row.original.remote(),
                        }));
                    }
                    Ok(false) => {}
                    Err(Error::Stale | Error::Deadline) => {
                        return Some(self.retire_parent(index, owner, cx, Error::Deadline, None));
                    }
                    Err(error) => return Some(Self::failure(error)),
                }
                continue;
            }
            // Reserve the native ten-second bound BEFORE the actual side effect.
            let hard = match Instant::now().checked_add(Duration::from_micros(REVERSAL_US)) {
                Some(h) => h,
                None => return Some(Self::failure(Error::Overflow)),
            };
            if now.checked_add(REVERSAL_US).is_none_or(|v| v == u64::MAX) {
                return Some(Self::failure(Error::Overflow));
            }
            let row = &self.pending[index];
            let receipt = owner
                .published_mut()
                .ok_or(addresses::Failure::Protocol(Error::Closed))
                .and_then(|published| published.request_reversal(cx, &row.original, row.until));
            match receipt {
                Ok(proof) => {
                    let applied = owner.pool_mut().ok_or(Error::Closed).and_then(|pool| {
                        pool.reversal_admitted(&mut self.pending[index].original, &proof)
                    });
                    let row = &mut self.pending[index];
                    row.until = proof
                        .admitted_at()
                        .checked_add(REVERSAL_US)
                        .unwrap_or(row.until);
                    row.hard = hard;
                    row.alarm.as_mut().reset(hard);
                    row.proof = Some(proof);
                    let event = match applied {
                        Ok(()) => Event::NatAdmitted {
                            peer: row.original.peer(),
                            remote: row.original.remote(),
                        },
                        Err(error) => Event::Failed(Failure::Core(error)),
                    };
                    return Some(Step {
                        created: row.create.take().map(|id| (id, true)),
                        event,
                        fatal: applied.err(),
                    });
                }
                Err(addresses::Failure::Protocol(
                    Error::NotReady | Error::WouldBlock | Error::Capacity,
                )) => {}
                Err(error) => {
                    return Some(self.retire_parent(
                        index,
                        owner,
                        cx,
                        Error::Unavailable,
                        Some(error),
                    ));
                }
            }
        }
        None
    }
    fn callback_step(
        &mut self,
        cx: &mut Context<'_>,
        owner: &mut publication::Owner<'nat, 'pool, '_>,
        local: EddsaPublicKey,
        now: u64,
    ) -> Option<Step> {
        if !self.can_accept() {
            return None;
        }
        let published = owner.published_mut()?;
        let callback = match published.reverse_notification(cx) {
            Ok(Some(callback)) => callback,
            Ok(None) => return None,
            Err(addresses::Failure::Protocol(
                Error::Closed | Error::WouldBlock | Error::NotReady,
            )) => return None,
            Err(error) => return Some(Step::event(Event::Failed(Failure::Nat(error)))),
        };
        let bounds = match Self::bounds_at(now, PROTO_US, Instant::now()) {
            Ok(bounds) => bounds,
            Err(error) => return Some(Self::failure(error)),
        };
        let remote = SocketAddr::V4(callback.remote());
        let connected = preamble::ConnectBack::begin(remote, local, bounds, now);
        // The original callback is released only after that exact attempt was
        // admitted or definitely refused; no future reconstructs it on retry.
        let released = published.release_reverse(&callback);
        match (connected, released) {
            (Ok(original), Ok(())) => {
                self.connectback.push(ConnectBack { original, remote });
                cx.waker().wake_by_ref();
                None
            }
            (Ok(mut original), Err(error)) => {
                original.abort();
                Some(Step::event(Event::Failed(Failure::Nat(error))))
            }
            (Err(error), Ok(())) => Some(Step::event(Event::Failed(Failure::Prototype(error)))),
            (Err(prototype), Err(notification)) => {
                Some(Step::event(Event::Failed(Failure::PrototypeAndNat {
                    prototype,
                    notification,
                })))
            }
        }
    }
    fn handoff(
        result: Result<SessionId, Failure>,
        read: usize,
        written: usize,
        fatal: Option<Error>,
    ) -> Step {
        Step {
            created: None,
            event: Event::Handoff {
                result,
                read,
                written,
            },
            fatal,
        }
    }
    fn accepted_step(
        &mut self,
        cx: &mut Context<'_>,
        owner: &mut publication::Owner<'nat, 'pool, '_>,
        clock: &mut impl Clock,
        entropy: &mut impl Entropy,
        now: u64,
    ) -> Option<Step> {
        for index in 0..self.accepted.len() {
            let progress = match self.accepted[index].admission.poll(cx, now) {
                Poll::Pending => continue,
                Poll::Ready(result) => result,
            };
            let progress = match progress {
                Ok(progress) => progress,
                Err(error) => {
                    self.accepted.remove(index);
                    return Some(Step::event(Event::Failed(Failure::Prototype(error))));
                }
            };
            if !progress.complete {
                return Some(Step::event(Event::Read(progress)));
            }
            let row = self.accepted.remove(index);
            return self.accepted_handoff(row, progress.retained, owner, clock, entropy, now);
        }
        None
    }
    fn accepted_handoff(
        &mut self,
        row: Accepted,
        read: usize,
        owner: &mut publication::Owner<'nat, 'pool, '_>,
        clock: &mut impl Clock,
        entropy: &mut impl Entropy,
        now: u64,
    ) -> Option<Step> {
        let (connection, preamble, bounds) = match row.admission.into_parts(now) {
            Ok(parts) => parts,
            Err(rejected) => {
                drop(rejected.value);
                return Some(Self::handoff(
                    Err(Failure::Core(rejected.reason)),
                    read,
                    0,
                    None,
                ));
            }
        };
        let bound = match HandshakeBounds::new(bounds.until(), bounds.hard()) {
            Ok(bound) => bound,
            Err(error) => {
                drop(connection);
                return Some(Self::handoff(Err(Failure::Core(error)), read, 0, None));
            }
        };
        if let Err(error) = bound.check(now) {
            drop(connection);
            return Some(Self::handoff(Err(Failure::Core(error)), read, 0, None));
        }
        let time = match clock.read() {
            Ok(time) => time,
            Err(error) => {
                drop(connection);
                return Some(Self::handoff(
                    Err(Failure::Core(error)),
                    read,
                    0,
                    Some(error),
                ));
            }
        };
        let address = format!("tcp-{}", row.remote);
        let Some(pool) = owner.pool_mut() else {
            drop(connection);
            return Some(Self::handoff(
                Err(Failure::Core(Error::Closed)),
                read,
                0,
                Some(Error::Closed),
            ));
        };
        let admission = match preamble {
            preamble::Preamble::Handshake { prefix } => pool.accepted_prefixed(
                connection,
                address.as_bytes(),
                &prefix,
                bound,
                time,
                entropy,
            ),
            preamble::Preamble::Probe { claimed } => {
                let parent = self.pending.iter().find(|r| {
                    r.proof.is_some()
                        && r.original.peer() == claimed
                        && std::net::IpAddr::V4(r.original.remote()) == row.remote.ip()
                        && now < r.until
                        && Instant::now() < r.hard
                });
                if let Some(parent) = parent {
                    pool.reversal_probe(
                        &parent.original,
                        connection,
                        address.as_bytes(),
                        bound,
                        time,
                        entropy,
                    )
                } else {
                    drop(connection);
                    Err(AdmissionError::Core(Error::NotFound))
                }
            }
        };
        Some(Self::handoff(
            admission.map_err(Failure::Admission),
            read,
            0,
            None,
        ))
    }
    fn connect_step(
        &mut self,
        cx: &mut Context<'_>,
        owner: &mut publication::Owner<'nat, 'pool, '_>,
        clock: &mut impl Clock,
        entropy: &mut impl Entropy,
        now: u64,
    ) -> Option<Step> {
        for index in 0..self.connectback.len() {
            let progress = match self.connectback[index].original.poll(cx, now) {
                Poll::Pending => continue,
                Poll::Ready(result) => result,
            };
            let progress = match progress {
                Ok(progress) => progress,
                Err(error) => {
                    self.connectback.remove(index);
                    return Some(Step::event(Event::Failed(Failure::Prototype(error))));
                }
            };
            if !matches!(
                progress,
                preamble::ConnectProgress::Written { complete: true, .. }
            ) {
                return Some(Step::event(Event::ConnectBack(progress)));
            }
            let row = self.connectback.remove(index);
            let written = row.original.written();
            let (connection, bounds) = match row.original.into_connection(now) {
                Ok(parts) => parts,
                Err(rejected) => {
                    drop(rejected.value);
                    return Some(Self::handoff(
                        Err(Failure::Core(rejected.reason)),
                        0,
                        written,
                        None,
                    ));
                }
            };
            let bound = match HandshakeBounds::new(bounds.until(), bounds.hard()) {
                Ok(bound) => bound,
                Err(error) => {
                    drop(connection);
                    return Some(Self::handoff(Err(Failure::Core(error)), 0, written, None));
                }
            };
            if let Err(error) = bound.check(now) {
                drop(connection);
                return Some(Self::handoff(Err(Failure::Core(error)), 0, written, None));
            }
            let time = match clock.read() {
                Ok(time) => time,
                Err(error) => {
                    drop(connection);
                    return Some(Self::handoff(
                        Err(Failure::Core(error)),
                        0,
                        written,
                        Some(error),
                    ));
                }
            };
            let address = format!("tcp-{}", row.remote);
            let admission = owner
                .pool_mut()
                .ok_or(AdmissionError::Core(Error::Closed))
                .and_then(|pool| {
                    pool.accepted_prefixed(
                        connection,
                        address.as_bytes(),
                        &[],
                        bound,
                        time,
                        entropy,
                    )
                });
            return Some(Self::handoff(
                admission.map_err(Failure::Admission),
                0,
                written,
                None,
            ));
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Setup;
    use gnunet_crypto::EddsaPrivateKey;
    use gnunet_service_runtime::clock::SystemClock;
    use gnunet_tcp_communicator_core::{
        registry::Slot,
        session::{Buffers, CIPHERTEXT_CAPACITY, CompletionSlot, Identity, KeyRing, Policy, Scope},
        wire,
    };
    use gnunet_tcp_communicator_host::{Capacity, ManagerCapacity};
    use std::{num::NonZeroUsize, task::Waker};
    use tokio::net::UnixStream;

    #[tokio::test(flavor = "current_thread")]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert the actual failed submission retires its original registry row and preserves its independent facts"
    )]
    async fn unavailable_nat_owner_preserves_the_cause_and_retires_the_planned_pool_row()
    -> Result<(), Box<dyn std::error::Error>> {
        let keys = KeyRing::from_seed([1; 32]);
        let peer = EddsaPrivateKey::from_seed([2; 32]).public_key();
        let remote = Ipv4Addr::new(192, 0, 2, 7);
        let address = b"tcp-192.0.2.7:0";
        let mut scope = Scope::new();
        let mut slots = [Slot::new(), Slot::new()];
        let mut receive = vec![0; wire::MAX_RECORD];
        let mut transmit = vec![0; CIPHERTEXT_CAPACITY];
        let mut plaintext = vec![0; wire::MAX_RECORD];
        let mut completions = (0..8)
            .map(|_| CompletionSlot::default())
            .collect::<Vec<_>>();
        let (peerstore, _peerstore_remote) = UnixStream::pair()?;
        let (transport, _transport_remote) = UnixStream::pair()?;
        let mut pool = crate::Pool::new(Setup {
            services: [
                Connection::from_unix(peerstore),
                Connection::from_unix(transport),
            ],
            identity: Identity::from_keys(&keys),
            scope: &mut scope,
            slots: &mut slots,
            buffers: vec![Buffers {
                receive: &mut receive,
                transmit: &mut transmit,
                plaintext: &mut plaintext,
                completions: &mut completions,
            }],
            policy: Policy::reference(NonZeroUsize::new(1).ok_or(Error::InvalidInput)?),
            ipc: Capacity {
                ipc_bytes: 65535,
                ipc_frames: 8,
                callbacks: 8,
            },
            capacity: ManagerCapacity {
                sessions: 1,
                pending_sends: 8,
                commands: 8,
            },
            disable_v6: false,
        })?;
        let original = pool.plan_reversal(peer, address)?;
        let original_id = original.id();
        assert!(pool.reversal_live(&original));
        // The real pool survives unsuccessful publication adoption. It has no
        // native NAT owner, so the production submission gate refuses Closed;
        // no CREATE capability, NAT write or authentication receipt is invented.
        let mut owner = publication::Owner::unpublished(pool);
        let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
        let now = clock.sample()?.now.as_micros();
        let mut driver = Driver::new(clock, 1)?;
        let bounds = Driver::bounds_at(now, 30_000_000, Instant::now())?;
        driver.pending.push(Pending {
            original,
            create: None,
            proof: None,
            until: bounds.until(),
            hard: bounds.hard(),
            alarm: Box::pin(tokio::time::sleep_until(bounds.hard())),
        });
        let mut cx = Context::from_waker(Waker::noop());
        let step = driver
            .pending_step(&mut cx, &mut owner, now)
            .ok_or(Error::NotReady)?;
        assert!(step.created.is_none());
        assert!(step.fatal.is_none());
        assert!(matches!(step.event, Event::ParentRetired {
            peer: actual_peer,
            remote: actual_remote,
            reason: Error::Unavailable,
            original: Some(addresses::Failure::Protocol(Error::Closed)),
            cancellation: None,
            cancelled: None,
        } if actual_peer == peer && actual_remote == remote));
        assert!(driver.pending.is_empty());
        // Reserving the same target again requires the first original registry
        // row to have retired, rather than merely dropping its diagnostic event.
        let pool = owner.pool_mut().ok_or(Error::Closed)?;
        let next = pool.plan_reversal(peer, address)?;
        assert_ne!(next.id(), original_id);
        pool.cancel_reversal(&next)?;
        Ok(())
    }
}
