//! Actual marked-store generation reservations. Only8B public highwater is
//! stored. This neither reads a key nor claims an in-memory value is durable.
use gnunet_snapshot_host::{
    backend::{self, Namespace},
    worker::{self, Worker},
};
use gnunet_transport::monotime::Span;
use gnunet_types::Error as Fault;
use std::time::Duration;
use std::{
    path::Path,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::time::Instant;
use zeroize::Zeroizing;
/// Actual storage/protocol cause, retaining unknown exposure and cleanup facts.
#[derive(Debug)]
pub enum Error {
    /// Invalid original binding, exhausted counter or malformed public body.
    Protocol(Fault),
    /// Original actual shared store failure with independent cleanup.
    Storage(Arc<backend::Failure>),
    /// Actual worker creation OS failure.
    Worker(std::io::Error),
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Protocol(e) => e.fmt(f),
            Self::Storage(e) => e.fmt(f),
            Self::Worker(e) => e.fmt(f),
        }
    }
}
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Protocol(e) => Some(e),
            Self::Storage(e) => Some(e.as_ref()),
            Self::Worker(e) => Some(e),
        }
    }
}
impl From<Fault> for Error {
    fn from(e: Fault) -> Self {
        Self::Protocol(e)
    }
}
/// Independently allocated range consumer. Their numeric intervals never
/// overlap, and a genuine result for one purpose cannot authorize the other.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Purpose {
    /// Official FLOW sender_time anti-replay scalar.
    Flow,
    /// Official DV LEARN/BOX material authentication monotime.
    Dv,
}
/// Actual admitted original highwater operation; not a commit proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// One own-address generation, preserving the original stamp semantics.
    Stamp(u64),
    /// Exclusive inclusive interval for exactly one consumer.
    Range {
        /// Independently allocated consumer; never reassigned on completion.
        purpose: Purpose,
        /// Exact inclusive endpoints written as a durable upper bound.
        span: Span,
    },
}
impl Kind {
    fn upper(self) -> u64 {
        match self {
            Self::Stamp(value) => value,
            Self::Range { span, .. } => span.last(),
        }
    }
}
/// Original actual disk request, not a successful reservation or signature.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Request {
    job: worker::Job,
    kind: Kind,
    expires: u64,
    hard: Instant,
}
impl Request {
    /// Exact admitted purpose/value, never inferred from a current caller.
    pub const fn kind(&self) -> Kind {
        self.kind
    }
    /// Original finite canonical target, unchanged while IO is pending.
    pub const fn expires(&self) -> u64 {
        self.expires
    }
    /// Original finite native target. IO cannot be forcibly canceled by it.
    pub const fn hard(&self) -> Instant {
        self.hard
    }
}
/// Actual matching successful original file+directory commit/readback for one
/// own-address stamp. Private constructors require the real worker receipt.
pub struct CommittedReservation {
    request: Request,
    stamp: u64,
    generation: u64,
}
impl CommittedReservation {
    /// Actually durably consumed public generation value; never reused.
    pub const fn stamp(&self) -> u64 {
        self.stamp
    }
    /// Original real request; no unrelated effect may acquire this result.
    pub fn request(&self) -> &Request {
        &self.request
    }
    /// Actual backend generation, not an attempted-write count.
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}
/// Actual durably reserved exclusive numeric interval. This owner is not Clone:
/// consumers retain the original receipt while linearly burning its numbers.
/// A late/expired result remains durably consumed and grants no replacement job.
pub struct CommittedRange {
    request: Request,
    purpose: Purpose,
    span: Span,
    generation: u64,
}
impl CommittedRange {
    /// Actual original independently allocated consumer.
    pub const fn purpose(&self) -> Purpose {
        self.purpose
    }
    /// Inclusive interval whose upper bound was actually durably committed.
    pub const fn span(&self) -> Span {
        self.span
    }
    /// Exact original disk request, including immutable finite targets.
    pub fn request(&self) -> &Request {
        &self.request
    }
    /// Actual backend generation of the matching commit.
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}
/// Typed actual completion; the sole worker owner routes the original purpose.
pub enum Completion {
    /// One original own-address stamp.
    Stamp(CommittedReservation),
    /// One independently allocated FLOW or DV interval.
    Range(CommittedRange),
}
impl Completion {
    /// Original worker identity/purpose and unchanged targets.
    pub fn request(&self) -> &Request {
        match self {
            Self::Stamp(c) => c.request(),
            Self::Range(c) => c.request(),
        }
    }
    /// Actual durable backend generation, never admission count.
    pub fn generation(&self) -> u64 {
        match self {
            Self::Stamp(c) => c.generation(),
            Self::Range(c) => c.generation(),
        }
    }
}
/// One explicit bounded writer, one pending actual reservation, no key cache.
pub struct Reservations {
    worker: Worker,
    highwater: u64,
    generation: u64,
    pending: Option<Request>,
    failed: bool,
}
fn body(stamp: u64) -> Result<Zeroizing<Vec<u8>>, Fault> {
    let mut out = Vec::new();
    out.try_reserve_exact(8).map_err(|_| Fault::Capacity)?;
    out.extend_from_slice(&stamp.to_be_bytes());
    Ok(Zeroizing::new(out))
}
impl Reservations {
    /// Actual production startup after UID/GID setup, before any network owner.
    /// Only a brand-new or matching marked private Rust directory is accepted.
    /// Existing C/foreign/unmarked stores are never adopted or migrated.
    pub fn open(path: &Path) -> Result<Self, Error> {
        let (mut store, loaded) = backend::Store::open(
            Namespace::Transport,
            path,
            backend::Limits { body_bytes: 8 },
        )
        .map_err(|e| Error::Storage(Arc::new(e)))?;
        if loaded.namespace() != Namespace::Transport {
            return Err(Fault::Authentication.into());
        }
        let mut generation = loaded.generation();
        let new = loaded.created_directory();
        let bytes = loaded.into_body();
        let highwater = if generation == 0 {
            if !new || !bytes.is_empty() {
                return Err(Fault::Malformed.into());
            }
            let committed = store.commit(0, body(0)?).map_err(Error::Storage)?;
            if committed.namespace() != Namespace::Transport || committed.generation() != 1 {
                return Err(Fault::Stale.into());
            }
            generation = committed.generation();
            0
        } else {
            let value =
                u64::from_be_bytes(bytes.as_slice().try_into().map_err(|_| Fault::Malformed)?);
            if value == u64::MAX {
                return Err(Fault::Overflow.into());
            }
            value
        };
        let worker = Worker::start(store).map_err(Error::Worker)?;
        Ok(Self {
            worker,
            highwater,
            generation,
            pending: None,
            failed: false,
        })
    }
    /// True only when this one actual writer can admit a new original effect.
    /// It is not a statement about any previously attempted write's result.
    pub fn is_idle(&self) -> bool {
        !self.failed && self.pending.is_none()
    }
    fn admit(&mut self, kind: Kind, expires: u64, hard: Instant) -> Result<Request, Error> {
        if self.failed {
            return Err(Fault::OutcomeUnknown.into());
        }
        if self.pending.is_some() {
            return Err(Fault::WouldBlock.into());
        }
        if expires == 0 || expires == u64::MAX || hard <= Instant::now() {
            return Err(Fault::Deadline.into());
        }
        let job = self
            .worker
            .submit(self.generation, body(kind.upper())?)
            .map_err(|(e, _body)| Error::Protocol(e))?;
        let request = Request {
            job,
            kind,
            expires,
            hard,
        };
        self.pending = Some(request.clone());
        Ok(request)
    }
    /// Reserve one actual original stamp. Queue admission grants no durability.
    pub fn request(&mut self, minimum: u64, expires: u64, hard: Instant) -> Result<Request, Error> {
        let stamp = self
            .highwater
            .checked_add(1)
            .map(|n| n.max(minimum))
            .filter(|n| *n != u64::MAX)
            .ok_or(Fault::Overflow)?;
        self.admit(Kind::Stamp(stamp), expires, hard)
    }
    /// Persist an exclusive numeric time horizon, not a temporal capability.
    /// first=max(actualUTC,oldDurable+1); last=first+width-1. The actual receipt
    /// arrives only after the original worker's durable upper-bound commit.
    /// Production policy requires at least one minute to avoid per-tick fsync.
    pub fn request_range(
        &mut self,
        purpose: Purpose,
        actual_utc: u64,
        horizon: Duration,
        expires: u64,
        hard: Instant,
    ) -> Result<Request, Error> {
        if actual_utc == 0 || actual_utc == u64::MAX {
            return Err(Fault::InvalidInput.into());
        }
        let width = u64::try_from(horizon.as_micros()).map_err(|_| Fault::Overflow)?;
        if !(60_000_000..=86_400_000_000).contains(&width) {
            return Err(Fault::InvalidInput.into());
        }
        let first = self
            .highwater
            .checked_add(1)
            .ok_or(Fault::Overflow)?
            .max(actual_utc);
        let last = first.checked_add(width - 1).ok_or(Fault::Overflow)?;
        let span = Span::checked(first, last)?;
        self.admit(Kind::Range { purpose, span }, expires, hard)
    }
    fn complete(&mut self, completion: worker::Completion) -> Result<Completion, Error> {
        let request = self.pending.take().ok_or(Fault::Stale)?;
        let (job, result) = completion.into_parts();
        if job != request.job || job.namespace() != Namespace::Transport {
            self.failed = true;
            return Err(Fault::Stale.into());
        }
        let committed = match result {
            Ok(c) => c,
            Err(e) => {
                self.failed = true;
                return Err(Error::Storage(e));
            }
        };
        let next = self.generation.checked_add(1).ok_or(Fault::Overflow)?;
        if committed.namespace() != Namespace::Transport || committed.generation() != next {
            self.failed = true;
            return Err(Fault::Stale.into());
        }
        self.highwater = request.kind.upper();
        self.generation = next;
        Ok(match request.kind {
            Kind::Stamp(stamp) => Completion::Stamp(CommittedReservation {
                request,
                stamp,
                generation: next,
            }),
            Kind::Range { purpose, span } => Completion::Range(CommittedRange {
                request,
                purpose,
                span,
                generation: next,
            }),
        })
    }
    /// Poll only real original worker completion. A late committed reservation
    /// remains durably consumed even when its original caller must discard it.
    /// No clock sample, crypto/key access or success fabrication occurs here.
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<Option<Completion>, Error>> {
        match self.worker.poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                self.failed = true;
                Poll::Ready(Err(e.into()))
            }
            Poll::Ready(Ok(Some(c))) => Poll::Ready(self.complete(c).map(Some)),
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(None)),
        }
    }
    /// Stop admission without abandoning the original already-admitted IO.
    pub fn begin_stop(&mut self) {
        self.worker.request_stop();
    }
    /// Drain actual original completion then join. In-progress OS fsync/rename
    /// duration is not claimed cancellable by a socket/native deadline.
    pub async fn shutdown(&mut self) -> Result<worker::Stopped, Error> {
        let mut completion = None;
        let stopped = self
            .worker
            .shutdown(|c| completion = Some(c))
            .await
            .map_err(Error::Protocol)?;
        if let Some(c) = completion {
            let _consumed = self.complete(c)?;
        }
        if stopped.namespace != Namespace::Transport || stopped.generation != self.generation {
            return Err(Fault::Stale.into());
        }
        if let Some(error) = &stopped.failure {
            return Err(Error::Storage(error.clone()));
        }
        Ok(stopped)
    }
}
