//! Explicit owned native work. These contracts do not manufacture a provider.
use gnunet_gns::{EffectKind, Record};
use gnunet_types::{AbsoluteTime, Error};
use std::{
    fmt::Debug,
    net::IpAddr,
    task::{Context, Poll},
};
use tokio::time::Instant;

/// The one original request budget; every nested effect inherits it unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bounds {
    until: AbsoluteTime,
    hard: Instant,
}
impl Bounds {
    /// A finite logical/native request. Neither value is a retry duration.
    pub fn new(until: AbsoluteTime, hard: Instant) -> Result<Self, Error> {
        if until.as_micros() == u64::MAX {
            return Err(Error::InvalidInput);
        }
        Ok(Self { until, hard })
    }
    /// Original absolute source-clock target.
    pub const fn until(self) -> AbsoluteTime {
        self.until
    }
    /// Original absolute native target, unaffected by source-clock rollback.
    pub const fn hard(self) -> Instant {
        self.hard
    }
    pub(crate) fn expired(self, now: AbsoluteTime) -> bool {
        now >= self.until || Instant::now() >= self.hard
    }
}

/// A retained native error and its classification for the pure resolver.
/// Classification is never a replacement for returning the original error.
pub trait NativeFailure: std::error::Error {
    /// A protocol/resource category suitable for this exact effect's receipt.
    fn reason(&self) -> Error;
    /// Actual extra recursive work already performed by this original effect.
    /// Ordinary ports with no extra recursive work retain the default zero.
    fn spent(&self) -> u32 {
        0
    }
}
impl NativeFailure for Error {
    fn reason(&self) -> Error {
        *self
    }
}

/// An observation from the original operation, not admission or local writing.
#[derive(Debug)]
pub enum Value {
    /// Actual revocation response.
    Revocation(bool),
    /// Actual encrypted cache response or explicit miss.
    Cache(Option<Vec<u8>>),
    /// Actual NAMECACHE reply. GNUNET_OK is 1.
    Stored(i32),
    /// Actual symbolic registry result; None is genuinely absent.
    Service(Option<(u16, u16)>),
    /// Actual DNS-only nameserver resolution and work consumed.
    Addresses {
        /// Actual addresses from the original nameserver operation.
        addresses: Vec<IpAddr>,
        /// Actual work units charged to this dependency.
        spent: u32,
    },
    /// Actual DNS/system records and work consumed.
    Records {
        /// Owned records returned by the original operation.
        records: Vec<Record>,
        /// Actual work units charged to this dependency.
        spent: u32,
    },
    /// One encrypted candidate from the original DHT GET stream.
    Block(Vec<u8>),
    /// Actual terminal exhaustion of that original DHT GET.
    End,
}

/// Actual progress while relinquishing an original native operation.
#[derive(Debug)]
pub enum Close<R, E> {
    /// Original cancellation/close/join made progress, with ownership retained.
    Activity,
    /// A distinct owned cleanup error. This does not mean the owner is closed.
    Failed(E),
    /// Actual terminal retirement, with the provider's whole/partial/unknown
    /// facts. A timeout, Drop, cancel ticket or new epoch alone is not Closed.
    Closed(R),
}

/// One native operation, including any cancellation and mutation ambiguity.
///
/// An operation may own only a callback subscription to an explicit shared
/// foreground Driver. In that case Close::Closed reports that subscription's
/// actual revocation/terminal observation, and its report must explicitly state
/// that the same shared Driver still owns any wire/tombstone/partial IO debt.
/// Such a receipt is not a whole-source drain. The final SERVICE must separately
/// drive and physically disconnect that original Driver before claiming closed.
/// There must be no detached or unowned transfer of the retained work.
///
/// A provider must retain the exact original source/epoch/operation identifiers,
/// bytes and all unretired work. Retrying an idempotent read is permitted only
/// inside this same owner and original Bounds. A potentially exposed mutation
/// must not be replayed. CachePut admission/write is not its Stored reply.
pub trait Operation {
    /// Original typed error.
    type Error: NativeFailure;
    /// Actual native terminal report, including exposed/unknown mutations.
    type Report: Debug;
    /// Check/register original native timers without source-clock samples or
    /// new I/O. An error is yielded once; keep retirement guards functional.
    fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Option<Self::Error>;
    /// Poll actual I/O/callbacks. The manager supplies the common source time;
    /// this method must still check its original native guards before effects.
    fn poll(&mut self, cx: &mut Context<'_>, now: AbsoluteTime)
    -> Poll<Result<Value, Self::Error>>;
    /// Fence new work and start cancellation once, without a source-clock read.
    /// Keep any resource that still requires native close/join in this owner.
    fn begin_close(&mut self) -> Option<Self::Error>;
    /// Drive only original retirement work, clock-free and native-first. Return
    /// Closed only after that work actually settled; failure alone is not proof.
    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<Close<Self::Report, Self::Error>>;
}

/// An explicit source-level observation. It does not fail unrelated requests.
#[derive(Debug)]
pub enum Shared<E> {
    /// Real shared activity.
    Activity,
    /// Original source failure. The provider fences affected operations and
    /// reports their failures separately, without invalidating other sources.
    Failed(E),
    /// An actually re-established source. This is not proof that an old
    /// operation/mutation completed and does not authorize mutation replay.
    Recovered,
}

/// Selection of genuine dependencies. No default "successful" implementation.
pub trait Provider {
    /// The concrete retained operation type, commonly a native enum.
    type Operation: Operation;
    /// Admit this exact effect, or return the original refusal. Refusal may
    /// allocate no detached work. Any partially constructed native resources
    /// must be settled before Err, or returned in an admitted Operation that
    /// reports failure and retires. The original Bounds must not be extended.
    fn start(
        &mut self,
        effect: &EffectKind,
        bounds: Bounds,
    ) -> Result<Self::Operation, <Self::Operation as Operation>::Error>;
    /// Native-only guards for shared source debt, before the host reads time.
    fn poll_native_guard(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Option<<Self::Operation as Operation>::Error>;
    /// Fairly drive retained process-level work, including canceled requests.
    /// Failed is latched/consumed, not returned indefinitely on a dead source.
    fn poll_shared(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Shared<<Self::Operation as Operation>::Error>>;
    /// Clock-free stop of new source activity. Original operation owners remain
    /// available through poll_close, and shared debt remains through poll_shared.
    fn begin_close(&mut self) -> Option<<Self::Operation as Operation>::Error>;
    /// True only after this provider's own shared resources actually retired.
    fn is_closed(&self) -> bool;
}
