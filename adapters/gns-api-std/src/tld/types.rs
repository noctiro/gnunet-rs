//! Public request, observation and retirement types for one with-TLD owner.
use gnunet_gns_client_host::{
    Answer, EndpointSource, Epoch, Error, LocalOptions, QueryId, RecordType,
};
use gnunet_identity_client_host as identity;
use gnunet_types::Error as Fault;
use std::fmt;
use tokio::time::Instant;

/// The two original ordinary CLIENT selectors, sharing one actual clock Arc.
pub struct Sources {
    /// GNS service selector, with the caller's actual Resolver source.
    pub gns: EndpointSource,
    /// IDENTITY service selector, with the same actual clock source.
    pub identity: EndpointSource,
}

/// User-name semantics before an explicit starting zone is selected.
#[derive(Clone, Copy, Debug)]
pub struct Request<'name> {
    /// Original NUL-free user name. No IDNA/case normalization occurs here.
    pub name: &'name [u8],
    /// Exact requested record type.
    pub record_type: RecordType,
    /// Caller options, preserved for direct-key/configuration routes. Ego
    /// routing uses the official NO_DHT/LOCAL_MASTER override instead.
    pub options: LocalOptions,
    /// Original authority recursion policy.
    pub recursion_depth: u16,
}

/// Original overall bounds. A FOREVER lookup has no fabricated native timer.
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Canonical absolute target in the original source domain; MAX is FOREVER.
    pub until: u64,
    /// Original native target; absent only for the overall FOREVER policy.
    pub hard: Option<Instant>,
}
impl Bounds {
    /// Bind a finite canonical target to the caller's once-captured native hard.
    #[must_use]
    pub const fn bounded(until: u64, hard: Instant) -> Self {
        Self {
            until,
            hard: Some(hard),
        }
    }
    /// Official default overall lifetime. Actual underlying IO budgets remain.
    #[must_use]
    pub const fn forever() -> Self {
        Self {
            until: u64::MAX,
            hard: None,
        }
    }
}

/// Explicit bounded storage and original native-client policies.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Native GNS framing/output policy. This owner has one logical query slot.
    pub gns: gnunet_gns_client_host::Limits,
    /// Native dedicated IDENTITY lookup policy; no monitor is started.
    pub identity: identity::Limits,
    /// Maximum original full user-name extent, independent of the reduced GNS
    /// name's existing 252-byte protocol limit.
    pub name_bytes: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            gns: gnunet_gns_client_host::Limits::default(),
            identity: identity::Limits::default(),
            name_bytes: 1024,
        }
    }
}

/// One actual original GNS physical retirement, distinct from an Answer.
#[derive(Debug)]
pub struct GnsRetirement<'gns> {
    /// Original connection identity.
    pub epoch: Epoch<'gns>,
    /// Actual local retirement cause.
    pub cause: gnunet_gns_client_host::LossCause,
    /// Original lower-owner live intents retained at that observation.
    pub retained_queries: usize,
}

/// Original tokens and independent physical cleanup facts. None never claims
/// that an unattached source had a successful remote cancellation.
#[derive(Default, Debug)]
pub struct Report<'gns, 'id> {
    /// Original lower GNS query, if admitted.
    pub query: Option<QueryId<'gns>>,
    /// Original dedicated IDENTITY operation, if admitted.
    pub identity_operation: Option<identity::Operation<'id>>,
    /// Actual terminal IDENTITY callback received on that operation.
    pub identity_finished: bool,
    /// Actual original GNS reply received, including a late rejected delivery.
    pub gns_answer_received: bool,
    /// Original GNS callback was successfully canceled locally.
    pub gns_cancelled: bool,
    /// Original IDENTITY callback was successfully canceled locally.
    pub identity_cancelled: bool,
    /// Actual dedicated GNS owner was physically closed before transfer.
    pub gns_closed: bool,
    /// Actual dedicated IDENTITY owner was physically closed before transfer.
    pub identity_closed: bool,
    /// Original GNS source loss before final physical close.
    pub gns_source_loss: Option<(Epoch<'gns>, usize)>,
    /// Actual IDENTITY source loss before final physical close.
    pub identity_source_loss: Option<identity::Loss<'id>>,
    /// Actual original GNS close receipt, if an epoch was attached.
    pub gns_retirement: Option<GnsRetirement<'gns>>,
    /// Actual original IDENTITY close receipt, if supplied by that owner.
    pub identity_retirement: Option<identity::Loss<'id>>,
    /// Independent original GNS local cancellation failure.
    pub gns_cancel_error: Option<Error>,
    /// Independent original IDENTITY local cancellation failure.
    pub identity_cancel_error: Option<identity::Error>,
}

/// Static diagnostic metadata after original opaque tokens are intentionally
/// released. These counts/booleans cannot authorize a query on another owner.
#[derive(Debug)]
pub struct Diagnostics {
    /// The original GNS query was locally admitted, not necessarily answered.
    pub query_admitted: bool,
    /// A dedicated IDENTITY suffix operation was locally admitted.
    pub identity_admitted: bool,
    /// Actual terminal IDENTITY callback was observed.
    pub identity_finished: bool,
    /// Actual original GNS reply observed, independent of successful delivery.
    pub gns_answer_received: bool,
    /// Original GNS callback successfully canceled locally.
    pub gns_cancelled: bool,
    /// Original IDENTITY callback successfully canceled locally.
    pub identity_cancelled: bool,
    /// Actual original dedicated GNS owner closed.
    pub gns_closed: bool,
    /// Actual original dedicated IDENTITY owner closed.
    pub identity_closed: bool,
    /// An original attached GNS source was lost; value is its retained count.
    pub gns_source_loss: Option<usize>,
    /// Actual original IDENTITY loss metadata.
    pub identity_source_loss: Option<IdentityRetirement>,
    /// Actual final original GNS physical-close metadata.
    pub gns_retirement: Option<Retirement>,
    /// Actual final original IDENTITY physical-close metadata.
    pub identity_retirement: Option<IdentityRetirement>,
    /// Independent original GNS cancellation failure.
    pub gns_cancel_error: Option<Error>,
    /// Independent original IDENTITY cancellation failure.
    pub identity_cancel_error: Option<identity::Error>,
}

/// Actual GNS close metadata without a reusable epoch token.
#[derive(Debug)]
pub struct Retirement {
    /// Original local retirement cause.
    pub cause: gnunet_gns_client_host::LossCause,
    /// Live intents reported at that original physical loss.
    pub retained_queries: usize,
}

/// Actual IDENTITY close/loss metadata without reusable operation/epoch tokens.
#[derive(Debug)]
pub struct IdentityRetirement {
    /// Whether an original MQ was actually attached.
    pub attached: bool,
    /// Original operations locally retired.
    pub operations: usize,
    /// Operations with real positive exposure.
    pub exposed: usize,
    /// Original ego allocations invalidated by the lower owner.
    pub egos: usize,
}
impl From<identity::Loss<'_>> for IdentityRetirement {
    fn from(loss: identity::Loss<'_>) -> Self {
        Self {
            attached: loss.epoch.is_some(),
            operations: loss.operations,
            exposed: loss.exposed,
            egos: loss.egos,
        }
    }
}
impl Report<'_, '_> {
    /// Consume original tokens into static metadata and retain every actual
    /// independent error. This does not manufacture cross-instance authority.
    #[must_use]
    pub fn into_diagnostics(self) -> Diagnostics {
        Diagnostics {
            query_admitted: self.query.is_some(),
            identity_admitted: self.identity_operation.is_some(),
            identity_finished: self.identity_finished,
            gns_answer_received: self.gns_answer_received,
            gns_cancelled: self.gns_cancelled,
            identity_cancelled: self.identity_cancelled,
            gns_closed: self.gns_closed,
            identity_closed: self.identity_closed,
            gns_source_loss: self.gns_source_loss.map(|(_, count)| count),
            identity_source_loss: self.identity_source_loss.map(Into::into),
            gns_retirement: self.gns_retirement.map(|retired| Retirement {
                cause: retired.cause,
                retained_queries: retired.retained_queries,
            }),
            identity_retirement: self.identity_retirement.map(Into::into),
            gns_cancel_error: self.gns_cancel_error,
            identity_cancel_error: self.identity_cancel_error,
        }
    }
}

/// Terminal classification. A structurally valid zero-record GNS reply remains
/// Answer; only the actual IDENTITY missing result produces NotGns.
pub enum Outcome<'gns, 'id> {
    /// Exact original GNS reply with its own query/epoch and immutable bytes.
    Answer {
        /// Service observation; not independent zone-authentication proof.
        answer: Answer<'gns>,
        /// Original local retirement facts.
        report: Report<'gns, 'id>,
    },
    /// No direct/configured key and the actual ego-suffix lookup was missing.
    NotGns {
        /// Original local retirement facts, with no invented GNS reply.
        report: Report<'gns, 'id>,
    },
}
impl fmt::Debug for Outcome<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Answer { answer, report } => f
                .debug_struct("Answer")
                .field("query", &answer.query())
                .field("epoch", &answer.epoch())
                .field("report", report)
                .finish(),
            Self::NotGns { report } => f.debug_struct("NotGns").field("report", report).finish(),
        }
    }
}

/// One actual source observation or terminal classification.
#[expect(
    clippy::large_enum_variant,
    reason = "Terminal progress transfers original source and cancellation outcomes inline without another allocation"
)]
pub enum Progress<'gns, 'id> {
    /// Actual original dedicated IDENTITY source progress.
    Identity(identity::Progress<'id>),
    /// Actual original GNS source progress, never a synthesized answer.
    Gns(gnunet_gns_client_host::Progress<'gns>),
    /// Real IDENTITY result selected and admitted the original GNS query.
    Routed,
    /// Exactly one terminal outcome, after original physical retirement.
    Finished(Outcome<'gns, 'id>),
    /// Terminal outcome/report was already transferred or explicitly closed.
    Closed,
}
impl fmt::Debug for Progress<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identity(event) => f.debug_tuple("Identity").field(event).finish(),
            Self::Gns(_) => f.write_str("GnsSourceProgress"),
            Self::Routed => f.write_str("Routed"),
            Self::Finished(outcome) => f.debug_tuple("Finished").field(outcome).finish(),
            Self::Closed => f.write_str("Closed"),
        }
    }
}

/// Actual failure; none of these implies NotGns, NXDOMAIN or an empty answer.
#[derive(Debug)]
pub enum Cause {
    /// Original native hard elapsed.
    NativeDeadline,
    /// Original canonical target elapsed.
    LogicalDeadline,
    /// Same actual source clock/subscription failed.
    Clock(Fault),
    /// Malformed selected `[gns]` mapping; shorter suffixes are not attempted.
    Configuration(Fault),
    /// Invalid input or explicit local resource refusal.
    Protocol(Fault),
    /// Actual original GNS CLIENT/source error.
    Gns(Error),
    /// Actual original GNS physical source loss.
    GnsSource(gnunet_gns_client_host::LossCause),
    /// Actual original IDENTITY CLIENT/source error.
    Identity(identity::Error),
    /// Actual original IDENTITY physical source loss.
    IdentitySource(identity::LossCause),
    /// Real service code other than the missing-name result.
    IdentityResult(u32),
    /// Real local retirement, without a matching missing-name callback.
    IdentityLocal {
        /// Original local reason.
        reason: identity::LocalReason,
        /// Actual original request exposure.
        submission: identity::Submission,
        /// Late original result, if one was actually received.
        result_code: Option<u32>,
    },
}
impl fmt::Display for Cause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GNS user-name lookup: {self:?}")
    }
}
impl std::error::Error for Cause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Clock(error) | Self::Configuration(error) | Self::Protocol(error) => Some(error),
            Self::Gns(error) | Self::Identity(error) => Some(error),
            Self::GnsSource(gnunet_gns_client_host::LossCause::Io(error)) => Some(error),
            Self::GnsSource(
                gnunet_gns_client_host::LossCause::Protocol(error)
                | gnunet_gns_client_host::LossCause::Resource(error),
            ) => Some(error),
            Self::IdentitySource(identity::LossCause::Io(error)) => Some(error),
            Self::IdentitySource(
                identity::LossCause::Protocol(error) | identity::LossCause::Resource(error),
            ) => Some(error),
            Self::IdentitySource(identity::LossCause::Ports(error)) => Some(error),
            _ => None,
        }
    }
}

/// Terminal owned cause and all independent original retirement facts.
#[derive(Debug)]
pub struct Failure<'gns, 'id> {
    /// Actual principal failure.
    pub cause: Cause,
    /// Original token/source/cancellation/close observations.
    pub report: Report<'gns, 'id>,
}
impl Failure<'_, '_> {
    /// Consume original tokens while preserving principal and cleanup causes.
    #[must_use]
    pub fn into_diagnostics(self) -> (Cause, Diagnostics) {
        (self.cause, self.report.into_diagnostics())
    }
}
impl fmt::Display for Failure<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.cause.fmt(f)
    }
}
impl std::error::Error for Failure<'_, '_> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}
