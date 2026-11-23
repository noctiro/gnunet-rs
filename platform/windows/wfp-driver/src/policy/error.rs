use crate::{callbacks, sdk};
use core::fmt;

/// One exact kernel FWPM failure, without translating its NTSTATUS.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeFailure {
    /// Native operation that returned the status.
    pub operation: &'static str,
    /// Original negative NTSTATUS.
    pub status: sdk::NTSTATUS,
}

impl NativeFailure {
    pub(super) fn session_aborted(self) -> bool {
        self.status == sdk::GNUNET_WFP_STATUS_FWP_SESSION_ABORTED
    }
}

impl fmt::Display for NativeFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} returned NTSTATUS {:#010x}",
            self.operation, self.status
        )
    }
}

impl core::error::Error for NativeFailure {}

/// Fixed driver datagram callout being observed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Datagram {
    /// IPv4 datagram-data callout and guard.
    V4,
    /// IPv6 datagram-data callout and guard.
    V6,
}

/// A native catalog observation did not match the fixed driver contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Problem {
    /// The requested fixed GUID was not returned.
    Identity,
    /// Provider identity was absent or different.
    Provider,
    /// The filtering layer was different.
    Layer,
    /// Kernel callout registration was not observed.
    Unregistered,
    /// A provider context was required but is not part of this contract.
    ProviderContext,
    /// A successful native add/query omitted its required output.
    MissingOutput,
    /// The guard action, flags, context or conditions were different.
    GuardShape,
}

/// The original reason setup could not install the owned guard policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// Transaction wait is outside the supported 1..=30,000 ms range.
    InvalidLimits,
    /// This owner has already started; an existing policy was left untouched.
    AlreadyStarted,
    /// An actual kernel FWPM call failed.
    Native(NativeFailure),
    /// A successful operation did not return its engine handle.
    MissingEngine,
    /// A required original filter ID was absent before commit.
    Incomplete,
    /// The callback recipient refused the original filter ID set.
    Routing(callbacks::Error),
    /// The fixed callout or newly added guard did not match its contract.
    Catalog {
        /// Original family under examination.
        datagram: Datagram,
        /// Observed incompatibility.
        problem: Problem,
    },
}

impl From<NativeFailure> for Error {
    fn from(value: NativeFailure) -> Self {
        Self::Native(value)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => {
                f.write_str("transaction wait is outside 1..=30,000 milliseconds")
            }
            Self::AlreadyStarted => f.write_str("guard policy owner has already started"),
            Self::Native(error) => error.fmt(f),
            Self::Incomplete => f.write_str("missing original filter ID before commit"),
            Self::Routing(error) => error.fmt(f),
            Self::MissingEngine => f.write_str("successful engine open omitted its handle"),
            Self::Catalog { datagram, problem } => {
                write!(f, "{datagram:?} catalog mismatch: {problem:?}")
            }
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Native(error) => Some(error),
            Self::Routing(error) => Some(error),
            _ => None,
        }
    }
}

/// A single original cleanup operation's observation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Cleanup {
    /// No corresponding resource or transaction existed.
    #[default]
    NotNeeded,
    /// An earlier transaction failure prevented this operation from running.
    NotAttempted,
    /// The actual native operation succeeded.
    Succeeded,
    /// The actual native operation returned this failure.
    Failed(NativeFailure),
}

impl Cleanup {
    pub(super) fn observe(result: Result<(), NativeFailure>) -> Self {
        match result {
            Ok(()) => Self::Succeeded,
            Err(error) => Self::Failed(error),
        }
    }

    /// Whether this individual native operation failed.
    pub const fn failed(self) -> bool {
        matches!(self, Self::Failed(_))
    }

    pub(super) fn session_aborted(self) -> Option<NativeFailure> {
        match self {
            Self::Failed(error) if error.session_aborted() => Some(error),
            _ => None,
        }
    }

    pub(super) fn blocks_removal(self, operation: &str, absent: sdk::NTSTATUS) -> bool {
        self.failed() && !self.absent(operation, absent)
    }

    pub(super) fn absent(self, operation: &str, absent: sdk::NTSTATUS) -> bool {
        matches!(self, Self::Failed(error) if error.operation == operation && error.status == absent)
    }
}

/// Independent observations from retirement of the original dynamic engine.
/// A close failure leaves the owner and its original handle in `Policy`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[must_use = "inspect cleanup results and retain native state after an uncertain close"]
pub struct Retirement {
    /// Authoritative cancellation observed on this original dynamic session.
    /// Its dynamic objects are gone, but its client handle still needs the
    /// actual original engine close. Earlier negative outcomes stay unchanged.
    pub session_aborted: Option<NativeFailure>,
    /// Abort of an unsettled setup transaction.
    pub setup_abort: Cleanup,
    /// Start of the independent removal transaction.
    pub removal_begin: Cleanup,
    /// Deletion of the original IPv4 and IPv6 guard IDs.
    pub guards: [Cleanup; 2],
    /// Original discovery, capture and endpoint closure filter deletion results.
    pub capture: [Cleanup; 6],
    /// Deletion of the original dynamic guard sublayer.
    pub sublayer: Cleanup,
    /// Deletion of the original dynamic guard provider.
    pub provider: Cleanup,
    /// Commit of an entirely successful removal transaction.
    pub removal_commit: Cleanup,
    /// Abort after a failed removal operation or commit.
    pub removal_abort: Cleanup,
    /// Close of the original engine; this result never erases earlier failures.
    pub engine_close: Cleanup,
}

impl Retirement {
    /// Whether any actual cleanup call failed, even if engine close succeeded.
    pub fn has_failure(self) -> bool {
        self.first_failure().is_some()
    }

    /// Return a retained refusal, preferring this retirement's actual calls.
    pub fn first_failure(self) -> Option<NativeFailure> {
        [self.setup_abort, self.removal_begin]
            .into_iter()
            .chain(self.capture)
            .chain(self.guards)
            .chain([
                self.sublayer,
                self.provider,
                self.removal_commit,
                self.removal_abort,
                self.engine_close,
            ])
            .find_map(|cleanup| match cleanup {
                Cleanup::Failed(error) => Some(error),
                _ => None,
            })
            .or(self.session_aborted)
    }
}
