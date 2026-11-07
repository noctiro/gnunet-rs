use crate::{Ego, Epoch, Error, Operation, SecretKey};
use gnunet_service_runtime::framing::{Accounting, Budget, Limits as Framing};
use gnunet_types::Error as Fault;
use std::{fmt, io, time::Duration};
/// Actual bounded memory/frame resources and finite native retirement policy.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum live operation/tombstone/completion rows.
    pub operations: usize,
    /// Maximum monitored egos. Operation-only/lookup clients allocate no ego rows.
    pub egos: usize,
    /// Maximum accepted user/returned name bytes, without final NUL.
    pub name_bytes: usize,
    /// Total original immutable outbound bytes, including physical queued frames.
    pub source_bytes: usize,
    /// Complete native frame bound, through65535.
    pub frame_bytes: usize,
    /// Actual syscall byte quantum, nonzero.
    pub io_slice_bytes: usize,
    /// First actual attachment through initial END_OF_LIST, never renewed.
    pub initialization_timeout: Duration,
    /// Original cancellation/deadline through actual partial/ACK retirement.
    pub retirement_grace: Duration,
    /// Automatically reconnect the monitor/operation source after real loss.
    /// No old mutation or lookup is ever replayed.
    pub reconnect: bool,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            operations: 32,
            egos: 1024,
            name_bytes: 1024,
            source_bytes: 256 * 1024,
            frame_bytes: 65535,
            io_slice_bytes: 65535,
            initialization_timeout: Duration::from_secs(30),
            retirement_grace: Duration::from_secs(5),
            reconnect: true,
        }
    }
}
impl Limits {
    pub(crate) fn validate(self, monitor: bool) -> Result<(), Fault> {
        if self.operations == 0
            || (monitor && self.egos == 0)
            || self.name_bytes > 65535 - 12 - 36 - 1
            || self.source_bytes < 4
            || self.frame_bytes < 49
            || self.frame_bytes > 65535
            || self.io_slice_bytes == 0
            || self.initialization_timeout.is_zero()
            || self.retirement_grace.is_zero()
            || std::time::Instant::now()
                .checked_add(self.initialization_timeout)
                .is_none()
            || std::time::Instant::now()
                .checked_add(self.retirement_grace)
                .is_none()
        {
            return Err(Fault::InvalidInput);
        }
        Ok(())
    }
    pub(crate) fn framing(self) -> Framing {
        Framing {
            frame_bytes: self.frame_bytes,
            ordinary: Budget {
                frames: 1,
                bytes: self.frame_bytes,
            },
            reserved: Budget::default(),
            accounting: Accounting::Retained,
            io_slice_bytes: self.io_slice_bytes,
        }
    }
}
/// Original request operation; no private protocol identifiers are added.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Kind {
    /// Create/import an identity.
    Create,
    /// Rename an identity.
    Rename,
    /// Delete an identity.
    Delete,
    /// Exact lookup on a dedicated MQ.
    Lookup,
    /// Longest dot-delimited suffix lookup on a dedicated MQ.
    LookupSuffix,
}
/// Actual original native byte exposure, not a durable mutation proof.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Submission {
    /// No byte exposed.
    Unsent,
    /// Positive prefix only.
    Partial {
        /// Actual bytes.
        bytes: usize,
        /// Original complete frame bytes.
        total: usize,
    },
    /// Whole request wrote locally; response is independent.
    Written {
        /// Original complete frame bytes.
        bytes: usize,
    },
}
/// Why an original operation locally ended without a normal callback result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LocalReason {
    /// Explicit callback suppression; no wire CANCEL exists.
    Cancelled,
    /// Original logical/native operation deadline.
    Deadline,
    /// Original physical MQ lost.
    Lost,
    /// Explicit permanent client close.
    Closed,
}
/// Owned identity material from a real lookup or deleted monitor entry.
/// Formatting deliberately never exposes secret bytes.
pub struct Identity {
    pub(crate) name: Vec<u8>,
    pub(crate) key: SecretKey,
}
impl Identity {
    /// Exact original returned canonical C-string name bytes.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        &self.name
    }
    /// Explicit opaque borrowed private material. The caller controls any
    /// intentional exposure/duplication; no JSON/Serialize/Clone is implemented.
    #[must_use]
    pub const fn secret(&self) -> &SecretKey {
        &self.key
    }
    /// Public typed key serialization only, derived by the pure production crypto.
    pub fn public_key(&self) -> Result<[u8; 36], Fault> {
        self.key.public_key()
    }
    /// Consume the snapshot and transfer its zeroizing secret to the caller.
    #[must_use]
    pub fn into_secret(self) -> SecretKey {
        self.key
    }
}
impl fmt::Debug for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Identity")
            .field("name_bytes", &self.name.len())
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}
/// Borrow a live monitor identity, tied to the client cache borrow.
pub struct EgoView<'a, 'id> {
    pub(crate) ego: Ego<'id>,
    pub(crate) identity: &'a Identity,
}
impl<'a, 'id> EgoView<'a, 'id> {
    /// Exact live original identity allocation.
    #[must_use]
    pub const fn ego(&self) -> Ego<'id> {
        self.ego
    }
    /// Current returned name.
    #[must_use]
    pub fn name(&self) -> &[u8] {
        self.identity.name()
    }
    /// Opaque borrowed secret, never automatically formatted/serialized.
    #[must_use]
    pub const fn secret(&self) -> &SecretKey {
        self.identity.secret()
    }
    /// Explicit public-key derivation; this grants no network authentication.
    pub fn public_key(&self) -> Result<[u8; 36], Fault> {
        self.identity.public_key()
    }
}
impl fmt::Debug for EgoView<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EgoView")
            .field("ego", &self.ego)
            .field("private_key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
/// Original actual result or bounded local retirement. Sensitive creation
/// material is owned/zeroizing and never derives Debug or Serialize implicitly.
pub enum Outcome {
    /// Actual ordered RESULT_CODE. Code0 is service success, not an fsync proof.
    Result {
        /// Raw official error code.
        code: u32,
        /// Original generated/imported private material only for CREATE success.
        created: Option<SecretKey>,
    },
    /// Actual one-shot UPDATE, not a monitor cache event.
    Found(Identity),
    /// Local callback policy/loss; an exposed mutation may have committed.
    Local {
        /// Original policy/cause.
        reason: LocalReason,
        /// Actual byte exposure.
        submission: Submission,
        /// Actual late service result if it arrived before retirement.
        result_code: Option<u32>,
        /// Original local creation material for explicit recovery, when not canceled.
        creation_material: Option<SecretKey>,
    },
}
impl fmt::Debug for Outcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Result { code, created } => f
                .debug_struct("Result")
                .field("code", code)
                .field("private_material_present", &created.is_some())
                .finish(),
            Self::Found(_) => f.write_str("Found([REDACTED])"),
            Self::Local {
                reason,
                submission,
                result_code,
                creation_material,
            } => f
                .debug_struct("Local")
                .field("reason", reason)
                .field("submission", submission)
                .field("result_code", result_code)
                .field("private_material_present", &creation_material.is_some())
                .finish(),
        }
    }
}
/// Original completed operation. Holding it never grants a new request/source.
#[derive(Debug)]
pub struct Completion<'id> {
    /// Exact original operation.
    pub operation: Operation<'id>,
    /// Actual MQ if admitted before completion.
    pub epoch: Option<Epoch<'id>>,
    /// Original operation kind.
    pub kind: Kind,
    /// Actual/local outcome with opaque sensitive ownership.
    pub outcome: Outcome,
}
/// Local cancellation state; no wire cancellation/remote revocation is implied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cancellation {
    /// Zero-written original was removed before any service request exposure.
    Unsent,
    /// Original bytes/reply drain on their MQ under the first finite grace.
    Retiring,
    /// Original completion already exists and is not rewritten.
    Completed,
}
/// A live Ego UPDATE's directory effect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Change {
    /// Previously unknown key.
    Added,
    /// Same original key, current name updated.
    Renamed,
}
/// Original physical source ended; all current egos are immediately revoked.
#[derive(Clone, Copy, Debug)]
pub struct Loss<'id> {
    /// Actual original MQ, absent if no attachment occurred.
    pub epoch: Option<Epoch<'id>>,
    /// Pending original operations retired locally.
    pub operations: usize,
    /// Those with actual positive exposure.
    pub exposed: usize,
    /// Live ego allocations invalidated/wiped.
    pub egos: usize,
}
/// Known cause preceding native owner retirement; no secret bytes are retained.
#[derive(Debug)]
pub enum LossCause {
    /// Original clean EOF.
    Eof,
    /// Original native I/O cause.
    Io(io::Error),
    /// Actual invalid service framing/semantics.
    Protocol(Fault),
    /// Resource or first-initialization deadline refusal.
    Resource(Fault),
    /// Original CLIENT/clock/Resolver port failure.
    Ports(Error),
    /// Caller forced fresh MQ, without replay.
    Requested,
    /// Explicit permanent close.
    Closed,
    /// A pending partial/ACK could not retire before original hard bound.
    RetirementDeadline,
}
/// One bounded monitor step for a caller coordinating another service. Idle is
/// a local receive observation on the original epoch, never an atomic snapshot
/// across services or a promise that later input cannot arrive.
#[derive(Debug)]
pub enum InventoryProgress<'id> {
    /// The same source/lifecycle event delivered by the ordinary client driver.
    Source(Progress<'id>),
    /// This poll reached a pending native read with no retained partial/full
    /// input, queued output or own operations on the initialized monitor.
    Idle(Epoch<'id>),
}
/// One actual/local bounded scheduling step. Secret-bearing completions and
/// snapshots have explicit opaque ownership and redacted Debug implementations.
#[derive(Debug)]
pub enum Progress<'id> {
    /// Actual source attachment.
    Connected(Epoch<'id>),
    /// Monitor START truly admitted.
    StartQueued(Epoch<'id>),
    /// Actual whole START wrote; not the initial-list END.
    StartWritten(Epoch<'id>),
    /// One original mutation/lookup truly admitted.
    Queued {
        /// Actual source.
        epoch: Epoch<'id>,
        /// Original request.
        operation: Operation<'id>,
    },
    /// Actual whole mutation/lookup write, not its result.
    Written {
        /// Exact source.
        epoch: Epoch<'id>,
        /// Exact original operation.
        operation: Operation<'id>,
    },
    /// End-of-list from the actual START stream.
    Initialized(Epoch<'id>),
    /// Actual current name/key directory event.
    Ego {
        /// Exact source-bound ego.
        ego: Ego<'id>,
        /// Added or same-key renamed.
        change: Change,
        /// Snapshot was not yet ended.
        initial: bool,
    },
    /// Actual deletion event; old token is immediately stale.
    Deleted {
        /// Original invalidated allocation.
        ego: Ego<'id>,
        /// Last actual private material; owned/zeroizing and redacted.
        identity: Identity,
    },
    /// Physical loss revoked/wiped this ego, distinct from service DELETE.
    EgoRetired(Ego<'id>),
    /// Actual operation outcome.
    Completed(Completion<'id>),
    /// Source physically retired before outcome publication.
    Lost {
        /// Original counts/exposure facts.
        report: Loss<'id>,
        /// Actual original cause.
        cause: LossCause,
    },
    /// Original pre-attachment syscall failed; no exposed request is replayed.
    ConnectRetry {
        /// Actual errno.
        error: io::Error,
        /// Source-selected backoff.
        retry_after: Duration,
    },
    /// Current endpoint selection unavailable.
    Unavailable(Error),
    /// Concrete positive native byte movement.
    Activity {
        /// Native bytes read.
        read_bytes: usize,
        /// Native bytes written.
        written_bytes: usize,
    },
    /// Caller-only observation budget, no cancellation.
    WaitDeadline,
    /// Permanently closed client with all local events consumed.
    Closed,
}
